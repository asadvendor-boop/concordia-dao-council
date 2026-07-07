"""Rowan, Proposal Sentinel — local Council Chamber runtime + LLM.

Classifies incoming signals, filters noise, applies deterministic guards,
and routes genuine proposals to Mercer via a sealed TriageDecision.

Architecture:
  - Preprocessor intercepts ProposalCard messages from the Council Chamber runtime
  - Validates sender identity (must be Recorder from trusted agent registry)
  - Validates card structure via Pydantic (ProposalCard model)
  - Calls LLM for noise classification
  - Applies deterministic code guards (P1/security → always route)
  - Submits TriageDecision via SubmissionClient (prepare → publish → confirm)
  - Only recruits Mercer when decision="route" (not on suppress)
  - Non-ProposalCard messages pass through to the default LLM adapter

Security:
  - Sender validation: only accepts ProposalCards from the registered Recorder UUID
  - Card validation: Pydantic parsing rejects malformed payloads
  - Idempotency: derived from source message ID (not random), safe for redelivery
  - Guards: P1/security_relevant → always route, invalid output → fail-closed
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time

import httpx

from shared.config import (
    ACTIVE_PROPOSALS,
    MODELS,
    get_provider_settings,
    get_agent_api_key,
    get_agent_ids,
)
from shared.card_intake import (
    extract_sealed_card,
    has_seal_fields,
    derive_idempotency_key,
)
from shared.models import ProposalCard, TriageDecision
from shared.proposal_room import ProposalRoomClient
from shared.replay_guard import should_skip_stale_card, should_skip_stale_chatter
from shared.submission_client import SubmissionClient, format_card_message
from shared.local_room_runtime import LocalDefaultPreprocessor, LocalRoomAgent
from shared.supervisor import run_with_supervisor

logger = logging.getLogger("concordia.triage")

# Gateway URL for SubmissionClient (same pattern as tracer_bullet.py)
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")

# ----- Constants -----
TRIAGE_SYSTEM_PROMPT = """You are Rowan, the Proposal Sentinel for Concordia DAO Council.

Your job: given a ProposalCard from a DAO governance feed, determine whether the
proposal needs treasury/risk investigation or should be suppressed as noise.

You MUST respond with ONLY a valid JSON object (no markdown, no explanation
outside the JSON). The JSON must have these fields:

{
  "decision": "route" or "suppress",
  "noise_score": <float 0.0 to 1.0>,
  "reasoning": "<brief explanation>"
}

Guidelines:
- noise_score 0.0 = definitely a real proposal
- noise_score 1.0 = definitely noise
- If noise_score < 0.5, decision should be "route"
- If noise_score >= 0.7, decision can be "suppress"
- P1 severity or security-relevant signals should ALWAYS be "route" with low noise_score
- When in doubt, route (false negatives are worse than false positives)
- Keep reasoning under 200 characters

Respond with ONLY the JSON object."""


# _extract_sealed_card: now imported from shared.card_intake as extract_sealed_card
def _extract_sealed_card(content: str) -> dict | None:
    """Delegate to shared.card_intake.extract_sealed_card."""
    return extract_sealed_card(content)


def _validate_signal_card(card_data: dict) -> ProposalCard | None:
    """Validate card_data against the ProposalCard Pydantic model.

    Returns a validated ProposalCard instance, or None if validation fails.
    """
    try:
        return ProposalCard(**card_data)
    except Exception as exc:
        logger.warning(
            "[triage] ProposalCard validation failed (%s)",
            type(exc).__name__,
        )
        return None


# _has_seal_fields: now imported from shared.card_intake as has_seal_fields
def _has_seal_fields(card_data: dict) -> bool:
    """Delegate to shared.card_intake.has_seal_fields."""
    return has_seal_fields(card_data)


def _apply_deterministic_guards(
    signal_card: dict,
    llm_decision: str,
    llm_noise_score: float,
    llm_reasoning: str,
) -> tuple[str, float, str]:
    """Apply deterministic code guards AFTER LLM classification.

    These override the LLM when safety-critical conditions are met:
    1. P1 or security_relevant → always route
    2. Clamp noise_score to [0.0, 1.0]
    3. Invalid decision → fail closed to "route"

    Returns:
        (decision, noise_score, reasoning) — potentially overridden.
    """
    decision = llm_decision
    noise_score = llm_noise_score
    reasoning = llm_reasoning

    # Guard 1: Clamp noise_score
    noise_score = max(0.0, min(1.0, noise_score))

    # Guard 2: Validate decision
    if decision not in ("route", "suppress"):
        logger.warning(
            f"[triage] Invalid LLM decision '{decision}' → fail-closed to 'route'"
        )
        decision = "route"
        noise_score = 0.1
        reasoning = f"[GUARD] Invalid LLM decision '{llm_decision}' — defaulting to route"

    # Guard 3: P1 or security_relevant → always route
    severity = signal_card.get("preliminary_severity", "unknown")
    security = signal_card.get("security_relevant", False)

    if severity == "P1" or security:
        if decision != "route":
            logger.info(
                f"[triage] Overriding LLM suppress → route "
                f"(severity={severity}, security={security})"
            )
        # Always enforce for P1/security, even if already "route"
        decision = "route"
        noise_score = min(noise_score, 0.1)  # Force low noise
        guard_reason = []
        if severity == "P1":
            guard_reason.append("P1 severity")
        if security:
            guard_reason.append("security-relevant")
        reasoning = (
            f"[GUARD] {' + '.join(guard_reason)} — forced route. "
            f"Original LLM: {llm_reasoning}"
        )

    return decision, noise_score, reasoning


# _derive_idempotency_key: now imported from shared.card_intake as derive_idempotency_key
def _derive_idempotency_key(room_message_id: str, card_hash: str) -> str:
    """Delegate to shared.card_intake.derive_idempotency_key with 'triage' prefix."""
    return derive_idempotency_key("triage", room_message_id, card_hash)


# Rooms where Rowan has already submitted a sealed TriageDecision.
# Non-card Agent messages in these rooms are silently consumed.
_handoff_rooms: set[str] = set()


class TriagePreprocessor:
    """Deterministic preprocessor for Rowan.

    Intercepts room messages containing ProposalCards. When an ProposalCard is
    found, the preprocessor:
    1. Validates sender identity (must be Recorder)
    2. Validates card structure via Pydantic
    3. Calls the LLM for noise classification
    4. Applies deterministic guards
    5. Submits a sealed TriageDecision via Gateway
    6. Only on decision="route": recruits Mercer into the room
    7. Returns None (consuming the message — no further LLM processing)

    Non-ProposalCard messages from agents are silently consumed after
    handoff (post-handoff silence). Non-ProposalCard messages from
    non-agents pass through to the default adapter.
    """

    def __init__(self, llm, triage_agent_id: str, triage_api_key: str):
        self._default_preprocessor = None
        self._llm = llm
        self._triage_agent_id = triage_agent_id
        self._triage_api_key = triage_api_key
        self._gateway_url = GATEWAY_URL
        self._submission_key = os.getenv("TRIAGE_SUBMISSION_KEY", "")
        self._diagnosis_agent_id = os.getenv("DIAGNOSIS_AGENT_ID", "")
        self._boot_epoch = time.time()

        # Trusted sender: only Recorder may send ProposalCards
        self._recorder_agent_id = get_agent_ids().get("recorder", "")

        self._room_client = ProposalRoomClient(
            sender_id=self._triage_agent_id or "triage",
            sender_role="triage",
        )

    async def _ensure_default(self):
        """Lazily import and create DefaultPreprocessor."""
        if self._default_preprocessor is None:
            self._default_preprocessor = LocalDefaultPreprocessor()

    async def _post_to_room(
        self, room_id: str, content: str, mentions: list[str]
    ) -> str:
        """Post a message to a Gateway-owned Council Chamber.

        Returns the proposal-room message id.
        """
        return await self._room_client.post_message(
            room_id,
            content,
            mentions=[mid for mid in mentions if mid],
            metadata={"publisher": "triage"},
        )

    async def _add_participant(self, room_id: str, agent_id: str) -> None:
        """Add an agent to an Council Chamber (for dynamic recruitment).

        Raises on failure — a failed Diagnosis recruitment must block
        the handoff, not silently produce a card nobody reads.
        """
        await self._room_client.add_participant(
            room_id,
            agent_id,
            role="diagnosis",
            display_name="Mercer",
        )
        logger.info(
            f"[triage] Added participant {agent_id[:12]}... "
            f"to room {room_id[:12]}..."
        )

    async def _classify_with_llm(self, signal_card: dict) -> dict:
        """Call LLM to classify the signal.

        Returns dict with {decision, noise_score, reasoning}.
        Falls back to {"decision": "route", "noise_score": 0.1} on any error.
        """
        # Build a concise prompt for the LLM
        signal_summary = (
            f"ProposalCard:\n"
            f"  Title: {signal_card.get('title', 'unknown')}\n"
            f"  Source: {signal_card.get('source', 'unknown')}\n"
            f"  Severity: {signal_card.get('preliminary_severity', 'unknown')}\n"
            f"  Security Relevant: {signal_card.get('security_relevant', False)}\n"
            f"  Signal ID: {signal_card.get('signal_id', 'unknown')}\n"
        )

        # Add raw_payload summary if present
        raw = signal_card.get("raw_payload", {})
        if raw:
            # Truncate raw payload to avoid token overflow
            raw_str = json.dumps(raw, default=str)[:500]
            signal_summary += f"  Raw Payload (truncated): {raw_str}\n"

        try:
            from langchain_core.messages import HumanMessage, SystemMessage

            messages = [
                SystemMessage(content=TRIAGE_SYSTEM_PROMPT),
                HumanMessage(content=signal_summary),
            ]

            response = await self._llm.ainvoke(messages)
            content = response.content.strip()

            # Parse JSON from LLM response
            # Try to find JSON in the response (LLM may wrap in markdown)
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                return {
                    "decision": result.get("decision", "route"),
                    "noise_score": float(result.get("noise_score", 0.0)),
                    "reasoning": str(result.get("reasoning", "")),
                }
            else:
                logger.warning(
                    "[triage] LLM returned non-JSON output (length=%s)",
                    len(content),
                )
                return {
                    "decision": "route",
                    "noise_score": 0.1,
                    "reasoning": "[FALLBACK] LLM response was not valid JSON — routing by default",
                }

        except Exception as exc:
            logger.error(
                "[triage] LLM classification failed (%s)",
                type(exc).__name__,
            )
            return {
                "decision": "route",
                "noise_score": 0.1,
                "reasoning": f"[FALLBACK] LLM error: {type(exc).__name__} — routing by default",
            }

    async def _submit_triage_decision(
        self,
        signal_card: dict,
        decision: str,
        noise_score: float,
        reasoning: str,
        room_id: str,
        room_message_id: str,
    ) -> dict:
        """Build, seal, publish, and confirm a TriageDecision.

        Returns a dict with evidence: {submission_id, card_hash, message_id,
        new_state, sequence_number, latency_ms}.
        """
        start_time = time.monotonic()

        # Get proposal_id — ProposalCard uses signal_id as the proposal key via Gateway
        proposal_id = signal_card.get("proposal_id") or signal_card.get("signal_id", "")
        signal_id = signal_card.get("signal_id", "")

        # Build the TriageDecision card
        triage_card = TriageDecision(
            proposal_id=proposal_id,
            signal_id=signal_id,
            decision=decision,
            noise_score=noise_score,
            reasoning=reasoning,
        )

        # Derive idempotency key from source message + card hash
        # This makes redelivery safe: same message → same sealed card (or 409)
        source_card_hash = signal_card.get("card_hash", "")
        idem_key = _derive_idempotency_key(room_message_id, source_card_hash)

        async with SubmissionClient(
            self._gateway_url, agent_key=self._submission_key
        ) as sc:
            # Step 1: Prepare (seal via Gateway)
            prepared = await sc.prepare(triage_card, idempotency_key=idem_key)
            logger.info(
                f"[triage] Prepared TriageDecision: "
                f"submission_id={prepared.submission_id}, "
                f"card_hash={prepared.card_hash[:16]}..., "
                f"sequence={prepared.sequence_number}, "
                f"proposal={prepared.proposal_id}"
            )

            # Step 2: Publish sealed card to the Council Chamber
            # Use the room from prepare result, or fall back to the message's room
            publish_room = prepared.room_id or room_id
            sealed_message = format_card_message(prepared.sealed_card)

            # Route: recruit Diagnosis + mention it (fail-closed if unconfigured)
            # Suppress: mention Recorder so the audit handoff has a recipient.
            mentions = []
            if decision == "route":
                if not self._diagnosis_agent_id:
                    raise RuntimeError(
                        "[triage] Cannot route: DIAGNOSIS_AGENT_ID not configured. "
                        "Route decision requires a Treasury Intelligence Agent to hand off to."
                    )
                # Dynamically recruit Diagnosis into the room
                await self._add_participant(publish_room, self._diagnosis_agent_id)
                mentions.append(self._diagnosis_agent_id)
            else:
                # Suppress: mention Recorder for proposal-room delivery
                if self._recorder_agent_id:
                    mentions.append(self._recorder_agent_id)
                else:
                    raise RuntimeError(
                        "[triage] Cannot suppress: RECORDER_AGENT_ID not configured. "
                        "Suppress decision requires Recorder to acknowledge."
                    )

            if not mentions:
                raise RuntimeError(
                    "[triage] No mentions resolved for proposal-room publication."
                )

            message_id = await self._post_to_room(
                publish_room, sealed_message, mentions
            )
            logger.info(
                f"[triage] Published sealed TriageDecision to Council Chamber: "
                f"message_id={message_id}, room={publish_room}, "
                f"decision={decision}, mentions={len(mentions)}"
            )

            # Step 3: Confirm (advance state machine: DETECTED → TRIAGED/SUPPRESSED)
            confirmed = await sc.confirm(
                submission_id=prepared.submission_id,
                proposal_id=prepared.proposal_id,
                card_hash=prepared.card_hash,
                message_id=message_id,
                room_id=publish_room,
            )

            submit_latency_ms = (time.monotonic() - start_time) * 1000

            evidence = {
                "submission_id": prepared.submission_id,
                "card_hash": prepared.card_hash,
                "sequence_number": prepared.sequence_number,
                "message_id": message_id,
                "room_id": publish_room,
                "new_state": confirmed.new_state,
                "confirm_status": confirmed.status,
                "submit_latency_ms": round(submit_latency_ms, 1),
            }

            logger.info(
                f"[triage] TriageDecision CONFIRMED: "
                f"state={confirmed.new_state}, "
                f"hash={prepared.card_hash[:16]}..., "
                f"submit_latency={submit_latency_ms:.0f}ms"
            )

            return evidence

    async def process(self, ctx, event, **kwargs):
        """Preprocess incoming room events.

        SDK contract: process(ctx, event, **kwargs) → AgentInput | None
        - Return AgentInput → local runtime invokes the triage callback
        - Return None → event consumed silently
        """
        await self._ensure_default()

        # Only handle MessageEvents (same pattern as Casper Execution Agent preprocessor)
        event_type = type(event).__name__
        if event_type != "MessageEvent":
            return await self._default_preprocessor.process(ctx, event, **kwargs)

        # Access payload (MessageCreatedPayload)
        # Fields are FLAT on the payload — no .message sub-object.
        payload = getattr(event, "payload", None)
        if payload is None:
            return await self._default_preprocessor.process(ctx, event, **kwargs)

        content = getattr(payload, "content", None) or ""
        sender_id = getattr(payload, "sender_id", "") or ""
        sender_type = getattr(payload, "sender_type", "") or ""

        # room_id lives on the event, not the payload (Council Chamber 1.0)
        room_id = getattr(event, "room_id", "") or ""

        # room message ID for idempotency derivation
        room_message_id = getattr(payload, "id", "") or ""

        # Skip self-messages
        if sender_id == self._triage_agent_id:
            return None

        # Try to extract an ProposalCard from the message
        card_data = _extract_sealed_card(content)

        if not card_data:
            # No sealed card — deterministic post-handoff silence.
            # If TriageDecision was already submitted for this room, silently
            # consume non-card Agent messages to prevent chatter loops.
            if room_id and room_id in _handoff_rooms and sender_type == "Agent":
                logger.debug(
                    f"[triage] Post-handoff silence: consuming non-card "
                    f"agent message in room {room_id[:12]}..."
                )
                return None

            # Check freshness for non-sealed chatter
            inserted_at = getattr(payload, "inserted_at", None)
            if should_skip_stale_chatter(str(inserted_at) if inserted_at else None, self._boot_epoch, "triage"):
                return None
            return await self._default_preprocessor.process(ctx, event, **kwargs)

        if card_data.get("card_type") != "ProposalCard":
            # Sealed card but not our type — silent consume if has seal fields
            if has_seal_fields(card_data):
                logger.info(
                    f"[triage] Silently consuming unsupported sealed card "
                    f"{card_data.get('card_type', '?')}"
                )
                return None
            # Card-shaped but no seal fields — reject + log
            logger.warning(
                f"[triage] Card-shaped payload missing seal fields "
                f"(type={card_data.get('card_type', '?')}) — rejected"
            )
            return None

        # ----- Sender Validation -----
        # Only the registered Recorder agent may send ProposalCards.
        # Forged ProposalCards from other participants are rejected.
        if sender_type != "Agent":
            logger.warning(
                f"[triage] REJECTED ProposalCard from non-agent "
                f"sender_type={sender_type!r}, sender_id={sender_id!r}"
            )
            return None

        if not self._recorder_agent_id:
            # Fail-closed: if Recorder ID is not configured, reject ALL ProposalCards.
            # Never trust an ProposalCard when we can't verify the sender.
            logger.error(
                "[triage] REJECTED ProposalCard: RECORDER_AGENT_ID not configured. "
                "Cannot verify sender identity."
            )
            return None

        if sender_id != self._recorder_agent_id:
            logger.warning(
                f"[triage] REJECTED ProposalCard from untrusted agent "
                f"{sender_id!r} — expected Recorder {self._recorder_agent_id!r}"
            )
            return None

        # ----- Seal Field Check -----
        # Structural pre-filter: reject cards missing card_hash/sequence_number.
        # This is NOT cryptographic proof — the Gateway hash chain is the
        # integrity guarantee. This catches raw/unserialized cards.
        if not _has_seal_fields(card_data):
            return None

        # ----- Active Proposal Allowlist (credit protection) -----
        proposal_id = card_data.get("signal_id", "")
        if ACTIVE_PROPOSALS and proposal_id not in ACTIVE_PROPOSALS:
            logger.info(f"[triage] Skipping non-active proposal {proposal_id}")
            return None

        # ----- Stale Card Guard (cost optimization) -----
        # Skip if a higher-seq card is already published for this proposal.
        card_seq = card_data.get("sequence_number")
        if proposal_id and await should_skip_stale_card(proposal_id, card_seq, "triage"):
            return None

        # ----- Pydantic Validation -----
        validated_card = _validate_signal_card(card_data)
        if validated_card is None:
            logger.warning(
                f"[triage] REJECTED malformed ProposalCard from {sender_id[:12]}..."
            )
            return None

        # ----- ProposalCard Processing Pipeline -----
        logger.info(
            f"[triage] Received ProposalCard from Recorder/{sender_id[:12]}...: "
            f"signal_id={card_data.get('signal_id', '?')}, "
            f"severity={card_data.get('preliminary_severity', '?')}, "
            f"security={card_data.get('security_relevant', False)}"
        )

        try:
            pipeline_start = time.monotonic()

            # Step 1: LLM classification
            llm_result = await self._classify_with_llm(card_data)
            logger.info(
                f"[triage] LLM classification: "
                f"decision={llm_result['decision']}, "
                f"noise_score={llm_result['noise_score']}, "
                f"reasoning={llm_result['reasoning'][:80]}"
            )

            # Step 2: Apply deterministic guards
            decision, noise_score, reasoning = _apply_deterministic_guards(
                signal_card=card_data,
                llm_decision=llm_result["decision"],
                llm_noise_score=llm_result["noise_score"],
                llm_reasoning=llm_result["reasoning"],
            )
            logger.info(
                f"[triage] After guards: "
                f"decision={decision}, noise_score={noise_score}"
            )

            # Step 2b: Bounded Suppression Learning
            # P1/security NEVER suppressed (certified safety property)
            preliminary_severity = card_data.get("preliminary_severity", "")
            is_security = card_data.get("security_relevant", False)
            fingerprint = card_data.get("fingerprint", "")

            if (
                decision == "suppress"
                and preliminary_severity != "P1"
                and not is_security
                and fingerprint
            ):
                # Check if a suppression rule exists for this fingerprint
                gw = os.getenv("GATEWAY_URL", "http://localhost:8000")
                triage_key = os.getenv("TRIAGE_SUBMISSION_KEY", "")
                try:
                    async with httpx.AsyncClient(timeout=5) as supp_client:
                        rules_resp = await supp_client.get(
                            f"{gw}/suppression-rules",
                            params={"fingerprint": fingerprint},
                        )
                        rules = rules_resp.json() if rules_resp.status_code == 200 else []

                        if rules:
                            rule = rules[0]  # Use first active rule
                            # Atomic increment — ONLY suppress if 200
                            inc_resp = await supp_client.post(
                                f"{gw}/suppression-rules/{rule['id']}/increment",
                                headers={"X-Agent-Key": triage_key},
                            )
                            if inc_resp.status_code == 200:
                                logger.info(
                                    f"[triage] Suppression rule {rule['id']} matched "
                                    f"(fp={fingerprint[:16]}...) — suppressing"
                                )
                            else:
                                # 409 = exhausted, or error → route normally
                                logger.info(
                                    f"[triage] Suppression rule {rule['id']} exhausted "
                                    f"(status={inc_resp.status_code}) — routing normally"
                                )
                                decision = "route"
                                reasoning = (
                                    f"[SUPPRESSION] Rule {rule['id']} exhausted "
                                    f"(count >= max). Routing normally. "
                                    f"Original: {reasoning}"
                                )
                except Exception as exc:
                    # Suppression lookup failure → route normally (fail-open to safety)
                    logger.warning(
                        "[triage] Suppression lookup failed (%s) — routing normally",
                        type(exc).__name__,
                    )
                    if decision == "suppress":
                        decision = "route"
                        reasoning = f"[SUPPRESSION] Lookup failed — routing. Original: {reasoning}"

            # Step 3: Submit TriageDecision via Gateway
            evidence = await self._submit_triage_decision(
                signal_card=card_data,
                decision=decision,
                noise_score=noise_score,
                reasoning=reasoning,
                room_id=room_id,
                room_message_id=room_message_id,
            )

            pipeline_ms = (time.monotonic() - pipeline_start) * 1000

            logger.info(
                f"[triage] === TRIAGE COMPLETE ===\n"
                f"  Signal: {card_data.get('signal_id', '?')}\n"
                f"  Decision: {decision}\n"
                f"  Noise Score: {noise_score}\n"
                f"  New State: {evidence['new_state']}\n"
                f"  Card Hash: {evidence['card_hash'][:16]}...\n"
                f"  Sequence: {evidence['sequence_number']}\n"
                f"  Pipeline Latency: {pipeline_ms:.0f}ms "
                f"(submit: {evidence['submit_latency_ms']}ms)"
            )

        except Exception as exc:
            logger.error(
                "[triage] Failed to process ProposalCard (%s)",
                type(exc).__name__,
            )
            # Don't crash the agent — swallow and log
            # The signal will remain at DETECTED, and can be retried

        # Mark room for post-handoff silence
        if room_id:
            _handoff_rooms.add(room_id)
            logger.info(
                f"[triage] Marked room {room_id[:12]}... for "
                f"post-handoff silence (proposal {card_data.get('signal_id', '?')})"
            )

        # Consume the message — don't pass ProposalCards to the LLM adapter
        return None


async def create_triage_agent():
    """Create the Triage agent on the Gateway-owned proposal-room runtime."""
    from langchain_openai import ChatOpenAI

    config = MODELS["triage"]

    provider = get_provider_settings()["llm"]

    # LLM: LLM via OpenAI-compatible LLM provider's LLM-compatible endpoint.
    llm = ChatOpenAI(
        model=config.model,
        openai_api_base=provider["api_base"],
        openai_api_key=provider["api_key"],
        streaming=False,
    )

    # Preprocessor: intercepts ProposalCards before the LLM
    triage_agent_id = os.getenv("TRIAGE_AGENT_ID", "")
    triage_api_key = get_agent_api_key("triage")

    # Startup validation: fail fast on misconfiguration
    # (catches before demo, not mid-proposal)
    required_vars = {
        "TRIAGE_AGENT_ID": triage_agent_id,
        "RECORDER_AGENT_ID": os.getenv("RECORDER_AGENT_ID", ""),
        "TRIAGE_SUBMISSION_KEY": os.getenv("TRIAGE_SUBMISSION_KEY", ""),
        "DIAGNOSIS_AGENT_ID": os.getenv("DIAGNOSIS_AGENT_ID", ""),
    }
    missing = [k for k, v in required_vars.items() if not v]
    if missing:
        raise RuntimeError(
            f"Triage agent cannot start: missing required env vars: "
            f"{', '.join(missing)}. Set them in .env before starting."
        )
    logger.info("[triage] Startup validation passed — all required IDs configured")

    preprocessor = TriagePreprocessor(
        llm=llm,
        triage_agent_id=triage_agent_id,
        triage_api_key=triage_api_key,
    )

    agent = LocalRoomAgent(
        role="triage",
        agent_id=triage_agent_id,
        agent_key=triage_api_key,
        preprocessor=preprocessor,
        framework="Council Runtime + LLM",
        model=config.model,
    )

    return agent


async def main():
    logging.basicConfig(level=logging.INFO)
    await run_with_supervisor(create_triage_agent, "triage")


if __name__ == "__main__":
    asyncio.run(main())
