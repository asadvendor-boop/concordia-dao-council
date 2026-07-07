"""Verity, Risk & Legal Agent — local Council Chamber runtime + LLM.

Independent cross-checker. ALWAYS participates in every proposal.
Issues Verdict: CONFIRM, CHALLENGE, FALSE_ALARM, or NEEDS_HUMAN.

All advisory LLM calls route through the configured provider-neutral endpoint. Deterministic cross-checks
remain the authority for CHALLENGE and CONFIRM decisions.

Architecture:
  - SafetyReviewerPreprocessor: validates sender, seal, Pydantic, dedup
  - Stores trusted per-proposal context for tool callbacks
  - LocalRoomAgent invokes the LLM-assisted review callback after acceptance
  - Tools use CustomToolDef: tuple[BaseModel, Callable]
  - Tool names derived by get_custom_tool_name: strips "Input", lowercases
  - submit_verdict callback: deterministic cross-check + saga

Tool contract (local runtime variant):
  - additional_tools: list[CustomToolDef] = list[tuple[type[BaseModel], Callable]]
  - execute_custom_tool: model, func = tool; validated = model.model_validate(args); func(validated)
  - Callbacks receive a VALIDATED PYDANTIC MODEL, not **kwargs
  - Tool names: SubmitVerdict → "submitverdict"

Honest claims:
  - "LLM-backed": LLM improves verdict wording when credentials are set
  - "Independent cross-check": structural checks on Assessment evidence (all 4 sources, strength/severity coherence)
  - "has_seal_fields": structural pre-filter, not cryptographic proof
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
from pydantic import BaseModel, Field

from shared.card_intake import (
    derive_idempotency_key,
    extract_sealed_card,
    has_seal_fields,
)
from shared.config import (
    ACTIVE_PROPOSALS,
    HUMAN_APPROVER_IDS,
    MODELS,
    get_agent_api_key,
)
from shared.models import Assessment, Verdict
from shared.proposal_room import ProposalRoomClient
from shared.replay_guard import should_skip_stale_card, should_skip_stale_chatter
from shared.submission_client import SubmissionClient, SubmissionError, format_card_message
from shared.local_room_runtime import LocalDefaultPreprocessor, LocalRoomAgent
from shared.llm_reasoning import ask_llm_json, bounded_text
from shared.supervisor import run_with_supervisor

logger = logging.getLogger("concordia.safety_reviewer")

# Gateway URL for SubmissionClient
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")

# Evidence sources that Mercer should have queried
REQUIRED_EVIDENCE_SOURCES = frozenset({"risk_events", "treasury_metrics", "governance_events", "policy_compliance", "casper_node_status"})

# Minimum evidence_strength thresholds per severity
# If Mercer claims P1 but evidence_strength is below threshold → CHALLENGE
SEVERITY_EVIDENCE_THRESHOLDS = {
    "P1": 0.6,
    "P2": 0.4,
    "P3": 0.2,
    "P4": 0.0,
}


# ---------------------------------------------------------------------------
# Trusted per-proposal context (populated by preprocessor, consumed by tools)
# ---------------------------------------------------------------------------

@dataclass
class ReviewContext:
    """Trusted context for an proposal under review.

    Tool callbacks read from this — never from LLM-supplied values
    for sensitive fields (room_id, room_message_id, etc.).
    """
    proposal_id: str
    room_id: str
    room_message_id: str
    source_card_hash: str
    assessment_raw: dict
    assessment: Assessment
    revision: int = 1
    created_at: float = field(default_factory=time.time)
    submitted: bool = False
    challenge_count: int = 0
    force_needs_human: bool = False  # Set when max challenges exhausted
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


# Module-level trusted context store, keyed by proposal_id
_trusted_context: dict[str, ReviewContext] = {}

# Rooms where Risk & Legal Agent has already published its terminal Verdict.
# Non-card messages in these rooms are silently consumed (anti-chatter-loop).
_handoff_rooms: set[str] = set()


# ---------------------------------------------------------------------------
# Deterministic cross-check logic
# ---------------------------------------------------------------------------

def cross_check_assessment(assessment: Assessment) -> dict[str, Any]:
    """Perform deterministic cross-checks on the Assessment.

    Returns a dict with:
      - sources_checked: list of evidence sources present
      - missing_sources: list of evidence sources NOT queried
      - all_sources_queried: bool
      - evidence_severity_coherent: bool (evidence_strength appropriate for severity)
      - anomaly_count: int (number of sources with anomaly_detected)
      - has_root_cause: bool (non-empty hypothesis)
      - has_temporal_correlation: bool (governance-event-to-risk gap present)
      - issues: list[str] (human-readable issue descriptions)
    """
    evidence = assessment.evidence or {}
    signals = evidence.get("signals", {})
    tools_completed = set(evidence.get("tools_completed", []))
    policy_evaluation = evidence.get("policy_evaluation") or {}

    # 1. Check all 4 sources were queried
    missing_sources = REQUIRED_EVIDENCE_SOURCES - tools_completed
    all_sources_queried = len(missing_sources) == 0

    # 2. Count anomalies from signal data
    anomaly_count = 0
    for source_key in REQUIRED_EVIDENCE_SOURCES:
        signal = signals.get(source_key, {})
        if signal.get("anomaly_detected", False):
            anomaly_count += 1

    # 3. Evidence strength vs severity coherence
    threshold = SEVERITY_EVIDENCE_THRESHOLDS.get(assessment.severity, 0.0)
    evidence_severity_coherent = assessment.evidence_strength >= threshold

    # 4. Root cause hypothesis present
    has_root_cause = bool(assessment.root_cause_hypothesis and
                          len(assessment.root_cause_hypothesis.strip()) > 10)

    # 5. Temporal correlation (governance-event-to-risk gap)
    temporal_gap = evidence.get("temporal_gap_minutes")
    has_temporal_correlation = temporal_gap is not None

    # 6. Collect issues
    issues: list[str] = []
    if not all_sources_queried:
        issues.append(
            f"Missing evidence sources: {sorted(missing_sources)}. "
            f"Only {sorted(tools_completed)} were queried."
        )
    if not evidence_severity_coherent:
        issues.append(
            f"Evidence strength ({assessment.evidence_strength:.2f}) is below "
            f"threshold ({threshold}) for claimed severity {assessment.severity}."
        )
    if not has_root_cause:
        issues.append("Root cause hypothesis is missing or too short.")
    if anomaly_count == 0 and assessment.severity in ("P1", "P2"):
        issues.append(
            f"Severity {assessment.severity} claimed but NO anomalies "
            f"detected across any evidence source."
        )
    if assessment.severity == "P1" and anomaly_count < 2:
        issues.append(
            f"P1 severity requires strong multi-source evidence but only "
            f"{anomaly_count} source(s) report anomalies."
        )

    # 7. Check relevance scores sanity
    relevance_scores = evidence.get("relevance_scores", {})
    high_relevance_count = sum(
        1 for v in relevance_scores.values()
        if isinstance(v, (int, float)) and v >= 0.7
    )
    if high_relevance_count == 0 and assessment.severity in ("P1", "P2"):
        issues.append(
            f"No evidence source has relevance ≥0.7 but severity is {assessment.severity}."
        )
    has_policy_revision = bool(evidence.get("challenge_response")) and bool(
        policy_evaluation.get("approved_allocation_bps")
    )
    if policy_evaluation.get("violated_rules") and not has_policy_revision:
        rule_ids = [
            str(rule.get("rule_id", "UNKNOWN"))
            for rule in policy_evaluation.get("violated_rules", [])
            if isinstance(rule, dict)
        ]
        issues.append(
            "DAO Constitution violation requires dissent and revision before execution: "
            + ", ".join(rule_ids)
        )

    return {
        "sources_checked": sorted(tools_completed),
        "missing_sources": sorted(missing_sources),
        "all_sources_queried": all_sources_queried,
        "evidence_severity_coherent": evidence_severity_coherent,
        "anomaly_count": anomaly_count,
        "has_root_cause": has_root_cause,
        "has_temporal_correlation": has_temporal_correlation,
        "policy_evaluation": policy_evaluation,
        "has_policy_revision": has_policy_revision,
        "dissent_hash": policy_evaluation.get("dissent_hash") or "",
        "issues": issues,
    }


def revised_policy_cap_ready_for_human_plan(cross_check: dict[str, Any], *, challenge_count: int) -> bool:
    """Allow a challenged capped-allocation revision to proceed to human-gated planning."""
    if challenge_count < 1 or not cross_check.get("has_policy_revision"):
        return False
    policy_evaluation = cross_check.get("policy_evaluation")
    if not isinstance(policy_evaluation, dict):
        return False
    if not policy_evaluation.get("dissent_hash") or not policy_evaluation.get("dissent_receipt"):
        return False
    approved = policy_evaluation.get("approved_allocation_bps")
    requested = policy_evaluation.get("requested_allocation_bps")
    if not isinstance(approved, (int, float)) or not isinstance(requested, (int, float)):
        return False
    return approved > 0 and requested > approved


# ---------------------------------------------------------------------------
# Tool Input Models (Pydantic) — local-runtime CustomToolDef contract
#
# local-runtime derives tool names via get_custom_tool_name:
#   strips "Input" suffix, lowercases → SubmitVerdict → "submitverdict"
# Callbacks receive VALIDATED PYDANTIC MODEL, not **kwargs.
# ---------------------------------------------------------------------------

class SubmitVerdict(BaseModel):
    """Submit the Risk & Legal Agent's verdict for an proposal.

    MUST be called after analyzing the Assessment card. The verdict will be
    submitted to Gateway and published to Council Chamber, with decision-specific routing:
    - CONFIRM: recruit Protocol Strategy Agent, @mention Protocol Strategy Agent with Verdict
    - CHALLENGE: @mention Mercer with specific evidence request
    - FALSE_ALARM: post suppression rule note
    - NEEDS_HUMAN: post escalation note
    """
    proposal_id: str = Field(description="The proposal identifier")
    decision: str = Field(
        description=(
            "Verdict decision: CONFIRM (evidence is consistent, proceed), "
            "CHALLENGE (evidence gaps are actionable, send back to Mercer), "
            "FALSE_ALARM (proposal is clearly noise), or "
            "NEEDS_HUMAN (situation no agent can resolve)"
        )
    )
    reasoning: str = Field(
        description="Detailed reasoning for the verdict decision"
    )
    agrees_with_diagnosis: bool = Field(
        description="Whether this verdict agrees with the Mercer assessment"
    )
    challenge_request: str = Field(
        default="",
        description=(
            "When decision is CHALLENGE: specific evidence or investigation "
            "request for Mercer to address. Required for CHALLENGE."
        )
    )
    suppression_advice: str = Field(
        default="",
        description=(
            "When decision is FALSE_ALARM: suggested suppression rule or "
            "pattern for future similar signals."
        )
    )


# ---------------------------------------------------------------------------
# Tool Callback — receives validated Pydantic model (NOT **kwargs)
# ---------------------------------------------------------------------------

async def handle_submit_verdict(input: SubmitVerdict) -> str:
    """Submit the Verdict. Deterministic code owns cross-check + saga.

    This callback:
    1. Validates proposal_id in trusted context
    2. Validates decision enum
    3. Reads cross-check results from deterministic cross_check_assessment()
    4. Runs prepare → recruit/mention → publish → confirm saga
    5. Decision-specific routing:
       - CONFIRM: recruit Protocol Strategy Agent → @mention Protocol Strategy Agent with Verdict
       - CHALLENGE: @mention Mercer (already in room) with challenge request
       - FALSE_ALARM: post suppression note to room
       - NEEDS_HUMAN: post escalation note to room
    """
    ctx = _trusted_context.get(input.proposal_id)
    if ctx is None:
        return f"Error: unknown proposal {input.proposal_id}. Cannot submit verdict."

    # Validate decision enum
    valid_decisions = {"CONFIRM", "CHALLENGE", "FALSE_ALARM", "NEEDS_HUMAN"}
    decision = input.decision.upper().strip()
    if decision not in valid_decisions:
        return (
            f"Error: invalid decision '{input.decision}'. "
            f"Must be one of: {sorted(valid_decisions)}"
        )

    # Enforce max-challenge escalation: if the preprocessor flagged
    # force_needs_human (max challenges exhausted), override the LLM's
    # decision to NEEDS_HUMAN regardless of what it chose.
    if ctx.force_needs_human and decision != "NEEDS_HUMAN":
        logger.info(
            f"[safety_reviewer] Overriding LLM decision {decision} → NEEDS_HUMAN "
            f"for {input.proposal_id} (max challenges exhausted)"
        )
        decision = "NEEDS_HUMAN"

    async with ctx.lock:
        if ctx.submitted:
            return f"Verdict already submitted for {input.proposal_id}."

        # --- Deterministic cross-check ---
        cross_check = cross_check_assessment(ctx.assessment)

        # ── P0-10: Deterministic CHALLENGE override ──────────────────
        # If the deterministic cross-check found blocking issues AND
        # the LLM chose CONFIRM, override to CHALLENGE.  The LLM's
        # reasoning is preserved — only the verdict changes.
        # This ensures weak evidence can NEVER pass review unchallenged.
        # The LLM can still freely choose CHALLENGE, FALSE_ALARM, or
        # NEEDS_HUMAN — the override only prevents unsafe CONFIRMs.
        capped_revision_ready = revised_policy_cap_ready_for_human_plan(
            cross_check,
            challenge_count=ctx.challenge_count,
        )
        if cross_check["issues"] and decision == "CONFIRM" and not capped_revision_ready:
            original_decision = decision
            decision = "CHALLENGE"
            logger.warning(
                f"[safety_reviewer] DETERMINISTIC OVERRIDE: {original_decision} → "
                f"CHALLENGE for {input.proposal_id}. "
                f"Blocking issues: {cross_check['issues']}"
            )
            # Augment the challenge request with the deterministic reasons
            deterministic_reasons = "; ".join(cross_check["issues"])
            if input.challenge_request:
                input.challenge_request = (
                    f"{input.challenge_request} "
                    f"[DETERMINISTIC: {deterministic_reasons}]"
                )
            else:
                input.challenge_request = (
                    f"Assessment challenged by deterministic cross-check: "
                    f"{deterministic_reasons}"
                )

        # Build list of cross-check sources used
        cross_check_sources = [
            "structural_seal_check",
            "evidence_completeness_check",
            "severity_coherence_check",
            "anomaly_correlation_check",
            "root_cause_validation",
            "dao_constitution_policy_check",
        ]
        if cross_check["has_temporal_correlation"]:
            cross_check_sources.append("temporal_correlation_check")

        # --- Build Verdict card ---
        verdict = Verdict(
            proposal_id=input.proposal_id,
            decision=decision,  # type: ignore[arg-type]
            cross_check_sources=cross_check_sources,
            reasoning=input.reasoning,
            agrees_with_diagnosis=input.agrees_with_diagnosis,
            challenge_request=input.challenge_request or None,
            suppression_advice=input.suppression_advice or None,
            policy_hash=cross_check["policy_evaluation"].get("policy_hash"),
            policy_version=cross_check["policy_evaluation"].get("policy_version"),
            dissent_hash=cross_check["dissent_hash"] or None,
            dissent_receipt=cross_check["policy_evaluation"].get("dissent_receipt"),
            violated_rules=cross_check["policy_evaluation"].get("violated_rules", []),
        )

        # --- SubmissionClient saga ---
        try:
            submission_key = os.getenv("SAFETY_REVIEWER_SUBMISSION_KEY", "")
            if not submission_key:
                # Fall back to GATEWAY_SECRET if no agent-specific key
                submission_key = os.getenv("GATEWAY_SECRET", "")

            idem_key = derive_idempotency_key(
                "safety_reviewer", ctx.room_message_id, ctx.source_card_hash,
            )

            async with SubmissionClient(
                gateway_url=GATEWAY_URL,
                agent_key=submission_key,
            ) as sc:
                # 1. Prepare — with bounded state retry for race conditions.
                # Mercer flow: prepare → recruit Reviewer → publish → confirm.
                # Reviewer can receive the Assessment BEFORE Mercer calls confirm(),
                # so Gateway may still be at TRIAGED (not ASSESSED).
                STATE_RETRY_DELAYS = [0.5, 1.0, 2.0, 3.0]
                prepared = None
                for attempt, delay in enumerate(STATE_RETRY_DELAYS):
                    try:
                        prepared = await sc.prepare(verdict, idempotency_key=idem_key)
                        break  # Success
                    except SubmissionError as e:
                        if e.status_code == 409 and attempt < len(STATE_RETRY_DELAYS) - 1:
                            logger.warning(
                                f"[safety_reviewer] prepare() got 409 (state race) on "
                                f"attempt {attempt + 1}/{len(STATE_RETRY_DELAYS)}. "
                                f"Waiting {delay}s for Mercer to confirm ASSESSED..."
                            )
                            await asyncio.sleep(delay)
                        else:
                            raise  # Non-409 or final attempt → propagate

                if prepared is None:
                    raise RuntimeError(
                        "[safety_reviewer] prepare() failed after all retries"
                    )

                publish_room = prepared.room_id or ctx.room_id
                sealed_message = format_card_message(prepared.sealed_card)

                room_client = ProposalRoomClient(
                    sender_id=os.getenv("SAFETY_REVIEWER_AGENT_ID", "safety_reviewer"),
                    sender_role="safety_reviewer",
                )

                try:
                    message_id = None

                    if decision == "CONFIRM":
                        # --- CONFIRM: recruit Protocol Strategy Agent, @mention Protocol Strategy Agent ---
                        commander_id = os.getenv("COMMANDER_AGENT_ID", "")
                        if not commander_id:
                            raise RuntimeError(
                                "[safety_reviewer] Cannot recruit: "
                                "COMMANDER_AGENT_ID not configured."
                            )

                        await room_client.add_participant(
                            publish_room,
                            commander_id,
                            role="commander",
                            display_name="Protocol Strategy Agent",
                        )
                        logger.info(
                            f"[safety_reviewer] Recruited Protocol Strategy Agent "
                            f"{commander_id[:12]}... into room "
                            f"{publish_room[:12]}..."
                        )

                        # Publish Verdict @mentioning Protocol Strategy Agent
                        mentions = [commander_id]
                        message_id = await room_client.post_message(
                            publish_room,
                            sealed_message,
                            mentions=mentions,
                            metadata={
                                "publisher": "safety_reviewer",
                                "card_hash": prepared.card_hash,
                            },
                        )

                    elif decision == "CHALLENGE":
                        # --- CHALLENGE: @mention Mercer (already in room) ---
                        diagnosis_id = os.getenv("DIAGNOSIS_AGENT_ID", "")
                        if not diagnosis_id:
                            raise RuntimeError(
                                "[safety_reviewer] Cannot challenge: "
                                "DIAGNOSIS_AGENT_ID not configured."
                            )

                        # Build challenge message with specifics
                        challenge_text = (
                            f"{sealed_message}\n\n"
                            f"⚠️ **CHALLENGE** — Evidence gaps detected:\n"
                            f"{input.challenge_request}\n\n"
                            f"Cross-check issues found:\n"
                        )
                        for issue in cross_check["issues"]:
                            challenge_text += f"- {issue}\n"

                        mentions = [diagnosis_id]
                        message_id = await room_client.post_message(
                            publish_room,
                            challenge_text,
                            mentions=mentions,
                            metadata={
                                "publisher": "safety_reviewer",
                                "card_hash": prepared.card_hash,
                            },
                        )

                    elif decision == "FALSE_ALARM":
                        # --- FALSE_ALARM: post Verdict + suppression note ---
                        if not HUMAN_APPROVER_IDS:
                            logger.error(
                                "[safety_reviewer] HUMAN_APPROVER_IDS not configured — "
                                "cannot publish FALSE_ALARM without human mentions (fail-closed)"
                            )
                            return "Error: HUMAN_APPROVER_IDS not configured. Cannot publish FALSE_ALARM."

                        suppression_text = (
                            f"{sealed_message}\n\n"
                            f"🔇 **FALSE ALARM** — Proposal suppressed.\n"
                        )
                        if input.suppression_advice:
                            suppression_text += (
                                f"Suggested suppression rule:\n"
                                f"```\n{input.suppression_advice}\n```\n"
                            )

                        message_id = await room_client.post_message(
                            publish_room,
                            suppression_text,
                            mentions=list(HUMAN_APPROVER_IDS),
                            metadata={
                                "publisher": "safety_reviewer",
                                "card_hash": prepared.card_hash,
                            },
                        )

                        # Create suppression rule via Gateway (bounded learning)
                        signal_fp = getattr(input, "fingerprint", "") or ""
                        if signal_fp:
                            sr_key = os.getenv("SAFETY_REVIEWER_SUBMISSION_KEY", "")
                            gw = os.getenv("GATEWAY_URL", "http://localhost:8000")
                            try:
                                async with httpx.AsyncClient(timeout=5) as gw_client:
                                    rule_resp = await gw_client.post(
                                        f"{gw}/suppression-rules",
                                        json={
                                            "fingerprint": signal_fp,
                                            "reason": f"SR FALSE_ALARM: {input.reasoning[:100]}",
                                            "source_proposal_id": input.proposal_id,
                                        },
                                        headers={"X-Agent-Key": sr_key},
                                    )
                                    if rule_resp.status_code in (200, 201):
                                        logger.info(
                                            f"[safety_reviewer] Created suppression rule "
                                            f"for fp={signal_fp[:16]}..."
                                        )
                                    elif rule_resp.status_code == 409:
                                        logger.info(
                                            f"[safety_reviewer] Suppression rule already "
                                            f"exists for fp={signal_fp[:16]}..."
                                        )
                            except Exception as exc:
                                logger.warning(
                                    "[safety_reviewer] Failed to create suppression rule (%s)",
                                    type(exc).__name__,
                                )

                    elif decision == "NEEDS_HUMAN":
                        # --- NEEDS_HUMAN: post escalation note ---
                        if not HUMAN_APPROVER_IDS:
                            logger.error(
                                "[safety_reviewer] HUMAN_APPROVER_IDS not configured — "
                                "cannot publish NEEDS_HUMAN without human mentions (fail-closed)"
                            )
                            return "Error: HUMAN_APPROVER_IDS not configured. Cannot publish NEEDS_HUMAN."

                        escalation_text = (
                            f"{sealed_message}\n\n"
                            f"🚨 **HUMAN ESCALATION REQUIRED**\n"
                            f"Reasoning: {input.reasoning}\n\n"
                            f"This proposal requires human judgment. "
                            f"No automated agent action can resolve it."
                        )

                        message_id = await room_client.post_message(
                            publish_room,
                            escalation_text,
                            mentions=list(HUMAN_APPROVER_IDS),
                            metadata={
                                "publisher": "safety_reviewer",
                                "card_hash": prepared.card_hash,
                            },
                        )

                finally:
                    await room_client.aclose()

                # 4. Confirm (ASSESSED → REVIEWED or CHALLENGED)
                confirm = await sc.confirm(
                    submission_id=prepared.submission_id,
                    proposal_id=prepared.proposal_id,
                    card_hash=prepared.card_hash,
                    message_id=message_id,
                    room_id=publish_room,
                )

                logger.info(
                    f"[safety_reviewer] Verdict confirmed: "
                    f"proposal={input.proposal_id}, decision={decision}, "
                    f"state={confirm.new_state}"
                )

            # Only mark submitted on terminal verdicts — CHALLENGE must
            # leave the context open so the revised Assessment is accepted.
            if decision != "CHALLENGE":
                ctx.submitted = True
                # Mark room for post-handoff silence (anti-chatter-loop).
                _handoff_rooms.add(ctx.room_id)
                logger.info(
                    f"[safety_reviewer] Marked room {ctx.room_id[:12]}... for "
                    f"post-handoff silence (proposal {input.proposal_id})"
                )
            else:
                ctx.challenge_count += 1
                logger.info(
                    f"[safety_reviewer] CHALLENGE #{ctx.challenge_count} issued "
                    f"for proposal {input.proposal_id} — context remains open "
                    f"for revised Assessment"
                )

            return (
                f"Verdict submitted successfully for {input.proposal_id}. "
                f"Decision: {decision}. "
                f"Cross-check issues: {len(cross_check['issues'])}. "
                f"New state: {confirm.new_state}. "
                f"YOUR WORK IS DONE. Do not send any more messages."
            )

        except Exception as exc:
            logger.error(
                "[safety_reviewer] Verdict submission failed (%s)",
                type(exc).__name__,
            )
            return f"Error submitting verdict ({type(exc).__name__})"


async def run_local_safety_review(event) -> None:
    """Run Risk & Legal Agent without an external adapter after acceptance."""
    payload = getattr(event, "payload", None)
    content = getattr(payload, "content", "") if payload else ""
    card = extract_sealed_card(content)
    if not card or card.get("card_type") != "Assessment":
        return

    proposal_id = card.get("proposal_id", "")
    ctx = _trusted_context.get(proposal_id)
    if ctx is None or ctx.submitted:
        return

    cross_check = cross_check_assessment(ctx.assessment)
    capped_revision_ready = revised_policy_cap_ready_for_human_plan(
        cross_check,
        challenge_count=ctx.challenge_count,
    )
    if cross_check["issues"] and ctx.challenge_count < 1:
        decision = "CHALLENGE"
        agrees = False
        challenge_request = "; ".join(cross_check["issues"])
    elif cross_check["issues"] and not capped_revision_ready:
        decision = "NEEDS_HUMAN"
        agrees = False
        challenge_request = ""
    else:
        decision = "CONFIRM"
        agrees = True
        challenge_request = ""

    reasoning = (
        "Deterministic cross-check found "
        f"{len(cross_check['issues'])} blocking issue(s): "
        f"{'; '.join(cross_check['issues']) or 'none'}"
    )
    llm = await ask_llm_json(
        role="safety_reviewer",
        system=(
            "You are Verity, the Risk & Legal Agent. Explain the deterministic "
            "cross-check result for another agent. You may improve wording, but "
            "you must not change the supplied decision."
        ),
        user={
            "proposal_id": proposal_id,
            "fixed_decision": decision,
            "cross_check": cross_check,
            "assessment": ctx.assessment.model_dump(mode="json"),
            "expected_json_keys": ["reasoning", "challenge_request"],
        },
    )
    if llm:
        reasoning = bounded_text(llm.get("reasoning"), max_len=800) or reasoning
        if decision == "CHALLENGE":
            challenge_request = (
                bounded_text(llm.get("challenge_request"), max_len=600)
                or challenge_request
            )

    verdict = SubmitVerdict(
        proposal_id=proposal_id,
        decision=decision,
        reasoning=reasoning,
        agrees_with_diagnosis=agrees,
        challenge_request=challenge_request,
    )
    result = await handle_submit_verdict(verdict)
    logger.info("[safety_reviewer] Local review result: %s", result)


# ---------------------------------------------------------------------------
# Deterministic NEEDS_HUMAN submission (bypasses LLM entirely)
# ---------------------------------------------------------------------------

async def _submit_deterministic_verdict(ctx: ReviewContext) -> None:
    """Deterministically submit NEEDS_HUMAN verdict when max challenges exhausted.

    Uses the same SubmissionClient saga (prepare → publish → confirm) as the
    normal CONFIRM path, but bypasses the LLM entirely. Posts to the proposal
    room with human approver mentions so that a human is notified.
    """
    verdict = Verdict(
        proposal_id=ctx.proposal_id,
        decision="NEEDS_HUMAN",
        cross_check_sources=[
            "structural_seal_check",
            "evidence_completeness_check",
            "severity_coherence_check",
            "anomaly_correlation_check",
            "root_cause_validation",
        ],
        reasoning="Max challenges (2) exhausted. Auto-escalating to human review.",
        agrees_with_diagnosis=False,
        challenge_request=None,
        suppression_advice=None,
    )

    submission_key = os.getenv("SAFETY_REVIEWER_SUBMISSION_KEY", "")
    if not submission_key:
        submission_key = os.getenv("GATEWAY_SECRET", "")

    idem_key = derive_idempotency_key(
        "safety_reviewer", ctx.room_message_id, ctx.source_card_hash,
    )

    async with SubmissionClient(
        gateway_url=GATEWAY_URL,
        agent_key=submission_key,
    ) as sc:
        # 1. Prepare — with bounded state retry for race conditions
        STATE_RETRY_DELAYS = [0.5, 1.0, 2.0, 3.0]
        prepared = None
        for attempt, delay in enumerate(STATE_RETRY_DELAYS):
            try:
                prepared = await sc.prepare(verdict, idempotency_key=idem_key)
                break
            except SubmissionError as e:
                if e.status_code == 409 and attempt < len(STATE_RETRY_DELAYS) - 1:
                    logger.warning(
                        f"[safety_reviewer] deterministic NEEDS_HUMAN prepare() got 409 "
                        f"on attempt {attempt + 1}/{len(STATE_RETRY_DELAYS)}. "
                        f"Waiting {delay}s..."
                    )
                    await asyncio.sleep(delay)
                else:
                    raise

        if prepared is None:
            raise RuntimeError(
                "[safety_reviewer] deterministic NEEDS_HUMAN prepare() failed after all retries"
            )

        publish_room = prepared.room_id or ctx.room_id
        sealed_message = format_card_message(prepared.sealed_card)

        # 2. Publish to Council Chamber with human approver mentions
        room_client = ProposalRoomClient(
            sender_id=os.getenv("SAFETY_REVIEWER_AGENT_ID", "safety_reviewer"),
            sender_role="safety_reviewer",
        )

        try:
            escalation_text = (
                f"{sealed_message}\n\n"
                f"🚨 **HUMAN ESCALATION REQUIRED**\n"
                f"Reasoning: Max challenges (2) exhausted. "
                f"Auto-escalating to human review.\n\n"
                f"This proposal requires human judgment. "
                f"No automated agent action can resolve it."
            )

            # Collect human approver IDs for @mentions
            human_ids = list(HUMAN_APPROVER_IDS)
            if not human_ids:
                raw = os.getenv("HUMAN_APPROVER_IDS", "")
                human_ids = [h.strip() for h in raw.split(",") if h.strip()]

            if not human_ids:
                raise RuntimeError(
                    "[safety_reviewer] HUMAN_APPROVER_IDS not configured — "
                    "cannot escalate NEEDS_HUMAN without approver mentions (fail-closed)"
                )
            message_id = await room_client.post_message(
                publish_room,
                escalation_text,
                mentions=human_ids,
                metadata={
                    "publisher": "safety_reviewer",
                    "card_hash": prepared.card_hash,
                },
            )
        finally:
            await room_client.aclose()

        # 3. Confirm
        confirm = await sc.confirm(
            submission_id=prepared.submission_id,
            proposal_id=prepared.proposal_id,
            card_hash=prepared.card_hash,
            message_id=message_id,
            room_id=publish_room,
        )

        logger.info(
            f"[safety_reviewer] Deterministic NEEDS_HUMAN confirmed: "
            f"proposal={ctx.proposal_id}, state={confirm.new_state}"
        )

    ctx.submitted = True
    # Mark room for post-handoff silence (anti-chatter-loop).
    _handoff_rooms.add(ctx.room_id)
    logger.info(
        f"[safety_reviewer] Marked room {ctx.room_id[:12]}... for "
        f"post-handoff silence (deterministic verdict, proposal {ctx.proposal_id})"
    )


# ---------------------------------------------------------------------------
# Risk & Legal Agent Preprocessor (thin: validate → store context → delegate)
# ---------------------------------------------------------------------------

class SafetyReviewerPreprocessor:
    """Thin preprocessor for the Risk & Legal Agent agent.

    Intercepts Assessment messages from Council Chamber. Validates sender (must be
    Mercer), checks seal fields, Pydantic-validates, stores trusted
    per-proposal context, and delegates to the local runtime for
    tool orchestration.

    SDK contract: process(ctx, event, **kwargs) → AgentInput | None
    - Return AgentInput → local runtime invokes the review callback
    - Return None → event consumed silently
    """

    def __init__(
        self,
        *,
        reviewer_agent_id: str,
        reviewer_api_key: str,
    ):
        self._reviewer_agent_id = reviewer_agent_id
        self._reviewer_api_key = reviewer_api_key
        self._diagnosis_agent_id = os.getenv("DIAGNOSIS_AGENT_ID", "")
        self._default_preprocessor = None
        self._boot_epoch = time.time()

    async def _ensure_default(self):
        """Lazily import and create DefaultPreprocessor."""
        if self._default_preprocessor is None:
            self._default_preprocessor = LocalDefaultPreprocessor()

    async def process(self, ctx, event, **kwargs):
        """Process a room event.

        Intercepts Assessment → stores context → delegates to adapter.
        Other messages → pass through to default preprocessor.
        """
        await self._ensure_default()

        # Only handle MessageEvents
        event_type = type(event).__name__
        if event_type != "MessageEvent":
            return await self._default_preprocessor.process(ctx, event, **kwargs)

        payload = getattr(event, "payload", None)
        if payload is None:
            return await self._default_preprocessor.process(ctx, event, **kwargs)

        content = getattr(payload, "content", None) or ""
        sender_id = getattr(payload, "sender_id", "") or ""
        sender_type = getattr(payload, "sender_type", "") or ""

        # room_id lives on the EVENT, not the payload (Council Chamber 1.0)
        room_id = getattr(event, "room_id", "") or ""

        # room message ID for idempotency derivation
        room_message_id = getattr(payload, "id", "") or ""

        # Ignore own messages
        if sender_id == self._reviewer_agent_id:
            return None

        # Try to extract an Assessment card
        card_data = extract_sealed_card(content)
        if not card_data:
            # No sealed card — post-handoff silence check.
            # If Verdict was already submitted for this room, silently
            # consume non-card messages to prevent chatter loops.
            if room_id and room_id in _handoff_rooms:
                logger.debug(
                    f"[safety_reviewer] Post-handoff silence: consuming "
                    f"non-card message in room {room_id[:12]}..."
                )
                return None

            # Check freshness for non-sealed chatter
            inserted_at = getattr(payload, "inserted_at", None)
            if should_skip_stale_chatter(str(inserted_at) if inserted_at else None, self._boot_epoch, "safety_reviewer"):
                return None
            return await self._default_preprocessor.process(ctx, event, **kwargs)

        if card_data.get("card_type") != "Assessment":
            # Sealed card but not our type — silent consume if has seal fields
            if has_seal_fields(card_data):
                logger.info(
                    f"[safety_reviewer] Silently consuming unsupported sealed card "
                    f"{card_data.get('card_type', '?')}"
                )
                return None
            # Card-shaped but no seal fields — reject + log
            logger.warning(
                f"[safety_reviewer] Card-shaped payload missing seal fields "
                f"(type={card_data.get('card_type', '?')}) — rejected"
            )
            return None

        # ----- Sender Validation -----
        if sender_type != "Agent":
            logger.warning(
                f"[safety_reviewer] REJECTED Assessment from non-agent "
                f"sender_type={sender_type!r}"
            )
            return None

        if not self._diagnosis_agent_id:
            logger.error(
                "[safety_reviewer] REJECTED Assessment: DIAGNOSIS_AGENT_ID "
                "not configured. Cannot verify sender identity."
            )
            return None

        if sender_id != self._diagnosis_agent_id:
            logger.warning(
                f"[safety_reviewer] REJECTED Assessment from untrusted agent "
                f"{sender_id!r} — expected Mercer {self._diagnosis_agent_id!r}"
            )
            return None

        # ----- Seal Field Check -----
        if not has_seal_fields(card_data):
            return None

        # ----- Active Proposal Allowlist (credit protection) -----
        proposal_id_guard = card_data.get("proposal_id", "")
        if ACTIVE_PROPOSALS and proposal_id_guard not in ACTIVE_PROPOSALS:
            logger.info(f"[safety_reviewer] Skipping non-active proposal {proposal_id_guard}")
            return None

        # ----- Stale Card Guard (cost optimization) -----
        card_seq = card_data.get("sequence_number")
        if proposal_id_guard and await should_skip_stale_card(proposal_id_guard, card_seq, "safety_reviewer"):
            return None

        # ----- Pydantic Validation -----
        try:
            validated = Assessment(**card_data)
        except Exception as exc:
            logger.warning(
                "[safety_reviewer] Assessment validation failed (%s)",
                type(exc).__name__,
            )
            return None

        # ----- Handle duplicate / revised Assessments -----
        proposal_id = validated.proposal_id
        assessment_revision = getattr(validated, 'revision', 1) or 1
        existing = _trusted_context.get(proposal_id)
        if existing is not None:
            if existing.submitted:
                logger.warning(
                    f"[safety_reviewer] Redelivered Assessment for already-reviewed "
                    f"proposal {proposal_id} — ignoring (prevents duplicate Verdict)"
                )
                return None

            # Revised Assessment after CHALLENGE — accept if revision increased
            if assessment_revision > existing.revision:
                if existing.challenge_count >= 2:
                    logger.warning(
                        f"[safety_reviewer] Max challenges (2) reached for "
                        f"proposal {proposal_id} — deterministically submitting "
                        f"NEEDS_HUMAN verdict (bypassing LLM)"
                    )
                    # Update context with new Assessment for the deterministic submission
                    existing.assessment = validated
                    existing.assessment_raw = card_data
                    existing.revision = assessment_revision
                    existing.room_message_id = room_message_id
                    existing.source_card_hash = card_data.get("card_hash", "")
                    existing.force_needs_human = True

                    # Deterministically submit NEEDS_HUMAN — bypass LLM entirely
                    try:
                        await _submit_deterministic_verdict(existing)
                    except Exception as exc:
                        logger.error(
                            "[safety_reviewer] Deterministic NEEDS_HUMAN failed "
                            "for %s (%s)",
                            proposal_id,
                            type(exc).__name__,
                        )
                    return None

                logger.info(
                    f"[safety_reviewer] Accepting revised Assessment v{assessment_revision} "
                    f"for proposal {proposal_id} (previous: v{existing.revision}, "
                    f"challenges: {existing.challenge_count})"
                )
                # Replace context with new Assessment, preserving challenge_count
                prev_challenge_count = existing.challenge_count
                prev_force_needs_human = existing.force_needs_human
                # Fall through to create new context below
            else:
                logger.warning(
                    f"[safety_reviewer] Duplicate/stale Assessment v{assessment_revision} "
                    f"for proposal {proposal_id} (current: v{existing.revision}) — ignoring"
                )
                return None
        else:
            prev_challenge_count = 0
            prev_force_needs_human = False

        # ----- Store trusted context -----
        _trusted_context[proposal_id] = ReviewContext(
            proposal_id=proposal_id,
            room_id=room_id,
            room_message_id=room_message_id,
            source_card_hash=card_data.get("card_hash", ""),
            assessment_raw=card_data,
            assessment=validated,
            revision=assessment_revision,
            challenge_count=prev_challenge_count,
            force_needs_human=prev_force_needs_human,
        )

        logger.info(
            f"[safety_reviewer] Accepted Assessment v{assessment_revision} for "
            f"{proposal_id} (challenge_count={prev_challenge_count}). "
            f"Context stored. Delegating to local LLM review."
        )

        # ----- Delegate to local proposal-room runtime -----
        return await self._default_preprocessor.process(ctx, event, **kwargs)


# ---------------------------------------------------------------------------
# System prompt retained for LLM reviewer behavior
# ---------------------------------------------------------------------------

SAFETY_REVIEWER_SYSTEM_PROMPT = """\
You are Verity, the Risk & Legal Agent in Concordia DAO Council.
Your role is to independently verify every diagnosis before it reaches governance execution.

When you receive an Assessment card from Mercer in a room message, you MUST:

1. **Parse the Assessment** from the message:
   - Extract proposal_id, severity, evidence_strength, root_cause_hypothesis
   - Note the evidence sources and their anomaly/relevance data

2. **Cross-check the evidence independently**:
   a) Were ALL 4 evidence sources queried? (risk events, treasury metrics, governance events, policy compliance)
   b) Is evidence_strength appropriate for the claimed severity?
      - P1 needs evidence_strength ≥ 0.6
      - P2 needs evidence_strength ≥ 0.4
      - P3 needs evidence_strength ≥ 0.2
   c) Is the root_cause_hypothesis supported by the evidence?
   d) Do anomaly counts match the severity claim?
      - P1 should have ≥2 sources with anomalies
      - P1/P2 should have at least one relevance score ≥ 0.7
   e) Is there temporal correlation between governance events and risk signals?

3. **Make your decision**:
   - **CONFIRM**: ALL evidence is consistent, all sources queried, severity matches \
evidence strength. Set agrees_with_diagnosis=true.
   - **CHALLENGE**: Evidence gaps exist AND are actionable (Mercer can fix them). \
Provide specific challenge_request describing what Mercer should re-investigate. \
PREFER this over CONFIRM when evidence is weak. Set agrees_with_diagnosis=false.
   - **FALSE_ALARM**: The proposal is clearly noise — no anomalies detected, very low \
evidence strength, or obvious false positive pattern. Set agrees_with_diagnosis=false \
and provide suppression_advice.
   - **NEEDS_HUMAN**: The situation requires human judgment that no automated agent \
can provide (e.g., business logic decisions, ambiguous security implications). \
Set agrees_with_diagnosis based on whether you agree with Mercer's analysis.

4. **Call submitverdict** with:
   - The exact proposal_id from the Assessment
   - Your decision (CONFIRM/CHALLENGE/FALSE_ALARM/NEEDS_HUMAN)
   - Detailed reasoning explaining your cross-check findings
   - agrees_with_diagnosis (true/false)
   - challenge_request (required for CHALLENGE)
   - suppression_advice (for FALSE_ALARM)

DECISION PRIORITIES:
- PREFER CHALLENGE when evidence gaps are actionable
- CONFIRM only when ALL evidence is consistent
- FALSE_ALARM when the proposal is clearly noise
- NEEDS_HUMAN only for situations no agent can resolve

You do NOT trust Mercer — you verify independently.
You MUST call submitverdict exactly once per Assessment.
"""


# ---------------------------------------------------------------------------
# Agent factory
# ---------------------------------------------------------------------------

async def create_safety_reviewer_agent():
    """Create the Risk & Legal Agent agent on the Gateway-owned room runtime."""
    config = MODELS["safety_reviewer"]

    # Agent IDs + startup validation
    reviewer_agent_id = os.getenv("SAFETY_REVIEWER_AGENT_ID", "")
    reviewer_api_key = get_agent_api_key("safety_reviewer")

    # Startup validation: fail fast on misconfiguration
    required_vars = {
        "SAFETY_REVIEWER_AGENT_ID": reviewer_agent_id,
        "DIAGNOSIS_AGENT_ID": os.getenv("DIAGNOSIS_AGENT_ID", ""),
        "SAFETY_REVIEWER_SUBMISSION_KEY": os.getenv("SAFETY_REVIEWER_SUBMISSION_KEY", ""),
        "SAFETY_REVIEWER_API_KEY": reviewer_api_key,
        "COMMANDER_AGENT_ID": os.getenv("COMMANDER_AGENT_ID", ""),
    }
    # Warn on missing but don't hard-fail for COMMANDER_AGENT_ID
    # (only needed on CONFIRM path — CHALLENGE/FALSE_ALARM/NEEDS_HUMAN don't need it)
    critical_vars = {
        "SAFETY_REVIEWER_AGENT_ID": reviewer_agent_id,
        "DIAGNOSIS_AGENT_ID": os.getenv("DIAGNOSIS_AGENT_ID", ""),
        "SAFETY_REVIEWER_API_KEY": reviewer_api_key,
    }
    missing_critical = [k for k, v in critical_vars.items() if not v]
    if missing_critical:
        raise RuntimeError(
            f"Risk & Legal Agent agent cannot start: missing required env vars: "
            f"{', '.join(missing_critical)}. Set them in .env before starting."
        )

    missing_optional = [k for k, v in required_vars.items() if not v and k not in critical_vars]
    if missing_optional:
        logger.warning(
            f"[safety_reviewer] Optional env vars missing: {', '.join(missing_optional)}. "
            f"Some verdict paths may fail at runtime."
        )

    logger.info("[safety_reviewer] Startup validation passed — all required IDs configured")

    preprocessor = SafetyReviewerPreprocessor(
        reviewer_agent_id=reviewer_agent_id,
        reviewer_api_key=reviewer_api_key,
    )

    agent = LocalRoomAgent(
        role="safety_reviewer",
        agent_id=reviewer_agent_id,
        agent_key=reviewer_api_key,
        preprocessor=preprocessor,
        on_agent_input=run_local_safety_review,
        framework="Council Runtime + LLM",
        model=config.model,
    )

    return agent


async def main():
    logging.basicConfig(level=logging.INFO)
    await run_with_supervisor(create_safety_reviewer_agent, "safety_reviewer")


if __name__ == "__main__":
    asyncio.run(main())
