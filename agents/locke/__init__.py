"""Locke, Casper Execution Agent — local Council Chamber runtime + LLM.

Independently validates approval via custom Preprocessor before
executing any governance execution. The Preprocessor is a deterministic security
filter — unauthorized execution never reaches the execution path.

The LLM handles audit explanations and non-approval messages.

Execution tools:
- execute_governance_execution: submit the approved Casper governance receipt
- submit_action_receipt: seal and publish the CasperExecutionReceipt card
"""
from __future__ import annotations

from collections import Counter

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

from shared.config import (
    ACTIVE_PROPOSALS,
    HUMAN_APPROVER_IDS,
    MODELS,
    get_agent_api_key,
    get_agent_ids,
)
from shared.card_intake import derive_idempotency_key, extract_sealed_card
from shared.models import ActionReceipt
from shared.casper_executor import build_receipt_request, submit_governance_receipt
from shared.governance_archive import build_governance_archive
from shared.proposal_room import ProposalRoomClient
from shared.replay_guard import should_skip_stale_chatter
from shared.submission_client import SubmissionClient, format_card_message
from shared.local_room_runtime import LocalDefaultPreprocessor, LocalRoomAgent
from shared.llm_reasoning import ask_llm_json, bounded_text
from shared.supervisor import run_with_supervisor

logger = logging.getLogger("concordia.operator")

# Gateway URL
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")


# ---------------------------------------------------------------------------
# Execution context — tracks authorized actions per proposal
# ---------------------------------------------------------------------------

@dataclass
class ExecutionContext:
    """Tracks approved execution for an proposal."""
    proposal_id: str
    authorization_type: str  # "human_approval" or "policy"
    authorization_id: str
    plan_hash: str
    action_hash: str
    envelopes: list[dict] = field(default_factory=list)
    actions_taken: list[dict] = field(default_factory=list)
    # Canonical action keys currently executing.  Added before the first await
    # so concurrent duplicate tool calls are rejected before side effects.
    in_flight_actions: set[tuple[str, str, str]] = field(default_factory=set)
    timeline: list[dict] = field(default_factory=list)
    room_id: str = ""
    room_message_id: str = ""
    started_at: float = field(default_factory=time.time)

_execution_contexts: dict[str, ExecutionContext] = {}


async def _consume_authorization_with_retry(
    authorization_id: str,
    proposal_id: str,
    *,
    max_retries: int = 3,
    backoff_schedule: tuple[float, ...] = (0.5, 1.0, 2.0),
) -> dict | None:
    """Consume an authorization from Gateway, with bounded retry on 409.

    The PENDING→PUBLISHED race: if Gateway's _publish_and_advance hasn't
    committed the status flip before the Casper Execution Agent reacts to the room message,
    the Casper Execution Agent gets 409 authorization_pending. Bounded retry resolves this.

    Returns:
        dict with authorization data on success, None on failure.
    """
    import asyncio

    gateway_url = os.getenv("GATEWAY_URL", "http://localhost:8000")
    operator_key = os.getenv(
        "OPERATOR_SUBMISSION_KEY",
        os.getenv("GATEWAY_SECRET", ""),
    )

    last_detail = ""
    for attempt in range(max_retries + 1):
        try:
            async with httpx.AsyncClient(timeout=10.0) as http:
                resp = await http.post(
                    f"{gateway_url}/api/authorization/{authorization_id}/consume",
                    json={"proposal_id": proposal_id},
                    headers={"X-Agent-Key": operator_key},
                )

            if resp.status_code == 200:
                return resp.json()

            try:
                detail = str(resp.json().get("detail", ""))
            except ValueError:
                detail = ""
            last_detail = f"HTTP {resp.status_code}"

            # Retry ONLY on 409 authorization_pending
            if resp.status_code == 409 and "authorization_pending" in detail.lower():
                if attempt < max_retries:
                    wait = backoff_schedule[min(attempt, len(backoff_schedule) - 1)]
                    logger.info(
                        f"[operator] Authorization {authorization_id} is PENDING "
                        f"(attempt {attempt + 1}/{max_retries + 1}). "
                        f"Retrying in {wait}s..."
                    )
                    await asyncio.sleep(wait)
                    continue

            # All other failures are immediate fail-closed
            logger.warning(
                "[operator] Authorization consume failed (%s); rejecting fail-closed",
                last_detail,
            )
            return None

        except Exception as exc:
            logger.error(
                "[operator] Authorization consume exception (%s); rejecting fail-closed",
                type(exc).__name__,
            )
            return None

    # Exhausted retries
    logger.warning(
        f"[operator] Authorization {authorization_id} still PENDING after "
        f"{max_retries + 1} attempts ({last_detail}). Rejecting (fail-closed)."
    )
    return None


# ---------------------------------------------------------------------------
# Execution tools used by the local proposal-room runtime.
# ---------------------------------------------------------------------------

ALLOWED_ACTIONS = frozenset({
    "execute_casper_governance_receipt",
})


def _canonical_action_key(
    action_id: str,
    target: str,
    parameters: dict,
) -> tuple[str, str, str]:
    """Return a stable key for exact-envelope and duplicate checks."""
    return (
        action_id,
        target,
        json.dumps(parameters, sort_keys=True, separators=(",", ":")),
    )


async def _perform_governance_execution_action(
    *,
    ctx: ExecutionContext,
    proposal_id: str,
    action_id: str,
    target: str,
    parameters: dict,
) -> dict:
    """Perform one allowlisted governance action and return a sanitized result."""
    start = time.time()
    result: dict = {
        "action_id": action_id,
        "target": target,
        "parameters": parameters,
        "status": "unknown",
    }

    try:
        if action_id != "execute_casper_governance_receipt":
            result["status"] = "failed"
            result["error"] = f"Unsupported governance action: {action_id}"
        else:
            receipt_request = build_receipt_request(
                proposal_id=proposal_id,
                action_hash=ctx.action_hash,
                final_card_hash=str(parameters.get("final_card_hash") or ctx.action_hash),
                plan_hash=ctx.plan_hash,
                parameters=parameters,
            )
            casper_result = await submit_governance_receipt(receipt_request)
            result.update(casper_result)
            result["receipt_payload"] = receipt_request.__dict__

    except Exception as exc:  # defensive: fail closed without leaking internals
        result["status"] = "error"
        result["error"] = f"Governance execution failed ({type(exc).__name__})."

    result["duration_seconds"] = round(time.time() - start, 2)
    return result


async def execute_governance_execution(
    proposal_id: str,
    action_id: str,
    target: str,
    parameters: str = "{}",
) -> str:
    """Execute one exact, allowlisted action from the consumed authorization."""
    ctx = _execution_contexts.get(proposal_id)
    if ctx is None:
        return json.dumps({
            "error": f"No authorized execution context for {proposal_id}. "
            "Approval must be validated first."
        })

    if not ctx.envelopes:
        logger.warning(
            "[operator] REJECTED action %s: no approved envelopes for %s",
            action_id,
            proposal_id,
        )
        return json.dumps({
            "error": "No approved envelopes in execution context. "
            "Authorization required before execution."
        })

    if action_id not in ALLOWED_ACTIONS:
        logger.warning(
            "[operator] REJECTED unknown action_id %r for %s",
            action_id,
            proposal_id,
        )
        return json.dumps({
            "error": f"Action '{action_id}' is not in the allowed action set. "
            "Execution refused."
        })

    try:
        requested_parameters = (
            json.loads(parameters) if isinstance(parameters, str) else parameters
        )
    except (json.JSONDecodeError, TypeError):
        return json.dumps({
            "error": f"Malformed parameter JSON for {action_id}. Execution refused."
        })
    if not isinstance(requested_parameters, dict):
        return json.dumps({
            "error": "Action parameters must be a JSON object. Execution refused."
        })

    requested_key = _canonical_action_key(
        action_id, target, requested_parameters
    )
    approved_keys = {
        _canonical_action_key(
            str(envelope.get("action_id", "")),
            str(envelope.get("target", "")),
            envelope.get("parameters", {})
            if isinstance(envelope.get("parameters", {}), dict)
            else {},
        )
        for envelope in ctx.envelopes
    }
    if requested_key not in approved_keys:
        logger.warning(
            "[operator] REJECTED unapproved action %s on %s for %s",
            action_id,
            target,
            proposal_id,
        )
        same_target = [
            envelope
            for envelope in ctx.envelopes
            if envelope.get("action_id") == action_id
            and envelope.get("target") == target
        ]
        if same_target:
            return json.dumps({
                "error": f"Parameter mismatch for {action_id} on {target}. "
                "Execution refused; submit a new plan."
            })
        return json.dumps({
            "error": f"Action {action_id} on {target} is not in the approved "
            "execution envelopes. Execution refused."
        })

    already_executed = any(
        _canonical_action_key(
            str(action.get("action_id", "")),
            str(action.get("target", "")),
            action.get("parameters", {})
            if isinstance(action.get("parameters", {}), dict)
            else {},
        ) == requested_key
        and action.get("status") in ("success", "already_applied")
        for action in ctx.actions_taken
    )
    if already_executed or requested_key in ctx.in_flight_actions:
        logger.warning(
            "[operator] REJECTED duplicate/concurrent execution of %s on %s for %s",
            action_id,
            target,
            proposal_id,
        )
        return json.dumps({
            "error": f"Action {action_id} on {target} is already executed or in progress. "
            "Duplicate execution refused."
        })

    # No await occurs between the duplicate check and this insertion, making
    # this an atomic event-loop guard for concurrent tool calls in one process.
    ctx.in_flight_actions.add(requested_key)
    try:
        result = await _perform_governance_execution_action(
            ctx=ctx,
            proposal_id=proposal_id,
            action_id=action_id,
            target=target,
            parameters=requested_parameters,
        )
    finally:
        ctx.in_flight_actions.discard(requested_key)

    duration = result["duration_seconds"]
    ctx.actions_taken.append(result)
    ctx.timeline.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": f"executed_{action_id}",
        "target": target,
        "status": result["status"],
        "duration_seconds": duration,
    })

    if SLACK_WEBHOOK_URL and result["status"] != "already_applied":
        try:
            status_emoji = "✅" if result["status"] == "success" else "❌"
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(
                    SLACK_WEBHOOK_URL,
                    json={
                        "text": (
                            f"{status_emoji} *Concordia DAO Council Locke* executed "
                            f"`{action_id}` on `{target}` for proposal "
                            f"`{proposal_id[:12]}...` — {result['status']} "
                            f"({duration}s)"
                        ),
                    },
                )
        except Exception as exc:
            logger.warning(
                "[operator] Slack notification failed (%s)",
                type(exc).__name__,
            )

    logger.info(
        "[operator] Executed %s on %s: status=%s, duration=%ss",
        action_id,
        target,
        result["status"],
        duration,
    )
    return json.dumps(result)


async def submit_action_receipt(
    proposal_id: str,
    resolution_summary: str,
) -> str:
    """Submit an CasperExecutionReceipt card after executing all approved actions.

    Seals the receipt via Gateway prepare → publish to Council Chamber → confirm.

    Args:
        proposal_id: The proposal that was executed.
        resolution_summary: Human-readable summary of what was done.
    """
    ctx = _execution_contexts.get(proposal_id)
    if ctx is None:
        return json.dumps({
            "error": f"No execution context for {proposal_id}. "
            "Execute actions first."
        })

    if not ctx.actions_taken:
        return json.dumps({
            "error": "No actions have been executed yet. "
            "Execute governance execution actions before submitting receipt."
        })

    # ── Deterministic guard: refuse receipt if any action failed ──────
    # (Fix: prevents EXECUTED state when governance execution actually failed)
    failed_actions = [
        a for a in ctx.actions_taken
        if a.get("status") in ("failed", "error", "unknown")
    ]
    if failed_actions:
        failed_ids = [a.get("action_id", "?") for a in failed_actions]
        logger.warning(
            f"[operator] REFUSED receipt for {proposal_id} — "
            f"failed actions: {failed_ids}"
        )
        return json.dumps({
            "error": f"Cannot submit receipt — {len(failed_actions)} action(s) "
            f"failed: {failed_ids}. Resolve failures before sealing receipt."
        })

    # ── Deterministic guard: exact envelope equality (Counter) ────────
    # Fix B3: Use Counter instead of set to detect duplicate executions.
    # Every approved envelope must be executed exactly once.
    if ctx.envelopes:
        approved_counts = Counter(
            _canonical_action_key(
                str(env.get("action_id", "")),
                str(env.get("target", "")),
                env.get("parameters", {})
                if isinstance(env.get("parameters", {}), dict)
                else {},
            )
            for env in ctx.envelopes
        )
        executed_counts = Counter(
            _canonical_action_key(
                str(action.get("action_id", "")),
                str(action.get("target", "")),
                action.get("parameters", {})
                if isinstance(action.get("parameters", {}), dict)
                else {},
            )
            for action in ctx.actions_taken
            if action.get("status") in ("success", "already_applied")
        )

        if approved_counts != executed_counts:
            missing = approved_counts - executed_counts
            extra = executed_counts - approved_counts
            detail_parts = []
            if missing:
                missing_ids = [k[0] for k in missing.elements()]
                detail_parts.append(
                    f"{len(list(missing.elements()))} approved action(s) "
                    f"not executed: {missing_ids}"
                )
            if extra:
                extra_ids = [k[0] for k in extra.elements()]
                detail_parts.append(
                    f"{len(list(extra.elements()))} extra/duplicate "
                    f"action(s): {extra_ids}"
                )
            detail = "; ".join(detail_parts)
            logger.warning(
                f"[operator] REFUSED receipt for {proposal_id} — "
                f"envelope mismatch: {detail}"
            )
            return json.dumps({
                "error": f"Exact-envelope mismatch — {detail}. "
                f"Every approved action must be executed exactly once."
            })

    # ── On-chain verification guard ───────────────────────────────────────
    # For Casper governance envelopes, the receipt is sealable only when every
    # Casper action returned a transaction hash. Legacy simulator metrics are
    # intentionally not used for the DAO path.
    casper_actions = [
        action for action in ctx.actions_taken
        if action.get("action_id") == "execute_casper_governance_receipt"
    ]
    if casper_actions:
        verification_details = [
            {
                "action_id": action.get("action_id"),
                "network": action.get("network"),
                "mode": action.get("mode"),
                "contract_hash": action.get("contract_hash"),
                "entry_point": action.get("entry_point"),
                "transaction_hash": action.get("transaction_hash"),
                "verified": bool(action.get("transaction_hash")) and action.get("status") in {"success", "already_applied"},
            }
            for action in casper_actions
        ]
        receipt_verified = all(item["verified"] for item in verification_details)
        ctx.timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "casper_transaction_verified" if receipt_verified else "casper_transaction_missing",
            "receipt_verified": receipt_verified,
            "details": verification_details,
        })
        if not receipt_verified:
            logger.warning("[operator] Casper transaction verification failed for %s", proposal_id)
            return json.dumps({
                "error": "Casper transaction hash was not produced; CasperExecutionReceipt refused.",
                "details": verification_details,
            })
    else:
        # Non-Casper developer actions are verified from the deterministic action
        # results only. We intentionally do not use legacy simulator health
        # metrics (uptime/error-rate) to decide whether a governance receipt can
        # be sealed.
        verification_details = [
            {
                "action_id": action.get("action_id"),
                "target": action.get("target"),
                "status": action.get("status"),
                "verified": action.get("status") in {"success", "already_applied", "skipped"},
            }
            for action in ctx.actions_taken
        ]
        receipt_verified = bool(verification_details) and all(
            item["verified"] for item in verification_details
        )
        ctx.timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "deterministic_action_receipt_verified" if receipt_verified else "deterministic_action_receipt_failed",
            "receipt_verified": receipt_verified,
            "details": verification_details,
        })
        if not receipt_verified:
            return json.dumps({
                "error": "Deterministic action result was not verified; CasperExecutionReceipt refused.",
                "details": verification_details,
            })

    governance_archive = {}
    if casper_actions:
        governance_archive = build_governance_archive(
            proposal_id=proposal_id,
            actions_taken=ctx.actions_taken,
            timeline=ctx.timeline,
        )
        ctx.timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "wells_governance_archive_created",
            "archive_hash": governance_archive.get("archive_hash"),
            "evidence_uri": governance_archive.get("evidence_uri"),
        })

    # Build CasperExecutionReceipt card
    receipt = ActionReceipt(
        proposal_id=proposal_id,
        authorization_type=ctx.authorization_type,
        authorization_id=ctx.authorization_id,
        actions_taken=ctx.actions_taken,
        timeline=ctx.timeline,
        governance_archive=governance_archive,
        resolution_summary=resolution_summary,
    )

    # SubmissionClient saga: prepare → publish → confirm
    try:
        submission_key = os.getenv(
            "OPERATOR_SUBMISSION_KEY",
            os.getenv("GATEWAY_SECRET", ""),
        )
        idem_key = derive_idempotency_key(
            "operator", ctx.room_message_id,
            ctx.plan_hash,
        )
        async with SubmissionClient(
            gateway_url=GATEWAY_URL,
            agent_key=submission_key,
        ) as sc:
            # 1. Prepare
            result = await sc.prepare(receipt, idempotency_key=idem_key)
            sealed_card = result.sealed_card
            publish_room = result.legacy_room_id or ctx.room_id

            if not publish_room:
                return json.dumps({
                    "error": "No room_id for publishing CasperExecutionReceipt."
                })

            # 2. Publish to the Gateway-owned Council Chamber
            sealed_message = format_card_message(sealed_card)

            recorder_id = os.getenv("RECORDER_AGENT_ID", "")
            if not recorder_id:
                logger.error(
                    "[operator] RECORDER_AGENT_ID not configured — "
                    "cannot publish CasperExecutionReceipt (fail-closed)"
                )
                return json.dumps({
                    "error": "RECORDER_AGENT_ID not configured. Cannot publish CasperExecutionReceipt."
                })

            room_client = ProposalRoomClient(
                gateway_url=GATEWAY_URL,
                agent_key=submission_key,
                sender_id=os.getenv("OPERATOR_AGENT_ID", "operator"),
                sender_role="operator",
                timeout=15.0,
            )
            try:
                await room_client.add_participant(
                    publish_room,
                    recorder_id,
                    role="recorder",
                    display_name="Concordia Core",
                )
                message_id = await room_client.post_message(
                    publish_room,
                    sealed_message,
                    mentions=[recorder_id],
                    metadata={
                        "publisher": "operator",
                        "card_hash": result.card_hash,
                    },
                )
            finally:
                await room_client.aclose()

            # 3. Confirm
            confirm = await sc.confirm(
                submission_id=result.submission_id,
                room_message_id=message_id,
                proposal_id=proposal_id,
                card_hash=result.card_hash,
                legacy_room_id=publish_room,
            )

        logger.info(
            f"[operator] CasperExecutionReceipt submitted for {proposal_id}: "
            f"state={confirm.new_state}, "
            f"actions={len(ctx.actions_taken)}"
        )

        # Invite Wells, the Governance Archivist for a conversational summary (best-effort)
        scribe_id = os.getenv("SCRIBE_AGENT_ID", "")
        if scribe_id and publish_room:
            try:
                scribe_room_client = ProposalRoomClient(
                    gateway_url=GATEWAY_URL,
                    agent_key=submission_key,
                    sender_id=os.getenv("OPERATOR_AGENT_ID", "operator"),
                    sender_role="operator",
                    timeout=15.0,
                )
                try:
                    await scribe_room_client.add_participant(
                        publish_room,
                        scribe_id,
                        role="scribe",
                        display_name="Wells",
                    )
                    await scribe_room_client.post_message(
                        publish_room,
                        (
                            f"@Wells — Execution completed for proposal {proposal_id}. "
                            f"Actions taken: {len(ctx.actions_taken)}. "
                            f"Please generate an optional governance archive summary."
                        ),
                        mentions=[scribe_id],
                        message_type="governance_summary_request",
                        metadata={"publisher": "operator", "governance_summary": True},
                    )
                finally:
                    await scribe_room_client.aclose()
                logger.info(
                    f"[operator] Wells invited to room {publish_room[:12]}..."
                )
            except Exception as exc:
                # Best-effort: CasperExecutionReceipt is already certified/sealed
                logger.warning(
                    "[operator] Wells invite failed (non-fatal, %s)",
                    type(exc).__name__,
                )

        # Clean up context
        _execution_contexts.pop(proposal_id, None)

        return json.dumps({
            "status": "submitted",
            "proposal_id": proposal_id,
            "new_state": confirm.new_state,
            "actions_count": len(ctx.actions_taken),
            "card_hash": result.card_hash,
            "governance_archive_hash": governance_archive.get("archive_hash"),
        })

    except Exception as exc:
        logger.error(
            "[operator] CasperExecutionReceipt submission failed (%s)",
            type(exc).__name__,
        )
        return json.dumps({
            "error": f"CasperExecutionReceipt submission failed ({type(exc).__name__})."
        })


# ---------------------------------------------------------------------------
# Casper Execution Agent Preprocessor (deterministic security filter)
# ---------------------------------------------------------------------------

class CasperTransactionSignerPreprocessor:
    """Deterministic security filter for the Casper Execution Agent agent.

    Subclasses DefaultPreprocessor to retain SDK plumbing (self-message
    filtering, history bootstrap, AgentTools creation) while adding
    approval validation logic.

    Intercepts MessageEvent.payload BEFORE the local execution callback sees them.
    Caches approval challenges, validates human approvals, and prevents
    unauthorized execution.

    SDK contract: process(ctx, event, **kwargs) -> AgentInput | None
    Note: local proposal-room runtime 1.0 passes agent_id as keyword argument.
    - Return AgentInput → local runtime invokes the execution callback
    - Return None → event consumed silently (go silent)
    """

    def __init__(self):
        self._default_preprocessor = None
        self._boot_epoch = time.time()
        # Cache of the current pending approval challenge from Protocol Strategy Agent.
        # Key: "current" (only one active challenge at a time).
        # Value: {proposal_id, plan_hash, action_hash, nonce}
        # Populated when Protocol Strategy Agent posts a challenge; consumed when
        # the human APPROVE is successfully consumed by the Gateway.
        self._pending_approvals: dict[str, dict] = {}

    async def _ensure_default(self):
        """Lazily import and create DefaultPreprocessor."""
        if self._default_preprocessor is None:
            self._default_preprocessor = LocalDefaultPreprocessor()

    def _parse_challenge(self, content: str) -> dict | None:
        """Parse a Protocol Strategy Agent approval challenge from a room message.

        Extracts proposal_id, plan_hash, and action_hash from the message.

        Supports two formats:
        1. JSON (primary — structured card):
           {"type": "approval_challenge", "proposal_id": "INC-001",
            "plan_hash": "abc...", "action_hash": "def...", "nonce": "K7V3NW"}

        2. Key-value lines (fallback — human-readable or markdown):
           proposal_id: INC-001
           plan_hash: abc123...
           action_hash: def456...
           nonce: K7V3NW

        Returns:
            dict with {proposal_id, plan_hash, action_hash, nonce} if all found,
            None otherwise.
        """
        import json as json_mod
        import re

        required = {"proposal_id", "plan_hash", "action_hash", "nonce"}

        # --- Try JSON first ---
        # The Protocol Strategy Agent may embed a JSON object in the message.
        # Look for JSON objects anywhere in the content.
        json_pattern = re.compile(r'\{[^{}]*\}')
        for m in json_pattern.finditer(content):
            try:
                data = json_mod.loads(m.group())
                if required.issubset(data.keys()):
                    return {
                        "proposal_id": str(data["proposal_id"]),
                        "plan_hash": str(data["plan_hash"]),
                        "action_hash": str(data["action_hash"]),
                        "nonce": str(data["nonce"]),
                    }
            except (json_mod.JSONDecodeError, TypeError):
                continue

        # --- Fallback: key-value lines ---
        # Match "key: value" or "key=value" patterns
        extracted = {}
        for key in required:
            pattern = re.compile(
                rf'(?:^|\n)\s*{re.escape(key)}\s*[:=]\s*(\S+)',
                re.MULTILINE,
            )
            match = pattern.search(content)
            if match:
                extracted[key] = match.group(1)

        if required.issubset(extracted.keys()):
            return extracted

        return None

    async def process(self, ctx, event, **kwargs):
        """Process a PlatformEvent before the adapter.

        Pattern-matches on event type and payload to intercept
        approval-related messages. All other events delegate to
        DefaultPreprocessor for standard SDK processing.

        Returns:
            - AgentInput (from DefaultPreprocessor) → local runtime processes
            - None → event consumed, agent goes silent
        """
        await self._ensure_default()

        # Only intercept MessageEvent with MessageCreatedPayload
        event_type = type(event).__name__
        if event_type != "MessageEvent":
            return await self._default_preprocessor.process(ctx, event, **kwargs)

        # Access payload (MessageCreatedPayload)
        # Fields are FLAT on the payload — no .message sub-object.
        # Local room payloads expose the same flat attributes used here.
        payload = getattr(event, "payload", None)
        if payload is None:
            return await self._default_preprocessor.process(ctx, event, **kwargs)

        # Read fields directly from payload (not payload.message)
        content = getattr(payload, "content", None) or ""
        sender_type = getattr(payload, "sender_type", "")
        sender_id = getattr(payload, "sender_id", "")

        # Log sender_type on first human message to verify assumption
        if sender_type and sender_type != "Agent":
            logger.info(
                f"[operator] Non-agent sender: type={sender_type!r} "
                f"id={sender_id!r} (log this value for approval chain)"
            )

        # Skip self-messages
        agent_id = kwargs.get("agent_id", "")
        if sender_id == agent_id:
            return None

        # --- Approval challenge from Protocol Strategy Agent ---
        # Protocol Strategy Agent posts a structured challenge containing plan_hash,
        # action_hash, nonce, and proposal_id. Cache it so the subsequent
        # human APPROVE can be consumed against it.
        #
        # SECURITY: Only the ACTUAL Protocol Strategy Agent agent may populate the cache.
        # Without this check, any agent in the room could post a fake
        # challenge and poison the cache (denial-of-approval attack).
        # The Gateway would reject the mismatched hashes (fail-closed),
        # but the human's legitimate APPROVE would silently fail until
        # the Protocol Strategy Agent re-posts.
        #
        # Message format (JSON embedded in proposal-room message):
        #   {"type": "approval_challenge", "proposal_id": "...",
        #    "plan_hash": "...", "action_hash": "...", "nonce": "..."}
        #
        # Also supports key-value format for legacy/manual challenges:
        #   plan_hash: abc123\naction_hash: def456\nnonce: K7V3NW
        commander_id = get_agent_ids().get("commander", "")
        # Detect challenge-shaped messages, but NOT sealed cards (which also
        # contain plan_hash/nonce). Sealed cards like StructuredApproval and
        # PolicyAuthorization must fall through to their dedicated handlers below.
        _is_sealed_card = (
            '"card_type": "StructuredApproval"' in content
            or '"card_type": "PolicyAuthorization"' in content
        )
        if ("plan_hash" in content
                and "nonce" in content
                and sender_type == "Agent"
                and not _is_sealed_card):
            # Gate: only the Protocol Strategy Agent agent may set the challenge cache
            if commander_id and sender_id != commander_id:
                logger.warning(
                    f"[operator] Challenge-shaped message from non-Protocol Strategy Agent "
                    f"agent {sender_id!r} — ignored (only Protocol Strategy Agent "
                    f"{commander_id!r} may set approval challenges)"
                )
                return None  # Silently consume — don't let it reach the LLM
            if not commander_id:
                logger.warning(
                    "[operator] COMMANDER_AGENT_ID not configured — "
                    "accepting challenge from any Agent sender (degraded mode)"
                )
            try:
                challenge = self._parse_challenge(content)
                if challenge:
                    # ----- Active Proposal Allowlist (credit protection) -----
                    if ACTIVE_PROPOSALS and challenge.get("proposal_id", "") not in ACTIVE_PROPOSALS:
                        logger.debug(
                            f"[operator] Skipping challenge for non-active proposal "
                            f"{challenge.get('proposal_id', '?')}"
                        )
                        return None
                    self._pending_approvals["current"] = challenge
                    logger.info(
                        f"[operator] Cached approval challenge from Protocol Strategy Agent: "
                        f"proposal={challenge['proposal_id']}, "
                        f"plan_hash={challenge['plan_hash'][:12]}..., "
                        f"action_hash={challenge['action_hash'][:12]}..."
                    )
                else:
                    logger.warning(
                        "[operator] Protocol Strategy Agent challenge detected but could not "
                        "extract required fields (proposal_id, plan_hash, "
                        "action_hash). Challenge NOT cached."
                    )
                return None  # Go silent — don't respond to the challenge
            except Exception as exc:
                logger.warning(
                    "[operator] Failed to parse challenge (%s)",
                    type(exc).__name__,
                )
                return await self._default_preprocessor.process(
                    ctx, event, **kwargs
                )

        # --- PolicyAuthorization from Gateway/Recorder (low-risk path) ---
        # Gateway publishes a sealed PolicyAuthorization card via format_card_message().
        # The message contains a JSON code block with card_type=PolicyAuthorization.
        # We verify: (1) sender is RECORDER_AGENT_ID, (2) card_type matches,
        # (3) then consume the authorization from Gateway to get approved envelopes.
        import json as _json
        import re as _re

        # Try to parse the sealed card from the fenced JSON block in the message
        _sealed_card = None
        _json_match = _re.search(r'```json\s*(\{.*?\})\s*```', content, _re.DOTALL)
        if _json_match:
            try:
                _sealed_card = _json.loads(_json_match.group(1))
            except Exception:
                _sealed_card = None

        _is_policy_auth = (
            _sealed_card is not None
            and _sealed_card.get("card_type") == "PolicyAuthorization"
            and sender_type == "Agent"
        )

        _is_structured_approval = (
            _sealed_card is not None
            and _sealed_card.get("card_type") == "StructuredApproval"
            and sender_type == "Agent"
        )

        if _is_policy_auth:
            # Validate sender IS the Gateway/Recorder (RECORDER_AGENT_ID)
            recorder_id = os.getenv("RECORDER_AGENT_ID", "")
            if recorder_id and sender_id != recorder_id:
                logger.warning(
                    f"[operator] PolicyAuthorization card from "
                    f"unauthorized agent {sender_id!r} — rejected "
                    f"(only RECORDER_AGENT_ID {recorder_id!r} may authorize)"
                )
                return None
            if not recorder_id:
                logger.warning(
                    "[operator] RECORDER_AGENT_ID not configured — "
                    "cannot verify PolicyAuthorization sender. Rejecting (fail-closed)."
                )
                return None

            # Extract proposal_id and authorization_id directly from card JSON
            proposal_id = _sealed_card.get("proposal_id", "")
            authorization_id = _sealed_card.get("authorization_id", "")
            if not proposal_id or not authorization_id:
                logger.warning(
                    "[operator] PolicyAuthorization card missing proposal_id or "
                    "authorization_id — rejecting"
                )
                return None

            # ----- Active Proposal Allowlist (credit protection) -----
            if ACTIVE_PROPOSALS and proposal_id not in ACTIVE_PROPOSALS:
                logger.info(f"[operator] Skipping non-active proposal {proposal_id}")
                return None

            # Consume authorization via shared helper (with bounded 409 retry)
            auth_data = await _consume_authorization_with_retry(
                authorization_id, proposal_id
            )
            if auth_data is None:
                return None

            _execution_contexts[proposal_id] = ExecutionContext(
                proposal_id=proposal_id,
                authorization_type="policy",
                authorization_id=auth_data.get("authorization_id", authorization_id),
                plan_hash=auth_data.get("plan_hash", ""),
                action_hash=auth_data.get("action_hash", ""),
                envelopes=auth_data.get("envelopes", []),
                room_id=getattr(event, "room_id", "") or "",
                room_message_id=getattr(payload, "id", "") or "",
            )
            logger.info(
                f"[operator] PolicyAuthorization consumed for {proposal_id} — "
                f"execution context set up with {len(auth_data.get('envelopes', []))} envelopes"
            )

            # Optimization: skip if already EXECUTED (not authoritative — see proposal-simulator idempotency)
            try:
                gateway_url = os.getenv("GATEWAY_URL", "http://localhost:8000")
                async with httpx.AsyncClient(timeout=5.0) as _ec:
                    _ec_resp = await _ec.get(f"{gateway_url}/proposals/{proposal_id}")
                if _ec_resp.status_code == 200:
                    _ec_state = _ec_resp.json().get("proposal", {}).get("state", "")
                    if _ec_state == "EXECUTED":
                        logger.info(f"[operator] {proposal_id} already EXECUTED — skipping (optimization)")
                        return None
            except Exception:
                pass  # fail-open — proposal-simulator idempotency is the real guard

            # Pass through to LLM for execution
            return await self._default_preprocessor.process(ctx, event, **kwargs)

        # --- StructuredApproval from Gateway (high-risk / human-approval path) ---
        # The web UI consumes the nonce → _publish_and_advance creates a sealed
        # StructuredApproval card and posts it to Council Chamber mentioning the Casper Execution Agent.
        # The Casper Execution Agent must: validate sender, extract action_id as authorization_id,
        # consume via /api/authorization/{id}/consume, build ExecutionContext.
        #
        # CRITICAL: authorization_id lives in action_id, NOT authorization_id.
        # nonce.py:335 sets action_id=authorization_id when sealing.
        if _is_structured_approval:
            # ANTI-FORGERY: sender MUST be RECORDER_AGENT_ID
            recorder_id = os.getenv("RECORDER_AGENT_ID", "")
            if recorder_id and sender_id != recorder_id:
                logger.warning(
                    f"[operator] StructuredApproval card from "
                    f"unauthorized agent {sender_id!r} — rejected "
                    f"(only RECORDER_AGENT_ID {recorder_id!r} may authorize)"
                )
                return None
            if not recorder_id:
                logger.warning(
                    "[operator] RECORDER_AGENT_ID not configured — "
                    "cannot verify StructuredApproval sender. Rejecting (fail-closed)."
                )
                return None

            # APPROVED-only gate — Casper Execution Agent only executes APPROVED plans.
            # REJECTED and FALSE_ALARM cards are sealed human decisions that
            # Protocol Strategy Agent (or no one) acts on — Casper Execution Agent must ignore them.
            _sa_decision = _sealed_card.get("decision")
            if _sa_decision != "APPROVED":
                logger.info(
                    f"[operator] Ignoring StructuredApproval({_sa_decision}) "
                    f"— Casper Execution Agent only executes APPROVED plans"
                )
                return None

            # Extract fields — action_id carries the authorization_id.
            proposal_id = _sealed_card.get("proposal_id", "")
            authorization_id = _sealed_card.get("action_id", "")  # NOT .get("authorization_id")
            if not proposal_id or not authorization_id:
                logger.warning(
                    "[operator] StructuredApproval card missing proposal_id or "
                    "action_id (authorization) — rejecting"
                )
                return None

            # Validate seal fields present
            if not _sealed_card.get("card_hash"):
                logger.warning(
                    "[operator] StructuredApproval card missing card_hash — "
                    "unsealed card rejected"
                )
                return None

            # ----- Active Proposal Allowlist (credit protection) -----
            if ACTIVE_PROPOSALS and proposal_id not in ACTIVE_PROPOSALS:
                logger.info(f"[operator] Skipping non-active proposal {proposal_id}")
                return None

            # Consume authorization via shared helper (with bounded 409 retry)
            auth_data = await _consume_authorization_with_retry(
                authorization_id, proposal_id
            )
            if auth_data is None:
                return None

            # Validate envelopes present
            envelopes = auth_data.get("envelopes", [])
            if not envelopes:
                logger.warning(
                    f"[operator] StructuredApproval for {proposal_id} has "
                    f"empty envelopes — cannot execute. Rejecting."
                )
                return None

            _execution_contexts[proposal_id] = ExecutionContext(
                proposal_id=proposal_id,
                authorization_type="human_approval",
                authorization_id=auth_data.get("authorization_id", authorization_id),
                plan_hash=auth_data.get("plan_hash", ""),
                action_hash=auth_data.get("action_hash", ""),
                envelopes=envelopes,
                room_id=getattr(event, "room_id", "") or "",
                room_message_id=getattr(payload, "id", "") or "",
            )
            logger.info(
                f"[operator] StructuredApproval consumed for {proposal_id} — "
                f"execution context set up with {len(envelopes)} envelopes "
                f"(human_approval path)"
            )

            # Optimization: skip if already EXECUTED
            try:
                gateway_url = os.getenv("GATEWAY_URL", "http://localhost:8000")
                async with httpx.AsyncClient(timeout=5.0) as _ec:
                    _ec_resp = await _ec.get(f"{gateway_url}/proposals/{proposal_id}")
                if _ec_resp.status_code == 200:
                    _ec_state = _ec_resp.json().get("proposal", {}).get("state", "")
                    if _ec_state == "EXECUTED":
                        logger.info(f"[operator] {proposal_id} already EXECUTED — skipping (optimization)")
                        return None
            except Exception:
                pass  # fail-open

            # Pass through to LLM for execution — inject approved envelopes
            # into the payload.content so the LLM knows exactly which actions
            # to run (critical after reject→revise where v1+v2 are in history)
            envelope_summary = "\n".join(
                f"  - action_id={e.get('action_id')}, target={e.get('target')}, "
                f"parameters={json.dumps(e.get('parameters', {}))}"
                for e in envelopes
            )
            system_note = (
                f"\n\n[SYSTEM NOTE — APPROVED ENVELOPES]\n"
                f"You MUST ONLY execute these specific approved actions for {proposal_id}:\n"
                f"{envelope_summary}\n"
                f"Do NOT use actions from earlier rejected plans. Only the above "
                f"actions are authorized by the human approver.\n"
                f"[END SYSTEM NOTE]\n"
            )
            # Inject into payload.content (the room message text field)
            _payload = getattr(event, "payload", None)
            if _payload is not None:
                _pc = getattr(_payload, "content", None)
                if isinstance(_pc, str):
                    _payload.content = _pc + system_note
                    logger.info(
                        f"[operator] Injected approved envelopes into payload.content "
                        f"for {proposal_id}: {[e.get('action_id') for e in envelopes]}"
                    )
                else:
                    logger.warning(
                        f"[operator] payload.content is {type(_pc).__name__}, "
                        f"cannot inject envelopes for {proposal_id}"
                    )
            else:
                logger.warning(
                    f"[operator] No payload on event for {proposal_id}"
                )

            return await self._default_preprocessor.process(ctx, event, **kwargs)

        # --- Approval-shaped content gate ---
        # CRITICAL: Match APPROVE regex FIRST, before checking sender_type.
        # This prevents Agent senders from bypassing the gate and reaching
        # the LLM with approval-shaped content (recruitment-injection risk).
        #
        # Nonce alphabet: [A-Z2-9] (no I/O/0/1), exactly 6 chars — see shared/approval.py:35
        # COUPLING: generate_nonce(length=6) hardcodes 6; this regex hardcodes {6}.
        #   If nonce length ever changes, BOTH must be updated.
        # DEMO NOTE: (?:\s|$) means trailing punctuation ("APPROVE K7V3NW.") won't match.
        #   Demo crib card must say: type nonce then space or Enter, no period.
        #
        # PARSING STRATEGY (verified R3→R4b):
        #   1. Strip leading @[[uuid]] Council Chamber mentions (users type "@Casper Execution Agent APPROVE K7V3NW")
        #   2. Strip whitespace, then re.fullmatch — APPROVE must be the ENTIRE content
        #   3. "DO NOT APPROVE K7V3NW" → stripped = "DO NOT APPROVE..." → no match ✅
        #   4. "DISAPPROVE K7V3NW" → stripped = "DISAPPROVE..." → no match ✅
        #   5. "APPROVE K7V3NW then reject" → trailing text → no fullmatch ✅
        #   6. (?<!\S) lookbehind was tried in R3 but failed: space before APPROVE
        #      satisfies the lookbehind, so "DO NOT APPROVE" still matched.
        import re
        stripped = re.sub(r'^(?:\s*@\[\[[^\]]+\]\]\s*)+', '', content).strip()
        nonce_match = re.fullmatch(
            r'APPROVE\s+([A-Z2-9]{6})', stripped
        )
        if nonce_match:
            # Gate 1: Only User sender_type may approve
            if sender_type != "User":
                logger.warning(
                    f"[operator] Approval-shaped message from non-User "
                    f"sender ({sender_type}/{sender_id}) — rejected"
                )
                return None

            # Gate 2: Fail closed — empty allowlist rejects ALL approvals
            if not HUMAN_APPROVER_IDS:
                logger.error(
                    "[operator] HUMAN_APPROVER_IDS not configured — "
                    "rejecting approval (fail-closed)"
                )
                return None

            # Gate 3: Sender must be in allowlist
            if sender_id not in HUMAN_APPROVER_IDS:
                logger.warning(
                    f"[operator] Approval from unauthorized user {sender_id} "
                    f"— rejected (not in HUMAN_APPROVER_IDS)"
                )
                return None

            # All gates passed — extract nonce and consume via Gateway
            nonce = nonce_match.group(1)

            # --- Nonce consumption via Gateway ---
            # The Gateway is the REAL authorization boundary.
            # If consumption fails, execution MUST NOT proceed.
            pending = self._pending_approvals.get("current")
            if not pending:
                logger.warning(
                    "[operator] No pending approval challenge cached; "
                    "approval rejected."
                )
                return None

            proposal_id = str(pending.get("proposal_id") or "")
            if not proposal_id:
                logger.warning(
                    "[operator] Pending approval has no proposal binding; "
                    "approval rejected."
                )
                return None

            logger.info(
                "[operator] Parsed approval from %s for proposal=%s",
                sender_id,
                proposal_id,
            )

            # Belt: assert nonce from APPROVE matches cached challenge nonce
            if pending.get("nonce") and nonce != pending.get("nonce"):
                logger.warning(
                    f"[operator] Nonce mismatch: APPROVE={nonce}, "
                    f"challenge={pending.get('nonce')} — rejecting"
                )
                return None

            # local proposal-room runtime: MessageCreatedPayload has .id (not .message_id)
            room_message_id = getattr(payload, "id", "") or ""
            # Room binding: trace approval to specific Council Chamber
            room_id = getattr(event, "room_id", "") or ""
            try:
                gateway_url = os.getenv("GATEWAY_URL", "http://localhost:8000")
                operator_key = os.getenv(
                    "OPERATOR_SUBMISSION_KEY",
                    os.getenv("GATEWAY_SECRET", ""),
                )
                async with httpx.AsyncClient(timeout=10.0) as http:
                    resp = await http.post(
                        f"{gateway_url}/api/nonce/consume",
                        json={
                            "proposal_id": pending["proposal_id"],
                            "nonce": nonce,
                            "plan_hash": pending["plan_hash"],
                            "action_hash": pending["action_hash"],
                            "consumed_by": sender_id,
                            "room_message_id": room_message_id,
                            "room_id": room_id,
                        },
                        headers={"X-Agent-Key": operator_key},
                    )
                if resp.status_code == 200:
                    logger.info(
                        f"[operator] Nonce {nonce} CONSUMED — "
                        f"execution authorized for {pending['proposal_id']}"
                    )

                    # Fetch envelopes from the nonce consume response
                    consume_data = resp.json()
                    envelopes = consume_data.get("envelopes", [])
                    consume_auth_id = consume_data.get("authorization_id", nonce)

                    # Set up execution context with envelopes
                    _execution_contexts[pending["proposal_id"]] = ExecutionContext(
                        proposal_id=pending["proposal_id"],
                        authorization_type="human_approval",
                        authorization_id=consume_auth_id,
                        plan_hash=pending["plan_hash"],
                        action_hash=pending["action_hash"],
                        envelopes=envelopes,
                        room_id=room_id,
                        room_message_id=room_message_id,
                    )
                    # Clear the pending approval
                    self._pending_approvals.pop("current", None)

                    # Optimization: skip if already EXECUTED
                    try:
                        async with httpx.AsyncClient(timeout=5.0) as _ec:
                            _ec_resp = await _ec.get(
                                f"{gateway_url}/proposals/{pending['proposal_id']}"
                            )
                        if _ec_resp.status_code == 200:
                            _ec_state = _ec_resp.json().get("proposal", {}).get("state", "")
                            if _ec_state == "EXECUTED":
                                logger.info(
                                    f"[operator] {pending['proposal_id']} already "
                                    f"EXECUTED — skipping (optimization)"
                                )
                                return None
                    except Exception:
                        pass  # fail-open

                    # Pass to LLM for execution
                    return await self._default_preprocessor.process(
                        ctx, event, **kwargs
                    )
                else:
                    logger.warning(
                        "[operator] Nonce consumption refused by Gateway (HTTP %s)",
                        resp.status_code,
                    )
                    return None
            except Exception as exc:
                logger.error(
                    "[operator] Gateway nonce consumption failed (%s); "
                    "rejecting approval fail-closed",
                    type(exc).__name__,
                )
                return None

        # --- Gate 0b: APPROVE-shaped but malformed → swallow + audit ---
        # Defense-in-depth: if stripped content is "APPROVE" followed by
        # space or end-of-string (but didn't pass fullmatch), this is a
        # malformed approval attempt. Swallow it (don't pass to LLM).
        # Examples:
        #   "APPROVE K7V3NW then reject"  → ambiguous trailing text → swallowed
        #   "APPROVE it please"           → invalid nonce → swallowed
        #   "APPROVED the plan earlier"   → NOT swallowed (word is APPROVED, not APPROVE)
        #   "DO NOT APPROVE K7V3NW"       → NOT swallowed (starts with DO)
        # re.match(r'APPROVE(?:\s|$)') is more precise than startswith("APPROVE")
        # because it lets APPROVED/APPROVES/APPROVEMENT chatter through.
        if re.match(r'APPROVE(?:\s|$)', stripped):
            logger.warning(
                f"[operator] APPROVE-shaped but malformed message from "
                f"{sender_type}/{sender_id} — swallowed (not passed to LLM). "
                f"Content starts with: {stripped[:40]!r}"
            )
            return None

        # --- Deterministic Agent non-card silence ---
        # All supported Agent paths are handled above:
        # - Challenges from Protocol Strategy Agent
        # - PolicyAuthorization cards from Recorder (low-risk path)
        # - StructuredApproval cards from Recorder (high-risk / human-approval path)
        # Any remaining non-card Agent message is chatter — consume silently.
        if sender_type == "Agent":
            logger.debug(
                f"[operator] Consuming non-card Agent message from "
                f"{sender_id[:12] if sender_id else '?'}... "
                f"(no supported path matched)"
            )
            return None

        # --- All other messages (Human/User) pass through ---
        # Check freshness for non-sealed, non-approval chatter
        inserted_at = getattr(payload, "inserted_at", None)
        if should_skip_stale_chatter(str(inserted_at) if inserted_at else None, self._boot_epoch, "operator"):
            return None
        return await self._default_preprocessor.process(ctx, event, **kwargs)


async def run_local_operator(event) -> None:
    """Execute approved envelopes without an external adapter."""
    payload = getattr(event, "payload", None)
    content = getattr(payload, "content", "") if payload else ""
    card = extract_sealed_card(content)
    if not card:
        return
    card_type = card.get("card_type")
    if card_type not in {"PolicyAuthorization", "StructuredApproval"}:
        return
    if card_type == "StructuredApproval" and card.get("decision") != "APPROVED":
        return

    proposal_id = card.get("proposal_id", "")
    ctx = _execution_contexts.get(proposal_id)
    if ctx is None or not ctx.envelopes:
        return

    execution_results: list[dict] = []
    for envelope in ctx.envelopes:
        result = await execute_governance_execution(
            proposal_id=proposal_id,
            action_id=str(envelope.get("action_id", "")),
            target=str(envelope.get("target", "")),
            parameters=json.dumps(envelope.get("parameters", {})),
        )
        logger.info("[operator] Local governance execution result: %s", result)
        execution_results.append(
            {
                "action_id": envelope.get("action_id", ""),
                "target": envelope.get("target", ""),
                "result": result,
            }
        )

    summary = "Executed all approved governance execution envelopes."
    llm = await ask_llm_json(
        role="operator",
        system=(
            "You are Locke, the Casper Execution Agent. Summarize the exact approved "
            "execution results for the audit receipt. Do not claim actions "
            "that are not present in execution_results."
        ),
        user={
            "proposal_id": proposal_id,
            "authorization_type": ctx.authorization_type,
            "approved_envelopes": ctx.envelopes,
            "execution_results": execution_results,
            "expected_json_keys": ["resolution_summary"],
        },
        max_tokens=400,
    )
    if llm:
        summary = bounded_text(llm.get("resolution_summary"), max_len=700) or summary

    receipt = await submit_action_receipt(
        proposal_id=proposal_id,
        resolution_summary=summary,
    )
    logger.info("[operator] Local CasperExecutionReceipt result: %s", receipt)


async def create_operator_agent():
    """Create the Casper Execution Agent agent on the Gateway-owned proposal-room runtime."""
    config = MODELS["operator"]

    preprocessor = CasperTransactionSignerPreprocessor()

    agent_id = os.getenv("OPERATOR_AGENT_ID", "")
    api_key = get_agent_api_key("operator")
    agent = LocalRoomAgent(
        role="operator",
        agent_id=agent_id,
        agent_key=api_key,
        preprocessor=preprocessor,
        on_agent_input=run_local_operator,
        framework="Council Runtime + LLM",
        model=config.model,
    )

    return agent


async def main():
    logging.basicConfig(level=logging.INFO)
    await run_with_supervisor(create_operator_agent, "operator")


if __name__ == "__main__":
    asyncio.run(main())
