"""CONCORDIA SubmissionClient — Agent-side client for Gateway seal-before-send.

Every card flows through this three-phase saga:
  1. prepare(card)  → Gateway validates, enriches, seals → PrepareResult
  2. Agent publishes sealed card to the Council Chamber (caller's responsibility)
  3. confirm(...)   → Gateway advances state machine → ConfirmResult

Contract:
  - Always sends X-Idempotency-Key. The Gateway's random-uuid fallback
    means a retry without a header seals a duplicate card.
  - Retries with the SAME idempotency key on transient failures.
  - Used by ALL agent adapters: Recorder, Triage, Diagnosis,
    Risk & Legal Agent, Protocol Strategy Agent, Casper Execution Agent.

Architecture note:
  /prepare returns the sealed card, resolved destination (room_id),
  and the agent_role. Local tool handlers receive only the validated
  Pydantic model — SubmissionClient learns where to publish from Gateway's
  response.
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from typing import Any

import httpx

from shared.models import CardBase

logger = logging.getLogger("concordia.submission_client")

# Retry configuration
MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = [0.5, 1.0, 2.0]
RETRYABLE_STATUS_CODES = frozenset({502, 503, 504})


@dataclass(frozen=True)
class PrepareResult:
    """Result of a successful /prepare call."""
    submission_id: str       # idempotency_key echoed back
    sealed_card: dict        # Full sealed card (post-enrichment, with hashes)
    card_hash: str           # SHA-256 of the sealed card
    sequence_number: int     # Position in the proposal's card chain
    proposal_id: str         # Proposal this card belongs to
    agent_role: str          # Role resolved from the agent key
    room_id: str | None      # Room to publish to (None if room not yet created)

    @property
    def legacy_room_id(self) -> str | None:
        """Compatibility alias for schemas that still expose legacy_room_id."""
        return self.room_id


@dataclass(frozen=True)
class ConfirmResult:
    """Result of a successful /confirm call."""
    status: str              # "confirmed" or "already_confirmed"
    proposal_id: str
    card_hash: str
    message_id: str
    new_state: str | None    # New proposal state (None if no transition)

    @property
    def room_message_id(self) -> str:
        """Compatibility alias for schemas that still expose room_message_id."""
        return self.message_id


class SubmissionError(Exception):
    """Raised when Gateway returns a non-retryable error."""
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"Gateway {status_code}: {detail}")


class SubmissionClient:
    """Agent-side HTTP client for Gateway /prepare and /confirm.

    Each agent creates one SubmissionClient with its own agent_key.
    The client handles idempotency key generation and retry logic.

    Usage:
        client = SubmissionClient(
            gateway_url="http://localhost:8000",
            agent_key="my-agent-secret",
        )

        # 1. Prepare (seal)
        result = await client.prepare(signal_card)

        # 2. Publish to the Gateway-owned Council Chamber
        message_id = await room_client.post_message(
            room_id=result.room_id,
            content=format_card_message(result.sealed_card),
            mentions=[next_agent_id],
        )

        # 3. Confirm (advance state)
        confirm = await client.confirm(
            submission_id=result.submission_id,
            proposal_id=result.proposal_id,
            card_hash=result.card_hash,
            message_id=message_id,
            room_id=result.room_id,
        )
    """

    def __init__(
        self,
        gateway_url: str,
        agent_key: str,
        *,
        timeout: float = 30.0,
    ):
        self.gateway_url = gateway_url.rstrip("/")
        self.agent_key = agent_key
        self._client = httpx.AsyncClient(
            base_url=f"{self.gateway_url}/api",
            headers={
                "X-Agent-Key": agent_key,
                "Content-Type": "application/json",
            },
            timeout=timeout,
        )

    async def prepare(
        self,
        card: CardBase,
        *,
        idempotency_key: str | None = None,
    ) -> PrepareResult:
        """Prepare (seal) a card through the Gateway.

        Args:
            card: Any CardBase subclass (ProposalCard, Assessment, etc.)
            idempotency_key: Optional. If not provided, a UUID4 is generated.
                             MUST be reused on retries to prevent duplicates.

        Returns:
            PrepareResult with sealed card, hash, and destination.

        Raises:
            SubmissionError on non-retryable Gateway errors (400, 401, 403, 409).
        """
        idem_key = idempotency_key or str(uuid.uuid4())
        card_type = card.model_dump().get("card_type", "unknown")

        payload = card.model_dump(mode="json")

        response = await self._post_with_retry(
            f"/prepare/{card_type}",
            json_data=payload,
            idempotency_key=idem_key,
        )

        data = response.json()
        return PrepareResult(
            submission_id=data["submission_id"],
            sealed_card=data["sealed_card"],
            card_hash=data["card_hash"],
            sequence_number=data["sequence_number"],
            proposal_id=data["proposal_id"],
            agent_role=data["agent_role"],
            room_id=(
                data.get("destination", {}).get("room_id")
                or data.get("destination", {}).get("legacy_room_id")
            ),
        )

    async def confirm(
        self,
        *,
        submission_id: str,
        proposal_id: str,
        card_hash: str,
        message_id: str | None = None,
        room_id: str | None = None,
        room_message_id: str | None = None,
        legacy_room_id: str | None = None,
    ) -> ConfirmResult:
        """Confirm that a sealed card was published to the Council Chamber.

        This advances the proposal state machine. Call AFTER the card
        is visible in the Council Chamber.

        Args:
            submission_id: The submission_id from PrepareResult.
            proposal_id: The proposal this card belongs to.
            card_hash: The card_hash from PrepareResult.
            message_id: The proposal-room message id.
            room_id: Optional room id for tracking.

        Returns:
            ConfirmResult with new state.
        """
        resolved_message_id = message_id or room_message_id
        resolved_room_id = room_id or legacy_room_id
        if not resolved_message_id:
            raise SubmissionError(400, "message_id is required")

        body: dict[str, Any] = {
            "submission_id": submission_id,
            "message_id": resolved_message_id,
            "proposal_id": proposal_id,
            "card_hash": card_hash,
        }
        if resolved_room_id:
            body["room_id"] = resolved_room_id

        # Confirm is inherently idempotent (same submission_id + card_hash),
        # no separate idempotency key needed.
        response = await self._post_with_retry(
            "/confirm",
            json_data=body,
        )

        data = response.json()
        return ConfirmResult(
            status=data["status"],
            proposal_id=data["proposal_id"],
            card_hash=data["card_hash"],
            message_id=data.get("message_id") or data["room_message_id"],
            new_state=data.get("new_state"),
        )

    async def _post_with_retry(
        self,
        path: str,
        json_data: dict,
        *,
        idempotency_key: str | None = None,
    ) -> httpx.Response:
        """POST with retry on transient errors.

        Uses the SAME idempotency key across retries — Gateway's
        idempotency check returns the existing sealed card.
        """
        headers: dict[str, str] = {}
        if idempotency_key:
            headers["X-Idempotency-Key"] = idempotency_key

        last_error: Exception | None = None

        for attempt in range(MAX_RETRIES):
            try:
                response = await self._client.post(
                    path,
                    json=json_data,
                    headers=headers,
                )

                # Success
                if response.status_code == 200:
                    return response

                # Non-retryable errors — fail immediately
                if response.status_code not in RETRYABLE_STATUS_CODES:
                    detail = "Gateway rejected the submission."
                    try:
                        parsed_detail = response.json().get("detail")
                        if isinstance(parsed_detail, str) and parsed_detail:
                            detail = parsed_detail
                    except ValueError:
                        pass
                    raise SubmissionError(response.status_code, str(detail))

                # Retryable — log and continue
                logger.warning(
                    "Gateway %s returned %d on attempt %d/%d",
                    path, response.status_code, attempt + 1, MAX_RETRIES,
                )
                last_error = SubmissionError(
                    response.status_code,
                    "Gateway returned a retryable upstream error.",
                )

            except httpx.HTTPError as exc:
                logger.warning(
                    "Gateway %s transport error on attempt %d/%d (%s)",
                    path, attempt + 1, MAX_RETRIES, type(exc).__name__,
                )
                last_error = SubmissionError(
                    502, f"Gateway transport failed ({type(exc).__name__})."
                )

            # Backoff before retry (except on last attempt)
            if attempt < MAX_RETRIES - 1:
                import asyncio
                await asyncio.sleep(RETRY_BACKOFF_SECONDS[attempt])

        # All retries exhausted
        raise last_error or SubmissionError(500, "All retries exhausted")

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> SubmissionClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()


def format_card_message(sealed_card: dict) -> str:
    """Format a sealed card as an proposal-room message.

    This is the standard message format for CONCORDIA cards in Council Chambers:
    a short human-readable summary followed by the full sealed card JSON.
    """
    card_type = sealed_card.get("card_type", "Card")
    proposal_id = sealed_card.get("proposal_id", sealed_card.get("signal_id", "unknown"))
    card_hash = sealed_card.get("card_hash", "")[:12]
    seq = sealed_card.get("sequence_number", "?")

    # Build human-readable summary based on card type
    summary_parts = [f"**{card_type}** for proposal `{proposal_id}` (seq {seq}, hash `{card_hash}…`)"]

    if card_type == "ProposalCard":
        title = sealed_card.get("title", "")
        severity = sealed_card.get("preliminary_severity", "unknown")
        source = sealed_card.get("source", "")
        summary_parts.append(f"🚨 {severity} — {title} (from {source})")

    elif card_type == "TriageDecision":
        decision = sealed_card.get("decision", "")
        noise = sealed_card.get("noise_score", "?")
        summary_parts.append(f"📋 Decision: {decision} (noise score: {noise})")

    elif card_type == "Assessment":
        severity = sealed_card.get("severity", "?")
        evidence = sealed_card.get("evidence_strength", "?")
        summary_parts.append(f"🔬 Severity: {severity}, Evidence: {evidence}")

    elif card_type == "Verdict":
        decision = sealed_card.get("decision", "?")
        summary_parts.append(f"⚖️ Verdict: {decision}")

    elif card_type == "ResponsePlan":
        risk = sealed_card.get("risk_level", "?")
        approval = sealed_card.get("requires_human_approval", False)
        summary_parts.append(f"📝 Risk: {risk}, Human approval: {approval}")

    elif card_type == "CasperExecutionReceipt":
        summary_parts.append("✅ Action completed")

    # Fenced JSON card
    card_json = json.dumps(sealed_card, indent=2, default=str)

    return "\n".join(summary_parts) + f"\n\n```json\n{card_json}\n```"
