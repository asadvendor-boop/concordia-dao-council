"""Concordia DAO Council Gateway — Card Submission Routes.

Handles the seal-before-send protocol:
    POST /api/prepare/{card_type}  — Validate, enrich, seal a card
    POST /api/confirm              — Confirm proposal-room publication
    GET  /api/export/evidence/{id} — Export chain with verification
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Header, HTTPException, Request

from gateway.auth import configured_key_to_role
from shared.approval import requires_human_approval
from shared.dao_policy import load_constitution
from shared.integrity import seal_card, IdempotencyConflict, request_fingerprint
from shared.models import CARD_TYPES

logger = logging.getLogger("concordia.submission")
router = APIRouter()

# ---------------------------------------------------------------------------
# Outcome-aware state transitions
# Cards with a decision field produce different states based on outcome.
# ---------------------------------------------------------------------------

# Default transitions (for cards without outcome-specific logic)
_BASE_TRANSITIONS: dict[str, str] = {
    "ProposalCard": "DETECTED",
    "TriageDecision": "TRIAGED",  # overridden for suppress
    "Assessment": "ASSESSED",
    # Verdict: outcome-aware (see _resolve_state)
    "ResponsePlan": "PLANNED",
    "StructuredApproval": "APPROVED",  # overridden for REJECTED
    "PolicyAuthorization": "AUTHORIZED",
    "CasperExecutionReceipt": "EXECUTED",
    "GovernanceSummary": "RESOLVED",
}

# Outcome-specific overrides: (card_type, decision_value) → state
_OUTCOME_TRANSITIONS: dict[tuple[str, str], str] = {
    # Verdict outcomes
    ("Verdict", "CONFIRM"): "REVIEWED",
    ("Verdict", "CHALLENGE"): "CHALLENGED",
    ("Verdict", "FALSE_ALARM"): "CLOSED_FALSE_ALARM",
    ("Verdict", "NEEDS_HUMAN"): "ESCALATED_HUMAN",
    # TriageDecision outcomes
    ("TriageDecision", "route"): "TRIAGED",
    ("TriageDecision", "suppress"): "SUPPRESSED",
    # StructuredApproval outcomes
    ("StructuredApproval", "APPROVED"): "APPROVED",
    ("StructuredApproval", "REJECTED"): "REJECTED",
    ("StructuredApproval", "FALSE_ALARM"): "CLOSED_FALSE_ALARM",
}


def _resolve_state(card_type: str, card_json: str) -> str | None:
    """Resolve the state transition for a confirmed card.

    Checks outcome-specific overrides first, then falls back to
    the base transition map.
    """
    data = json.loads(card_json)
    decision = data.get("decision")

    if decision:
        key = (card_type, decision)
        if key in _OUTCOME_TRANSITIONS:
            return _OUTCOME_TRANSITIONS[key]

    return _BASE_TRANSITIONS.get(card_type)


def _verify_room_publication(
    db,
    *,
    room_id: str,
    message_id: str,
    card_hash: str,
    agent_role: str,
) -> None:
    """Verify a confirmed card message exists in the Gateway room ledger.

    This proves the message was written to the Council Chamber before the Gateway
    advances the state machine.
    """
    row = db.execute(
        """
        SELECT sender_role, content, metadata_json
        FROM proposal_room_messages
        WHERE room_id=? AND message_id=?
        """,
        (room_id, message_id),
    ).fetchone()
    if not row:
        raise HTTPException(
            status_code=409,
            detail="Claimed room message was not found in the Council Chamber.",
        )

    sender_role = row["sender_role"] or ""
    if sender_role and agent_role != "gateway" and sender_role != agent_role:
        raise HTTPException(
            status_code=409,
            detail="Room message sender does not match the confirming agent role.",
        )

    metadata = {}
    try:
        metadata = json.loads(row["metadata_json"] or "{}")
    except (TypeError, json.JSONDecodeError):
        metadata = {}

    metadata_hash = metadata.get("card_hash")
    content = row["content"] or ""
    if metadata_hash:
        if metadata_hash != card_hash:
            raise HTTPException(
                status_code=409,
                detail="Room message metadata points at a different sealed card.",
            )
        return

    if card_hash not in content:
        raise HTTPException(
            status_code=409,
            detail="Room message does not contain the sealed card hash.",
        )


# ---------------------------------------------------------------------------
# Role-bound submission authentication
# Each agent has its own key. The key determines which card types it can submit.
# ---------------------------------------------------------------------------

# Agent role → allowed card types.
# StructuredApproval and PolicyAuthorization are gateway-only:
# agents cannot fabricate human approvals or self-authorize execution.
_ROLE_ACL: dict[str, frozenset[str]] = {
    "recorder": frozenset({"ProposalCard"}),
    "triage": frozenset({"TriageDecision"}),
    "diagnosis": frozenset({"Assessment"}),
    "safety_reviewer": frozenset({"Verdict"}),
    "commander": frozenset({"ResponsePlan"}),
    "operator": frozenset({"CasperExecutionReceipt"}),
    "gateway": frozenset(CARD_TYPES.keys()),  # Gateway deterministic path
}

# Card types that require a specific prior state to exist.
# Maps card_type → set of allowed current states.
#
# Two execution paths must both reach EXECUTED:
#   Human:  PLANNED → StructuredApproval → APPROVED → CasperExecutionReceipt → EXECUTED
#   Policy: PLANNED → PolicyAuthorization → AUTHORIZED → CasperExecutionReceipt → EXECUTED
#
# Revision loops:
#   CHALLENGE → CHALLENGED → Assessment (re-investigate)
#   REJECTED → ResponsePlan (revise plan)
#   ESCALATED_HUMAN → ResponsePlan (act on human guidance)
_STATE_PREREQUISITES: dict[str, frozenset[str]] = {
    "TriageDecision": frozenset({"DETECTED"}),
    "Assessment": frozenset({"TRIAGED", "CHALLENGED"}),
    "Verdict": frozenset({"ASSESSED"}),
    "ResponsePlan": frozenset({"REVIEWED", "REJECTED", "ESCALATED_HUMAN"}),
    "StructuredApproval": frozenset({"PLANNED"}),
    "PolicyAuthorization": frozenset({"PLANNED"}),
    "CasperExecutionReceipt": frozenset({"APPROVED", "AUTHORIZED"}),
    "GovernanceSummary": frozenset({"EXECUTED"}),
    # ProposalCard has no prerequisite — it creates the proposal
}

# Populated at first request from env vars
_agent_keys: dict[str, str] | None = None


def _load_agent_keys() -> dict[str, str]:
    """Load unambiguous, role-bound submission keys.

    ``GATEWAY_SECRET`` is deliberately not accepted as an agent credential.
    Gateway-owned card paths call the sealing primitives directly; network
    agents receive only their dedicated least-privilege keys.
    """
    global _agent_keys
    if _agent_keys is not None:
        return _agent_keys

    _agent_keys = configured_key_to_role()
    return _agent_keys


def _reset_agent_keys_for_testing() -> None:
    """Clear the process-local auth cache for isolated test fixtures."""
    global _agent_keys
    _agent_keys = None


def _authenticate_agent(key: str, card_type: str) -> tuple[bool, str]:
    """Authenticate agent key AND verify card-type ACL.

    Returns (allowed, role_or_error).
    Fail-closed: unknown key → rejected. Wrong card type → 403.
    """
    if not key:
        return False, "Missing agent key"

    keys = _load_agent_keys()

    # If no keys configured at all (no GATEWAY_SECRET, no per-agent keys), fail closed
    if not keys:
        return False, "No submission keys configured — all requests rejected"

    role = keys.get(key)
    if role is None:
        return False, "Invalid agent key"

    # Check card-type ACL
    allowed_types = _ROLE_ACL.get(role, frozenset())
    if card_type not in allowed_types:
        return False, f"Agent role '{role}' cannot submit {card_type}"

    return True, role


def _validate_agent_key_basic(key: str) -> bool:
    """Basic key validation for endpoints that don't need card-type ACL
    (e.g., /confirm, /export). Fail-closed."""
    if not key:
        return False
    keys = _load_agent_keys()
    if not keys:
        return False
    return key in keys


# ---------------------------------------------------------------------------
# Risk floor mapping (deterministic override — code decides, not LLM)
# DAO-native labels are canonical. P1/P2/P3/P4 and RB-* aliases remain accepted
# only for older stored cards and older simulator payloads.
# ---------------------------------------------------------------------------
GOVERNANCE_IMPACT_RISK_FLOOR: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "unknown": "low",
    # Backward-compatible aliases. Do not emit these in public proof packs.
    "p1": "high",
    "p2": "medium",
    "p3": "low",
    "p4": "low",
}

RISK_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
GOVERNANCE_HIGH_RISK_PLAYBOOKS = frozenset({
    "treasury-cap-exceeded",
    "payment-settlement-review",
    "rwa-evidence-review",
})
LEGACY_HIGH_RISK_PLAYBOOK_ALIASES = frozenset({"RB-002", "RB-005"})


def _apply_risk_floor(card, db) -> None:
    """Apply deterministic risk floor to ResponsePlan cards.

    The LLM's risk_level is advisory input. The floor is authoritative.
    The model may underrate high-impact treasury actions; this deterministic floor prevents that.
    """
    if not hasattr(card, "risk_level"):
        return

    proposal_id = getattr(card, "proposal_id", None)
    if not proposal_id:
        return

    # Look up the proposal's assessed severity
    row = db.execute(
        "SELECT card_json FROM cards "
        "WHERE proposal_id=? AND card_type='Assessment' "
        "ORDER BY sequence_number DESC LIMIT 1",
        (proposal_id,),
    ).fetchone()

    if row:
        assessment = json.loads(row["card_json"])
        severity = str(assessment.get("severity") or "unknown").strip().lower()
        floor = GOVERNANCE_IMPACT_RISK_FLOOR.get(severity, "low")

        # Apply floor: effective_risk = max(llm_risk, floor)
        card.risk_level = str(card.risk_level or "low").strip().lower()
        llm_rank = RISK_RANK.get(card.risk_level, 0)
        floor_rank = RISK_RANK.get(floor, 0)
        if floor_rank > llm_rank:
            card.risk_level = floor

    # Also check high-risk governance playbooks → minimum high. RB-* values are
    # accepted only as compatibility aliases for old stored cards.
    playbook = str(
        getattr(card, "governance_playbook", "")
        or getattr(card, "policy_path", "")
        or getattr(card, "runbook", "")
        or ""
    ).strip()
    if playbook in GOVERNANCE_HIGH_RISK_PLAYBOOKS or playbook in LEGACY_HIGH_RISK_PLAYBOOK_ALIASES:
        if RISK_RANK.get(card.risk_level, 0) < RISK_RANK["high"]:
            card.risk_level = "high"

    # Recompute requires_human_approval with corrected risk
    if hasattr(card, "requires_human_approval") and hasattr(card, "envelopes"):
        envelopes = [e.model_dump() if hasattr(e, "model_dump") else e
                     for e in card.envelopes]
        constitution = load_constitution()
        card.requires_human_approval = requires_human_approval(
            card.risk_level,
            envelopes,
            requires_multisig_for_execution=bool(
                constitution.get("requires_multisig_for_execution", True)
            ),
        )


def _upsert_proposal(db, proposal_id: str, card_type: str, severity: str | None = None) -> None:
    """Ensure an proposal row exists before sealing a card against it.

    ONLY creates the proposal if it doesn't exist. State is NOT advanced
    here — state advances happen exclusively at /confirm after verified
    proposal-room publication. This prevents the DB claiming a state that the
    Council Chamber hasn't seen yet.
    """
    now = datetime.now(timezone.utc).isoformat()
    existing = db.execute(
        "SELECT proposal_id FROM proposals WHERE proposal_id=?",
        (proposal_id,),
    ).fetchone()

    if not existing:
        db.execute(
            "INSERT INTO proposals (proposal_id, state, severity, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (proposal_id, "DETECTED", severity, now, now),
        )
    # else: proposal already exists — do NOT update state here.


@router.post("/prepare/{card_type}")
async def prepare_card(
    card_type: str,
    request: Request,
    x_agent_key: str = Header(..., alias="X-Agent-Key"),
    x_idempotency_key: str | None = Header(None, alias="X-Idempotency-Key"),
):
    """Validate, enrich, and seal a card.

    Flow:
        1. Authenticate agent + verify card-type ACL
        2. Validate card_type exists
        3. Parse and validate body against Pydantic schema
        4. Apply deterministic enrichment (risk floor)
        5. Upsert proposal (prevents FK constraint failure)
        6. Seal with integrity chain (atomic sequence assignment)
        7. Return sealed card + submission_id + destination
    """
    # Role-bound auth: verify agent key + check card-type ACL
    if card_type not in CARD_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown card_type: {card_type}. "
            f"Valid types: {list(CARD_TYPES.keys())}",
        )

    allowed, role_or_error = _authenticate_agent(x_agent_key, card_type)
    if not allowed:
        status = 403 if "cannot submit" in role_or_error else 401
        raise HTTPException(status_code=status, detail=role_or_error)

    body = await request.json()
    body["card_type"] = card_type  # Ensure consistency

    # Validate against Pydantic schema
    try:
        card = CARD_TYPES[card_type].model_validate(body)
    except Exception as exc:
        logger.warning(
            "[submission] %s validation failed (%s)",
            card_type,
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=422,
            detail=f"Validation error for {card_type}.",
        ) from exc

    # Extract proposal_id (all cards except ProposalCard have it directly)
    proposal_id = getattr(card, "proposal_id", None)
    if proposal_id is None and card_type == "ProposalCard":
        proposal_id = card.signal_id  # Use signal_id as proposal key for ProposalCards

    if not proposal_id:
        raise HTTPException(status_code=400, detail="Missing proposal_id")

    db = request.app.state.db
    idempotency_key = x_idempotency_key or str(uuid.uuid4())

    # Compute pre-enrichment fingerprint NOW, before _apply_risk_floor
    # mutates the card. This is what we compare on idempotent retries.
    raw_fp = request_fingerprint(card.model_dump())

    # 1. Idempotency check FIRST — if this card was already sealed,
    # return it immediately (no prerequisite or upsert side effects).
    existing = db.execute(
        "SELECT card_hash, card_json, sequence_number, card_type, request_fp "
        "FROM cards "
        "WHERE proposal_id=? AND idempotency_key=? AND card_type=?",
        (proposal_id, idempotency_key, card_type),
    ).fetchone()
    if existing:
        # Compare against stored pre-enrichment fingerprint.
        stored_fp = existing["request_fp"]
        if not stored_fp:
            # Fallback for cards sealed before request_fp was added
            stored = json.loads(existing["card_json"])
            stored_fp = request_fingerprint(stored)
        if stored_fp != raw_fp:
            raise HTTPException(
                status_code=409,
                detail=f"Idempotency key {idempotency_key!r} already used "
                f"with a different payload for {card_type}",
            )
        room_row = db.execute(
            "SELECT legacy_room_id FROM proposals WHERE proposal_id=?",
            (proposal_id,),
        ).fetchone()
        legacy_room_id = room_row["legacy_room_id"] if room_row and room_row["legacy_room_id"] else None
        return {
            "submission_id": idempotency_key,
            "sealed_card": json.loads(existing["card_json"]),
            "card_hash": existing["card_hash"],
            "sequence_number": existing["sequence_number"],
            "proposal_id": proposal_id,
            "agent_role": role_or_error,
            "destination": {"legacy_room_id": legacy_room_id},
        }

    # 2. State prerequisites BEFORE upsert — don't create phantom
    # DETECTED proposals for out-of-order submissions.
    if card_type in _STATE_PREREQUISITES:
        current = db.execute(
            "SELECT state FROM proposals WHERE proposal_id=?",
            (proposal_id,),
        ).fetchone()
        if not current:
            raise HTTPException(
                status_code=409,
                detail=f"Cannot submit {card_type}: proposal {proposal_id!r} "
                f"does not exist yet.",
            )
        current_state = current["state"]
        allowed_states = _STATE_PREREQUISITES[card_type]
        if current_state not in allowed_states:
            raise HTTPException(
                status_code=409,
                detail=f"Cannot submit {card_type} when proposal is in state "
                f"{current_state!r}. Required: {sorted(allowed_states)}",
            )

    # 3. Upsert proposal (only for ProposalCard which has no prerequisite)
    severity = getattr(card, "severity", getattr(card, "preliminary_severity", None))
    _upsert_proposal(db, proposal_id, card_type, severity)

    # 4. Apply deterministic risk floor BEFORE sealing
    # (card is mutated — fingerprint was already captured above)
    _apply_risk_floor(card, db)

    # 5. Seal the card atomically with prepared_by_role and
    # pre-enrichment fingerprint.
    try:
        sealed = seal_card(
            card, proposal_id, db,
            idempotency_key=idempotency_key,
            prepared_by_role=role_or_error,
            request_fp=raw_fp,
        )
    except IdempotencyConflict as e:
        raise HTTPException(status_code=409, detail=str(e))

    # Look up room_id for this proposal (destination for proposal-room publish)
    room_row = db.execute(
        "SELECT legacy_room_id FROM proposals WHERE proposal_id=?",
        (proposal_id,),
    ).fetchone()
    legacy_room_id = room_row["legacy_room_id"] if room_row and room_row["legacy_room_id"] else None

    return {
        "submission_id": idempotency_key,  # Use idempotency_key as submission_id
        "sealed_card": json.loads(
            json.dumps(sealed.model_dump(), default=str)
        ),
        "card_hash": sealed.card_hash,
        "sequence_number": sealed.sequence_number,
        "proposal_id": proposal_id,
        "agent_role": role_or_error,
        "destination": {
            "room_id": legacy_room_id,
            # Compatibility alias for card schemas that still expose this field.
            "legacy_room_id": legacy_room_id,
        },
    }


@router.post("/confirm")
async def confirm_publication(
    request: Request,
    x_agent_key: str = Header(..., alias="X-Agent-Key"),
):
    """Confirm that a sealed card was published to the Council Chamber.

    Body: {
        "submission_id": "...",      (required — must match the prepare call)
        "message_id": "...",         (preferred)
        "proposal_id": "...",
        "card_hash": "...",
        "room_id": "..."             (optional — stored for future lookups)
    }

    Alias field names (room_message_id, legacy_room_id) are accepted for card
    schema compatibility. DAO Treasury verification resolves the claimed message
    from the Gateway-owned Council Chamber ledger.
    """
    # Auth validation — resolve role (not just key check)
    keys = _load_agent_keys()
    confirming_role = keys.get(x_agent_key)
    if not confirming_role:
        raise HTTPException(status_code=401, detail="Invalid agent key")

    body = await request.json()
    submission_id = body.get("submission_id")
    message_id = body.get("message_id") or body.get("room_message_id")
    proposal_id = body.get("proposal_id")
    card_hash = body.get("card_hash")
    room_id = body.get("room_id") or body.get("legacy_room_id")

    if not all([submission_id, message_id, proposal_id, card_hash]):
        raise HTTPException(
            status_code=400,
            detail="Missing submission_id, message_id, proposal_id, or card_hash",
        )

    # DAO Treasury accepts Gateway-owned room message IDs plus compact provider
    # IDs. Synthetic/mock IDs remain test-only.
    import re
    _REAL_MESSAGE_ID_PATTERN = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$|"
        r"^msg-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$|"
        r"^bm[a-zA-Z0-9]{6,64}$"
    )
    _is_test_mode = os.getenv("Concordia DAO Council_TEST_MODE", "").lower() in ("1", "true", "yes")
    _TEST_MESSAGE_ID_PATTERN = re.compile(
        r"^mock-msg-[a-zA-Z0-9_-]{4,64}$|"
        r"^synthetic-[a-zA-Z0-9_-]{8,64}$"
    )

    is_valid = bool(_REAL_MESSAGE_ID_PATTERN.match(message_id))
    if not is_valid and _is_test_mode:
        is_valid = bool(_TEST_MESSAGE_ID_PATTERN.match(message_id))

    if len(message_id) < 8 or not is_valid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid message_id format: '{message_id[:40]}'. "
            "Expected a real proposal-room message ID. "
            "Synthetic/fabricated IDs are not accepted in DAO treasury mode.",
        )

    db = request.app.state.db

    # Resolve the prepared card and its room before contacting Council Chamber.  These
    # checks are repeated inside the write transaction below to preserve the
    # existing TOCTOU protection around state advancement.
    prepared = db.execute(
        "SELECT card_type, prepared_by_role, published_at, room_message_id "
        "FROM cards WHERE proposal_id=? AND card_hash=? AND idempotency_key=?",
        (proposal_id, card_hash, submission_id),
    ).fetchone()
    if not prepared:
        raise HTTPException(
            status_code=404,
            detail="Card not found — submission_id/card_hash/proposal_id mismatch. "
            "Was it prepared first?",
        )

    prepared_by = prepared["prepared_by_role"]
    if not prepared_by:
        if confirming_role != "gateway":
            raise HTTPException(
                status_code=403,
                detail="Card has no recorded preparing role. Only gateway can confirm it.",
            )
    elif confirming_role != "gateway" and confirming_role != prepared_by:
        raise HTTPException(
            status_code=403,
            detail=f"Agent role '{confirming_role}' cannot confirm a card "
            f"prepared by '{prepared_by}'",
        )

    # Strict idempotency: a retry must repeat the same room message ID.
    if prepared["published_at"] is not None:
        if prepared["room_message_id"] != message_id:
            raise HTTPException(
                status_code=409,
                detail="Card was already confirmed with a different message ID.",
            )
        return {
            "status": "already_confirmed",
            "proposal_id": proposal_id,
            "card_hash": card_hash,
            "room_message_id": prepared["room_message_id"],
            "message_id": prepared["room_message_id"],
        }

    proposal_row = db.execute(
        "SELECT room_id, legacy_room_id FROM proposals WHERE proposal_id=?",
        (proposal_id,),
    ).fetchone()
    stored_room_id = (
        (proposal_row["room_id"] or proposal_row["legacy_room_id"])
        if proposal_row
        else None
    )
    if stored_room_id and room_id and stored_room_id != room_id:
        raise HTTPException(
            status_code=400,
            detail="room_id does not match the proposal's registered room.",
        )
    expected_room_id = stored_room_id or room_id

    # Publication verification is deliberately outside the SQLite write lock.
    # It is local DB I/O now, but keeping it outside preserves the old
    # low-contention shape and the transactional checks below still repeat.
    if not _is_test_mode:
        if not expected_room_id:
            raise HTTPException(
                status_code=409,
                detail="Cannot verify publication because the proposal has no room.",
            )
        verification_role = prepared_by or confirming_role
        _verify_room_publication(
            db,
            room_id=expected_room_id,
            message_id=message_id,
            card_hash=card_hash,
            agent_role=verification_role,
        )

    # Prevent reuse of one room message for a different sealed card.
    reuse_row = db.execute(
        "SELECT card_hash FROM cards WHERE room_message_id=? AND published_at IS NOT NULL",
        (message_id,),
    ).fetchone()
    if reuse_row and reuse_row["card_hash"] != card_hash:
        raise HTTPException(
            status_code=409,
            detail=f"message_id '{message_id[:20]}...' already used "
            f"for a different card {reuse_row['card_hash'][:12]}. "
            "Each card requires a unique room message ID.",
        )

    db = request.app.state.db
    now = datetime.now(timezone.utc).isoformat()

    # === ALL validation and mutation inside one transaction ===
    # This prevents TOCTOU: concurrent confirmations both passing validation
    # then committing sequentially. BEGIN IMMEDIATE acquires a write lock.
    db.execute("BEGIN IMMEDIATE")
    try:
        # 1. Find the card
        card_row = db.execute(
            "SELECT card_type, card_json, sequence_number, published_at, "
            "room_message_id, prepared_by_role "
            "FROM cards "
            "WHERE proposal_id=? AND card_hash=? AND idempotency_key=?",
            (proposal_id, card_hash, submission_id),
        ).fetchone()

        if not card_row:
            db.execute("ROLLBACK")
            raise HTTPException(
                status_code=404,
                detail="Card not found — submission_id/card_hash/proposal_id mismatch. "
                "Was it prepared first?",
            )

        # 2. Role check (before any success response)
        prepared_by = card_row["prepared_by_role"]
        if not prepared_by:
            if confirming_role != "gateway":
                db.execute("ROLLBACK")
                raise HTTPException(
                    status_code=403,
                    detail="Card has no recorded preparing role (possible crash). "
                    "Only gateway can confirm it.",
                )
        elif confirming_role != "gateway" and confirming_role != prepared_by:
            db.execute("ROLLBACK")
            raise HTTPException(
                status_code=403,
                detail=f"Agent role '{confirming_role}' cannot confirm a card "
                f"prepared by '{prepared_by}'",
            )

        # 3. Idempotent success (after role check)
        if card_row["published_at"] is not None:
            if card_row["room_message_id"] != message_id:
                db.execute("ROLLBACK")
                raise HTTPException(
                    status_code=409,
                    detail="Card was already confirmed with a different message ID.",
                )
            db.execute("ROLLBACK")
            return {
                "status": "already_confirmed",
                "proposal_id": proposal_id,
                "card_hash": card_hash,
                "room_message_id": card_row["room_message_id"],
                "message_id": card_row["room_message_id"],
            }

        # Re-check message reuse while holding the write lock.  The earlier
        # check avoids unnecessary transactions for normal requests, but two
        # concurrent confirmations could otherwise both pass it before either
        # one commits.  One room message may certify exactly one sealed card.
        reuse_row = db.execute(
            "SELECT proposal_id, card_hash FROM cards "
            "WHERE room_message_id=? AND published_at IS NOT NULL LIMIT 1",
            (message_id,),
        ).fetchone()
        if reuse_row and reuse_row["card_hash"] != card_hash:
            db.execute("ROLLBACK")
            raise HTTPException(
                status_code=409,
                detail="Room message ID is already bound to a different sealed card.",
            )

        card_type_to_confirm = card_row["card_type"]
        card_seq = card_row["sequence_number"]
        new_state = _resolve_state(card_type_to_confirm, card_row["card_json"])

        # 4. Prerequisite state check + ProposalCard regression guard
        current = db.execute(
            "SELECT state FROM proposals WHERE proposal_id=?",
            (proposal_id,),
        ).fetchone()
        current_state = current["state"] if current else None

        # ProposalCard regression guard: if the proposal has progressed
        # past DETECTED, a late ProposalCard must not reset it.
        if (card_type_to_confirm == "ProposalCard"
                and current_state
                and current_state != "DETECTED"):
            # Still publish the card (for the audit trail) but suppress
            # the state transition. ProposalCards are informational after
            # the first one — they don't drive the state machine.
            new_state = None

        if current_state and card_type_to_confirm in _STATE_PREREQUISITES:
            allowed = _STATE_PREREQUISITES[card_type_to_confirm]
            if current_state not in allowed:
                db.execute("ROLLBACK")
                raise HTTPException(
                    status_code=409,
                    detail=f"Cannot confirm {card_type_to_confirm}: proposal state "
                    f"is now {current_state!r} (expected {sorted(allowed)}). "
                    f"This card is stale.",
                )

        # 5. Sequence-based staleness check.
        # If any card with a HIGHER sequence_number has already been
        # confirmed (published), this card is stale — it was prepared
        # before newer decisions were made and confirmed.
        # This catches ALL stale-card scenarios including:
        #   - Old CONFIRM Verdict after CHALLENGE → revised Assessment
        #   - Old ResponsePlan approval after plan revision
        #   - Old Assessment after a new one was investigated
        newer_confirmed = db.execute(
            "SELECT MIN(sequence_number) as newer_seq, card_type FROM cards "
            "WHERE proposal_id=? AND sequence_number > ? "
            "AND published_at IS NOT NULL "
            "LIMIT 1",
            (proposal_id, card_seq),
        ).fetchone()

        if newer_confirmed and newer_confirmed["newer_seq"] is not None:
            db.execute("ROLLBACK")
            raise HTTPException(
                status_code=409,
                detail=f"Stale card rejected: a newer card (seq "
                f"{newer_confirmed['newer_seq']}, type "
                f"{newer_confirmed['card_type']}) was already confirmed. "
                f"This card (seq {card_seq}) is outdated.",
            )

        # 6. Atomic: publish card + advance state
        db.execute(
            "UPDATE cards SET published_at=?, room_message_id=? "
            "WHERE proposal_id=? AND card_hash=? AND idempotency_key=?",
            (now, message_id, proposal_id, card_hash, submission_id),
        )

        updates = ["updated_at=?"]
        params: list = [now]

        if new_state:
            updates.append("state=?")
            params.append(new_state)
        if room_id:
            updates.append("room_id=?")
            params.append(room_id)
            updates.append("legacy_room_id=?")
            params.append(room_id)

        # Update proposal severity when Assessment provides a diagnosed severity
        if card_type_to_confirm == "Assessment":
            try:
                card_json = json.loads(card_row["card_json"])
                assessed_severity = card_json.get("severity")
                if assessed_severity:
                    updates.append("severity=?")
                    params.append(assessed_severity)
            except (json.JSONDecodeError, TypeError):
                pass

        params.append(proposal_id)
        db.execute(
            f"UPDATE proposals SET {', '.join(updates)} WHERE proposal_id=?",
            params,
        )
        db.execute("COMMIT")
    except HTTPException:
        # HTTPExceptions already rolled back above — re-raise
        raise
    except Exception:
        db.execute("ROLLBACK")
        raise

    # ── Scribe hook: DISABLED ─────────────────────────────────────────
    # Scribe is now a Concordia DAO Council governance summary writer (Internal Agent) triggered by
    # Casper Execution Agent posts governance summary requests into the Council Chamber after execution.
    # The gateway no longer auto-generates governance summaries server-side.

    return {
        "status": "confirmed",
        "proposal_id": proposal_id,
        "card_hash": card_hash,
        "room_message_id": message_id,
        "message_id": message_id,
        "new_state": new_state,
    }


@router.get("/export/evidence/{proposal_id}")
async def export_evidence(
    proposal_id: str,
    request: Request,
    x_agent_key: str = Header(..., alias="X-Agent-Key"),
):
    """Export all sealed cards + chain verification for an proposal."""
    if not _validate_agent_key_basic(x_agent_key):
        raise HTTPException(status_code=401, detail="Invalid agent key")

    from shared.integrity import verify_chain

    db = request.app.state.db

    cards = db.execute(
        "SELECT card_json, card_hash, sequence_number, published_at, room_message_id "
        "FROM cards WHERE proposal_id=? ORDER BY sequence_number ASC",
        (proposal_id,),
    ).fetchall()

    is_valid, errors = verify_chain(proposal_id, db)

    return {
        "proposal_id": proposal_id,
        "total_cards": len(cards),
        "chain_valid": is_valid,
        "chain_errors": errors,
        "cards": [
            {
                "sequence": row["sequence_number"],
                "hash": row["card_hash"],
                "published": row["published_at"] is not None,
                "data": json.loads(row["card_json"]),
            }
            for row in cards
        ],
    }


@router.get("/proposals/{proposal_id}/cards")
async def get_proposal_cards(
    proposal_id: str,
    request: Request,
    x_agent_key: str = Header(..., alias="X-Agent-Key"),
    card_type: str | None = None,
):
    """Get all cards for an proposal, optionally filtered by type.

    Used by Protocol Strategy Agent to fetch the Assessment linked to a Verdict.
    """
    if not _validate_agent_key_basic(x_agent_key):
        raise HTTPException(status_code=401, detail="Invalid agent key")

    db = request.app.state.db

    if card_type:
        cards = db.execute(
            "SELECT card_json, card_hash, card_type, sequence_number, published_at "
            "FROM cards WHERE proposal_id=? AND card_type=? "
            "ORDER BY sequence_number DESC",
            (proposal_id, card_type),
        ).fetchall()
    else:
        cards = db.execute(
            "SELECT card_json, card_hash, card_type, sequence_number, published_at "
            "FROM cards WHERE proposal_id=? ORDER BY sequence_number ASC",
            (proposal_id,),
        ).fetchall()

    return {
        "proposal_id": proposal_id,
        "total": len(cards),
        "cards": [
            {
                "card_type": row["card_type"],
                "sequence": row["sequence_number"],
                "hash": row["card_hash"],
                "published": row["published_at"] is not None,
                "data": json.loads(row["card_json"]),
            }
            for row in cards
        ],
    }
