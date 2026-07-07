"""CONCORDIA Gateway — Authorization Routes (Fork B: Gateway-owned).

POST /api/authorization/request — Protocol Strategy Agent requests policy authorization for low-risk plans.
    Gateway validates confirmed ResponsePlan, derives risk_level from stored plan,
    builds PolicyAuthorization, seals it, and advances state PLANNED → AUTHORIZED.

These cards are Gateway-owned (see _ROLE_ACL line 80):
    "StructuredApproval and PolicyAuthorization are gateway-only:
     agents cannot fabricate human approvals or self-authorize execution."
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from gateway.routes.rooms import store_room_message, store_room_participant
from shared.approval import constitution_bound_execution_reason
from shared.dao_policy import load_constitution
from shared.models import PolicyAuthorization

logger = logging.getLogger("concordia.authorization")

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class PolicyAuthRequest(BaseModel):
    """Protocol Strategy Agent requests policy authorization for a low-risk plan."""
    proposal_id: str
    plan_hash: str
    # action_hash and envelopes are NOT accepted from request body.
    # They are derived from the confirmed ResponsePlan in the Gateway DB.
    expiry_minutes: int = 30  # Default 30 min


class PolicyAuthResponse(BaseModel):
    authorized: bool
    authorization_id: str
    proposal_id: str
    card_hash: str
    new_state: str


class AuthorizationConsumeRequest(BaseModel):
    proposal_id: str  # ONLY proposal_id - Gateway derives everything


class AuthorizationConsumeResponse(BaseModel):
    authorization_id: str
    proposal_id: str
    plan_hash: str
    action_hash: str
    envelopes: list


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _authenticate_commander(key: str) -> tuple[bool, str]:
    """Verify X-Agent-Key belongs to 'commander' or 'gateway' role."""
    if not key:
        return False, "Missing X-Agent-Key header"

    from gateway.routes.submission import _load_agent_keys
    keys = _load_agent_keys()
    if not keys:
        return False, "No agent keys configured"
    role = keys.get(key)
    if role is None:
        return False, "Invalid agent key"
    if role not in ("commander", "gateway"):
        return False, f"Role {role!r} cannot request authorization"
    return True, role


def _authenticate_operator(key: str) -> tuple[bool, str]:
    """Verify X-Agent-Key belongs to the 'operator' role.

    Reuses the same _load_agent_keys() as card submission.
    Fail-closed: no key / wrong role → rejected.
    """
    if not key:
        return False, "Missing X-Agent-Key header"

    from gateway.routes.submission import _load_agent_keys
    keys = _load_agent_keys()
    if not keys:
        return False, "No agent keys configured"
    role = keys.get(key)
    if role is None:
        return False, "Invalid agent key"
    if role not in ("operator", "gateway"):
        return False, f"Role '{role}' is not authorized to consume authorizations"
    return True, role


def _requires_multisig_for_execution() -> bool:
    """Read the DAO Constitution fail-closed for PolicyAuthorization."""
    try:
        return bool(load_constitution().get("requires_multisig_for_execution", True))
    except Exception:
        logger.exception("[authorization] Failed to load DAO Constitution; requiring multisig.")
        return True


def _policy_authorization_block_reason(envelopes: list[dict]) -> str | None:
    return constitution_bound_execution_reason(
        envelopes,
        requires_multisig_for_execution=_requires_multisig_for_execution(),
    )


# ---------------------------------------------------------------------------
# Gateway-owned PolicyAuthorization (low-risk path)
# ---------------------------------------------------------------------------

@router.post("/authorization/request", response_model=PolicyAuthResponse)
async def request_policy_authorization(
    body: PolicyAuthRequest,
    request: Request,
    x_agent_key: str = Header(..., alias="X-Agent-Key"),
):
    """Gateway issues PolicyAuthorization for low-risk plans.

    The Gateway is the SOLE authority — risk_level, envelopes, and action_hash
    are ALL derived from the confirmed ResponsePlan in the DB, NOT from
    the request body. The Protocol Strategy Agent only provides proposal_id + plan_hash.

    Prerequisites:
        - Proposal must be in PLANNED state (ResponsePlan confirmed)
        - Stored ResponsePlan risk_level must be "low" or "medium"
        - requires_human_approval must be False
        - Protocol Strategy Agent role verified via X-Agent-Key

    The Gateway:
        1. Validates state is PLANNED
        2. Fetches the confirmed ResponsePlan
        3. Derives risk_level, envelopes, action_hash from stored plan
        4. Rejects if high-risk or requires_human_approval
        5. Builds a PolicyAuthorization card
        6. Seals it into the integrity chain (seal_card owns the transaction)
        7. Advances state to AUTHORIZED + creates authorization record
    """
    # --- Auth ---
    authed, role_or_error = _authenticate_commander(x_agent_key)
    if not authed:
        logger.warning(f"[authorization] Auth FAILED: {role_or_error}")
        status = 403 if "cannot request" in role_or_error else 401
        raise HTTPException(status_code=status, detail=role_or_error)

    db = request.app.state.db
    now = datetime.now(timezone.utc)

    # --- Idempotency check (BEFORE state validation) ---
    # On retry, state may already be AUTHORIZED — so check idempotency first.
    from shared.card_intake import derive_idempotency_key

    idem_key = derive_idempotency_key(
        "gateway_policy_auth", body.proposal_id, body.plan_hash,
    )

    existing_card = db.execute(
        "SELECT card_json, card_hash FROM cards "
        "WHERE idempotency_key=? AND proposal_id=? AND card_type='PolicyAuthorization'",
        (idem_key, body.proposal_id),
    ).fetchone()

    needs_seal = True
    sealed_card_hash = None
    authorization_id = None
    stored_risk = None
    stored_envelopes = []
    stored_action_hash = None

    if existing_card:
        try:
            card_data = json.loads(existing_card["card_json"])
            authorization_id = card_data.get("authorization_id")
            stored_risk = card_data.get("risk_level", "high")
            stored_envelopes = card_data.get("envelopes", [])
            stored_action_hash = card_data.get("action_hash")
            sealed_card_hash = existing_card["card_hash"]
        except Exception:
            raise HTTPException(status_code=500, detail="Corrupted existing PolicyAuthorization card.")

        block_reason = _policy_authorization_block_reason(stored_envelopes)
        if block_reason:
            raise HTTPException(status_code=403, detail=block_reason)

        if not authorization_id:
            raise HTTPException(status_code=500, detail="Missing authorization_id in existing card.")

        auth_row = db.execute(
            "SELECT status FROM authorizations WHERE authorization_id=? AND card_hash=?",
            (authorization_id, sealed_card_hash),
        ).fetchone()

        if not auth_row:
            raise HTTPException(status_code=500, detail="Authorization record missing for existing card.")

        status = auth_row["status"]

        if status == "PUBLISHED":
            inc_row = db.execute("SELECT state FROM proposals WHERE proposal_id=?", (body.proposal_id,)).fetchone()
            if inc_row and inc_row["state"] == "AUTHORIZED":
                return PolicyAuthResponse(
                    authorized=True,
                    authorization_id=authorization_id,
                    proposal_id=body.proposal_id,
                    card_hash=sealed_card_hash,
                    new_state="AUTHORIZED",
                )
            else:
                raise HTTPException(status_code=409, detail="inconsistent_lifecycle")
        elif status == "CONSUMED":
            raise HTTPException(status_code=409, detail="already_consumed")
        elif status == "PENDING":
            # Proceed to revalidate and republish
            needs_seal = False

    # --- Validate state is PLANNED ---
    proposal = db.execute(
        "SELECT state FROM proposals WHERE proposal_id=?",
        (body.proposal_id,),
    ).fetchone()

    if not proposal:
        raise HTTPException(
            status_code=404,
            detail=f"Proposal {body.proposal_id} not found",
        )

    if proposal["state"] != "PLANNED":
        raise HTTPException(
            status_code=409,
            detail=f"Proposal state is {proposal['state']!r}, expected 'PLANNED'. "
            f"ResponsePlan must be confirmed before requesting authorization.",
        )

    # --- Fetch confirmed ResponsePlan (AUTHORITATIVE source of truth) ---
    plan_card = db.execute(
        "SELECT card_json, card_hash FROM cards "
        "WHERE proposal_id=? AND card_type='ResponsePlan' "
        "AND published_at IS NOT NULL "
        "ORDER BY sequence_number DESC LIMIT 1",
        (body.proposal_id,),
    ).fetchone()

    if not plan_card:
        raise HTTPException(
            status_code=409,
            detail="No confirmed ResponsePlan found for this proposal.",
        )

    try:
        plan_data = json.loads(plan_card["card_json"])
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(
            status_code=500,
            detail="Confirmed ResponsePlan is corrupted (invalid JSON). Cannot authorize.",
        )

    # --- Cross-check plan_hash (fail-closed) ---
    # The Protocol Strategy Agent computes plan_hash from model_dump() BEFORE seal_card
    # adds chain fields (card_hash, previous_card_hash, sequence_number).
    # The stored card_json has seal-set values for those fields.
    # To match the Protocol Strategy Agent's hash, reset chain fields to pre-seal defaults.
    from shared.approval import compute_plan_hash as _compute_plan_hash, normalize_plan_for_hash as _normalize
    stored_plan_hash = _compute_plan_hash(_normalize(plan_data))
    if stored_plan_hash != body.plan_hash:
        raise HTTPException(
            status_code=400,
            detail="plan_hash mismatch: request does not match confirmed ResponsePlan.",
        )

    # --- Derive envelopes + action_hash from stored plan ---
    stored_envelopes = plan_data.get("envelopes", [])

    if not stored_envelopes:
        raise HTTPException(
            status_code=500,
            detail="Confirmed ResponsePlan has no envelopes. Cannot authorize.",
        )

    block_reason = _policy_authorization_block_reason(stored_envelopes)
    if block_reason:
        raise HTTPException(status_code=403, detail=block_reason)

    # --- Derive risk_level from stored plan (NOT from request body) ---
    stored_risk = str(plan_data.get("risk_level", "high") or "high").strip().lower()
    stored_requires_human = plan_data.get("requires_human_approval", True)

    if stored_risk not in ("low", "medium"):
        raise HTTPException(
            status_code=403,
            detail=f"ResponsePlan risk_level is {stored_risk!r}. "
            f"PolicyAuthorization is only for low/medium risk. "
            f"High-risk plans require human approval via nonce.",
        )

    if stored_requires_human:
        raise HTTPException(
            status_code=403,
            detail="ResponsePlan requires human approval (requires_human_approval=True). "
            "Cannot auto-authorize. Use nonce/human approval path.",
        )

    # action_hash is NOT stored in card_json — always recompute from envelopes
    from shared.approval import compute_action_hash
    stored_action_hash = compute_action_hash(stored_envelopes)



    if needs_seal:
        # --- Build PolicyAuthorization card ---
        authorization_id = str(uuid.uuid4())
        expiry = now + timedelta(minutes=body.expiry_minutes)

        auth_card = PolicyAuthorization(
            proposal_id=body.proposal_id,
            authorization_id=authorization_id,
            plan_hash=body.plan_hash,
            action_hash=stored_action_hash,
            risk_level=stored_risk,
            policy_rule="auto_approve_low_risk",
            expiry=expiry,
            envelopes=stored_envelopes,
        )

        # --- Atomic preparation: seal + PENDING auth record in one txn ---
        # Prevents orphan cards if crash between seal and auth record creation.
        from shared.integrity import seal_card_in_transaction

        db.execute("BEGIN IMMEDIATE")
        try:
            # 1. Seal PolicyAuthorization card (no nested BEGIN)
            sealed = seal_card_in_transaction(
                auth_card, body.proposal_id, db,
                idempotency_key=idem_key,
                prepared_by_role="gateway",
            )
            sealed_card_hash = sealed.card_hash

            # Create authorization record for consumption tracking (PENDING initially)
            db.execute(
                "INSERT OR IGNORE INTO authorizations "
                "(authorization_id, proposal_id, authorization_type, plan_hash, "
                "action_hash, envelopes_json, expiry, created_at, consumed, status, card_hash) "
                "VALUES (?, ?, 'policy', ?, ?, ?, ?, ?, 0, 'PENDING', ?)",
                (authorization_id, body.proposal_id, body.plan_hash,
                 stored_action_hash, json.dumps(stored_envelopes),
                 expiry.isoformat(), now.isoformat(), sealed_card_hash),
            )

            db.execute("COMMIT")
        except Exception:
            db.execute("ROLLBACK")
            raise

    # --- Post-commit: post sealed card to the Gateway-owned Council Chamber ---
    # Fail-closed: if room publication fails, state stays PENDING and retry is safe.
    # On retry, idempotency detects the existing card and returns stored result.
    from shared.submission_client import format_card_message

    # Fetch room_id from the proposal record. ``legacy_room_id`` is a temporary
    # compatibility alias while the schema is being renamed.
    inc_row = db.execute(
        "SELECT room_id, legacy_room_id FROM proposals WHERE proposal_id=?",
        (body.proposal_id,),
    ).fetchone()
    room_id = None
    if inc_row:
        room_id = inc_row["room_id"] or inc_row["legacy_room_id"]

    if not room_id:
        logger.error(
            f"[authorization] No room_id for proposal {body.proposal_id} — "
            f"cannot publish PolicyAuthorization"
        )
        raise HTTPException(
            status_code=502,
            detail="Cannot publish PolicyAuthorization: no Council Chamber for this proposal. "
            "Authorization is PENDING — retry is safe.",
        )

    # Use Recorder identity (system/gateway role), NOT Protocol Strategy Agent's identity.
    recorder_agent_id = os.getenv("RECORDER_AGENT_ID", "recorder")
    operator_agent_id = os.getenv("OPERATOR_AGENT_ID", "")

    if not operator_agent_id:
        logger.error(
            "[authorization] OPERATOR_AGENT_ID not configured — "
            "cannot mention Casper Execution Agent"
        )
        raise HTTPException(
            status_code=502,
            detail="Cannot publish PolicyAuthorization: OPERATOR_AGENT_ID not configured. "
            "Authorization is PENDING — retry is safe.",
        )

    # ⚠️ INTEGRITY NOTE: card_hash is excluded from card_json during sealing
    # to prevent self-referential hashing. We inject it into the proposal-room
    # message COPY only. DB card_json MUST remain hash-free.
    row = db.execute(
        "SELECT card_json, card_hash FROM cards WHERE card_hash=? AND proposal_id=?",
        (sealed_card_hash, body.proposal_id),
    ).fetchone()
    sealed_card_data = json.loads(row["card_json"])
    sealed_card_data["card_hash"] = row["card_hash"]  # Copy only — DB untouched
    sealed_message = format_card_message(sealed_card_data)

    try:
        store_room_participant(
            db,
            room_id,
            operator_agent_id,
            role="operator",
            display_name="Casper Execution Agent",
        )
        message = store_room_message(
            db,
            room_id,
            sealed_message,
            sender_id=recorder_agent_id,
            sender_role="recorder",
            mentions=[operator_agent_id],
            metadata={
                "publisher": "gateway",
                "card_hash": sealed_card_hash,
            },
        )
        message_id = message["message_id"]
    except Exception as exc:
        logger.error(
            "[authorization] Proposal-room publication failed for proposal %s (%s); "
            "leaving authorization PENDING",
            body.proposal_id,
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=502,
            detail="PolicyAuthorization was sealed but proposal-room publication failed. "
            "Authorization remains PENDING; retry is safe.",
        ) from exc

    # --- Room post succeeded: advance state + mark PUBLISHED (atomic) ---
    from shared.approval import advance_authorization_lifecycle
    advance_authorization_lifecycle(
        db=db,
        proposal_id=body.proposal_id,
        card_hash=sealed_card_hash,
        authorization_id=authorization_id,
        room_message_id=message_id,
        target_proposal_state="AUTHORIZED"
    )

    logger.info(
        f"[authorization] PolicyAuthorization issued + published to Council Chamber: "
        f"proposal={body.proposal_id}, auth_id={authorization_id[:12]}..., "
        f"risk={stored_risk}, message_id={message_id}"
    )

    return PolicyAuthResponse(
        authorized=True,
        authorization_id=authorization_id,
        proposal_id=body.proposal_id,
        card_hash=sealed_card_hash,
        new_state="AUTHORIZED",
    )


# ---------------------------------------------------------------------------
# Consume authorization (Casper Execution Agent consumes a PUBLISHED authorization)
# ---------------------------------------------------------------------------

@router.post("/authorization/{authorization_id}/consume",
             response_model=AuthorizationConsumeResponse)
async def consume_authorization(
    authorization_id: str,
    body: AuthorizationConsumeRequest,
    request: Request,
    x_agent_key: str = Header(..., alias="X-Agent-Key"),
):
    """Casper Execution Agent consumes a PUBLISHED PolicyAuthorization.

    Lifecycle: PENDING → PUBLISHED → CONSUMED.
    Only PUBLISHED authorizations can be consumed.
    PENDING returns 409 (retryable), CONSUMED returns 409 (replay blocked).
    """
    # --- Auth: Casper Execution Agent role required ---
    authed, role_or_error = _authenticate_operator(x_agent_key)
    if not authed:
        logger.warning(f"[consume] Auth FAILED: {role_or_error}")
        status = 403 if "not authorized" in role_or_error else 401
        raise HTTPException(status_code=status, detail=role_or_error)

    db = request.app.state.db
    now = datetime.now(timezone.utc)

    # --- Load authorization record ---
    auth_row = db.execute(
        "SELECT * FROM authorizations WHERE authorization_id=?",
        (authorization_id,),
    ).fetchone()

    if not auth_row:
        raise HTTPException(status_code=404, detail="Unknown authorization_id")

    # --- Check status (PENDING/CONSUMED/PUBLISHED) ---
    auth_status = auth_row["status"] or "PENDING"
    if auth_status == "PENDING":
        raise HTTPException(status_code=409, detail="authorization_pending")
    if auth_status == "CONSUMED":
        raise HTTPException(status_code=409, detail="already_consumed")
    if auth_status != "PUBLISHED":
        raise HTTPException(
            status_code=409,
            detail=f"Authorization status is {auth_status!r}, expected 'PUBLISHED'",
        )

    # --- Validate proposal_id matches ---
    if auth_row["proposal_id"] != body.proposal_id:
        raise HTTPException(
            status_code=400,
            detail=f"Proposal mismatch — authorization is for "
            f"{auth_row['proposal_id']!r}, not {body.proposal_id!r}",
        )

    # --- Check not expired ---
    expiry = datetime.fromisoformat(auth_row["expiry"])
    if now > expiry:
        raise HTTPException(status_code=410, detail="Authorization expired")

    # --- Load confirmed ResponsePlan from cards table ---
    plan_card = db.execute(
        "SELECT card_json, card_hash FROM cards "
        "WHERE proposal_id=? AND card_type='ResponsePlan' "
        "AND published_at IS NOT NULL "
        "ORDER BY sequence_number DESC LIMIT 1",
        (body.proposal_id,),
    ).fetchone()

    if not plan_card:
        raise HTTPException(
            status_code=409,
            detail="No confirmed ResponsePlan found for this proposal.",
        )

    try:
        plan_data = json.loads(plan_card["card_json"])
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(
            status_code=500,
            detail="Confirmed ResponsePlan is corrupted (invalid JSON).",
        )

    # --- Recompute plan_hash and action_hash from stored plan ---
    from shared.approval import compute_plan_hash as _compute_plan_hash, normalize_plan_for_hash as _normalize
    from shared.approval import compute_action_hash as _compute_action_hash

    recomputed_plan_hash = _compute_plan_hash(_normalize(plan_data))

    stored_envelopes = plan_data.get("envelopes", [])
    recomputed_action_hash = _compute_action_hash(stored_envelopes)

    # --- Compare against authorization record ---
    if recomputed_plan_hash != auth_row["plan_hash"]:
        raise HTTPException(
            status_code=409,
            detail="plan_hash mismatch: stored plan has changed since authorization.",
        )
    if recomputed_action_hash != auth_row["action_hash"]:
        raise HTTPException(
            status_code=409,
            detail="action_hash mismatch: envelopes have changed since authorization.",
        )

    # --- Atomically: PUBLISHED → CONSUMED ---
    db.execute("BEGIN IMMEDIATE")
    try:
        # Re-check status under lock to prevent TOCTOU race
        locked_row = db.execute(
            "SELECT status FROM authorizations WHERE authorization_id=?",
            (authorization_id,),
        ).fetchone()
        if locked_row["status"] != "PUBLISHED":
            db.execute("ROLLBACK")
            raise HTTPException(
                status_code=409,
                detail=f"Authorization status changed to {locked_row['status']!r} (race)",
            )

        db.execute(
            "UPDATE authorizations SET status='CONSUMED', "
            "consumed_by=?, consumed_at=?, consumed=1 "
            "WHERE authorization_id=? AND status='PUBLISHED'",
            (role_or_error, now.isoformat(), authorization_id),
        )

        db.execute("COMMIT")
    except HTTPException:
        raise
    except Exception:
        db.execute("ROLLBACK")
        raise

    # --- Return authoritative envelopes from stored authorization record ---
    auth_envelopes = json.loads(auth_row["envelopes_json"]) if auth_row["envelopes_json"] else []

    logger.info(
        f"[consume] Authorization consumed: auth_id={authorization_id[:12]}..., "
        f"proposal={body.proposal_id}, consumed_by={role_or_error}"
    )

    return AuthorizationConsumeResponse(
        authorization_id=authorization_id,
        proposal_id=body.proposal_id,
        plan_hash=auth_row["plan_hash"],
        action_hash=auth_row["action_hash"],
        envelopes=auth_envelopes,
    )
