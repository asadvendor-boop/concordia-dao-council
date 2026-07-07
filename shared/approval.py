"""CONCORDIA Approval System — Nonce validation and authorization verification.

Both Protocol Strategy Agent and Casper Execution Agent independently verify approvals from the
platform-issued PlatformMessage. Neither agent trusts the other's
interpretation.

Human approval uses nonce-based challenge-response.
Low-risk actions use deterministic PolicyAuthorization.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from datetime import datetime, timezone


# DAO/Casper actions that alter governance state or commit an irreversible
# receipt. These are constitution-bound actions, not model-advisory actions.
DAO_MUTATING_ACTIONS = frozenset({
    "execute_casper_governance_receipt",
    "execute_casper_rejection_receipt",
    "execute_casper_dissent_receipt",
    "execute_casper_x402_settlement",
    "execute_casper_wallet_signed_receipt",
    "rebalance_liquidity_allocation",
    "authorize_rwa_escrow",
})

# Legacy infrastructure verbs are retained for compatibility with older stored
# cards, but the DAO-native actions above are now the load-bearing policy set.
LEGACY_MUTATING_ACTIONS = frozenset({
    "scale_down",
    "terminate_instance",
    "modify_security_group",
    "delete_resource",
    "modify_database",
    "revoke_credentials",
})

MUTATING_ACTIONS = DAO_MUTATING_ACTIONS | LEGACY_MUTATING_ACTIONS


def is_constitution_bound_execution_action(action_id: object) -> bool:
    """Return True when an action must pass the DAO multisig boundary."""
    action = str(action_id or "").strip().lower()
    return action.startswith("execute_casper_") or action in DAO_MUTATING_ACTIONS


def contains_constitution_bound_execution(envelopes: list[dict]) -> bool:
    """Detect actions that the DAO Constitution cannot auto-authorize."""
    return any(is_constitution_bound_execution_action(envelope.get("action_id")) for envelope in envelopes)


def constitution_bound_execution_reason(
    envelopes: list[dict],
    *,
    requires_multisig_for_execution: bool = True,
) -> str | None:
    """Fail-closed reason for PolicyAuthorization and similar auto paths."""
    if requires_multisig_for_execution and contains_constitution_bound_execution(envelopes):
        return "Casper execution receipts require multisig approval under the DAO Constitution."
    return None


def generate_nonce(length: int = 6) -> str:
    """Generate a short challenge nonce for demo readability.

    Uses URL-safe characters, uppercase for visual clarity.

    COUPLING: The Casper Execution Agent preprocessor regex hardcodes {6} to match this
    default length. If you change the default, update the regex in
    agents/operator/__init__.py too.
    """
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I/O/0/1 confusion
    return "".join(secrets.choice(alphabet) for _ in range(length))


def compute_plan_hash(plan: dict) -> str:
    """SHA-256 hash of a ResponsePlan for approval binding."""
    canonical = json.dumps(plan, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def normalize_plan_for_hash(plan_data: dict) -> dict:
    """Reset seal-added fields before hashing.

    seal_card() adds card_hash, previous_card_hash, sequence_number to cards.
    Protocol Strategy Agent computes plan_hash BEFORE sealing, so all Gateway routes that
    hash stored (sealed) cards must reset these fields to match.

    This helper centralizes the normalization so adding a new seal field
    in the future only requires updating one place.
    """
    normalized = {**plan_data}
    normalized["card_hash"] = None
    normalized["previous_card_hash"] = None
    normalized["sequence_number"] = None
    return normalized


def compute_action_hash(envelopes: list[dict]) -> str:
    """SHA-256 hash over canonical ExecutionEnvelopes.

    The human approves the exact typed actions, not a description of them.
    """
    canonical = json.dumps(envelopes, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def requires_human_approval(
    risk_level: str,
    envelopes: list[dict],
    *,
    requires_multisig_for_execution: bool = True,
) -> bool:
    """Deterministic override — code decides, not the LLM.

    LLM's requires_human_approval is advisory input, not authoritative.
    """
    if constitution_bound_execution_reason(
        envelopes,
        requires_multisig_for_execution=requires_multisig_for_execution,
    ):
        return True
    if str(risk_level or "").strip().lower() in ("high", "critical"):
        return True
    for envelope in envelopes:
        if str(envelope.get("action_id") or "").strip().lower() in MUTATING_ACTIONS:
            return True
    return False


# ---------------------------------------------------------------------------
# Nonce Management (Gateway-side)
# ---------------------------------------------------------------------------

def create_nonce(
    proposal_id: str,
    plan_hash: str,
    action_hash: str,
    plan_revision: int,
    expiry: datetime,
    db: sqlite3.Connection,
) -> str:
    """Create a nonce for human approval challenge.

    Atomically invalidates any previous nonce for this proposal
    (plan revision = new nonce).

    Args:
        proposal_id: The proposal being approved.
        plan_hash: SHA-256 of the ResponsePlan.
        action_hash: SHA-256 of the ExecutionEnvelopes — binds approval
                     to the exact actions the human reviewed.
        plan_revision: Monotonic revision counter.
        expiry: When this nonce expires.
        db: SQLite connection.
    """
    nonce = generate_nonce()

    db.execute("BEGIN IMMEDIATE")
    try:
        # Invalidate previous nonces for this proposal
        db.execute(
            "UPDATE nonces SET invalidated=1 WHERE proposal_id=? AND consumed=0",
            (proposal_id,),
        )
        # Insert new nonce
        db.execute(
            "INSERT INTO nonces "
            "(proposal_id, nonce, plan_hash, action_hash, plan_revision, expiry, consumed, invalidated) "
            "VALUES (?, ?, ?, ?, ?, ?, 0, 0)",
            (proposal_id, nonce, plan_hash, action_hash, plan_revision, expiry.isoformat()),
        )
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise

    return nonce


def validate_and_consume_nonce(
    proposal_id: str,
    nonce: str,
    plan_hash: str,
    action_hash: str,
    consumed_by: str,
    db: sqlite3.Connection,
) -> tuple[bool, str]:
    """Atomically validate and consume a nonce. Prevents replay.

    This is the REAL authorization boundary. The preprocessor regex is
    just triage — this function is what decides whether execution happens.

    Validates (all in one BEGIN IMMEDIATE transaction):
        1. Nonce exists for this proposal
        2. Nonce not invalidated (by plan revision)
        3. Nonce not already consumed (replay attempt)
        4. Plan hash matches (approved plan = current plan)
        5. Action hash matches (approved actions = current envelopes)
        6. Nonce not expired

    Invalid requests do NOT consume. Only all-pass flips consumed=1.

    Returns:
        (success, reason) — True if valid and consumed, error message if not.
    """
    now = datetime.now(timezone.utc)
    db.execute("BEGIN IMMEDIATE")
    try:
        row = db.execute(
            "SELECT nonce, plan_hash, action_hash, expiry, consumed, invalidated "
            "FROM nonces WHERE proposal_id=? AND nonce=?",
            (proposal_id, nonce),
        ).fetchone()

        if not row:
            db.execute("ROLLBACK")
            return False, "Unknown nonce"

        if row["invalidated"]:
            db.execute("ROLLBACK")
            return False, "Nonce invalidated by plan revision"

        if row["consumed"]:
            db.execute("ROLLBACK")
            return False, "Nonce already consumed (replay attempt)"

        if row["plan_hash"] != plan_hash:
            db.execute("ROLLBACK")
            return False, "Plan hash mismatch — approved plan differs from current"

        if row["action_hash"] != action_hash:
            db.execute("ROLLBACK")
            return False, "Action hash mismatch — envelopes may have been tampered"

        expiry = datetime.fromisoformat(row["expiry"])
        if now > expiry:
            db.execute("ROLLBACK")
            return False, "Nonce expired"

        # All checks passed — consume atomically
        db.execute(
            "UPDATE nonces SET consumed=1, consumed_by=?, consumed_at=? "
            "WHERE proposal_id=? AND nonce=?",
            (consumed_by, now.isoformat(), proposal_id, nonce),
        )
        db.execute("COMMIT")
        return True, "Nonce valid and consumed"

    except Exception:
        db.execute("ROLLBACK")
        raise


def validate_nonce_only(
    proposal_id: str,
    nonce: str,
    plan_hash: str,
    action_hash: str,
    db: sqlite3.Connection,
    *,
    require_challenge_visibility: bool = False,
) -> tuple[bool, str, dict | None]:
    """Validate a nonce WITHOUT consuming it and WITHOUT managing transactions.

    The caller MUST be inside a BEGIN IMMEDIATE transaction.
    Returns (success, reason, nonce_row_dict) where nonce_row_dict
    contains expiry, plan_revision, etc. on success.
    """
    now = datetime.now(timezone.utc)

    row = db.execute(
        "SELECT nonce, plan_hash, action_hash, expiry, consumed, "
        "invalidated, plan_revision, challenge_message_id "
        "FROM nonces WHERE proposal_id=? AND nonce=?",
        (proposal_id, nonce),
    ).fetchone()

    if not row:
        return False, "Unknown nonce", None

    if row["invalidated"]:
        return False, "Nonce invalidated by plan revision", None

    if row["consumed"]:
        return False, "Nonce already consumed (replay attempt)", None

    if require_challenge_visibility and not (
        row["challenge_message_id"] or ""
    ).strip():
        return False, "Approval challenge is not yet visible in Council Chamber", None

    if row["plan_hash"] != plan_hash:
        return False, "Plan hash mismatch — approved plan differs from current", None

    if row["action_hash"] != action_hash:
        return False, "Action hash mismatch — envelopes may have been tampered", None

    expiry = datetime.fromisoformat(row["expiry"])
    if now > expiry:
        return False, "Nonce expired", None

    return True, "Nonce valid", dict(row)


def consume_nonce_only(
    proposal_id: str,
    nonce: str,
    consumed_by: str,
    db: sqlite3.Connection,
) -> None:
    """Mark a nonce as consumed. Caller MUST be inside a BEGIN IMMEDIATE transaction."""
    now = datetime.now(timezone.utc)
    db.execute(
        "UPDATE nonces SET consumed=1, consumed_by=?, consumed_at=? "
        "WHERE proposal_id=? AND nonce=?",
        (consumed_by, now.isoformat(), proposal_id, nonce),
    )


# ---------------------------------------------------------------------------
# PolicyAuthorization Management (Gateway-side)
# ---------------------------------------------------------------------------

def create_authorization(
    authorization_id: str,
    proposal_id: str,
    plan_hash: str,
    action_hash: str,
    policy_rule: str,
    expiry: datetime,
    db: sqlite3.Connection,
) -> None:
    """Store a new PolicyAuthorization for consumption tracking.

    The sealed card is the tamper-evident issuance record.
    This table tracks consumption lifecycle.
    """
    db.execute(
        "INSERT INTO authorizations "
        "(authorization_id, proposal_id, plan_hash, action_hash, "
        "policy_rule, expiry, consumed_at, status) "
        "VALUES (?, ?, ?, ?, ?, ?, NULL, 'PENDING')",
        (authorization_id, proposal_id, plan_hash, action_hash,
         policy_rule, expiry.isoformat()),
    )
    db.connection.commit() if hasattr(db, 'connection') else db.commit()


def validate_and_consume_authorization(
    authorization_id: str,
    proposal_id: str,
    plan_hash: str,
    action_hash: str,
    db: sqlite3.Connection,
) -> tuple[bool, str]:
    """Atomically validate ALL bindings and consume authorization.

    Validates: existence, proposal_id, plan_hash, action_hash,
    not expired, not consumed. Invalid request does not consume.
    """
    db.execute("BEGIN IMMEDIATE")
    try:
        row = db.execute(
            "SELECT authorization_id, proposal_id, plan_hash, action_hash, "
            "policy_rule, expiry, consumed_at "
            "FROM authorizations WHERE authorization_id=?",
            (authorization_id,),
        ).fetchone()

        if not row:
            db.execute("ROLLBACK")
            return False, "Unknown authorization_id"

        if row["consumed_at"] is not None:
            db.execute("ROLLBACK")
            return False, "Authorization already consumed"

        expiry = datetime.fromisoformat(row["expiry"])
        if datetime.now(timezone.utc) > expiry:
            db.execute("ROLLBACK")
            return False, "Authorization expired"

        if row["proposal_id"] != proposal_id:
            db.execute("ROLLBACK")
            return False, f"Proposal mismatch — auth for {row['proposal_id']}, not {proposal_id}"

        if row["plan_hash"] != plan_hash:
            db.execute("ROLLBACK")
            return False, "Plan hash mismatch — plan may have been revised"

        if row["action_hash"] != action_hash:
            db.execute("ROLLBACK")
            return False, "Action hash mismatch — envelopes may have been tampered"

        # Consume atomically — sync status + legacy fields
        now_str = datetime.now(timezone.utc).isoformat()
        db.execute(
            "UPDATE authorizations SET consumed_at=?, consumed=1, "
            "status='CONSUMED' WHERE authorization_id=?",
            (now_str, authorization_id),
        )
        db.execute("COMMIT")
        return True, "Authorization valid and consumed"

    except Exception:
        db.execute("ROLLBACK")
        raise


def advance_authorization_lifecycle(
    db: sqlite3.Connection,
    proposal_id: str,
    card_hash: str,
    authorization_id: str,
    room_message_id: str,
    target_proposal_state: str,
) -> bool:
    """Two-mode state transition for proposal-room publication success.
    
    Reads under BEGIN IMMEDIATE.
    Mode 1 (source): unpublished/PENDING/PLANNED -> updates exactly 1 row each -> commits.
    Mode 2 (target): published/PUBLISHED/target_state -> rolls back -> returns True (idempotent success).
    Mixed state -> rolls back -> raises 409 inconsistent_lifecycle.
    """
    from fastapi import HTTPException
    
    now = datetime.now(timezone.utc).isoformat()
    db.execute("BEGIN IMMEDIATE")
    try:
        # Read current state
        card = db.execute("SELECT published_at FROM cards WHERE card_hash=? AND proposal_id=?", (card_hash, proposal_id)).fetchone()
        auth = db.execute("SELECT status FROM authorizations WHERE authorization_id=?", (authorization_id,)).fetchone()
        inc = db.execute("SELECT state FROM proposals WHERE proposal_id=?", (proposal_id,)).fetchone()

        if not card or not auth or not inc:
            db.execute("ROLLBACK")
            raise HTTPException(status_code=500, detail="Missing records for state transition.")

        is_source = (card["published_at"] is None and auth["status"] == "PENDING" and inc["state"] == "PLANNED")
        is_target = (card["published_at"] is not None and auth["status"] == "PUBLISHED" and inc["state"] == target_proposal_state)

        if is_source:
            # Execute 3 conditional updates, require rowcount=1 for each
            c1 = db.execute(
                "UPDATE cards SET published_at=?, room_message_id=? WHERE card_hash=? AND proposal_id=? AND published_at IS NULL",
                (now, room_message_id, card_hash, proposal_id)
            )
            c2 = db.execute(
                "UPDATE proposals SET state=?, updated_at=? WHERE proposal_id=? AND state='PLANNED'",
                (target_proposal_state, now, proposal_id)
            )
            c3 = db.execute(
                "UPDATE authorizations SET status='PUBLISHED', room_message_id=? WHERE authorization_id=? AND status='PENDING'",
                (room_message_id, authorization_id)
            )

            if c1.rowcount != 1 or c2.rowcount != 1 or c3.rowcount != 1:
                db.execute("ROLLBACK")
                raise HTTPException(status_code=500, detail="Concurrent modification during state advance.")
            db.execute("COMMIT")
            return True

        elif is_target:
            db.execute("ROLLBACK")
            return True
        else:
            db.execute("ROLLBACK")
            raise HTTPException(status_code=409, detail="inconsistent_lifecycle")

    except Exception as e:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise e
