"""CONCORDIA Integrity Chain — Seal-Before-Send.

Cards are sealed by the Gateway before posting to Council Chambers.
The card in Council Chamber already contains its hash — verifiable by any observer.

Flow:
    Agent → typed tool → SubmissionClient → POST /prepare/{card_type}
    → Gateway validates, enriches, seals → returns sealed card + destination
    → SubmissionClient publishes to Council Chamber → POST /confirm with room_message_id
    → state advances.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone

from .models import CardBase, parse_card


class IdempotencyConflict(Exception):
    """Raised when an idempotency key is reused with a different payload or card type."""
    pass


# Chain fields assigned by seal_card — excluded from payload fingerprinting.
_CHAIN_FIELDS = {"card_hash", "sequence_number", "previous_card_hash"}


def request_fingerprint(card_data: dict) -> str:
    """Compute a stable fingerprint of caller-provided card fields.

    Excludes chain fields (card_hash, sequence_number, previous_card_hash)
    which are assigned by seal_card, not the caller. Used by both
    seal_card's internal idempotency check and the route pre-check.
    """
    stripped = {k: v for k, v in card_data.items() if k not in _CHAIN_FIELDS}
    return hashlib.sha256(
        json.dumps(stripped, sort_keys=True, default=str).encode()
    ).hexdigest()


def seal_card(
    card: CardBase,
    proposal_id: str,
    db: sqlite3.Connection,
    idempotency_key: str | None = None,
    prepared_by_role: str | None = None,
    request_fp: str | None = None,
) -> CardBase:
    """Gateway atomically assigns sequence_number, previous_hash, card_hash.

    Uses isolation_level=None for explicit transaction control.
    UNIQUE(proposal_id, sequence_number) and UNIQUE(proposal_id, idempotency_key)
    prevent races and enable safe retries.

    prepared_by_role is written atomically with the card — no crash window.
    request_fp is the pre-enrichment fingerprint — computed by the route
    BEFORE _apply_risk_floor modifies the card. If not supplied, falls
    back to fingerprinting the (post-enrichment) card.

    Raises IdempotencyConflict if the same key is reused with a different
    payload or card type.
    """
    # Use pre-enrichment fingerprint if provided, else compute from card.
    payload_fingerprint = request_fp or request_fingerprint(card.model_dump())

    card_type_str = card.model_dump().get("card_type", "unknown")

    db.execute("BEGIN IMMEDIATE")
    try:
        # Idempotency: return existing sealed card on retry.
        # Binds (proposal_id, idempotency_key, card_type).
        if idempotency_key:
            existing = db.execute(
                "SELECT card_json, card_hash, request_fp FROM cards "
                "WHERE proposal_id=? AND idempotency_key=? AND card_type=?",
                (proposal_id, idempotency_key, card_type_str),
            ).fetchone()
            if existing:
                db.execute("ROLLBACK")
                # Compare against stored pre-enrichment fingerprint.
                # Falls back to card_json fingerprint if request_fp wasn't stored.
                stored_fp = existing["request_fp"]
                if not stored_fp:
                    stored = json.loads(existing["card_json"])
                    stored_fp = request_fingerprint(stored)
                if stored_fp != payload_fingerprint:
                    raise IdempotencyConflict(
                        f"Idempotency key {idempotency_key!r} already used "
                        f"with a different payload for {card_type_str}"
                    )
                sealed = parse_card(existing["card_json"])
                sealed.card_hash = existing["card_hash"]
                return sealed

        # Get previous card in chain
        prev = db.execute(
            "SELECT sequence_number, card_hash FROM cards "
            "WHERE proposal_id=? ORDER BY sequence_number DESC LIMIT 1",
            (proposal_id,),
        ).fetchone()

        card.sequence_number = (prev["sequence_number"] + 1) if prev else 1
        card.previous_card_hash = prev["card_hash"] if prev else None

        # Compute hash over canonical JSON (excluding the hash field itself)
        canonical = json.dumps(
            card.model_dump(exclude={"card_hash"}),
            sort_keys=True,
            default=str,
        )
        card.card_hash = hashlib.sha256(canonical.encode()).hexdigest()

        # Insert into chain — includes prepared_by_role atomically
        db.execute(
            "INSERT INTO cards (proposal_id, sequence_number, card_type, "
            "card_hash, card_json, idempotency_key, prepared_by_role, request_fp, "
            "created_at, published_at, room_message_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
            (
                proposal_id,
                card.sequence_number,
                card_type_str,
                card.card_hash,
                canonical,
                idempotency_key,
                prepared_by_role,
                payload_fingerprint,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        db.execute("COMMIT")
    except IdempotencyConflict:
        # Already rolled back above. Re-raise with its own message.
        raise
    except sqlite3.IntegrityError:
        # Cross-type key collision (UNIQUE constraint).
        try:
            db.execute("ROLLBACK")
        except Exception:
            pass
        raise IdempotencyConflict(
            f"Idempotency key {idempotency_key!r} already used for a "
            f"different card type on proposal {proposal_id!r}"
        )
    except Exception:
        db.execute("ROLLBACK")
        raise

    return card


def seal_card_in_transaction(
    card: CardBase,
    proposal_id: str,
    db: sqlite3.Connection,
    idempotency_key: str | None = None,
    prepared_by_role: str | None = None,
    request_fp: str | None = None,
) -> CardBase:
    """Same as seal_card(), but does NOT manage its own transaction.

    The caller MUST wrap this call in their own BEGIN IMMEDIATE / COMMIT
    block and handle ROLLBACK on failure. This function will raise on
    errors without issuing any transaction-control statements.

    Raises IdempotencyConflict if the same key is reused with a different
    payload or card type.
    """
    # Use pre-enrichment fingerprint if provided, else compute from card.
    payload_fingerprint = request_fp or request_fingerprint(card.model_dump())

    card_type_str = card.model_dump().get("card_type", "unknown")

    # Idempotency: return existing sealed card on retry.
    if idempotency_key:
        existing = db.execute(
            "SELECT card_json, card_hash, request_fp FROM cards "
            "WHERE proposal_id=? AND idempotency_key=? AND card_type=?",
            (proposal_id, idempotency_key, card_type_str),
        ).fetchone()
        if existing:
            # Compare against stored pre-enrichment fingerprint.
            # Falls back to card_json fingerprint if request_fp wasn't stored.
            stored_fp = existing["request_fp"]
            if not stored_fp:
                stored = json.loads(existing["card_json"])
                stored_fp = request_fingerprint(stored)
            if stored_fp != payload_fingerprint:
                raise IdempotencyConflict(
                    f"Idempotency key {idempotency_key!r} already used "
                    f"with a different payload for {card_type_str}"
                )
            sealed = parse_card(existing["card_json"])
            sealed.card_hash = existing["card_hash"]
            return sealed

    # Get previous card in chain
    prev = db.execute(
        "SELECT sequence_number, card_hash FROM cards "
        "WHERE proposal_id=? ORDER BY sequence_number DESC LIMIT 1",
        (proposal_id,),
    ).fetchone()

    card.sequence_number = (prev["sequence_number"] + 1) if prev else 1
    card.previous_card_hash = prev["card_hash"] if prev else None

    # Compute hash over canonical JSON (excluding the hash field itself)
    canonical = json.dumps(
        card.model_dump(exclude={"card_hash"}),
        sort_keys=True,
        default=str,
    )
    card.card_hash = hashlib.sha256(canonical.encode()).hexdigest()

    # Insert into chain — includes prepared_by_role atomically
    try:
        db.execute(
            "INSERT INTO cards (proposal_id, sequence_number, card_type, "
            "card_hash, card_json, idempotency_key, prepared_by_role, request_fp, "
            "created_at, published_at, room_message_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
            (
                proposal_id,
                card.sequence_number,
                card_type_str,
                card.card_hash,
                canonical,
                idempotency_key,
                prepared_by_role,
                payload_fingerprint,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
    except sqlite3.IntegrityError:
        raise IdempotencyConflict(
            f"Idempotency key {idempotency_key!r} already used for a "
            f"different card type on proposal {proposal_id!r}"
        )

    return card


def verify_chain(proposal_id: str, db: sqlite3.Connection) -> tuple[bool, list[str]]:
    """Verify the integrity of an proposal's card chain.

    Returns:
        (is_valid, errors) — True if chain is intact, list of error messages if not.
    """
    errors: list[str] = []

    rows = db.execute(
        "SELECT sequence_number, card_hash, card_json FROM cards "
        "WHERE proposal_id=? ORDER BY sequence_number ASC",
        (proposal_id,),
    ).fetchall()

    if not rows:
        return True, []  # Empty chain is trivially valid

    prev_hash: str | None = None
    for i, row in enumerate(rows):
        seq = row["sequence_number"]
        stored_hash = row["card_hash"]

        # Parse and recompute hash
        card = parse_card(row["card_json"])

        # Check sequence continuity
        expected_seq = i + 1
        if seq != expected_seq:
            errors.append(f"Sequence gap: expected {expected_seq}, got {seq}")

        # Check previous_card_hash linkage
        if card.previous_card_hash != prev_hash:
            errors.append(
                f"Card {seq}: previous_card_hash mismatch. "
                f"Expected {prev_hash}, got {card.previous_card_hash}"
            )

        # Recompute hash and verify
        recomputed = card.compute_hash()
        if recomputed != stored_hash:
            errors.append(
                f"Card {seq}: hash mismatch. "
                f"Stored {stored_hash[:16]}..., recomputed {recomputed[:16]}..."
            )

        prev_hash = stored_hash

    return len(errors) == 0, errors


def get_chain_root_hash(proposal_id: str, db: sqlite3.Connection) -> str | None:
    """Get the hash of the final card in the chain (for AuditSeal)."""
    row = db.execute(
        "SELECT card_hash FROM cards "
        "WHERE proposal_id=? ORDER BY sequence_number DESC LIMIT 1",
        (proposal_id,),
    ).fetchone()
    return row["card_hash"] if row else None


def get_chain_length(proposal_id: str, db: sqlite3.Connection) -> int:
    """Get total number of cards in the chain."""
    row = db.execute(
        "SELECT COUNT(*) as cnt FROM cards WHERE proposal_id=?",
        (proposal_id,),
    ).fetchone()
    return row["cnt"] if row else 0
