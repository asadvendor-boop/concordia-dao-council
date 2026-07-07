"""Atomic cleanup helpers for controlled CONCORDIA demo sessions."""
from __future__ import annotations

import sqlite3
from collections.abc import Sequence

# Current full-pipeline triggers use DAO-PROP-* to identify synthetic demo rows.
_DEMO_PREFIXES: tuple[str, ...] = ("DAO-PROP-%",)


def _demo_proposal_ids(db: sqlite3.Connection) -> list[str]:
    clauses = " OR ".join("proposal_id LIKE ?" for _ in _DEMO_PREFIXES)
    rows = db.execute(
        f"SELECT proposal_id FROM proposals WHERE {clauses}",
        _DEMO_PREFIXES,
    ).fetchall()
    return [str(row[0]) for row in rows]


def _delete_for_proposals(
    db: sqlite3.Connection,
    table: str,
    column: str,
    proposal_ids: Sequence[str],
) -> int:
    if not proposal_ids:
        return 0
    placeholders = ",".join("?" for _ in proposal_ids)
    cursor = db.execute(
        f"DELETE FROM {table} WHERE {column} IN ({placeholders})",
        tuple(proposal_ids),
    )
    return max(cursor.rowcount, 0)


def _detach_for_proposals(
    db: sqlite3.Connection,
    table: str,
    column: str,
    proposal_ids: Sequence[str],
) -> int:
    if not proposal_ids:
        return 0
    placeholders = ",".join("?" for _ in proposal_ids)
    cursor = db.execute(
        f"UPDATE {table} SET {column}=NULL WHERE {column} IN ({placeholders})",
        tuple(proposal_ids),
    )
    return max(cursor.rowcount, 0)


def remove_demo_proposals(db: sqlite3.Connection) -> dict[str, object]:
    """Delete only synthetic demo proposals and their local dependent records.

    Council Chambers are deliberately preserved as audit evidence.  The
    operation changes no schema, does not touch real proposals, and is atomic
    under BEGIN IMMEDIATE.
    """
    proposal_ids = _demo_proposal_ids(db)
    if not proposal_ids:
        return {
            "cleaned_proposals": 0,
            "deleted_records": {},
            "rooms_preserved": 0,
        }

    deleted: dict[str, int] = {}
    try:
        db.execute("BEGIN IMMEDIATE")
        deleted["suppression_rules"] = _delete_for_proposals(
            db, "suppression_rules", "source_proposal_id", proposal_ids
        )
        deleted["authorizations"] = _delete_for_proposals(
            db, "authorizations", "proposal_id", proposal_ids
        )
        deleted["nonces"] = _delete_for_proposals(
            db, "nonces", "proposal_id", proposal_ids
        )
        deleted["proposal_room_messages_detached"] = _detach_for_proposals(
            db, "proposal_room_messages", "proposal_id", proposal_ids
        )
        deleted["proposal_rooms_detached"] = _detach_for_proposals(
            db, "proposal_rooms", "proposal_id", proposal_ids
        )
        deleted["cards"] = _delete_for_proposals(
            db, "cards", "proposal_id", proposal_ids
        )
        deleted["signals"] = _delete_for_proposals(
            db, "signals", "proposal_id", proposal_ids
        )
        deleted["signals"] += _delete_for_proposals(
            db, "signals", "signal_id", proposal_ids
        )
        deleted["proposals"] = _delete_for_proposals(
            db, "proposals", "proposal_id", proposal_ids
        )
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise

    return {
        "cleaned_proposals": len(proposal_ids),
        "deleted_records": deleted,
        "rooms_preserved": len(proposal_ids),
    }
