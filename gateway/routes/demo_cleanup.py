"""Ownership-scoped cleanup for controlled CONCORDIA demo runs.

Demo capability v1 (G1 freeze, §12):
    - Cleanup accepts ONE exact ``demo_run_id`` and deletes only records
      recorded as belonging to that run (``demo_runs`` provenance rows with
      ``is_demo=1``).
    - Prefix/LIKE-pattern deletion is forbidden and has been removed.
    - Every canonical/historical proposal ID is permanently excluded even
      if provenance rows are corrupt: the denylist below is consulted for
      every candidate row before any deletion.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Sequence

# Read-only import of the canonical/supplemental proposal identities
# (shared/proof_runtime.py is Codex-owned; importing the constants is allowed,
# editing the file is not).
from shared.proof_runtime import (
    CANONICAL_PROPOSAL_ID,
    SUPPLEMENTAL_DYNAMIC_PROPOSAL_ID,
    SUPPLEMENTAL_RWA_PROPOSAL_ID,
)

# Strict demo namespace. Only proposal IDs with this prefix are ever eligible
# for deletion by cleanup; every other id (canonical, historical, arbitrary or
# corrupt provenance) fails closed.
_DEMO_PROPOSAL_PREFIX = "DAO-DEMO-"

# Permanent hardcoded denylist covering the COMPLETE frozen canonical/historical
# proposal set (addendum item 6 — not only DAO-PROP-6CB25C). The literals are
# deliberately duplicated (belt and suspenders): even if the imported constants
# were ever re-pointed, these finals proposals can never be deleted by cleanup.
_PROTECTED_PROPOSAL_IDS: frozenset[str] = frozenset(
    {
        "DAO-PROP-6CB25C",
        "DAO-PROP-DYN-002",
        "DAO-PROP-RWA-001",
        str(CANONICAL_PROPOSAL_ID),
        str(SUPPLEMENTAL_DYNAMIC_PROPOSAL_ID),
        str(SUPPLEMENTAL_RWA_PROPOSAL_ID),
    }
)

# Lazily-created demo provenance/capability tables. gateway/database.py is
# Codex-owned; folding this DDL into init_db() is recorded as a WP3 manifest
# need. The statements are idempotent (CREATE TABLE IF NOT EXISTS) and use the
# same SQLite connection the routes already share.
_DEMO_TABLES_DDL = """
CREATE TABLE IF NOT EXISTS demo_capabilities (
    capability_id TEXT PRIMARY KEY,
    scenario_id TEXT NOT NULL,
    client_binding_hash TEXT NOT NULL,
    nonce_hash TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'ISSUED',
    demo_run_id TEXT,
    consumed_at INTEGER,
    response_status INTEGER,
    response_json TEXT
);

CREATE TABLE IF NOT EXISTS demo_runs (
    demo_run_id TEXT NOT NULL,
    proposal_id TEXT NOT NULL,
    scenario_id TEXT NOT NULL,
    is_demo INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    PRIMARY KEY (demo_run_id, proposal_id)
);

-- Durable fixed-window counters for capability ISSUANCE admission (WP3-6).
-- Atomic admission across independent connections is provided by the shared
-- SQLite write lock (BEGIN IMMEDIATE) in gateway.routes.demo.
CREATE TABLE IF NOT EXISTS demo_capability_issue_counters (
    scope TEXT NOT NULL,
    client_key TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (scope, client_key, window_start)
);
"""


def ensure_demo_tables(db: sqlite3.Connection) -> None:
    """Idempotently create/upgrade the durable demo ledger tables.

    Lazy migration: gateway/database.py is Codex-owned, so the durable capability
    lifecycle ``state`` column is added here if an older table predates it.
    """
    db.executescript(_DEMO_TABLES_DDL)
    columns = {
        row[1]
        for row in db.execute("PRAGMA table_info(demo_capabilities)").fetchall()
    }
    if "state" not in columns:
        db.execute(
            "ALTER TABLE demo_capabilities ADD COLUMN state TEXT NOT NULL "
            "DEFAULT 'ISSUED'"
        )
        # Best-effort backfill: any pre-migration consumed rows are terminal.
        db.execute(
            "UPDATE demo_capabilities SET state='SUCCEEDED' "
            "WHERE consumed_at IS NOT NULL AND response_status=200"
        )
        db.execute(
            "UPDATE demo_capabilities SET state='FAILED' "
            "WHERE consumed_at IS NOT NULL AND (response_status IS NULL OR response_status<>200)"
        )


def is_protected_proposal_id(proposal_id: str) -> bool:
    """True when a proposal ID may never be deleted by demo cleanup."""
    return proposal_id in _PROTECTED_PROPOSAL_IDS


def is_strict_demo_proposal_id(proposal_id: str) -> bool:
    """True only for a strict ``DAO-DEMO-<suffix>`` id with a non-empty suffix.

    Case-sensitive on purpose: the canonical namespace is ``DAO-PROP-*`` and any
    lowercase / prefix-only / arbitrary id is not a demo id and is never
    deletable.
    """
    if not isinstance(proposal_id, str):
        return False
    if not proposal_id.startswith(_DEMO_PROPOSAL_PREFIX):
        return False
    return len(proposal_id) > len(_DEMO_PROPOSAL_PREFIX)


def _run_proposal_ids(db: sqlite3.Connection, demo_run_id: str) -> list[str]:
    """Deletion candidates for one exact demo run.

    Three independent guards, every one applied to every candidate row so that
    corrupt provenance always fails closed:

    - **One-run ownership**: a proposal id claimed by ANY other ``demo_run_id``
      is ambiguous and excluded (protects the other run).
    - **Strict prefix**: only strict ``DAO-DEMO-*`` ids are eligible; any
      canonical/arbitrary id claimed by the run is excluded.
    - **Denylist**: the complete frozen canonical/historical set is excluded
      even if it somehow also matched the prefix.
    """
    rows = db.execute(
        "SELECT proposal_id FROM demo_runs "
        "WHERE demo_run_id=? AND is_demo=1 "
        "AND proposal_id NOT IN ("
        "    SELECT proposal_id FROM demo_runs WHERE demo_run_id<>?"
        ")",
        (demo_run_id, demo_run_id),
    ).fetchall()
    proposal_ids: list[str] = []
    for row in rows:
        proposal_id = str(row[0])
        if is_protected_proposal_id(proposal_id):
            continue  # corrupt provenance — never delete canonical/historical
        if not is_strict_demo_proposal_id(proposal_id):
            continue  # strict demo prefix only — everything else fails closed
        proposal_ids.append(proposal_id)
    return proposal_ids


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


def remove_demo_proposals(
    db: sqlite3.Connection,
    demo_run_id: str,
) -> dict[str, object]:
    """Delete exactly one demo run's local records.

    Selection is ownership-scoped: only proposals recorded in ``demo_runs``
    for this exact ``demo_run_id`` (with ``is_demo=1``) are candidates, and
    the permanent canonical/historical denylist excludes protected IDs even
    when provenance rows are corrupt. Council Chambers are preserved as audit
    evidence (detached, not deleted). Atomic under BEGIN IMMEDIATE.
    """
    if not isinstance(demo_run_id, str) or not demo_run_id.strip():
        raise ValueError("cleanup requires one exact demo_run_id")
    demo_run_id = demo_run_id.strip()

    ensure_demo_tables(db)

    deleted: dict[str, int] = {}
    try:
        db.execute("BEGIN IMMEDIATE")
        # Selection AND deletion occur inside the SAME BEGIN IMMEDIATE so no
        # concurrent writer can add/re-own a candidate row between the two.
        proposal_ids = _run_proposal_ids(db, demo_run_id)
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
        # The run's own provenance + capability ledger rows belong to the run.
        cursor = db.execute(
            "DELETE FROM demo_runs WHERE demo_run_id=?",
            (demo_run_id,),
        )
        deleted["demo_runs"] = max(cursor.rowcount, 0)
        cursor = db.execute(
            "DELETE FROM demo_capabilities WHERE demo_run_id=?",
            (demo_run_id,),
        )
        deleted["demo_capabilities"] = max(cursor.rowcount, 0)
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise

    return {
        "demo_run_id": demo_run_id,
        "cleaned_proposals": len(proposal_ids),
        "deleted_records": deleted,
        "rooms_preserved": len(proposal_ids),
    }
