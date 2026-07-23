"""Gateway startup migrations required by the finals security boundaries."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from gateway.database import init_db


def _columns(db: sqlite3.Connection, table: str) -> set[str]:
    return {
        str(row[1])
        for row in db.execute(f"PRAGMA table_info({table})").fetchall()
    }


def test_init_db_creates_complete_demo_capability_schema(tmp_path: Path) -> None:
    db = init_db(tmp_path / "gateway.db")
    try:
        assert _columns(db, "demo_capabilities") == {
            "capability_id",
            "scenario_id",
            "client_binding_hash",
            "nonce_hash",
            "issued_at",
            "expires_at",
            "state",
            "demo_run_id",
            "consumed_at",
            "response_status",
            "response_json",
        }
        assert _columns(db, "demo_runs") == {
            "demo_run_id",
            "proposal_id",
            "scenario_id",
            "is_demo",
            "created_at",
        }
        assert _columns(db, "demo_capability_issue_counters") == {
            "scope",
            "client_key",
            "window_start",
            "count",
        }
    finally:
        db.close()


def test_init_db_migrates_pre_state_demo_capabilities_table(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "legacy-gateway.db"
    legacy = sqlite3.connect(database_path)
    legacy.execute(
        """
        CREATE TABLE demo_capabilities (
            capability_id TEXT PRIMARY KEY,
            scenario_id TEXT NOT NULL,
            client_binding_hash TEXT NOT NULL,
            nonce_hash TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            demo_run_id TEXT,
            consumed_at INTEGER,
            response_status INTEGER,
            response_json TEXT
        )
        """
    )
    legacy.execute(
        """
        INSERT INTO demo_capabilities (
            capability_id, scenario_id, client_binding_hash, nonce_hash,
            issued_at, expires_at, consumed_at, response_status, response_json
        ) VALUES ('ok', 'treasury-cap', 'client', 'nonce', 1, 2, 2, 200, '{}')
        """
    )
    legacy.execute(
        """
        INSERT INTO demo_capabilities (
            capability_id, scenario_id, client_binding_hash, nonce_hash,
            issued_at, expires_at, consumed_at, response_status, response_json
        ) VALUES ('failed', 'treasury-cap', 'client', 'nonce-2', 1, 2, 2, 503, '{}')
        """
    )
    legacy.commit()
    legacy.close()

    db = init_db(database_path)
    try:
        assert "state" in _columns(db, "demo_capabilities")
        rows = dict(
            db.execute(
                "SELECT capability_id, state FROM demo_capabilities"
            ).fetchall()
        )
        assert rows == {"ok": "SUCCEEDED", "failed": "FAILED"}
    finally:
        db.close()
