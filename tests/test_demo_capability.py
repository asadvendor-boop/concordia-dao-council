"""Demo capability v1 tests (DM) — signed opaque capability round-trip,
tamper/expiry/scenario/binding rejection, one-use idempotent activation,
internal-endpoint authentication, ownership-scoped cleanup, and removal of
the public reset route.

Spec: handoff/G1_INTERFACE_SPEC.md §12 "Demo capability v1".
"""
from __future__ import annotations

import base64
import json
import secrets as pysecrets
import uuid

import pytest
from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.database import init_db
from gateway.routes import demo
from gateway.routes.demo_cleanup import (
    ensure_demo_tables,
    remove_demo_proposals,
)

OPERATOR_TOKEN = "operator-token-for-demo-tests-0123456789"
DASHBOARD_TOKEN = "dashboard-demo-gateway-token-0123456789"
HMAC_SECRET = "demo-capability-hmac-secret-0123456789abcdef0123"

TOKEN_HEADER = "X-Concordia-Dashboard-Token"
NONCE_HEADER = "X-Concordia-Demo-Client"


def _wire_nonce(raw: bytes | None = None) -> str:
    raw = raw if raw is not None else pysecrets.token_bytes(32)
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _headers(nonce_wire: str, token: str = DASHBOARD_TOKEN) -> dict[str, str]:
    return {TOKEN_HEADER: token, NONCE_HEADER: nonce_wire}


@pytest.fixture()
def demo_env(monkeypatch, tmp_path):
    monkeypatch.delenv("DEMO_CAPABILITY_HMAC_SECRET", raising=False)
    monkeypatch.delenv("DASHBOARD_DEMO_GATEWAY_TOKEN", raising=False)

    secret_file = tmp_path / "demo_capability_hmac_secret"
    secret_file.write_text(HMAC_SECRET, encoding="utf-8")
    monkeypatch.setenv("DEMO_CAPABILITY_HMAC_SECRET_FILE", str(secret_file))

    token_file = tmp_path / "dashboard_demo_gateway_token"
    token_file.write_text(DASHBOARD_TOKEN, encoding="utf-8")
    monkeypatch.setenv("DASHBOARD_DEMO_GATEWAY_TOKEN_FILE", str(token_file))

    monkeypatch.setenv("CONCORDIA_OPERATOR_TOKEN", OPERATOR_TOKEN)
    yield tmp_path


@pytest.fixture()
def app_db_path(demo_env):
    return str(demo_env / "demo-capability.db")


@pytest.fixture()
def client(app_db_path):
    with TestClient(create_app(db_path=app_db_path)) as test_client:
        yield test_client


@pytest.fixture()
def app_db(app_db_path, client):
    """Test-thread connection to the app's file-backed DB (the app's own
    connection lives in the TestClient portal thread)."""
    connection = init_db(app_db_path)
    yield connection
    connection.close()


@pytest.fixture()
def stub_executor(monkeypatch):
    """Replace the pipeline executor — capability tests target capability
    semantics, never a real simulator/agent pipeline (hard safety rule)."""
    calls: list[dict] = []

    async def _stub(db, scenario_type, *, demo_run_id, enforce_cooldown):
        calls.append(
            {
                "scenario_type": scenario_type,
                "demo_run_id": demo_run_id,
                "enforce_cooldown": enforce_cooldown,
            }
        )
        return 200, {
            "success": True,
            "scenario_type": scenario_type,
            "proposal_id": "DAO-DEMO-STUB01",
            "demo_run_id": demo_run_id,
            "is_demo": True,
        }

    monkeypatch.setattr(demo, "_execute_demo_trigger", _stub)
    return calls


def _issue(client, scenario_id="treasury", nonce_wire=None, token=DASHBOARD_TOKEN):
    nonce_wire = nonce_wire or _wire_nonce()
    response = client.post(
        "/internal/demo/capability",
        json={"scenario_id": scenario_id},
        headers=_headers(nonce_wire, token),
    )
    return response, nonce_wire


def _activate(client, capability, scenario_id, nonce_wire, token=DASHBOARD_TOKEN):
    return client.post(
        "/internal/demo/activate",
        json={"capability": capability, "scenario_id": scenario_id},
        headers=_headers(nonce_wire, token),
    )


# ---------------------------------------------------------------------------
# Issue endpoint
# ---------------------------------------------------------------------------

def test_dm_issue_response_shape_is_exact(client):
    response, _ = _issue(client)
    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {"schema_version", "capability", "scenario_id", "expires_at"}
    assert body["schema_version"] == "demo-capability-v1"
    assert body["scenario_id"] == "treasury"
    assert isinstance(body["expires_at"], int)
    assert body["capability"].count(".") == 1


def test_dm_issue_requires_dashboard_token(client):
    nonce_wire = _wire_nonce()
    response = client.post(
        "/internal/demo/capability",
        json={"scenario_id": "treasury"},
        headers={NONCE_HEADER: nonce_wire},
    )
    assert response.status_code == 403

    response, _ = _issue(client, token="wrong-token")
    assert response.status_code == 403

    # The operator token is NOT the dashboard token.
    response, _ = _issue(client, token=OPERATOR_TOKEN)
    assert response.status_code == 403


def test_dm_issue_rejects_unknown_scenario_and_unknown_fields(client):
    response, _ = _issue(client, scenario_id="not-a-scenario")
    assert response.status_code == 400

    nonce_wire = _wire_nonce()
    response = client.post(
        "/internal/demo/capability",
        json={"scenario_id": "treasury", "reset": True},
        headers=_headers(nonce_wire),
    )
    assert response.status_code == 422  # unknown fields rejected


def test_dm_issue_requires_valid_client_nonce(client):
    response = client.post(
        "/internal/demo/capability",
        json={"scenario_id": "treasury"},
        headers={TOKEN_HEADER: DASHBOARD_TOKEN},
    )
    assert response.status_code == 400

    short = base64.urlsafe_b64encode(b"short").decode().rstrip("=")
    response = client.post(
        "/internal/demo/capability",
        json={"scenario_id": "treasury"},
        headers=_headers(short),
    )
    assert response.status_code == 400


def test_dm_secret_too_short_fails_closed(client, monkeypatch, tmp_path):
    weak_file = tmp_path / "weak_secret"
    weak_file.write_text("short-secret", encoding="utf-8")
    monkeypatch.setenv("DEMO_CAPABILITY_HMAC_SECRET_FILE", str(weak_file))
    response, _ = _issue(client)
    assert response.status_code == 503


def test_dm_secret_reuse_of_operator_token_fails_closed(client, monkeypatch, tmp_path):
    """The dedicated HMAC secret may not reuse the operator token."""
    monkeypatch.setenv("CONCORDIA_OPERATOR_TOKEN", HMAC_SECRET)
    response, _ = _issue(client)
    assert response.status_code == 503


# ---------------------------------------------------------------------------
# Activation — round-trip, tamper, expiry, scoping, binding, one-use
# ---------------------------------------------------------------------------

def test_dm_activation_roundtrip_started(client, stub_executor):
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]

    activated = _activate(client, capability, "treasury", nonce_wire)
    assert activated.status_code == 200
    body = activated.json()
    assert body["schema_version"] == "demo-run-v1"
    assert body["status"] == "started"
    assert body["scenario_id"] == "treasury"
    assert body["is_demo"] is True
    assert body["created_proposal_ids"] == ["DAO-DEMO-STUB01"]
    assert body["demo_run_id"].startswith("demo-run-")
    assert len(stub_executor) == 1
    assert stub_executor[0]["scenario_type"] == "treasury"
    assert stub_executor[0]["enforce_cooldown"] is False


def test_dm_tampered_capability_rejected(client, stub_executor):
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]
    payload_part, tag_part = capability.split(".")

    # Flip payload bytes, flip tag bytes, and structural garbage.
    flipped_payload = ("A" if payload_part[0] != "A" else "B") + payload_part[1:]
    flipped_tag = tag_part[:-1] + ("A" if tag_part[-1] != "A" else "B")
    for tampered in (
        f"{flipped_payload}.{tag_part}",
        f"{payload_part}.{flipped_tag}",
        payload_part,
        "not-a-token",
        "",
    ):
        activated = _activate(client, tampered, "treasury", nonce_wire)
        assert activated.status_code in (401, 422), tampered  # 422: empty body field
        if activated.status_code == 401:
            assert activated.json()["error_code"] == "invalid_capability"
    assert stub_executor == []


def test_dm01_expired_capability_rejected(client, stub_executor, monkeypatch):
    monkeypatch.setattr(demo, "_CAPABILITY_LIFETIME_SECONDS", -10)
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]

    activated = _activate(client, capability, "treasury", nonce_wire)
    assert activated.status_code == 403
    assert activated.json()["error_code"] == "capability_expired"
    assert stub_executor == []


def test_dm03_wrong_scenario_rejected(client, stub_executor):
    response, nonce_wire = _issue(client, scenario_id="treasury")
    capability = response.json()["capability"]

    activated = _activate(client, capability, "oracle", nonce_wire)
    assert activated.status_code == 403
    assert activated.json()["error_code"] == "scenario_mismatch"
    assert stub_executor == []


def test_dm_client_binding_mismatch_rejected(client, stub_executor):
    response, _ = _issue(client)
    capability = response.json()["capability"]

    other_client = _wire_nonce()
    activated = _activate(client, capability, "treasury", other_client)
    assert activated.status_code == 403
    assert activated.json()["error_code"] == "client_binding_mismatch"
    assert stub_executor == []


def test_dm02_dm09_one_use_idempotent_replay(client, stub_executor):
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]

    first = _activate(client, capability, "treasury", nonce_wire)
    assert first.status_code == 200
    assert first.json()["status"] == "started"

    replay = _activate(client, capability, "treasury", nonce_wire)
    assert replay.status_code == 200
    body = replay.json()
    assert body["status"] == "idempotent_replay"
    assert body["demo_run_id"] == first.json()["demo_run_id"]
    assert body["created_proposal_ids"] == first.json()["created_proposal_ids"]
    # The pipeline ran exactly once.
    assert len(stub_executor) == 1


def test_dm10_degraded_pipeline_is_honest_and_replayed(client, monkeypatch):
    async def _failing(db, scenario_type, *, demo_run_id, enforce_cooldown):
        return 502, {"success": False, "error": "Demo trigger failed — check server logs"}

    monkeypatch.setattr(demo, "_execute_demo_trigger", _failing)
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]

    activated = _activate(client, capability, "treasury", nonce_wire)
    assert activated.status_code == 502
    assert activated.json()["success"] is False

    # Capability was consumed; the stored honest failure is replayed.
    replay = _activate(client, capability, "treasury", nonce_wire)
    assert replay.status_code == 502
    assert replay.json()["success"] is False


def test_dm_activate_requires_dashboard_token(client, stub_executor):
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]

    activated = _activate(client, capability, "treasury", nonce_wire, token="wrong")
    assert activated.status_code == 403
    assert stub_executor == []


def test_dm04_per_client_activation_throttle(client, app_db, stub_executor):
    nonce_wire = _wire_nonce()
    for _ in range(3):
        response, _ = _issue(client, nonce_wire=nonce_wire)
        capability = response.json()["capability"]
        activated = _activate(client, capability, "treasury", nonce_wire)
        assert activated.status_code == 200

    response, _ = _issue(client, nonce_wire=nonce_wire)
    capability = response.json()["capability"]
    throttled = _activate(client, capability, "treasury", nonce_wire)
    assert throttled.status_code == 429
    assert throttled.json()["error_code"] == "throttled"
    assert len(stub_executor) == 3

    # Throttled BEFORE consumption — the capability row stays unconsumed.
    unconsumed = app_db.execute(
        "SELECT COUNT(*) FROM demo_capabilities WHERE consumed_at IS NULL"
    ).fetchone()[0]
    assert unconsumed == 1


def test_dm06_operator_token_never_in_capability_responses(client, stub_executor):
    response, nonce_wire = _issue(client)
    assert OPERATOR_TOKEN not in response.text
    capability = response.json()["capability"]
    activated = _activate(client, capability, "treasury", nonce_wire)
    assert OPERATOR_TOKEN not in activated.text
    assert HMAC_SECRET not in response.text
    assert HMAC_SECRET not in activated.text


# ---------------------------------------------------------------------------
# DM-05 — the public reset route does not exist
# ---------------------------------------------------------------------------

def test_dm05_public_reset_route_removed(client):
    response = client.post(
        "/demo/reset", headers={"X-Operator-Token": OPERATOR_TOKEN}
    )
    assert response.status_code in (404, 405)
    response = client.post("/demo/reset")
    assert response.status_code in (404, 405)


def test_dm_legacy_trigger_remains_operator_gated(client):
    response = client.post("/demo/trigger", json={"scenario_type": "treasury"})
    assert response.status_code == 401
    response = client.post(
        "/demo/trigger",
        json={"scenario_type": "treasury"},
        headers={"X-Operator-Token": "wrong-token"},
    )
    assert response.status_code == 401
    # The dashboard token is NOT an operator token.
    response = client.post(
        "/demo/trigger",
        json={"scenario_type": "treasury"},
        headers={"X-Operator-Token": DASHBOARD_TOKEN},
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# DM-07 / DM-08 — ownership-scoped cleanup + canonical denylist
# ---------------------------------------------------------------------------

def _seed_proposal(db, proposal_id: str) -> None:
    db.execute(
        "INSERT INTO proposals (proposal_id, state, created_at, updated_at) "
        "VALUES (?, 'CHALLENGED', '2026-06-29T00:00:00Z', '2026-06-29T00:00:00Z')",
        (proposal_id,),
    )
    db.execute(
        "INSERT INTO cards (proposal_id, sequence_number, card_type, card_hash, "
        "card_json, created_at) VALUES (?, 1, 'ProposalCard', ?, '{}', "
        "'2026-06-29T00:00:00Z')",
        (proposal_id, f"hash-{proposal_id}"),
    )


def _seed_run(db, demo_run_id: str, proposal_id: str) -> None:
    ensure_demo_tables(db)
    db.execute(
        "INSERT OR IGNORE INTO demo_runs "
        "(demo_run_id, proposal_id, scenario_id, is_demo, created_at) "
        "VALUES (?, ?, 'treasury', 1, '2026-06-29T00:00:00Z')",
        (demo_run_id, proposal_id),
    )


def test_dm07_cleanup_deletes_exactly_one_run(tmp_path):
    db = init_db(tmp_path / "cleanup.db")
    _seed_proposal(db, "DAO-DEMO-RUNA01")
    _seed_proposal(db, "DAO-DEMO-RUNB01")
    _seed_run(db, "demo-run-a", "DAO-DEMO-RUNA01")
    _seed_run(db, "demo-run-b", "DAO-DEMO-RUNB01")

    result = remove_demo_proposals(db, "demo-run-a")
    assert result["cleaned_proposals"] == 1

    remaining = {
        row[0] for row in db.execute("SELECT proposal_id FROM proposals").fetchall()
    }
    assert remaining == {"DAO-DEMO-RUNB01"}
    # Run B's provenance is untouched.
    assert (
        db.execute(
            "SELECT COUNT(*) FROM demo_runs WHERE demo_run_id='demo-run-b'"
        ).fetchone()[0]
        == 1
    )


def test_dm08_canonical_and_historical_survive_even_with_corrupt_provenance(tmp_path):
    db = init_db(tmp_path / "cleanup-canonical.db")
    _seed_proposal(db, "DAO-PROP-6CB25C")   # canonical finals proposal
    _seed_proposal(db, "DAO-PROP-HIST01")   # historical DAO-PROP-* row
    _seed_proposal(db, "DAO-DEMO-RUNA01")
    _seed_run(db, "demo-run-a", "DAO-DEMO-RUNA01")
    # CORRUPT provenance: claims the canonical proposal belongs to the run.
    _seed_run(db, "demo-run-a", "DAO-PROP-6CB25C")

    result = remove_demo_proposals(db, "demo-run-a")
    assert result["cleaned_proposals"] == 1  # only the true demo row

    remaining = {
        row[0] for row in db.execute("SELECT proposal_id FROM proposals").fetchall()
    }
    assert "DAO-PROP-6CB25C" in remaining
    assert "DAO-PROP-HIST01" in remaining
    assert "DAO-DEMO-RUNA01" not in remaining
    # Canonical evidence chain untouched.
    assert (
        db.execute(
            "SELECT COUNT(*) FROM cards WHERE proposal_id='DAO-PROP-6CB25C'"
        ).fetchone()[0]
        == 1
    )


def test_dm_cleanup_no_prefix_deletion_and_requires_run_id(tmp_path):
    db = init_db(tmp_path / "cleanup-prefix.db")
    # A stray DAO-PROP-* proposal with NO provenance row: the removed LIKE
    # pattern would have deleted it; ownership-scoped cleanup must not.
    _seed_proposal(db, "DAO-PROP-STRAY1")
    _seed_run(db, "demo-run-x", "DAO-DEMO-XYZ001")

    result = remove_demo_proposals(db, "demo-run-x")
    assert result["cleaned_proposals"] == 1
    assert (
        db.execute(
            "SELECT COUNT(*) FROM proposals WHERE proposal_id='DAO-PROP-STRAY1'"
        ).fetchone()[0]
        == 1
    )

    with pytest.raises(ValueError):
        remove_demo_proposals(db, "")
    with pytest.raises(TypeError):
        remove_demo_proposals(db)  # exact demo_run_id is mandatory


# ===========================================================================
# WP3 corrective coverage (Codex NO-GO fixes). Every test below maps to a
# named WP3 blocker / addendum acceptance item.
# ===========================================================================

def _capability_row(db, capability_id):
    ensure_demo_tables(db)
    return db.execute(
        "SELECT * FROM demo_capabilities WHERE capability_id=?", (capability_id,)
    ).fetchone()


def _capability_id_of(token: str) -> str:
    """Decode the capability_id from a minted token (test-only)."""
    from gateway.routes.demo import _capability_secret, _parse_capability

    secret, err = _capability_secret()
    assert secret is not None, err
    parsed = _parse_capability(token, secret)
    assert parsed is not None
    return parsed["capability_id"]


# ---------------------------------------------------------------------------
# WP3-1 / addendum 1-2 — durable capability lifecycle ISSUED→RUNNING→terminal
# ---------------------------------------------------------------------------

def test_dm_wp3_1_lifecycle_states_persisted(client, app_db, stub_executor):
    """Issue -> row is ISSUED. Activate -> terminal SUCCEEDED with stored body."""
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]
    capability_id = _capability_id_of(capability)

    issued = _capability_row(app_db, capability_id)
    assert issued["state"] == "ISSUED"
    assert issued["consumed_at"] is None

    activated = _activate(client, capability, "treasury", nonce_wire)
    assert activated.status_code == 200

    terminal = _capability_row(app_db, capability_id)
    assert terminal["state"] == "SUCCEEDED"
    assert terminal["consumed_at"] is not None
    assert terminal["demo_run_id"] is not None
    assert int(terminal["response_status"]) == 200
    assert json.loads(terminal["response_json"])["schema_version"] == "demo-run-v1"


def test_dm_wp3_1_running_retry_returns_202_same_run_identity(client, app_db, stub_executor):
    """A concurrent retry WHILE RUNNING returns explicit 202 (never empty 200)
    and echoes the SAME run identity; the pipeline is NOT re-run."""
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]
    capability_id = _capability_id_of(capability)

    # Simulate an in-flight claim (RUNNING, no stored response yet, fresh lease).
    import time as _time

    running_run_id = "demo-run-inflight-abc"
    app_db.execute(
        "UPDATE demo_capabilities SET state='RUNNING', consumed_at=?, "
        "demo_run_id=?, response_status=NULL, response_json=NULL "
        "WHERE capability_id=?",
        (int(_time.time()), running_run_id, capability_id),
    )

    retry = _activate(client, capability, "treasury", nonce_wire)
    assert retry.status_code == 202
    body = retry.json()
    assert body != {}  # never an empty 200/202
    assert body["status"] == "running"
    assert body["demo_run_id"] == running_run_id
    # The executor must NOT run again for an in-flight retry.
    assert stub_executor == []


def test_dm_wp3_1_no_empty_200_on_running(client, app_db, stub_executor):
    """Explicit guard for the exact NO-GO defect: a RUNNING retry may never be
    an empty body with HTTP 200."""
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]
    capability_id = _capability_id_of(capability)

    import time as _time

    app_db.execute(
        "UPDATE demo_capabilities SET state='RUNNING', consumed_at=?, "
        "demo_run_id='demo-run-x', response_status=NULL, response_json=NULL "
        "WHERE capability_id=?",
        (int(_time.time()), capability_id),
    )
    retry = _activate(client, capability, "treasury", nonce_wire)
    assert not (retry.status_code == 200 and retry.json() == {})
    assert retry.status_code == 202


def test_dm_wp3_1_crash_recovery_stale_running_fails_closed_without_rerun(
    client, app_db, stub_executor
):
    """A RUNNING row whose lease is stale (crashed mid-run) recovers to a
    terminal FAILED WITHOUT re-running mutations."""
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]
    capability_id = _capability_id_of(capability)

    stale = int(__import__("time").time()) - (demo._RUNNING_LEASE_SECONDS + 60)
    app_db.execute(
        "UPDATE demo_capabilities SET state='RUNNING', consumed_at=?, "
        "demo_run_id='demo-run-crashed', response_status=NULL, response_json=NULL "
        "WHERE capability_id=?",
        (stale, capability_id),
    )

    recovered = _activate(client, capability, "treasury", nonce_wire)
    assert recovered.status_code in (500, 503)
    assert recovered.json() != {}
    # No pipeline re-run on crash recovery.
    assert stub_executor == []

    row = _capability_row(app_db, capability_id)
    assert row["state"] == "FAILED"
    assert row["response_status"] is not None

    # A subsequent terminal retry returns the exact stored terminal response.
    again = _activate(client, capability, "treasury", nonce_wire)
    assert again.status_code == recovered.status_code
    assert stub_executor == []


def test_dm_wp3_1_terminal_retry_returns_exact_stored_status(client, monkeypatch):
    """A terminal FAILED retry returns the EXACT stored status/body (honest
    degraded state is replayed verbatim, not fabricated success)."""
    async def _failing(db, scenario_type, *, demo_run_id, enforce_cooldown):
        return 502, {"success": False, "error": "Demo trigger failed — check server logs"}

    monkeypatch.setattr(demo, "_execute_demo_trigger", _failing)
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]

    first = _activate(client, capability, "treasury", nonce_wire)
    assert first.status_code == 502
    replay = _activate(client, capability, "treasury", nonce_wire)
    assert replay.status_code == 502
    assert replay.json()["success"] is False


# ---------------------------------------------------------------------------
# WP3-6 / addendum 6 — durable capability ISSUANCE limits + caps + GC
# ---------------------------------------------------------------------------

def test_dm_wp3_6_issue_per_client_limit(client, app_db, monkeypatch):
    # Freeze the clock so every issue lands in one fixed rate window (no
    # 600s-boundary flake across the required stable runs).
    monkeypatch.setattr(demo.time, "time", lambda: 1_900_000_000.0)
    monkeypatch.setattr(demo, "_PER_CLIENT_ISSUE_LIMIT", 2)
    nonce_wire = _wire_nonce()
    for _ in range(2):
        resp, _ = _issue(client, nonce_wire=nonce_wire)
        assert resp.status_code == 200
    resp, _ = _issue(client, nonce_wire=nonce_wire)
    assert resp.status_code == 429
    assert resp.json()["error_code"] == "issue_rate_limited"

    # A DIFFERENT client is unaffected (per-client window is independent).
    other, _ = _issue(client, nonce_wire=_wire_nonce())
    assert other.status_code == 200


def test_dm_wp3_6_issue_global_limit(client, monkeypatch):
    monkeypatch.setattr(demo.time, "time", lambda: 1_900_000_000.0)
    monkeypatch.setattr(demo, "_GLOBAL_ISSUE_LIMIT", 2)
    monkeypatch.setattr(demo, "_PER_CLIENT_ISSUE_LIMIT", 100)
    for _ in range(2):
        resp, _ = _issue(client, nonce_wire=_wire_nonce())
        assert resp.status_code == 200
    resp, _ = _issue(client, nonce_wire=_wire_nonce())
    assert resp.status_code == 429
    assert resp.json()["error_code"] == "issue_rate_limited"


def test_dm_wp3_6_issue_outstanding_cap(client, monkeypatch):
    monkeypatch.setattr(demo, "_MAX_OUTSTANDING_CAPABILITIES", 1)
    resp, _ = _issue(client, nonce_wire=_wire_nonce())
    assert resp.status_code == 200
    resp, _ = _issue(client, nonce_wire=_wire_nonce())
    assert resp.status_code == 503
    assert resp.json()["error_code"] == "issue_capacity_exhausted"


def test_dm_wp3_6_issue_retained_cap(client, monkeypatch):
    monkeypatch.setattr(demo, "_MAX_RETAINED_CAPABILITIES", 1)
    resp, _ = _issue(client, nonce_wire=_wire_nonce())
    assert resp.status_code == 200
    resp, _ = _issue(client, nonce_wire=_wire_nonce())
    assert resp.status_code == 503
    assert resp.json()["error_code"] == "issue_capacity_exhausted"


def test_dm_wp3_6_issue_bounded_expired_cleanup(client, app_db, monkeypatch):
    """Bounded GC removes expired UNCONSUMED capability rows on issuance;
    consumed/terminal rows are never garbage-collected."""
    ensure_demo_tables(app_db)
    now = int(__import__("time").time())
    # An expired unconsumed capability (GC candidate).
    app_db.execute(
        "INSERT INTO demo_capabilities (capability_id, scenario_id, "
        "client_binding_hash, nonce_hash, issued_at, expires_at, state) "
        "VALUES ('expired-unconsumed', 'treasury', 'h', 'n', ?, ?, 'ISSUED')",
        (now - 10_000, now - 5_000),
    )
    # An expired but CONSUMED/terminal capability (must be preserved).
    app_db.execute(
        "INSERT INTO demo_capabilities (capability_id, scenario_id, "
        "client_binding_hash, nonce_hash, issued_at, expires_at, state, "
        "consumed_at, response_status, response_json) "
        "VALUES ('expired-consumed', 'treasury', 'h', 'n', ?, ?, 'SUCCEEDED', ?, 200, '{}')",
        (now - 10_000, now - 5_000, now - 6_000),
    )

    resp, _ = _issue(client, nonce_wire=_wire_nonce())
    assert resp.status_code == 200

    remaining = {
        r[0]
        for r in app_db.execute(
            "SELECT capability_id FROM demo_capabilities"
        ).fetchall()
    }
    assert "expired-unconsumed" not in remaining  # GC'd
    assert "expired-consumed" in remaining  # preserved


def test_dm_wp3_6_issue_limit_durable_across_connections(client, app_db_path, monkeypatch):
    """Issuance counters are a durable SQLite fixed window: a fresh,
    independent DB connection observes the same charged counters."""
    monkeypatch.setattr(demo.time, "time", lambda: 1_900_000_000.0)
    monkeypatch.setattr(demo, "_PER_CLIENT_ISSUE_LIMIT", 2)
    nonce_wire = _wire_nonce()
    for _ in range(2):
        resp, _ = _issue(client, nonce_wire=nonce_wire)
        assert resp.status_code == 200

    # Independent connection sees the durable counter rows.
    probe = init_db(app_db_path)
    try:
        total = probe.execute(
            "SELECT COALESCE(SUM(count), 0) FROM demo_capability_issue_counters "
            "WHERE scope='client'"
        ).fetchone()[0]
        assert int(total) >= 2
    finally:
        probe.close()

    resp, _ = _issue(client, nonce_wire=nonce_wire)
    assert resp.status_code == 429


# ---------------------------------------------------------------------------
# WP3-2 / WP3-3 — pipeline stub harness (preallocated id + provenance)
# ---------------------------------------------------------------------------

_ISO = "2026-07-01T00:00:00Z"


class _AsyncCloser:
    async def aclose(self):
        return None


def _install_pipeline_stubs(
    monkeypatch,
    db,
    *,
    simulator_returns_id=None,
    fail_at=None,
):
    """Install controllable stubs for the demo pipeline collaborators.

    ``simulator_returns_id`` overrides the proposal_id the simulator echoes
    back (default: echo the requested/preallocated id). ``fail_at`` injects a
    RuntimeError right after a named durable stage:
    ``after_prepare`` / ``after_room`` / ``after_message`` / ``after_confirm``.
    """
    calls: list[str] = []

    async def _stub_simulator(endpoint, requested_proposal_id):
        calls.append("simulator")
        pid = simulator_returns_id if simulator_returns_id is not None else requested_proposal_id
        return {
            "proposal_id": pid,
            "signal": {
                "source": "governance_feed",
                "title": "stubbed proposal",
                "preliminary_severity": "medium",
                "security_relevant": True,
                "raw_payload": {"dao_target": "treasury"},
            },
        }

    monkeypatch.setattr(demo, "_run_simulator_scenario", _stub_simulator)
    monkeypatch.setattr(
        demo, "llm_readiness_status", lambda: {"required": False, "ready": True}
    )

    class _Prepared:
        def __init__(self, proposal_id):
            self.submission_id = "sub-1"
            self.proposal_id = proposal_id
            self.card_hash = f"hash-{proposal_id}"
            self.sequence_number = 1
            self.agent_role = "recorder"
            self.room_id = None
            self.sealed_card = {
                "proposal_id": proposal_id,
                "card_type": "ProposalCard",
                "sequence_number": 1,
                "card_hash": f"hash-{proposal_id}",
            }

    class _Confirmed:
        new_state = "CHALLENGED"

    class _StubSubmission:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def prepare(self, card, *, idempotency_key=None):
            calls.append("prepare")
            pid = card.signal_id
            db.execute(
                "INSERT OR IGNORE INTO proposals (proposal_id, state, created_at, updated_at) "
                "VALUES (?, 'PLANNED', ?, ?)",
                (pid, _ISO, _ISO),
            )
            db.execute(
                "INSERT INTO cards (proposal_id, sequence_number, card_type, card_hash, "
                "card_json, created_at) VALUES (?, 1, 'ProposalCard', ?, '{}', ?)",
                (pid, f"hash-{pid}", _ISO),
            )
            if fail_at == "after_prepare":
                raise RuntimeError("boom after prepare")
            return _Prepared(pid)

        async def confirm(self, *, submission_id, proposal_id, card_hash,
                          message_id=None, room_id=None):
            calls.append("confirm")
            if fail_at == "after_confirm":
                raise RuntimeError("boom after confirm")
            return _Confirmed()

    monkeypatch.setattr("shared.submission_client.SubmissionClient", _StubSubmission)

    class _StubRecorder:
        def __init__(self):
            self.client = _AsyncCloser()
            self._proposal_id = None

        async def create_room(self, title, proposal_id=None):
            calls.append("create_room")
            self._proposal_id = proposal_id
            room_id = f"room-{proposal_id}"
            db.execute(
                "INSERT OR IGNORE INTO proposal_rooms (room_id, proposal_id, title, "
                "created_by, created_at, updated_at) VALUES (?, ?, ?, 'recorder', ?, ?)",
                (room_id, proposal_id, title, _ISO, _ISO),
            )
            return room_id

        async def add_participant(self, room_id, agent_id):
            calls.append("add_participant")
            if fail_at == "after_room":
                raise RuntimeError("boom after room")

        async def post_message(self, room_id, content, mentions=None):
            calls.append("post_message")
            message_id = f"msg-{room_id}"
            db.execute(
                "INSERT INTO proposal_room_messages (message_id, room_id, proposal_id, "
                "sender_id, sender_role, sender_type, content, mentions_json, "
                "message_type, metadata_json, created_at, inserted_at) "
                "VALUES (?, ?, ?, 'recorder', 'recorder', 'Agent', ?, '[]', 'message', '{}', ?, ?)",
                (message_id, room_id, self._proposal_id, content, _ISO, _ISO),
            )
            if fail_at == "after_message":
                raise RuntimeError("boom after message")
            return message_id

    monkeypatch.setattr("agents.recorder.Recorder", _StubRecorder)
    return calls


async def test_dm_wp3_2_simulator_id_mismatch_fails_before_prepare(monkeypatch, tmp_path):
    """A simulator/preparer proposal_id that is NOT the preallocated DAO-DEMO-*
    id fails BEFORE the first proposal mutation (prepare never runs)."""
    db = init_db(tmp_path / "wp3-2-mismatch.db")
    try:
        calls = _install_pipeline_stubs(
            monkeypatch, db, simulator_returns_id="DAO-DEMO-DIFFERENT"
        )
        status, payload = await demo._execute_demo_trigger(
            db, "treasury", demo_run_id="demo-run-mismatch", enforce_cooldown=False
        )
        assert status == 502
        assert "prepare" not in calls  # failed before first proposal mutation
        # Provenance was reserved before any mutation -> discoverable + cleanable.
        row = db.execute(
            "SELECT COUNT(*) FROM demo_runs WHERE demo_run_id='demo-run-mismatch'"
        ).fetchone()[0]
        assert row == 1
        remove_demo_proposals(db, "demo-run-mismatch")
        assert (
            db.execute(
                "SELECT COUNT(*) FROM demo_runs WHERE demo_run_id='demo-run-mismatch'"
            ).fetchone()[0]
            == 0
        )
    finally:
        db.close()


async def test_dm_wp3_2_canonical_id_from_simulator_rejected(monkeypatch, tmp_path):
    """A canonical/historical id returned by the simulator fails before mutation."""
    db = init_db(tmp_path / "wp3-2-canonical.db")
    try:
        calls = _install_pipeline_stubs(
            monkeypatch, db, simulator_returns_id="DAO-PROP-6CB25C"
        )
        status, _ = await demo._execute_demo_trigger(
            db, "treasury", demo_run_id="demo-run-canon", enforce_cooldown=False
        )
        assert status == 502
        assert "prepare" not in calls
        # The canonical proposal is never touched.
        assert (
            db.execute(
                "SELECT COUNT(*) FROM proposals WHERE proposal_id='DAO-PROP-6CB25C'"
            ).fetchone()[0]
            == 0
        )
    finally:
        db.close()


@pytest.mark.parametrize("fail_at", ["after_prepare", "after_room", "after_message", "after_confirm"])
async def test_dm_wp3_3_partial_failure_stays_discoverable_and_cleanable(
    monkeypatch, tmp_path, fail_at
):
    """Provenance is reserved before the first mutation and kept on every
    partial failure; the partial run stays discoverable and exactly cleanable."""
    db = init_db(tmp_path / f"wp3-3-{fail_at}.db")
    try:
        _install_pipeline_stubs(monkeypatch, db, fail_at=fail_at)
        run_id = f"demo-run-{fail_at}"
        status, _ = await demo._execute_demo_trigger(
            db, "treasury", demo_run_id=run_id, enforce_cooldown=False
        )
        assert status == 502

        # Discoverable: exactly one provenance row for this run.
        prov = db.execute(
            "SELECT proposal_id FROM demo_runs WHERE demo_run_id=? AND is_demo=1",
            (run_id,),
        ).fetchall()
        assert len(prov) == 1
        demo_pid = prov[0][0]
        assert demo_pid.startswith("DAO-DEMO-")

        # The proposal really was created (prepare mutated the ledger).
        assert (
            db.execute(
                "SELECT COUNT(*) FROM proposals WHERE proposal_id=?", (demo_pid,)
            ).fetchone()[0]
            == 1
        )

        # Exactly cleanable: cleanup removes the run's proposal + provenance.
        result = remove_demo_proposals(db, run_id)
        assert result["cleaned_proposals"] == 1
        assert (
            db.execute(
                "SELECT COUNT(*) FROM proposals WHERE proposal_id=?", (demo_pid,)
            ).fetchone()[0]
            == 0
        )
        assert (
            db.execute(
                "SELECT COUNT(*) FROM demo_runs WHERE demo_run_id=?", (run_id,)
            ).fetchone()[0]
            == 0
        )
    finally:
        db.close()


def test_dm_wp3_2_pure_id_guards():
    """Unit guards for the preallocated-id contract."""
    from gateway.routes.demo_cleanup import is_strict_demo_proposal_id
    from gateway.routes.demo import _assert_demo_proposal_id

    assert is_strict_demo_proposal_id("DAO-DEMO-ABC123") is True
    assert is_strict_demo_proposal_id("DAO-PROP-6CB25C") is False
    assert is_strict_demo_proposal_id("DAO-DEMO-") is False
    assert is_strict_demo_proposal_id("dao-demo-x") is False
    assert is_strict_demo_proposal_id("") is False

    # Equal + strict passes.
    _assert_demo_proposal_id("DAO-DEMO-ABC123", "DAO-DEMO-ABC123")
    # Mismatch fails.
    with pytest.raises(ValueError):
        _assert_demo_proposal_id("DAO-DEMO-ABC123", "DAO-DEMO-XYZ999")
    # Canonical fails even if "equal".
    with pytest.raises(ValueError):
        _assert_demo_proposal_id("DAO-PROP-6CB25C", "DAO-PROP-6CB25C")


# ---------------------------------------------------------------------------
# WP3-4 / addendum 5-6 — cleanup strict prefix, one-run ownership, full
# canonical protection, atomic transaction
# ---------------------------------------------------------------------------

def test_dm_wp3_4_cleanup_strict_prefix_only(tmp_path):
    """A provenance row that claims a NON-DAO-DEMO id (not in the denylist) is
    never deleted — strict prefix, corrupt provenance fails closed."""
    db = init_db(tmp_path / "wp3-4-prefix.db")
    _seed_proposal(db, "not-a-demo-id-999")
    _seed_proposal(db, "DAO-DEMO-REAL01")
    _seed_run(db, "demo-run-a", "not-a-demo-id-999")  # corrupt claim
    _seed_run(db, "demo-run-a", "DAO-DEMO-REAL01")

    result = remove_demo_proposals(db, "demo-run-a")
    assert result["cleaned_proposals"] == 1  # only the strict demo id
    remaining = {r[0] for r in db.execute("SELECT proposal_id FROM proposals").fetchall()}
    assert "not-a-demo-id-999" in remaining
    assert "DAO-DEMO-REAL01" not in remaining


def test_dm_wp3_4_cleanup_one_run_ownership(tmp_path):
    """A proposal owned by more than one run is ambiguous and is NEVER deleted
    (protects the other run)."""
    db = init_db(tmp_path / "wp3-4-ownership.db")
    _seed_proposal(db, "DAO-DEMO-SHARED1")
    _seed_proposal(db, "DAO-DEMO-SOLOA01")
    _seed_run(db, "demo-run-a", "DAO-DEMO-SHARED1")
    _seed_run(db, "demo-run-b", "DAO-DEMO-SHARED1")  # cross-run claim
    _seed_run(db, "demo-run-a", "DAO-DEMO-SOLOA01")

    result = remove_demo_proposals(db, "demo-run-a")
    assert result["cleaned_proposals"] == 1  # only the solely-owned id
    remaining = {r[0] for r in db.execute("SELECT proposal_id FROM proposals").fetchall()}
    assert "DAO-DEMO-SHARED1" in remaining  # ambiguous ownership preserved
    assert "DAO-DEMO-SOLOA01" not in remaining


def test_dm_wp3_6_full_canonical_set_protected(tmp_path):
    """The COMPLETE frozen canonical/historical proposal set is protected, not
    only DAO-PROP-6CB25C."""
    from gateway.routes.demo_cleanup import is_protected_proposal_id

    for pid in ("DAO-PROP-6CB25C", "DAO-PROP-DYN-002", "DAO-PROP-RWA-001"):
        assert is_protected_proposal_id(pid) is True

    db = init_db(tmp_path / "wp3-6-canonical.db")
    for pid in ("DAO-PROP-6CB25C", "DAO-PROP-DYN-002", "DAO-PROP-RWA-001"):
        _seed_proposal(db, pid)
        _seed_run(db, "demo-run-a", pid)  # corrupt provenance
    _seed_proposal(db, "DAO-DEMO-REAL02")
    _seed_run(db, "demo-run-a", "DAO-DEMO-REAL02")

    result = remove_demo_proposals(db, "demo-run-a")
    assert result["cleaned_proposals"] == 1
    remaining = {r[0] for r in db.execute("SELECT proposal_id FROM proposals").fetchall()}
    for pid in ("DAO-PROP-6CB25C", "DAO-PROP-DYN-002", "DAO-PROP-RWA-001"):
        assert pid in remaining
    assert "DAO-DEMO-REAL02" not in remaining


# ---------------------------------------------------------------------------
# Reviewer fail-closed corrections (Codex review of 73279a1, items 1-4)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "corrupt_json",
    ["{not json", "[1, 2, 3]", "null", '"started"', "", None],
)
def test_dm_rev1_corrupt_response_json_replays_as_503_integrity(
    client, app_db, stub_executor, corrupt_json
):
    """A terminal row whose response_json is missing/corrupt/non-object replays
    as a terminal 503 integrity error — never an empty {} with HTTP 200."""
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]
    capability_id = _capability_id_of(capability)

    first = _activate(client, capability, "treasury", nonce_wire)
    assert first.status_code == 200

    app_db.execute(
        "UPDATE demo_capabilities SET response_json=? WHERE capability_id=?",
        (corrupt_json, capability_id),
    )
    replay = _activate(client, capability, "treasury", nonce_wire)
    assert not (replay.status_code == 200 and replay.json() == {})
    assert replay.status_code == 503
    assert replay.json()["error_code"] == "stored_response_integrity"
    # The pipeline never re-runs for a corrupt terminal replay.
    assert len(stub_executor) == 1


@pytest.mark.parametrize("corrupt_status", [None, "two-hundred", 99, 1000])
def test_dm_rev2_corrupt_response_status_replays_as_503_integrity(
    client, app_db, stub_executor, corrupt_status
):
    """A terminal row whose response_status is missing, non-int, or outside the
    sane HTTP range replays as a terminal 503 integrity error, never {} 200."""
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]
    capability_id = _capability_id_of(capability)

    first = _activate(client, capability, "treasury", nonce_wire)
    assert first.status_code == 200

    app_db.execute(
        "UPDATE demo_capabilities SET response_status=? WHERE capability_id=?",
        (corrupt_status, capability_id),
    )
    replay = _activate(client, capability, "treasury", nonce_wire)
    assert not (replay.status_code == 200 and replay.json() == {})
    assert replay.status_code == 503
    assert replay.json()["error_code"] == "stored_response_integrity"
    assert len(stub_executor) == 1


def test_dm_rev3_terminalization_race_durable_failed_state_wins(
    client, app_db, monkeypatch
):
    """Lease expiry + concurrent crash recovery: when the RUNNING claim is
    terminalized FAILED while the original request's pipeline is still in
    flight, the original request must return the persisted FAILED state — the
    durable ledger is the authority, never the in-memory success."""
    crash_body = {
        "schema_version": "demo-run-v1",
        "status": "failed",
        "error": "Demo run did not finish (crash/expiry recovery)",
        "scenario_id": "treasury",
        "is_demo": True,
    }

    async def _racing(db, scenario_type, *, demo_run_id, enforce_cooldown):
        # A concurrent retry recovered the expired lease mid-flight: the row
        # is already terminal FAILED before this result can be recorded.
        db.execute(
            "UPDATE demo_capabilities SET state='FAILED', response_status=503, "
            "response_json=? WHERE demo_run_id=?",
            (json.dumps({**crash_body, "demo_run_id": demo_run_id}), demo_run_id),
        )
        return 200, {
            "success": True,
            "scenario_type": scenario_type,
            "proposal_id": "DAO-DEMO-STUB01",
            "demo_run_id": demo_run_id,
            "is_demo": True,
        }

    monkeypatch.setattr(demo, "_execute_demo_trigger", _racing)
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]
    capability_id = _capability_id_of(capability)

    activated = _activate(client, capability, "treasury", nonce_wire)
    assert activated.status_code == 503
    body = activated.json()
    assert body["status"] == "failed"
    assert body.get("status") != "started"

    # The durable ledger keeps the concurrent FAILED terminalization — the
    # lost in-memory success never clobbers it.
    row = _capability_row(app_db, capability_id)
    assert row["state"] == "FAILED"
    assert int(row["response_status"]) == 503
    assert json.loads(row["response_json"])["status"] == "failed"

    # A subsequent terminal retry replays the same persisted FAILED state.
    replay = _activate(client, capability, "treasury", nonce_wire)
    assert replay.status_code == 503
    assert replay.json()["status"] == "failed"


async def test_dm_rev4_preexisting_demo_id_collision_never_adopted(
    monkeypatch, tmp_path
):
    """Pre-existing DAO-DEMO-* rows in proposals AND demo_runs: allocation
    skips both colliding suffixes and never adopts (or later cleanup-owns)
    the pre-existing records."""
    db = init_db(tmp_path / "rev4-collision.db")
    try:
        ensure_demo_tables(db)
        _seed_proposal(db, "DAO-DEMO-AAAAAA")             # collision in proposals
        _seed_run(db, "demo-run-old", "DAO-DEMO-BBBBBB")  # collision in demo_runs

        fixed = [
            uuid.UUID("aaaaaa00-0000-4000-8000-000000000001"),
            uuid.UUID("bbbbbb00-0000-4000-8000-000000000002"),
            uuid.UUID("cccccc00-0000-4000-8000-000000000003"),
        ]
        real_uuid4 = uuid.uuid4

        def _fake_uuid4():
            return fixed.pop(0) if fixed else real_uuid4()

        monkeypatch.setattr(demo.uuid, "uuid4", _fake_uuid4)

        _install_pipeline_stubs(monkeypatch, db)
        status, payload = await demo._execute_demo_trigger(
            db, "treasury", demo_run_id="demo-run-new", enforce_cooldown=False
        )
        assert status == 200
        # Both colliding suffixes were skipped — never silently adopted.
        assert payload["proposal_id"] == "DAO-DEMO-CCCCCC"

        # The new run owns ONLY its own fresh id.
        owned = db.execute(
            "SELECT proposal_id FROM demo_runs WHERE demo_run_id='demo-run-new'"
        ).fetchall()
        assert [r[0] for r in owned] == ["DAO-DEMO-CCCCCC"]

        # Cleanup of the new run never touches the pre-existing records.
        result = remove_demo_proposals(db, "demo-run-new")
        assert result["cleaned_proposals"] == 1
        remaining = {
            r[0] for r in db.execute("SELECT proposal_id FROM proposals").fetchall()
        }
        assert "DAO-DEMO-AAAAAA" in remaining      # pre-existing proposal survives
        assert "DAO-DEMO-CCCCCC" not in remaining  # the run's own proposal removed
        assert (
            db.execute(
                "SELECT COUNT(*) FROM demo_runs WHERE demo_run_id='demo-run-old' "
                "AND proposal_id='DAO-DEMO-BBBBBB'"
            ).fetchone()[0]
            == 1
        )
    finally:
        db.close()


async def test_dm_rev4_allocation_fails_closed_after_bounded_attempts(
    monkeypatch, tmp_path
):
    """When every candidate suffix collides, allocation fails closed after a
    bounded number of attempts — the pre-existing record is never adopted and
    no mutation ever runs."""
    db = init_db(tmp_path / "rev4-exhausted.db")
    try:
        ensure_demo_tables(db)
        _seed_proposal(db, "DAO-DEMO-AAAAAA")
        monkeypatch.setattr(
            demo.uuid,
            "uuid4",
            lambda: uuid.UUID("aaaaaa00-0000-4000-8000-000000000001"),
        )
        calls = _install_pipeline_stubs(monkeypatch, db)
        status, payload = await demo._execute_demo_trigger(
            db, "treasury", demo_run_id="demo-run-exhausted", enforce_cooldown=False
        )
        assert status == 500
        assert payload["success"] is False
        assert calls == []  # failed closed BEFORE any pipeline mutation
        # The pre-existing record was never adopted or cleanup-owned.
        assert (
            db.execute(
                "SELECT COUNT(*) FROM demo_runs WHERE proposal_id='DAO-DEMO-AAAAAA'"
            ).fetchone()[0]
            == 0
        )
        assert (
            db.execute(
                "SELECT COUNT(*) FROM proposals WHERE proposal_id='DAO-DEMO-AAAAAA'"
            ).fetchone()[0]
            == 1
        )
    finally:
        db.close()


def test_dm_rev5_issued_at_mismatch_rejected(client, app_db, stub_executor):
    """A signed token whose issued_at no longer equals the durable row is
    refused as 401 invalid_capability (ALL signed immutable fields match)."""
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]
    capability_id = _capability_id_of(capability)

    app_db.execute(
        "UPDATE demo_capabilities SET issued_at=issued_at-1 WHERE capability_id=?",
        (capability_id,),
    )
    activated = _activate(client, capability, "treasury", nonce_wire)
    assert activated.status_code == 401
    assert activated.json()["error_code"] == "invalid_capability"
    assert stub_executor == []


def test_dm_rev5_expires_at_mismatch_rejected(client, app_db, stub_executor):
    """A signed token whose expires_at no longer equals the durable row is
    refused as 401 invalid_capability — a widened durable expiry can never be
    activated by the originally-signed token."""
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]
    capability_id = _capability_id_of(capability)

    app_db.execute(
        "UPDATE demo_capabilities SET expires_at=expires_at+1000 "
        "WHERE capability_id=?",
        (capability_id,),
    )
    activated = _activate(client, capability, "treasury", nonce_wire)
    assert activated.status_code == 401
    assert activated.json()["error_code"] == "invalid_capability"
    assert stub_executor == []


# ---------------------------------------------------------------------------
# WP3 re-review — expiry-vs-durable-row state ordering (Codex reproduction at
# 4b60f1c): the RUNNING recovery lease (180s) exceeds the capability lifetime
# (120s), so checking token expiry BEFORE loading the durable row made every
# crashed RUNNING capability externally unrecoverable (403 capability_expired
# forever, row stuck RUNNING). Expiry may reject ONLY an ISSUED, never-consumed
# row; terminal/RUNNING rows are dispatched from the durable ledger first.
# ---------------------------------------------------------------------------


def _freeze_demo_clock(monkeypatch, frozen: float) -> None:
    """Freeze the clock the demo routes read (demo.time is the time module)."""
    monkeypatch.setattr(demo.time, "time", lambda: frozen)


def test_dm_wp3_7_expired_crashed_running_recovers_failed_not_403(
    client, app_db, monkeypatch
):
    """Codex reproduction: issue → claim RUNNING → crash (no terminal write) →
    clock past BOTH the 120s capability expiry AND the 180s lease → retry must
    return the 503 crash-recovery body and terminalize the row FAILED, never
    403 capability_expired with the row retained RUNNING forever."""
    import time as _time

    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]
    capability_id = _capability_id_of(capability)

    async def _crashing(db, scenario_type, *, demo_run_id, enforce_cooldown):
        raise RuntimeError("pipeline crashed mid-run (no terminal write)")

    monkeypatch.setattr(demo, "_execute_demo_trigger", _crashing)
    with pytest.raises(RuntimeError):
        _activate(client, capability, "treasury", nonce_wire)

    row = _capability_row(app_db, capability_id)
    assert row["state"] == "RUNNING"
    assert row["response_status"] is None  # crashed before any terminal write
    running_run_id = row["demo_run_id"]

    # Advance past BOTH the capability expiry and the recovery lease.
    frozen = (
        max(
            int(row["expires_at"]),
            int(row["consumed_at"]) + demo._RUNNING_LEASE_SECONDS,
        )
        + 60
    )
    assert frozen > int(row["expires_at"])
    assert frozen > int(row["consumed_at"]) + demo._RUNNING_LEASE_SECONDS
    assert frozen > _time.time()
    _freeze_demo_clock(monkeypatch, float(frozen))

    recovered = _activate(client, capability, "treasury", nonce_wire)
    assert recovered.status_code == 503
    body = recovered.json()
    assert body["status"] == "failed"
    assert body["demo_run_id"] == running_run_id
    assert body["scenario_id"] == "treasury"
    assert body.get("error_code") != "capability_expired"

    terminal = _capability_row(app_db, capability_id)
    assert terminal["state"] == "FAILED"
    assert int(terminal["response_status"]) == 503

    # Subsequent retries replay the stored FAILED terminal (transition ONCE).
    replay = _activate(client, capability, "treasury", nonce_wire)
    assert replay.status_code == 503
    assert replay.json() == body


def test_dm_wp3_7_expired_issued_row_rejected_403_and_stays_issued(
    client, app_db, stub_executor, monkeypatch
):
    """An ISSUED, never-consumed capability past its lifetime is the ONLY
    expiry rejection (403 capability_expired); the row is left ISSUED and no
    pipeline runs. Once GC removes the expired row, the token is simply
    invalid (401) — deliberate migration of the old expiry-before-row-load
    ordering."""
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]
    capability_id = _capability_id_of(capability)
    row = _capability_row(app_db, capability_id)

    _freeze_demo_clock(monkeypatch, float(int(row["expires_at"]) + 10))

    activated = _activate(client, capability, "treasury", nonce_wire)
    assert activated.status_code == 403
    assert activated.json()["error_code"] == "capability_expired"
    assert stub_executor == []

    after = _capability_row(app_db, capability_id)
    assert after["state"] == "ISSUED"
    assert after["consumed_at"] is None

    # An unrelated issuance GCs the expired unconsumed row; the signed token
    # then fails the durable-row match as 401 invalid_capability.
    gc_issue, _ = _issue(client, nonce_wire=_wire_nonce())
    assert gc_issue.status_code == 200
    assert _capability_row(app_db, capability_id) is None
    retry = _activate(client, capability, "treasury", nonce_wire)
    assert retry.status_code == 401
    assert retry.json()["error_code"] == "invalid_capability"
    assert stub_executor == []


def test_dm_wp3_7_expired_running_before_lease_end_returns_202_same_run(
    client, app_db, stub_executor, monkeypatch
):
    """A RUNNING claim whose token has expired but whose 180s lease is still
    active returns 202 with the SAME run identity (the in-flight run owns the
    lease); the row stays RUNNING and the pipeline is never re-run."""
    import time as _time

    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]
    capability_id = _capability_id_of(capability)

    claimed_at = int(_time.time())
    app_db.execute(
        "UPDATE demo_capabilities SET state='RUNNING', consumed_at=?, "
        "demo_run_id='demo-run-inflight-expired', response_status=NULL, "
        "response_json=NULL WHERE capability_id=?",
        (claimed_at, capability_id),
    )
    row = _capability_row(app_db, capability_id)

    # Past the 120s token expiry, but still inside the 180s recovery lease.
    frozen = int(row["expires_at"]) + 10
    assert frozen > int(row["expires_at"])
    assert frozen < claimed_at + demo._RUNNING_LEASE_SECONDS
    _freeze_demo_clock(monkeypatch, float(frozen))

    retry = _activate(client, capability, "treasury", nonce_wire)
    assert retry.status_code == 202
    body = retry.json()
    assert body["status"] == "running"
    assert body["demo_run_id"] == "demo-run-inflight-expired"
    assert stub_executor == []

    after = _capability_row(app_db, capability_id)
    assert after["state"] == "RUNNING"  # the active lease was honored


def test_dm_wp3_7_expired_terminal_row_replays_stored_result(
    client, app_db, stub_executor, monkeypatch
):
    """A terminal row replays its validated stored result even after the token
    has expired — idempotent replay is governed by the durable ledger, not the
    token clock."""
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]
    capability_id = _capability_id_of(capability)

    first = _activate(client, capability, "treasury", nonce_wire)
    assert first.status_code == 200
    assert first.json()["status"] == "started"
    assert len(stub_executor) == 1

    row = _capability_row(app_db, capability_id)
    assert row["state"] == "SUCCEEDED"
    frozen = (
        max(
            int(row["expires_at"]),
            int(row["consumed_at"]) + demo._RUNNING_LEASE_SECONDS,
        )
        + 60
    )
    _freeze_demo_clock(monkeypatch, float(frozen))

    replay = _activate(client, capability, "treasury", nonce_wire)
    assert replay.status_code == 200
    body = replay.json()
    assert body["status"] == "idempotent_replay"
    assert body["demo_run_id"] == first.json()["demo_run_id"]
    assert len(stub_executor) == 1  # never re-run


def test_dm_wp3_7_reconciliation_terminalizes_abandoned_running_on_issuance(
    client, app_db, stub_executor, monkeypatch
):
    """A crashed RUNNING claim the browser never retries is terminalized by the
    bounded issuance-time reconciliation (a later UNRELATED issuance call), with
    the standard crash-recovery body. Active-lease RUNNING rows — even with an
    expired token — and terminal rows are never touched."""
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]
    capability_id = _capability_id_of(capability)

    async def _crashing(db, scenario_type, *, demo_run_id, enforce_cooldown):
        raise RuntimeError("pipeline crashed mid-run (no terminal write)")

    monkeypatch.setattr(demo, "_execute_demo_trigger", _crashing)
    with pytest.raises(RuntimeError):
        _activate(client, capability, "treasury", nonce_wire)

    abandoned = _capability_row(app_db, capability_id)
    assert abandoned["state"] == "RUNNING"
    abandoned_run_id = abandoned["demo_run_id"]

    frozen = (
        max(
            int(abandoned["expires_at"]),
            int(abandoned["consumed_at"]) + demo._RUNNING_LEASE_SECONDS,
        )
        + 60
    )

    # Guard rows: an ACTIVE-lease RUNNING claim whose token already expired,
    # and a terminal row with a stale consumed_at. Neither may be touched.
    app_db.execute(
        "INSERT INTO demo_capabilities (capability_id, scenario_id, "
        "client_binding_hash, nonce_hash, issued_at, expires_at, state, "
        "demo_run_id, consumed_at) "
        "VALUES ('active-lease-expired-token', 'oracle', 'h', 'n', ?, ?, "
        "'RUNNING', 'demo-run-active', ?)",
        (frozen - 200, frozen - 80, frozen - 30),
    )
    app_db.execute(
        "INSERT INTO demo_capabilities (capability_id, scenario_id, "
        "client_binding_hash, nonce_hash, issued_at, expires_at, state, "
        "demo_run_id, consumed_at, response_status, response_json) "
        "VALUES ('terminal-stale', 'yield', 'h', 'n', ?, ?, 'SUCCEEDED', "
        "'demo-run-terminal', ?, 200, '{\"status\": \"started\"}')",
        (frozen - 10_000, frozen - 9_000, frozen - 9_500),
    )

    _freeze_demo_clock(monkeypatch, float(frozen))

    # A later, UNRELATED issuance (different client) runs the reconciliation.
    unrelated, _ = _issue(client, nonce_wire=_wire_nonce())
    assert unrelated.status_code == 200

    reconciled = _capability_row(app_db, capability_id)
    assert reconciled["state"] == "FAILED"
    assert int(reconciled["response_status"]) == 503
    assert json.loads(reconciled["response_json"]) == {
        "schema_version": "demo-run-v1",
        "status": "failed",
        "error": "Demo run did not finish (crash/expiry recovery)",
        "demo_run_id": abandoned_run_id,
        "scenario_id": "treasury",
        "is_demo": True,
    }

    active = _capability_row(app_db, "active-lease-expired-token")
    assert active["state"] == "RUNNING"  # active lease never reconciled
    assert active["response_status"] is None
    terminal = _capability_row(app_db, "terminal-stale")
    assert terminal["state"] == "SUCCEEDED"  # terminal rows never touched
    assert json.loads(terminal["response_json"]) == {"status": "started"}

    # A very late browser retry replays the reconciled FAILED terminal.
    late = _activate(client, capability, "treasury", nonce_wire)
    assert late.status_code == 503
    assert late.json()["status"] == "failed"
    assert late.json()["demo_run_id"] == abandoned_run_id
    assert stub_executor == []


def test_dm_wp3_7_reconciliation_batch_is_bounded(client, app_db, monkeypatch):
    """Reconciliation transitions at most _STALE_RUNNING_RECONCILE_BATCH stale
    RUNNING rows per issuance (oldest lease first) — bounded housekeeping."""
    import time as _time

    ensure_demo_tables(app_db)
    now = int(_time.time())
    stale = now - (demo._RUNNING_LEASE_SECONDS + 1_000)
    for index in range(3):
        app_db.execute(
            "INSERT INTO demo_capabilities (capability_id, scenario_id, "
            "client_binding_hash, nonce_hash, issued_at, expires_at, state, "
            "demo_run_id, consumed_at) VALUES (?, 'treasury', 'h', 'n', ?, ?, "
            "'RUNNING', ?, ?)",
            (
                f"stale-running-{index}",
                stale - 120,
                stale - 60,
                f"demo-run-stale-{index}",
                stale + index,
            ),
        )
    monkeypatch.setattr(demo, "_STALE_RUNNING_RECONCILE_BATCH", 2)

    resp, _ = _issue(client, nonce_wire=_wire_nonce())
    assert resp.status_code == 200
    failed = app_db.execute(
        "SELECT COUNT(*) FROM demo_capabilities "
        "WHERE state='FAILED' AND capability_id LIKE 'stale-running-%'"
    ).fetchone()[0]
    assert failed == 2  # bounded: oldest two only

    resp, _ = _issue(client, nonce_wire=_wire_nonce())
    assert resp.status_code == 200
    failed = app_db.execute(
        "SELECT COUNT(*) FROM demo_capabilities "
        "WHERE state='FAILED' AND capability_id LIKE 'stale-running-%'"
    ).fetchone()[0]
    assert failed == 3  # the next issuance drains the remainder


def test_dm_wp3_7_concurrent_recovery_single_transition_cas_holds(
    client, app_db, monkeypatch
):
    """Concurrent recovery: reconciliation terminalizes a stale-leased RUNNING
    claim while the original request's pipeline is still in flight. Exactly ONE
    transition happens — the in-flight request's terminal write loses the
    rowcount CAS and must return the persisted FAILED state (the durable
    ledger, never its in-memory success)."""
    import time as _time

    async def _racing(db, scenario_type, *, demo_run_id, enforce_cooldown):
        # The lease elapses mid-flight...
        db.execute(
            "UPDATE demo_capabilities SET consumed_at=consumed_at-? "
            "WHERE demo_run_id=?",
            (demo._RUNNING_LEASE_SECONDS + 60, demo_run_id),
        )
        # ...and a concurrent issuance runs its bounded reconciliation.
        db.execute("BEGIN IMMEDIATE")
        try:
            demo._reconcile_stale_running(db, int(_time.time()))
            db.execute("COMMIT")
        except Exception:
            db.execute("ROLLBACK")
            raise
        return 200, {
            "success": True,
            "scenario_type": scenario_type,
            "proposal_id": "DAO-DEMO-STUB01",
            "demo_run_id": demo_run_id,
            "is_demo": True,
        }

    monkeypatch.setattr(demo, "_execute_demo_trigger", _racing)
    response, nonce_wire = _issue(client)
    capability = response.json()["capability"]
    capability_id = _capability_id_of(capability)

    activated = _activate(client, capability, "treasury", nonce_wire)
    assert activated.status_code == 503
    body = activated.json()
    assert body["status"] == "failed"
    assert body.get("status") != "started"

    row = _capability_row(app_db, capability_id)
    assert row["state"] == "FAILED"
    assert int(row["response_status"]) == 503
    # The reconciliation's crash body won — the lost in-memory success never
    # overwrote it (single transition).
    assert json.loads(row["response_json"])["status"] == "failed"

    replay = _activate(client, capability, "treasury", nonce_wire)
    assert replay.status_code == 503
    assert replay.json() == body


def test_dm_wp3_4_cleanup_atomic_rollback_on_error(tmp_path, monkeypatch):
    """Cleanup selection+deletion is one BEGIN IMMEDIATE: an error mid-delete
    rolls back with nothing removed."""
    from gateway.routes import demo_cleanup

    db = init_db(tmp_path / "wp3-4-atomic.db")
    _seed_proposal(db, "DAO-DEMO-ATOM01")
    _seed_run(db, "demo-run-a", "DAO-DEMO-ATOM01")

    original = demo_cleanup._delete_for_proposals
    state = {"calls": 0}

    def _boom(db_, table, column, proposal_ids):
        state["calls"] += 1
        if table == "proposals":
            raise RuntimeError("injected mid-delete failure")
        return original(db_, table, column, proposal_ids)

    monkeypatch.setattr(demo_cleanup, "_delete_for_proposals", _boom)
    with pytest.raises(RuntimeError):
        remove_demo_proposals(db, "demo-run-a")

    # Rolled back: the proposal, its card, and provenance all survive.
    assert (
        db.execute(
            "SELECT COUNT(*) FROM proposals WHERE proposal_id='DAO-DEMO-ATOM01'"
        ).fetchone()[0]
        == 1
    )
    assert (
        db.execute(
            "SELECT COUNT(*) FROM demo_runs WHERE demo_run_id='demo-run-a'"
        ).fetchone()[0]
        == 1
    )
