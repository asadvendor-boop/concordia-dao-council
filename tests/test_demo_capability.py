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
