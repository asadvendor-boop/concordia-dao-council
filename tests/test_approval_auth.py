"""Approval boundary v1 tests (AU) — file-secret loading, layered auth,
CSRF + nonce, and no plain-env in production mode.

Spec: handoff/G1_INTERFACE_SPEC.md §12 "Approval boundary v1".
"""
from __future__ import annotations

import base64
import hashlib
import hmac as hmac_mod
import json
from datetime import datetime, timedelta, timezone

import bcrypt
import pytest
from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.database import init_db
from gateway.routes import approve_ui
from shared.config import HUMAN_APPROVER_IDS

PROPOSAL_ID = "DAO-PROP-AUTEST"
PROXY_SECRET = "proxy-secret-0123456789abcdef0123456789abcdef"
UI_USER = "council-approver"
UI_PASSWORD = "correct-horse-battery-staple"
APPROVER_ID = "human-approver-au"
CSRF_SECRET = "csrf-secret-0123456789abcdef0123456789abcdef"

# rounds=4 keeps the suite fast; production uses a real cost factor.
BCRYPT_HASH = bcrypt.hashpw(UI_PASSWORD.encode(), bcrypt.gensalt(rounds=4)).decode()

_FILE_NAMES = {
    "APPROVAL_PROXY_SECRET": PROXY_SECRET,
    "APPROVAL_UI_USER": UI_USER,
    "APPROVAL_UI_APPROVER_ID": APPROVER_ID,
    "APPROVAL_UI_BCRYPT_HASH": BCRYPT_HASH,
    "APPROVAL_UI_CSRF_SECRET": CSRF_SECRET,
}


def _basic_auth(user: str = UI_USER, password: str = UI_PASSWORD) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def _full_headers(
    proxy: str = PROXY_SECRET,
    auth: str | None = None,
) -> dict[str, str]:
    headers = {}
    if proxy is not None:
        headers["X-Proxy-Secret"] = proxy
    headers["Authorization"] = auth if auth is not None else _basic_auth()
    return headers


def _csrf_for(nonce: str, secret: str = CSRF_SECRET) -> str:
    return hmac_mod.new(secret.encode(), nonce.encode(), hashlib.sha256).hexdigest()


@pytest.fixture()
def approval_env(monkeypatch, tmp_path):
    """Production-mode fixture: the five frozen _FILE names point at tmp
    files; direct value variables are NOT set; CONCORDIA_TEST_MODE is unset."""
    monkeypatch.delenv("CONCORDIA_TEST_MODE", raising=False)
    for env_name, value in _FILE_NAMES.items():
        monkeypatch.delenv(env_name, raising=False)
        secret_file = tmp_path / f"{env_name.lower()}.secret"
        secret_file.write_text(value + "\n", encoding="utf-8")
        monkeypatch.setenv(f"{env_name}_FILE", str(secret_file))

    # _publish_and_advance requirements (server-side helpers only).
    monkeypatch.setenv("OPERATOR_AGENT_ID", "locke-casper-execution")
    monkeypatch.setenv("RECORDER_AGENT_ID", "recorder-concordia-core")

    approve_ui._reset_config_for_testing()
    HUMAN_APPROVER_IDS.add(APPROVER_ID)
    yield tmp_path
    HUMAN_APPROVER_IDS.discard(APPROVER_ID)
    approve_ui._reset_config_for_testing()


@pytest.fixture()
def db_path(approval_env):
    return str(approval_env / "approval-auth.db")


@pytest.fixture()
def client(db_path):
    with TestClient(create_app(db_path=db_path)) as test_client:
        yield test_client


@pytest.fixture()
def db(db_path, client):
    """Test-thread connection to the app's file-backed DB (WAL).

    The app's own connection lives in the TestClient portal thread; sharing
    it across threads raises sqlite3.ProgrammingError.
    """
    connection = init_db(db_path)
    yield connection
    connection.close()


def _seed_approval_fixture(db, proposal_id: str = PROPOSAL_ID):
    """Seed a PLANNED proposal + published ResponsePlan + active nonce."""
    from shared.approval import (
        compute_action_hash,
        compute_plan_hash,
        create_nonce,
        normalize_plan_for_hash,
    )

    now = datetime.now(timezone.utc).isoformat()
    room_id = f"room-{proposal_id.lower()}"
    db.execute(
        "INSERT INTO proposals (proposal_id, state, room_id, created_at, updated_at) "
        "VALUES (?, 'PLANNED', ?, ?, ?)",
        (proposal_id, room_id, now, now),
    )
    db.execute(
        "INSERT INTO proposal_rooms (room_id, proposal_id, title, created_by, created_at, updated_at) "
        "VALUES (?, ?, 'AU Test Chamber', 'recorder', ?, ?)",
        (room_id, proposal_id, now, now),
    )

    plan_data = {
        "card_type": "ResponsePlan",
        "proposal_id": proposal_id,
        "runbook": "RB-001",
        "envelopes": [],
        "risk_level": "high",
        "requires_human_approval": True,
        "revision": 1,
    }
    db.execute(
        "INSERT INTO cards (proposal_id, sequence_number, card_type, card_hash, "
        "card_json, created_at, published_at) VALUES (?, 1, 'ResponsePlan', ?, ?, ?, ?)",
        (proposal_id, "hash-plan-au", json.dumps(plan_data), now, now),
    )

    plan_hash = compute_plan_hash(normalize_plan_for_hash(plan_data))
    action_hash = compute_action_hash(plan_data["envelopes"])
    nonce = create_nonce(
        proposal_id,
        plan_hash,
        action_hash,
        1,
        datetime.now(timezone.utc) + timedelta(minutes=30),
        db,
    )
    db.execute(
        "UPDATE nonces SET challenge_message_id='msg-challenge-au' "
        "WHERE proposal_id=? AND nonce=?",
        (proposal_id, nonce),
    )
    return nonce, plan_hash, action_hash


def _nonce_consumed(db, proposal_id: str, nonce: str) -> int:
    row = db.execute(
        "SELECT consumed FROM nonces WHERE proposal_id=? AND nonce=?",
        (proposal_id, nonce),
    ).fetchone()
    assert row is not None
    return int(row["consumed"])


# ---------------------------------------------------------------------------
# AU-01..06 — layered authentication, exact failure codes
# ---------------------------------------------------------------------------

def test_au01_direct_access_forbidden_without_proxy_secret(client):
    response = client.get(f"/approve/{PROPOSAL_ID}")
    assert response.status_code == 403
    assert response.json()["detail"] == "Direct access forbidden"


def test_au02_basic_auth_required_with_valid_proxy(client):
    response = client.get(
        f"/approve/{PROPOSAL_ID}", headers={"X-Proxy-Secret": PROXY_SECRET}
    )
    assert response.status_code == 401
    assert response.headers.get("WWW-Authenticate") == "Basic"


@pytest.mark.parametrize(
    "auth,expected_status",
    [
        (_basic_auth(password="wrong-password"), 403),
        (_basic_auth(user="wrong-user"), 403),
        ("Basic not!!base64??", 401),
    ],
)
def test_au03_bad_basic_credentials_rejected(client, auth, expected_status):
    response = client.get(
        f"/approve/{PROPOSAL_ID}",
        headers={"X-Proxy-Secret": PROXY_SECRET, "Authorization": auth},
    )
    assert response.status_code == expected_status


@pytest.mark.parametrize("proxy_value", ["", "caller-supplied-wrong-secret"])
def test_au04_au05_au06_wrong_or_missing_proxy_secret_rejected(client, proxy_value):
    """Even with fully valid Basic credentials, the gateway trusts only the
    (Caddy-overwritten) X-Proxy-Secret value. Caddy-side overwrite is a
    Codex release-layer item recorded in the WP3 interface manifest."""
    response = client.get(
        f"/approve/{PROPOSAL_ID}",
        headers={"X-Proxy-Secret": proxy_value, "Authorization": _basic_auth()},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Direct access forbidden"


# ---------------------------------------------------------------------------
# File-secret loading, production ignore of direct env, reset hook
# ---------------------------------------------------------------------------

def test_file_secrets_load_in_production_mode(client, db):
    _seed_approval_fixture(db)
    response = client.get(f"/approve/{PROPOSAL_ID}", headers=_full_headers())
    assert response.status_code == 200
    assert "Approval Required" in response.text


def test_direct_env_values_ignored_in_production(monkeypatch, tmp_path):
    """Direct value variables must be ignored when CONCORDIA_TEST_MODE is
    off — plain-env configuration cannot enable the approval UI."""
    monkeypatch.delenv("CONCORDIA_TEST_MODE", raising=False)
    for env_name, value in _FILE_NAMES.items():
        monkeypatch.delenv(f"{env_name}_FILE", raising=False)
        monkeypatch.setenv(env_name, value)
    approve_ui._reset_config_for_testing()
    HUMAN_APPROVER_IDS.add(APPROVER_ID)
    try:
        with TestClient(create_app(db_path=":memory:")) as client:
            response = client.get(
                f"/approve/{PROPOSAL_ID}", headers=_full_headers()
            )
            # Proxy secret was never loaded → direct access forbidden.
            assert response.status_code == 403
            assert response.json()["detail"] == "Direct access forbidden"
    finally:
        HUMAN_APPROVER_IDS.discard(APPROVER_ID)
        approve_ui._reset_config_for_testing()


def test_test_mode_fallback_allows_direct_env(monkeypatch, tmp_path):
    """The direct-value fallback exists ONLY behind CONCORDIA_TEST_MODE."""
    monkeypatch.setenv("CONCORDIA_TEST_MODE", "1")
    for env_name, value in _FILE_NAMES.items():
        monkeypatch.delenv(f"{env_name}_FILE", raising=False)
        monkeypatch.setenv(env_name, value)
    monkeypatch.setenv("OPERATOR_AGENT_ID", "locke-casper-execution")
    approve_ui._reset_config_for_testing()
    HUMAN_APPROVER_IDS.add(APPROVER_ID)
    db_path = str(tmp_path / "test-mode.db")
    try:
        with TestClient(create_app(db_path=db_path)) as client:
            db = init_db(db_path)
            _seed_approval_fixture(db)
            db.close()
            response = client.get(f"/approve/{PROPOSAL_ID}", headers=_full_headers())
            assert response.status_code == 200
    finally:
        HUMAN_APPROVER_IDS.discard(APPROVER_ID)
        approve_ui._reset_config_for_testing()


def test_reset_config_for_testing_hook(client, approval_env):
    # Cached config: first request warms the cache.
    response = client.get(f"/approve/{PROPOSAL_ID}", headers=_full_headers())
    assert response.status_code in (200, 404)  # authenticated (proposal absent → 404 page)

    # Rotate the proxy secret file. Without a reset the old value is cached.
    new_secret = "rotated-proxy-secret-fedcba9876543210fedcba98"
    proxy_file = approval_env / "approval_proxy_secret.secret"
    proxy_file.write_text(new_secret, encoding="utf-8")

    response = client.get(f"/approve/{PROPOSAL_ID}", headers=_full_headers())
    assert response.status_code in (200, 404)  # stale cache still accepts old secret

    approve_ui._reset_config_for_testing()

    response = client.get(f"/approve/{PROPOSAL_ID}", headers=_full_headers())
    assert response.status_code == 403  # old secret now rejected

    response = client.get(
        f"/approve/{PROPOSAL_ID}", headers=_full_headers(proxy=new_secret)
    )
    assert response.status_code in (200, 404)  # new secret accepted


# ---------------------------------------------------------------------------
# AU-07 / AU-08 — CSRF and approver allowlist
# ---------------------------------------------------------------------------

def test_au07_csrf_failure_does_not_consume_nonce(client, db):
    nonce, _, _ = _seed_approval_fixture(db)

    response = client.post(
        f"/approve/{PROPOSAL_ID}",
        headers=_full_headers(),
        data={
            "nonce": nonce,
            "csrf_token": "not-the-right-token",
            "decision": "approve",
        },
    )
    assert response.status_code == 403
    assert "CSRF verification failed" in response.text
    assert _nonce_consumed(db, PROPOSAL_ID, nonce) == 0


def test_au07b_missing_csrf_or_nonce_is_400(client, db):
    nonce, _, _ = _seed_approval_fixture(db)
    response = client.post(
        f"/approve/{PROPOSAL_ID}",
        headers=_full_headers(),
        data={"decision": "approve"},
    )
    assert response.status_code == 400
    assert _nonce_consumed(db, PROPOSAL_ID, nonce) == 0


def test_au08_approver_not_in_allowlist_denied(client, db):
    """Configured approver id outside HUMAN_APPROVER_IDS is denied with the
    existing (frozen) status code and nothing is consumed."""
    nonce, _, _ = _seed_approval_fixture(db)

    HUMAN_APPROVER_IDS.discard(APPROVER_ID)
    try:
        response = client.get(f"/approve/{PROPOSAL_ID}", headers=_full_headers())
        assert response.status_code == 500  # same status code as frozen behavior
        assert _nonce_consumed(db, PROPOSAL_ID, nonce) == 0
    finally:
        HUMAN_APPROVER_IDS.add(APPROVER_ID)


# ---------------------------------------------------------------------------
# AU-09 / AU-10 — full approval, consumed nonce, idempotent replay
# ---------------------------------------------------------------------------

def test_au09_au10_full_approve_then_replay_is_single_use(client, db):
    nonce, _, _ = _seed_approval_fixture(db)

    # The GET page renders the plan with the CSRF token bound to the nonce.
    page = client.get(f"/approve/{PROPOSAL_ID}", headers=_full_headers())
    assert page.status_code == 200
    assert nonce in page.text

    response = client.post(
        f"/approve/{PROPOSAL_ID}",
        headers=_full_headers(),
        data={
            "nonce": nonce,
            "csrf_token": _csrf_for(nonce),
            "decision": "approve",
        },
    )
    assert response.status_code == 200
    assert "Approved" in response.text

    # Trusted result: consumed nonce + PUBLISHED human_approval authorization.
    assert _nonce_consumed(db, PROPOSAL_ID, nonce) == 1
    auth_rows = db.execute(
        "SELECT status, consumed_by FROM authorizations "
        "WHERE proposal_id=? AND authorization_type='human_approval'",
        (PROPOSAL_ID,),
    ).fetchall()
    assert len(auth_rows) == 1
    assert auth_rows[0]["status"] == "PUBLISHED"
    assert auth_rows[0]["consumed_by"] == APPROVER_ID

    state = db.execute(
        "SELECT state FROM proposals WHERE proposal_id=?", (PROPOSAL_ID,)
    ).fetchone()["state"]
    assert state == "APPROVED"

    # The trusted message was stored via the internal server-side helper.
    room_messages = db.execute(
        "SELECT COUNT(*) FROM proposal_room_messages WHERE proposal_id=?",
        (PROPOSAL_ID,),
    ).fetchone()[0]
    assert room_messages >= 1

    # AU-09: replay with the same nonce creates no second authorization and
    # the nonce remains consumed exactly once (idempotent success page).
    replay = client.post(
        f"/approve/{PROPOSAL_ID}",
        headers=_full_headers(),
        data={
            "nonce": nonce,
            "csrf_token": _csrf_for(nonce),
            "decision": "approve",
        },
    )
    assert replay.status_code == 200
    auth_count = db.execute(
        "SELECT COUNT(*) FROM authorizations "
        "WHERE proposal_id=? AND authorization_type='human_approval'",
        (PROPOSAL_ID,),
    ).fetchone()[0]
    assert auth_count == 1
    assert _nonce_consumed(db, PROPOSAL_ID, nonce) == 1
