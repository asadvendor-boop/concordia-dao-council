"""SafePay Lite supplemental v2 ledger and wire-contract tests (WP2).

Covers SP-01..SP-04 plus the frozen issuance abuse controls: fixed-window
rate limiting, the two-phase reservation flow, capacity caps, content-
addressed report storage with fail-closed hash conflicts, terminal
404/409/410/422 redemption outcomes, and proxy-identity resolution.

Everything runs offline: chain observation, the report source, and the clock
are injected; secret files live in pytest tmp dirs.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

import x402_provider.app as provider_app
from shared.x402_payments import (
    SAFEPAY_V2_MAX_PUBLIC_REQUEST_BYTES,
    SAFEPAY_V2_NETWORK,
    SAFEPAY_V2_QUOTE_FIELDS,
    redeem_provider_x402_with_retry,
    safepay_v2_correlation_id,
    safepay_v2_quote_hash,
)
from x402_provider.app import (
    SafePayRedemptionAdmission,
    SafePayRedemptionAdmissionCaps,
    _normalize_ip_text,
    create_app,
    resolve_safepay_client_ip,
)
from x402_provider.ledger import (
    QuoteCapacityExhausted,
    QuoteRateLimited,
    SafePayCaps,
    SafePayLedger,
)


PAYEE = "ab" * 32
AMOUNT = "2500000000"
START = 1_800_000_000  # aligned far from a window boundary concern; 1_800_000_000 % 60 == 0


class FakeClock:
    def __init__(self, start: int = START) -> None:
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeObserver:
    """Injected chain observation source; the tests never touch the network."""

    def __init__(self) -> None:
        self.calls = 0
        self.by_hash: dict[str, object] = {}

    async def __call__(self, network: str, payment_hash: str) -> dict:
        self.calls += 1
        result = self.by_hash[payment_hash]
        if isinstance(result, Exception):
            raise result
        return dict(result)


def make_observation(quote: dict, payment_hash: str, **overrides) -> dict:
    observation = {
        "network": quote["network"],
        "payment_hash": payment_hash,
        "block_hash": "cd" * 32,
        "block_height": 8590556,
        "execution_status": "processed",
        "finality_status": "finalized",
        "from_account_hash": "ef" * 32,
        "to_account_hash": quote["payee_account_hash"],
        "amount_motes": quote["amount_motes"],
        "transfer_id": quote["correlation_id"],
        "execution_error": None,
        "observed_at": "2026-07-23T00:00:00Z",
        "native_transfer_count": 1,
    }
    observation.update(overrides)
    return observation


def install_secret_files(monkeypatch, tmp_path) -> None:
    proxy = tmp_path / "proxy_secret"
    proxy.write_bytes(b"p" * 48)
    hmac_file = tmp_path / "client_key_hmac_secret"
    hmac_file.write_bytes(b"h" * 48)
    monkeypatch.setenv("SAFEPAY_PROXY_SECRET_FILE", str(proxy))
    monkeypatch.setenv("SAFEPAY_CLIENT_KEY_HMAC_SECRET_FILE", str(hmac_file))


def build_app(
    tmp_path,
    monkeypatch,
    *,
    caps: SafePayCaps | None = None,
    clock: FakeClock | None = None,
    observer: FakeObserver | None = None,
    report_source=None,
    simulated_lag_attempts: int = 0,
    ledger_path: str | None = None,
    redemption_admission: SafePayRedemptionAdmission | None = None,
):
    install_secret_files(monkeypatch, tmp_path)
    return create_app(
        ledger_path=ledger_path or str(tmp_path / "safepay.db"),
        caps=caps or SafePayCaps(),
        clock=clock or FakeClock(),
        chain_observer=observer or FakeObserver(),
        report_source=report_source,
        payee_account_hash=PAYEE,
        amount_motes=AMOUNT,
        simulated_lag_attempts=simulated_lag_attempts,
        redemption_admission=redemption_admission,
    )


def issue_quote(client: TestClient, proposal_id: str = "DAO-PROP-6CB25C", resource_id: str = "risk-report:test") -> dict:
    response = client.post(
        "/x402/v2/quotes",
        json={
            "schema_version": "safepay-quote-request-v2",
            "proposal_id": proposal_id,
            "resource_id": resource_id,
        },
    )
    assert response.status_code == 402, response.text
    return response.json()


def redeem(client: TestClient, quote: dict, payment_hash: str):
    return client.post(
        "/x402/v2/redemptions",
        json={"schema_version": "safepay-redemption-v2", "quote": quote, "payment_hash": payment_hash},
    )


def db_count(path, table: str, where: str = "1=1", args: tuple = ()) -> int:
    conn = sqlite3.connect(str(path))
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}", args).fetchone()[0]
    finally:
        conn.close()


def assert_error_body(response, status: int, code: str, retryable: bool, disposition: str) -> None:
    assert response.status_code == status, response.text
    assert response.json() == {
        "schema_version": "safepay-v2",
        "error": {"code": code, "retryable": retryable},
        "delivery": {"replay_disposition": disposition},
    }
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Concordia-SafePay-Version"] == "safepay-v2"


# ---------------------------------------------------------------- quote issue


def test_quote_issue_402_shape_headers_and_persistence(tmp_path, monkeypatch):
    clock = FakeClock()
    app = build_app(tmp_path, monkeypatch, clock=clock)
    client = TestClient(app)
    body = issue_quote(client)

    assert list(body) == ["schema_version", "error", "quote", "payment_requirements"]
    assert body["schema_version"] == "safepay-v2"
    assert body["error"] == {"code": "payment_required", "retryable": False}

    quote = body["quote"]
    assert list(quote) == list(SAFEPAY_V2_QUOTE_FIELDS)
    assert quote["schema_version"] == "safepay-v2"
    assert quote["network"] == SAFEPAY_V2_NETWORK
    assert quote["payee_account_hash"] == PAYEE
    assert quote["amount_motes"] == AMOUNT
    assert quote["report_version"] == "safepay-report-v2"
    assert quote["expires_at"] == int(clock.now) + 900
    assert int(quote["quote_nonce"], 16) != 0

    requirements = body["payment_requirements"]
    assert list(requirements) == ["network", "payee_account_hash", "amount_motes", "correlation_id", "expires_at"]
    for field in requirements:
        assert requirements[field] == quote[field]

    response = client.post(
        "/x402/v2/quotes",
        json={"schema_version": "safepay-quote-request-v2", "proposal_id": "DAO-PROP-6CB25C", "resource_id": "risk-report:test"},
    )
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Concordia-SafePay-Version"] == "safepay-v2"

    # The complete immutable quote is persisted before the 402 returns.
    assert db_count(tmp_path / "safepay.db", "safepay_quotes", "quote_id = ?", (quote["quote_id"],)) == 1
    # Re-quotes have a new quote id and nonce.
    second = response.json()["quote"]
    assert second["quote_id"] != quote["quote_id"]
    assert second["quote_nonce"] != quote["quote_nonce"]
    assert second["correlation_id"] != quote["correlation_id"]


@pytest.mark.parametrize(
    "body",
    [
        {"schema_version": "safepay-quote-request-v2", "proposal_id": "DAO-PROP-6CB25C"},
        {
            "schema_version": "safepay-quote-request-v2",
            "proposal_id": "DAO-PROP-6CB25C",
            "resource_id": "x",
            "extra": 1,
        },
        {"schema_version": "safepay-quote-request-v1", "proposal_id": "DAO-PROP-6CB25C", "resource_id": "x"},
        {"schema_version": "safepay-quote-request-v2", "proposal_id": "dao-lowercase", "resource_id": "x"},
        {"schema_version": "safepay-quote-request-v2", "proposal_id": "DAO-PROP-6CB25C", "resource_id": ""},
        {"schema_version": "safepay-quote-request-v2", "proposal_id": "DAO-PROP-6CB25C", "resource_id": "r" * 201},
        {"schema_version": "safepay-quote-request-v2", "proposal_id": "DAO-PROP-6CB25C", "resource_id": "café"},
    ],
)
def test_quote_request_strict_validation(tmp_path, monkeypatch, body):
    app = build_app(tmp_path, monkeypatch)
    client = TestClient(app)
    response = client.post("/x402/v2/quotes", json=body)
    assert_error_body(response, 400, "invalid_request", False, "not_attempted")


def test_rate_limit_fixed_window_429_then_new_window(tmp_path, monkeypatch):
    clock = FakeClock()
    caps = SafePayCaps(per_client_limit=3)
    app = build_app(tmp_path, monkeypatch, caps=caps, clock=clock)
    client = TestClient(app)
    for _ in range(3):
        issue_quote(client)
    response = client.post(
        "/x402/v2/quotes",
        json={"schema_version": "safepay-quote-request-v2", "proposal_id": "DAO-PROP-6CB25C", "resource_id": "risk-report:test"},
    )
    assert_error_body(response, 429, "quote_rate_limited", True, "not_attempted")
    # Fixed window: floor(now/60)*60. Advancing into the next window admits again.
    clock.advance(60)
    issue_quote(client)


def test_global_rate_limit_across_clients(tmp_path, monkeypatch):
    caps = SafePayCaps(per_client_limit=10, global_limit=2)
    app = build_app(tmp_path, monkeypatch, caps=caps)
    client_a = TestClient(app, client=("203.0.113.10", 40001))
    client_b = TestClient(app, client=("203.0.113.20", 40002))
    issue_quote(client_a)
    issue_quote(client_b)
    response = client_b.post(
        "/x402/v2/quotes",
        json={"schema_version": "safepay-quote-request-v2", "proposal_id": "DAO-PROP-6CB25C", "resource_id": "risk-report:test"},
    )
    assert_error_body(response, 429, "quote_rate_limited", True, "not_attempted")


def test_rejected_preflight_never_calls_report_source(tmp_path, monkeypatch):
    calls = []

    def counting_source(proposal_id: str, resource_id: str) -> bytes:
        calls.append((proposal_id, resource_id))
        return b'{"ok":true}'

    caps = SafePayCaps(per_client_limit=1)
    app = build_app(tmp_path, monkeypatch, caps=caps, report_source=counting_source)
    client = TestClient(app)
    issue_quote(client)
    assert len(calls) == 1
    response = client.post(
        "/x402/v2/quotes",
        json={"schema_version": "safepay-quote-request-v2", "proposal_id": "DAO-PROP-6CB25C", "resource_id": "risk-report:test"},
    )
    assert response.status_code == 429
    # A rejected preflight never resolves or renders report bytes.
    assert len(calls) == 1


def test_report_source_failure_consumes_attempt_and_returns_503(tmp_path, monkeypatch):
    state = {"fail": True}

    def flaky_source(proposal_id: str, resource_id: str) -> bytes:
        if state["fail"]:
            raise RuntimeError("report backend down")
        return b'{"ok":true}'

    caps = SafePayCaps(per_client_limit=2)
    app = build_app(tmp_path, monkeypatch, caps=caps, report_source=flaky_source)
    client = TestClient(app)
    response = client.post(
        "/x402/v2/quotes",
        json={"schema_version": "safepay-quote-request-v2", "proposal_id": "DAO-PROP-6CB25C", "resource_id": "risk-report:test"},
    )
    assert_error_body(response, 503, "report_source_unavailable", True, "not_attempted")
    assert db_count(tmp_path / "safepay.db", "safepay_quote_issue_reservations", "state = 'failed'") == 1
    assert db_count(tmp_path / "safepay.db", "safepay_quotes") == 0

    # The failed attempt charged both fixed-window counters without refund:
    # only one admission remains in this window.
    state["fail"] = False
    issue_quote(client)
    response = client.post(
        "/x402/v2/quotes",
        json={"schema_version": "safepay-quote-request-v2", "proposal_id": "DAO-PROP-6CB25C", "resource_id": "risk-report:test"},
    )
    assert_error_body(response, 429, "quote_rate_limited", True, "not_attempted")


def test_inflight_reservation_cap(tmp_path, monkeypatch):
    install_secret_files(monkeypatch, tmp_path)
    caps = SafePayCaps(max_inflight_reservations=1)
    ledger = SafePayLedger(str(tmp_path / "ledger.db"), caps)
    ledger.preflight_reservation(client_key="k1", proposal_id="DAO-1", resource_id="r", now=START)
    with pytest.raises(QuoteCapacityExhausted):
        ledger.preflight_reservation(client_key="k2", proposal_id="DAO-1", resource_id="r", now=START)


def test_rate_limited_preflight_does_not_charge_counters(tmp_path, monkeypatch):
    caps = SafePayCaps(per_client_limit=1)
    ledger = SafePayLedger(str(tmp_path / "ledger.db"), caps)
    ledger.preflight_reservation(client_key="k1", proposal_id="DAO-1", resource_id="r", now=START)
    with pytest.raises(QuoteRateLimited):
        ledger.preflight_reservation(client_key="k1", proposal_id="DAO-1", resource_id="r", now=START)
    conn = sqlite3.connect(str(tmp_path / "ledger.db"))
    try:
        window = (START // 60) * 60
        row = conn.execute(
            "SELECT count FROM safepay_quote_rate_limits WHERE scope='client' AND client_key='k1' AND window_start=?",
            (window,),
        ).fetchone()
        global_row = conn.execute(
            "SELECT count FROM safepay_quote_rate_limits WHERE scope='global' AND client_key='global' AND window_start=?",
            (window,),
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == 1
    assert global_row[0] == 1


def test_outstanding_quote_cap_503(tmp_path, monkeypatch):
    caps = SafePayCaps(max_outstanding_quotes=1)
    app = build_app(tmp_path, monkeypatch, caps=caps)
    client = TestClient(app)
    issue_quote(client)
    response = client.post(
        "/x402/v2/quotes",
        json={"schema_version": "safepay-quote-request-v2", "proposal_id": "DAO-PROP-6CB25C", "resource_id": "risk-report:test"},
    )
    assert_error_body(response, 503, "quote_capacity_exhausted", True, "not_attempted")


def test_retained_unconsumed_cap_includes_expired(tmp_path, monkeypatch):
    clock = FakeClock()
    caps = SafePayCaps(max_retained_unconsumed_quotes=1)
    app = build_app(tmp_path, monkeypatch, caps=caps, clock=clock)
    client = TestClient(app)
    issue_quote(client)
    clock.advance(901)  # expired, unconsumed, still retained (far below the 86400s GC threshold)
    response = client.post(
        "/x402/v2/quotes",
        json={"schema_version": "safepay-quote-request-v2", "proposal_id": "DAO-PROP-6CB25C", "resource_id": "risk-report:test"},
    )
    assert_error_body(response, 503, "quote_capacity_exhausted", True, "not_attempted")


def test_report_content_addressing_stores_bytes_once(tmp_path, monkeypatch):
    app = build_app(tmp_path, monkeypatch)
    client = TestClient(app)
    first = issue_quote(client)["quote"]
    second = issue_quote(client)["quote"]
    assert first["report_hash"] == second["report_hash"]
    assert db_count(tmp_path / "safepay.db", "safepay_reports") == 1


def test_report_hash_conflict_fails_closed(tmp_path, monkeypatch):
    app = build_app(tmp_path, monkeypatch)
    client = TestClient(app)
    quote = issue_quote(client)["quote"]
    # Corrupt the stored content-addressed row so its bytes no longer match its key.
    conn = sqlite3.connect(str(tmp_path / "safepay.db"))
    try:
        conn.execute(
            "UPDATE safepay_reports SET report_bytes = ?, decoded_length = ? WHERE report_hash = ?",
            (b'{"tampered":true}', len(b'{"tampered":true}'), quote["report_hash"]),
        )
        conn.commit()
    finally:
        conn.close()
    response = client.post(
        "/x402/v2/quotes",
        json={"schema_version": "safepay-quote-request-v2", "proposal_id": "DAO-PROP-6CB25C", "resource_id": "risk-report:test"},
    )
    assert_error_body(response, 503, "provider_unavailable", True, "not_attempted")
    assert db_count(tmp_path / "safepay.db", "safepay_quotes") == 1


def test_report_row_and_total_byte_caps(tmp_path, monkeypatch):
    def sized_source(proposal_id: str, resource_id: str) -> bytes:
        return json.dumps({"resource": resource_id}).encode("ascii")

    caps = SafePayCaps(max_report_rows=1)
    app = build_app(tmp_path, monkeypatch, caps=caps, report_source=sized_source)
    client = TestClient(app)
    issue_quote(client, resource_id="resource-a")
    response = client.post(
        "/x402/v2/quotes",
        json={"schema_version": "safepay-quote-request-v2", "proposal_id": "DAO-PROP-6CB25C", "resource_id": "resource-b"},
    )
    assert_error_body(response, 503, "quote_capacity_exhausted", True, "not_attempted")

    first_len = len(sized_source("DAO-PROP-6CB25C", "resource-a"))
    caps_bytes = SafePayCaps(max_report_total_decoded_bytes=first_len + 3)
    app2 = build_app(tmp_path, monkeypatch, caps=caps_bytes, report_source=sized_source, ledger_path=str(tmp_path / "bytes.db"))
    client2 = TestClient(app2)
    issue_quote(client2, resource_id="resource-a")
    response = client2.post(
        "/x402/v2/quotes",
        json={"schema_version": "safepay-quote-request-v2", "proposal_id": "DAO-PROP-6CB25C", "resource_id": "resource-b"},
    )
    assert_error_body(response, 503, "quote_capacity_exhausted", True, "not_attempted")


# ------------------------------------------------------------- redemption core


def _issued_and_observed(tmp_path, monkeypatch, **app_kwargs):
    clock = app_kwargs.pop("clock", FakeClock())
    observer = app_kwargs.pop("observer", FakeObserver())
    app = build_app(tmp_path, monkeypatch, clock=clock, observer=observer, **app_kwargs)
    client = TestClient(app)
    quote = issue_quote(client)["quote"]
    payment_hash = "11" * 32
    observer.by_hash[payment_hash] = make_observation(quote, payment_hash)
    return app, client, quote, payment_hash, observer, clock


def test_first_consumption_success_shape(tmp_path, monkeypatch):
    app, client, quote, payment_hash, observer, clock = _issued_and_observed(tmp_path, monkeypatch)
    response = redeem(client, quote, payment_hash)
    assert response.status_code == 200, response.text
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Concordia-SafePay-Version"] == "safepay-v2"
    body = response.json()
    assert list(body) == ["schema_version", "fulfillment", "delivery"]
    assert body["schema_version"] == "safepay-v2"
    assert body["delivery"] == {"replay_disposition": "first_consumption"}
    fulfillment = body["fulfillment"]
    assert list(fulfillment) == [
        "quote",
        "payment_observation",
        "consumption",
        "report",
        "binding_checks",
        "observed_at",
        "response_hash",
    ]
    assert fulfillment["quote"] == quote
    observation = fulfillment["payment_observation"]
    assert "native_transfer_count" not in observation
    assert observation["transfer_id"] == quote["correlation_id"]
    consumption = fulfillment["consumption"]
    assert list(consumption) == [
        "network",
        "payment_hash",
        "quote_id",
        "resource_id",
        "quote_hash",
        "response_hash",
        "consumed_at",
    ]
    assert consumption["payment_hash"] == payment_hash
    assert consumption["response_hash"] == fulfillment["response_hash"]
    report = fulfillment["report"]
    assert list(report) == [
        "report_version",
        "proposal_id",
        "resource_id",
        "correlation_id",
        "media_type",
        "content_base64",
        "report_hash",
    ]
    import base64 as _base64

    decoded = _base64.b64decode(report["content_base64"], validate=True)
    assert hashlib.sha256(decoded).hexdigest() == quote["report_hash"]
    assert report["media_type"] == "application/json"
    assert all(fulfillment["binding_checks"].values())
    assert set(fulfillment["binding_checks"]) == {
        "network_exact",
        "payment_finalized",
        "payment_execution_success",
        "single_transfer_exact",
        "payee_exact",
        "amount_exact",
        "transfer_id_exact",
        "proposal_exact",
        "resource_exact",
        "correlation_exact",
        "report_version_exact",
        "report_hash_exact",
        "quote_hash_recomputed",
    }


def test_sp03_same_binding_idempotent_replay(tmp_path, monkeypatch):
    app, client, quote, payment_hash, observer, clock = _issued_and_observed(tmp_path, monkeypatch)
    first = redeem(client, quote, payment_hash)
    assert first.status_code == 200
    assert first.json()["delivery"]["replay_disposition"] == "first_consumption"
    assert observer.calls == 1

    second = redeem(client, quote, payment_hash)
    assert second.status_code == 200
    body = second.json()
    assert body["delivery"]["replay_disposition"] == "idempotent_replay"
    # Identical immutable fulfillment and response hash; only delivery differs.
    assert body["fulfillment"] == first.json()["fulfillment"]
    assert body["fulfillment"]["response_hash"] == first.json()["fulfillment"]["response_hash"]
    # The stored idempotent result needs no fresh chain call and no second consumption.
    assert observer.calls == 1
    assert db_count(tmp_path / "safepay.db", "payment_consumptions") == 1


def test_sp02_restart_persistence(tmp_path, monkeypatch):
    clock = FakeClock()
    observer = FakeObserver()
    app, client, quote, payment_hash, observer, clock = _issued_and_observed(
        tmp_path, monkeypatch, clock=clock, observer=observer
    )
    first = redeem(client, quote, payment_hash).json()

    # Dispose the app; reopen the same ledger file with a fresh instance.
    observer2 = FakeObserver()
    observer2.by_hash[payment_hash] = make_observation(quote, payment_hash)
    app2 = build_app(tmp_path, monkeypatch, clock=clock, observer=observer2)
    client2 = TestClient(app2)
    replay = redeem(client2, quote, payment_hash)
    assert replay.status_code == 200
    body = replay.json()
    assert body["delivery"]["replay_disposition"] == "idempotent_replay"
    assert body["fulfillment"] == first["fulfillment"]
    assert body["fulfillment"]["consumption"]["consumed_at"] == first["fulfillment"]["consumption"]["consumed_at"]
    assert body["fulfillment"]["response_hash"] == first["fulfillment"]["response_hash"]
    assert observer2.calls == 0
    assert db_count(tmp_path / "safepay.db", "payment_consumptions") == 1


def test_sp04_cross_binding_terminal_409(tmp_path, monkeypatch):
    clock = FakeClock()
    observer = FakeObserver()
    app = build_app(tmp_path, monkeypatch, clock=clock, observer=observer)
    client = TestClient(app)
    quote_a = issue_quote(client, resource_id="resource-a")["quote"]
    quote_b = issue_quote(client, resource_id="resource-b")["quote"]
    payment_hash = "22" * 32
    observer.by_hash[payment_hash] = make_observation(quote_a, payment_hash)

    assert redeem(client, quote_a, payment_hash).status_code == 200
    calls_after_first = observer.calls
    response = redeem(client, quote_b, payment_hash)
    assert_error_body(response, 409, "payment_already_consumed_for_other_binding", False, "cross_binding_rejected")
    # Terminal cross-binding rejection needs no fresh chain call and writes no row.
    assert observer.calls == calls_after_first
    assert db_count(tmp_path / "safepay.db", "payment_consumptions") == 1


async def test_sp04_helper_never_retries_409(monkeypatch):
    monkeypatch.setenv("X402_MAX_ATTEMPTS", "4")
    monkeypatch.setenv("X402_RETRY_DELAY_SECONDS", "0")
    requests_seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests_seen.append(request)
        return httpx.Response(409, json={"error": "cross_binding"})

    result = await redeem_provider_x402_with_retry(
        resource="resource-a",
        payment_header="33" * 32,
        provider_url="https://provider.invalid/x402/risk-report",
        transport=httpx.MockTransport(handler),
    )
    assert len(requests_seen) == 1
    assert result["status"] == "duplicate_conflict"
    assert result["terminal"] is True


def test_sp01_concurrent_redemption_exactly_one_winner(tmp_path, monkeypatch):
    app, client, quote, payment_hash, observer, clock = _issued_and_observed(tmp_path, monkeypatch)
    ledger = SafePayLedger(str(tmp_path / "safepay.db"), SafePayCaps())
    quote_row = ledger.load_quote(quote["quote_id"])
    observation = make_observation(quote, payment_hash)
    observation.pop("native_transfer_count")
    report_object = {
        "report_version": quote["report_version"],
        "proposal_id": quote["proposal_id"],
        "resource_id": quote["resource_id"],
        "correlation_id": quote["correlation_id"],
        "media_type": "application/json",
        "content_base64": "e30=",
        "report_hash": quote["report_hash"],
    }
    binding_checks = {
        name: True
        for name in (
            "network_exact",
            "payment_finalized",
            "payment_execution_success",
            "single_transfer_exact",
            "payee_exact",
            "amount_exact",
            "transfer_id_exact",
            "proposal_exact",
            "resource_exact",
            "correlation_exact",
            "report_version_exact",
            "report_hash_exact",
            "quote_hash_recomputed",
        )
    }
    results: list[tuple[dict, str]] = []
    errors: list[Exception] = []
    barrier = threading.Barrier(8)

    def worker() -> None:
        try:
            barrier.wait()
            results.append(
                ledger.claim_consumption(
                    quote_row=quote_row,
                    payment_hash=payment_hash,
                    payment_observation=observation,
                    report_object=report_object,
                    binding_checks=binding_checks,
                    observed_at=observation["observed_at"],
                    now=START + 10,
                )
            )
        except Exception as exc:  # pragma: no cover - failure surface
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors
    dispositions = [disposition for _, disposition in results]
    assert dispositions.count("first_consumption") == 1
    assert dispositions.count("idempotent_replay") == 7
    assert db_count(tmp_path / "safepay.db", "payment_consumptions", "network = ? AND payment_hash = ?", (SAFEPAY_V2_NETWORK, payment_hash)) == 1
    fulfillments = [json.dumps(fulfillment, sort_keys=True) for fulfillment, _ in results]
    assert len(set(fulfillments)) == 1


def test_expired_quote_410_before_observation(tmp_path, monkeypatch):
    app, client, quote, payment_hash, observer, clock = _issued_and_observed(tmp_path, monkeypatch)
    clock.advance(900)
    response = redeem(client, quote, payment_hash)
    assert_error_body(response, 410, "quote_expired", False, "not_attempted")
    assert observer.calls == 0
    assert db_count(tmp_path / "safepay.db", "payment_consumptions") == 0


def test_consumed_before_expiry_keeps_stored_response_after_expiry(tmp_path, monkeypatch):
    app, client, quote, payment_hash, observer, clock = _issued_and_observed(tmp_path, monkeypatch)
    first = redeem(client, quote, payment_hash)
    assert first.status_code == 200
    clock.advance(5000)
    replay = redeem(client, quote, payment_hash)
    assert replay.status_code == 200
    assert replay.json()["delivery"]["replay_disposition"] == "idempotent_replay"
    assert replay.json()["fulfillment"] == first.json()["fulfillment"]
    assert observer.calls == 1


def test_404_quote_not_issued_without_payment_lookup(tmp_path, monkeypatch):
    app, client, quote, payment_hash, observer, clock = _issued_and_observed(tmp_path, monkeypatch)
    # A caller-computed, internally consistent but UNISSUED quote is rejected.
    quote_id = str(uuid.uuid4())
    nonce = b"\x07" * 32
    correlation = safepay_v2_correlation_id(quote_id, "DAO-PROP-6CB25C", "risk-report:test", nonce)
    forged = dict(quote)
    forged["quote_id"] = quote_id
    forged["quote_nonce"] = nonce.hex()
    forged["correlation_id"] = str(correlation)
    forged["quote_hash"] = safepay_v2_quote_hash(
        quote_id=quote_id,
        proposal_id=forged["proposal_id"],
        resource_id=forged["resource_id"],
        network=forged["network"],
        payee_account_hash=forged["payee_account_hash"],
        amount_motes=forged["amount_motes"],
        correlation_id=correlation,
        report_version=forged["report_version"],
        report_hash=forged["report_hash"],
        expires_at=forged["expires_at"],
        quote_nonce=nonce,
    )
    response = redeem(client, forged, payment_hash)
    assert_error_body(response, 404, "quote_not_issued", False, "not_attempted")
    assert observer.calls == 0


def test_422_quote_binding_invalid(tmp_path, monkeypatch):
    app, client, quote, payment_hash, observer, clock = _issued_and_observed(tmp_path, monkeypatch)
    # Tampered amount with a consistently recomputed hash: still 422, because
    # the persisted row is authoritative.
    tampered = dict(quote)
    tampered["amount_motes"] = "9999999999"
    tampered["quote_hash"] = safepay_v2_quote_hash(
        quote_id=tampered["quote_id"],
        proposal_id=tampered["proposal_id"],
        resource_id=tampered["resource_id"],
        network=tampered["network"],
        payee_account_hash=tampered["payee_account_hash"],
        amount_motes=tampered["amount_motes"],
        correlation_id=int(tampered["correlation_id"]),
        report_version=tampered["report_version"],
        report_hash=tampered["report_hash"],
        expires_at=tampered["expires_at"],
        quote_nonce=bytes.fromhex(tampered["quote_nonce"]),
    )
    response = redeem(client, tampered, payment_hash)
    assert_error_body(response, 422, "quote_binding_invalid", False, "not_attempted")

    # Naive tamper without recomputing the hash: identical terminal 422.
    naive = dict(quote)
    naive["expires_at"] = quote["expires_at"] + 1
    response = redeem(client, naive, payment_hash)
    assert_error_body(response, 422, "quote_binding_invalid", False, "not_attempted")
    assert observer.calls == 0


def test_alias_network_rejected_before_ledger_lookup(tmp_path, monkeypatch):
    app, client, quote, payment_hash, observer, clock = _issued_and_observed(tmp_path, monkeypatch)
    alias = dict(quote)
    alias["network"] = "casper-testnet"
    response = redeem(client, alias, payment_hash)
    assert_error_body(response, 400, "invalid_request", False, "not_attempted")
    assert observer.calls == 0


def test_simulated_lag_switch_is_param_only_and_defaults_off(tmp_path, monkeypatch):
    clock = FakeClock()
    observer = FakeObserver()
    app = build_app(
        tmp_path, monkeypatch, clock=clock, observer=observer, simulated_lag_attempts=2
    )
    client = TestClient(app)
    quote = issue_quote(client)["quote"]
    payment_hash = "44" * 32
    observer.by_hash[payment_hash] = make_observation(quote, payment_hash)
    for _ in range(2):
        response = redeem(client, quote, payment_hash)
        assert_error_body(response, 425, "payment_not_finalized", True, "verification_pending")
    assert observer.calls == 0
    assert redeem(client, quote, payment_hash).status_code == 200
    # Default OFF is exercised by every other redemption test in this module
    # (no env switch exists for the v2 path).


def test_v2_endpoints_answer_503_when_ledger_unavailable(tmp_path, monkeypatch):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    app = build_app(tmp_path, monkeypatch, ledger_path=str(blocker / "safepay.db"))
    client = TestClient(app)
    response = client.post(
        "/x402/v2/quotes",
        json={"schema_version": "safepay-quote-request-v2", "proposal_id": "DAO-PROP-6CB25C", "resource_id": "x"},
    )
    assert_error_body(response, 503, "provider_unavailable", True, "not_attempted")


# ------------------------------------------------- startup and proxy identity


def test_short_or_missing_secrets_fail_startup(tmp_path, monkeypatch):
    short = tmp_path / "short_secret"
    short.write_bytes(b"tooshort")
    good = tmp_path / "good_secret"
    good.write_bytes(b"g" * 48)
    monkeypatch.setenv("SAFEPAY_PROXY_SECRET_FILE", str(short))
    monkeypatch.setenv("SAFEPAY_CLIENT_KEY_HMAC_SECRET_FILE", str(good))
    with pytest.raises(RuntimeError):
        create_app(ledger_path=str(tmp_path / "db.sqlite"))

    monkeypatch.setenv("SAFEPAY_PROXY_SECRET_FILE", str(tmp_path / "does-not-exist"))
    with pytest.raises(RuntimeError):
        create_app(ledger_path=str(tmp_path / "db.sqlite"))

    # Outside the repository test convention, entirely unset secrets fail startup.
    monkeypatch.delenv("SAFEPAY_PROXY_SECRET_FILE", raising=False)
    monkeypatch.delenv("SAFEPAY_CLIENT_KEY_HMAC_SECRET_FILE", raising=False)
    monkeypatch.delenv("CONCORDIA_TEST_MODE", raising=False)
    with pytest.raises(RuntimeError):
        create_app(ledger_path=str(tmp_path / "db.sqlite"))


def test_invalid_trusted_proxy_cidrs_fail_startup(tmp_path, monkeypatch):
    install_secret_files(monkeypatch, tmp_path)
    monkeypatch.setenv("SAFEPAY_TRUSTED_PROXY_CIDRS", "not-a-cidr")
    with pytest.raises(RuntimeError):
        create_app(ledger_path=str(tmp_path / "db.sqlite"))
    monkeypatch.delenv("SAFEPAY_TRUSTED_PROXY_CIDRS", raising=False)


@pytest.mark.parametrize("raw", [None, "", " ", ",", " , "])
def test_provider_requires_nonempty_proxy_cidrs_outside_explicit_test_mode(
    tmp_path,
    monkeypatch,
    raw,
):
    install_secret_files(monkeypatch, tmp_path)
    monkeypatch.delenv("CONCORDIA_TEST_MODE", raising=False)
    if raw is None:
        monkeypatch.delenv("SAFEPAY_TRUSTED_PROXY_CIDRS", raising=False)
    else:
        monkeypatch.setenv("SAFEPAY_TRUSTED_PROXY_CIDRS", raw)
    with pytest.raises(
        RuntimeError,
        match="SAFEPAY_TRUSTED_PROXY_CIDRS requires at least one valid CIDR",
    ):
        create_app(ledger_path=str(tmp_path / "db.sqlite"))


def test_provider_accepts_multiple_proxy_cidrs_outside_test_mode(
    tmp_path,
    monkeypatch,
):
    install_secret_files(monkeypatch, tmp_path)
    monkeypatch.delenv("CONCORDIA_TEST_MODE", raising=False)
    monkeypatch.setenv(
        "SAFEPAY_TRUSTED_PROXY_CIDRS",
        "10.1.2.3/8, 2001:db8::1/64",
    )
    app = create_app(
        ledger_path=str(tmp_path / "db.sqlite"),
        payee_account_hash=PAYEE,
        amount_motes=AMOUNT,
    )
    assert app.title == "Concordia Risk Oracle Provider"


def test_proxy_identity_trust_and_normalization():
    import ipaddress

    secret = b"s" * 32
    cidrs = [ipaddress.ip_network("10.0.0.0/8")]

    # Untrusted socket peer: forwarded headers are ignored entirely.
    assert (
        resolve_safepay_client_ip("203.0.113.9", "198.51.100.7", "s" * 32, cidrs, secret)
        == "203.0.113.9"
    )
    # Trusted peer + exact attestation: the forwarded client IP is used.
    assert (
        resolve_safepay_client_ip("10.1.2.3", "198.51.100.7", "s" * 32, cidrs, secret)
        == "198.51.100.7"
    )
    # Trusted peer, wrong attestation: fall back to the socket peer.
    assert (
        resolve_safepay_client_ip("10.1.2.3", "198.51.100.7", "wrong", cidrs, secret)
        == "10.1.2.3"
    )
    # No trusted proxies configured: headers never trusted.
    assert resolve_safepay_client_ip("10.1.2.3", "198.51.100.7", "s" * 32, [], secret) == "10.1.2.3"
    # IPv4-mapped IPv6 collapses to IPv4; IPv6 uses lowercase compressed form.
    assert _normalize_ip_text("::ffff:192.0.2.1") == "192.0.2.1"
    assert _normalize_ip_text("2001:0DB8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"
    # Zone identifiers and invalid values are rejected.
    assert _normalize_ip_text("fe80::1%eth0") is None
    assert _normalize_ip_text("not-an-ip") is None
    # Unparseable socket peer falls back to the raw peer string, headers ignored.
    assert (
        resolve_safepay_client_ip("testclient", "198.51.100.7", "s" * 32, cidrs, secret)
        == "testclient"
    )


@pytest.mark.parametrize("raw", [b'{"value":1.0}', b'{"value":1e9999}'])
def test_provider_v2_rejects_float_json_before_business_logic(
    tmp_path,
    monkeypatch,
    raw,
):
    app = build_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        response = client.post(
            "/x402/v2/quotes",
            content=raw,
            headers={"Content-Type": "application/json"},
        )
    assert_error_body(response, 400, "invalid_request", False, "not_attempted")


@pytest.mark.parametrize("path", ["/x402/v2/quotes", "/x402/v2/redemptions"])
def test_provider_v2_rejects_oversized_public_request_before_business_logic(
    tmp_path,
    monkeypatch,
    path,
):
    observer = FakeObserver()
    app = build_app(tmp_path, monkeypatch, observer=observer)
    with TestClient(app) as client:
        response = client.post(
            path,
            content=b"{" + b"x" * SAFEPAY_V2_MAX_PUBLIC_REQUEST_BYTES,
            headers={"Content-Type": "application/json"},
        )
    assert_error_body(response, 400, "invalid_request", False, "not_attempted")
    assert observer.calls == 0


def _provider_request_with_messages(
    *,
    content_length: int | None,
    chunks: list[bytes],
) -> tuple[Request, list[int]]:
    headers = []
    if content_length is not None:
        headers.append((b"content-length", str(content_length).encode("ascii")))
    messages = [
        {
            "type": "http.request",
            "body": chunk,
            "more_body": index < len(chunks) - 1,
        }
        for index, chunk in enumerate(chunks)
    ]
    receive_calls: list[int] = []

    async def receive() -> dict:
        receive_calls.append(1)
        if messages:
            return messages.pop(0)
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/x402/v2/redemptions",
        "raw_path": b"/x402/v2/redemptions",
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 443),
    }
    return Request(scope, receive), receive_calls


async def test_provider_content_length_over_limit_rejects_without_receiving_body() -> None:
    request, receive_calls = _provider_request_with_messages(
        content_length=SAFEPAY_V2_MAX_PUBLIC_REQUEST_BYTES + 1,
        chunks=[b"must-not-be-read"],
    )

    assert await provider_app._read_safepay_v2_request_body(request) is None
    assert receive_calls == []


@pytest.mark.parametrize(
    "content_length",
    [None, 8],
    ids=["chunked-without-length", "lying-content-length"],
)
async def test_provider_streaming_body_cap_stops_at_first_oversized_chunk(
    content_length: int | None,
) -> None:
    request, receive_calls = _provider_request_with_messages(
        content_length=content_length,
        chunks=[b"a" * 40_000, b"b" * 30_000, b"must-not-be-read"],
    )

    assert await provider_app._read_safepay_v2_request_body(request) is None
    assert len(receive_calls) == 2


def _provider_proxy_headers(client_ip: str, **extra: str) -> dict[str, str]:
    return {
        "X-Concordia-Client-IP": client_ip,
        "X-Concordia-SafePay-Proxy": "p" * 48,
        **extra,
    }


def _issue_quote_with_headers(
    client: TestClient,
    *,
    resource_id: str,
    headers: dict[str, str],
) -> dict:
    response = client.post(
        "/x402/v2/quotes",
        json={
            "schema_version": "safepay-quote-request-v2",
            "proposal_id": "DAO-PROP-6CB25C",
            "resource_id": resource_id,
        },
        headers=headers,
    )
    assert response.status_code == 402, response.text
    return response.json()["quote"]


def _redeem_with_headers(
    client: TestClient,
    quote: dict,
    payment_hash: str,
    headers: dict[str, str],
):
    return client.post(
        "/x402/v2/redemptions",
        json={
            "schema_version": "safepay-redemption-v2",
            "quote": quote,
            "payment_hash": payment_hash,
        },
        headers=headers,
    )


def _redemption_admission(
    clock: FakeClock,
    *,
    per_client_limit: int,
    global_limit: int,
) -> SafePayRedemptionAdmission:
    return SafePayRedemptionAdmission(
        SafePayRedemptionAdmissionCaps(
            per_client_limit=per_client_limit,
            global_limit=global_limit,
            window_seconds=60,
            max_client_buckets=16,
        ),
        clock=clock,
    )


def test_provider_redemption_admission_isolates_clients_and_preserves_idempotent_replay(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("SAFEPAY_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    clock = FakeClock()
    observer = FakeObserver()
    admission = _redemption_admission(clock, per_client_limit=1, global_limit=10)
    app = build_app(
        tmp_path,
        monkeypatch,
        clock=clock,
        observer=observer,
        redemption_admission=admission,
    )
    client = TestClient(app, client=("10.1.2.3", 40001))
    headers_a = _provider_proxy_headers("198.51.100.10")
    headers_b = _provider_proxy_headers("198.51.100.20")

    quote_a1 = _issue_quote_with_headers(client, resource_id="resource-a1", headers=headers_a)
    quote_a2 = _issue_quote_with_headers(client, resource_id="resource-a2", headers=headers_a)
    quote_b = _issue_quote_with_headers(client, resource_id="resource-b", headers=headers_b)
    hash_a1, hash_a2, hash_b = "a1" * 32, "a2" * 32, "b1" * 32
    observer.by_hash[hash_a1] = make_observation(quote_a1, hash_a1)
    observer.by_hash[hash_a2] = make_observation(quote_a2, hash_a2)
    observer.by_hash[hash_b] = make_observation(quote_b, hash_b)

    first = _redeem_with_headers(client, quote_a1, hash_a1, headers_a)
    assert first.status_code == 200
    assert observer.calls == 1

    # Stored exact retries remain cheap and available even after this client's
    # slow-path budget is exhausted.
    replay = _redeem_with_headers(client, quote_a1, hash_a1, headers_a)
    assert replay.status_code == 200
    assert replay.json()["delivery"]["replay_disposition"] == "idempotent_replay"
    assert observer.calls == 1

    limited = _redeem_with_headers(client, quote_a2, hash_a2, headers_a)
    assert_error_body(
        limited, 503, "provider_unavailable", True, "verification_pending"
    )
    assert observer.calls == 1

    # A distinct attested client retains its own allowance.
    accepted_b = _redeem_with_headers(client, quote_b, hash_b, headers_b)
    assert accepted_b.status_code == 200
    assert observer.calls == 2


def test_provider_redemption_admission_global_limit_blocks_without_observation(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("SAFEPAY_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    clock = FakeClock()
    observer = FakeObserver()
    admission = _redemption_admission(clock, per_client_limit=10, global_limit=1)
    app = build_app(
        tmp_path,
        monkeypatch,
        clock=clock,
        observer=observer,
        redemption_admission=admission,
    )
    client = TestClient(app, client=("10.1.2.3", 40001))
    headers_a = _provider_proxy_headers("198.51.100.10")
    headers_b = _provider_proxy_headers("198.51.100.20")
    quote_a = _issue_quote_with_headers(client, resource_id="global-a", headers=headers_a)
    quote_b = _issue_quote_with_headers(client, resource_id="global-b", headers=headers_b)
    hash_a, hash_b = "c1" * 32, "c2" * 32
    observer.by_hash[hash_a] = make_observation(quote_a, hash_a)
    observer.by_hash[hash_b] = make_observation(quote_b, hash_b)

    assert _redeem_with_headers(client, quote_a, hash_a, headers_a).status_code == 200
    assert observer.calls == 1
    limited = _redeem_with_headers(client, quote_b, hash_b, headers_b)
    assert_error_body(
        limited, 503, "provider_unavailable", True, "verification_pending"
    )
    assert observer.calls == 1


def test_provider_redemption_admission_cannot_be_bypassed_by_caller_headers(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("SAFEPAY_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    clock = FakeClock()
    observer = FakeObserver()
    admission = _redemption_admission(clock, per_client_limit=1, global_limit=10)
    app = build_app(
        tmp_path,
        monkeypatch,
        clock=clock,
        observer=observer,
        redemption_admission=admission,
    )
    client = TestClient(app, client=("10.1.2.3", 40001))
    identity = "198.51.100.10"
    first_headers = _provider_proxy_headers(
        identity,
        Authorization="Bearer caller-one",
        **{"X-Forwarded-For": "203.0.113.1"},
    )
    second_headers = _provider_proxy_headers(
        identity,
        Authorization="Basic caller-two",
        **{"X-Forwarded-For": "203.0.113.99"},
    )
    quote_a = _issue_quote_with_headers(client, resource_id="headers-a", headers=first_headers)
    quote_b = _issue_quote_with_headers(client, resource_id="headers-b", headers=second_headers)
    hash_a, hash_b = "d1" * 32, "d2" * 32
    observer.by_hash[hash_a] = make_observation(quote_a, hash_a)
    observer.by_hash[hash_b] = make_observation(quote_b, hash_b)

    assert _redeem_with_headers(client, quote_a, hash_a, first_headers).status_code == 200
    assert observer.calls == 1
    limited = _redeem_with_headers(client, quote_b, hash_b, second_headers)
    assert_error_body(
        limited, 503, "provider_unavailable", True, "verification_pending"
    )
    assert observer.calls == 1

    # Without the Caddy attestation, caller-supplied client-IP values are
    # ignored. Varying those values cannot mint new admission identities.
    bad_attestation_a = {
        "X-Concordia-Client-IP": "192.0.2.11",
        "X-Concordia-SafePay-Proxy": "wrong",
        "Authorization": "Bearer caller-three",
    }
    bad_attestation_b = {
        "X-Concordia-Client-IP": "192.0.2.99",
        "Authorization": "Bearer caller-four",
    }
    quote_c = _issue_quote_with_headers(
        client, resource_id="headers-c", headers=bad_attestation_a
    )
    quote_d = _issue_quote_with_headers(
        client, resource_id="headers-d", headers=bad_attestation_b
    )
    hash_c, hash_d = "d3" * 32, "d4" * 32
    observer.by_hash[hash_c] = make_observation(quote_c, hash_c)
    observer.by_hash[hash_d] = make_observation(quote_d, hash_d)
    assert (
        _redeem_with_headers(
            client, quote_c, hash_c, bad_attestation_a
        ).status_code
        == 200
    )
    assert observer.calls == 2
    limited_spoof = _redeem_with_headers(
        client, quote_d, hash_d, bad_attestation_b
    )
    assert_error_body(
        limited_spoof, 503, "provider_unavailable", True, "verification_pending"
    )
    assert observer.calls == 2


def test_provider_redemption_admission_bucket_table_is_bounded_and_fails_closed(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("SAFEPAY_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    clock = FakeClock()
    observer = FakeObserver()
    admission = SafePayRedemptionAdmission(
        SafePayRedemptionAdmissionCaps(
            per_client_limit=10,
            global_limit=10,
            window_seconds=60,
            max_client_buckets=1,
        ),
        clock=clock,
    )
    app = build_app(
        tmp_path,
        monkeypatch,
        clock=clock,
        observer=observer,
        redemption_admission=admission,
    )
    client = TestClient(app, client=("10.1.2.3", 40001))
    headers_a = _provider_proxy_headers("198.51.100.10")
    headers_b = _provider_proxy_headers("198.51.100.20")
    quote_a = _issue_quote_with_headers(client, resource_id="bounded-a", headers=headers_a)
    quote_b = _issue_quote_with_headers(client, resource_id="bounded-b", headers=headers_b)
    hash_a, hash_b = "e1" * 32, "e2" * 32
    observer.by_hash[hash_a] = make_observation(quote_a, hash_a)
    observer.by_hash[hash_b] = make_observation(quote_b, hash_b)

    assert _redeem_with_headers(client, quote_a, hash_a, headers_a).status_code == 200
    limited = _redeem_with_headers(client, quote_b, hash_b, headers_b)
    assert_error_body(
        limited, 503, "provider_unavailable", True, "verification_pending"
    )
    assert observer.calls == 1


def test_provider_v2_amount_never_falls_back_to_legacy_payment_amount(
    tmp_path,
    monkeypatch,
):
    install_secret_files(monkeypatch, tmp_path)
    monkeypatch.setenv("SAFEPAY_TRUSTED_PROXY_CIDRS", "127.0.0.0/8")
    monkeypatch.setenv("SAFEPAY_PAYEE_ACCOUNT_HASH", PAYEE)
    monkeypatch.delenv("SAFEPAY_AMOUNT_MOTES", raising=False)
    monkeypatch.setenv("X402_PAYMENT_AMOUNT", AMOUNT)
    app = create_app(
        ledger_path=str(tmp_path / "db.sqlite"),
        clock=FakeClock(),
        chain_observer=FakeObserver(),
    )
    with TestClient(app) as client:
        response = client.post(
            "/x402/v2/quotes",
            json={
                "schema_version": "safepay-quote-request-v2",
                "proposal_id": "DAO-PROP-AMOUNT",
                "resource_id": "report:DAO-PROP-AMOUNT",
            },
        )
    assert_error_body(
        response, 503, "provider_unavailable", True, "not_attempted"
    )


def test_only_hmac_client_keys_are_persisted(tmp_path, monkeypatch):
    app = build_app(tmp_path, monkeypatch)
    client = TestClient(app)
    issue_quote(client)
    conn = sqlite3.connect(str(tmp_path / "safepay.db"))
    try:
        keys = [
            row[0]
            for row in conn.execute(
                "SELECT client_key FROM safepay_quote_rate_limits WHERE scope = 'client'"
            )
        ] + [
            row[0]
            for row in conn.execute("SELECT client_key FROM safepay_quote_issue_reservations")
        ]
    finally:
        conn.close()
    assert keys
    for key in keys:
        assert len(key) == 64 and set(key) <= set("0123456789abcdef")
        assert key != "testclient"
