"""SafePay v2 exact chain-verifier tests (WP2, SP-05..SP-14) and golden vectors.

The correlation-id and quote-hash vectors are hand-computed inline with
hashlib against the frozen G1 encodings, cross-checking the implementation in
shared/x402_payments.py. Every chain observation is injected; no test touches
the network.
"""
from __future__ import annotations

import hashlib
import sqlite3
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from shared.x402_payments import (
    SAFEPAY_V2_FULFILLMENT_SEPARATOR,
    SAFEPAY_V2_NETWORK,
    SAFEPAY_V2_OBSERVATION_FIELDS,
    SAFEPAY_V2_QUOTE_HASH_SEPARATOR,
    SAFEPAY_V2_QUOTE_SEPARATOR,
    SafePayObserverUnavailable,
    _extract_transfer_proof_status,
    evaluate_safepay_v2_observation,
    observe_safepay_v2_payment,
    redeem_provider_x402_with_retry,
    safepay_v2_body_digest,
    safepay_v2_correlation_id,
    safepay_v2_error_body,
    safepay_v2_quote_hash,
    safepay_v2_response_hash,
    settle_x402_payment_with_retry,
    verify_casper_transfer_payment_with_retry,
)
from x402_provider.app import create_app
from x402_provider.ledger import SafePayCaps, SafePayLedger

from test_safepay_ledger import (
    AMOUNT,
    PAYEE,
    START,
    FakeClock,
    FakeObserver,
    assert_error_body,
    build_app,
    db_count,
    install_secret_files,
    issue_quote,
    make_observation,
    redeem,
)


# ----------------------------------------------------------- golden vectors


def test_frozen_domain_separators_match_the_g1_table():
    assert SAFEPAY_V2_QUOTE_SEPARATOR == b"CONCORDIA_SAFEPAY_QUOTE_V2\x00"
    assert len(SAFEPAY_V2_QUOTE_SEPARATOR) == 27
    assert SAFEPAY_V2_QUOTE_SEPARATOR.hex() == "434f4e434f524449415f534146455041595f51554f54455f563200"
    assert SAFEPAY_V2_QUOTE_HASH_SEPARATOR == b"CONCORDIA_SAFEPAY_QUOTE_HASH_V2\x00"
    assert len(SAFEPAY_V2_QUOTE_HASH_SEPARATOR) == 32
    assert (
        SAFEPAY_V2_QUOTE_HASH_SEPARATOR.hex()
        == "434f4e434f524449415f534146455041595f51554f54455f484153485f563200"
    )
    assert (
        SAFEPAY_V2_FULFILLMENT_SEPARATOR.hex()
        == "434f4e434f524449415f534146455041595f46554c46494c4c4d454e545f563200"
    )
    for separator in (
        SAFEPAY_V2_QUOTE_SEPARATOR,
        SAFEPAY_V2_QUOTE_HASH_SEPARATOR,
        SAFEPAY_V2_FULFILLMENT_SEPARATOR,
    ):
        assert separator.endswith(b"\x00")
        assert not separator.endswith(b"\\0")


def _lp(value: str) -> bytes:
    raw = value.encode("ascii")
    return len(raw).to_bytes(4, "big") + raw


def test_golden_correlation_id_vector_hand_computed():
    quote_id = "2f9c5f4e-3d1a-4b2c-8e5f-6a7b8c9d0e1f"
    proposal_id = "DAO-PROP-6CB25C"
    resource_id = "risk-report:test"
    quote_nonce = bytes(range(32))

    preimage = (
        b"CONCORDIA_SAFEPAY_QUOTE_V2\x00"
        + _lp(quote_id)
        + _lp(proposal_id)
        + _lp(resource_id)
        + quote_nonce
    )
    digest = hashlib.blake2b(preimage, digest_size=32).digest()
    expected = int.from_bytes(digest[:8], "big")

    assert safepay_v2_correlation_id(quote_id, proposal_id, resource_id, quote_nonce) == expected
    # BLAKE2b-256 means digest_size=32, never a truncated 64-byte digest.
    truncated_512 = int.from_bytes(hashlib.blake2b(preimage).digest()[:8], "big")
    assert expected != truncated_512


def test_golden_quote_hash_vector_hand_computed():
    quote_id = "2f9c5f4e-3d1a-4b2c-8e5f-6a7b8c9d0e1f"
    proposal_id = "DAO-PROP-6CB25C"
    resource_id = "risk-report:test"
    quote_nonce = bytes(range(32))
    report_hash = hashlib.sha256(b'{"ok":true}').hexdigest()
    correlation_id = safepay_v2_correlation_id(quote_id, proposal_id, resource_id, quote_nonce)
    expires_at = 1_800_000_900

    preimage = (
        b"CONCORDIA_SAFEPAY_QUOTE_HASH_V2\x00"
        + _lp(quote_id)
        + _lp(proposal_id)
        + _lp(resource_id)
        + _lp("casper:casper-test")
        + bytes.fromhex(PAYEE)
        + int(AMOUNT).to_bytes(64, "big")  # amount_motes as U512 fixed 64 big-endian
        + correlation_id.to_bytes(8, "big")
        + _lp("safepay-report-v2")
        + bytes.fromhex(report_hash)
        + expires_at.to_bytes(8, "big")
        + quote_nonce
    )
    expected = hashlib.blake2b(preimage, digest_size=32).hexdigest()

    assert (
        safepay_v2_quote_hash(
            quote_id=quote_id,
            proposal_id=proposal_id,
            resource_id=resource_id,
            network="casper:casper-test",
            payee_account_hash=PAYEE,
            amount_motes=AMOUNT,
            correlation_id=correlation_id,
            report_version="safepay-report-v2",
            report_hash=report_hash,
            expires_at=expires_at,
            quote_nonce=quote_nonce,
        )
        == expected
    )


def test_golden_response_hash_vector_hand_computed():
    quote_hash = "aa" * 32
    payment_hash = "bb" * 32
    block_hash = "cc" * 32
    report_hash = "dd" * 32
    preimage = (
        b"CONCORDIA_SAFEPAY_FULFILLMENT_V2\x00"
        + bytes.fromhex(quote_hash)
        + bytes.fromhex(payment_hash)
        + bytes.fromhex(block_hash)
        + (8590556).to_bytes(8, "big")
        + bytes.fromhex(report_hash)
        + (1_800_000_500).to_bytes(8, "big")
    )
    assert (
        safepay_v2_response_hash(
            quote_hash=quote_hash,
            payment_hash=payment_hash,
            block_hash=block_hash,
            block_height=8590556,
            report_hash=report_hash,
            consumed_at=1_800_000_500,
        )
        == hashlib.sha256(preimage).hexdigest()
    )


def test_issued_quote_derivations_recompute_exactly(tmp_path, monkeypatch):
    app = build_app(tmp_path, monkeypatch)
    client = TestClient(app)
    quote = issue_quote(client)["quote"]
    nonce = bytes.fromhex(quote["quote_nonce"])
    assert quote["correlation_id"] == str(
        safepay_v2_correlation_id(quote["quote_id"], quote["proposal_id"], quote["resource_id"], nonce)
    )
    assert quote["quote_hash"] == safepay_v2_quote_hash(
        quote_id=quote["quote_id"],
        proposal_id=quote["proposal_id"],
        resource_id=quote["resource_id"],
        network=quote["network"],
        payee_account_hash=quote["payee_account_hash"],
        amount_motes=quote["amount_motes"],
        correlation_id=int(quote["correlation_id"]),
        report_version=quote["report_version"],
        report_hash=quote["report_hash"],
        expires_at=quote["expires_at"],
        quote_nonce=nonce,
    )


# ---------------------------------------------------- SP-05/06: transfer id


def _issued(tmp_path, monkeypatch):
    clock = FakeClock()
    observer = FakeObserver()
    app = build_app(tmp_path, monkeypatch, clock=clock, observer=observer)
    client = TestClient(app)
    quote = issue_quote(client)["quote"]
    return client, quote, observer, tmp_path / "safepay.db"


@pytest.mark.parametrize("bad_transfer_id", ["12345", None])
def test_sp05_sp06_wrong_or_missing_transfer_id_refused(tmp_path, monkeypatch, bad_transfer_id):
    client, quote, observer, db = _issued(tmp_path, monkeypatch)
    payment_hash = "55" * 32
    observer.by_hash[payment_hash] = make_observation(quote, payment_hash, transfer_id=bad_transfer_id)
    response = redeem(client, quote, payment_hash)
    assert_error_body(response, 422, "payment_binding_invalid", False, "verification_rejected")
    assert db_count(db, "payment_consumptions") == 0


def test_transfer_id_checks_are_exact_in_evaluator():
    quote = {
        "network": SAFEPAY_V2_NETWORK,
        "payee_account_hash": PAYEE,
        "amount_motes": AMOUNT,
        "correlation_id": "123456789",
    }
    observation = {
        "network": SAFEPAY_V2_NETWORK,
        "finality_status": "finalized",
        "execution_status": "processed",
        "execution_error": None,
        "to_account_hash": PAYEE,
        "amount_motes": AMOUNT,
        "transfer_id": "123456789",
    }
    assert evaluate_safepay_v2_observation(quote, observation)["transfer_id_exact"] is True
    assert (
        evaluate_safepay_v2_observation(quote, {**observation, "transfer_id": "1234567890"})[
            "transfer_id_exact"
        ]
        is False
    )
    assert (
        evaluate_safepay_v2_observation(quote, {**observation, "transfer_id": None})["transfer_id_exact"]
        is False
    )


# ------------------------------------------------------- SP-07: payee exact


def test_sp07_substring_attack_payee_refused(tmp_path, monkeypatch):
    client, quote, observer, db = _issued(tmp_path, monkeypatch)
    payment_hash = "66" * 32
    # A value that merely CONTAINS the payee hash must never match.
    observer.by_hash[payment_hash] = make_observation(
        quote, payment_hash, to_account_hash="ff" + quote["payee_account_hash"]
    )
    response = redeem(client, quote, payment_hash)
    assert_error_body(response, 422, "payment_binding_invalid", False, "verification_rejected")
    assert db_count(db, "payment_consumptions") == 0


def test_sp07_wrong_payee_refused(tmp_path, monkeypatch):
    client, quote, observer, db = _issued(tmp_path, monkeypatch)
    payment_hash = "77" * 32
    observer.by_hash[payment_hash] = make_observation(quote, payment_hash, to_account_hash="99" * 32)
    response = redeem(client, quote, payment_hash)
    assert_error_body(response, 422, "payment_binding_invalid", False, "verification_rejected")
    assert db_count(db, "payment_consumptions") == 0


def test_sp07_evaluator_rejects_substring_and_exactness_holds():
    quote = {"network": SAFEPAY_V2_NETWORK, "payee_account_hash": PAYEE, "amount_motes": AMOUNT, "correlation_id": "1"}
    base = {
        "network": SAFEPAY_V2_NETWORK,
        "finality_status": "finalized",
        "execution_status": "processed",
        "execution_error": None,
        "amount_motes": AMOUNT,
        "transfer_id": "1",
    }
    assert evaluate_safepay_v2_observation(quote, {**base, "to_account_hash": PAYEE})["payee_exact"] is True
    for attack in ("ff" + PAYEE, PAYEE[:-2], PAYEE.upper(), "account-hash-" + PAYEE):
        assert (
            evaluate_safepay_v2_observation(quote, {**base, "to_account_hash": attack})["payee_exact"] is False
        ), attack


def test_sp07_legacy_parser_refuses_substring_payee(monkeypatch):
    monkeypatch.setenv("X402_PAYMENT_AMOUNT", "1000000")
    monkeypatch.setenv("X402_PAYMENT_ADDRESS", "account-hash-" + ("a" * 64))
    payload = {
        "status": "processed",
        "error_message": None,
        "transfers": [
            {
                # Contains the payee hash as a substring but is not equal to it.
                "target_account_hash": "account-hash-" + ("a" * 64) + "ff",
                "amount": "1000000",
            }
        ],
    }
    assert _extract_transfer_proof_status(payload)["valid"] is False


# -------------------------------------------------------- SP-08: amount exact


@pytest.mark.parametrize("amount", [str(int(AMOUNT) + 1), str(int(AMOUNT) - 1)])
def test_sp08_wrong_amount_refused_including_overpay(tmp_path, monkeypatch, amount):
    client, quote, observer, db = _issued(tmp_path, monkeypatch)
    payment_hash = "88" * 32
    observer.by_hash[payment_hash] = make_observation(quote, payment_hash, amount_motes=amount)
    response = redeem(client, quote, payment_hash)
    assert_error_body(response, 422, "payment_binding_invalid", False, "verification_rejected")
    assert db_count(db, "payment_consumptions") == 0


def test_sp08_legacy_parser_refuses_overpay(monkeypatch):
    monkeypatch.setenv("X402_PAYMENT_AMOUNT", "1000000")
    monkeypatch.setenv("X402_PAYMENT_ADDRESS", "account-hash-" + ("a" * 64))
    payload = {
        "status": "processed",
        "error_message": None,
        "transfers": [{"target_account_hash": "account-hash-" + ("a" * 64), "amount": "1200000"}],
    }
    result = _extract_transfer_proof_status(payload)
    assert result["valid"] is False
    exact = dict(payload)
    exact["transfers"] = [{"target_account_hash": "account-hash-" + ("a" * 64), "amount": "1000000"}]
    assert _extract_transfer_proof_status(exact)["valid"] is True


# ------------------------------------------- SP-09/SP-10: pending and failure


def test_sp09_pending_transfer_not_consumed(tmp_path, monkeypatch):
    client, quote, observer, db = _issued(tmp_path, monkeypatch)
    payment_hash = "99" * 32
    observer.by_hash[payment_hash] = make_observation(
        quote, payment_hash, execution_status="pending", finality_status="unknown"
    )
    response = redeem(client, quote, payment_hash)
    assert_error_body(response, 425, "payment_not_finalized", True, "verification_pending")
    assert db_count(db, "payment_consumptions") == 0

    observer.by_hash[payment_hash] = make_observation(quote, payment_hash, finality_status="not_finalized")
    response = redeem(client, quote, payment_hash)
    assert_error_body(response, 425, "payment_not_finalized", True, "verification_pending")
    assert db_count(db, "payment_consumptions") == 0


def test_sp10_execution_failure_refused(tmp_path, monkeypatch):
    client, quote, observer, db = _issued(tmp_path, monkeypatch)
    payment_hash = "aa" * 32
    observer.by_hash[payment_hash] = make_observation(
        quote, payment_hash, execution_status="failed", execution_error="User error: 1"
    )
    response = redeem(client, quote, payment_hash)
    assert_error_body(response, 422, "payment_binding_invalid", False, "verification_rejected")

    observer.by_hash[payment_hash] = make_observation(quote, payment_hash, execution_error="out of gas")
    response = redeem(client, quote, payment_hash)
    assert_error_body(response, 422, "payment_binding_invalid", False, "verification_rejected")
    assert db_count(db, "payment_consumptions") == 0


def test_multiple_native_transfers_refused(tmp_path, monkeypatch):
    client, quote, observer, db = _issued(tmp_path, monkeypatch)
    payment_hash = "bb" * 32
    observer.by_hash[payment_hash] = make_observation(quote, payment_hash, native_transfer_count=2)
    response = redeem(client, quote, payment_hash)
    assert_error_body(response, 422, "payment_binding_invalid", False, "verification_rejected")
    assert db_count(db, "payment_consumptions") == 0


@pytest.mark.parametrize("forged_count", [None, True, "1", 1.0])
def test_missing_or_mistyped_transfer_count_fails_closed(tmp_path, monkeypatch, forged_count):
    """The raw transfer count is a mandatory strict int in the observation contract.

    An observer omitting it, or supplying bool True / "1" / 1.0 (all of which
    int() would coerce to a passing 1), has produced no usable observation:
    the provider must fail closed as a retryable observer outage — it must
    never assume exactly one transfer, and must consume nothing.
    """
    client, quote, observer, db = _issued(tmp_path, monkeypatch)
    payment_hash = "bc" * 32
    observation = make_observation(quote, payment_hash)
    if forged_count is None:
        observation.pop("native_transfer_count")
    else:
        observation["native_transfer_count"] = forged_count
    observer.by_hash[payment_hash] = observation
    response = redeem(client, quote, payment_hash)
    assert_error_body(response, 503, "payment_observer_unavailable", True, "verification_pending")
    assert db_count(db, "payment_consumptions") == 0


# ------------------------------------- SP-11/SP-14: gateway-side helper truth


async def test_sp11_malformed_provider_response_safe_fail(monkeypatch):
    monkeypatch.setenv("X402_SETTLEMENT_MODE", "real")
    monkeypatch.setenv("X402_PROVIDER_URL", "https://provider.invalid/x402/risk-report")
    monkeypatch.setenv("X402_MAX_ATTEMPTS", "2")
    monkeypatch.setenv("X402_RETRY_DELAY_SECONDS", "0")

    def non_json_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>definitely not json</html>")

    result = await settle_x402_payment_with_retry(
        resource="resource-a",
        payment_header="12" * 32,
        transport=httpx.MockTransport(non_json_handler),
    )
    assert result["status"] == "invalid_provider_response"
    assert result["status"] != "settled"

    def missing_fields_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "shape"})

    result = await settle_x402_payment_with_retry(
        resource="resource-a",
        payment_header="12" * 32,
        transport=httpx.MockTransport(missing_fields_handler),
    )
    assert result["status"] == "invalid_provider_response"
    assert result["status"] != "settled"


async def test_sp14_provider_unavailable_honest_state(monkeypatch):
    monkeypatch.setenv("X402_SETTLEMENT_MODE", "real")
    monkeypatch.setenv("X402_PROVIDER_URL", "https://provider.invalid/x402/risk-report")
    monkeypatch.setenv("X402_MAX_ATTEMPTS", "2")
    monkeypatch.setenv("X402_RETRY_DELAY_SECONDS", "0")

    def failing_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    result = await settle_x402_payment_with_retry(
        resource="resource-a",
        payment_header="34" * 32,
        transport=httpx.MockTransport(failing_handler),
    )
    assert result["status"] == "stranded_payment"
    assert result["mode"] == "real_provider"
    assert result["last_error"]
    assert result["status"] != "settled"


def test_sp14_observer_unavailable_maps_to_503(tmp_path, monkeypatch):
    client, quote, observer, db = _issued(tmp_path, monkeypatch)
    payment_hash = "cc" * 32
    observer.by_hash[payment_hash] = RuntimeError("indexer down")
    response = redeem(client, quote, payment_hash)
    assert_error_body(response, 503, "payment_observer_unavailable", True, "verification_pending")
    assert db_count(db, "payment_consumptions") == 0


async def test_idempotent_v2_body_surfaces_idempotent_replay(monkeypatch):
    monkeypatch.setenv("X402_MAX_ATTEMPTS", "1")
    monkeypatch.setenv("X402_RETRY_DELAY_SECONDS", "0")

    def idempotent_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "schema_version": "safepay-v2",
                "fulfillment": {"response_hash": "ab" * 32},
                "delivery": {"replay_disposition": "idempotent_replay"},
            },
        )

    result = await redeem_provider_x402_with_retry(
        resource="resource-a",
        payment_header="56" * 32,
        provider_url="https://provider.invalid/x402/v2/redemptions",
        transport=httpx.MockTransport(idempotent_handler),
    )
    assert result["status"] == "idempotent_replay"


# -------------------------------------------------- SP-12: report integrity


def test_sp12_report_hash_mismatch_refused(tmp_path, monkeypatch):
    client, quote, observer, db = _issued(tmp_path, monkeypatch)
    payment_hash = "dd" * 32
    observer.by_hash[payment_hash] = make_observation(quote, payment_hash)
    # Corrupt the persisted content-addressed bytes after issuance.
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            "UPDATE safepay_reports SET report_bytes = ?, decoded_length = ? WHERE report_hash = ?",
            (b'{"forged":true}', len(b'{"forged":true}'), quote["report_hash"]),
        )
        conn.commit()
    finally:
        conn.close()
    response = redeem(client, quote, payment_hash)
    assert_error_body(response, 503, "provider_unavailable", True, "verification_pending")
    # The consumption is never recorded against a report that no longer
    # matches the quote's report_hash.
    assert db_count(db, "payment_consumptions") == 0


# -------------------------------------- SP-13: forged artifact booleans ignored


def test_sp13_forged_artifact_booleans_ignored_by_evidence_summary(tmp_path, monkeypatch):
    install_path = str(tmp_path / "evidence.db")
    ledger = SafePayLedger(install_path, SafePayCaps())
    forged = {
        "duplicate_proof_rejected": True,
        "proof": {"valid": True},
        "handshake_verified": True,
        "status": "verified",
    }
    quote_id = str(uuid.uuid4())
    summary = ledger.summarize_quote_evidence(quote_id, forged)
    # Zero recorded observations: nothing is verified, whatever the artifact claims.
    assert summary["consumption_recorded"] is False
    assert summary["cross_binding_rejected_observed"] is False
    assert summary["duplicate_proof_rejected"] is False
    assert summary["source"] == "ledger_rows"


def test_sp13_evidence_summary_derives_only_from_ledger_rows(tmp_path, monkeypatch):
    clock = FakeClock()
    observer = FakeObserver()
    app = build_app(tmp_path, monkeypatch, clock=clock, observer=observer)
    client = TestClient(app)
    quote_a = issue_quote(client, resource_id="resource-a")["quote"]
    quote_b = issue_quote(client, resource_id="resource-b")["quote"]
    payment_hash = "ee" * 32
    observer.by_hash[payment_hash] = make_observation(quote_a, payment_hash)

    ledger = SafePayLedger(str(tmp_path / "safepay.db"), SafePayCaps())
    # Before any redemption: nothing proven, even with a forged claim attached.
    assert ledger.summarize_quote_evidence(quote_a["quote_id"], {"duplicate_proof_rejected": True})[
        "duplicate_proof_rejected"
    ] is False

    assert redeem(client, quote_a, payment_hash).status_code == 200
    # Consumption alone still does not prove duplicate rejection.
    assert ledger.summarize_quote_evidence(quote_a["quote_id"])["consumption_recorded"] is True
    assert ledger.summarize_quote_evidence(quote_a["quote_id"])["duplicate_proof_rejected"] is False

    # A recorded terminal 409 cross-binding observation completes the derivation.
    assert redeem(client, quote_b, payment_hash).status_code == 409
    summary = ledger.summarize_quote_evidence(quote_a["quote_id"])
    assert summary["cross_binding_rejected_observed"] is True
    assert summary["duplicate_proof_rejected"] is True


# ------------------------------------- 409 removed from every retryable set


async def test_facilitator_verify_409_is_terminal(monkeypatch):
    monkeypatch.setenv("X402_SETTLEMENT_MODE", "real")
    monkeypatch.delenv("X402_PROVIDER_URL", raising=False)
    monkeypatch.delenv("X402_PAYMENT_ADDRESS", raising=False)
    monkeypatch.delenv("X402_PAYMENT_ACCOUNT_HASH", raising=False)
    monkeypatch.delenv("X402_PAYMENT_RECEIVER_PUBLIC_KEY", raising=False)
    monkeypatch.setenv("X402_FACILITATOR_URL", "https://facilitator.invalid")
    monkeypatch.setenv("X402_MAX_ATTEMPTS", "4")
    monkeypatch.setenv("X402_RETRY_DELAY_SECONDS", "0")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(409, json={"error": "conflict"})

    result = await settle_x402_payment_with_retry(
        resource="resource-a",
        payment_header="not-a-deploy-hash",
        transport=httpx.MockTransport(handler),
    )
    assert len(seen) == 1
    assert result["status"] == "duplicate_conflict"
    assert result["terminal"] is True


async def test_cspr_live_409_is_terminal(monkeypatch):
    monkeypatch.setenv("X402_PAYMENT_AMOUNT", "1000000")
    monkeypatch.setenv("X402_PAYMENT_ADDRESS", "account-hash-" + ("a" * 64))
    monkeypatch.setenv("X402_MAX_ATTEMPTS", "4")
    monkeypatch.setenv("X402_RETRY_DELAY_SECONDS", "0")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(409, json={"error": "conflict"})

    result = await verify_casper_transfer_payment_with_retry(
        resource="resource-a",
        payment_header="ab" * 32,
        transport=httpx.MockTransport(handler),
    )
    assert len(seen) == 1
    assert result["status"] == "duplicate_conflict"
    assert result["terminal"] is True


# -------------------------------------------------- legacy parser exactness


def test_legacy_parser_requires_transfer_id_when_resource_bound(monkeypatch):
    from shared.x402_payments import x402_payment_correlation_id

    monkeypatch.setenv("X402_PAYMENT_AMOUNT", "1000000")
    monkeypatch.setenv("X402_PAYMENT_ADDRESS", "account-hash-" + ("a" * 64))
    resource = "concordia-governance-report:DAO-PROP-6CB25C"
    expected_id = x402_payment_correlation_id(resource)
    record = {"target_account_hash": "account-hash-" + ("a" * 64), "amount": "1000000"}

    missing = _extract_transfer_proof_status(
        {"status": "processed", "error_message": None, "transfers": [dict(record)]}, resource=resource
    )
    assert missing["valid"] is False

    wrong = _extract_transfer_proof_status(
        {"status": "processed", "error_message": None, "transfers": [{**record, "id": expected_id + 1}]},
        resource=resource,
    )
    assert wrong["valid"] is False

    exact = _extract_transfer_proof_status(
        {"status": "processed", "error_message": None, "transfers": [{**record, "id": expected_id}]},
        resource=resource,
    )
    assert exact["valid"] is True
    assert exact["status"] == "settled"


def test_legacy_parser_requires_exactly_one_matching_transfer(monkeypatch):
    monkeypatch.setenv("X402_PAYMENT_AMOUNT", "1000000")
    monkeypatch.setenv("X402_PAYMENT_ADDRESS", "account-hash-" + ("a" * 64))
    record = {"target_account_hash": "account-hash-" + ("a" * 64), "amount": "1000000"}
    result = _extract_transfer_proof_status(
        {"status": "processed", "error_message": None, "transfers": [dict(record), dict(record)]}
    )
    assert result["valid"] is False


def test_legacy_risk_report_flow_still_serves_402_challenge(tmp_path, monkeypatch):
    app = build_app(tmp_path, monkeypatch)
    client = TestClient(app)
    monkeypatch.setenv("X402_PAYMENT_ADDRESS", "account-hash-" + ("a" * 64))
    monkeypatch.setenv("X402_PAYMENT_AMOUNT", "1000000")
    response = client.get("/x402/risk-report?proposal_id=DAO-PROP-6CB25C")
    assert response.status_code == 402
    assert response.headers["X-Payment-Resource"] == "concordia-governance-report:DAO-PROP-6CB25C"
    assert response.json()["provider"] == "concordia-risk-oracle-provider"


# =====================================================================
# WP2-1 / WP2-2 regressions: observe_safepay_v2_payment must parse the REAL
# CSPR.live response shape (including initiator_account_hash), bind exact deploy
# identity, network and exactly one RAW transfer, and NEVER convert a bare
# CSPR.live status=processed into finality. Finality is a defined, separate
# block observation. Every call is offline via httpx.MockTransport.
# =====================================================================

CSPR_BASE = "http://cspr.test"
BLOCK_HASH = "2b" * 32
BLOCK_HEIGHT = 8590556
SOURCE_HASH = "1a" * 32


def _cspr_transfer(quote: dict, **over) -> dict:
    """A native-transfer record shaped like a real CSPR.live transfer."""
    transfer = {
        "deploy_hash": over.get("deploy_hash", "dc" * 32),
        "block_hash": BLOCK_HASH,
        "initiator_account_hash": SOURCE_HASH,
        "from_purse": "uref-0000000000000000000000000000000000000000000000000000000000000000-007",
        "to_account_hash": quote["payee_account_hash"],
        "to_purse": "uref-1111111111111111111111111111111111111111111111111111111111111111-004",
        "amount": quote["amount_motes"],
        "transfer_id": int(quote["correlation_id"]),
        "timestamp": "2026-06-29T22:49:29Z",
    }
    for key in over.pop("_drop", ()):  # remove named fields (e.g. missing initiator)
        transfer.pop(key, None)
    transfer.update({k: v for k, v in over.items() if not k.startswith("_") and k != "deploy_hash"})
    return transfer


def _cspr_deploy_body(payment_hash: str, quote: dict, **over) -> dict:
    """A deploy-detail body shaped like a real CSPR.live /deploys/{hash} record."""
    transfers = over.get("transfers")
    if transfers is None:
        transfers = [_cspr_transfer(quote)]
    body = {
        "account_info": None,
        "deploy_hash": over.get("deploy_hash", payment_hash),
        "block_hash": over.get("block_hash", BLOCK_HASH),
        "block_height": over.get("block_height", BLOCK_HEIGHT),
        "caller_public_key": "01" + "aa" * 32,
        "caller_hash": SOURCE_HASH,
        "status": over.get("status", "processed"),
        "error_message": over.get("error_message", None),
        "execution_type_id": 2,
        "cost": "100000000",
        "payment_amount": "100000000",
        "refund_amount": "0",
        "consumed_gas": "100000000",
        "ft_token_actions": [],
        "nft_token_actions": [],
        "timestamp": "2026-06-29T22:49:29Z",
        "transfers": transfers,
    }
    return body


def _cspr_transport(
    payment_hash: str,
    quote: dict,
    *,
    finalized: bool = True,
    deploy_status: int = 200,
    deploy_body=None,
    deploy_payload=None,
    block_status: int = 200,
    block_body=None,
    deploy_raises: bool = False,
    block_raises: bool = False,
    deploy_text=None,
) -> httpx.MockTransport:
    body = deploy_body if deploy_body is not None else _cspr_deploy_body(payment_hash, quote)

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == f"/deploys/{payment_hash}":
            if deploy_raises:
                raise httpx.ConnectError("cspr.live unreachable")
            if deploy_text is not None:
                return httpx.Response(deploy_status, text=deploy_text)
            if deploy_status != 200:
                return httpx.Response(deploy_status, json={"error": "unavailable"})
            if deploy_payload is not None:  # full top-level JSON, no {"data": ...} wrapper
                return httpx.Response(200, json=deploy_payload)
            return httpx.Response(200, json={"data": body})
        if path.startswith("/blocks/"):
            if block_raises:
                raise httpx.ConnectError("cspr.live block endpoint unreachable")
            if not finalized:
                return httpx.Response(404, json={"error": "block_not_found"})
            if block_status != 200:
                return httpx.Response(block_status, json={"error": "unavailable"})
            confirmed = block_body if block_body is not None else {
                "block_hash": BLOCK_HASH,
                "block_height": BLOCK_HEIGHT,
                "era_id": 12345,
                "finality_signatures": 100,
            }
            return httpx.Response(200, json={"data": confirmed})
        return httpx.Response(404, json={"error": "unexpected_path"})

    return httpx.MockTransport(handler)


async def _observe(payment_hash: str, quote: dict, **transport_kwargs) -> dict:
    transport = _cspr_transport(payment_hash, quote, **transport_kwargs)
    return await observe_safepay_v2_payment(
        network=SAFEPAY_V2_NETWORK,
        payment_hash=payment_hash,
        transport=transport,
        base_url=CSPR_BASE,
    )


def _quote_terms() -> dict:
    """A minimal issued-quote stand-in for direct observer parsing tests."""
    quote_id = "2f9c5f4e-3d1a-4b2c-8e5f-6a7b8c9d0e1f"
    nonce = bytes(range(32))
    correlation = safepay_v2_correlation_id(quote_id, "DAO-PROP-6CB25C", "risk-report:test", nonce)
    return {
        "network": SAFEPAY_V2_NETWORK,
        "payee_account_hash": PAYEE,
        "amount_motes": AMOUNT,
        "correlation_id": str(correlation),
        "payment_hash": "dc" * 32,
    }


async def test_observer_parses_real_cspr_live_shape_and_finalizes():
    quote = _quote_terms()
    payment_hash = quote["payment_hash"]
    obs = await _observe(payment_hash, quote)
    # Exact deploy identity, network, block identity, and single-transfer binding.
    assert set(obs) == set(SAFEPAY_V2_OBSERVATION_FIELDS) | {"native_transfer_count"}
    assert obs["network"] == SAFEPAY_V2_NETWORK
    assert obs["payment_hash"] == payment_hash
    assert obs["block_hash"] == BLOCK_HASH
    assert obs["block_height"] == BLOCK_HEIGHT
    assert obs["execution_status"] == "processed"
    assert obs["finality_status"] == "finalized"
    assert obs["execution_error"] is None
    # initiator_account_hash is the bound source; to_account_hash the payee.
    assert obs["from_account_hash"] == SOURCE_HASH
    assert obs["to_account_hash"] == PAYEE
    assert obs["amount_motes"] == AMOUNT
    assert obs["transfer_id"] == quote["correlation_id"]
    assert obs["native_transfer_count"] == 1
    # RFC3339 UTC-Z observed_at.
    assert obs["observed_at"].endswith("Z")


async def test_observer_processed_without_finalized_block_is_not_final():
    # THE core WP2-2 regression: status=processed is NOT finality on its own.
    quote = _quote_terms()
    payment_hash = quote["payment_hash"]
    obs = await _observe(payment_hash, quote, finalized=False)
    assert obs["execution_status"] == "processed"
    assert obs["finality_status"] == "not_finalized"
    assert obs["finality_status"] != "finalized"


async def test_observer_binds_exact_deploy_identity_wrong_deploy_fails_closed():
    quote = _quote_terms()
    payment_hash = quote["payment_hash"]
    body = _cspr_deploy_body(payment_hash, quote, deploy_hash="ee" * 32)  # record claims a DIFFERENT deploy
    obs = await _observe(payment_hash, quote, deploy_body=body)
    # Never attribute a foreign deploy record to this payment hash.
    assert obs["finality_status"] != "finalized"
    assert obs["execution_status"] in {"pending", "unknown"}
    assert obs["native_transfer_count"] == 0


async def test_observer_pending_deploy_is_not_final():
    quote = _quote_terms()
    payment_hash = quote["payment_hash"]
    body = _cspr_deploy_body(payment_hash, quote, status="pending", transfers=[])
    obs = await _observe(payment_hash, quote, deploy_body=body)
    assert obs["execution_status"] in {"pending", "unknown"}
    assert obs["finality_status"] != "finalized"


async def test_observer_counts_raw_transfers_before_filtering():
    # One valid transfer PLUS an extra/malformed transfer must fail the exactly
    # one raw-transfer predicate. Raw count is taken before any filtering.
    quote = _quote_terms()
    payment_hash = quote["payment_hash"]
    valid = _cspr_transfer(quote)
    body = _cspr_deploy_body(payment_hash, quote, transfers=[valid, {"malformed": "extra"}])
    obs = await _observe(payment_hash, quote, deploy_body=body)
    assert obs["native_transfer_count"] == 2  # RAW length, not the filtered structured length

    body_two = _cspr_deploy_body(payment_hash, quote, transfers=[valid, _cspr_transfer(quote)])
    obs_two = await _observe(payment_hash, quote, deploy_body=body_two)
    assert obs_two["native_transfer_count"] == 2


async def test_observer_zero_transfers_is_not_attributable():
    quote = _quote_terms()
    payment_hash = quote["payment_hash"]
    body = _cspr_deploy_body(payment_hash, quote, transfers=[])
    obs = await _observe(payment_hash, quote, deploy_body=body)
    assert obs["native_transfer_count"] == 0
    assert obs["to_account_hash"] == ""


async def test_observer_missing_initiator_is_not_fabricated():
    quote = _quote_terms()
    payment_hash = quote["payment_hash"]
    transfer = _cspr_transfer(quote, _drop=("initiator_account_hash",))
    body = _cspr_deploy_body(payment_hash, quote, transfers=[transfer])
    obs = await _observe(payment_hash, quote, deploy_body=body)
    # No source field present anywhere -> empty, never invented.
    assert obs["from_account_hash"] == ""
    # The provider then rejects this observation on shape (see app-level test).


async def test_observer_initiator_account_hash_is_the_bound_source():
    quote = _quote_terms()
    payment_hash = quote["payment_hash"]
    other_source = "9c" * 32
    transfer = _cspr_transfer(quote, initiator_account_hash=other_source)
    body = _cspr_deploy_body(payment_hash, quote, transfers=[transfer])
    obs = await _observe(payment_hash, quote, deploy_body=body)
    assert obs["from_account_hash"] == other_source


async def test_observer_execution_error_reported_and_not_final():
    quote = _quote_terms()
    payment_hash = quote["payment_hash"]
    body = _cspr_deploy_body(payment_hash, quote, error_message="User error: 1")
    obs = await _observe(payment_hash, quote, deploy_body=body)
    assert obs["execution_error"] == "User error: 1"
    assert obs["finality_status"] != "finalized"


async def test_observer_malformed_and_missing_data_are_observer_unavailable():
    quote = _quote_terms()
    payment_hash = quote["payment_hash"]
    # Malformed (non-JSON) deploy body is an observer outage, never a verdict.
    with pytest.raises(SafePayObserverUnavailable):
        await _observe(payment_hash, quote, deploy_text="<html>not json</html>")
    # A response missing the "data" wrapper entirely cannot be observed.
    with pytest.raises(SafePayObserverUnavailable):
        await _observe(payment_hash, quote, deploy_payload={"errors": ["no data"]})
    # A non-200/non-404 deploy response is an observer outage, never a verdict.
    with pytest.raises(SafePayObserverUnavailable):
        await _observe(payment_hash, quote, deploy_status=500)
    # Transport failure is an outage.
    with pytest.raises(SafePayObserverUnavailable):
        await _observe(payment_hash, quote, deploy_raises=True)


async def test_observer_data_present_but_shapeless_fails_closed_not_settled():
    # A "data" object that lacks the requested deploy identity is not attributed
    # to this payment: honest non-final, never a fabricated settlement.
    quote = _quote_terms()
    payment_hash = quote["payment_hash"]
    obs = await _observe(payment_hash, quote, deploy_body={"unexpected": "shape"})
    assert obs["finality_status"] != "finalized"
    assert obs["execution_status"] in {"pending", "unknown"}


async def test_observer_404_deploy_is_pending_not_error():
    quote = _quote_terms()
    payment_hash = quote["payment_hash"]
    obs = await _observe(payment_hash, quote, deploy_status=404)
    assert obs["execution_status"] in {"pending", "unknown"}
    assert obs["finality_status"] != "finalized"


async def test_observer_extra_unknown_fields_are_ignored():
    quote = _quote_terms()
    payment_hash = quote["payment_hash"]
    body = _cspr_deploy_body(payment_hash, quote)
    body["totally_unexpected_top_level"] = {"nested": [1, 2, 3]}
    body["transfers"][0]["unexpected_transfer_field"] = "ignore-me"
    obs = await _observe(payment_hash, quote, deploy_body=body)
    assert obs["finality_status"] == "finalized"
    assert obs["to_account_hash"] == PAYEE


async def test_observer_block_lookup_outage_fails_closed():
    quote = _quote_terms()
    payment_hash = quote["payment_hash"]
    with pytest.raises(SafePayObserverUnavailable):
        await _observe(payment_hash, quote, block_raises=True)


async def test_observer_block_identity_mismatch_is_not_final():
    quote = _quote_terms()
    payment_hash = quote["payment_hash"]
    obs = await _observe(
        payment_hash, quote, block_body={"block_hash": "77" * 32, "block_height": 1}
    )
    assert obs["finality_status"] != "finalized"


async def test_observer_non_canonical_network_raises():
    quote = _quote_terms()
    with pytest.raises(SafePayObserverUnavailable):
        await observe_safepay_v2_payment(
            network="casper-testnet", payment_hash=quote["payment_hash"]
        )


# ---- App-level end-to-end proof that processed!=settled through the REAL observer ----


def _wired_app(tmp_path, monkeypatch, transport, clock):
    install_secret_files(monkeypatch, tmp_path)

    async def real_observer(network: str, payment_hash: str) -> dict:
        return await observe_safepay_v2_payment(
            network=network, payment_hash=payment_hash, transport=transport, base_url=CSPR_BASE
        )

    return create_app(
        ledger_path=str(tmp_path / "safepay.db"),
        caps=SafePayCaps(),
        clock=clock,
        chain_observer=real_observer,
        payee_account_hash=PAYEE,
        amount_motes=AMOUNT,
    )


def test_app_real_observer_processed_but_unfinalized_returns_425_not_settled(tmp_path, monkeypatch):
    clock = FakeClock()
    install_secret_files(monkeypatch, tmp_path)
    seed = build_app(tmp_path, monkeypatch, clock=clock)
    quote = issue_quote(TestClient(seed))["quote"]
    payment_hash = "dc" * 32
    transport = _cspr_transport(payment_hash, quote, finalized=False)
    app = _wired_app(tmp_path, monkeypatch, transport, clock)
    response = redeem(TestClient(app), quote, payment_hash)
    # The OLD injected observer settled this; now it must not.
    assert_error_body(response, 425, "payment_not_finalized", True, "verification_pending")
    assert db_count(tmp_path / "safepay.db", "payment_consumptions") == 0


def test_app_real_observer_finalized_happy_path_settles(tmp_path, monkeypatch):
    clock = FakeClock()
    install_secret_files(monkeypatch, tmp_path)
    seed = build_app(tmp_path, monkeypatch, clock=clock)
    quote = issue_quote(TestClient(seed))["quote"]
    payment_hash = "dc" * 32
    transport = _cspr_transport(payment_hash, quote, finalized=True)
    app = _wired_app(tmp_path, monkeypatch, transport, clock)
    response = redeem(TestClient(app), quote, payment_hash)
    assert response.status_code == 200, response.text
    assert response.json()["delivery"]["replay_disposition"] == "first_consumption"
    assert db_count(tmp_path / "safepay.db", "payment_consumptions") == 1


def test_app_real_observer_missing_initiator_fails_closed(tmp_path, monkeypatch):
    clock = FakeClock()
    install_secret_files(monkeypatch, tmp_path)
    seed = build_app(tmp_path, monkeypatch, clock=clock)
    quote = issue_quote(TestClient(seed))["quote"]
    payment_hash = "dc" * 32
    body = _cspr_deploy_body(
        payment_hash, quote, transfers=[_cspr_transfer(quote, _drop=("initiator_account_hash",))]
    )
    transport = _cspr_transport(payment_hash, quote, deploy_body=body)
    app = _wired_app(tmp_path, monkeypatch, transport, clock)
    response = redeem(TestClient(app), quote, payment_hash)
    # An observation with no source account is shape-invalid -> fail closed, never settled.
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "payment_observer_unavailable"
    assert db_count(tmp_path / "safepay.db", "payment_consumptions") == 0


# =====================================================================
# WP2-3 regressions: summarize_quote_evidence must derive duplicate rejection
# from the ACTUAL observed 409 terminal result against a genuinely different
# quote/resource binding on the same (network, payment_hash), in chronological
# order after the canonical consumption -- never from a bare observation kind.
# =====================================================================


# Canonical digest of the exact frozen 409 cross-binding body the provider
# serves; every genuine cross_binding_rejected observation is bound to it.
CROSS_409_DIGEST = safepay_v2_body_digest(
    safepay_v2_error_body("payment_already_consumed_for_other_binding", False, "cross_binding_rejected")
)


def _consumed_quote(tmp_path, monkeypatch):
    clock = FakeClock()
    observer = FakeObserver()
    app = build_app(tmp_path, monkeypatch, clock=clock, observer=observer)
    client = TestClient(app)
    quote = issue_quote(client, resource_id="resource-a")["quote"]
    payment_hash = "e1" * 32
    observer.by_hash[payment_hash] = make_observation(quote, payment_hash)
    assert redeem(client, quote, payment_hash).status_code == 200
    ledger = SafePayLedger(str(tmp_path / "safepay.db"), SafePayCaps())
    consumption = ledger.find_consumption(SAFEPAY_V2_NETWORK, payment_hash)
    return ledger, quote, payment_hash, consumption["response_hash"]


def test_summary_true_only_for_genuine_different_binding_409(tmp_path, monkeypatch):
    ledger, quote, payment_hash, response_hash = _consumed_quote(tmp_path, monkeypatch)
    ledger.record_redemption_observation(
        kind="cross_binding_rejected",
        http_status=409,
        network=SAFEPAY_V2_NETWORK,
        payment_hash=payment_hash,
        quote_id="7f000000-0000-4000-8000-000000000002",
        resource_id="resource-b",
        now=START + 50,
        response_digest=CROSS_409_DIGEST,
        consumed_response_hash=response_hash,
    )
    summary = ledger.summarize_quote_evidence(quote["quote_id"])
    assert summary["consumption_recorded"] is True
    assert summary["cross_binding_rejected_observed"] is True
    assert summary["duplicate_proof_rejected"] is True


def test_summary_forged_direct_insert_row_is_insufficient(tmp_path, monkeypatch):
    """Codex re-review regression: a directly inserted
    kind='cross_binding_rejected', http_status=409 row must NOT be sufficient.
    The observation must be BOUND to the response actually served (canonical
    409-body digest) AND to the actually consumed fulfillment (its stored
    response_hash); every unbound/forged combination stays false.
    """
    ledger, quote, payment_hash, response_hash = _consumed_quote(tmp_path, monkeypatch)
    conn = sqlite3.connect(str(tmp_path / "safepay.db"))
    forged_rows = [
        # (quote_id suffix, response_digest, consumed_response_hash)
        ("7f000000-0000-4000-8000-00000000f001", "ab" * 32, "cd" * 32),  # fully unbound
        ("7f000000-0000-4000-8000-00000000f002", "ab" * 32, response_hash),  # copied hash, wrong digest
        ("7f000000-0000-4000-8000-00000000f003", CROSS_409_DIGEST, "cd" * 32),  # right digest, unbound hash
    ]
    for forged_quote_id, digest, consumed_hash in forged_rows:
        conn.execute(
            "INSERT INTO safepay_redemption_observations("
            "kind, http_status, network, payment_hash, quote_id, resource_id, observed_at, "
            "response_digest, consumed_response_hash) "
            "VALUES('cross_binding_rejected', 409, ?, ?, ?, 'resource-b', ?, ?, ?)",
            (SAFEPAY_V2_NETWORK, payment_hash, forged_quote_id, START + 50, digest, consumed_hash),
        )
    conn.commit()
    conn.close()
    summary = ledger.summarize_quote_evidence(quote["quote_id"])
    assert summary["consumption_recorded"] is True
    assert summary["cross_binding_rejected_observed"] is False
    assert summary["duplicate_proof_rejected"] is False
    # The rule remains achievable ONLY via a fully bound observation.
    ledger.record_redemption_observation(
        kind="cross_binding_rejected",
        http_status=409,
        network=SAFEPAY_V2_NETWORK,
        payment_hash=payment_hash,
        quote_id="7f000000-0000-4000-8000-00000000f004",
        resource_id="resource-b",
        now=START + 60,
        response_digest=CROSS_409_DIGEST,
        consumed_response_hash=response_hash,
    )
    summary = ledger.summarize_quote_evidence(quote["quote_id"])
    assert summary["duplicate_proof_rejected"] is True


def test_summary_false_for_non_409_http_status(tmp_path, monkeypatch):
    ledger, quote, payment_hash, response_hash = _consumed_quote(tmp_path, monkeypatch)
    # A "cross_binding_rejected" row whose ACTUAL observed HTTP result was 200.
    ledger.record_redemption_observation(
        kind="cross_binding_rejected",
        http_status=200,
        network=SAFEPAY_V2_NETWORK,
        payment_hash=payment_hash,
        quote_id="7f000000-0000-4000-8000-000000000002",
        resource_id="resource-b",
        now=START + 50,
        response_digest=CROSS_409_DIGEST,
        consumed_response_hash=response_hash,
    )
    summary = ledger.summarize_quote_evidence(quote["quote_id"])
    assert summary["cross_binding_rejected_observed"] is False
    assert summary["duplicate_proof_rejected"] is False


def test_summary_false_for_same_binding_observation(tmp_path, monkeypatch):
    ledger, quote, payment_hash, response_hash = _consumed_quote(tmp_path, monkeypatch)
    # Same quote AND same resource as the canonical consumption: not a genuinely
    # different binding, even at http 409.
    ledger.record_redemption_observation(
        kind="cross_binding_rejected",
        http_status=409,
        network=SAFEPAY_V2_NETWORK,
        payment_hash=payment_hash,
        quote_id=quote["quote_id"],
        resource_id="resource-a",
        now=START + 50,
        response_digest=CROSS_409_DIGEST,
        consumed_response_hash=response_hash,
    )
    summary = ledger.summarize_quote_evidence(quote["quote_id"])
    assert summary["cross_binding_rejected_observed"] is False
    assert summary["duplicate_proof_rejected"] is False


def test_summary_false_for_unrelated_payment_observation(tmp_path, monkeypatch):
    ledger, quote, payment_hash, response_hash = _consumed_quote(tmp_path, monkeypatch)
    # 409 against a DIFFERENT (network, payment_hash) than the canonical consumption.
    ledger.record_redemption_observation(
        kind="cross_binding_rejected",
        http_status=409,
        network=SAFEPAY_V2_NETWORK,
        payment_hash="ff" * 32,
        quote_id="7f000000-0000-4000-8000-000000000002",
        resource_id="resource-b",
        now=START + 50,
        response_digest=CROSS_409_DIGEST,
        consumed_response_hash=response_hash,
    )
    summary = ledger.summarize_quote_evidence(quote["quote_id"])
    assert summary["cross_binding_rejected_observed"] is False
    assert summary["duplicate_proof_rejected"] is False


def test_summary_false_when_409_precedes_consumption(tmp_path, monkeypatch):
    ledger, quote, payment_hash, response_hash = _consumed_quote(tmp_path, monkeypatch)
    # Chronology: a 409 observed BEFORE the canonical consumption cannot evidence
    # rejection of a duplicate of that consumption.
    ledger.record_redemption_observation(
        kind="cross_binding_rejected",
        http_status=409,
        network=SAFEPAY_V2_NETWORK,
        payment_hash=payment_hash,
        quote_id="7f000000-0000-4000-8000-000000000002",
        resource_id="resource-b",
        now=START - 100,
        response_digest=CROSS_409_DIGEST,
        consumed_response_hash=response_hash,
    )
    summary = ledger.summarize_quote_evidence(quote["quote_id"])
    assert summary["cross_binding_rejected_observed"] is False
    assert summary["duplicate_proof_rejected"] is False


def test_summary_idempotent_replay_does_not_imply_duplicate_rejected(tmp_path, monkeypatch):
    ledger, quote, payment_hash, response_hash = _consumed_quote(tmp_path, monkeypatch)
    ledger.record_redemption_observation(
        kind="idempotent_replay",
        http_status=200,
        network=SAFEPAY_V2_NETWORK,
        payment_hash=payment_hash,
        quote_id=quote["quote_id"],
        resource_id="resource-a",
        now=START + 50,
        response_digest=response_hash,
        consumed_response_hash=response_hash,
    )
    summary = ledger.summarize_quote_evidence(quote["quote_id"])
    assert summary["idempotent_replay_observed"] is True
    assert summary["cross_binding_rejected_observed"] is False
    assert summary["duplicate_proof_rejected"] is False


def test_summary_distinguishes_exact_replay_from_cross_binding(tmp_path, monkeypatch):
    # End-to-end through the app: an exact retry is idempotent (no second
    # consumption), and reuse under a different quote is a terminal 409. The
    # evidence must reflect both facts distinctly.
    clock = FakeClock()
    observer = FakeObserver()
    app = build_app(tmp_path, monkeypatch, clock=clock, observer=observer)
    client = TestClient(app)
    quote_a = issue_quote(client, resource_id="resource-a")["quote"]
    quote_b = issue_quote(client, resource_id="resource-b")["quote"]
    payment_hash = "e2" * 32
    observer.by_hash[payment_hash] = make_observation(quote_a, payment_hash)

    assert redeem(client, quote_a, payment_hash).status_code == 200
    assert redeem(client, quote_a, payment_hash).json()["delivery"]["replay_disposition"] == "idempotent_replay"
    assert db_count(tmp_path / "safepay.db", "payment_consumptions") == 1
    assert redeem(client, quote_b, payment_hash).status_code == 409

    ledger = SafePayLedger(str(tmp_path / "safepay.db"), SafePayCaps())
    summary = ledger.summarize_quote_evidence(quote_a["quote_id"])
    assert summary["consumption_recorded"] is True
    assert summary["idempotent_replay_observed"] is True
    assert summary["cross_binding_rejected_observed"] is True
    assert summary["duplicate_proof_rejected"] is True
