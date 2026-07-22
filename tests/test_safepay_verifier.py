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
    SAFEPAY_V2_QUOTE_HASH_SEPARATOR,
    SAFEPAY_V2_QUOTE_SEPARATOR,
    _extract_transfer_proof_status,
    evaluate_safepay_v2_observation,
    redeem_provider_x402_with_retry,
    safepay_v2_correlation_id,
    safepay_v2_quote_hash,
    safepay_v2_response_hash,
    settle_x402_payment_with_retry,
    verify_casper_transfer_payment_with_retry,
)
from x402_provider.ledger import SafePayCaps, SafePayLedger

from test_safepay_ledger import (
    AMOUNT,
    PAYEE,
    FakeClock,
    FakeObserver,
    assert_error_body,
    build_app,
    db_count,
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
