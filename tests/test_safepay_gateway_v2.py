from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

import gateway.app as gateway_app
import shared.x402_payments as safepay_module
from gateway.app import create_app
from gateway.rate_limit import SafePayAdmissionLimiter
from shared.x402_payments import (
    SAFEPAY_V2_BINDING_CHECK_FIELDS,
    SAFEPAY_V2_PROVIDER_ORIGIN,
    SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
    SAFEPAY_V2_REDEMPTION_REQUEST_SCHEMA,
    SAFEPAY_V2_REPORT_VERSION,
    SAFEPAY_V2_SCHEMA_VERSION,
    SAFEPAY_V2_WALLET_INTENT_REQUEST_SCHEMA,
    safepay_v2_account_hash_from_public_key,
    safepay_v2_correlation_id,
    safepay_v2_error_body,
    issue_safepay_v2_quote_capability,
    safepay_v2_quote_hash,
    safepay_v2_response_hash,
    validate_safepay_v2_gateway_quote,
    verify_safepay_v2_quote_capability,
)


RECEIVER_PUBLIC_KEY = "01" + ("11" * 32)
RECEIVER_ACCOUNT_HASH = (
    "33b261261c76ab5a249ae145461cadc722dc67ed59cf0e9c538b6c2b366ec463"
)
SIGNER_PUBLIC_KEY = "01" + ("22" * 32)
PROPOSAL_ID = "DAO-PROP-6CB25C"
RESOURCE_ID = "concordia-governance-report:DAO-PROP-6CB25C"
AMOUNT_MOTES = "1000000"
PAYMENT_HASH = "ab" * 32
BLOCK_HASH = "cd" * 32
REPORT_BYTES = b'{"risk":"bounded"}'
REPORT_HASH = hashlib.sha256(REPORT_BYTES).hexdigest()
QUOTE_NONCE = bytes.fromhex("ef" * 32)
QUOTE_ID = "12345678-1234-4abc-8def-1234567890ab"
CORRELATION_ID = str(
    safepay_v2_correlation_id(QUOTE_ID, PROPOSAL_ID, RESOURCE_ID, QUOTE_NONCE)
)
EXPIRES_AT = 2_000_000_000
QUOTE_CAPABILITY_SECRET = b"safepay-quote-capability-test-secret-32-bytes"
PROXY_SECRET = "safepay-proxy-test-secret-32-bytes"
V2_HEADERS = {
    "Cache-Control": "no-store",
    "X-Concordia-SafePay-Version": "safepay-v2",
}


def _quote(
    *,
    payee_account_hash: str = RECEIVER_ACCOUNT_HASH,
    amount_motes: str = AMOUNT_MOTES,
    network: str = "casper:casper-test",
    proposal_id: str = PROPOSAL_ID,
    resource_id: str = RESOURCE_ID,
    expires_at: int = EXPIRES_AT,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    frozen_correlation_id = correlation_id or str(
        safepay_v2_correlation_id(
            QUOTE_ID, proposal_id, resource_id, QUOTE_NONCE
        )
    )
    quote_hash = safepay_v2_quote_hash(
        quote_id=QUOTE_ID,
        proposal_id=proposal_id,
        resource_id=resource_id,
        network=network,
        payee_account_hash=payee_account_hash,
        amount_motes=amount_motes,
        correlation_id=int(frozen_correlation_id),
        report_version=SAFEPAY_V2_REPORT_VERSION,
        report_hash=REPORT_HASH,
        expires_at=expires_at,
        quote_nonce=QUOTE_NONCE,
    )
    return {
        "schema_version": SAFEPAY_V2_SCHEMA_VERSION,
        "quote_id": QUOTE_ID,
        "proposal_id": proposal_id,
        "resource_id": resource_id,
        "network": network,
        "payee_account_hash": payee_account_hash,
        "amount_motes": amount_motes,
        "correlation_id": frozen_correlation_id,
        "report_version": SAFEPAY_V2_REPORT_VERSION,
        "report_hash": REPORT_HASH,
        "expires_at": expires_at,
        "quote_nonce": QUOTE_NONCE.hex(),
        "quote_hash": quote_hash,
    }


def _quote_issue_body(quote: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SAFEPAY_V2_SCHEMA_VERSION,
        "error": {"code": "payment_required", "retryable": False},
        "quote": quote,
        "payment_requirements": {
            "network": quote["network"],
            "payee_account_hash": quote["payee_account_hash"],
            "amount_motes": quote["amount_motes"],
            "correlation_id": quote["correlation_id"],
            "expires_at": quote["expires_at"],
        },
    }


def _success_body(
    quote: dict[str, Any], *, disposition: str = "first_consumption"
) -> dict[str, Any]:
    consumed_at = 1_900_000_000
    response_hash = safepay_v2_response_hash(
        quote_hash=quote["quote_hash"],
        payment_hash=PAYMENT_HASH,
        block_hash=BLOCK_HASH,
        block_height=8_600_000,
        report_hash=quote["report_hash"],
        consumed_at=consumed_at,
    )
    return {
        "schema_version": SAFEPAY_V2_SCHEMA_VERSION,
        "fulfillment": {
            "quote": quote,
            "payment_observation": {
                "network": quote["network"],
                "payment_hash": PAYMENT_HASH,
                "block_hash": BLOCK_HASH,
                "block_height": 8_600_000,
                "execution_status": "processed",
                "finality_status": "finalized",
                "from_account_hash": "12" * 32,
                "to_account_hash": quote["payee_account_hash"],
                "amount_motes": quote["amount_motes"],
                "transfer_id": quote["correlation_id"],
                "execution_error": None,
                "observed_at": "2026-07-23T00:00:00Z",
            },
            "consumption": {
                "network": quote["network"],
                "payment_hash": PAYMENT_HASH,
                "quote_id": quote["quote_id"],
                "resource_id": quote["resource_id"],
                "quote_hash": quote["quote_hash"],
                "response_hash": response_hash,
                "consumed_at": consumed_at,
            },
            "report": {
                "report_version": quote["report_version"],
                "proposal_id": quote["proposal_id"],
                "resource_id": quote["resource_id"],
                "correlation_id": quote["correlation_id"],
                "media_type": "application/json",
                "content_base64": "eyJyaXNrIjoiYm91bmRlZCJ9",
                "report_hash": quote["report_hash"],
            },
            "binding_checks": {name: True for name in SAFEPAY_V2_BINDING_CHECK_FIELDS},
            "observed_at": "2026-07-23T00:00:00Z",
            "response_hash": response_hash,
        },
        "delivery": {"replay_disposition": disposition},
    }


def _provider_response(
    status_code: int, body: dict[str, Any], *, headers: dict[str, str] | None = None
) -> httpx.Response:
    return httpx.Response(
        status_code,
        content=json.dumps(body, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json", **(headers or V2_HEADERS)},
    )


@pytest.fixture(autouse=True)
def _gateway_safepay_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    quote_secret = tmp_path / "safepay_quote_token_secret"
    quote_secret.write_bytes(QUOTE_CAPABILITY_SECRET)
    quote_secret.chmod(0o600)
    proxy_secret = tmp_path / "safepay_proxy_secret"
    proxy_secret.write_text(PROXY_SECRET, encoding="utf-8")
    proxy_secret.chmod(0o600)
    monkeypatch.setenv("X402_PAYMENT_RECEIVER_PUBLIC_KEY", RECEIVER_PUBLIC_KEY)
    monkeypatch.setenv("SAFEPAY_AMOUNT_MOTES", AMOUNT_MOTES)
    monkeypatch.setenv("X402_PAYMENT_AMOUNT", AMOUNT_MOTES)
    monkeypatch.setenv("X402_MAX_ATTEMPTS", "3")
    monkeypatch.setenv("X402_RETRY_DELAY_SECONDS", "0")
    monkeypatch.setenv("SAFEPAY_QUOTE_TOKEN_SECRET_FILE", str(quote_secret))
    monkeypatch.setenv("SAFEPAY_PROXY_SECRET_FILE", str(proxy_secret))
    monkeypatch.setenv("SAFEPAY_TRUSTED_PROXY_CIDRS", "10.0.0.0/8,127.0.0.0/8")
    monkeypatch.delenv("SAFEPAY_V2_PROVIDER_ORIGIN", raising=False)


def _client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    client_host: str = "127.0.0.1",
) -> TestClient:
    app = create_app(db_path=":memory:")
    app.state.safepay_v2_transport = httpx.MockTransport(handler)
    return TestClient(app, client=(client_host, 50000))


def _quote_capability(quote: dict[str, Any]) -> str:
    return issue_safepay_v2_quote_capability(quote, QUOTE_CAPABILITY_SECRET)


def _u512_bytes(value: int) -> str:
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "little")
    return bytes([len(raw)]).hex() + raw.hex()


def _valid_unsigned_transfer(
    *,
    signer_public_key: str = SIGNER_PUBLIC_KEY,
    target_public_key: str = RECEIVER_PUBLIC_KEY,
    amount_motes: int = int(AMOUNT_MOTES),
    correlation_id: int = int(CORRELATION_ID),
    chain_name: str = "casper-test",
) -> dict[str, Any]:
    deploy = {
        "approvals": [],
        "hash": "de" * 32,
        "header": {
            "account": signer_public_key,
            "chain_name": chain_name,
        },
        "session": {
            "Transfer": {
                "args": [
                    [
                        "amount",
                        {
                            "cl_type": "U512",
                            "bytes": _u512_bytes(amount_motes),
                            "parsed": str(amount_motes),
                        },
                    ],
                    [
                        "target",
                        {
                            "cl_type": "PublicKey",
                            "bytes": target_public_key,
                            "parsed": target_public_key,
                        },
                    ],
                    [
                        "id",
                        {
                            "cl_type": {"Option": "U64"},
                            "bytes": (
                                "01"
                                + correlation_id.to_bytes(
                                    8, "little", signed=False
                                ).hex()
                            ),
                            "parsed": correlation_id,
                        },
                    ],
                ]
            }
        },
    }
    return {
        "status": "ready",
        "driver": "test",
        "payload_kind": "deploy",
        "chain_name": chain_name,
        "transfer_amount_motes": amount_motes,
        "correlation_id": correlation_id,
        "signer_public_key": signer_public_key,
        "target_public_key": target_public_key,
        "deploy_hash": deploy["hash"],
        "deploy_json": deploy,
        "wallet_payload": copy.deepcopy(deploy),
        "wallet_payload_wrapped": {"deploy": copy.deepcopy(deploy)},
    }


def test_account_hash_derivation_matches_casper_ed25519_vector() -> None:
    assert (
        safepay_v2_account_hash_from_public_key(RECEIVER_PUBLIC_KEY)
        == RECEIVER_ACCOUNT_HASH
    )


def test_account_hash_derivation_matches_casper_secp256k1_vector() -> None:
    assert (
        safepay_v2_account_hash_from_public_key("02" + "03" + ("22" * 32))
        == "d5525fd33097ea234d9df22fb2c2238456943901195d16522ddc74c0eb59f5e9"
    )


def test_quote_correlation_id_matches_the_frozen_golden_derivation() -> None:
    assert CORRELATION_ID == "1994822504869016532"
    assert validate_safepay_v2_gateway_quote(_quote()) is None


def test_gateway_v2_amount_never_falls_back_to_legacy_payment_amount(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SAFEPAY_AMOUNT_MOTES", AMOUNT_MOTES)
    monkeypatch.setenv("X402_PAYMENT_AMOUNT", "9999999")
    assert validate_safepay_v2_gateway_quote(_quote()) is None

    monkeypatch.delenv("SAFEPAY_AMOUNT_MOTES", raising=False)
    monkeypatch.setenv("X402_PAYMENT_AMOUNT", AMOUNT_MOTES)
    assert (
        validate_safepay_v2_gateway_quote(_quote())
        == "expected_amount_motes_invalid"
    )


def test_rehashed_wrong_correlation_is_not_a_valid_gateway_quote() -> None:
    wrong = _quote(correlation_id="42")
    assert wrong["quote_hash"] == safepay_v2_quote_hash(
        quote_id=wrong["quote_id"],
        proposal_id=wrong["proposal_id"],
        resource_id=wrong["resource_id"],
        network=wrong["network"],
        payee_account_hash=wrong["payee_account_hash"],
        amount_motes=wrong["amount_motes"],
        correlation_id=42,
        report_version=wrong["report_version"],
        report_hash=wrong["report_hash"],
        expires_at=wrong["expires_at"],
        quote_nonce=bytes.fromhex(wrong["quote_nonce"]),
    )
    assert (
        validate_safepay_v2_gateway_quote(wrong)
        == "correlation_id_derivation_mismatch"
    )


def test_quote_proxy_uses_pinned_internal_origin_and_preserves_machine_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quote = _quote()
    seen: list[httpx.Request] = []
    monkeypatch.setenv("X402_PROVIDER_URL", "https://attacker.invalid/x402/v2/quotes")

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert str(request.url) == f"{SAFEPAY_V2_PROVIDER_ORIGIN}/x402/v2/quotes"
        assert json.loads(request.content) == {
            "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
            "proposal_id": PROPOSAL_ID,
            "resource_id": RESOURCE_ID,
        }
        return _provider_response(402, _quote_issue_body(quote))

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/quotes",
            json={
                "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
                "proposal_id": PROPOSAL_ID,
                "resource_id": RESOURCE_ID,
            },
        )

    assert response.status_code == 402
    assert response.json() == _quote_issue_body(quote)
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-concordia-safepay-version"] == "safepay-v2"
    assert response.headers["x-concordia-safepay-quote-capability"] == (
        _quote_capability(quote)
    )
    assert len(seen) == 1


def test_quote_capability_header_is_exposed_to_the_local_browser_origin() -> None:
    quote = _quote()

    def handler(_request: httpx.Request) -> httpx.Response:
        return _provider_response(402, _quote_issue_body(quote))

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/quotes",
            json={
                "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
                "proposal_id": PROPOSAL_ID,
                "resource_id": RESOURCE_ID,
            },
            headers={"Origin": "http://localhost:3000"},
        )

    assert response.status_code == 402
    exposed = response.headers["access-control-expose-headers"].lower()
    assert "x-concordia-safepay-quote-capability" in exposed


def test_quote_proxy_rejects_an_origin_override_before_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    monkeypatch.setenv("SAFEPAY_V2_PROVIDER_ORIGIN", "https://attacker.invalid")

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise AssertionError("an invalid provider origin must never receive I/O")

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/quotes",
            json={
                "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
                "proposal_id": PROPOSAL_ID,
                "resource_id": RESOURCE_ID,
            },
        )

    assert response.status_code == 503
    assert response.json() == safepay_v2_error_body(
        "provider_unavailable", True, "not_attempted"
    )
    assert calls == 0


@pytest.mark.parametrize(
    ("quote", "mutate"),
    [
        (_quote(payee_account_hash="99" * 32), lambda body: body),
        (_quote(amount_motes="1000001"), lambda body: body),
        (_quote(correlation_id="42"), lambda body: body),
        (
            _quote(),
            lambda body: {**body, "quote": {**body["quote"], "quote_hash": "00" * 32}},
        ),
    ],
    ids=[
        "payee-mismatch",
        "amount-mismatch",
        "derived-correlation-mismatch",
        "quote-hash-mismatch",
    ],
)
def test_quote_proxy_rejects_invalid_provider_bindings_without_echoing_upstream_text(
    quote: dict[str, Any],
    mutate: Callable[[dict[str, Any]], dict[str, Any]],
) -> None:
    upstream = mutate(_quote_issue_body(quote))

    def handler(_request: httpx.Request) -> httpx.Response:
        return _provider_response(402, upstream)

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/quotes",
            json={
                "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
                "proposal_id": PROPOSAL_ID,
                "resource_id": RESOURCE_ID,
            },
        )

    assert response.status_code == 503
    assert response.json() == safepay_v2_error_body(
        "provider_unavailable", True, "not_attempted"
    )
    assert quote["payee_account_hash"].encode() not in response.content
    assert quote["quote_hash"].encode() not in response.content


def test_quote_proxy_sanitizes_an_upstream_debug_body() -> None:
    upstream = _quote_issue_body(_quote())
    upstream["upstream_debug"] = "secret-upstream-trace"

    def handler(_request: httpx.Request) -> httpx.Response:
        return _provider_response(402, upstream)

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/quotes",
            json={
                "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
                "proposal_id": PROPOSAL_ID,
                "resource_id": RESOURCE_ID,
            },
        )

    assert response.status_code == 503
    assert response.json() == safepay_v2_error_body(
        "provider_unavailable", True, "not_attempted"
    )
    assert b"secret-upstream-trace" not in response.content


def test_wallet_intent_uses_the_exact_quote_payment_terms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quote = _quote()
    observed: dict[str, Any] = {}

    def fake_build(**kwargs: Any) -> dict[str, Any]:
        observed.update(kwargs)
        return _valid_unsigned_transfer(**kwargs)

    monkeypatch.setattr(
        gateway_app, "build_unsigned_casper_transfer_deploy", fake_build
    )

    with _client(
        lambda _request: pytest.fail("wallet intent must not call the provider")
    ) as client:
        response = client.post(
            "/x402/v2/payment-intent",
            json={
                "schema_version": SAFEPAY_V2_WALLET_INTENT_REQUEST_SCHEMA,
                "quote": quote,
                "quote_capability": _quote_capability(quote),
                "signer_public_key": SIGNER_PUBLIC_KEY,
            },
        )

    assert response.status_code == 200
    assert observed == {
        "signer_public_key": SIGNER_PUBLIC_KEY,
        "target_public_key": RECEIVER_PUBLIC_KEY,
        "amount_motes": int(quote["amount_motes"]),
        "correlation_id": int(quote["correlation_id"]),
        "chain_name": "casper-test",
    }
    payload = response.json()
    assert payload["quote"] == quote
    assert payload["payment_requirements"]["correlation_id"] == quote["correlation_id"]
    assert (
        payload["payment_requirements"]["payee_account_hash"]
        == quote["payee_account_hash"]
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(status="failed"),
        lambda value: value.update(chain_name="casper"),
        lambda value: value["deploy_json"]["header"].update(chain_name="casper"),
        lambda value: value.update(target_public_key="01" + ("99" * 32)),
        lambda value: value["deploy_json"]["session"]["Transfer"]["args"][1][
            1
        ].update(parsed="01" + ("99" * 32)),
        lambda value: value.update(transfer_amount_motes=int(AMOUNT_MOTES) + 1),
        lambda value: value["deploy_json"]["session"]["Transfer"]["args"][0][
            1
        ].update(parsed=str(int(AMOUNT_MOTES) + 1)),
        lambda value: value.update(correlation_id=int(CORRELATION_ID) + 1),
        lambda value: value["deploy_json"]["session"]["Transfer"]["args"][2][
            1
        ].update(parsed=int(CORRELATION_ID) + 1),
        lambda value: value.update(signer_public_key="01" + ("99" * 32)),
        lambda value: value["deploy_json"]["header"].update(
            account="01" + ("99" * 32)
        ),
        lambda value: value["wallet_payload"]["header"].update(
            chain_name="casper"
        ),
    ],
    ids=[
        "status",
        "top-level-chain",
        "serialized-chain",
        "top-level-target",
        "serialized-target",
        "top-level-amount",
        "serialized-amount",
        "top-level-correlation",
        "serialized-correlation",
        "top-level-signer",
        "serialized-signer",
        "wallet-payload-divergence",
    ],
)
def test_wallet_intent_refuses_every_forged_builder_field(
    monkeypatch: pytest.MonkeyPatch,
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    quote = _quote()

    def fake_build(**kwargs: Any) -> dict[str, Any]:
        unsigned = _valid_unsigned_transfer(**kwargs)
        mutation(unsigned)
        return unsigned

    monkeypatch.setattr(
        gateway_app, "build_unsigned_casper_transfer_deploy", fake_build
    )
    with _client(
        lambda _request: pytest.fail("wallet intent must not call the provider")
    ) as client:
        response = client.post(
            "/x402/v2/payment-intent",
            json={
                "schema_version": SAFEPAY_V2_WALLET_INTENT_REQUEST_SCHEMA,
                "quote": quote,
                "quote_capability": _quote_capability(quote),
                "signer_public_key": SIGNER_PUBLIC_KEY,
            },
        )

    assert response.status_code == 503
    assert response.json() == safepay_v2_error_body(
        "wallet_intent_unavailable", False, "not_attempted"
    )


def test_wallet_intent_validator_fails_closed_on_truncated_serialized_args() -> None:
    quote = _quote()
    unsigned = _valid_unsigned_transfer()
    unsigned["deploy_json"]["session"]["Transfer"]["args"] = [
        ["amount"],
        ["target"],
        ["id"],
    ]
    unsigned["wallet_payload"] = copy.deepcopy(unsigned["deploy_json"])
    unsigned["wallet_payload_wrapped"] = {
        "deploy": copy.deepcopy(unsigned["deploy_json"])
    }

    assert not gateway_app._safepay_unsigned_transfer_matches(
        unsigned,
        signer_public_key=SIGNER_PUBLIC_KEY,
        receiver_public_key=RECEIVER_PUBLIC_KEY,
        quote=quote,
    )


def test_wallet_intent_chain_is_literal_testnet_despite_ambient_chain_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quote = _quote()
    observed: dict[str, Any] = {}
    monkeypatch.setenv("CASPER_CHAIN_NAME", "casper")

    def fake_build(**kwargs: Any) -> dict[str, Any]:
        observed.update(kwargs)
        return _valid_unsigned_transfer(**kwargs)

    monkeypatch.setattr(
        gateway_app, "build_unsigned_casper_transfer_deploy", fake_build
    )
    with _client(
        lambda _request: pytest.fail("wallet intent must not call the provider")
    ) as client:
        response = client.post(
            "/x402/v2/payment-intent",
            json={
                "schema_version": SAFEPAY_V2_WALLET_INTENT_REQUEST_SCHEMA,
                "quote": quote,
                "quote_capability": _quote_capability(quote),
                "signer_public_key": SIGNER_PUBLIC_KEY,
            },
        )

    assert response.status_code == 200
    assert observed["chain_name"] == "casper-test"
    assert response.json()["chain_name"] == "casper-test"
    assert response.json()["deploy_json"]["header"]["chain_name"] == "casper-test"


def test_wallet_intent_validator_accepts_real_pycspr_checksum_serialization() -> None:
    signer = "01" + ("ab" * 32)
    target = "01" + ("cd" * 32)
    quote = _quote(
        payee_account_hash=safepay_v2_account_hash_from_public_key(target)
    )
    unsigned = gateway_app.build_unsigned_casper_transfer_deploy(
        signer_public_key=signer,
        target_public_key=target,
        amount_motes=int(quote["amount_motes"]),
        correlation_id=int(quote["correlation_id"]),
        chain_name="casper-test",
    )

    assert gateway_app._safepay_unsigned_transfer_matches(
        unsigned,
        signer_public_key=signer,
        receiver_public_key=target,
        quote=quote,
    )


def test_wallet_intent_refuses_an_expired_unconsumed_quote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        gateway_app,
        "build_unsigned_casper_transfer_deploy",
        lambda **_kwargs: pytest.fail("an expired quote must not build a transfer"),
    )

    with _client(
        lambda _request: pytest.fail("wallet intent must not call the provider")
    ) as client:
        response = client.post(
            "/x402/v2/payment-intent",
            json={
                "schema_version": SAFEPAY_V2_WALLET_INTENT_REQUEST_SCHEMA,
                "quote": (expired_quote := _quote(expires_at=1)),
                "quote_capability": _quote_capability(expired_quote),
                "signer_public_key": SIGNER_PUBLIC_KEY,
            },
        )

    assert response.status_code == 400
    assert response.json() == safepay_v2_error_body(
        "invalid_request", False, "not_attempted"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda token: token[:-1] + ("0" if token[-1] != "0" else "1"),
        lambda _token: "sqc1.invalid.invalid",
        lambda _token: "",
    ],
    ids=["mac-tamper", "malformed", "missing"],
)
def test_wallet_intent_requires_an_issuer_authenticated_quote_capability(
    monkeypatch: pytest.MonkeyPatch,
    mutation: Callable[[str], str],
) -> None:
    quote = _quote()
    monkeypatch.setattr(
        gateway_app,
        "build_unsigned_casper_transfer_deploy",
        lambda **_kwargs: pytest.fail("an unissued quote must never build a transfer"),
    )

    with _client(
        lambda _request: pytest.fail("wallet intent must not call the provider")
    ) as client:
        response = client.post(
            "/x402/v2/payment-intent",
            json={
                "schema_version": SAFEPAY_V2_WALLET_INTENT_REQUEST_SCHEMA,
                "quote": quote,
                "quote_capability": mutation(_quote_capability(quote)),
                "signer_public_key": SIGNER_PUBLIC_KEY,
            },
        )

    assert response.status_code == 400
    assert response.json() == safepay_v2_error_body(
        "invalid_request", False, "not_attempted"
    )


def test_quote_capability_is_stable_across_gateway_restart() -> None:
    quote = _quote()

    def handler(_request: httpx.Request) -> httpx.Response:
        return _provider_response(402, _quote_issue_body(quote))

    capabilities: list[str] = []
    for _ in range(2):
        with _client(handler) as client:
            response = client.post(
                "/x402/v2/quotes",
                json={
                    "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
                    "proposal_id": PROPOSAL_ID,
                    "resource_id": RESOURCE_ID,
                },
            )
            capabilities.append(
                response.headers["x-concordia-safepay-quote-capability"]
            )
    assert capabilities == [_quote_capability(quote), _quote_capability(quote)]


def test_quote_capability_expires_with_the_bound_quote() -> None:
    quote = _quote(expires_at=100)
    token = _quote_capability(quote)

    assert verify_safepay_v2_quote_capability(
        quote, token, QUOTE_CAPABILITY_SECRET, now=99
    )
    assert not verify_safepay_v2_quote_capability(
        quote, token, QUOTE_CAPABILITY_SECRET, now=100
    )


def test_missing_quote_capability_secret_fails_before_provider_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SAFEPAY_QUOTE_TOKEN_SECRET_FILE")
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise AssertionError("provider must not receive an un-signable quote request")

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/quotes",
            json={
                "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
                "proposal_id": PROPOSAL_ID,
                "resource_id": RESOURCE_ID,
            },
        )

    assert response.status_code == 503
    assert response.json() == safepay_v2_error_body(
        "provider_unavailable", True, "not_attempted"
    )
    assert calls == 0


def test_rehashed_wrong_correlation_is_refused_by_intent_and_redemption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrong = _quote(correlation_id="42")
    monkeypatch.setattr(
        gateway_app,
        "build_unsigned_casper_transfer_deploy",
        lambda **_kwargs: pytest.fail("wrong correlation must not build"),
    )
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise AssertionError("wrong correlation must not reach provider")

    with _client(handler) as client:
        intent = client.post(
            "/x402/v2/payment-intent",
            json={
                "schema_version": SAFEPAY_V2_WALLET_INTENT_REQUEST_SCHEMA,
                "quote": wrong,
                "quote_capability": _quote_capability(wrong),
                "signer_public_key": SIGNER_PUBLIC_KEY,
            },
        )
        redemption = client.post(
            "/x402/v2/redemptions",
            json={
                "schema_version": SAFEPAY_V2_REDEMPTION_REQUEST_SCHEMA,
                "quote": wrong,
                "payment_hash": PAYMENT_HASH,
            },
        )

    assert intent.status_code == 400
    assert redemption.status_code == 400
    assert calls == 0


@pytest.mark.parametrize("disposition", ["first_consumption", "idempotent_replay"])
def test_redemption_proxy_submits_exact_quote_and_maps_success_honestly(
    disposition: str,
) -> None:
    quote = _quote()
    expected = _success_body(quote, disposition=disposition)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert str(request.url) == f"{SAFEPAY_V2_PROVIDER_ORIGIN}/x402/v2/redemptions"
        assert "x-payment" not in request.headers
        assert json.loads(request.content) == {
            "schema_version": SAFEPAY_V2_REDEMPTION_REQUEST_SCHEMA,
            "quote": quote,
            "payment_hash": PAYMENT_HASH,
        }
        return _provider_response(200, expected)

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/redemptions",
            json={
                "schema_version": SAFEPAY_V2_REDEMPTION_REQUEST_SCHEMA,
                "quote": quote,
                "payment_hash": PAYMENT_HASH,
            },
            headers={"X-Payment": "legacy-header-must-not-be-forwarded"},
        )

    assert response.status_code == 200
    assert response.json() == expected
    assert response.json()["delivery"]["replay_disposition"] == disposition
    assert len(seen) == 1


@pytest.mark.parametrize(
    ("status_code", "code", "disposition"),
    [
        (400, "invalid_request", "not_attempted"),
        (404, "quote_not_issued", "not_attempted"),
        (409, "payment_already_consumed_for_other_binding", "cross_binding_rejected"),
        (410, "quote_expired", "not_attempted"),
        (422, "quote_binding_invalid", "not_attempted"),
        (422, "payment_binding_invalid", "verification_rejected"),
    ],
)
def test_redemption_terminal_provider_outcomes_are_never_retried(
    status_code: int, code: str, disposition: str
) -> None:
    quote = _quote()
    calls = 0
    body = safepay_v2_error_body(code, False, disposition)

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _provider_response(status_code, body)

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/redemptions",
            json={
                "schema_version": SAFEPAY_V2_REDEMPTION_REQUEST_SCHEMA,
                "quote": quote,
                "payment_hash": PAYMENT_HASH,
            },
        )

    assert response.status_code == status_code
    assert response.json() == body
    assert calls == 1


@pytest.mark.parametrize(
    ("status_code", "code", "disposition"),
    [
        (425, "payment_not_finalized", "verification_pending"),
        (503, "payment_observer_unavailable", "verification_pending"),
    ],
)
def test_only_explicit_machine_retryable_outcomes_receive_bounded_retries(
    status_code: int, code: str, disposition: str
) -> None:
    quote = _quote()
    calls = 0
    success = _success_body(quote)

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return _provider_response(
                status_code, safepay_v2_error_body(code, True, disposition)
            )
        return _provider_response(200, success)

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/redemptions",
            json={
                "schema_version": SAFEPAY_V2_REDEMPTION_REQUEST_SCHEMA,
                "quote": quote,
                "payment_hash": PAYMENT_HASH,
            },
        )

    assert response.status_code == 200
    assert response.json() == success
    assert calls == 2


def test_explicit_quote_rate_limit_receives_a_bounded_retry() -> None:
    quote = _quote()
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return _provider_response(
                429,
                safepay_v2_error_body("quote_rate_limited", True, "not_attempted"),
            )
        return _provider_response(402, _quote_issue_body(quote))

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/quotes",
            json={
                "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
                "proposal_id": PROPOSAL_ID,
                "resource_id": RESOURCE_ID,
            },
        )

    assert response.status_code == 402
    assert response.json() == _quote_issue_body(quote)
    assert calls == 2


def test_retryable_status_with_a_non_retryable_body_is_not_retried() -> None:
    quote = _quote()
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _provider_response(
            503,
            safepay_v2_error_body(
                "payment_observer_unavailable", False, "verification_pending"
            ),
        )

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/redemptions",
            json={
                "schema_version": SAFEPAY_V2_REDEMPTION_REQUEST_SCHEMA,
                "quote": quote,
                "payment_hash": PAYMENT_HASH,
            },
        )

    assert response.status_code == 503
    assert response.json() == safepay_v2_error_body(
        "provider_unavailable", True, "verification_pending"
    )
    assert calls == 1


@pytest.mark.parametrize(
    "failure",
    [
        httpx.ConnectError("secret-upstream-hostname"),
        RuntimeError("secret-transport-runtime"),
    ],
)
def test_transport_failure_is_sanitized_and_not_retried(
    failure: Exception,
) -> None:
    quote = _quote()
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise failure

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/redemptions",
            json={
                "schema_version": SAFEPAY_V2_REDEMPTION_REQUEST_SCHEMA,
                "quote": quote,
                "payment_hash": PAYMENT_HASH,
            },
        )

    assert response.status_code == 503
    assert response.json() == safepay_v2_error_body(
        "provider_unavailable", True, "verification_pending"
    )
    assert b"secret-" not in response.content
    assert calls == 1


def test_internal_provider_client_ignores_ambient_proxy_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quote = _quote()
    constructor_calls: list[dict[str, Any]] = []
    ambient_proxy_capture: list[str] = []
    original_async_client = httpx.AsyncClient
    monkeypatch.setenv(
        "HTTP_PROXY", "http://ambient-user:ambient-secret@127.0.0.1:9"
    )
    monkeypatch.setenv(
        "ALL_PROXY", "http://ambient-user:ambient-secret@127.0.0.1:9"
    )
    monkeypatch.setenv("NO_PROXY", "")

    class AuditedAsyncClient(original_async_client):
        def __init__(self, **kwargs: Any) -> None:
            constructor_calls.append(dict(kwargs))
            if kwargs.get("trust_env", True):
                ambient_proxy_capture.append("ambient-proxy-enabled")
            super().__init__(**kwargs)

    monkeypatch.setattr(
        safepay_module.httpx, "AsyncClient", AuditedAsyncClient
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert "proxy-authorization" not in request.headers
        assert all(
            "ambient-secret" not in value for value in request.headers.values()
        )
        return _provider_response(402, _quote_issue_body(quote))

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/quotes",
            json={
                "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
                "proposal_id": PROPOSAL_ID,
                "resource_id": RESOURCE_ID,
            },
        )

    assert response.status_code == 402
    assert ambient_proxy_capture == []
    assert constructor_calls
    assert constructor_calls[-1]["trust_env"] is False
    assert constructor_calls[-1]["follow_redirects"] is False


def test_internal_provider_redirect_is_never_followed() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if len(calls) > 1:
            raise AssertionError("SafePay internal redirects must never be followed")
        return httpx.Response(
            307,
            content=b"{}",
            headers={
                "Content-Type": "application/json",
                "Location": "https://attacker.invalid/collect",
                **V2_HEADERS,
            },
        )

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/quotes",
            json={
                "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
                "proposal_id": PROPOSAL_ID,
                "resource_id": RESOURCE_ID,
            },
        )

    assert response.status_code == 503
    assert response.json() == safepay_v2_error_body(
        "provider_unavailable", True, "not_attempted"
    )
    assert calls == [f"{SAFEPAY_V2_PROVIDER_ORIGIN}/x402/v2/quotes"]


def test_malformed_provider_success_is_sanitized_instead_of_raising() -> None:
    quote = _quote()
    malformed = _success_body(quote)
    malformed["fulfillment"]["report"]["content_base64"] = (
        "secret-upstream-invalid-base64***"
    )

    def handler(_request: httpx.Request) -> httpx.Response:
        return _provider_response(200, malformed)

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/redemptions",
            json={
                "schema_version": SAFEPAY_V2_REDEMPTION_REQUEST_SCHEMA,
                "quote": quote,
                "payment_hash": PAYMENT_HASH,
            },
        )

    assert response.status_code == 503
    assert response.json() == safepay_v2_error_body(
        "provider_unavailable", True, "verification_pending"
    )
    assert b"secret-upstream-invalid-base64" not in response.content


def test_type_confused_provider_success_is_sanitized_instead_of_raising() -> None:
    quote = _quote()
    malformed = _success_body(quote)
    malformed["delivery"]["replay_disposition"] = ["secret-upstream-value"]

    def handler(_request: httpx.Request) -> httpx.Response:
        return _provider_response(200, malformed)

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/redemptions",
            json={
                "schema_version": SAFEPAY_V2_REDEMPTION_REQUEST_SCHEMA,
                "quote": quote,
                "payment_hash": PAYMENT_HASH,
            },
        )

    assert response.status_code == 503
    assert response.json() == safepay_v2_error_body(
        "provider_unavailable", True, "verification_pending"
    )
    assert b"secret-upstream-value" not in response.content


@pytest.mark.parametrize(
    "payment_hash", ["AB" * 32, "ab" * 31, "casper:" + ("ab" * 32)]
)
def test_redemption_rejects_noncanonical_payment_hash_before_provider_io(
    payment_hash: str,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise AssertionError("invalid payment hashes must never reach the provider")

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/redemptions",
            json={
                "schema_version": SAFEPAY_V2_REDEMPTION_REQUEST_SCHEMA,
                "quote": _quote(),
                "payment_hash": payment_hash,
            },
        )

    assert response.status_code == 400
    assert response.json() == safepay_v2_error_body(
        "invalid_request", False, "not_attempted"
    )
    assert calls == 0


def test_gateway_keeps_no_redemption_cache_or_consumption_ledger() -> None:
    quote = _quote()
    dispositions = iter(["first_consumption", "idempotent_replay"])
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _provider_response(
            200, _success_body(quote, disposition=next(dispositions))
        )

    with _client(handler) as client:
        bodies = []
        for _ in range(2):
            response = client.post(
                "/x402/v2/redemptions",
                json={
                    "schema_version": SAFEPAY_V2_REDEMPTION_REQUEST_SCHEMA,
                    "quote": quote,
                    "payment_hash": PAYMENT_HASH,
                },
            )
            bodies.append(response.json()["delivery"]["replay_disposition"])

    assert bodies == ["first_consumption", "idempotent_replay"]
    assert calls == 2


def test_gateway_preserves_distinct_trusted_client_quota_identities() -> None:
    quote = _quote()
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(
            (
                request.headers["x-concordia-client-ip"],
                request.headers["x-concordia-safepay-proxy"],
            )
        )
        return _provider_response(402, _quote_issue_body(quote))

    with _client(handler, client_host="10.1.2.3") as client:
        for client_ip in ("198.51.100.10", "198.51.100.11"):
            response = client.post(
                "/x402/v2/quotes",
                json={
                    "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
                    "proposal_id": PROPOSAL_ID,
                    "resource_id": RESOURCE_ID,
                },
                headers={
                    "X-Concordia-Client-IP": client_ip,
                    "X-Concordia-SafePay-Proxy": PROXY_SECRET,
                },
            )
            assert response.status_code == 402

    assert seen == [
        ("198.51.100.10", PROXY_SECRET),
        ("198.51.100.11", PROXY_SECRET),
    ]


def test_generic_rate_limiter_never_handles_safepay_v2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quote = _quote()
    calls = 0
    monkeypatch.setenv("CONCORDIA_RATE_LIMIT_PER_MINUTE", "1")
    monkeypatch.setenv("SAFEPAY_GATEWAY_QUOTE_REQUESTS_PER_WINDOW", "10")

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _provider_response(402, _quote_issue_body(quote))

    with _client(handler) as client:
        responses = [
            client.post(
                "/x402/v2/quotes",
                json={
                    "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
                    "proposal_id": PROPOSAL_ID,
                    "resource_id": RESOURCE_ID,
                },
                headers={"Authorization": "Bearer one-fixed-caller"},
            )
            for _index in range(3)
        ]

    assert [response.status_code for response in responses] == [402, 402, 402]
    assert calls == 3
    assert all(b"Rate limit exceeded" not in response.content for response in responses)


def test_safepay_quote_admission_isolated_by_attested_client_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quote = _quote()
    calls = 0
    monkeypatch.setenv("SAFEPAY_GATEWAY_QUOTE_REQUESTS_PER_WINDOW", "1")

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _provider_response(402, _quote_issue_body(quote))

    with _client(handler, client_host="10.1.2.3") as client:
        def issue(client_ip: str) -> httpx.Response:
            return client.post(
                "/x402/v2/quotes",
                json={
                    "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
                    "proposal_id": PROPOSAL_ID,
                    "resource_id": RESOURCE_ID,
                },
                headers={
                    "X-Concordia-Client-IP": client_ip,
                    "X-Concordia-SafePay-Proxy": PROXY_SECRET,
                },
            )

        first_a = issue("198.51.100.10")
        second_a = issue("198.51.100.10")
        first_b = issue("198.51.100.11")

    assert first_a.status_code == 402
    assert second_a.status_code == 429
    assert second_a.json() == safepay_v2_error_body(
        "quote_rate_limited", True, "not_attempted"
    )
    assert first_b.status_code == 402
    assert calls == 2


def test_safepay_authorization_and_xff_cannot_reset_admission_quota(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quote = _quote()
    monkeypatch.setenv("SAFEPAY_GATEWAY_QUOTE_REQUESTS_PER_WINDOW", "1")

    def handler(_request: httpx.Request) -> httpx.Response:
        return _provider_response(402, _quote_issue_body(quote))

    with _client(handler, client_host="10.1.2.3") as client:
        responses = []
        for index in range(3):
            responses.append(
                client.post(
                    "/x402/v2/quotes",
                    json={
                        "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
                        "proposal_id": PROPOSAL_ID,
                        "resource_id": RESOURCE_ID,
                    },
                    headers={
                        "Authorization": f"Bearer caller-{index}",
                        "X-Forwarded-For": f"198.51.100.{index + 1}",
                        "X-Concordia-Client-IP": "198.51.100.20",
                        "X-Concordia-SafePay-Proxy": PROXY_SECRET,
                    },
                )
            )

    assert responses[0].status_code == 402
    assert [response.status_code for response in responses[1:]] == [429, 429]
    for response in responses[1:]:
        assert response.json() == safepay_v2_error_body(
            "quote_rate_limited", True, "not_attempted"
        )
        assert b"Rate limit exceeded" not in response.content


def test_safepay_quote_and_redemption_admission_are_separate_and_frozen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quote = _quote()
    success = _success_body(quote)
    quote_calls = 0
    redemption_calls = 0
    monkeypatch.setenv("SAFEPAY_GATEWAY_QUOTE_REQUESTS_PER_WINDOW", "1")
    monkeypatch.setenv("SAFEPAY_GATEWAY_REDEMPTION_REQUESTS_PER_WINDOW", "1")

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal quote_calls, redemption_calls
        if request.url.path.endswith("/quotes"):
            quote_calls += 1
            return _provider_response(402, _quote_issue_body(quote))
        redemption_calls += 1
        return _provider_response(200, success)

    headers = {
        "X-Concordia-Client-IP": "198.51.100.30",
        "X-Concordia-SafePay-Proxy": PROXY_SECRET,
    }
    with _client(handler, client_host="10.1.2.3") as client:
        issued = client.post(
            "/x402/v2/quotes",
            json={
                "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
                "proposal_id": PROPOSAL_ID,
                "resource_id": RESOURCE_ID,
            },
            headers=headers,
        )
        redemption_body = {
            "schema_version": SAFEPAY_V2_REDEMPTION_REQUEST_SCHEMA,
            "quote": quote,
            "payment_hash": PAYMENT_HASH,
        }
        first_redemption = client.post(
            "/x402/v2/redemptions", json=redemption_body, headers=headers
        )
        second_redemption = client.post(
            "/x402/v2/redemptions", json=redemption_body, headers=headers
        )

    assert issued.status_code == 402
    assert first_redemption.status_code == 200
    assert second_redemption.status_code == 503
    assert second_redemption.json() == safepay_v2_error_body(
        "provider_unavailable", True, "verification_pending"
    )
    assert b"Rate limit exceeded" not in second_redemption.content
    assert quote_calls == 1
    assert redemption_calls == 1


def test_safepay_payment_intent_has_its_own_attested_admission_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quote = _quote()
    monkeypatch.setenv(
        "SAFEPAY_GATEWAY_PAYMENT_INTENT_REQUESTS_PER_WINDOW", "1"
    )
    monkeypatch.setattr(
        gateway_app,
        "build_unsigned_casper_transfer_deploy",
        lambda **kwargs: _valid_unsigned_transfer(**kwargs),
    )
    body = {
        "schema_version": SAFEPAY_V2_WALLET_INTENT_REQUEST_SCHEMA,
        "quote": quote,
        "quote_capability": _quote_capability(quote),
        "signer_public_key": SIGNER_PUBLIC_KEY,
    }
    headers = {
        "X-Concordia-Client-IP": "198.51.100.40",
        "X-Concordia-SafePay-Proxy": PROXY_SECRET,
    }

    with _client(
        lambda _request: pytest.fail("wallet intent must not call the provider"),
        client_host="10.1.2.3",
    ) as client:
        first = client.post(
            "/x402/v2/payment-intent", json=body, headers=headers
        )
        second = client.post(
            "/x402/v2/payment-intent",
            json=body,
            headers={
                **headers,
                "Authorization": "Bearer quota-reset-attempt",
                "X-Forwarded-For": "203.0.113.99",
            },
        )

    assert first.status_code == 200
    assert second.status_code == 503
    assert second.json() == safepay_v2_error_body(
        "wallet_intent_unavailable", False, "not_attempted"
    )
    assert b"Rate limit exceeded" not in second.content


def test_safepay_admission_bucket_table_is_strictly_bounded() -> None:
    now = [120.0]
    limiter = SafePayAdmissionLimiter(
        quote_requests_per_window=2,
        payment_intent_requests_per_window=2,
        redemption_requests_per_window=2,
        window_seconds=60,
        max_buckets=2,
        clock=lambda: now[0],
    )

    assert limiter.admit("quotes", "198.51.100.1")
    assert limiter.admit("quotes", "198.51.100.2")
    assert not limiter.admit("quotes", "198.51.100.3")
    assert len(limiter._buckets) == 2

    now[0] = 180.0
    assert limiter.admit("quotes", "198.51.100.3")
    assert len(limiter._buckets) == 1


@pytest.mark.parametrize(
    "raw",
    [
        "10.0.0.0/8,not-a-cidr",
        "10.0.0.0/8,2001:db8::/129",
    ],
)
def test_invalid_mixed_proxy_cidrs_fail_gateway_startup(
    monkeypatch: pytest.MonkeyPatch,
    raw: str,
) -> None:
    monkeypatch.setenv("SAFEPAY_TRUSTED_PROXY_CIDRS", raw)
    with pytest.raises(
        RuntimeError,
        match="SAFEPAY_TRUSTED_PROXY_CIDRS contains an invalid CIDR",
    ):
        create_app(db_path=":memory:")


@pytest.mark.parametrize("raw", [None, "", " ", ",", " , "])
def test_gateway_requires_nonempty_proxy_cidrs_outside_explicit_test_mode(
    monkeypatch: pytest.MonkeyPatch,
    raw: str | None,
) -> None:
    monkeypatch.delenv("CONCORDIA_TEST_MODE", raising=False)
    if raw is None:
        monkeypatch.delenv("SAFEPAY_TRUSTED_PROXY_CIDRS", raising=False)
    else:
        monkeypatch.setenv("SAFEPAY_TRUSTED_PROXY_CIDRS", raw)
    with pytest.raises(
        RuntimeError,
        match="SAFEPAY_TRUSTED_PROXY_CIDRS requires at least one valid CIDR",
    ):
        create_app(db_path=":memory:")


def test_gateway_accepts_multiple_proxy_cidrs_outside_test_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CONCORDIA_TEST_MODE", raising=False)
    monkeypatch.setenv(
        "SAFEPAY_TRUSTED_PROXY_CIDRS",
        "10.1.2.3/8, 2001:db8::1/64",
    )
    app = create_app(db_path=":memory:")
    assert tuple(
        str(network) for network in app.state.safepay_trusted_proxy_networks
    ) == ("10.0.0.0/8", "2001:db8::/64")


def test_gateway_canonicalizes_host_bit_and_ipv6_proxy_cidrs_once_at_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "SAFEPAY_TRUSTED_PROXY_CIDRS",
        "10.1.2.3/8,2001:0DB8:0000:0000::1/64",
    )
    app = create_app(db_path=":memory:")

    assert tuple(
        str(network) for network in app.state.safepay_trusted_proxy_networks
    ) == ("10.0.0.0/8", "2001:db8::/64")


def test_gateway_proxy_cidrs_do_not_reparse_request_time_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quote = _quote()
    monkeypatch.setenv("SAFEPAY_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["x-concordia-client-ip"])
        return _provider_response(402, _quote_issue_body(quote))

    app = create_app(db_path=":memory:")
    app.state.safepay_v2_transport = httpx.MockTransport(handler)
    monkeypatch.setenv("SAFEPAY_TRUSTED_PROXY_CIDRS", "not-a-cidr")
    with TestClient(app, client=("10.1.2.3", 50000)) as client:
        response = client.post(
            "/x402/v2/quotes",
            json={
                "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
                "proposal_id": PROPOSAL_ID,
                "resource_id": RESOURCE_ID,
            },
            headers={
                "X-Concordia-Client-IP": "2001:db8::7",
                "X-Concordia-SafePay-Proxy": PROXY_SECRET,
            },
        )

    assert response.status_code == 402
    assert seen == ["2001:db8::7"]


@pytest.mark.parametrize(
    ("forwarded", "attestation"),
    [
        ("198.51.100.10", "wrong-attestation"),
        ("198.51.100.10,198.51.100.11", PROXY_SECRET),
        ("not-an-ip", PROXY_SECRET),
    ],
)
def test_gateway_never_forwards_spoofed_or_invalid_client_identity(
    forwarded: str,
    attestation: str,
) -> None:
    quote = _quote()
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["x-concordia-client-ip"])
        assert request.headers["x-concordia-safepay-proxy"] == PROXY_SECRET
        return _provider_response(402, _quote_issue_body(quote))

    with _client(handler, client_host="10.1.2.3") as client:
        response = client.post(
            "/x402/v2/quotes",
            json={
                "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
                "proposal_id": PROPOSAL_ID,
                "resource_id": RESOURCE_ID,
            },
            headers={
                "X-Concordia-Client-IP": forwarded,
                "X-Concordia-SafePay-Proxy": attestation,
            },
        )

    assert response.status_code == 402
    assert seen == ["10.1.2.3"]


@pytest.mark.parametrize(
    "raw",
    [
        (
            b'{"schema_version":"safepay-quote-request-v2",'
            b'"proposal_id":"DAO-PROP-6CB25C",'
            b'"proposal_id":"DAO-PROP-OTHER",'
            b'"resource_id":"concordia-governance-report:DAO-PROP-6CB25C"}'
        ),
        (
            b'{"schema_version":"safepay-quote-request-v2",'
            b'"proposal_id":"DAO-PROP-6CB25C","resource_id":NaN}'
        ),
        (b'{"value":' + (b"[" * 80) + b"0" + (b"]" * 80) + b"}"),
    ],
    ids=["duplicate-key", "non-finite", "excessive-depth"],
)
def test_public_safepay_json_parser_fails_closed_without_provider_io(raw: bytes) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise AssertionError("invalid JSON must not reach the provider")

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/quotes",
            content=raw,
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 400
    assert response.json() == safepay_v2_error_body(
        "invalid_request", False, "not_attempted"
    )
    assert calls == 0


@pytest.mark.parametrize("raw", [b'{"value":1.0}', b'{"value":1e9999}'])
def test_strict_safepay_json_helper_rejects_every_float(raw: bytes) -> None:
    with pytest.raises(ValueError, match="invalid SafePay JSON"):
        safepay_module.parse_safepay_v2_strict_json(raw)


def test_public_safepay_request_body_is_bounded_before_provider_io() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise AssertionError("oversize body must not reach provider")

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/quotes",
            content=b"{" + (b"x" * 70_000) + b"}",
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 400
    assert calls == 0


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":"safepay-v2","schema_version":"safepay-v2"}',
        b'{"schema_version":"safepay-v2","value":Infinity}',
        b'{"value":' + (b"[" * 80) + b"0" + (b"]" * 80) + b"}",
    ],
    ids=["duplicate-key", "non-finite", "excessive-depth"],
)
def test_malformed_upstream_json_maps_to_frozen_provider_unavailable(raw: bytes) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            402,
            content=raw,
            headers={"Content-Type": "application/json", **V2_HEADERS},
        )

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/quotes",
            json={
                "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
                "proposal_id": PROPOSAL_ID,
                "resource_id": RESOURCE_ID,
            },
        )

    assert response.status_code == 503
    assert response.json() == safepay_v2_error_body(
        "provider_unavailable", True, "not_attempted"
    )


def test_upstream_response_cap_stops_streaming_as_soon_as_limit_is_crossed() -> None:
    yielded: list[int] = []

    class TrackingStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            for index in range(4):
                yielded.append(index)
                yield b"x" * 400_000

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            402,
            stream=TrackingStream(),
            headers={"Content-Type": "application/json", **V2_HEADERS},
        )

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/quotes",
            json={
                "schema_version": SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
                "proposal_id": PROPOSAL_ID,
                "resource_id": RESOURCE_ID,
            },
        )

    assert response.status_code == 503
    assert yielded == [0, 1, 2]


def test_success_validator_rejects_rehashed_wrong_correlation_independently() -> None:
    wrong = _quote(correlation_id="42")
    body = _success_body(wrong)

    assert not safepay_module._validate_safepay_v2_success_response(
        body,
        submitted_quote=wrong,
        payment_hash=PAYMENT_HASH,
    )


def test_redemption_accepts_persisted_quote_after_payment_config_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    quote = _quote()
    expected = _success_body(quote, disposition="idempotent_replay")
    monkeypatch.setenv("X402_PAYMENT_RECEIVER_PUBLIC_KEY", "01" + ("99" * 32))
    monkeypatch.setenv("X402_PAYMENT_AMOUNT", "9999999")

    def handler(_request: httpx.Request) -> httpx.Response:
        return _provider_response(200, expected)

    with _client(handler) as client:
        response = client.post(
            "/x402/v2/redemptions",
            json={
                "schema_version": SAFEPAY_V2_REDEMPTION_REQUEST_SCHEMA,
                "quote": quote,
                "payment_hash": PAYMENT_HASH,
            },
        )

    assert response.status_code == 200
    assert response.json() == expected
