from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from scripts import bound_live_proof_collector as collector


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii") + b"\n"


def _safepay_input() -> dict[str, object]:
    quote = {
        "schema_version": "safepay-v2",
        "quote_id": "123e4567-e89b-42d3-a456-426614174000",
        "proposal_id": "DAO-PROP-TEST-1",
        "resource_id": "risk-report:test",
        "network": "casper:casper-test",
        "payee_account_hash": "ab" * 32,
        "amount_motes": "2500000000",
        "correlation_id": "0",
        "report_version": "safepay-report-v2",
        "report_hash": "cd" * 32,
        "expires_at": 1_800_000_000,
        "quote_nonce": "ef" * 32,
        "quote_hash": "",
    }
    from shared.x402_payments import safepay_v2_correlation_id, safepay_v2_quote_hash

    quote["correlation_id"] = str(
        safepay_v2_correlation_id(
            quote["quote_id"], quote["proposal_id"], quote["resource_id"], bytes.fromhex(quote["quote_nonce"])
        )
    )
    quote["quote_hash"] = safepay_v2_quote_hash(
        quote_id=quote["quote_id"], proposal_id=quote["proposal_id"], resource_id=quote["resource_id"],
        network=quote["network"], payee_account_hash=quote["payee_account_hash"],
        amount_motes=quote["amount_motes"], correlation_id=int(quote["correlation_id"]),
        report_version=quote["report_version"], report_hash=quote["report_hash"],
        expires_at=quote["expires_at"], quote_nonce=bytes.fromhex(quote["quote_nonce"]),
    )
    cross_quote = {**quote, "quote_id": "223e4567-e89b-42d3-a456-426614174000", "resource_id": "risk-report:other", "quote_nonce": "fe" * 32}
    cross_quote["correlation_id"] = str(
        safepay_v2_correlation_id(
            cross_quote["quote_id"], cross_quote["proposal_id"], cross_quote["resource_id"], bytes.fromhex(cross_quote["quote_nonce"])
        )
    )
    cross_quote["quote_hash"] = safepay_v2_quote_hash(
        quote_id=cross_quote["quote_id"], proposal_id=cross_quote["proposal_id"], resource_id=cross_quote["resource_id"],
        network=cross_quote["network"], payee_account_hash=cross_quote["payee_account_hash"],
        amount_motes=cross_quote["amount_motes"], correlation_id=int(cross_quote["correlation_id"]),
        report_version=cross_quote["report_version"], report_hash=cross_quote["report_hash"],
        expires_at=cross_quote["expires_at"], quote_nonce=bytes.fromhex(cross_quote["quote_nonce"]),
    )
    return {
        "schema_version": "concordia.safepay_v2_capture_plan_input.v1",
        "wallet_intent": {
            "schema_version": "safepay-wallet-intent-v2",
            "status": "ready",
            "quote": quote,
            "payment_requirements": {key: quote[key] for key in ("network", "payee_account_hash", "amount_motes", "correlation_id", "expires_at")},
        },
        "payment_hash": "34" * 32,
        "cross_binding_quote": cross_quote,
    }


def _official_input() -> dict[str, object]:
    signed_payload = {
        "x402Version": 2,
        "resource": {"url": "https://x402.concordiadao.xyz/resource/report-1"},
        "accepted": {
            "network": "casper:casper-test",
            "asset": "ab" * 32,
            "scheme": "exact",
            "amount": "1",
            "payTo": "00" + "cd" * 32,
            "extra": {"name": "Wrapped CSPR", "version": "1"},
        },
        "payload": {
            "signature": "01" + "ef" * 64,
            "publicKey": "01" + "34" * 32,
            "authorization": {
                "from": "00" + "56" * 32,
                "to": "00" + "cd" * 32,
                "value": "1",
                "validAfter": "1",
                "validBefore": "2",
                "nonce": "78" * 32,
            },
        },
    }
    request = {
        "x402Version": 2,
        "paymentPayload": signed_payload,
        "paymentRequirements": signed_payload["accepted"],
    }
    raw = _canonical(request)
    imported = {
        "schema_version": "concordia.official_x402_imported_authorization.v1",
        "network": "casper:casper-test",
        "payee_account_hash": "cd" * 32,
        "signature_hex": signed_payload["payload"]["signature"],
        "public_key_hex": signed_payload["payload"]["publicKey"],
        "signed_payment_payload": signed_payload,
        "facilitator_request": request,
        "frozen_verify_request_body_base64": base64.b64encode(raw).decode(),
        "frozen_settle_request_body_base64": base64.b64encode(raw).decode(),
        "frozen_request_body_sha256": __import__("hashlib").sha256(raw).hexdigest(),
    }
    return {
        "schema_version": "concordia.official_x402_capture_plan_input.v1",
        "imported_authorization": imported,
        "v3_proof_bytes_base64": base64.b64encode(b'{"proof":"frozen"}\n').decode(),
        "report_bytes_base64": base64.b64encode(b'{"report":"frozen"}\n').decode(),
        "cross_binding_resource_url": "https://x402.concordiadao.xyz/resource/report-other",
    }


def _load_module():
    from scripts import build_live_capture_plan as plans

    return plans


def _assert_no_observed_plan_material(value: object) -> None:
    forbidden = ("response", "observed", "runtime", "live", "secret")
    if isinstance(value, dict):
        for key, nested in value.items():
            assert not any(label in key.lower() for label in forbidden)
            _assert_no_observed_plan_material(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_no_observed_plan_material(nested)
    elif isinstance(value, str):
        # The collector schema name itself contains "live"; all other plan
        # values are static input or request material and must not carry a
        # capture-status label.
        if value != collector.PLAN_SCHEMA_VERSION:
            assert not any(label in value.lower() for label in forbidden)


@pytest.mark.parametrize(
    ("proof_id", "inputs", "expected"),
    [
        (
            "safepay_v2",
            _safepay_input(),
            {
                "redemption_first_consumption",
                "redemption_exact_retry",
                "redemption_cross_binding_reuse",
            },
        ),
        (
            "official_x402_settlement_v1",
            _official_input(),
            {
                "facilitator_supported",
                "facilitator_verify",
                "facilitator_settle",
                "paid_first_release",
                "paid_exact_retry",
                "paid_cross_binding_reuse",
            },
        ),
    ],
)
def test_builds_exact_collector_inventory_without_observed_data(
    proof_id: str, inputs: dict[str, object], expected: set[str]
) -> None:
    plans = _load_module()
    plan = plans.build_capture_plan(
        proof_id=proof_id,
        source_commit="11" * 20,
        deployment_commit="22" * 20,
        inputs=inputs,
    )

    assert set(plan["requests"]) == expected
    assert collector._validate_plan_document(plan) == plan
    _assert_no_observed_plan_material(plan)


@pytest.mark.parametrize("raw", [
    b'{"schema_version":"x","schema_version":"x"}',
    b'{"schema_version":NaN}',
    b'{ "schema_version":"x"}\n',
])
def test_strict_plan_input_loader_rejects_duplicate_nonfinite_and_noncanonical_json(raw: bytes) -> None:
    plans = _load_module()
    with pytest.raises(plans.CapturePlanError):
        plans.load_canonical_input(raw)


@pytest.mark.parametrize(
    ("proof_id", "inputs", "needle"),
    [
        ("safepay_v2", {**_safepay_input(), "wallet_intent": {**_safepay_input()["wallet_intent"], "quote": {**_safepay_input()["wallet_intent"]["quote"], "network": "casper:mainnet"}}}, "network"),
        ("safepay_v2", {**_safepay_input(), "cross_binding_quote": {**_safepay_input()["cross_binding_quote"], "resource_id": _safepay_input()["wallet_intent"]["quote"]["resource_id"]}}, "resource"),
        ("safepay_v2", {**_safepay_input(), "wallet_intent": {**_safepay_input()["wallet_intent"], "quote": {**_safepay_input()["wallet_intent"]["quote"], "quote_hash": "00" * 32}}}, "quote"),
        ("official_x402_settlement_v1", {**_official_input(), "imported_authorization": {**_official_input()["imported_authorization"], "network": "casper:mainnet"}}, "network"),
        ("official_x402_settlement_v1", {**_official_input(), "cross_binding_resource_url": "https://elsewhere.invalid/resource/x"}, "resource"),
        ("official_x402_settlement_v1", {**_official_input(), "imported_authorization": {**_official_input()["imported_authorization"], "signature_hex": "01" + "00" * 64}}, "signature"),
    ],
)
def test_refuses_wrong_fixed_bindings(proof_id: str, inputs: dict[str, object], needle: str) -> None:
    plans = _load_module()
    with pytest.raises(plans.CapturePlanError, match=needle):
        plans.build_capture_plan(
            proof_id=proof_id,
            source_commit="11" * 20,
            deployment_commit="22" * 20,
            inputs=inputs,
        )


@pytest.mark.parametrize(
    ("proof_id", "inputs"),
    [
        ("safepay_v2", {**_safepay_input(), "rpc_requests": {"casper_rpc_a_info_get_deploy": "e30="}}),
        ("official_x402_settlement_v1", {**_official_input(), "settlement_requests": {"info_get_transaction": "e30="}}),
        ("official_x402_settlement_v1", {**_official_input(), "wcspr_requests": {}}),
    ],
)
def test_refuses_caller_supplied_runtime_selectors(proof_id: str, inputs: dict[str, object]) -> None:
    plans = _load_module()
    with pytest.raises(plans.CapturePlanError, match="runtime"):
        plans.build_capture_plan(
            proof_id=proof_id,
            source_commit="11" * 20,
            deployment_commit="22" * 20,
            inputs=inputs,
        )


def test_writes_fixed_canonical_path_once(tmp_path: Path) -> None:
    plans = _load_module()
    path = plans.write_capture_plan_once(
        repository_root=tmp_path,
        proof_id="safepay_v2",
        source_commit="11" * 20,
        deployment_commit="22" * 20,
        inputs=_safepay_input(),
    )
    assert path == tmp_path / "release/capture-plans/safepay-v2.json"
    raw = path.read_bytes()
    assert raw == _canonical(json.loads(raw))
    with pytest.raises(plans.CapturePlanError, match="already exists"):
        plans.write_capture_plan_once(
            repository_root=tmp_path,
            proof_id="safepay_v2",
            source_commit="11" * 20,
            deployment_commit="22" * 20,
            inputs=_safepay_input(),
        )
