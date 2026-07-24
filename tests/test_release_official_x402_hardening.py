from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

import shared.official_x402_release_adapter as official_adapter
from shared.release_proof_adapters import (
    ReleaseProofAdapterError,
    verify_official_x402_artifact,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_SOURCE = ROOT / "tests" / "test_release_official_x402_adapter.py"
SECP256K1_ORDER = int(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    16,
)
UPSTREAM_SECP_PRIVATE_VALUE = int("11" * 32, 16)
UPSTREAM_SECP_DIGEST = bytes.fromhex(
    "51aeaf3aa87aeddde5ccbd96882501eb88b74519efb9d818beb28a4c2b7125dc"
)
UPSTREAM_SECP_PUBLIC_KEY = bytes.fromhex(
    "02034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
)
UPSTREAM_SECP_ACCOUNT_HASH = bytes.fromhex(
    "c863d586aaf1385967d64d1408c3eef500c1df401db5203bce3d8e1113c76234"
)
UPSTREAM_SECP_SIGNATURE = bytes.fromhex(
    "027a807a0e018e288eb22bb6caa28cee356148a69c4e12bb9bb5745c5d967e44"
    "a75d610482cc54f90869e1be1bda456a0f302742db2a958f623af40b77a3a8b853"
)


@lru_cache(maxsize=1)
def _fixture_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "_official_x402_fixture_source",
        FIXTURE_SOURCE,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("official x402 fixture source cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _artifact() -> dict[str, Any]:
    module = _fixture_module()
    fixture = module.official_x402_artifact
    return copy.deepcopy(fixture.__wrapped__())


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _verify(artifact: dict[str, Any]) -> dict[str, Any]:
    return verify_official_x402_artifact(artifact, _canonical(artifact))


def _secp256k1_artifact() -> dict[str, Any]:
    artifact = _artifact()
    module = _fixture_module()
    private_key = ec.derive_private_key(
        UPSTREAM_SECP_PRIVATE_VALUE,
        ec.SECP256K1(),
    )
    public_key_raw = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    )
    public_key = b"\x02" + public_key_raw
    payer_account_hash = module._blake2b256(
        b"secp256k1\x00" + public_key_raw
    )
    eip712_digest = module._eip712_digest(
        payer_account_hash=payer_account_hash,
        payee_account_hash=module.PAYEE_ACCOUNT_HASH,
        value_atomic=module.AMOUNT_ATOMIC,
        valid_after=module.VALID_AFTER,
        valid_before=module.VALID_BEFORE,
        nonce=module.NONCE,
    )
    der_signature = private_key.sign(
        eip712_digest,
        ec.ECDSA(hashes.SHA256()),
    )
    r, s = utils.decode_dss_signature(der_signature)
    if s > SECP256K1_ORDER // 2:
        s = SECP256K1_ORDER - s
    signature = b"\x02" + r.to_bytes(32, "big") + s.to_bytes(32, "big")

    report_bytes = base64.b64decode(
        artifact["protected_report"]["content_base64"],
        validate=True,
    )
    resource_hash = module._resource_url_hash()
    report_digest = module._report_hash(report_bytes)
    requirements_digest = module._payment_requirements_hash()
    signed_payload_digest = module._signed_payload_hash(
        signature=signature,
        public_key=public_key,
        payer_account_hash=payer_account_hash,
        payment_requirements_hash=requirements_digest,
    )
    resource = {
        "url": module.RESOURCE_URL,
        "description": module.RESOURCE_DESCRIPTION,
        "mimeType": module.RESOURCE_MIME,
    }
    requirements = _decoded_json(
        artifact["resource_and_payment"],
        "accepted_json",
    )
    domain = {
        "name": module.TOKEN_NAME,
        "version": module.TOKEN_DOMAIN_VERSION,
        "chain_name": module.NETWORK,
        "contract_package_hash": "0x" + module.WCSPR_PACKAGE,
    }
    authorization = {
        "from": "00" + payer_account_hash.hex(),
        "to": "00" + module.PAYEE_ACCOUNT_HASH.hex(),
        "value": str(module.AMOUNT_ATOMIC),
        "validAfter": str(module.VALID_AFTER),
        "validBefore": str(module.VALID_BEFORE),
        "nonce": module.NONCE.hex(),
    }
    payment_payload = {
        "x402Version": 2,
        "resource": resource,
        "accepted": copy.deepcopy(requirements),
        "payload": {
            "signature": signature.hex(),
            "publicKey": public_key.hex(),
            "authorization": authorization,
        },
    }
    facilitator_request = {
        "x402Version": 2,
        "paymentPayload": payment_payload,
        "paymentRequirements": copy.deepcopy(requirements),
    }
    payment_payload_bytes = _canonical(payment_payload)
    facilitator_request_bytes = _canonical(facilitator_request)
    runtime_args = module._runtime_args(
        payer_account_hash=payer_account_hash,
        public_key=public_key,
        signature=signature,
    )
    v3_proof, prepared, identities = module._customized_official_v3_proof(
        payer_account_hash=payer_account_hash,
        resource_url_hash=resource_hash,
        report_hash=report_digest,
        payment_requirements_hash=requirements_digest,
        signed_payment_payload_hash=signed_payload_digest,
    )
    v3_proof_bytes = _canonical(v3_proof)
    v3_verification = module.verify_v3_proof_document(v3_proof)
    finalization_step = next(
        step
        for step in v3_proof["run"]["steps"]
        if step["name"] == "finalize_exact"
    )
    finalization_outcome = v3_verification["contract_step_outcomes"][
        "finalize_exact"
    ]
    settlement_response = {
        "success": True,
        "transaction": module.SETTLEMENT_TRANSACTION,
        "network": module.NETWORK,
        "payer": "00" + payer_account_hash.hex(),
    }
    settlement_response_bytes = _canonical(settlement_response)
    row = _decoded_json(
        artifact["fulfillment"]["first_row"],
        "row_canonical_json",
    )
    row.update(
        {
            "signedPaymentPayloadHash": signed_payload_digest.hex(),
            "actionId": prepared["action_id"],
            "envelopeHash": prepared["envelope_hash"],
            "payerAccountHash": payer_account_hash.hex(),
            "publicKey": public_key.hex(),
            "signature": signature.hex(),
            "settlementResponseHash": hashlib.sha256(
                settlement_response_bytes
            ).hexdigest(),
            "responseJson": settlement_response_bytes.decode("ascii"),
        }
    )
    cross_payment_payload = copy.deepcopy(payment_payload)
    cross_payment_payload["resource"]["url"] = (
        "https://x402.concordiadao.xyz/resource/other-report"
    )

    artifact["governance_binding"] = {
        "proposal_id": v3_proof["input"]["header"]["proposal_id"],
        "proposal_hash": v3_proof["input"]["header"]["proposal_hash"],
        "proposal_nonce": v3_proof["input"]["header"]["proposal_nonce"],
        "action_id": prepared["action_id"],
        "action_kind": "OfficialX402SettlementV1",
        "action_version": 1,
        "envelope_hash": prepared["envelope_hash"],
        "deployment_domain": v3_proof["input"]["header"][
            "deployment_domain"
        ],
        "network": module.NETWORK,
        "package_hash": identities["package"],
        "contract_hash": identities["contract"],
        "finalization_transaction": finalization_step["deploy_hash"],
        "finalized_at": finalization_outcome["finalized_at"],
        "observed_at": finalization_outcome["observed_at"],
        "resource_url_hash": resource_hash.hex(),
        "payment_requirements_hash": requirements_digest.hex(),
        "signed_payment_payload_hash": signed_payload_digest.hex(),
        "report_hash": report_digest.hex(),
        "v3_proof_sha256": hashlib.sha256(v3_proof_bytes).hexdigest(),
        "v3_proof_bytes_base64": base64.b64encode(v3_proof_bytes).decode(
            "ascii"
        ),
    }
    artifact["authorization"] = {
        "eip712_domain_json_base64": base64.b64encode(
            _canonical(domain)
        ).decode("ascii"),
        "eip712_authorization_preimage_base64": base64.b64encode(
            eip712_digest
        ).decode("ascii"),
        "signed_payment_payload_json_base64": base64.b64encode(
            payment_payload_bytes
        ).decode("ascii"),
        "signature_hex": signature.hex(),
        "public_key_hex": public_key.hex(),
        "recovered_payer_account_hash": payer_account_hash.hex(),
        "payer_account_hash": payer_account_hash.hex(),
        "payee_account_hash": module.PAYEE_ACCOUNT_HASH.hex(),
        "value_atomic": str(module.AMOUNT_ATOMIC),
        "nonce_hex": module.NONCE.hex(),
        "valid_after": str(module.VALID_AFTER),
        "valid_before": str(module.VALID_BEFORE),
        "payment_requirements_hash": requirements_digest.hex(),
        "signed_payment_payload_hash": signed_payload_digest.hex(),
    }
    artifact["facilitator"]["verify"] = module._exchange(
        method="POST",
        url="https://x402-facilitator.cspr.cloud/verify",
        request_bytes=facilitator_request_bytes,
        response={
            "isValid": True,
            "payer": "00" + payer_account_hash.hex(),
        },
        observed_at="2026-07-22T20:20:00Z",
    )
    artifact["facilitator"]["settle"] = module._exchange(
        method="POST",
        url="https://x402-facilitator.cspr.cloud/settle",
        request_bytes=facilitator_request_bytes,
        response=settlement_response,
        observed_at="2026-07-22T20:21:00Z",
    )
    artifact["facilitator"]["parsed_verify"]["payer_account_hash"] = (
        payer_account_hash.hex()
    )
    artifact["facilitator"]["parsed_settle"]["payer_account_hash"] = (
        payer_account_hash.hex()
    )
    artifact["wcspr_readbacks"] = {
        "pre_verify": module._wcspr_readback(
            runtime_args,
            phase="pre-verify",
            observed_at="2026-07-22T20:19:00Z",
        ),
        "pre_settle": module._wcspr_readback(
            runtime_args,
            phase="pre-settle",
            observed_at="2026-07-22T20:20:30Z",
        ),
        "post_settle": module._wcspr_readback(
            runtime_args,
            phase="post-settle",
            observed_at=module.SETTLEMENT_FINALIZED_AT,
        ),
    }
    artifact["settlement_chain_evidence"]["providers"] = [
        module._settlement_provider(
            "casper-testnet-rpc",
            "https://node.testnet.casper.network/rpc",
            runtime_args,
        ),
        module._settlement_provider(
            "cspr-cloud-testnet",
            "https://node.testnet.cspr.cloud/rpc",
            runtime_args,
        ),
    ]
    artifact["settlement_chain_evidence"]["parsed_settlement"][
        "runtime_args"
    ] = copy.deepcopy(runtime_args)
    artifact["fulfillment"] = {
        "first_row": module._row_observation(
            row,
            observed_at=module.SETTLEMENT_FINALIZED_AT,
            instance_id="x402-official-a",
        ),
        "post_restart_row": module._row_observation(
            row,
            observed_at="2026-07-22T20:25:30Z",
            instance_id="x402-official-b",
        ),
        "first_release": module._paid_resource_exchange(
            url=(
                "https://x402.concordiadao.xyz/resource/"
                "finals-report-001"
            ),
            payment_payload=payment_payload,
            response_body=report_bytes,
            status=200,
            payment_response=settlement_response,
            observed_at=module.REPORT_RELEASED_AT,
        ),
        "exact_retry": module._paid_resource_exchange(
            url=(
                "https://x402.concordiadao.xyz/resource/"
                "finals-report-001"
            ),
            payment_payload=payment_payload,
            response_body=report_bytes,
            status=200,
            payment_response=settlement_response,
            observed_at="2026-07-22T20:25:35Z",
        ),
        "cross_binding_reuse": module._paid_resource_exchange(
            url=(
                "https://x402.concordiadao.xyz/resource/"
                "other-report"
            ),
            payment_payload=cross_payment_payload,
            response_body=_canonical({"error": "cross_binding_rejected"}),
            status=409,
            payment_response=None,
            observed_at="2026-07-22T20:25:40Z",
        ),
        "upstream_settle_journal": module._upstream_settle_journal(
            row=row,
            request_bytes=facilitator_request_bytes,
            response_bytes=settlement_response_bytes,
        ),
    }
    artifact["release_order"]["v3_finalized_at"] = finalization_outcome[
        "finalized_at"
    ]
    return artifact


def test_official_cspr_click_secp256k1_vector_matches_python_verifier() -> None:
    assert (
        official_adapter._account_hash_from_public_key(UPSTREAM_SECP_PUBLIC_KEY)
        == UPSTREAM_SECP_ACCOUNT_HASH
    )

    official_adapter._verify_casper_eip712_signature(
        public_key=UPSTREAM_SECP_PUBLIC_KEY,
        signature=UPSTREAM_SECP_SIGNATURE,
        digest=UPSTREAM_SECP_DIGEST,
    )


def test_complete_official_x402_secp256k1_artifact_is_accepted() -> None:
    result = _verify(_secp256k1_artifact())

    assert result["internal_record"]["verification_status"] == "verified"


def test_secp256k1_signature_rejects_mismatched_algorithm_tag() -> None:
    mismatched = b"\x01" + UPSTREAM_SECP_SIGNATURE[1:]

    with pytest.raises(
        official_adapter.OfficialX402ReleaseAdapterError,
        match="signature algorithm tag differs",
    ):
        official_adapter._verify_casper_eip712_signature(
            public_key=UPSTREAM_SECP_PUBLIC_KEY,
            signature=mismatched,
            digest=UPSTREAM_SECP_DIGEST,
        )


def test_secp256k1_signature_hashes_the_eip712_digest_once_like_casper_sdk() -> None:
    private_key = ec.derive_private_key(
        UPSTREAM_SECP_PRIVATE_VALUE,
        ec.SECP256K1(),
    )
    der_signature = private_key.sign(
        UPSTREAM_SECP_DIGEST,
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )
    r, s = utils.decode_dss_signature(der_signature)
    if s > SECP256K1_ORDER // 2:
        s = SECP256K1_ORDER - s
    prehashed_signature = (
        b"\x02" + r.to_bytes(32, "big") + s.to_bytes(32, "big")
    )

    with pytest.raises(
        official_adapter.OfficialX402ReleaseAdapterError,
        match="secp256k1 EIP-712 signature is invalid",
    ):
        official_adapter._verify_casper_eip712_signature(
            public_key=UPSTREAM_SECP_PUBLIC_KEY,
            signature=prehashed_signature,
            digest=UPSTREAM_SECP_DIGEST,
        )


def test_secp256k1_signature_rejects_noncanonical_high_s() -> None:
    r = int.from_bytes(UPSTREAM_SECP_SIGNATURE[1:33], "big")
    s = int.from_bytes(UPSTREAM_SECP_SIGNATURE[33:], "big")
    high_s_signature = (
        b"\x02"
        + r.to_bytes(32, "big")
        + (SECP256K1_ORDER - s).to_bytes(32, "big")
    )

    with pytest.raises(
        official_adapter.OfficialX402ReleaseAdapterError,
        match="non-canonical high-S",
    ):
        official_adapter._verify_casper_eip712_signature(
            public_key=UPSTREAM_SECP_PUBLIC_KEY,
            signature=high_s_signature,
            digest=UPSTREAM_SECP_DIGEST,
        )


def test_capture_cannot_be_even_slightly_future_dated() -> None:
    artifact = _artifact()
    artifact["captured_at"] = (
        (datetime.now(UTC) + timedelta(minutes=1))
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )

    with pytest.raises(ReleaseProofAdapterError, match="captured_at is in the future"):
        _verify(artifact)


def _decoded_json(exchange: dict[str, Any], field: str) -> Any:
    return json.loads(base64.b64decode(exchange[f"{field}_base64"]))


def _replace_json(
    exchange: dict[str, Any],
    field: str,
    value: object,
) -> None:
    raw = _canonical(value)
    exchange[f"{field}_base64"] = base64.b64encode(raw).decode("ascii")
    exchange[f"{field}_sha256"] = hashlib.sha256(raw).hexdigest()


def _replace_raw_json(
    exchange: dict[str, Any],
    field: str,
    raw: bytes,
) -> None:
    json.loads(raw)
    exchange[f"{field}_base64"] = base64.b64encode(raw).decode("ascii")
    exchange[f"{field}_sha256"] = hashlib.sha256(raw).hexdigest()


def _use_noncanonical_raw_settle_response(
    artifact: dict[str, Any],
) -> bytes:
    module = _fixture_module()
    settle = artifact["facilitator"]["settle"]
    parsed = _decoded_json(settle, "response_body")
    raw = (
        b'{"transaction":'
        + json.dumps(parsed["transaction"]).encode("ascii")
        + b',"network":"casper:casper\\u002dtest","success":true,"payer":'
        + json.dumps(parsed["payer"]).encode("ascii")
        + b"}"
    )
    _replace_raw_json(settle, "response_body", raw)

    first_observation = artifact["fulfillment"]["first_row"]
    first_row = _decoded_json(first_observation, "row_canonical_json")
    first_row["settlementResponseHash"] = hashlib.sha256(raw).hexdigest()
    first_row["responseJson"] = raw.decode("ascii")
    _replace_json(first_observation, "row_canonical_json", first_row)

    restarted_observation = artifact["fulfillment"]["post_restart_row"]
    _replace_json(restarted_observation, "row_canonical_json", first_row)

    request_raw = base64.b64decode(settle["request_body_base64"], validate=True)
    artifact["fulfillment"]["upstream_settle_journal"] = (
        module._upstream_settle_journal(
            row=first_row,
            request_bytes=request_raw,
            response_bytes=raw,
        )
    )
    return raw


def test_raw_upstream_settle_response_need_not_be_canonical_json() -> None:
    artifact = _artifact()
    raw = _use_noncanonical_raw_settle_response(artifact)

    result = _verify(artifact)

    assert (
        result["derived_facts"]["settlement_transaction"]
        == json.loads(raw)["transaction"]
    )


def _use_real_casper_rpc_clvalues(artifact: dict[str, Any]) -> None:
    runtime_args = artifact["wcspr_readbacks"]["pre_verify"]["runtime_args"]
    entry_point_args = [
        {
            "name": argument["name"],
            "cl_type": (
                {"List": "U8"}
                if argument["cl_type"] == "List<U8>"
                else argument["cl_type"]
            ),
        }
        for argument in runtime_args
    ]

    for readback in artifact["wcspr_readbacks"].values():
        exchange = readback["rpc_transcript"]
        responses = _decoded_json(exchange, "response_body")
        contract_response = next(
            response
            for response in responses
            if "stored_value" in response["result"]
        )
        contract_response["result"]["stored_value"]["Contract"][
            "entry_points"
        ][0]["args"] = copy.deepcopy(entry_point_args)
        _replace_json(exchange, "response_body", responses)


def _truthful_retry_chronology(artifact: dict[str, Any]) -> None:
    fulfillment = artifact["fulfillment"]
    fulfillment["first_row"]["observed_at"] = "2026-07-22T20:25:00Z"
    fulfillment["first_release"]["observed_at"] = "2026-07-22T20:25:10Z"
    fulfillment["post_restart_row"]["observed_at"] = "2026-07-22T20:25:30Z"
    fulfillment["exact_retry"]["observed_at"] = "2026-07-22T20:25:35Z"
    fulfillment["cross_binding_reuse"]["observed_at"] = "2026-07-22T20:25:40Z"
    artifact["release_order"]["report_released_at"] = "2026-07-22T20:25:10Z"

    snapshots = fulfillment["upstream_settle_journal"]["snapshots"]
    snapshots["after_first_release"]["observed_at"] = "2026-07-22T20:25:20Z"
    snapshots["after_first_release"]["service_instance_id"] = "x402-official-a"
    snapshots["after_exact_retry"]["observed_at"] = "2026-07-22T20:25:36Z"
    snapshots["after_exact_retry"]["service_instance_id"] = "x402-official-b"
    snapshots["after_cross_binding_reuse"]["observed_at"] = (
        "2026-07-22T20:25:41Z"
    )
    snapshots["after_cross_binding_reuse"]["service_instance_id"] = (
        "x402-official-b"
    )


def _invalid_retry_before_first_release(artifact: dict[str, Any]) -> None:
    fulfillment = artifact["fulfillment"]
    fulfillment["first_row"]["observed_at"] = "2026-07-22T20:25:00Z"
    fulfillment["first_row"]["service_instance_id"] = "x402-official-a"
    fulfillment["post_restart_row"]["observed_at"] = "2026-07-22T20:25:30Z"
    fulfillment["post_restart_row"]["service_instance_id"] = "x402-official-b"
    fulfillment["first_release"]["observed_at"] = "2026-07-22T20:26:00Z"
    fulfillment["exact_retry"]["observed_at"] = "2026-07-22T20:25:35Z"
    fulfillment["cross_binding_reuse"]["observed_at"] = "2026-07-22T20:25:40Z"
    artifact["release_order"]["report_released_at"] = "2026-07-22T20:26:00Z"

    snapshots = fulfillment["upstream_settle_journal"]["snapshots"]
    snapshots["after_first_release"]["observed_at"] = "2026-07-22T20:26:00Z"
    snapshots["after_first_release"]["service_instance_id"] = "x402-official-a"
    snapshots["after_exact_retry"]["observed_at"] = "2026-07-22T20:25:35Z"
    snapshots["after_exact_retry"]["service_instance_id"] = "x402-official-a"
    snapshots["after_cross_binding_reuse"]["observed_at"] = (
        "2026-07-22T20:25:40Z"
    )
    snapshots["after_cross_binding_reuse"]["service_instance_id"] = (
        "x402-official-b"
    )


def test_real_casper_rpc_clvalue_encoding_is_accepted() -> None:
    artifact = _artifact()
    _use_real_casper_rpc_clvalues(artifact)

    result = _verify(artifact)

    assert result["internal_record"]["verification_status"] == "verified"


def test_duplicate_rpc_transcript_cannot_be_relabelled_as_second_provider() -> None:
    artifact = _artifact()
    providers = artifact["settlement_chain_evidence"]["providers"]
    providers[1] = copy.deepcopy(providers[0])
    providers[1]["endpoint_id"] = "relabelled-second-provider"
    providers[1]["origin"] = "https://second-provider.invalid/rpc"

    with pytest.raises(
        ReleaseProofAdapterError,
        match=r"^settlement_transaction_finalized_without_execution_error:",
    ):
        _verify(artifact)


def test_wcspr_readback_must_use_exact_state_identifier_and_empty_path() -> None:
    artifact = _artifact()
    exchange = artifact["wcspr_readbacks"]["pre_verify"]["rpc_transcript"]
    requests = _decoded_json(exchange, "request_body")
    requests[2]["params"]["state_identifier"] = {"BlockHash": "aa" * 32}
    requests[2]["params"]["path"] = ["not-the-contract-root"]
    _replace_json(exchange, "request_body", requests)

    with pytest.raises(
        ReleaseProofAdapterError,
        match=r"^active_wcspr_v8_pre_verify_drift_guard_passed:",
    ):
        _verify(artifact)


def test_wcspr_v8_is_rejected_when_newer_enabled_version_exists() -> None:
    artifact = _artifact()
    exchange = artifact["wcspr_readbacks"]["pre_verify"]["rpc_transcript"]
    responses = _decoded_json(exchange, "response_body")
    package = next(
        response["result"]["package"]["ContractPackage"]
        for response in responses
        if "package" in response["result"]
    )
    package["versions"].append(
        {
            "protocol_version_major": 2,
            "contract_version": 9,
            "contract_hash": f"contract-{'ab' * 32}",
        }
    )
    _replace_json(exchange, "response_body", responses)

    with pytest.raises(
        ReleaseProofAdapterError,
        match=r"^active_wcspr_v8_pre_verify_drift_guard_passed:",
    ):
        _verify(artifact)


def test_retry_and_cross_binding_reuse_cannot_precede_first_release() -> None:
    artifact = _artifact()
    _invalid_retry_before_first_release(artifact)

    with pytest.raises(
        ReleaseProofAdapterError,
        match=(
            r"^(?:exact_retry_returned_stored_fulfillment_without_second_settlement"
            r"|protected_report_released_only_after_finalized_state):"
        ),
    ):
        _verify(artifact)


def test_truthful_restart_then_retry_chronology_is_accepted() -> None:
    artifact = _artifact()
    _truthful_retry_chronology(artifact)

    result = _verify(artifact)

    assert result["internal_record"]["verification_status"] == "verified"


def test_repository_journal_migration_is_mandatory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    artifact = _artifact()
    monkeypatch.setattr(official_adapter, "_ROOT", tmp_path)

    with pytest.raises(
        ReleaseProofAdapterError,
        match=(
            r"^exact_retry_returned_stored_fulfillment_without_second_settlement:"
            r" repository migration cannot be read:"
        ),
    ):
        _verify(artifact)


def test_execution_result_must_explicitly_contain_no_error() -> None:
    artifact = _artifact()
    for provider in artifact["settlement_chain_evidence"]["providers"]:
        exchange = provider["info_get_transaction"]
        response = _decoded_json(exchange, "response_body")
        del response["result"]["execution_info"]["execution_result"][
            "Version2"
        ]["error_message"]
        _replace_json(exchange, "response_body", response)

    with pytest.raises(
        ReleaseProofAdapterError,
        match=r"^settlement_transaction_finalized_without_execution_error:",
    ):
        _verify(artifact)


def test_settlement_block_proof_entries_must_be_well_formed() -> None:
    artifact = _artifact()
    for provider in artifact["settlement_chain_evidence"]["providers"]:
        exchange = provider["chain_get_block"]
        response = _decoded_json(exchange, "response_body")
        response["result"]["block_with_signatures"]["proofs"] = [{}]
        _replace_json(exchange, "response_body", response)

    with pytest.raises(
        ReleaseProofAdapterError,
        match=r"^settlement_transaction_finalized_without_execution_error:",
    ):
        _verify(artifact)


@pytest.mark.parametrize(
    ("public_key", "signature"),
    (
        ("03" + "11" * 32, "03" + "22" * 64),
        ("01" + "11" * 32, "02" + "22" * 64),
    ),
)
def test_settlement_block_proof_requires_valid_matching_casper_tags(
    public_key: str,
    signature: str,
) -> None:
    artifact = _artifact()
    for provider in artifact["settlement_chain_evidence"]["providers"]:
        exchange = provider["chain_get_block"]
        response = _decoded_json(exchange, "response_body")
        response["result"]["block_with_signatures"]["proofs"] = [
            {
                "public_key": public_key,
                "signature": signature,
            }
        ]
        _replace_json(exchange, "response_body", response)

    with pytest.raises(
        ReleaseProofAdapterError,
        match=r"^settlement_transaction_finalized_without_execution_error:",
    ):
        _verify(artifact)


def test_settlement_block_proof_rejects_duplicate_signer() -> None:
    artifact = _artifact()
    for provider in artifact["settlement_chain_evidence"]["providers"]:
        exchange = provider["chain_get_block"]
        response = _decoded_json(exchange, "response_body")
        proofs = response["result"]["block_with_signatures"]["proofs"]
        proofs.append(copy.deepcopy(proofs[0]))
        _replace_json(exchange, "response_body", response)

    with pytest.raises(
        ReleaseProofAdapterError,
        match=r"^settlement_transaction_finalized_without_execution_error:",
    ):
        _verify(artifact)


def test_status_node_signing_key_requires_valid_casper_tag() -> None:
    artifact = _artifact()
    for provider in artifact["settlement_chain_evidence"]["providers"]:
        exchange = provider["info_get_status"]
        response = _decoded_json(exchange, "response_body")
        response["result"]["our_public_signing_key"] = "03" + "11" * 32
        _replace_json(exchange, "response_body", response)

    with pytest.raises(
        ReleaseProofAdapterError,
        match=r"^settlement_transaction_finalized_without_execution_error:",
    ):
        _verify(artifact)


@pytest.mark.parametrize("block_height", (True, -1))
def test_settlement_block_height_requires_nonnegative_integer(
    block_height: object,
) -> None:
    artifact = _artifact()
    for provider in artifact["settlement_chain_evidence"]["providers"]:
        transaction_exchange = provider["info_get_transaction"]
        transaction_response = _decoded_json(
            transaction_exchange,
            "response_body",
        )
        transaction_response["result"]["execution_info"]["block_height"] = (
            block_height
        )
        _replace_json(
            transaction_exchange,
            "response_body",
            transaction_response,
        )

        block_exchange = provider["chain_get_block"]
        block_response = _decoded_json(block_exchange, "response_body")
        block_response["result"]["block_with_signatures"]["block"]["Version2"][
            "header"
        ]["height"] = block_height
        _replace_json(block_exchange, "response_body", block_response)

    with pytest.raises(
        ReleaseProofAdapterError,
        match=r"^settlement_transaction_finalized_without_execution_error:",
    ):
        _verify(artifact)


def test_settlement_status_tip_height_rejects_boolean() -> None:
    artifact = _artifact()
    for provider in artifact["settlement_chain_evidence"]["providers"]:
        exchange = provider["info_get_status"]
        response = _decoded_json(exchange, "response_body")
        response["result"]["last_added_block_info"]["height"] = True
        _replace_json(exchange, "response_body", response)

    with pytest.raises(
        ReleaseProofAdapterError,
        match=r"^settlement_transaction_finalized_without_execution_error:",
    ):
        _verify(artifact)


def test_strict_integer_settlement_heights_are_accepted() -> None:
    artifact = _artifact()

    result = _verify(artifact)

    assert result["internal_record"]["verification_status"] == "verified"


def test_wcspr_readback_status_rejects_invalid_casper_key_tag() -> None:
    artifact = _artifact()
    for readback in artifact["wcspr_readbacks"].values():
        exchange = readback["rpc_transcript"]
        responses = _decoded_json(exchange, "response_body")
        status_response = next(
            response
            for response in responses
            if "last_added_block_info" in response["result"]
        )
        status_response["result"]["our_public_signing_key"] = "03" + "71" * 32
        _replace_json(exchange, "response_body", responses)

    with pytest.raises(
        ReleaseProofAdapterError,
        match=r"^active_wcspr_v8_pre_verify_drift_guard_passed:",
    ):
        _verify(artifact)


def test_wcspr_readback_status_accepts_valid_secp256k1_key_tag() -> None:
    artifact = _artifact()
    for readback in artifact["wcspr_readbacks"].values():
        exchange = readback["rpc_transcript"]
        responses = _decoded_json(exchange, "response_body")
        status_response = next(
            response
            for response in responses
            if "last_added_block_info" in response["result"]
        )
        status_response["result"]["our_public_signing_key"] = "02" + "71" * 33
        _replace_json(exchange, "response_body", responses)

    result = _verify(artifact)

    assert result["internal_record"]["verification_status"] == "verified"


def test_settlement_transaction_must_appear_exactly_once_in_block() -> None:
    artifact = _artifact()
    for provider in artifact["settlement_chain_evidence"]["providers"]:
        exchange = provider["chain_get_block"]
        response = _decoded_json(exchange, "response_body")
        transactions = response["result"]["block_with_signatures"]["block"][
            "Version2"
        ]["body"]["transactions"]["4"]
        transactions.append(copy.deepcopy(transactions[0]))
        _replace_json(exchange, "response_body", response)

    with pytest.raises(
        ReleaseProofAdapterError,
        match=r"^settlement_transaction_finalized_without_execution_error:",
    ):
        _verify(artifact)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("service_url", "https://unrelated.invalid"),
        ("service_deployment_id", "unrelated-deployment"),
    ),
)
def test_capture_identity_is_bound_to_release(
    field: str,
    replacement: str,
) -> None:
    artifact = _artifact()
    artifact["capture_identity"][field] = replacement

    with pytest.raises(
        ReleaseProofAdapterError,
        match=r"^official x402 capture identity differs from the release$",
    ):
        _verify(artifact)
