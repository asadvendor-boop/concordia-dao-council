from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import shared.official_x402_release_adapter as official_adapter
from shared.release_proof_adapters import (
    ReleaseProofAdapterError,
    verify_official_x402_artifact,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_SOURCE = ROOT / "tests" / "test_release_official_x402_adapter.py"


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
