from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

import pytest
from jsonschema import Draft202012Validator

from shared.release_proof_adapters import (
    ReleaseProofAdapterError,
    verify_safepay_v2_artifact,
)
from shared.x402_payments import (
    SAFEPAY_V2_BINDING_CHECK_FIELDS,
    safepay_v2_body_digest,
    safepay_v2_correlation_id,
    safepay_v2_error_body,
    safepay_v2_quote_hash,
    safepay_v2_response_hash,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "handoff" / "schemas"
UTC = "2026-07-23T01:02:03Z"
SOURCE_COMMIT = "11" * 20
DEPLOYMENT_COMMIT = "22" * 20
PAYMENT_HASH = "33" * 32
BLOCK_HASH = "44" * 32
STATE_ROOT_HASH = "55" * 32
SOURCE_ACCOUNT = "66" * 32
PAYEE_ACCOUNT = "77" * 32
QUOTE_ID = "123e4567-e89b-42d3-a456-426614174000"
PROPOSAL_ID = "DAO-PROP-TEST-1"
RESOURCE_ID = "risk-report:test"
AMOUNT_MOTES = "2500000000"
QUOTE_NONCE = bytes.fromhex("88" * 32)
ISSUED_AT = 1_753_230_000
CONSUMED_AT = ISSUED_AT + 30
EXPIRES_AT = ISSUED_AT + 600
BLOCK_HEIGHT = 8_400_001


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _exchange(
    *,
    url: str,
    request: object,
    response: object,
    status: int,
) -> dict[str, object]:
    request_bytes = _canonical(request)
    response_bytes = _canonical(response)
    return {
        "method": "POST",
        "url": url,
        "request_body_base64": _b64(request_bytes),
        "request_body_sha256": hashlib.sha256(request_bytes).hexdigest(),
        "response_status": status,
        "response_content_type": "application/json",
        "response_body_base64": _b64(response_bytes),
        "response_body_sha256": hashlib.sha256(response_bytes).hexdigest(),
        "observed_at": UTC,
    }


def _rpc_exchange(request: object, response: object) -> dict[str, object]:
    request_bytes = _canonical(request)
    response_bytes = _canonical(response)
    return {
        "request_body_base64": _b64(request_bytes),
        "request_body_sha256": hashlib.sha256(request_bytes).hexdigest(),
        "response_status": 200,
        "response_content_type": "application/json",
        "response_body_base64": _b64(response_bytes),
        "response_body_sha256": hashlib.sha256(response_bytes).hexdigest(),
        "observed_at": UTC,
    }


def _rpc_provider(
    endpoint_id: str, origin: str, correlation_id: int
) -> dict[str, object]:
    deploy_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "info_get_deploy",
        "params": {
            "deploy_hash": PAYMENT_HASH,
            "finalized_approvals": True,
        },
    }
    deploy_response = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "deploy": {
                "hash": PAYMENT_HASH,
                "header": {"account": SOURCE_ACCOUNT},
                "session": {
                    "Transfer": {
                        "args": [
                            ["target", {"parsed": PAYEE_ACCOUNT}],
                            ["amount", {"parsed": AMOUNT_MOTES}],
                            ["id", {"parsed": str(correlation_id)}],
                        ]
                    }
                },
            },
            "execution_results": [
                {
                    "block_hash": BLOCK_HASH,
                    "block_height": BLOCK_HEIGHT,
                    "result": {"Success": {"cost": "100000000"}},
                }
            ],
        },
    }
    block_request = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "chain_get_block",
        "params": {"block_identifier": {"Hash": BLOCK_HASH}},
    }
    block_response = {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "block": {
                "hash": BLOCK_HASH,
                "header": {
                    "height": BLOCK_HEIGHT,
                    "state_root_hash": STATE_ROOT_HASH,
                    "timestamp": UTC,
                },
                "body": {
                    "deploy_hashes": [PAYMENT_HASH],
                    "transfer_hashes": [],
                },
            }
        },
    }
    return {
        "endpoint_id": endpoint_id,
        "origin": origin,
        "info_get_deploy": _rpc_exchange(deploy_request, deploy_response),
        "chain_get_block": _rpc_exchange(block_request, block_response),
    }


def safepay_artifact() -> dict[str, Any]:
    report_bytes = _canonical(
        {
            "proposal_id": PROPOSAL_ID,
            "recommendation": "release after exact payment verification",
        }
    )
    report_hash = hashlib.sha256(report_bytes).hexdigest()
    correlation_id = safepay_v2_correlation_id(
        QUOTE_ID,
        PROPOSAL_ID,
        RESOURCE_ID,
        QUOTE_NONCE,
    )
    quote_hash = safepay_v2_quote_hash(
        quote_id=QUOTE_ID,
        proposal_id=PROPOSAL_ID,
        resource_id=RESOURCE_ID,
        network="casper:casper-test",
        payee_account_hash=PAYEE_ACCOUNT,
        amount_motes=AMOUNT_MOTES,
        correlation_id=correlation_id,
        report_version="safepay-report-v2",
        report_hash=report_hash,
        expires_at=EXPIRES_AT,
        quote_nonce=QUOTE_NONCE,
    )
    quote = {
        "schema_version": "safepay-v2",
        "quote_id": QUOTE_ID,
        "proposal_id": PROPOSAL_ID,
        "resource_id": RESOURCE_ID,
        "network": "casper:casper-test",
        "payee_account_hash": PAYEE_ACCOUNT,
        "amount_motes": AMOUNT_MOTES,
        "correlation_id": str(correlation_id),
        "report_version": "safepay-report-v2",
        "report_hash": report_hash,
        "expires_at": EXPIRES_AT,
        "quote_nonce": QUOTE_NONCE.hex(),
        "quote_hash": quote_hash,
    }
    quote_row = {key: value for key, value in quote.items() if key != "schema_version"}
    quote_row["issued_at"] = ISSUED_AT
    quote_row = {
        key: quote_row[key]
        for key in (
            "quote_id",
            "proposal_id",
            "resource_id",
            "network",
            "payee_account_hash",
            "amount_motes",
            "correlation_id",
            "report_version",
            "report_hash",
            "issued_at",
            "expires_at",
            "quote_nonce",
            "quote_hash",
        )
    }
    quote_row_hash = hashlib.sha256(_canonical(quote_row)).hexdigest()

    parsed_transfer = {
        "network": "casper:casper-test",
        "payment_hash": PAYMENT_HASH,
        "block_hash": BLOCK_HASH,
        "block_height": BLOCK_HEIGHT,
        "state_root_hash": STATE_ROOT_HASH,
        "block_timestamp": UTC,
        "execution_status": "processed",
        "finality_status": "finalized",
        "execution_error": None,
        "native_transfer_count": 1,
        "source_account_hash": SOURCE_ACCOUNT,
        "payee_account_hash": PAYEE_ACCOUNT,
        "amount_motes": AMOUNT_MOTES,
        "transfer_id": str(correlation_id),
    }
    response_hash = safepay_v2_response_hash(
        quote_hash=quote_hash,
        payment_hash=PAYMENT_HASH,
        block_hash=BLOCK_HASH,
        block_height=BLOCK_HEIGHT,
        report_hash=report_hash,
        consumed_at=CONSUMED_AT,
    )
    report_object = {
        "report_version": "safepay-report-v2",
        "proposal_id": PROPOSAL_ID,
        "resource_id": RESOURCE_ID,
        "correlation_id": str(correlation_id),
        "media_type": "application/json",
        "content_base64": _b64(report_bytes),
        "report_hash": report_hash,
    }
    fulfillment = {
        "quote": quote,
        "payment_observation": {
            key: value
            for key, value in parsed_transfer.items()
            if key != "native_transfer_count"
        },
        "consumption": {
            "network": "casper:casper-test",
            "payment_hash": PAYMENT_HASH,
            "quote_id": QUOTE_ID,
            "resource_id": RESOURCE_ID,
            "quote_hash": quote_hash,
            "response_hash": response_hash,
            "consumed_at": CONSUMED_AT,
        },
        "report": report_object,
        "binding_checks": {name: True for name in SAFEPAY_V2_BINDING_CHECK_FIELDS},
        "observed_at": str(CONSUMED_AT),
        "response_hash": response_hash,
    }
    fulfillment_json = json.dumps(
        fulfillment,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    consumption_row = {
        "network": "casper:casper-test",
        "payment_hash": PAYMENT_HASH,
        "quote_id": QUOTE_ID,
        "proposal_id": PROPOSAL_ID,
        "resource_id": RESOURCE_ID,
        "quote_hash": quote_hash,
        "report_hash": report_hash,
        "correlation_id": str(correlation_id),
        "fulfillment_json": fulfillment_json,
        "response_hash": response_hash,
        "consumed_at": CONSUMED_AT,
    }
    consumption_row_hash = hashlib.sha256(_canonical(consumption_row)).hexdigest()

    first_body = {
        "schema_version": "safepay-v2",
        "fulfillment": fulfillment,
        "delivery": {"replay_disposition": "first_consumption"},
    }
    retry_body = {
        "schema_version": "safepay-v2",
        "fulfillment": fulfillment,
        "delivery": {"replay_disposition": "idempotent_replay"},
    }
    cross_body = safepay_v2_error_body(
        "payment_already_consumed_for_other_binding",
        False,
        "cross_binding_rejected",
    )

    def redemption(
        *,
        kind: str,
        quote_id: str,
        resource_id: str,
        status: int,
        response_digest: str,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        request = {
            "network": "casper:casper-test",
            "payment_hash": PAYMENT_HASH,
            "quote_id": quote_id,
            "resource_id": resource_id,
        }
        return {
            "kind": kind,
            "network": "casper:casper-test",
            "payment_hash": PAYMENT_HASH,
            "quote_id": quote_id,
            "resource_id": resource_id,
            "http_status": status,
            "observed_at": CONSUMED_AT + 1,
            "response_digest": response_digest,
            "consumed_response_hash": response_hash,
            "exchange": _exchange(
                url="https://provider.example/x402/v2/redemptions",
                request=request,
                response=body,
                status=status,
            ),
        }

    return {
        "schema_version": "safepay-v2",
        "captured_at": UTC,
        "source_commit": SOURCE_COMMIT,
        "deployment_commit": DEPLOYMENT_COMMIT,
        "capture_identity": {
            "provider_url": "https://provider.example",
            "provider_deployment_id": "provider-release-1",
            "provider_image_digest": f"sha256:{'99' * 32}",
            "capture_tool_commit": SOURCE_COMMIT,
        },
        "quote": quote,
        "issued_quote_rows": {
            "before_restart": {
                "row": quote_row,
                "row_canonical_json_sha256": quote_row_hash,
                "observed_at": UTC,
                "provider_instance_id": "provider-before",
            },
            "after_restart": {
                "row": copy.deepcopy(quote_row),
                "row_canonical_json_sha256": quote_row_hash,
                "observed_at": UTC,
                "provider_instance_id": "provider-after",
            },
        },
        "chain_evidence": {
            "network": "casper:casper-test",
            "payment_hash": PAYMENT_HASH,
            "providers": [
                _rpc_provider(
                    "node-a",
                    "https://node-a.example/rpc",
                    correlation_id,
                ),
                _rpc_provider(
                    "node-b",
                    "https://node-b.example/rpc",
                    correlation_id,
                ),
            ],
            "parsed_transfer": parsed_transfer,
        },
        "consumption_rows": {
            "before_restart": {
                "row": consumption_row,
                "row_canonical_json_sha256": consumption_row_hash,
                "observed_at": UTC,
                "provider_instance_id": "provider-before",
            },
            "after_restart": {
                "row": copy.deepcopy(consumption_row),
                "row_canonical_json_sha256": consumption_row_hash,
                "observed_at": UTC,
                "provider_instance_id": "provider-after",
            },
            "exact_count": 1,
        },
        "redemption_observations": {
            "first_consumption": redemption(
                kind="first_consumption",
                quote_id=QUOTE_ID,
                resource_id=RESOURCE_ID,
                status=200,
                response_digest=response_hash,
                body=first_body,
            ),
            "exact_retry": redemption(
                kind="idempotent_replay",
                quote_id=QUOTE_ID,
                resource_id=RESOURCE_ID,
                status=200,
                response_digest=response_hash,
                body=retry_body,
            ),
            "cross_binding_reuse": redemption(
                kind="cross_binding_rejected",
                quote_id="223e4567-e89b-42d3-a456-426614174000",
                resource_id="risk-report:other",
                status=409,
                response_digest=safepay_v2_body_digest(cross_body),
                body=cross_body,
            ),
        },
        "protected_report": {
            **report_object,
            "decoded_length": len(report_bytes),
            "response_hash": response_hash,
            "persisted_at": UTC,
            "released_at": UTC,
        },
    }


def _load_schema(name: str) -> dict[str, Any]:
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


def test_safepay_fixture_matches_frozen_artifact_schema() -> None:
    Draft202012Validator(_load_schema("safepay-v2-live-artifact.schema.json")).validate(
        safepay_artifact()
    )


def test_safepay_adapter_recomputes_all_eleven_checks() -> None:
    artifact = safepay_artifact()
    raw = _canonical(artifact)

    result = verify_safepay_v2_artifact(artifact, raw)

    Draft202012Validator(
        _load_schema("safepay-v2-adapter-result.schema.json")
    ).validate(result)
    assert result["artifact_sha256"] == hashlib.sha256(raw).hexdigest()
    assert [check["name"] for check in result["checks"]] == [
        "quote_hash_recomputed",
        "issued_quote_row_matches_and_survives_restart",
        "per_quote_correlation_id_recomputed_and_equals_native_transfer_id",
        "payment_deploy_finalized_without_execution_error",
        "single_native_transfer_exact",
        "payee_amount_and_transfer_id_exact",
        "proposal_resource_and_correlation_exact",
        "report_hash_recomputed_and_matches_quote",
        "provider_consumption_row_matches_payment_and_binding",
        "exact_retry_returned_same_fulfillment_hash_without_second_consumption",
        "cross_binding_reuse_returned_terminal_409",
    ]
    assert all(check["passed"] is True for check in result["checks"])


Mutation = Callable[[dict[str, Any]], None]


def _flip_hex(value: str) -> str:
    return ("0" if value[0] != "0" else "1") + value[1:]


def _mutate_quote_hash(value: dict[str, Any]) -> None:
    value["quote"]["quote_hash"] = _flip_hex(value["quote"]["quote_hash"])


def _mutate_quote_row_nonce(value: dict[str, Any]) -> None:
    value["issued_quote_rows"]["after_restart"]["row"]["quote_nonce"] = "ab" * 32


def _mutate_correlation(value: dict[str, Any]) -> None:
    value["quote"]["correlation_id"] = str(int(value["quote"]["correlation_id"]) + 1)


def _mutate_rpc_response(value: dict[str, Any]) -> None:
    value["chain_evidence"]["providers"][0]["chain_get_block"][
        "response_body_base64"
    ] = _b64(_canonical({"jsonrpc": "2.0", "id": 2, "result": {}}))


def _mutate_transfer_count(value: dict[str, Any]) -> None:
    value["chain_evidence"]["parsed_transfer"]["native_transfer_count"] = 2


def _mutate_amount(value: dict[str, Any]) -> None:
    value["chain_evidence"]["parsed_transfer"]["amount_motes"] = "2500000001"


def _mutate_first_resource(value: dict[str, Any]) -> None:
    value["redemption_observations"]["first_consumption"]["resource_id"] = (
        "risk-report:wrong"
    )


def _mutate_report_bytes(value: dict[str, Any]) -> None:
    value["protected_report"]["content_base64"] = _b64(b'{"changed":true}')


def _mutate_consumption_payment(value: dict[str, Any]) -> None:
    value["consumption_rows"]["after_restart"]["row"]["payment_hash"] = "aa" * 32


def _mutate_retry_digest(value: dict[str, Any]) -> None:
    value["redemption_observations"]["exact_retry"]["response_digest"] = "bb" * 32


def _mutate_cross_status(value: dict[str, Any]) -> None:
    value["redemption_observations"]["cross_binding_reuse"]["exchange"][
        "response_status"
    ] = 200


@pytest.mark.parametrize(
    ("check_name", "mutate"),
    [
        ("quote_hash_recomputed", _mutate_quote_hash),
        ("issued_quote_row_matches_and_survives_restart", _mutate_quote_row_nonce),
        (
            "per_quote_correlation_id_recomputed_and_equals_native_transfer_id",
            _mutate_correlation,
        ),
        ("payment_deploy_finalized_without_execution_error", _mutate_rpc_response),
        ("single_native_transfer_exact", _mutate_transfer_count),
        ("payee_amount_and_transfer_id_exact", _mutate_amount),
        ("proposal_resource_and_correlation_exact", _mutate_first_resource),
        ("report_hash_recomputed_and_matches_quote", _mutate_report_bytes),
        (
            "provider_consumption_row_matches_payment_and_binding",
            _mutate_consumption_payment,
        ),
        (
            "exact_retry_returned_same_fulfillment_hash_without_second_consumption",
            _mutate_retry_digest,
        ),
        (
            "cross_binding_reuse_returned_terminal_409",
            _mutate_cross_status,
        ),
    ],
)
def test_safepay_adapter_rejects_each_required_mutation(
    check_name: str,
    mutate: Mutation,
) -> None:
    artifact = safepay_artifact()
    mutate(artifact)

    with pytest.raises(ReleaseProofAdapterError, match=check_name):
        verify_safepay_v2_artifact(artifact, _canonical(artifact))
