from __future__ import annotations

import base64
import copy
import hashlib
import json
import sqlite3
import tempfile
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
UTC = "2026-07-23T01:05:00Z"
BLOCK_TIMESTAMP = "2026-07-23T01:02:03Z"
SOURCE_COMMIT = "11" * 20
DEPLOYMENT_COMMIT = "22" * 20
PAYMENT_HASH = "33" * 32
BLOCK_HASH = "44" * 32
STATE_ROOT_HASH = "55" * 32
TIP_HASH = "aa" * 32
TIP_STATE_ROOT_HASH = "bb" * 32
SOURCE_PUBLIC_KEY = "01" + ("66" * 32)
PAYEE_PUBLIC_KEY = "01" + ("77" * 32)
SOURCE_ACCOUNT = hashlib.blake2b(
    b"ed25519\x00" + bytes.fromhex(SOURCE_PUBLIC_KEY)[1:], digest_size=32
).hexdigest()
PAYEE_ACCOUNT = hashlib.blake2b(
    b"ed25519\x00" + bytes.fromhex(PAYEE_PUBLIC_KEY)[1:], digest_size=32
).hexdigest()
QUOTE_ID = "123e4567-e89b-42d3-a456-426614174000"
PROPOSAL_ID = "DAO-PROP-TEST-1"
RESOURCE_ID = "risk-report:test"
AMOUNT_MOTES = "2500000000"
QUOTE_NONCE = bytes.fromhex("88" * 32)
ISSUED_AT = 1_784_768_400
CONSUMED_AT = ISSUED_AT + 180
EXPIRES_AT = ISSUED_AT + 600
BLOCK_HEIGHT = 8_400_001
MIGRATION_PATH = ROOT / "x402_provider/migrations/0001_safepay_v2.sql"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


PROVIDER_DEPLOYMENT_ID = "provider-release-1"
PROVIDER_IMAGE_DIGEST = f"sha256:{'99' * 32}"


def _provider_runtime_identity(
    *,
    container_id: str,
    started_at: str,
    observed_at: str,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "container_id": container_id,
        "deployment_id": PROVIDER_DEPLOYMENT_ID,
        "image_digest": PROVIDER_IMAGE_DIGEST,
        "started_at": started_at,
        "observed_at": observed_at,
        "restart_count": 0,
    }
    payload["instance_id"] = hashlib.sha256(
        b"CONCORDIA_SAFEPAY_PROVIDER_INSTANCE_V1\x00" + _canonical(payload)
    ).hexdigest()
    return payload


BEFORE_RUNTIME_IDENTITY = _provider_runtime_identity(
    container_id="90" * 32,
    started_at="2026-07-23T00:50:00Z",
    observed_at="2026-07-23T01:03:55Z",
)
AFTER_RUNTIME_IDENTITY = _provider_runtime_identity(
    container_id="91" * 32,
    started_at="2026-07-23T01:04:00Z",
    observed_at="2026-07-23T01:04:50Z",
)
BEFORE_INSTANCE_ID = str(BEFORE_RUNTIME_IDENTITY["instance_id"])
AFTER_INSTANCE_ID = str(AFTER_RUNTIME_IDENTITY["instance_id"])


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


def _rpc_exchange(
    url: str, request: object, response: object
) -> dict[str, object]:
    request_bytes = _canonical(request)
    response_bytes = _canonical(response)
    return {
        "url": url,
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
                "header": {
                    "account": SOURCE_PUBLIC_KEY,
                    "chain_name": "casper-test",
                },
                "session": {
                    "Transfer": {
                        "args": [
                            [
                                "amount",
                                {
                                    "cl_type": "U512",
                                    "bytes": "0400f90295",
                                    "parsed": AMOUNT_MOTES,
                                },
                            ],
                            [
                                "target",
                                {
                                    "cl_type": "PublicKey",
                                    "bytes": PAYEE_PUBLIC_KEY,
                                    "parsed": PAYEE_PUBLIC_KEY,
                                },
                            ],
                            [
                                "id",
                                {
                                    "cl_type": {"Option": "U64"},
                                    "bytes": "01"
                                    + correlation_id.to_bytes(8, "little").hex(),
                                    "parsed": correlation_id,
                                },
                            ],
                        ]
                    }
                },
            },
            "execution_info": {
                "block_hash": BLOCK_HASH,
                "block_height": BLOCK_HEIGHT,
                "execution_result": {
                    "Version2": {
                        "initiator": {"PublicKey": SOURCE_PUBLIC_KEY},
                        "error_message": None,
                        "transfers": [
                            {
                                "Version2": {
                                    "transaction_hash": {"Deploy": PAYMENT_HASH},
                                    "from": {
                                        "AccountHash": f"account-hash-{SOURCE_ACCOUNT}"
                                    },
                                    "to": f"account-hash-{PAYEE_ACCOUNT}",
                                    "amount": AMOUNT_MOTES,
                                    "gas": "100000000",
                                    "id": correlation_id,
                                }
                            }
                        ],
                    }
                }
            },
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
            "block_with_signatures": {
                "block": {
                    "Version2": {
                        "hash": BLOCK_HASH,
                        "header": {
                            "height": BLOCK_HEIGHT,
                            "state_root_hash": STATE_ROOT_HASH,
                            "timestamp": BLOCK_TIMESTAMP,
                        },
                        "body": {
                            "transactions": {
                                "0": [{"Deploy": PAYMENT_HASH}],
                            }
                        },
                    }
                },
                "proofs": [],
            }
        },
    }
    status_request = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "info_get_status",
        "params": [],
    }
    status_response = {
        "jsonrpc": "2.0",
        "id": 3,
        "result": {
            "api_version": "2.0.0",
            "chainspec_name": "casper-test",
            "last_added_block_info": {
                "hash": TIP_HASH,
                "height": BLOCK_HEIGHT + 8,
                "state_root_hash": TIP_STATE_ROOT_HASH,
                "timestamp": UTC,
            },
            "starting_state_root_hash": TIP_STATE_ROOT_HASH,
        },
    }
    return {
        "endpoint_id": endpoint_id,
        "origin": origin,
        "info_get_deploy": _rpc_exchange(origin, deploy_request, deploy_response),
        "chain_get_block": _rpc_exchange(origin, block_request, block_response),
        "info_get_status": _rpc_exchange(origin, status_request, status_response),
    }


def _sqlite_backup(connection: sqlite3.Connection, path: Path) -> bytes:
    destination = sqlite3.connect(path)
    try:
        connection.backup(destination)
    finally:
        destination.close()
    return path.read_bytes()


def _ledger_snapshot(
    raw: bytes,
    instance_id: str,
    observed_at: str,
) -> dict[str, object]:
    return {
        "sqlite_backup_base64": _b64(raw),
        "sqlite_backup_sha256": hashlib.sha256(raw).hexdigest(),
        "observed_at": observed_at,
        "provider_instance_id": instance_id,
    }


def _ledger_evidence(
    *,
    quote_row: dict[str, Any],
    consumption_row: dict[str, Any],
    protected_report: dict[str, Any],
    redemptions: dict[str, Any],
) -> dict[str, Any]:
    migration = MIGRATION_PATH.read_bytes()
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        connection = sqlite3.connect(directory / "provider.sqlite3")
        try:
            connection.executescript(migration.decode("utf-8"))
            connection.execute(
                "INSERT INTO safepay_reports("
                "report_hash, report_media_type, report_bytes, decoded_length, created_at"
                ") VALUES(?, ?, ?, ?, ?)",
                (
                    protected_report["report_hash"],
                    protected_report["media_type"],
                    base64.b64decode(protected_report["content_base64"]),
                    protected_report["decoded_length"],
                    quote_row["issued_at"],
                ),
            )
            connection.execute(
                "INSERT INTO safepay_quotes("
                "quote_id, proposal_id, resource_id, network, payee_account_hash, "
                "amount_motes, correlation_id, report_version, report_hash, issued_at, "
                "expires_at, quote_nonce, quote_hash"
                ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(
                    quote_row[field]
                    for field in (
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
                ),
            )
            connection.execute(
                "INSERT INTO payment_consumptions("
                "network, payment_hash, quote_id, proposal_id, resource_id, quote_hash, "
                "report_hash, correlation_id, fulfillment_json, response_hash, consumed_at"
                ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(
                    consumption_row[field]
                    for field in (
                        "network",
                        "payment_hash",
                        "quote_id",
                        "proposal_id",
                        "resource_id",
                        "quote_hash",
                        "report_hash",
                        "correlation_id",
                        "fulfillment_json",
                        "response_hash",
                        "consumed_at",
                    )
                ),
            )

            def add_observation(name: str) -> None:
                row = redemptions[name]
                connection.execute(
                    "INSERT INTO safepay_redemption_observations("
                    "kind, http_status, network, payment_hash, quote_id, resource_id, "
                    "observed_at, response_digest, consumed_response_hash"
                    ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    tuple(
                        row[field]
                        for field in (
                            "kind",
                            "http_status",
                            "network",
                            "payment_hash",
                            "quote_id",
                            "resource_id",
                            "observed_at",
                            "response_digest",
                            "consumed_response_hash",
                        )
                    ),
                )
                connection.commit()

            add_observation("first_consumption")
            after_first = _sqlite_backup(connection, directory / "after-first.sqlite3")
            add_observation("exact_retry")
            after_retry = _sqlite_backup(connection, directory / "after-retry.sqlite3")
            add_observation("cross_binding_reuse")
            after_cross = _sqlite_backup(connection, directory / "after-cross.sqlite3")
        finally:
            connection.close()
    return {
        "authoritative_database_id": "safepay-provider-ledger",
        "authoritative_schema_id": "concordia.safepay-provider-ledger.sqlite.v1",
        "migration_sql_base64": _b64(migration),
        "migration_sql_sha256": hashlib.sha256(migration).hexdigest(),
        "after_first_consumption": _ledger_snapshot(
            after_first,
            BEFORE_INSTANCE_ID,
            "2026-07-23T01:03:10Z",
        ),
        "after_exact_retry": _ledger_snapshot(
            after_retry,
            BEFORE_INSTANCE_ID,
            "2026-07-23T01:03:20Z",
        ),
        "after_cross_binding_reuse": _ledger_snapshot(
            after_cross,
            AFTER_INSTANCE_ID,
            "2026-07-23T01:04:30Z",
        ),
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
        "block_timestamp": BLOCK_TIMESTAMP,
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
            "network": parsed_transfer["network"],
            "payment_hash": parsed_transfer["payment_hash"],
            "block_hash": parsed_transfer["block_hash"],
            "block_height": parsed_transfer["block_height"],
            "execution_status": parsed_transfer["execution_status"],
            "finality_status": parsed_transfer["finality_status"],
            "from_account_hash": parsed_transfer["source_account_hash"],
            "to_account_hash": parsed_transfer["payee_account_hash"],
            "amount_motes": parsed_transfer["amount_motes"],
            "transfer_id": parsed_transfer["transfer_id"],
            "execution_error": parsed_transfer["execution_error"],
            "observed_at": UTC,
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
        "observed_at": UTC,
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
        observed_at: int,
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
            "observed_at": observed_at,
            "response_digest": response_digest,
            "consumed_response_hash": response_hash,
            "exchange": _exchange(
                url="https://provider.example/x402/v2/redemptions",
                request=request,
                response=body,
                status=status,
            ),
        }

    artifact = {
        "schema_version": "safepay-v2",
        "captured_at": UTC,
        "source_commit": SOURCE_COMMIT,
        "deployment_commit": DEPLOYMENT_COMMIT,
        "capture_identity": {
            "provider_url": "https://provider.example",
            "provider_deployment_id": PROVIDER_DEPLOYMENT_ID,
            "provider_image_digest": PROVIDER_IMAGE_DIGEST,
            "capture_tool_commit": SOURCE_COMMIT,
            "provider_instances": {
                "before_restart": copy.deepcopy(BEFORE_RUNTIME_IDENTITY),
                "after_restart": copy.deepcopy(AFTER_RUNTIME_IDENTITY),
            },
        },
        "quote": quote,
        "issued_quote_rows": {
            "before_restart": {
                "row": quote_row,
                "row_canonical_json_sha256": quote_row_hash,
                "observed_at": "2026-07-23T01:03:30Z",
                "provider_instance_id": BEFORE_INSTANCE_ID,
            },
            "after_restart": {
                "row": copy.deepcopy(quote_row),
                "row_canonical_json_sha256": quote_row_hash,
                "observed_at": "2026-07-23T01:04:40Z",
                "provider_instance_id": AFTER_INSTANCE_ID,
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
                "observed_at": "2026-07-23T01:03:30Z",
                "provider_instance_id": BEFORE_INSTANCE_ID,
            },
            "after_restart": {
                "row": copy.deepcopy(consumption_row),
                "row_canonical_json_sha256": consumption_row_hash,
                "observed_at": "2026-07-23T01:04:40Z",
                "provider_instance_id": AFTER_INSTANCE_ID,
            },
        },
        "redemption_observations": {
            "first_consumption": redemption(
                kind="first_consumption",
                quote_id=QUOTE_ID,
                resource_id=RESOURCE_ID,
                status=200,
                response_digest=response_hash,
                body=first_body,
                observed_at=CONSUMED_AT + 1,
            ),
            "exact_retry": redemption(
                kind="idempotent_replay",
                quote_id=QUOTE_ID,
                resource_id=RESOURCE_ID,
                status=200,
                response_digest=response_hash,
                body=retry_body,
                observed_at=CONSUMED_AT + 2,
            ),
            "cross_binding_reuse": redemption(
                kind="cross_binding_rejected",
                quote_id="223e4567-e89b-42d3-a456-426614174000",
                resource_id="risk-report:other",
                status=409,
                response_digest=safepay_v2_body_digest(cross_body),
                body=cross_body,
                observed_at=CONSUMED_AT + 70,
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
    artifact["ledger_evidence"] = _ledger_evidence(
        quote_row=quote_row,
        consumption_row=consumption_row,
        protected_report=artifact["protected_report"],
        redemptions=artifact["redemption_observations"],
    )
    return artifact


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
