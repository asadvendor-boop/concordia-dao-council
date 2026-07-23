"""Failure-first tests for the SafePay v2 raw-bundle capture generator.

The positive test assembles a synthetic *raw* capture bundle (mirroring the
raw inputs of ``tests.test_release_proof_adapters.safepay_artifact``), runs the
production ``build_safepay_v2_artifact`` over it, and asserts the frozen
adapter accepts the assembled document against its own canonical bytes.  Every
other test mutates exactly one raw bundle input and asserts the generator
*refuses* -- covering each adapter rejection path reachable by corrupting raw
evidence, plus the create-once private write.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import runpy
import sqlite3
import stat
from pathlib import Path
from typing import Any, Callable

import pytest

from scripts.safepay_v2_capture import (
    BUNDLE_VERSION,
    SafePayV2CaptureError,
    build_safepay_v2_artifact,
    canonical_artifact_bytes,
    capture,
)
from shared.release_proof_adapters import verify_safepay_v2_artifact
from shared.x402_payments import safepay_v2_correlation_id

# --- constants mirrored from the passing adapter fixture --------------------
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
AMOUNT_U512_BYTES = "0400f90295"
QUOTE_NONCE = "88" * 32
ISSUED_AT = 1_784_768_400
CONSUMED_AT = ISSUED_AT + 180
EXPIRES_AT = ISSUED_AT + 600
BLOCK_HEIGHT = 8_400_001
PROVIDER_URL = "https://provider.example"
PROVIDER_DEPLOYMENT_ID = "provider-release-1"
PROVIDER_IMAGE_DIGEST = f"sha256:{'99' * 32}"
CROSS_QUOTE_ID = "223e4567-e89b-42d3-a456-426614174000"
CROSS_RESOURCE_ID = "risk-report:other"

CORRELATION_ID = safepay_v2_correlation_id(
    QUOTE_ID, PROPOSAL_ID, RESOURCE_ID, bytes.fromhex(QUOTE_NONCE)
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _report_bytes() -> bytes:
    return _canonical(
        {
            "proposal_id": PROPOSAL_ID,
            "recommendation": "release after exact payment verification",
        }
    )


def _deploy_response(correlation_id: int) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "deploy": {
                "hash": PAYMENT_HASH,
                "header": {"account": SOURCE_PUBLIC_KEY, "chain_name": "casper-test"},
                "session": {
                    "Transfer": {
                        "args": [
                            [
                                "amount",
                                {
                                    "cl_type": "U512",
                                    "bytes": AMOUNT_U512_BYTES,
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
                                    "bytes": "01" + correlation_id.to_bytes(8, "little").hex(),
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
                                    "from": {"AccountHash": f"account-hash-{SOURCE_ACCOUNT}"},
                                    "to": f"account-hash-{PAYEE_ACCOUNT}",
                                    "amount": AMOUNT_MOTES,
                                    "gas": "100000000",
                                    "id": correlation_id,
                                }
                            }
                        ],
                    }
                },
            },
        },
    }


def _block_response(*, state_root: str = STATE_ROOT_HASH) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "block_with_signatures": {
                "block": {
                    "Version2": {
                        "hash": BLOCK_HASH,
                        "header": {
                            "height": BLOCK_HEIGHT,
                            "state_root_hash": state_root,
                            "timestamp": BLOCK_TIMESTAMP,
                        },
                        "body": {"transactions": {"0": [{"Deploy": PAYMENT_HASH}]}},
                    }
                },
                "proofs": [],
            }
        },
    }


def _status_response(*, tip_height: int = BLOCK_HEIGHT + 8) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 3,
        "result": {
            "api_version": "2.0.0",
            "chainspec_name": "casper-test",
            "last_added_block_info": {
                "hash": TIP_HASH,
                "height": tip_height,
                "state_root_hash": TIP_STATE_ROOT_HASH,
                "timestamp": UTC,
            },
            "starting_state_root_hash": TIP_STATE_ROOT_HASH,
        },
    }


def _provider(
    endpoint_id: str,
    origin: str,
    correlation_id: int,
    *,
    state_root: str = STATE_ROOT_HASH,
    tip_height: int = BLOCK_HEIGHT + 8,
) -> dict[str, Any]:
    semantic = {
        "endpoint_id": endpoint_id,
        "origin": origin,
        "observed_at": UTC,
        "info_get_deploy": {
            "request": {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "info_get_deploy",
                "params": {"deploy_hash": PAYMENT_HASH, "finalized_approvals": True},
            },
            "response": _deploy_response(correlation_id),
        },
        "chain_get_block": {
            "request": {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "chain_get_block",
                "params": {"block_identifier": {"Hash": BLOCK_HASH}},
            },
            "response": _block_response(state_root=state_root),
        },
        "info_get_status": {
            "request": {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "info_get_status",
                "params": [],
            },
            "response": _status_response(tip_height=tip_height),
        },
    }
    return {
        "endpoint_id": endpoint_id,
        "origin": origin,
        **{
            name: {
                "url": origin,
                "request_body_base64": _b64(
                    _canonical(semantic[name]["request"])
                ),
                "response_status": 200,
                "response_content_type": "application/json",
                "response_body_base64": _b64(
                    _canonical(semantic[name]["response"])
                ),
                "observed_at": UTC,
            }
            for name in (
                "info_get_deploy",
                "chain_get_block",
                "info_get_status",
            )
        },
    }


def _runtime_identity(
    container_id: str,
    started_at: str,
    observed_at: str,
    restart_count: int = 0,
) -> dict[str, Any]:
    return {
        "container_id": container_id,
        "deployment_id": PROVIDER_DEPLOYMENT_ID,
        "image_digest": PROVIDER_IMAGE_DIGEST,
        "started_at": started_at,
        "observed_at": observed_at,
        "restart_count": restart_count,
    }


_REF = runpy.run_path(
    str(
        Path(__file__).resolve().parents[1]
        / "tests"
        / "test_release_proof_adapters.py"
    )
)


def _raw_exchange(exchange: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "method",
        "url",
        "request_body_base64",
        "response_status",
        "response_content_type",
        "response_body_base64",
        "observed_at",
    )
    return {key: copy.deepcopy(exchange[key]) for key in keys}


def _raw_rpc_exchange(exchange: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "url",
        "request_body_base64",
        "response_status",
        "response_content_type",
        "response_body_base64",
        "observed_at",
    )
    return {key: copy.deepcopy(exchange[key]) for key in keys}


def _raw_bundle() -> dict[str, Any]:
    artifact = _REF["safepay_artifact"]()
    identity = artifact["capture_identity"]
    providers = artifact["chain_evidence"]["providers"]
    ledger = artifact["ledger_evidence"]
    return {
        "bundle_version": BUNDLE_VERSION,
        "captured_at": artifact["captured_at"],
        "source_commit": artifact["source_commit"],
        "deployment_commit": artifact["deployment_commit"],
        "provider": {
            "url": identity["provider_url"],
            "deployment_id": identity["provider_deployment_id"],
            "image_digest": identity["provider_image_digest"],
            "instances": {
                name: {
                    key: copy.deepcopy(value)
                    for key, value in identity["provider_instances"][name].items()
                    if key != "instance_id"
                }
                for name in ("before_restart", "after_restart")
            },
        },
        "chain": {
            "payment_hash": artifact["chain_evidence"]["payment_hash"],
            "providers": [
                {
                    "endpoint_id": provider["endpoint_id"],
                    "origin": provider["origin"],
                    **{
                        name: _raw_rpc_exchange(provider[name])
                        for name in (
                            "info_get_deploy",
                            "chain_get_block",
                            "info_get_status",
                        )
                    },
                }
                for provider in providers
            ],
        },
        "redemptions": {
            name: {
                "exchange": _raw_exchange(
                    artifact["redemption_observations"][name]["exchange"]
                )
            }
            for name in (
                "first_consumption",
                "exact_retry",
                "cross_binding_reuse",
            )
        },
        "ledger_snapshots_observed": {
            name: {
                "sqlite_backup_base64": ledger[name][
                    "sqlite_backup_base64"
                ],
                "observed_at": ledger[name]["observed_at"],
            }
            for name in (
                "after_first_consumption",
                "after_exact_retry",
                "after_cross_binding_reuse",
            )
        },
    }


_BASE_BUNDLE = _raw_bundle()


def base_bundle() -> dict[str, Any]:
    return copy.deepcopy(_BASE_BUNDLE)


# --- positive path ----------------------------------------------------------


def test_capture_builds_self_verifying_artifact() -> None:
    document = build_safepay_v2_artifact(base_bundle())
    raw = canonical_artifact_bytes(document)

    # The adapter must accept the assembled document against its own bytes.
    result = verify_safepay_v2_artifact(document, raw)

    assert result["proof_type"] == "safepay_v2"
    assert result["derived_facts"]["quote_hash"] == document["quote"]["quote_hash"]
    assert result["derived_facts"]["correlation_id"] == str(CORRELATION_ID)
    assert result["derived_facts"]["consumption_count"] == 1
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


def test_capture_derives_hashes_rather_than_trusting_inputs() -> None:
    document = build_safepay_v2_artifact(base_bundle())
    quote = document["quote"]

    # correlation id and quote hash are recomputed from the frozen preimage.
    assert quote["correlation_id"] == str(CORRELATION_ID)
    assert quote["report_hash"] == hashlib.sha256(_report_bytes()).hexdigest()
    assert document["chain_evidence"]["parsed_transfer"]["transfer_id"] == str(CORRELATION_ID)
    # the before/after restart instances derive distinct runtime instance ids.
    instances = document["capture_identity"]["provider_instances"]
    assert (
        instances["before_restart"]["instance_id"]
        != instances["after_restart"]["instance_id"]
    )
    # the three ledger snapshots straddle the restart.
    ledger = document["ledger_evidence"]
    assert (
        ledger["after_first_consumption"]["provider_instance_id"]
        == instances["before_restart"]["instance_id"]
    )
    assert (
        ledger["after_exact_retry"]["provider_instance_id"]
        == ledger["after_cross_binding_reuse"]["provider_instance_id"]
        == instances["after_restart"]["instance_id"]
    )


def test_capture_binds_retry_snapshots_to_the_restarted_service_instance() -> None:
    bundle = base_bundle()
    before = bundle["provider"]["instances"]["before_restart"]
    bundle["provider"]["instances"]["after_restart"] = _runtime_identity(
        before["container_id"],
        "2026-07-23T01:04:00Z",
        "2026-07-23T01:04:05Z",
        restart_count=before["restart_count"] + 1,
    )
    bundle["redemptions"]["first_consumption"]["exchange"]["observed_at"] = (
        "2026-07-23T01:03:57Z"
    )
    bundle["redemptions"]["exact_retry"]["exchange"]["observed_at"] = (
        "2026-07-23T01:04:10Z"
    )
    bundle["redemptions"]["cross_binding_reuse"]["exchange"]["observed_at"] = (
        "2026-07-23T01:04:25Z"
    )
    bundle["ledger_snapshots_observed"]["after_first_consumption"]["observed_at"] = (
        "2026-07-23T01:03:59Z"
    )
    bundle["ledger_snapshots_observed"]["after_exact_retry"]["observed_at"] = (
        "2026-07-23T01:04:20Z"
    )
    bundle["ledger_snapshots_observed"]["after_cross_binding_reuse"]["observed_at"] = (
        "2026-07-23T01:04:30Z"
    )

    document = build_safepay_v2_artifact(bundle)
    instances = document["capture_identity"]["provider_instances"]
    ledger = document["ledger_evidence"]

    assert (
        ledger["after_first_consumption"]["provider_instance_id"]
        == instances["before_restart"]["instance_id"]
    )
    assert (
        ledger["after_exact_retry"]["provider_instance_id"]
        == ledger["after_cross_binding_reuse"]["provider_instance_id"]
        == instances["after_restart"]["instance_id"]
    )


# --- create-once private write ---------------------------------------------


@pytest.mark.parametrize("input_mode", [0o400, 0o600])
def test_capture_reads_private_input_and_writes_canonical_bytes_once(
    tmp_path: Path, input_mode: int
) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_bytes(_canonical(base_bundle()))
    bundle_path.chmod(input_mode)
    output = tmp_path / "safepay-v2.json"

    document = capture(bundle_path=str(bundle_path), output_path=str(output))

    written = output.read_bytes()
    assert written == canonical_artifact_bytes(document)
    assert not written.endswith(b"\n")
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    # written bytes independently re-verify.
    verify_safepay_v2_artifact(json.loads(written), written)


def test_capture_refuses_to_overwrite_existing_output(tmp_path: Path) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_bytes(_canonical(base_bundle()))
    bundle_path.chmod(0o600)
    output = tmp_path / "safepay-v2.json"

    capture(bundle_path=str(bundle_path), output_path=str(output))
    with pytest.raises(SafePayV2CaptureError):
        capture(bundle_path=str(bundle_path), output_path=str(output))


def test_capture_rejects_relative_output(tmp_path: Path) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_bytes(_canonical(base_bundle()))
    bundle_path.chmod(0o600)
    with pytest.raises(SafePayV2CaptureError):
        capture(bundle_path=str(bundle_path), output_path="relative-output.json")


def test_capture_rejects_world_readable_or_stdin_bundle(
    tmp_path: Path,
) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_bytes(_canonical(base_bundle()))
    bundle_path.chmod(0o644)
    output = tmp_path / "artifact.json"

    with pytest.raises(SafePayV2CaptureError, match="secure|safely"):
        capture(bundle_path=str(bundle_path), output_path=str(output))
    with pytest.raises(SafePayV2CaptureError, match="absolute|file|secure"):
        capture(bundle_path="-", output_path=str(output))


def test_capture_rejects_missing_or_tampered_raw_evidence() -> None:
    missing = base_bundle()
    del missing["redemptions"]["exact_retry"]
    with pytest.raises(SafePayV2CaptureError):
        build_safepay_v2_artifact(missing)

    tampered_exchange = base_bundle()
    response = tampered_exchange["redemptions"]["first_consumption"][
        "exchange"
    ]
    raw = bytearray(base64.b64decode(response["response_body_base64"]))
    raw[-1] ^= 1
    response["response_body_base64"] = _b64(bytes(raw))
    with pytest.raises(SafePayV2CaptureError):
        build_safepay_v2_artifact(tampered_exchange)

    tampered_backup = base_bundle()
    snapshot = tampered_backup["ledger_snapshots_observed"][
        "after_exact_retry"
    ]
    raw = bytearray(base64.b64decode(snapshot["sqlite_backup_base64"]))
    raw[-1] ^= 1
    snapshot["sqlite_backup_base64"] = _b64(bytes(raw))
    with pytest.raises(SafePayV2CaptureError):
        build_safepay_v2_artifact(tampered_backup)


# --- failure-first mutation matrix -----------------------------------------

Mutation = Callable[[dict[str, Any]], None]


def _rewrite_snapshot_databases(
    bundle: dict[str, Any],
    statement: str,
    parameters: tuple[object, ...] = (),
) -> None:
    for snapshot in bundle["ledger_snapshots_observed"].values():
        connection = sqlite3.connect(":memory:")
        try:
            connection.deserialize(
                base64.b64decode(snapshot["sqlite_backup_base64"])
            )
            connection.execute(statement, parameters)
            connection.commit()
            snapshot["sqlite_backup_base64"] = _b64(connection.serialize())
        finally:
            connection.close()


def _mutate_exchange_json(
    exchange: dict[str, Any],
    key: str,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    document = json.loads(base64.b64decode(exchange[key]))
    mutate(document)
    exchange[key] = _b64(_canonical(document))


def _mutate_amount(bundle: dict[str, Any]) -> None:
    _rewrite_snapshot_databases(
        bundle,
        "UPDATE safepay_quotes SET amount_motes = ?",
        ("2500000001",),
    )


def _mutate_payee(bundle: dict[str, Any]) -> None:
    _rewrite_snapshot_databases(
        bundle,
        "UPDATE safepay_quotes SET payee_account_hash = ?",
        ("aa" * 32,),
    )


def _mutate_nonce(bundle: dict[str, Any]) -> None:
    _rewrite_snapshot_databases(
        bundle,
        "UPDATE safepay_quotes SET quote_nonce = ?",
        ("ab" * 32,),
    )


def _mutate_payee_non_hex(bundle: dict[str, Any]) -> None:
    _rewrite_snapshot_databases(
        bundle,
        "UPDATE safepay_quotes SET payee_account_hash = ?",
        ("zz" * 32,),
    )


def _mutate_zero_nonce(bundle: dict[str, Any]) -> None:
    _rewrite_snapshot_databases(
        bundle,
        "UPDATE safepay_quotes SET quote_nonce = ?",
        ("00" * 32,),
    )


def _mutate_amount_non_canonical(bundle: dict[str, Any]) -> None:
    _rewrite_snapshot_databases(
        bundle,
        "UPDATE safepay_quotes SET amount_motes = ?",
        ("02500000000",),
    )


def _mutate_rpc_empty_block(bundle: dict[str, Any]) -> None:
    exchange = bundle["chain"]["providers"][0]["chain_get_block"]
    exchange["response_body_base64"] = _b64(
        _canonical({"jsonrpc": "2.0", "id": 2, "result": {}})
    )


def _mutate_rpc_pending_execution(bundle: dict[str, Any]) -> None:
    exchange = bundle["chain"]["providers"][0]["info_get_deploy"]
    _mutate_exchange_json(
        exchange,
        "response_body_base64",
        lambda deploy: deploy["result"]["execution_info"][
            "execution_result"
        ]["Version2"].__setitem__("error_message", "Out of gas"),
    )


def _mutate_providers_disagree(bundle: dict[str, Any]) -> None:
    bundle["chain"]["providers"][1] = _provider(
        "node-b", "https://node-b.example/rpc", CORRELATION_ID, state_root="cc" * 32
    )


def _mutate_low_confirmations(bundle: dict[str, Any]) -> None:
    for index in (0, 1):
        origin = bundle["chain"]["providers"][index]["origin"]
        endpoint = bundle["chain"]["providers"][index]["endpoint_id"]
        bundle["chain"]["providers"][index] = _provider(
            endpoint, origin, CORRELATION_ID, tip_height=BLOCK_HEIGHT + 1
        )


def _mutate_report_released_before_block(bundle: dict[str, Any]) -> None:
    bundle["redemptions"]["first_consumption"]["exchange"]["observed_at"] = (
        "2026-07-23T01:01:00Z"
    )


def _mutate_consumed_after_expiry(bundle: dict[str, Any]) -> None:
    _rewrite_snapshot_databases(
        bundle,
        "UPDATE payment_consumptions SET consumed_at = ?",
        (EXPIRES_AT,),
    )


def _mutate_mixed_generation(bundle: dict[str, Any]) -> None:
    bundle["provider"]["instances"]["after_restart"]["image_digest"] = (
        f"sha256:{'ee' * 32}"
    )


def _mutate_forged_restart(bundle: dict[str, Any]) -> None:
    bundle["provider"]["instances"]["after_restart"]["container_id"] = "91" * 32


def _mutate_cross_binding_same_quote(bundle: dict[str, Any]) -> None:
    exchange = bundle["redemptions"]["cross_binding_reuse"]["exchange"]
    _mutate_exchange_json(
        exchange,
        "request_body_base64",
        lambda request: request.update(
            {"quote_id": QUOTE_ID, "resource_id": RESOURCE_ID}
        ),
    )


def _mutate_retry_before_first(bundle: dict[str, Any]) -> None:
    _rewrite_snapshot_databases(
        bundle,
        "UPDATE safepay_redemption_observations SET observed_at = ? "
        "WHERE kind = 'idempotent_replay'",
        (CONSUMED_AT,),
    )


def _mutate_ledger_snapshot_order(bundle: dict[str, Any]) -> None:
    bundle["ledger_snapshots_observed"]["after_exact_retry"][
        "observed_at"
    ] = "2026-07-23T01:03:05Z"


def _mutate_future_capture(bundle: dict[str, Any]) -> None:
    bundle["captured_at"] = "2099-01-01T00:00:00Z"


def _mutate_restart_observation_order(bundle: dict[str, Any]) -> None:
    # An "after restart" quote row observed before the restart even started.
    bundle["ledger_snapshots_observed"]["after_cross_binding_reuse"][
        "observed_at"
    ] = "2026-07-23T01:03:59Z"


def _mutate_bad_bundle_version(bundle: dict[str, Any]) -> None:
    bundle["bundle_version"] = "concordia.safepay_v2_capture_bundle.v0"


def _mutate_missing_key(bundle: dict[str, Any]) -> None:
    del bundle["ledger_snapshots_observed"]


def _mutate_extra_key(bundle: dict[str, Any]) -> None:
    bundle["forced_correlation_id"] = "1"


def _mutate_forged_boolean_issued_at(bundle: dict[str, Any]) -> None:
    _rewrite_snapshot_databases(
        bundle,
        "UPDATE safepay_quotes SET issued_at = ?",
        (True,),
    )


@pytest.mark.parametrize(
    "mutate",
    [
        _mutate_amount,
        _mutate_payee,
        _mutate_nonce,
        _mutate_payee_non_hex,
        _mutate_zero_nonce,
        _mutate_amount_non_canonical,
        _mutate_rpc_empty_block,
        _mutate_rpc_pending_execution,
        _mutate_providers_disagree,
        _mutate_low_confirmations,
        _mutate_report_released_before_block,
        _mutate_consumed_after_expiry,
        _mutate_mixed_generation,
        _mutate_forged_restart,
        _mutate_cross_binding_same_quote,
        _mutate_retry_before_first,
        _mutate_ledger_snapshot_order,
        _mutate_future_capture,
        _mutate_restart_observation_order,
        _mutate_bad_bundle_version,
        _mutate_missing_key,
        _mutate_extra_key,
        _mutate_forged_boolean_issued_at,
    ],
)
def test_capture_refuses_corrupted_bundle(mutate: Mutation) -> None:
    bundle = base_bundle()
    mutate(bundle)
    with pytest.raises(SafePayV2CaptureError):
        build_safepay_v2_artifact(bundle)


def test_baseline_bundle_is_accepted_after_deepcopy() -> None:
    # Guards the mutation matrix: an unmutated deep copy must still verify, so a
    # refusal above can only come from the mutation, never from fixture drift.
    build_safepay_v2_artifact(copy.deepcopy(base_bundle()))
