from __future__ import annotations

import copy
import dataclasses
from collections.abc import Callable

import pytest
from pycspr.factory.accounts import parse_private_key_bytes
from pycspr.types.crypto import KeyAlgorithm

from shared.native_transfer_deploy import (
    DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
    build_signed_native_transfer_deploy,
)
from shared.native_transfer_finality import (
    FINALITY_PREDICATE_CHECKS,
    FinalizedNativeTransferProof,
    NativeTransferFinalityError,
    require_verified_finalized_native_transfer,
    verify_finalized_native_transfer,
)


SOURCE_KEY = parse_private_key_bytes(bytes(range(1, 33)), KeyAlgorithm.ED25519)
SOURCE_ACCOUNT = SOURCE_KEY.to_public_key().to_account_hash()
RECIPIENT = bytes.fromhex("22" * 32)
AMOUNT = 50_000_000_000
TRANSFER_ID = 0x0102_0304_0506_0708
BLOCK_HASH = "ab" * 32
STATE_ROOT_HASH = "cd" * 32
BLOCK_HEIGHT = 8_400_123
GAS_MOTES = 100_000_000
NODE_A = "https://node.testnet.casper.network/rpc"
NODE_B = "https://rpc.testnet.casperlabs.io/rpc"


def _signed_deploy(**overrides: object) -> bytes:
    values: dict[str, object] = {
        "source_private_key": SOURCE_KEY,
        "recipient_account_hash": RECIPIENT,
        "amount_motes": AMOUNT,
        "transfer_id": TRANSFER_ID,
        "payment_amount_motes": DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
        "timestamp_seconds": 1_753_228_800.0,
        "ttl": "30m",
    }
    values.update(overrides)
    return build_signed_native_transfer_deploy(**values)


SIGNED_DEPLOY = _signed_deploy()


def _deploy_hash() -> str:
    from shared.native_transfer_deploy import validate_signed_native_transfer_deploy

    return validate_signed_native_transfer_deploy(
        SIGNED_DEPLOY,
        expected_source_account_hash=SOURCE_ACCOUNT,
        expected_recipient_account_hash=RECIPIENT,
        expected_amount_motes=AMOUNT,
        expected_transfer_id=TRANSFER_ID,
    ).deploy_hash_hex


DEPLOY_HASH = _deploy_hash()


def _legacy_deploy_payload() -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "api_version": "1.5.8",
            "deploy": {"hash": DEPLOY_HASH},
            "execution_results": [
                {
                    "block_hash": BLOCK_HASH,
                    "result": {
                        "Success": {
                            "cost": "100000000",
                            "transfers": ["transfer-" + ("12" * 32)],
                        }
                    },
                }
            ],
        },
    }


def _modern_deploy_payload() -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "name": "info_get_deploy_result",
            "value": {
                "api_version": "2.0.0",
                "deploy": {"hash": DEPLOY_HASH},
                "execution_info": {
                    "block_hash": BLOCK_HASH,
                    "block_height": BLOCK_HEIGHT,
                    "execution_result": {
                        "Version2": {
                            "initiator": {"PublicKey": SOURCE_KEY.account_key.hex()},
                            "error_message": None,
                            "cost": "100000000",
                        }
                    },
                },
            },
        },
    }


def _transaction_payload() -> dict[str, object]:
    payload = _modern_deploy_payload()
    value = payload["result"]["value"]  # type: ignore[index]
    value.pop("deploy")
    value["transaction"] = {"Deploy": {"hash": DEPLOY_HASH}}
    payload["result"]["name"] = "info_get_transaction_result"  # type: ignore[index]
    return payload


def _version1_execution_payload() -> dict[str, object]:
    payload = _modern_deploy_payload()
    payload["result"]["value"]["execution_info"]["execution_result"] = {  # type: ignore[index]
        "Version1": {
            "Success": {
                "cost": str(GAS_MOTES),
                "transfers": ["transfer-" + ("12" * 32)],
            }
        }
    }
    return payload


def _legacy_block_payload() -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "api_version": "1.5.8",
            "block": {
                "hash": BLOCK_HASH,
                "header": {
                    "height": BLOCK_HEIGHT,
                    "state_root_hash": STATE_ROOT_HASH,
                },
                "body": {
                    "deploy_hashes": [],
                    "transfer_hashes": [DEPLOY_HASH],
                },
            },
        },
    }


def _modern_block_payload() -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "name": "chain_get_block_result",
            "value": {
                "api_version": "2.0.0",
                "block_with_signatures": {
                    "block": {
                        "Version2": {
                            "hash": BLOCK_HASH,
                            "header": {
                                "height": BLOCK_HEIGHT,
                                "state_root_hash": STATE_ROOT_HASH,
                            },
                            "body": {
                                "transactions": {
                                    "0": [{"Deploy": DEPLOY_HASH}],
                                    "1": [],
                                }
                            },
                        }
                    },
                    "proofs": [],
                },
            },
        },
    }


def _wrapped_version1_block_payload() -> dict[str, object]:
    legacy = _legacy_block_payload()["result"]["block"]  # type: ignore[index]
    return {
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "name": "chain_get_block_result",
            "value": {
                "block_with_signatures": {
                    "block": {"Version1": legacy},
                    "proofs": [],
                }
            },
        },
    }


def _status_request(request_id: int) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "info_get_status",
        "params": {},
    }


def _status_payload(request_id: int) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "name": "info_get_status_result",
            "value": {"api_version": "2.0.0", "chainspec_name": "casper-test"},
        },
    }


def _transaction_request(
    payload: dict[str, object], request_id: int
) -> dict[str, object]:
    value = payload.get("result", {})
    if type(value) is dict and type(value.get("value")) is dict:
        value = value["value"]
    method = (
        "info_get_transaction"
        if type(value) is dict and value.get("transaction") is not None
        else "info_get_deploy"
    )
    params: dict[str, object]
    if method == "info_get_transaction":
        params = {
            "transaction_hash": {"Deploy": DEPLOY_HASH},
            "finalized_approvals": True,
        }
    else:
        params = {"deploy_hash": DEPLOY_HASH, "finalized_approvals": True}
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def _block_request(request_id: int) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "chain_get_block",
        "params": {"block_identifier": {"Hash": BLOCK_HASH}},
    }


def _node_observation(
    *,
    node_url: str,
    captured_at: str,
    rpc_payload: dict[str, object] | None = None,
    block_payload: dict[str, object] | None = None,
    request_id_offset: int = 0,
) -> dict[str, object]:
    rpc = copy.deepcopy(
        rpc_payload if rpc_payload is not None else _modern_deploy_payload()
    )
    block = copy.deepcopy(
        block_payload if block_payload is not None else _modern_block_payload()
    )
    status_id = 90 + request_id_offset
    transaction_id = rpc.get("id", 1)
    block_id = block.get("id", 2)
    requested_block_hash = BLOCK_HASH
    try:
        rpc_value = rpc["result"].get("value", rpc["result"])
        execution = rpc_value.get("execution_info")
        if execution is not None:
            requested_block_hash = execution["block_hash"]
        else:
            requested_block_hash = rpc_value["execution_results"][0]["block_hash"]
    except (KeyError, TypeError, IndexError):
        pass
    return {
        "node_url": node_url,
        "captured_at": captured_at,
        "status_request": _status_request(status_id),
        "status_response": _status_payload(status_id),
        "transaction_request": _transaction_request(rpc, transaction_id),
        "transaction_response": rpc,
        "canonical_block_request": {
            **_block_request(block_id),
            "params": {"block_identifier": {"Hash": requested_block_hash}},
        },
        "canonical_block_response": block,
    }


def _verify(
    rpc_payload: dict[str, object] | None = None,
    block_payload: dict[str, object] | None = None,
    **overrides: object,
) -> FinalizedNativeTransferProof:
    rpc = rpc_payload if rpc_payload is not None else _modern_deploy_payload()
    block = block_payload if block_payload is not None else _modern_block_payload()
    values: dict[str, object] = {
        "requested_deploy_hash": DEPLOY_HASH,
        "node_observations": (
            _node_observation(
                node_url=NODE_A,
                captured_at="2026-07-23T00:01:02Z",
                rpc_payload=rpc,
                block_payload=block,
            ),
            _node_observation(
                node_url=NODE_B,
                captured_at="2026-07-23T00:01:04Z",
                rpc_payload=rpc,
                block_payload=block,
                request_id_offset=100,
            ),
        ),
        "signed_deploy_bytes": SIGNED_DEPLOY,
        "expected_source_account_hash": SOURCE_ACCOUNT,
        "expected_recipient_account_hash": RECIPIENT,
        "expected_amount_motes": AMOUNT,
        "expected_transfer_id": TRANSFER_ID,
        "expected_payment_amount_motes": DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
        "max_payment_amount_motes": DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
    }
    values.update(overrides)
    return verify_finalized_native_transfer(**values)


@pytest.mark.parametrize(
    ("rpc_payload", "block_payload", "rpc_method", "result_kind", "inclusion_path"),
    [
        (
            _legacy_deploy_payload,
            _legacy_block_payload,
            "info_get_deploy",
            "Success",
            "transfer_hashes",
        ),
        (
            _modern_deploy_payload,
            _wrapped_version1_block_payload,
            "info_get_deploy",
            "Version2",
            "transfer_hashes",
        ),
        (
            _modern_deploy_payload,
            _modern_block_payload,
            "info_get_deploy",
            "Version2",
            "transactions.0",
        ),
        (
            _version1_execution_payload,
            _modern_block_payload,
            "info_get_deploy",
            "Version1.Success",
            "transactions.0",
        ),
        (
            _transaction_payload,
            _modern_block_payload,
            "info_get_transaction",
            "Version2",
            "transactions.0",
        ),
    ],
    ids=(
        "legacy-deploy",
        "wrapped-v1-block",
        "modern-deploy",
        "version1-execution",
        "modern-transaction",
    ),
)
def test_accepts_strict_node_finality_shapes_and_returns_immutable_proof(
    rpc_payload: Callable[[], dict[str, object]],
    block_payload: Callable[[], dict[str, object]],
    rpc_method: str,
    result_kind: str,
    inclusion_path: str,
) -> None:
    proof = _verify(rpc_payload(), block_payload())

    assert proof.requested_deploy_hash == DEPLOY_HASH
    assert proof.deploy_hash == DEPLOY_HASH
    assert proof.block_hash == BLOCK_HASH
    assert proof.block_height == BLOCK_HEIGHT
    assert proof.state_root_hash == STATE_ROOT_HASH
    assert proof.rpc_method == rpc_method
    assert proof.execution_result_kind == result_kind
    assert proof.gas_motes == GAS_MOTES
    assert proof.block_inclusion_path == inclusion_path
    assert proof.finality_predicate is True
    assert proof.finality_checks == FINALITY_PREDICATE_CHECKS
    assert proof.network == "casper-test"
    assert proof.node_observation_count == 2
    assert proof.corroboration_count == 1
    assert proof.node_urls == (NODE_A, NODE_B)
    assert proof.captured_at == (
        "2026-07-23T00:01:02Z",
        "2026-07-23T00:01:04Z",
    )
    assert len(proof.node_observation_json) == 2
    assert len(proof.node_observation_sha256) == 2
    assert proof.verification_scope == (
        "two-or-more-public-rpc-nodes-agree;validator-signatures-not-verified"
    )
    assert "validator_signatures_verified" not in proof.__slots__
    assert proof.signed_deploy.deploy_hash_hex == DEPLOY_HASH
    assert proof.signed_deploy.source_account_hash == SOURCE_ACCOUNT
    assert proof.signed_deploy.recipient_account_hash == RECIPIENT
    assert proof.signed_deploy.amount_motes == AMOUNT
    assert proof.signed_deploy.transfer_id == TRANSFER_ID
    with pytest.raises(dataclasses.FrozenInstanceError):
        proof.block_height = 1  # type: ignore[misc]


def test_proof_constructor_is_hidden_and_executor_can_require_factory_provenance() -> (
    None
):
    proof = _verify()

    assert require_verified_finalized_native_transfer(proof) is proof
    with pytest.raises(TypeError):
        FinalizedNativeTransferProof()  # type: ignore[call-arg]
    fabricated = object.__new__(FinalizedNativeTransferProof)
    with pytest.raises(NativeTransferFinalityError, match="not parser-verified"):
        require_verified_finalized_native_transfer(fabricated)


def test_factory_integrity_gate_rejects_post_construction_field_tampering() -> None:
    proof = _verify()
    object.__setattr__(proof, "block_hash", "ef" * 32)

    with pytest.raises(NativeTransferFinalityError, match="integrity check failed"):
        require_verified_finalized_native_transfer(proof)


def test_factory_integrity_gate_seals_execution_gas() -> None:
    proof = _verify()
    object.__setattr__(proof, "gas_motes", GAS_MOTES + 1)

    with pytest.raises(NativeTransferFinalityError, match="integrity check failed"):
        require_verified_finalized_native_transfer(proof)


def test_accepts_json_integer_execution_cost_without_treating_bool_as_integer() -> None:
    payload = _modern_deploy_payload()
    payload["result"]["value"]["execution_info"]["execution_result"]["Version2"][
        "cost"
    ] = GAS_MOTES  # type: ignore[index]

    assert _verify(payload).gas_motes == GAS_MOTES


@pytest.mark.parametrize(
    "bad_cost",
    (
        None,
        True,
        -1,
        "",
        "01",
        "-1",
        "+1",
        "1.0",
        str(1 << 512),
        {"value": str(GAS_MOTES)},
    ),
    ids=(
        "null",
        "bool",
        "negative-int",
        "empty",
        "leading-zero",
        "negative-string",
        "plus-sign",
        "decimal-point",
        "u512-overflow",
        "object",
    ),
)
def test_rejects_malformed_or_overflow_execution_cost(bad_cost: object) -> None:
    payload = _modern_deploy_payload()
    payload["result"]["value"]["execution_info"]["execution_result"]["Version2"][
        "cost"
    ] = bad_cost  # type: ignore[index]

    with pytest.raises(
        NativeTransferFinalityError,
        match="execution cost must be canonical non-negative U512 decimal",
    ):
        _verify(payload)


@pytest.mark.parametrize(
    "payload_factory",
    (_legacy_deploy_payload, _version1_execution_payload, _modern_deploy_payload),
    ids=("legacy", "version1", "version2"),
)
def test_rejects_absent_execution_cost(
    payload_factory: Callable[[], dict[str, object]],
) -> None:
    payload = payload_factory()
    value = payload["result"]  # type: ignore[index]
    if "execution_results" in value:
        value["execution_results"][0]["result"]["Success"].pop("cost")
        block = _legacy_block_payload()
    else:
        result = value["value"]["execution_info"]["execution_result"]
        if "Version1" in result:
            result["Version1"]["Success"].pop("cost")
        else:
            result["Version2"].pop("cost")
        block = _modern_block_payload()

    with pytest.raises(NativeTransferFinalityError, match="execution cost is required"):
        _verify(payload, block)


def test_rejects_ambiguous_execution_cost_keys() -> None:
    payload = _modern_deploy_payload()
    versioned = payload["result"]["value"]["execution_info"]["execution_result"][
        "Version2"
    ]  # type: ignore[index]
    versioned["Cost"] = versioned["cost"]

    with pytest.raises(
        NativeTransferFinalityError, match="execution cost is ambiguous"
    ):
        _verify(payload)


def test_accepts_full_node_rpc_corroboration_only_when_it_agrees() -> None:
    proof = _verify(
        node_observations=(
            _node_observation(
                node_url=NODE_A,
                captured_at="2026-07-23T00:01:02Z",
                rpc_payload=_legacy_deploy_payload(),
                block_payload=_legacy_block_payload(),
            ),
            _node_observation(
                node_url=NODE_B,
                captured_at="2026-07-23T00:01:04Z",
                rpc_payload=_transaction_payload(),
                block_payload=_modern_block_payload(),
            ),
        )
    )

    assert proof.corroboration_count == 1


@pytest.mark.parametrize(
    ("requested_hash", "error"),
    [
        ("ff" * 32, "returned deploy hash does not match requested hash"),
        (DEPLOY_HASH.upper(), "requested deploy hash must be lowercase 32-byte hex"),
        ("short", "requested deploy hash must be lowercase 32-byte hex"),
    ],
)
def test_rejects_wrong_or_malformed_requested_hash(
    requested_hash: str, error: str
) -> None:
    with pytest.raises(NativeTransferFinalityError, match=error):
        _verify(requested_deploy_hash=requested_hash)


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        ({"jsonrpc": "2.0", "error": {"code": -1}}, "RPC payload contains error"),
        ({"jsonrpc": "2.0", "result": {}}, "RPC result is malformed"),
        ({"finalized": True, "success": True}, "RPC result is malformed"),
        (
            {
                "result": {
                    "deploy": {"hash": DEPLOY_HASH},
                    "transaction": {"Version1": {"hash": DEPLOY_HASH}},
                    "execution_info": {},
                }
            },
            "RPC result must contain exactly one deploy or transaction",
        ),
    ],
    ids=("rpc-error", "empty-result", "explorer-booleans", "ambiguous-returned-item"),
)
def test_rejects_non_node_or_ambiguous_rpc_payload(
    payload: dict[str, object], error: str
) -> None:
    with pytest.raises(NativeTransferFinalityError, match=error):
        _verify(payload)


def test_rejects_returned_deploy_hash_mismatch() -> None:
    payload = _modern_deploy_payload()
    payload["result"]["value"]["deploy"]["hash"] = "ef" * 32  # type: ignore[index]

    with pytest.raises(
        NativeTransferFinalityError,
        match="returned deploy hash does not match requested hash",
    ):
        _verify(payload)


@pytest.mark.parametrize(
    "execution_field", (None, {}, []), ids=("absent", "empty-map", "empty-list")
)
def test_rejects_pending_or_absent_execution_result(execution_field: object) -> None:
    payload = _modern_deploy_payload()
    value = payload["result"]["value"]  # type: ignore[index]
    if execution_field is None:
        value.pop("execution_info")
    else:
        value["execution_info"] = execution_field

    with pytest.raises(
        NativeTransferFinalityError, match="processed execution result is required"
    ):
        _verify(payload)


def test_rejects_duplicate_legacy_execution_results_even_if_identical() -> None:
    payload = _legacy_deploy_payload()
    results = payload["result"]["execution_results"]  # type: ignore[index]
    results.append(copy.deepcopy(results[0]))

    with pytest.raises(
        NativeTransferFinalityError, match="exactly one execution result is required"
    ):
        _verify(payload, _legacy_block_payload())


def test_rejects_duplicate_execution_sources() -> None:
    payload = _modern_deploy_payload()
    value = payload["result"]["value"]  # type: ignore[index]
    value["execution_results"] = [
        {"block_hash": BLOCK_HASH, "result": {"Success": {"cost": "1"}}}
    ]

    with pytest.raises(
        NativeTransferFinalityError, match="execution evidence is ambiguous"
    ):
        _verify(payload)


@pytest.mark.parametrize(
    ("mutator", "error"),
    [
        (
            lambda result: result.update({"Failure": {"error_message": "revert"}}),
            "execution failed",
        ),
        (
            lambda result: result["Version2"].update({"error_message": "revert"}),
            "execution failed",
        ),
        (
            lambda result: result["Version2"].update(
                {"Failure": {"error_message": "revert"}}
            ),
            "execution failed",
        ),
    ],
    ids=("legacy-failure", "version2-error", "version2-failure-marker"),
)
def test_rejects_failure_or_error_markers(
    mutator: Callable[[dict[str, object]], None],
    error: str,
    request: pytest.FixtureRequest,
) -> None:
    if request.node.callspec.id == "legacy-failure":
        payload = _legacy_deploy_payload()
        result = payload["result"]["execution_results"][0]["result"]  # type: ignore[index]
        result.pop("Success")
        mutator(result)
        block = _legacy_block_payload()
    else:
        payload = _modern_deploy_payload()
        result = payload["result"]["value"]["execution_info"]["execution_result"]  # type: ignore[index]
        mutator(result)
        block = _modern_block_payload()

    with pytest.raises(NativeTransferFinalityError, match=error):
        _verify(payload, block)


def test_rejects_legacy_result_with_both_success_and_failure() -> None:
    payload = _legacy_deploy_payload()
    result = payload["result"]["execution_results"][0]["result"]  # type: ignore[index]
    result["Failure"] = {"error_message": "conflict"}

    with pytest.raises(
        NativeTransferFinalityError, match="execution result is conflicting"
    ):
        _verify(payload, _legacy_block_payload())


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        (
            "block_hash",
            "ef" * 32,
            "canonical block hash does not match execution block",
        ),
        (
            "block_hash",
            BLOCK_HASH.upper(),
            "execution block hash must be lowercase 32-byte hex",
        ),
        (
            "block_height",
            BLOCK_HEIGHT + 1,
            "execution block height does not match canonical block",
        ),
        ("block_height", True, "execution block height must be a non-negative integer"),
    ],
)
def test_rejects_wrong_execution_block_fields(
    field: str, value: object, error: str
) -> None:
    payload = _modern_deploy_payload()
    payload["result"]["value"]["execution_info"][field] = value  # type: ignore[index]

    with pytest.raises(NativeTransferFinalityError, match=error):
        _verify(payload)


@pytest.mark.parametrize(
    ("mutator", "error"),
    [
        (
            lambda block: block.update({"hash": "ef" * 32}),
            "canonical block hash does not match execution block",
        ),
        (
            lambda block: block.update({"hash": BLOCK_HASH.upper()}),
            "canonical block hash must be lowercase 32-byte hex",
        ),
        (
            lambda block: block["header"].update({"state_root_hash": "EF" * 32}),
            "canonical state root hash must be lowercase 32-byte hex",
        ),
        (
            lambda block: block["header"].update({"height": -1}),
            "canonical block height must be a non-negative integer",
        ),
        (
            lambda block: block["body"]["transactions"]["0"].clear(),
            "requested deploy is absent from canonical block",
        ),
        (
            lambda block: block["body"]["transactions"]["0"].append(
                {"Deploy": DEPLOY_HASH}
            ),
            "requested deploy appears multiple times in canonical block",
        ),
    ],
    ids=(
        "wrong-hash",
        "uppercase-hash",
        "bad-state-root",
        "bad-height",
        "absent",
        "duplicate",
    ),
)
def test_rejects_malformed_or_nonmatching_canonical_block(
    mutator: Callable[[dict[str, object]], None], error: str
) -> None:
    payload = _modern_block_payload()
    block = payload["result"]["value"]["block_with_signatures"]["block"]["Version2"]  # type: ignore[index]
    mutator(block)

    with pytest.raises(NativeTransferFinalityError, match=error):
        _verify(block_payload=payload)


def test_rejects_block_rpc_error_or_explorer_boolean() -> None:
    with pytest.raises(
        NativeTransferFinalityError, match="canonical block payload contains error"
    ):
        _verify(block_payload={"jsonrpc": "2.0", "id": 2, "error": {"code": -1}})
    with pytest.raises(NativeTransferFinalityError, match="canonical block response"):
        _verify(block_payload={"finalized": True, "block_hash": BLOCK_HASH})


def test_rejects_tampered_or_wrong_signed_deploy() -> None:
    tampered = SIGNED_DEPLOY[:-1] + bytes([SIGNED_DEPLOY[-1] ^ 1])
    with pytest.raises(
        NativeTransferFinalityError, match="signed deploy validation failed"
    ):
        _verify(signed_deploy_bytes=tampered)
    with pytest.raises(
        NativeTransferFinalityError, match="signed deploy validation failed"
    ):
        _verify(expected_amount_motes=AMOUNT + 1)


def test_rejects_signed_deploy_whose_derived_hash_differs_from_request() -> None:
    other = _signed_deploy(transfer_id=TRANSFER_ID + 1)

    with pytest.raises(
        NativeTransferFinalityError,
        match="signed deploy hash does not match requested hash",
    ):
        _verify(signed_deploy_bytes=other, expected_transfer_id=TRANSFER_ID + 1)


def test_rejects_conflicting_or_explorer_only_corroboration() -> None:
    conflicting = _modern_deploy_payload()
    conflicting["result"]["value"]["execution_info"]["block_hash"] = "ef" * 32  # type: ignore[index]
    conflicting_block = _modern_block_payload()
    conflicting_block["result"]["value"]["block_with_signatures"]["block"]["Version2"][
        "hash"
    ] = "ef" * 32  # type: ignore[index]
    observations = list(_verify_inputs())
    observations[1] = _node_observation(
        node_url=NODE_B,
        captured_at="2026-07-23T00:01:04Z",
        rpc_payload=conflicting,
        block_payload=conflicting_block,
    )
    with pytest.raises(NativeTransferFinalityError, match="node observations conflict"):
        _verify(node_observations=tuple(observations))

    malformed = _node_observation(
        node_url=NODE_B,
        captured_at="2026-07-23T00:01:04Z",
    )
    malformed["transaction_response"] = {"finalized": True, "success": True}
    with pytest.raises(
        NativeTransferFinalityError, match="node observation is malformed"
    ):
        _verify(node_observations=(_verify_inputs()[0], malformed))

    conflicting_cost = _modern_deploy_payload()
    conflicting_cost["result"]["value"]["execution_info"]["execution_result"][
        "Version2"
    ]["cost"] = str(GAS_MOTES + 1)  # type: ignore[index]
    cost_observation = _node_observation(
        node_url=NODE_B,
        captured_at="2026-07-23T00:01:04Z",
        rpc_payload=conflicting_cost,
    )
    with pytest.raises(NativeTransferFinalityError, match="node observations conflict"):
        _verify(node_observations=(_verify_inputs()[0], cost_observation))


def _verify_inputs() -> tuple[dict[str, object], dict[str, object]]:
    return (
        _node_observation(
            node_url=NODE_A,
            captured_at="2026-07-23T00:01:02Z",
        ),
        _node_observation(
            node_url=NODE_B,
            captured_at="2026-07-23T00:01:04Z",
            request_id_offset=100,
        ),
    )


def test_requires_two_distinct_public_credential_free_rpc_nodes() -> None:
    first, second = _verify_inputs()
    with pytest.raises(NativeTransferFinalityError, match="at least two"):
        _verify(node_observations=(first,))

    second["node_url"] = NODE_A
    with pytest.raises(NativeTransferFinalityError, match="distinct"):
        _verify(node_observations=(first, second))

    first, second = _verify_inputs()
    second["node_url"] = "https://node.testnet.casper.network/"
    with pytest.raises(NativeTransferFinalityError, match="distinct"):
        _verify(node_observations=(first, second))


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://node.example/rpc",
        "https://user:secret@node.example/rpc",
        "https://node.example/rpc?token=secret",
        "https://node.example/rpc#fragment",
        "https://127.0.0.1/rpc",
        "https://10.0.0.1/rpc",
        "https://localhost/rpc",
        "https://node.example/rpc/secret-token",
    ],
)
def test_rejects_nonpublic_or_credential_bearing_node_identity(bad_url: str) -> None:
    first, second = _verify_inputs()
    first["node_url"] = bad_url
    with pytest.raises(NativeTransferFinalityError, match="public credential-free"):
        _verify(node_observations=(first, second))


@pytest.mark.parametrize(
    ("section", "mutation", "error"),
    [
        (
            "status_request",
            lambda value: value.update(method="info_get_peers"),
            "info_get_status",
        ),
        ("status_response", lambda value: value.update(id=999), "response id"),
        (
            "transaction_request",
            lambda value: value.update(method="info_get_status"),
            "transaction request",
        ),
        (
            "transaction_request",
            lambda value: value["params"].update(deploy_hash="ef" * 32),
            "transaction request params",
        ),
        ("transaction_response", lambda value: value.update(id=999), "response id"),
        (
            "canonical_block_request",
            lambda value: value["params"]["block_identifier"].update(Hash="ef" * 32),
            "canonical block request params",
        ),
        ("canonical_block_response", lambda value: value.update(id=999), "response id"),
    ],
)
def test_every_raw_rpc_request_and_response_is_exactly_bound(
    section: str, mutation: Callable[[dict[str, object]], None], error: str
) -> None:
    first, second = _verify_inputs()
    target = first[section]
    assert type(target) is dict
    mutation(target)
    with pytest.raises(NativeTransferFinalityError, match=error):
        _verify(node_observations=(first, second))


def test_each_status_response_must_prove_exact_casper_test_network() -> None:
    first, second = _verify_inputs()
    first["status_response"]["result"]["value"]["chainspec_name"] = "casper"  # type: ignore[index]
    with pytest.raises(NativeTransferFinalityError, match="casper-test"):
        _verify(node_observations=(first, second))


@pytest.mark.parametrize(
    "bad_timestamp",
    ["", "2026-07-23 00:01:02Z", "2026-07-23T00:01:02+00:00", "tomorrow"],
)
def test_capture_timestamp_is_canonical_utc_rfc3339(bad_timestamp: str) -> None:
    first, second = _verify_inputs()
    first["captured_at"] = bad_timestamp
    with pytest.raises(NativeTransferFinalityError, match="capture timestamp"):
        _verify(node_observations=(first, second))


def test_canonical_transcripts_are_preserved_and_sealed() -> None:
    proof = _verify()
    assert '"method":"info_get_status"' in proof.node_observation_json[0]
    assert '"method":"info_get_deploy"' in proof.node_observation_json[0]
    assert '"method":"chain_get_block"' in proof.node_observation_json[0]

    object.__setattr__(proof, "node_observation_json", ("{}", "{}"))
    with pytest.raises(NativeTransferFinalityError, match="integrity"):
        require_verified_finalized_native_transfer(proof)
