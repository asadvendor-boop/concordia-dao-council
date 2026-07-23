"""Fail-closed construction of executable v3 native authorizations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from shared.v3_authorization import (
    V3AuthorizationError,
    V3ChainReadback,
    V3DeploymentIdentity,
    validate_verified_authorization,
    verify_exact_v3_finalization,
    verify_native_authorization,
)
from shared.casper_state_proof import verify_account_balance_at_block
from shared.treasury_snapshot import verify_treasury_snapshot_artifact
from scripts.read_v3_state import verify_and_seal_readback_artifact
from tests.v3_treasury_fixtures import treasury_v3_proof


PROOF = treasury_v3_proof(
    source_account=bytes.fromhex("41" * 32),
    recipient_account=bytes.fromhex("42" * 32),
)


def _inputs() -> tuple[dict[str, object], dict[str, object]]:
    return dict(PROOF["input"]["header"]), dict(PROOF["input"]["body"])


def _deployment(
    header: dict[str, object], proof: dict[str, object] = PROOF
) -> V3DeploymentIdentity:
    raw = proof["deployment"]
    return V3DeploymentIdentity(
        network="casper-test",
        package_hash=bytes.fromhex(str(raw["package_hash"])),
        contract_hash=bytes.fromhex(str(raw["contract_hash"])),
        schema_version=3,
        deployment_domain=bytes.fromhex(str(header["deployment_domain"])),
        casper_chain_name="casper-test",
        source_sha256=bytes.fromhex(str(raw["source"]["lib_rs_sha256"])),
        wasm_sha256=bytes.fromhex(str(raw["build"]["wasm_sha256"])),
        schema_sha256=bytes.fromhex(str(raw["build"]["schema_sha256"])),
    )


def _readback(
    header: dict[str, object],
    deployment: V3DeploymentIdentity,
    *,
    observed_block_height: int = 9_010,
) -> V3ChainReadback:
    readback = verify_and_seal_readback_artifact(PROOF["readback"])
    if observed_block_height != readback.observed_block_height:
        object.__setattr__(readback, "observed_block_height", observed_block_height)
    return readback


def _finalization():
    return verify_exact_v3_finalization(PROOF)


def _snapshot(body: dict[str, object]):
    block_hash = str(body["snapshot_block_hash"])
    block_height = int(str(body["snapshot_block_height"]))
    state_root = "98" * 32
    account_hash = bytes.fromhex(str(body["source_account"]))
    balance = int(str(body["treasury_snapshot_balance_motes"]))
    primary = verify_account_balance_at_block(
        chain_status_request={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "info_get_status",
            "params": {},
        },
        chain_status_payload={
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"chainspec_name": "casper-test"},
        },
        canonical_block_request={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "chain_get_block",
            "params": {"block_identifier": {"Hash": block_hash}},
        },
        canonical_block_payload={
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "block": {
                    "hash": block_hash,
                    "header": {
                        "height": block_height,
                        "state_root_hash": state_root,
                    },
                    "body": {},
                }
            },
        },
        balance_request={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "query_balance_details",
            "params": {
                "state_identifier": {"StateRootHash": state_root},
                "purse_identifier": {
                    "main_purse_under_account_hash": f"account-hash-{account_hash.hex()}"
                },
            },
        },
        balance_response={
            "jsonrpc": "2.0",
            "id": 3,
            "result": {
                "name": "query_balance_details_result",
                "value": {
                    "api_version": "2.0.0",
                    "total_balance": str(balance),
                    "available_balance": str(balance),
                    "total_balance_proof": "01" + ("ab" * 96),
                    "holds": [],
                },
            },
        },
        expected_account_hash=account_hash,
        expected_block_hash=bytes.fromhex(block_hash),
        expected_block_height=block_height,
        expected_state_root_hash=bytes.fromhex(state_root),
        expected_balance_motes=balance,
    )
    observations = []
    for index, node in enumerate(("rpc-a.example", "rpc-b.example"), start=1):
        observation = {
            "node_url": f"https://{node}/rpc",
            "captured_at": f"2026-07-23T00:00:0{index}Z",
            "status_request": json.loads(primary.status_request_json),
            "status_response": json.loads(primary.status_json),
            "block_request": json.loads(primary.block_request_json),
            "block_response": json.loads(primary.block_json),
            "balance_request": json.loads(primary.balance_request_json),
            "balance_response": json.loads(primary.balance_response_json),
        }
        for field in (
            "status_request",
            "status_response",
            "block_request",
            "block_response",
            "balance_request",
            "balance_response",
        ):
            observation[field]["id"] = index
        observations.append(observation)
    return verify_treasury_snapshot_artifact(
        {
            "schema_id": "concordia.native-treasury-snapshot.v1",
            "network": "casper-test",
            "source_account_hash": account_hash.hex(),
            "expected_balance_motes": str(balance),
            "observations": observations,
        },
        expected_account_hash=account_hash,
        expected_block_hash=bytes.fromhex(block_hash),
        expected_block_height=block_height,
        expected_balance_motes=balance,
    )


def test_factory_binds_complete_native_envelope_to_chain_and_snapshot() -> None:
    header, body = _inputs()
    deployment = _deployment(header)

    verified = verify_native_authorization(
        header=header,
        body=body,
        deployment=deployment,
        readback=_readback(header, deployment),
        snapshot=_snapshot(body),
        finalization=_finalization(),
    )

    assert verified.proposal_id == header["proposal_id"]
    assert verified.action_id == bytes.fromhex(str(header["action_id"]))
    assert verified.envelope_hash.hex() == PROOF["prepared"]["envelope_hash"]
    assert verified.amount_motes == 50_000_000_000
    assert verified.treasury_snapshot_balance_motes == 625_000_000_000
    assert verified.approved_allocation_bps == 800
    assert verified.snapshot_state_root_hash == bytes.fromhex("98" * 32)
    exact = next(
        step for step in PROOF["run"]["steps"] if step["name"] == "finalize_exact"
    )
    assert (
        verified.finalization_state_root_hash.hex()
        == exact["finality_block_evidence"]["state_root_hash"]
    )
    assert (
        verified.finalization_block_height
        == exact["finality_block_evidence"]["block_height"]
    )
    assert (
        verified.finalization_block_height
        < verify_and_seal_readback_artifact(PROOF["readback"]).observed_block_height
    )


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("network", "casper-testnet"),
        ("package_hash", bytes.fromhex("a1" * 32)),
        ("contract_hash", bytes.fromhex("a2" * 32)),
        ("schema_version", 2),
        ("deployment_domain", bytes.fromhex("a3" * 32)),
        ("casper_chain_name", "casper-mainnet"),
        ("proposal_id", "DAO-PROP-OTHER"),
        ("proposed_envelope", bytes.fromhex("a4" * 32)),
        ("finalized", False),
        ("finalized_envelope", bytes.fromhex("a5" * 32)),
        ("action_id", bytes.fromhex("a6" * 32)),
        ("action_authorized", False),
    ],
)
def test_factory_rejects_every_mismatched_chain_binding(
    field: str,
    bad_value: object,
) -> None:
    header, body = _inputs()
    deployment = _deployment(header)
    readback = _readback(header, deployment)
    object.__setattr__(readback, field, bad_value)

    with pytest.raises(V3AuthorizationError, match="readback"):
        verify_native_authorization(
            header=header,
            body=body,
            deployment=deployment,
            readback=readback,
            snapshot=_snapshot(body),
            finalization=_finalization(),
        )


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("network", "casper-testnet"),
        ("block_hash", bytes.fromhex("b1" * 32)),
        ("block_height", 8_590_557),
        ("account_hash", bytes.fromhex("b2" * 32)),
        ("balance_motes", 625_000_000_001),
    ],
)
def test_factory_rejects_every_mismatched_snapshot_binding(
    field: str,
    bad_value: object,
) -> None:
    header, body = _inputs()
    deployment = _deployment(header)
    snapshot = _snapshot(body)
    object.__setattr__(snapshot, field, bad_value)

    with pytest.raises(V3AuthorizationError, match="parser-verified"):
        verify_native_authorization(
            header=header,
            body=body,
            deployment=deployment,
            readback=_readback(header, deployment),
            snapshot=snapshot,
            finalization=_finalization(),
        )


def test_snapshot_must_precede_exact_finalization_block() -> None:
    proof = treasury_v3_proof(
        source_account=bytes.fromhex("41" * 32),
        recipient_account=bytes.fromhex("42" * 32),
        snapshot_block_height=9_007,
    )
    header = proof["input"]["header"]
    body = proof["input"]["body"]
    deployment = _deployment(header, proof)

    with pytest.raises(V3AuthorizationError, match="precede"):
        verify_native_authorization(
            header=header,
            body=body,
            deployment=deployment,
            readback=verify_and_seal_readback_artifact(proof["readback"]),
            snapshot=_snapshot(body),
            finalization=verify_exact_v3_finalization(proof),
        )


def test_verified_authorization_integrity_seal_rejects_post_factory_mutation() -> None:
    header, body = _inputs()
    deployment = _deployment(header)
    verified = verify_native_authorization(
        header=header,
        body=body,
        deployment=deployment,
        readback=_readback(header, deployment),
        snapshot=_snapshot(body),
        finalization=_finalization(),
    )

    validate_verified_authorization(verified)
    forged = replace(verified, approved_allocation_bps=1_000)

    with pytest.raises(V3AuthorizationError, match="recomputed typed envelope"):
        validate_verified_authorization(forged)


def test_verified_authorization_reparses_raw_snapshot_transcript() -> None:
    header, body = _inputs()
    deployment = _deployment(header)
    verified = verify_native_authorization(
        header=header,
        body=body,
        deployment=deployment,
        readback=_readback(header, deployment),
        snapshot=_snapshot(body),
        finalization=_finalization(),
    )
    forged = replace(
        verified,
        snapshot_balance_response_json=verified.snapshot_balance_response_json.replace(
            "625000000000", "625000000001"
        ),
    )

    with pytest.raises(V3AuthorizationError, match="authorization transcript"):
        validate_verified_authorization(forged)


def test_verified_authorization_reparses_persisted_exact_finalization_proof() -> None:
    header, body = _inputs()
    deployment = _deployment(header)
    verified = verify_native_authorization(
        header=header,
        body=body,
        deployment=deployment,
        readback=_readback(header, deployment),
        snapshot=_snapshot(body),
        finalization=_finalization(),
    )
    proof = json.loads(verified.v3_proof_artifact_json)
    exact = next(
        step for step in proof["run"]["steps"] if step["name"] == "finalize_exact"
    )
    exact["finality_block_evidence"]["state_root_hash"] = "ff" * 32
    artifact_json = json.dumps(
        proof,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    forged = replace(
        verified,
        v3_proof_artifact_json=artifact_json,
        v3_proof_artifact_sha256=hashlib.sha256(
            artifact_json.encode("ascii")
        ).hexdigest(),
    )

    with pytest.raises(V3AuthorizationError, match="authorization transcript"):
        validate_verified_authorization(forged)
