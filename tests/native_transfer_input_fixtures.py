"""Shared raw-artifact fixtures for the production NativeTransferV1 builder."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from pycspr import serializer
from pycspr.types.node.rpc import Deploy

from shared.historical_odra_artifact import verify_historical_odra_artifact
from tests import test_historical_odra_artifact as historical_fixture
from tests.test_treasury_execution_operator import _snapshot_artifact
from tests.v3_treasury_fixtures import treasury_v3_proof


SOURCE_ACCOUNT = bytes.fromhex("41" * 32)
RECIPIENT_ACCOUNT = bytes.fromhex("42" * 32)


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _unwrap_result(response: dict[str, object]) -> dict[str, object]:
    result = response["result"]
    assert isinstance(result, dict)
    if set(result) == {"name", "value"}:
        result = result["value"]
        assert isinstance(result, dict)
    return result


def _historical_arguments(
    artifact: dict[str, object],
) -> tuple[dict[str, object], Deploy]:
    raw_rpc = artifact["raw_rpc"]
    assert isinstance(raw_rpc, dict)
    deploy_transcript = raw_rpc["deploy"]
    assert isinstance(deploy_transcript, dict)
    response = deploy_transcript["response"]
    assert isinstance(response, dict)
    raw_deploy = _unwrap_result(response)["deploy"]
    assert isinstance(raw_deploy, dict)
    deploy = serializer.from_json(raw_deploy, Deploy)
    values: dict[str, object] = {}
    for argument in deploy.session.arguments:
        value = argument.value.value
        values[argument.name] = value.hex() if isinstance(value, bytes) else value
    return values, deploy


def _canonical_receipt(
    artifact: dict[str, object],
    inventory_bytes: bytes,
) -> dict[str, object]:
    facts = verify_historical_odra_artifact(
        canonical_bytes(artifact),
        inventory_bytes=inventory_bytes,
    )
    values, deploy = _historical_arguments(artifact)
    types = {
        "proposal_id": "String",
        "proposal_type": "String",
        "proposal_hash": {"ByteArray": 32},
        "policy_hash": {"ByteArray": 32},
        "dissent_hash": {"ByteArray": 32},
        "final_card_hash": {"ByteArray": 32},
        "plan_hash": {"ByteArray": 32},
        "agent_action_hash": {"ByteArray": 32},
        "approved_allocation_bps": "U32",
        "risk_score": "U32",
        "risk_level": "String",
        "decision": "String",
        "treasury_action": "String",
        "policy_version": "String",
        "casper_network": "String",
        "agent_council_version": "String",
        "evidence_uri": "String",
    }
    proposal_id = str(values["proposal_id"])
    deploy_hash = str(facts["deployHash"])
    return {
        "agent_action_hash": values["agent_action_hash"],
        "approved_allocation_bps": values["approved_allocation_bps"],
        "block_hash": facts["blockHash"],
        "block_height": facts["blockHeight"],
        "caller_hash": deploy.header.account.to_account_hash().hex(),
        "caller_public_key": deploy.header.account.account_key.hex(),
        "contract_hash": "hash-" + str(facts["contractHash"]),
        "contract_package_hash": "hash-" + str(facts["packageHash"]),
        "cspr_live_api_url": f"https://api.testnet.cspr.live/deploys/{deploy_hash}",
        "decision": values["decision"],
        "deploy_hash": deploy_hash,
        "dissent_hash": values["dissent_hash"],
        "entry_point": "store_governance_receipt",
        "evidence_uri": values["evidence_uri"],
        "explorer_url": f"https://testnet.cspr.live/deploy/{deploy_hash}",
        "final_card_hash": values["final_card_hash"],
        "network": values["casper_network"],
        "plan_hash": values["plan_hash"],
        "policy_hash": values["policy_hash"],
        "proof_status": "complete",
        "proposal_hash": values["proposal_hash"],
        "proposal_id": proposal_id,
        "proposal_type": values["proposal_type"],
        "risk_level": values["risk_level"],
        "risk_score": values["risk_score"],
        "transaction_hash": deploy_hash,
        "typed_args": types,
        "verified_at_utc": "2026-07-23T03:00:01Z",
    }


def source_documents(monkeypatch) -> dict[str, object]:
    historical, inventory, _, _ = historical_fixture._fixture(monkeypatch)
    historical_bytes = canonical_bytes(historical)
    canonical_receipt = _canonical_receipt(historical, inventory)
    proof = treasury_v3_proof(
        source_account=SOURCE_ACCOUNT,
        recipient_account=RECIPIENT_ACCOUNT,
        proposal_id="DAO-PROP-V3-INPUT-BUILD",
        snapshot_block_height=9_001,
    )
    deployment = copy.deepcopy(proof["deployment"])
    snapshot = _snapshot_artifact(proof)
    body = proof["input"]["body"]
    snapshot_hash = str(body["snapshot_block_hash"])
    snapshot_height = int(str(body["snapshot_block_height"]))
    for observation in snapshot["observations"]:
        status = observation["status_response"]["result"]
        status["last_added_block_info"] = {
            "hash": snapshot_hash,
            "height": snapshot_height,
        }
    intent = {
        "schema_id": "concordia.native-transfer-v3-intent.v1",
        "network": "casper-test",
        "intent_id": "finals_native_transfer",
        "canonical_proposal_id": canonical_receipt["proposal_id"],
        "source_account_hash": SOURCE_ACCOUNT.hex(),
        "recipient_account_hash": RECIPIENT_ACCOUNT.hex(),
        "requested_allocation_bps": 3_000,
        "captured_at": "2026-07-24T00:00:00Z",
    }
    return {
        "historical": historical_bytes,
        "inventory": inventory,
        "canonical_receipt": canonical_bytes(canonical_receipt),
        "deployment": canonical_bytes(deployment),
        "snapshot": canonical_bytes(snapshot),
        "intent": canonical_bytes(intent),
    }


def write_source_documents(root: Path, sources: dict[str, object]) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    for name in (
        "historical",
        "inventory",
        "canonical_receipt",
        "deployment",
        "snapshot",
        "intent",
    ):
        path = root / f"{name}.json"
        value = sources[name]
        assert isinstance(value, bytes)
        path.write_bytes(value)
        paths[name] = path
    return paths


__all__ = [
    "RECIPIENT_ACCOUNT",
    "SOURCE_ACCOUNT",
    "canonical_bytes",
    "source_documents",
    "write_source_documents",
]
