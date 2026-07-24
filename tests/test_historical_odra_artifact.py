from __future__ import annotations

import copy
import hashlib
import json

import pytest
from pycspr import serializer
from pycspr.factory.accounts import parse_private_key_bytes
from pycspr.factory.deploys import (
    create_deploy,
    create_deploy_parameters,
    create_standard_payment,
)
from pycspr.types.cl import CLV_ByteArray, CLV_String, CLV_U32
from pycspr.types.crypto import KeyAlgorithm
from pycspr.types.node.rpc import DeployArgument, DeployOfStoredContractByHash

from shared.historical_odra_artifact import (
    HistoricalOdraArtifactError,
    HistoricalOdraArtifactUnavailable,
    verify_historical_odra_artifact,
)
from shared.exact_casper_deploy_json import exact_deploy_rpc_json


PROPOSAL_ID = "DAO-PROP-HIST-001"
PACKAGE_HASH = "21" * 32
CONTRACT_HASH = "32" * 32
WASM_HASH = "43" * 32
BLOCK_HASH = "54" * 32
STATE_ROOT = "65" * 32
BLOCK_HEIGHT = 9_001
SOURCE_COMMIT = "ab" * 20
DEPLOYMENT_COMMIT = "cd" * 20
CAPTURED_AT = "2026-07-23T03:00:00Z"
SIGNER = parse_private_key_bytes(bytes(range(1, 33)), KeyAlgorithm.ED25519)

ARGUMENT_VALUES = (
    ("proposal_id", CLV_String(PROPOSAL_ID)),
    ("proposal_type", CLV_String("TREASURY_REALLOCATION")),
    ("proposal_hash", CLV_ByteArray(bytes.fromhex("01" * 32))),
    ("final_card_hash", None),
    ("plan_hash", CLV_ByteArray(bytes.fromhex("02" * 32))),
    ("decision", CLV_String("APPROVED_WITH_LIMITS")),
    ("risk_level", CLV_String("high")),
    ("risk_score", CLV_U32(72)),
    ("treasury_action", CLV_String("rebalance")),
    ("policy_hash", CLV_ByteArray(bytes.fromhex("03" * 32))),
    ("policy_version", CLV_String("1.0")),
    ("dissent_hash", CLV_ByteArray(bytes.fromhex("04" * 32))),
    ("approved_allocation_bps", CLV_U32(800)),
    ("casper_network", CLV_String("casper-test")),
    ("agent_council_version", CLV_String("1.0")),
    ("evidence_uri", CLV_String("https://concordia.example/evidence/DAO-PROP-HIST-001")),
    ("agent_action_hash", CLV_ByteArray(bytes.fromhex("05" * 32))),
)


def _card_chain() -> tuple[dict[str, object], str]:
    proposal_json = json.dumps(
        {
            "card_type": "ProposalCard",
            "signal_id": PROPOSAL_ID,
            "previous_card_hash": None,
            "sequence_number": 1,
        },
        separators=(",", ":"),
    )
    proposal_hash = hashlib.sha256(proposal_json.encode()).hexdigest()
    terminal_json = json.dumps(
        {
            "card_type": "GovernanceSummary",
            "proposal_id": PROPOSAL_ID,
            "previous_card_hash": proposal_hash,
            "sequence_number": 2,
        },
        separators=(",", ":"),
    )
    terminal_hash = hashlib.sha256(terminal_json.encode()).hexdigest()
    return (
        {
            "schema_version": "concordia.card_chain.v1",
            "proposal_id": PROPOSAL_ID,
            "captured_at": CAPTURED_AT,
            "source_url": (
                "https://concordia.example/proof-artifacts/v1/"
                f"{PROPOSAL_ID}/card-chain"
            ),
            "cards": [
                {
                    "sequence_number": 1,
                    "card_type": "ProposalCard",
                    "card_hash": proposal_hash,
                    "canonical_card_json": proposal_json,
                    "published_at": CAPTURED_AT,
                },
                {
                    "sequence_number": 2,
                    "card_type": "GovernanceSummary",
                    "card_hash": terminal_hash,
                    "canonical_card_json": terminal_json,
                    "published_at": None,
                },
            ],
        },
        terminal_hash,
    )


def _rpc(request_id: int, method: str, params: dict[str, object], result: object) -> dict[str, object]:
    return {
        "request": {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        },
        "response": {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"name": f"{method}_result", "value": result},
        },
    }


def _fixture(monkeypatch: pytest.MonkeyPatch) -> tuple[dict[str, object], bytes, str, str]:
    card_chain, final_card_hash = _card_chain()
    arguments = [
        DeployArgument(
            name,
            CLV_ByteArray(bytes.fromhex(final_card_hash)) if value is None else value,
        )
        for name, value in ARGUMENT_VALUES
    ]
    deploy = create_deploy(
        create_deploy_parameters(SIGNER, "casper-test", timestamp=1_784_750_400),
        create_standard_payment(1_000_000_000),
        DeployOfStoredContractByHash(
            args=arguments,
            entry_point="store_governance_receipt",
            hash=bytes.fromhex(CONTRACT_HASH),
        ),
    )
    deploy.approve(SIGNER)
    deploy_json = exact_deploy_rpc_json(deploy)
    deploy_hash = deploy.hash.hex()
    inventory = {
        "schema_version": "concordia.historical_odra_inventory.v1",
        "network": "casper-test",
        "receipt_argument_types": {
            "proposal_id": "String",
            "proposal_type": "String",
            "proposal_hash": "ByteArray(32)",
            "policy_hash": "ByteArray(32)",
            "dissent_hash": "ByteArray(32)",
            "final_card_hash": "ByteArray(32)",
            "plan_hash": "ByteArray(32)",
            "agent_action_hash": "ByteArray(32)",
            "approved_allocation_bps": "U32",
            "risk_score": "U32",
            "risk_level": "String",
            "decision": "String",
            "treasury_action": "String",
            "policy_version": "String",
            "casper_network": "String",
            "agent_council_version": "String",
            "evidence_uri": "String",
        },
        "chain_identity": {
            "v1": {
                "package_hash": PACKAGE_HASH,
                "contract_hash": CONTRACT_HASH,
                "contract_wasm_state_hash": WASM_HASH,
                "contract_version": 1,
                "protocol_version_major": 2,
                "install_deploy_hash": "76" * 32,
                "install_block_height": 8_999,
                "entry_point": "store_governance_receipt",
                "accepted_session": {
                    "variant": "StoredContractByHash",
                    "target_kind": "contract",
                    "target_hash": CONTRACT_HASH,
                    "version": None,
                    "final_card_hash": final_card_hash,
                    "card_chain_binding": "canonical_export_required",
                    "argument_order": [name for name, _ in ARGUMENT_VALUES],
                },
                "receipt_deploys": {"canonical_accepted": deploy_hash},
            },
            "v2": {
                "package_hash": "87" * 32,
                "contract_hash": "98" * 32,
                "contract_wasm_state_hash": "a9" * 32,
                "contract_version": 1,
                "protocol_version_major": 2,
                "install_deploy_hash": "ba" * 32,
                "install_block_height": 9_999,
                "entry_point": "store_governance_receipt",
                "accepted_session": {
                    "variant": "StoredVersionedContractByHash",
                    "target_kind": "package",
                    "target_hash": "87" * 32,
                    "version": 1,
                    "final_card_hash": "dd" * 32,
                    "card_chain_binding": "separate_export_required",
                    "argument_order": [
                        "proposal_id",
                        "proposal_type",
                        "proposal_hash",
                        "policy_hash",
                        "dissent_hash",
                        "final_card_hash",
                        "plan_hash",
                        "agent_action_hash",
                        "approved_allocation_bps",
                        "risk_score",
                        "risk_level",
                        "decision",
                        "treasury_action",
                        "policy_version",
                        "casper_network",
                        "agent_council_version",
                        "evidence_uri",
                    ],
                },
                "receipt_deploys": {
                    "pre_quorum_expected_rejection": "cb" * 32,
                    "post_quorum_accepted": "dc" * 32,
                },
            },
        },
        "preserved_repo_source": {
            "baseline_commit": "ef" * 20,
            "manifest_path": "handoff/HISTORICAL_ODRA_SHA256.txt",
            "manifest_sha256": "10" * 32,
            "governance_receipt_wasm_path": (
                "contracts/odra-governance-receipt/wasm/GovernanceReceipt.wasm"
            ),
            "governance_receipt_wasm_sha256": "20" * 32,
            "source_deployment_equivalence": "unproven",
        },
    }
    inventory_bytes = (
        json.dumps(inventory, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    )
    inventory_sha = hashlib.sha256(inventory_bytes).hexdigest()
    monkeypatch.setattr(
        "shared.historical_odra_artifact.FROZEN_INVENTORY_SHA256",
        inventory_sha,
    )
    version2 = {
        "initiator": {"PublicKey": SIGNER.to_public_key().account_key.hex()},
        "error_message": None,
        "current_price": 1,
        "limit": "1000000000",
        "consumed": "100000000",
        "cost": "100000000",
        "refund": "0",
        "transfers": [],
        "size_estimate": 512,
        "effects": [],
    }
    artifact = {
        "schema_version": "concordia.historical_odra_receipt.v1",
        "proposal_id": PROPOSAL_ID,
        "generation": "v1",
        "captured_at": CAPTURED_AT,
        "source_commit": SOURCE_COMMIT,
        "deployment_commit": DEPLOYMENT_COMMIT,
        "source_url": (
            "https://concordia.example/proof-artifacts/v1/"
            f"{PROPOSAL_ID}/historical-odra-receipt"
        ),
        "network": "casper-test",
        "lineage_inventory": {
            "schema_version": "concordia.historical_odra_inventory.v1",
            "sha256": inventory_sha,
            "canonical_json": inventory_bytes.decode("utf-8"),
        },
        "contract_identity": {
            "package_hash": PACKAGE_HASH,
            "contract_hash": CONTRACT_HASH,
            "contract_wasm_state_hash": WASM_HASH,
            "contract_version": 1,
            "protocol_version_major": 2,
            "entry_point": "store_governance_receipt",
            "session_variant": "StoredContractByHash",
            "session_target_kind": "contract",
            "session_target_hash": CONTRACT_HASH,
            "session_version": None,
        },
        "card_chain": card_chain,
        "raw_rpc": {
            "deploy": _rpc(
                1,
                "info_get_deploy",
                {"deploy_hash": deploy_hash, "finalized_approvals": True},
                {
                    "api_version": "2.0.0",
                    "deploy": deploy_json,
                    "execution_info": {
                        "block_hash": BLOCK_HASH,
                        "block_height": BLOCK_HEIGHT,
                        "execution_result": {"Version2": version2},
                    },
                },
            ),
            "canonical_block": _rpc(
                2,
                "chain_get_block",
                {"block_identifier": {"Hash": BLOCK_HASH}},
                {
                    "api_version": "2.0.0",
                    "block_with_signatures": {
                        "block": {
                            "Version2": {
                                "hash": BLOCK_HASH,
                                "header": {
                                    "height": BLOCK_HEIGHT,
                                    "state_root_hash": STATE_ROOT,
                                },
                                "body": {
                                    "transactions": {"0": [{"Deploy": deploy_hash}]}
                                },
                            }
                        },
                        "proofs": [],
                    },
                },
            ),
            "state_root": _rpc(
                3,
                "chain_get_state_root_hash",
                {"block_identifier": {"Hash": BLOCK_HASH}},
                {"api_version": "2.0.0", "state_root_hash": STATE_ROOT},
            ),
            "package": _rpc(
                4,
                "query_global_state",
                {
                    "state_identifier": {"StateRootHash": STATE_ROOT},
                    "key": "hash-" + PACKAGE_HASH,
                    "path": [],
                },
                {
                    "api_version": "2.0.0",
                    "block_header": None,
                    "merkle_proof": "00",
                    "stored_value": {
                        "ContractPackage": {
                            "access_key": "uref-" + "11" * 32 + "-007",
                            "versions": [
                                {
                                    "protocol_version_major": 2,
                                    "contract_version": 1,
                                    "contract_hash": "contract-" + CONTRACT_HASH,
                                }
                            ],
                            "disabled_versions": [],
                            "groups": [],
                            "lock_status": "Locked",
                        }
                    },
                },
            ),
            "contract": _rpc(
                5,
                "query_global_state",
                {
                    "state_identifier": {"StateRootHash": STATE_ROOT},
                    "key": "hash-" + CONTRACT_HASH,
                    "path": [],
                },
                {
                    "api_version": "2.0.0",
                    "block_header": None,
                    "merkle_proof": "00",
                    "stored_value": {
                        "Contract": {
                            "contract_package_hash": "contract-package-" + PACKAGE_HASH,
                            "contract_wasm_hash": "contract-wasm-" + WASM_HASH,
                            "protocol_version": "2.0.0",
                        }
                    },
                },
            ),
        },
    }
    args_preimage = len(arguments).to_bytes(4, "little") + b"".join(
        serializer.to_bytes(argument) for argument in arguments
    )
    return artifact, inventory_bytes, deploy_hash, hashlib.sha256(args_preimage).hexdigest()


def _verify(artifact: dict[str, object], inventory_bytes: bytes) -> dict[str, object]:
    return verify_historical_odra_artifact(
        json.dumps(artifact, separators=(",", ":")),
        inventory_bytes=inventory_bytes,
    )


def test_historical_odra_artifact_derives_every_fact_from_raw_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact, inventory_bytes, deploy_hash, args_digest = _fixture(monkeypatch)

    result = _verify(artifact, inventory_bytes)

    assert result == {
        "proposalId": PROPOSAL_ID,
        "generation": "v1",
        "deployHash": deploy_hash,
        "blockHash": BLOCK_HASH,
        "blockHeight": BLOCK_HEIGHT,
        "stateRootHash": STATE_ROOT,
        "packageHash": PACKAGE_HASH,
        "contractHash": CONTRACT_HASH,
        "contractWasmStateHash": WASM_HASH,
        "sessionVariant": "StoredContractByHash",
        "sessionTargetKind": "contract",
        "sessionTargetHash": CONTRACT_HASH,
        "sessionVersion": None,
        "finalCardHash": artifact["card_chain"]["cards"][-1]["card_hash"],
        "receiptArgumentDigest": args_digest,
        "sourceCommit": SOURCE_COMMIT,
        "deploymentCommit": DEPLOYMENT_COMMIT,
        "capturedAt": CAPTURED_AT,
        "sourceDeploymentEquivalence": "unproven",
        "verificationScope": "artifact_transcript_consistency",
        "observationSources": [],
        "artifactInputs": [
            "packaged_frozen_inventory",
            "artifact.card_chain",
            "artifact.raw_rpc.deploy",
            "artifact.raw_rpc.canonical_block",
            "artifact.raw_rpc.state_root",
            "artifact.raw_rpc.package",
            "artifact.raw_rpc.contract",
        ],
        "notVerified": [
            "canonical_chain_membership_or_finality",
            "live_rpc_observation",
            "validator_consensus_or_block_signatures",
            "preserved_source_to_deployed_wasm_equivalence",
            "retroactive_v3_exact_envelope_enforcement",
        ],
    }


def test_historical_odra_artifact_reports_v2_combined_proof_unavailable_until_its_chain_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact, inventory_bytes, _, _ = _fixture(monkeypatch)
    inventory = json.loads(inventory_bytes)
    v2 = inventory["chain_identity"]["v2"]
    artifact["generation"] = "v2"
    artifact["contract_identity"] = {
        "package_hash": v2["package_hash"],
        "contract_hash": v2["contract_hash"],
        "contract_wasm_state_hash": v2["contract_wasm_state_hash"],
        "contract_version": v2["contract_version"],
        "protocol_version_major": v2["protocol_version_major"],
        "entry_point": v2["entry_point"],
        "session_variant": v2["accepted_session"]["variant"],
        "session_target_kind": v2["accepted_session"]["target_kind"],
        "session_target_hash": v2["accepted_session"]["target_hash"],
        "session_version": v2["accepted_session"]["version"],
    }

    with pytest.raises(HistoricalOdraArtifactUnavailable, match="separate matching.*card chain"):
        _verify(artifact, inventory_bytes)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("session_variant", "StoredVersionedContractByHash"),
        ("session_target_kind", "package"),
        ("session_target_hash", "ff" * 32),
        ("session_version", 1),
        ("contract_version", True),
    ],
)
def test_historical_odra_artifact_rejects_generation_session_identity_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    artifact, inventory_bytes, _, _ = _fixture(monkeypatch)
    artifact["contract_identity"][field] = value

    with pytest.raises(HistoricalOdraArtifactError, match="contract_identity"):
        _verify(artifact, inventory_bytes)


def test_historical_odra_artifact_classifies_missing_raw_evidence_as_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact, inventory_bytes, _, _ = _fixture(monkeypatch)
    artifact["raw_rpc"].pop("contract")

    with pytest.raises(HistoricalOdraArtifactUnavailable, match="contract"):
        _verify(artifact, inventory_bytes)


def test_historical_odra_artifact_rejects_duplicate_json_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact, inventory_bytes, _, _ = _fixture(monkeypatch)
    raw = json.dumps(artifact, separators=(",", ":"))
    raw = raw.replace('"jsonrpc":"2.0"', '"jsonrpc":"2.0","jsonrpc":"2.0"', 1)

    with pytest.raises(HistoricalOdraArtifactError, match="duplicate"):
        verify_historical_odra_artifact(raw, inventory_bytes=inventory_bytes)


def test_historical_odra_artifact_rejects_forged_boolean_inside_raw_rpc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact, inventory_bytes, _, _ = _fixture(monkeypatch)
    artifact["raw_rpc"]["state_root"]["response"]["result"]["value"]["passed"] = True

    with pytest.raises(HistoricalOdraArtifactError, match="asserted summary boolean"):
        _verify(artifact, inventory_bytes)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("body_hash", "body hash"),
        ("signature", "signature"),
        ("missing_arg", "17"),
        ("reordered_args", "ordered"),
        ("extra_arg", "17"),
        ("wrong_arg_type", "type"),
    ],
)
def test_historical_odra_artifact_rejects_deploy_or_runtime_argument_forgery(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected: str,
) -> None:
    artifact, inventory_bytes, _, _ = _fixture(monkeypatch)
    deploy = artifact["raw_rpc"]["deploy"]["response"]["result"]["value"]["deploy"]
    if mutation == "body_hash":
        deploy["header"]["body_hash"] = "ff" * 32
    elif mutation == "signature":
        signature = deploy["approvals"][0]["signature"]
        deploy["approvals"][0]["signature"] = signature[:-2] + ("00" if signature[-2:] != "00" else "01")
    else:
        args = deploy["session"]["StoredContractByHash"]["args"]
        if mutation == "missing_arg":
            args.pop()
        elif mutation == "reordered_args":
            args[0], args[1] = args[1], args[0]
        elif mutation == "extra_arg":
            args.append(("unexpected", copy.deepcopy(args[-1][1])))
        else:
            args[0] = (args[0][0], serializer.to_json(CLV_U32(7)))

    with pytest.raises(HistoricalOdraArtifactError, match=expected):
        _verify(artifact, inventory_bytes)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("execution_error", "execution failed"),
        ("block_hash", "block hash"),
        ("block_height", "block height"),
        ("state_root", "state root"),
        ("package_contract", "package"),
        ("contract_package", "package"),
        ("contract_wasm", "Wasm"),
        ("package_version_type", "package"),
    ],
)
def test_historical_odra_artifact_rejects_contradictory_chain_state(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected: str,
) -> None:
    artifact, inventory_bytes, _, _ = _fixture(monkeypatch)
    raw_rpc = artifact["raw_rpc"]
    if mutation == "execution_error":
        raw_rpc["deploy"]["response"]["result"]["value"]["execution_info"][
            "execution_result"
        ]["Version2"]["error_message"] = "User error: 1"
    elif mutation == "block_hash":
        raw_rpc["canonical_block"]["response"]["result"]["value"][
            "block_with_signatures"
        ]["block"]["Version2"]["hash"] = "ff" * 32
    elif mutation == "block_height":
        raw_rpc["canonical_block"]["response"]["result"]["value"][
            "block_with_signatures"
        ]["block"]["Version2"]["header"]["height"] += 1
    elif mutation == "state_root":
        raw_rpc["state_root"]["response"]["result"]["value"]["state_root_hash"] = "ff" * 32
    elif mutation == "package_contract":
        raw_rpc["package"]["response"]["result"]["value"]["stored_value"][
            "ContractPackage"
        ]["versions"][0]["contract_hash"] = "contract-" + "ff" * 32
    elif mutation == "contract_package":
        raw_rpc["contract"]["response"]["result"]["value"]["stored_value"][
            "Contract"
        ]["contract_package_hash"] = "contract-package-" + "ff" * 32
    elif mutation == "contract_wasm":
        raw_rpc["contract"]["response"]["result"]["value"]["stored_value"][
            "Contract"
        ]["contract_wasm_hash"] = "contract-wasm-" + "ff" * 32
    else:
        raw_rpc["package"]["response"]["result"]["value"]["stored_value"][
            "ContractPackage"
        ]["versions"][0]["contract_version"] = True

    with pytest.raises(HistoricalOdraArtifactError, match=expected):
        _verify(artifact, inventory_bytes)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("proposal", "proposal"),
        ("terminal_hash", "final_card_hash"),
        ("card_preimage", "card_hash"),
        ("sequence_type", "sequence"),
    ],
)
def test_historical_odra_artifact_binds_receipt_to_exact_card_chain(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected: str,
) -> None:
    artifact, inventory_bytes, _, _ = _fixture(monkeypatch)
    if mutation == "proposal":
        artifact["card_chain"]["proposal_id"] = "DAO-PROP-OTHER"
    elif mutation == "terminal_hash":
        terminal = artifact["card_chain"]["cards"][-1]
        preimage = json.loads(terminal["canonical_card_json"])
        preimage["marker"] = "independently valid but wrong root"
        terminal["canonical_card_json"] = json.dumps(preimage, separators=(",", ":"))
        terminal["card_hash"] = hashlib.sha256(
            terminal["canonical_card_json"].encode()
        ).hexdigest()
    elif mutation == "card_preimage":
        artifact["card_chain"]["cards"][0]["canonical_card_json"] += " "
    else:
        artifact["card_chain"]["cards"][0]["sequence_number"] = True

    with pytest.raises(HistoricalOdraArtifactError, match=expected):
        _verify(artifact, inventory_bytes)


def test_historical_odra_artifact_rejects_legacy_summary_even_when_it_says_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact, inventory_bytes, _, _ = _fixture(monkeypatch)
    artifact["passed"] = True
    artifact["processed"] = True
    artifact["chain_valid"] = True

    with pytest.raises(HistoricalOdraArtifactError, match="top-level"):
        _verify(artifact, inventory_bytes)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("inventory_byte", "inventory"),
        ("inventory_hash", "inventory"),
        ("source_equivalence", "unproven"),
        ("private_url", "source_url"),
    ],
)
def test_historical_odra_artifact_pins_inventory_and_publication_metadata(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected: str,
) -> None:
    artifact, inventory_bytes, _, _ = _fixture(monkeypatch)
    if mutation == "inventory_byte":
        artifact["lineage_inventory"]["canonical_json"] += " "
    elif mutation == "inventory_hash":
        artifact["lineage_inventory"]["sha256"] = "ff" * 32
    elif mutation == "source_equivalence":
        parsed = json.loads(inventory_bytes)
        parsed["preserved_repo_source"]["source_deployment_equivalence"] = "proven"
        forged = json.dumps(parsed, indent=2).encode() + b"\n"
        forged_sha = hashlib.sha256(forged).hexdigest()
        monkeypatch.setattr(
            "shared.historical_odra_artifact.FROZEN_INVENTORY_SHA256",
            forged_sha,
        )
        artifact["lineage_inventory"] = {
            "schema_version": "concordia.historical_odra_inventory.v1",
            "sha256": forged_sha,
            "canonical_json": forged.decode(),
        }
        inventory_bytes = forged
    else:
        artifact["source_url"] = (
            "https://127.0.0.1/proof-artifacts/v1/"
            f"{PROPOSAL_ID}/historical-odra-receipt"
        )

    with pytest.raises(HistoricalOdraArtifactError, match=expected):
        _verify(artifact, inventory_bytes)
