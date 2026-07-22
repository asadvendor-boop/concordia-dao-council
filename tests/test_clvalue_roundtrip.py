"""CLValue, installer, schema and readback gates for exact-envelope v3."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

import pytest
import scripts.run_v3_live_proof as live_proof_runner
from pycspr import serializer
from pycspr.factory.accounts import parse_private_key_bytes
from pycspr.factory.deploys import (
    create_deploy,
    create_deploy_parameters,
    create_standard_payment,
)
from pycspr.types.cl import (
    CLV_ByteArray,
    CLV_Key,
    CLV_KeyType,
    CLV_List,
    CLV_U32,
    CLV_U512,
    CLV_U64,
    CLV_U8,
)
from pycspr.types.crypto import KeyAlgorithm
from pycspr.types.node.rpc import DeployOfModuleBytes
from pycspr.types.node.rpc import Deploy

from scripts.install_governance_receipt_v3 import (
    InstallValidationError,
    _resolve_locked_contract,
    _validate_successful_install_rpc,
    build_locked_install_args,
    build_signed_install_payload,
    diff_entry_point_args_against_schema,
    validate_finalized_install_deploy,
)
from scripts.prepare_v3_envelope import prepare_v3_envelope
from scripts.read_v3_state import (
    ReadbackValidationError,
    build_checkpoint_state_readback_from_transcripts,
    build_readback_artifact_from_transcripts,
    state_dictionary_key,
    validate_verified_readback,
    verify_checkpoint_state_readback_artifact,
    verify_and_seal_readback_artifact,
)
from scripts.run_v3_live_proof import (
    LiveProofError,
    _build_call,
    _steps,
    build_browser_checkpoint,
    build_browser_signature_import,
    outcome_from_finality_response,
    validate_and_stage_browser_import,
)
from scripts.verify_v3_proof import ProofVerificationError, verify_v3_proof_document


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts/odra-governance-receipt-v3/resources/casper_contract_schemas/governance_receiptv3_schema.json"
VECTORS = ROOT / "tests/golden/envelope_v3"
DEPLOYMENT_MANIFEST = ROOT / "contracts/odra-governance-receipt-v3/deployment.manifest.json"
HISTORICAL_ODRA_MANIFEST = ROOT / "handoff/HISTORICAL_ODRA_SHA256.txt"


@pytest.mark.parametrize(
    "value",
    [
        CLV_U8(7),
        CLV_U32(0x01020304),
        CLV_U64(0x0102030405060708),
        CLV_U512((1 << 511) + 9),
        CLV_Key(bytes.fromhex("11" * 32), CLV_KeyType.ACCOUNT),
        CLV_List(
            [
                CLV_Key(bytes.fromhex("22" * 32), CLV_KeyType.ACCOUNT),
                CLV_Key(bytes.fromhex("33" * 32), CLV_KeyType.HASH),
            ]
        ),
        CLV_ByteArray(bytes.fromhex("44" * 32)),
    ],
    ids=["u8", "u32", "u64", "u512", "key", "list-key", "bytearray-32"],
)
def test_clv_01_through_07_json_roundtrip_is_byte_exact(value: object) -> None:
    encoded = serializer.to_bytes(value)
    decoded = serializer.from_json(serializer.to_json(value), type(value))

    assert type(decoded) is type(value)
    assert serializer.to_bytes(decoded) == encoded


def _fields(items: list[dict[str, object]]) -> dict[str, object]:
    return {str(item["name"]): item["value"] for item in items}


def _native_document() -> dict[str, object]:
    vector = json.loads((VECTORS / "native_transfer/GV-NT-01.json").read_text())
    return {
        "schema_id": "concordia.exact-envelope-v3.input.v1",
        "action": "NativeTransferV1",
        "header": _fields(vector["typed_input"]["header"]),
        "body": _fields(vector["typed_input"]["body"]),
    }


def test_clv_08_prepared_finalize_args_match_generated_odra_schema_exactly() -> None:
    prepared = prepare_v3_envelope(_native_document())
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    assert diff_entry_point_args_against_schema(
        schema,
        prepared["entry_point"],
        prepared["runtime_args"],
    ) == []


def test_wasm_04_locked_install_args_are_fail_closed_and_schema_exact() -> None:
    roles = {
        "proposer": {"kind": "Account", "account_hash": "11" * 32},
        "finalizer": {"kind": "Account", "account_hash": "22" * 32},
        "signer_a": {"kind": "Account", "account_hash": "33" * 32},
        "signer_b": {"kind": "Account", "account_hash": "44" * 32},
        "signer_c": {"kind": "Account", "account_hash": "55" * 32},
    }

    args = build_locked_install_args(
        installer_account_hash="66" * 32,
        roles=roles,
        threshold=2,
        casper_chain_name="casper-test",
        installation_nonce="77" * 32,
    )

    assert serializer.to_json(args["odra_cfg_package_hash_key_name"])["parsed"] == "concordia_governance_receipt_v3"
    assert serializer.to_json(args["odra_cfg_is_upgradable"])["bytes"] == "00"
    assert serializer.to_json(args["odra_cfg_allow_key_override"])["bytes"] == "00"
    assert serializer.to_json(args["odra_cfg_is_upgrade"])["bytes"] == "00"
    assert serializer.to_json(args["proposer"])["cl_type"] == {"ByteArray": 32}

    bad_roles = copy.deepcopy(roles)
    bad_roles["proposer"]["kind"] = "ContractPackage"
    with pytest.raises(InstallValidationError, match="account-only"):
        build_locked_install_args(
            installer_account_hash="66" * 32,
            roles=bad_roles,
            threshold=2,
            casper_chain_name="casper-test",
            installation_nonce="77" * 32,
        )


def test_wasm_05_deployment_manifest_binds_and_rechecks_frozen_historical_inventory() -> None:
    deployment = json.loads(DEPLOYMENT_MANIFEST.read_text(encoding="utf-8"))
    inventory_bytes = HISTORICAL_ODRA_MANIFEST.read_bytes()

    assert deployment["historical_isolation"]["manifest_sha256"] == hashlib.sha256(
        inventory_bytes
    ).hexdigest()
    records = [line for line in inventory_bytes.decode("utf-8").splitlines() if line and not line.startswith("#")]
    assert len(records) == deployment["historical_isolation"]["tracked_file_count"]
    for record in records:
        expected_sha256, relative_path = record.split("  ", 1)
        assert hashlib.sha256((ROOT / relative_path).read_bytes()).hexdigest() == expected_sha256


def test_wasm_06_live_package_must_be_locked_single_version_one_without_upgrade_authority() -> None:
    package = {
        "ContractPackage": {
            "access_key": "uref-" + "aa" * 32 + "-007",
            "versions": [
                {
                    "protocol_version_major": 2,
                    "contract_version": 1,
                    "contract_hash": "contract-" + "bb" * 32,
                }
            ],
            "disabled_versions": [],
            "groups": [{"group_name": "upgrader_group", "group_users": []}],
            "lock_status": "Locked",
        }
    }
    assert _resolve_locked_contract(package) == (1, "bb" * 32)

    mutations = [
        ("lock_status", "Unlocked"),
        ("versions", package["ContractPackage"]["versions"] * 2),
        (
            "versions",
            [
                {
                    "protocol_version_major": 2,
                    "contract_version": 2,
                    "contract_hash": "contract-" + "bb" * 32,
                }
            ],
        ),
        ("disabled_versions", [{"contract_version": 1, "protocol_version_major": 2}]),
        (
            "groups",
            [{"group_name": "upgrader_group", "group_users": ["uref-" + "cc" * 32 + "-007"]}],
        ),
        ("access_key", "uref-not-a-canonical-uref"),
    ]
    for field, value in mutations:
        broken = copy.deepcopy(package)
        broken["ContractPackage"][field] = value
        with pytest.raises(InstallValidationError):
            _resolve_locked_contract(broken)


def test_wasm_07_finalized_install_deploy_reproves_wasm_locked_args_and_signature() -> None:
    private = parse_private_key_bytes(bytes([7]) * 32, KeyAlgorithm.ED25519)
    public = private.to_public_key()
    roles = {
        name: {"kind": "Account", "account_hash": bytes([offset] * 32).hex()}
        for name, offset in zip(
            ("proposer", "finalizer", "signer_a", "signer_b", "signer_c"),
            (11, 12, 13, 14, 15),
            strict=True,
        )
    }
    nonce = "77" * 32
    args = build_locked_install_args(
        installer_account_hash=public.to_account_hash().hex(),
        roles=roles,
        threshold=2,
        casper_chain_name="casper-test",
        installation_nonce=nonce,
    )
    wasm = b"\x00asm" + b"concordia-v3-test"
    deploy = create_deploy(
        create_deploy_parameters(private, "casper-test", timestamp=1_784_750_400),
        create_standard_payment(30_000_000_000),
        DeployOfModuleBytes(module_bytes=wasm, args=args),
    )
    deploy.approve(private)
    deploy_json = serializer.to_json(deploy)
    manifest = {
        "installer_public_key": public.account_key.hex(),
        "installer_account_hash": public.to_account_hash().hex(),
        "installation_nonce": nonce,
        "threshold": 2,
        "roles": roles,
        "build": {"wasm_sha256": hashlib.sha256(wasm).hexdigest()},
        "install_deploy_hash": deploy_json["hash"],
        "install_payment_motes": 30_000_000_000,
    }

    facts = validate_finalized_install_deploy(deploy_json, manifest)
    assert facts["wasm_sha256"] == hashlib.sha256(wasm).hexdigest()

    for mutation in ("module", "flag", "signature"):
        broken = copy.deepcopy(deploy_json)
        if mutation == "module":
            broken["session"]["ModuleBytes"]["module_bytes"] += "00"
        elif mutation == "flag":
            flag = next(
                item
                for item in broken["session"]["ModuleBytes"]["args"]
                if item[0] == "odra_cfg_is_upgradable"
            )
            flag[1]["bytes"] = "01"
            flag[1]["parsed"] = True
        else:
            signature = broken["approvals"][0]["signature"]
            broken["approvals"][0]["signature"] = signature[:-2] + (
                "00" if signature[-2:] != "00" else "01"
            )
        with pytest.raises(InstallValidationError):
            validate_finalized_install_deploy(broken, manifest)


def test_install_payload_requires_and_persists_exact_source_and_deployment_commits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = parse_private_key_bytes(bytes([7]) * 32, KeyAlgorithm.ED25519)
    monkeypatch.setattr(
        "scripts.install_governance_receipt_v3.parse_private_key",
        lambda *_: private,
    )
    roles = {
        name: {"kind": "Account", "account_hash": bytes([offset] * 32).hex()}
        for name, offset in zip(
            ("proposer", "finalizer", "signer_a", "signer_b", "signer_c"),
            (11, 12, 13, 14, 15),
            strict=True,
        )
    }
    wasm = ROOT / "contracts/odra-governance-receipt-v3/wasm/GovernanceReceiptV3.wasm"
    source_commit = "ab" * 20
    deployment_commit = "cd" * 20

    _, manifest = build_signed_install_payload(
        secret_key_path=Path("not-read-because-test-patches-loader.pem"),
        key_algorithm="ED25519",
        roles=roles,
        threshold=2,
        installation_nonce="77" * 32,
        wasm_path=wasm,
        schema_path=SCHEMA,
        payment_amount_motes=30_000_000_000,
        ttl="30m",
        source_commit=source_commit,
        deployment_commit=deployment_commit,
    )
    assert manifest["source_commit"] == source_commit
    assert manifest["deployment_commit"] == deployment_commit

    with pytest.raises(InstallValidationError, match="source_commit"):
        build_signed_install_payload(
            secret_key_path=Path("not-read-because-test-patches-loader.pem"),
            key_algorithm="ED25519",
            roles=roles,
            threshold=2,
            installation_nonce="77" * 32,
            wasm_path=wasm,
            schema_path=SCHEMA,
            payment_amount_motes=30_000_000_000,
            ttl="30m",
            source_commit=source_commit.upper(),
            deployment_commit=deployment_commit,
        )


def _cl_bytes(inner: bytes) -> dict[str, object]:
    return {
        "CLValue": {
            "cl_type": {"List": "U8"},
            "bytes": (len(inner).to_bytes(4, "little") + inner).hex(),
            "parsed": list(inner),
        }
    }


def _rpc(method: str, params: dict[str, object], result: dict[str, object]) -> dict[str, object]:
    request = {"jsonrpc": "2.0", "id": method, "method": method, "params": params}
    response = {"jsonrpc": "2.0", "id": method, "result": result}
    return {
        "rpc_url_identity_or_node_id": "node.testnet.casper.network",
        "method": method,
        "params": params,
        "request": request,
        "response": response,
        "canonical_sha256": hashlib.sha256(
            json.dumps({"request": request, "response": response}, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def _readback_fixture() -> tuple[list[dict[str, object]], dict[str, str]]:
    ids = {
        "package": "aa" * 32,
        "contract": "bb" * 32,
        "block": "cc" * 32,
        "state_root": "dd" * 32,
        "domain": "ee" * 32,
        "proposal": "DAO-PROP-V3-TEST",
        "envelope": "12" * 32,
        "action": "34" * 32,
    }
    transcripts: list[dict[str, object]] = [
        _rpc(
            "chain_get_block",
            {"block_identifier": {"Hash": ids["block"]}},
            {
                "api_version": "2.0.0",
                "block_with_signatures": {
                    "block": {
                        "Version2": {
                            "hash": ids["block"],
                            "header": {"height": 9_003, "state_root_hash": ids["state_root"]},
                            "body": {},
                        }
                    },
                    "proofs": [],
                }
            },
        ),
        _rpc(
            "query_global_state",
            {"state_identifier": {"StateRootHash": ids["state_root"]}, "key": "hash-" + ids["contract"], "path": []},
            {"stored_value": {"Contract": {"contract_package_hash": "contract-package-" + ids["package"]}}},
        ),
    ]

    def dictionary(index: int, mapping: bytes, inner: bytes) -> None:
        transcripts.append(
            _rpc(
                "state_get_dictionary_item",
                {
                    "state_root_hash": ids["state_root"],
                    "dictionary_identifier": {
                        "ContractNamedKey": {"key": "hash-" + ids["contract"], "dictionary_name": "state"}
                    },
                    "dictionary_item_key": state_dictionary_key(index, mapping),
                },
                {"stored_value": _cl_bytes(inner)},
            )
        )

    proposal_key = len(ids["proposal"].encode()).to_bytes(4, "little") + ids["proposal"].encode()
    dictionary(1, b"", (3).to_bytes(4, "little"))
    dictionary(2, b"", bytes.fromhex(ids["domain"]))
    dictionary(3, b"", len(b"casper-test").to_bytes(4, "little") + b"casper-test")
    dictionary(4, b"", bytes.fromhex("01" * 32))
    dictionary(5, b"", bytes.fromhex("02" * 32))
    dictionary(6, b"", bytes.fromhex("03" * 32))
    dictionary(7, b"", bytes.fromhex("04" * 32))
    dictionary(8, b"", bytes.fromhex("05" * 32))
    dictionary(9, b"", b"\x02")
    dictionary(11, proposal_key, bytes.fromhex(ids["envelope"]))
    dictionary(12, proposal_key, b"\x02")
    dictionary(14, proposal_key, b"\x01")
    dictionary(15, proposal_key, bytes.fromhex(ids["envelope"]))
    dictionary(16, bytes.fromhex(ids["action"]), b"\x01")
    return transcripts, ids


def _sealed_readback_artifact() -> tuple[dict[str, object], dict[str, str]]:
    transcripts, ids = _readback_fixture()
    artifact = build_readback_artifact_from_transcripts(
        transcripts=transcripts,
        expected_network="casper-test",
        expected_package_hash=ids["package"],
        expected_contract_hash=ids["contract"],
        proposal_id=ids["proposal"],
        action_id=ids["action"],
    )
    return artifact, ids


def _role_private_keys() -> dict[str, object]:
    return {
        "proposer": parse_private_key_bytes(bytes([1]) * 32, KeyAlgorithm.ED25519),
        "finalizer": parse_private_key_bytes(bytes([2]) * 32, KeyAlgorithm.SECP256K1),
        "signer_a": parse_private_key_bytes(bytes([3]) * 32, KeyAlgorithm.ED25519),
        "signer_b": parse_private_key_bytes(bytes([4]) * 32, KeyAlgorithm.SECP256K1),
        "signer_c": parse_private_key_bytes(bytes([5]) * 32, KeyAlgorithm.ED25519),
    }


def _live_run(prepared: dict[str, object], readback: dict[str, object], ids: dict[str, str]) -> dict[str, object]:
    role_keys = _role_private_keys()
    role_accounts = {}
    for role, private in role_keys.items():
        public = private.to_public_key()
        role_accounts[role] = {
            "custody": "server",
            "public_key": public.account_key.hex(),
            "account_hash": public.to_account_hash().hex(),
        }
    records = []
    for step in _steps(prepared):
        private = role_keys[step["role"]]
        public = private.to_public_key()
        deploy = _build_call(
            signer=public,
            private_key=private,
            contract_hash=ids["contract"],
            entry_point=step["entry_point"],
            runtime_args=step["args"],
            payment_motes=5_000_000_000,
            ttl="30m",
        )
        deploy_hash = deploy["hash"]
        error_code = step.get("expected_error")
        broadcast = _rpc(
            "account_put_deploy",
            {"deploy": deploy},
            {"api_version": "2.0.0", "deploy_hash": deploy_hash},
        )
        finality = _rpc(
            "info_get_deploy",
            {"deploy_hash": deploy_hash},
            {
                "api_version": "2.0.0",
                "deploy": copy.deepcopy(deploy),
                "execution_info": {
                    "block_hash": "cd" * 32,
                    "block_height": 9_002,
                    "execution_result": {
                        "Version2": {
                            "initiator": {"PublicKey": public.account_key.hex()},
                            "error_message": (
                                f"User error: {error_code}" if error_code is not None else None
                            ),
                            "current_price": 1,
                            "limit": "5000000000",
                            "consumed": "100000000",
                            "cost": "100000000",
                            "refund": "0",
                            "transfers": [],
                            "size_estimate": 512,
                            "effects": [],
                        }
                    },
                },
            },
        )
        records.append(
            {
                "name": step["name"],
                "role": step["role"],
                "custody": "server",
                "entry_point": step["entry_point"],
                "expected": step.get("expected"),
                "expected_error": error_code,
                "deploy_hash": deploy_hash,
                "deploy": deploy,
                "broadcast_transcript": broadcast,
                "finality_transcript": finality,
                "observed_outcome": {
                    "success": error_code is None,
                    "user_error": error_code,
                },
            }
        )
    return {
        "schema_id": "concordia.v3-live-proof-run.v1",
        "status": "contract_sequence_verified",
        "network": "casper-test",
        "package_hash": ids["package"],
        "contract_hash": ids["contract"],
        "prepared": prepared,
        "role_accounts": role_accounts,
        "steps": records,
        "readback": readback,
    }


def _deployment_evidence(
    run: dict[str, object],
    ids: dict[str, str],
    deployment_domain: str,
) -> dict[str, object]:
    manifest = json.loads(DEPLOYMENT_MANIFEST.read_text(encoding="utf-8"))
    installer = parse_private_key_bytes(bytes([7]) * 32, KeyAlgorithm.ED25519)
    installer_public = installer.to_public_key()
    roles = {
        name: {
            "kind": "Account",
            "account_hash": run["role_accounts"][name]["account_hash"],
        }
        for name in ("proposer", "finalizer", "signer_a", "signer_b", "signer_c")
    }
    nonce = "a5" * 32
    install_args = build_locked_install_args(
        installer_account_hash=installer_public.to_account_hash().hex(),
        roles=roles,
        threshold=2,
        casper_chain_name="casper-test",
        installation_nonce=nonce,
    )
    wasm = (ROOT / "contracts/odra-governance-receipt-v3/wasm/GovernanceReceiptV3.wasm").read_bytes()
    install = create_deploy(
        create_deploy_parameters(installer, "casper-test", timestamp=1_784_750_400),
        create_standard_payment(30_000_000_000),
        DeployOfModuleBytes(module_bytes=wasm, args=install_args),
    )
    install.approve(installer)
    install_json = serializer.to_json(install)
    state_root = ids["state_root"]
    block_hash = ids["block"]
    package_state = {
        "ContractPackage": {
            "access_key": "uref-" + "ab" * 32 + "-007",
            "versions": [
                {
                    "protocol_version_major": 2,
                    "contract_version": 1,
                    "contract_hash": "contract-" + ids["contract"],
                }
            ],
            "disabled_versions": [],
            "groups": [{"group_name": "upgrader_group", "group_users": []}],
            "lock_status": "Locked",
        }
    }
    install_rpc = _rpc(
        "info_get_deploy",
        {"deploy_hash": install_json["hash"]},
        {
            "api_version": "2.0.0",
            "deploy": copy.deepcopy(install_json),
            "execution_info": {
                "block_hash": block_hash,
                "block_height": 9_000,
                "execution_result": {
                    "Version2": {
                        "initiator": {"PublicKey": installer_public.account_key.hex()},
                        "error_message": None,
                        "current_price": 1,
                        "limit": "30000000000",
                        "consumed": "100000000",
                        "cost": "100000000",
                        "refund": "0",
                        "transfers": [],
                        "size_estimate": 512,
                        "effects": [],
                    }
                },
            },
        },
    )
    account_rpc = _rpc(
        "query_global_state",
        {
            "state_identifier": {"StateRootHash": state_root},
            "key": "account-hash-" + installer_public.to_account_hash().hex(),
            "path": [],
        },
        {
            "api_version": "2.0.0",
            "block_header": None,
            "merkle_proof": "account-proof",
            "stored_value": {
                "Account": {
                    "named_keys": [
                        {
                            "name": "concordia_governance_receipt_v3",
                            "key": "hash-" + ids["package"],
                        }
                    ]
                }
            }
        },
    )
    package_rpc = _rpc(
        "query_global_state",
        {
            "state_identifier": {"StateRootHash": state_root},
            "key": "hash-" + ids["package"],
            "path": [],
        },
        {
            "api_version": "2.0.0",
            "block_header": None,
            "merkle_proof": "package-proof",
            "stored_value": package_state,
        },
    )
    contract_rpc = _rpc(
        "query_global_state",
        {
            "state_identifier": {"StateRootHash": state_root},
            "key": "hash-" + ids["contract"],
            "path": [],
        },
        {
            "api_version": "2.0.0",
            "block_header": None,
            "merkle_proof": "contract-proof",
            "stored_value": {
                "Contract": {"contract_package_hash": "contract-package-" + ids["package"]}
            }
        },
    )
    state_root_rpc = _rpc(
        "chain_get_state_root_hash",
        {"block_identifier": {"Hash": block_hash}},
        {"api_version": "2.0.0", "state_root_hash": state_root},
    )
    install_raw = {
        "request": install_rpc["request"],
        "response": install_rpc["response"],
    }
    install_manifest = {
        **manifest,
        "installer_public_key": installer_public.account_key.hex(),
        "installer_account_hash": installer_public.to_account_hash().hex(),
        "installation_nonce": nonce,
        "threshold": 2,
        "roles": roles,
        "install_payment_motes": 30_000_000_000,
        "install_deploy_hash": install_json["hash"],
    }
    verified_install = _validate_successful_install_rpc(install_raw, install_manifest)
    manifest.update(
        {
            "status": "finalized",
            "package_hash": ids["package"],
            "contract_hash": ids["contract"],
            "contract_version": 1,
            "install_deploy_hash": install_json["hash"],
            "install_block_hash": block_hash,
            "install_block_height": 9_000,
            "install_state_root_hash": state_root,
            "deployment_domain": deployment_domain,
            "installation_nonce": nonce,
            "roles": roles,
            "source_commit": "ab" * 20,
            "deployment_commit": "cd" * 20,
            "installer_public_key": installer_public.account_key.hex(),
            "installer_account_hash": installer_public.to_account_hash().hex(),
            "threshold": 2,
            "install_payment_motes": 30_000_000_000,
            "install_ttl": "30m",
            "finality": {
                "status": "finalized",
                "success": True,
                "block_hash": verified_install["block_hash"],
                "block_height": verified_install["block_height"],
                "deploy_hash": verified_install["deploy_hash"],
            },
            "verified_install_deploy": verified_install,
            "raw_rpc": {
                "broadcast_response": {
                    "jsonrpc": "2.0",
                    "id": "concordia-v3-install",
                    "result": {"api_version": "2.0.0", "deploy_hash": install_json["hash"]},
                },
                "install_deploy": install_raw,
                "state_root": {
                    "request": state_root_rpc["request"],
                    "response": state_root_rpc["response"],
                },
                "installer_account": {
                    "request": account_rpc["request"],
                    "response": account_rpc["response"],
                },
                "package": {
                    "request": package_rpc["request"],
                    "response": package_rpc["response"],
                },
                "contract": {
                    "request": contract_rpc["request"],
                    "response": contract_rpc["response"],
                },
            },
        }
    )
    return manifest


def _bound_v3_proof() -> tuple[dict[str, object], dict[str, object], dict[str, str]]:
    document = _native_document()
    prepared = prepare_v3_envelope(document)
    transcripts, ids = _readback_fixture()
    proposal = document["header"]["proposal_id"]
    old_proposal_key = len(ids["proposal"].encode()).to_bytes(4, "little") + ids[
        "proposal"
    ].encode()
    new_proposal_key = len(proposal.encode()).to_bytes(4, "little") + proposal.encode()
    role_accounts = {
        name: private.to_public_key().to_account_hash().hex()
        for name, private in _role_private_keys().items()
    }
    role_indexes = {
        4: "proposer",
        5: "finalizer",
        6: "signer_a",
        7: "signer_b",
        8: "signer_c",
    }
    for transcript in transcripts:
        params = transcript["params"]
        item_key = params.get("dictionary_item_key") if isinstance(params, dict) else None
        replacements = {
            state_dictionary_key(11, old_proposal_key): state_dictionary_key(11, new_proposal_key),
            state_dictionary_key(12, old_proposal_key): state_dictionary_key(12, new_proposal_key),
            state_dictionary_key(14, old_proposal_key): state_dictionary_key(14, new_proposal_key),
            state_dictionary_key(15, old_proposal_key): state_dictionary_key(15, new_proposal_key),
            state_dictionary_key(16, bytes.fromhex(ids["action"])): state_dictionary_key(
                16, bytes.fromhex(prepared["action_id"])
            ),
        }
        if item_key == state_dictionary_key(2):
            transcript["response"]["result"]["stored_value"] = _cl_bytes(
                bytes.fromhex(document["header"]["deployment_domain"])
            )
        for index, role in role_indexes.items():
            if item_key == state_dictionary_key(index):
                transcript["response"]["result"]["stored_value"] = _cl_bytes(
                    bytes.fromhex(role_accounts[role])
                )
        if item_key in replacements:
            params["dictionary_item_key"] = replacements[item_key]
        if item_key in (
            state_dictionary_key(11, old_proposal_key),
            state_dictionary_key(15, old_proposal_key),
        ):
            transcript["response"]["result"]["stored_value"] = _cl_bytes(
                bytes.fromhex(prepared["envelope_hash"])
            )
        transcript["request"]["params"] = params
        transcript["canonical_sha256"] = hashlib.sha256(
            json.dumps(
                {"request": transcript["request"], "response": transcript["response"]},
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
    readback = build_readback_artifact_from_transcripts(
        transcripts=transcripts,
        expected_network="casper-test",
        expected_package_hash=ids["package"],
        expected_contract_hash=ids["contract"],
        proposal_id=proposal,
        action_id=prepared["action_id"],
    )
    run = _live_run(prepared, readback, ids)
    proof = {
        "schema_id": "concordia.v3-proof.v1",
        "deployment": _deployment_evidence(
            run,
            ids,
            document["header"]["deployment_domain"],
        ),
        "input": document,
        "prepared": prepared,
        "run": run,
        "readback": readback,
    }
    return proof, prepared, ids


def test_rb_01_through_10_reparse_raw_state_root_pinned_transcripts_into_opaque_readback() -> None:
    artifact, ids = _sealed_readback_artifact()
    verified = verify_and_seal_readback_artifact(artifact)

    facts = validate_verified_readback(verified)
    assert facts.schema_id == "concordia.v3-chain-readback.v1"
    assert facts.package_hash.hex() == ids["package"]
    assert facts.contract_hash.hex() == ids["contract"]
    assert facts.schema_version == 3
    assert facts.deployment_domain.hex() == ids["domain"]
    assert facts.casper_chain_name == "casper-test"
    assert facts.proposal_id == ids["proposal"]
    assert facts.proposed_envelope.hex() == ids["envelope"]
    assert facts.approval_count == 2
    assert facts.finalized is True
    assert facts.finalized_envelope.hex() == ids["envelope"]
    assert facts.action_id.hex() == ids["action"]
    assert facts.action_authorized is True
    assert facts.observed_block_height == 9_003
    assert facts.observed_state_root_hash.hex() == ids["state_root"]


@pytest.mark.parametrize("block_version", ["Version1", "Version2"])
def test_readback_accepts_exact_casper_v1_and_v2_block_with_signatures_wrappers(
    block_version: str,
) -> None:
    transcripts, ids = _readback_fixture()
    wrapped_block = transcripts[0]["response"]["result"]["block_with_signatures"]["block"]
    payload = wrapped_block.pop("Version2")
    wrapped_block[block_version] = payload
    transcripts[0]["canonical_sha256"] = hashlib.sha256(
        json.dumps(
            {"request": transcripts[0]["request"], "response": transcripts[0]["response"]},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()

    artifact = build_readback_artifact_from_transcripts(
        transcripts=transcripts,
        expected_network="casper-test",
        expected_package_hash=ids["package"],
        expected_contract_hash=ids["contract"],
        proposal_id=ids["proposal"],
        action_id=ids["action"],
    )

    assert artifact["facts"]["observed_block_height"] == 9_003


def test_readback_rejects_flags_echoes_unpinned_queries_and_tampered_transcripts() -> None:
    artifact, _ = _sealed_readback_artifact()
    for mutation in ("boolean", "echo", "state_root", "transcript"):
        broken = copy.deepcopy(artifact)
        if mutation == "boolean":
            broken["verified"] = True
        elif mutation == "echo":
            broken["deploy_input"] = copy.deepcopy(broken["facts"])
        elif mutation == "state_root":
            broken["transcripts"][2]["params"]["state_root_hash"] = "ff" * 32
        else:
            broken["transcripts"][0]["response"]["result"]["block_with_signatures"]["block"]["Version2"][
                "header"
            ]["height"] = 9_002
        with pytest.raises(ReadbackValidationError):
            verify_and_seal_readback_artifact(broken)


def test_readback_rejects_post_factory_public_slot_tampering() -> None:
    artifact, _ = _sealed_readback_artifact()
    verified = verify_and_seal_readback_artifact(artifact)
    object.__setattr__(verified, "action_authorized", False)

    with pytest.raises(ReadbackValidationError, match="public facts changed"):
        validate_verified_readback(verified)


@pytest.mark.parametrize("mutation", ["zero_proposer", "duplicate_finalizer_signer"])
def test_readback_rejects_zero_or_cross_role_colliding_governance_state(mutation: str) -> None:
    transcripts, ids = _readback_fixture()
    key = state_dictionary_key(4 if mutation == "zero_proposer" else 5)
    replacement = bytes(32) if mutation == "zero_proposer" else bytes.fromhex("03" * 32)
    target = next(item for item in transcripts if item["params"].get("dictionary_item_key") == key)
    target["response"]["result"]["stored_value"] = _cl_bytes(replacement)
    target["canonical_sha256"] = hashlib.sha256(
        json.dumps(
            {"request": target["request"], "response": target["response"]},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()

    with pytest.raises(ReadbackValidationError, match="governance roles"):
        build_readback_artifact_from_transcripts(
            transcripts=transcripts,
            expected_network="casper-test",
            expected_package_hash=ids["package"],
            expected_contract_hash=ids["contract"],
            proposal_id=ids["proposal"],
            action_id=ids["action"],
        )


def test_offline_verifier_recomputes_envelope_and_readback_instead_of_trusting_booleans() -> None:
    proof, _, _ = _bound_v3_proof()

    result = verify_v3_proof_document(proof)
    assert result["valid"] is True

    proof["passed"] = True
    proof["prepared"]["envelope_hash"] = "ff" * 32
    with pytest.raises(ProofVerificationError):
        verify_v3_proof_document(proof)


def test_offline_verifier_rejects_state_readback_before_exact_finalization() -> None:
    proof, _, ids = _bound_v3_proof()
    transcripts = copy.deepcopy(proof["readback"]["transcripts"])
    readback_header = transcripts[0]["response"]["result"]["block_with_signatures"][
        "block"
    ]["Version2"]["header"]
    readback_header["height"] = 9_001
    transcripts[0]["canonical_sha256"] = hashlib.sha256(
        json.dumps(
            {
                "request": transcripts[0]["request"],
                "response": transcripts[0]["response"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    readback = build_readback_artifact_from_transcripts(
        transcripts=transcripts,
        expected_network="casper-test",
        expected_package_hash=ids["package"],
        expected_contract_hash=ids["contract"],
        proposal_id=proof["prepared"]["proposal_id"],
        action_id=proof["prepared"]["action_id"],
    )
    proof["readback"] = readback
    proof["run"]["readback"] = copy.deepcopy(readback)

    with pytest.raises(ProofVerificationError, match="predates exact finalization"):
        verify_v3_proof_document(proof)


def test_offline_verifier_rejects_nonmonotonic_contract_step_finality() -> None:
    proof, _, _ = _bound_v3_proof()
    final_step = proof["run"]["steps"][-1]
    finality = final_step["finality_transcript"]
    finality["response"]["result"]["execution_info"]["block_height"] = 9_001
    finality["canonical_sha256"] = hashlib.sha256(
        json.dumps(
            {"request": finality["request"], "response": finality["response"]},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()

    with pytest.raises(ProofVerificationError, match="preceding contract step"):
        verify_v3_proof_document(proof)


@pytest.mark.parametrize(
    "tamper",
    [
        "missing",
        "wasm",
        "package",
        "domain",
        "role",
        "threshold",
        "package_lock",
        "install_height",
        "finality_summary",
        "broadcast_identity",
        "nested_install_success",
        "install_initiator",
        "state_root_shape",
        "state_query_shape",
        "build_command",
    ],
)
def test_proof_verifier_binds_finalized_locked_deployment_release_and_roles(tamper: str) -> None:
    proof, _, _ = _bound_v3_proof()
    deployment = proof["deployment"]
    if tamper == "missing":
        del proof["deployment"]
    elif tamper == "wasm":
        deployment["build"]["wasm_sha256"] = "ff" * 32
    elif tamper == "package":
        deployment["package_hash"] = "ff" * 32
    elif tamper == "domain":
        deployment["deployment_domain"] = "ff" * 32
    elif tamper == "role":
        deployment["roles"]["proposer"]["account_hash"] = "ff" * 32
    elif tamper == "threshold":
        deployment["threshold"] = 3
    elif tamper == "package_lock":
        deployment["raw_rpc"]["package"]["response"]["result"]["stored_value"]["ContractPackage"][
            "lock_status"
        ] = "Unlocked"
    elif tamper == "install_height":
        deployment["install_block_height"] += 1
    elif tamper == "finality_summary":
        deployment["finality"]["block_hash"] = "ff" * 32
    elif tamper == "broadcast_identity":
        deployment["raw_rpc"]["broadcast_response"]["id"] = "wrong"
    elif tamper == "nested_install_success":
        versioned = deployment["raw_rpc"]["install_deploy"]["response"]["result"][
            "execution_info"
        ]["execution_result"]["Version2"]
        del versioned["error_message"]
        versioned["effects"] = [{"Success": True}]
    elif tamper == "install_initiator":
        deployment["raw_rpc"]["install_deploy"]["response"]["result"]["execution_info"][
            "execution_result"
        ]["Version2"]["initiator"] = {"PublicKey": "01" + "ff" * 32}
    elif tamper == "state_root_shape":
        del deployment["raw_rpc"]["state_root"]["response"]["result"]["api_version"]
    elif tamper == "state_query_shape":
        del deployment["raw_rpc"]["package"]["response"]["result"]["merkle_proof"]
    else:
        deployment["build"]["command"] = "cargo build"

    with pytest.raises(ProofVerificationError):
        verify_v3_proof_document(proof)


def test_live_runner_derives_outcomes_only_from_exact_casper_v2_execution_result() -> None:
    prepared = prepare_v3_envelope(_native_document())
    readback, ids = _sealed_readback_artifact()
    run = _live_run(prepared, readback, ids)

    failed = outcome_from_finality_response(
        run["steps"][1]["finality_transcript"]["response"]
    )
    succeeded = outcome_from_finality_response(
        run["steps"][5]["finality_transcript"]["response"]
    )
    assert failed["success"] is False and failed["user_error"] == 8
    assert succeeded["success"] is True and succeeded["user_error"] is None

    forged = copy.deepcopy(run["steps"][5]["finality_transcript"]["response"])
    versioned = forged["result"]["execution_info"]["execution_result"]["Version2"]
    del versioned["error_message"]
    versioned["effects"] = [{"kind": {"Success": {}}}]
    with pytest.raises(LiveProofError, match="execution result"):
        outcome_from_finality_response(forged)


def _checkpoint_state_readback(
    *,
    package_hash: str,
    contract_hash: str,
    proposal_id: str,
    action_id: str,
    completed_steps: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    block_hash = "cc" * 32
    state_root = "dd" * 32
    transcripts = [
        _rpc(
            "chain_get_block",
            {"block_identifier": {"Hash": block_hash}},
            {
                "api_version": "2.0.0",
                "block_with_signatures": {
                    "block": {
                        "Version2": {
                            "hash": block_hash,
                            "header": {
                                "height": 9_001,
                                "state_root_hash": state_root,
                            },
                            "body": {},
                        }
                    },
                    "proofs": [],
                },
            },
        ),
        _rpc(
            "query_global_state",
            {
                "state_identifier": {"StateRootHash": state_root},
                "key": "hash-" + contract_hash,
                "path": [],
            },
            {
                "stored_value": {
                    "Contract": {
                        "contract_package_hash": "contract-package-" + package_hash
                    }
                }
            },
        ),
    ]
    return build_checkpoint_state_readback_from_transcripts(
        transcripts=transcripts,
        expected_network="casper-test",
        expected_package_hash=package_hash,
        expected_contract_hash=contract_hash,
        proposal_id=proposal_id,
        action_id=action_id,
        completed_steps=[] if completed_steps is None else completed_steps,
    )


def test_checkpoint_state_readback_reparses_raw_state_root_pinned_transcripts() -> None:
    artifact = _checkpoint_state_readback(
        package_hash="aa" * 32,
        contract_hash="bb" * 32,
        proposal_id="DAO-PROP-V3-001",
        action_id="34" * 32,
    )
    verified = verify_checkpoint_state_readback_artifact(artifact)
    assert verified["facts"]["observed_block_height"] == 9_001

    broken = copy.deepcopy(artifact)
    broken["transcripts"][0]["response"]["result"]["block_with_signatures"]["block"][
        "Version2"
    ]["header"]["state_root_hash"] = "ee" * 32
    broken["transcripts"][0]["canonical_sha256"] = hashlib.sha256(
        json.dumps(
            {
                "request": broken["transcripts"][0]["request"],
                "response": broken["transcripts"][0]["response"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    broken_without_hash = {
        key: value for key, value in broken.items() if key != "artifact_sha256"
    }
    broken["artifact_sha256"] = hashlib.sha256(
        json.dumps(
            broken_without_hash,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    with pytest.raises(ReadbackValidationError):
        verify_checkpoint_state_readback_artifact(broken)


@pytest.mark.parametrize(
    "tamper",
    [
        "checkpoint_hash",
        "role",
        "public_key",
        "network",
        "package",
        "contract",
        "entry_point",
        "args",
        "prior_state",
        "signature",
        "stale",
        "duplicate",
        "checkpoint_choreography",
    ],
)
def test_mixed_custody_browser_resume_is_checkpoint_bound_single_use_and_fail_closed(
    tamper: str,
) -> None:
    prepared = prepare_v3_envelope(_native_document())
    role_keys = _role_private_keys()
    browser_private = role_keys["proposer"]
    role_accounts: dict[str, object] = {}
    for role, private in role_keys.items():
        public = private.to_public_key()
        role_accounts[role] = {
            "custody": "browser" if role == "proposer" else "server",
            "public_key": public.account_key.hex(),
            "account_hash": public.to_account_hash().hex(),
        }
    step = _steps(prepared)[0]
    unsigned = _build_call(
        signer=browser_private.to_public_key(),
        private_key=None,
        contract_hash="bb" * 32,
        entry_point=step["entry_point"],
        runtime_args=step["args"],
        payment_motes=5_000_000_000,
        ttl="30m",
    )
    run = {
        "schema_id": "concordia.v3-live-proof-run.v1",
        "status": "waiting_for_browser_signature",
        "network": "casper-test",
        "package_hash": "aa" * 32,
        "contract_hash": "bb" * 32,
        "prepared": prepared,
        "role_accounts": role_accounts,
        "steps": [
            {
                "name": step["name"],
                "role": step["role"],
                "custody": "browser",
                "entry_point": step["entry_point"],
                "expected": step.get("expected"),
                "expected_error": step.get("expected_error"),
                "deploy_hash": unsigned["hash"],
                "deploy": unsigned,
            }
        ],
        "next_step": step["name"],
    }
    state = _checkpoint_state_readback(
        package_hash="aa" * 32,
        contract_hash="bb" * 32,
        proposal_id=prepared["proposal_id"],
        action_id=prepared["action_id"],
    )
    checkpoint = build_browser_checkpoint(
        run,
        next_step_index=0,
        prior_state_readback=state,
    )
    deploy = serializer.from_json(unsigned, Deploy)
    deploy.approve(browser_private)
    signed = serializer.to_json(deploy)
    imported = build_browser_signature_import(checkpoint, signed)
    now_seconds = deploy.header.timestamp.value + 1

    if tamper == "checkpoint_hash":
        imported["checkpoint_sha256"] = "ff" * 32
    elif tamper in {
        "role",
        "public_key",
        "network",
        "package",
        "contract",
        "entry_point",
        "args",
        "prior_state",
    }:
        field = {
            "role": "role",
            "public_key": "public_key",
            "network": "network",
            "package": "package_hash",
            "contract": "contract_hash",
            "entry_point": "entry_point",
            "args": "runtime_args_sha256",
            "prior_state": "prior_state_readback_sha256",
        }[tamper]
        imported["binding"][field] = (
            "wrong" if field in {"role", "network", "entry_point"} else "ff" * 32
        )
    elif tamper == "signature":
        signature = imported["deploy"]["approvals"][0]["signature"]
        imported["deploy"]["approvals"][0]["signature"] = signature[:-2] + (
            "00" if signature[-2:] != "00" else "01"
        )
    elif tamper == "stale":
        now_seconds = deploy.header.timestamp.value + deploy.header.ttl.as_milliseconds / 1000 + 1
    elif tamper == "checkpoint_choreography":
        checkpoint["run"]["steps"][0]["name"] = "approve_a"
        checkpoint["run"]["next_step"] = "approve_a"
        checkpoint["signature_request"]["step_name"] = "approve_a"
        checkpoint_without_hash = {
            key: value for key, value in checkpoint.items() if key != "checkpoint_sha256"
        }
        checkpoint["checkpoint_sha256"] = hashlib.sha256(
            json.dumps(
                checkpoint_without_hash,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest()
        imported = build_browser_signature_import(checkpoint, signed)
    else:
        checkpoint = validate_and_stage_browser_import(
            checkpoint,
            imported,
            now_seconds=now_seconds,
        )
        imported = build_browser_signature_import(checkpoint, signed)

    with pytest.raises(LiveProofError):
        validate_and_stage_browser_import(
            checkpoint,
            imported,
            now_seconds=now_seconds,
        )


def test_mixed_custody_browser_resume_accepts_exact_signed_deploy_and_seals_consumption() -> None:
    prepared = prepare_v3_envelope(_native_document())
    role_keys = _role_private_keys()
    browser_private = role_keys["proposer"]
    role_accounts: dict[str, object] = {}
    for role, private in role_keys.items():
        public = private.to_public_key()
        role_accounts[role] = {
            "custody": "browser" if role == "proposer" else "server",
            "public_key": public.account_key.hex(),
            "account_hash": public.to_account_hash().hex(),
        }
    step = _steps(prepared)[0]
    unsigned = _build_call(
        signer=browser_private.to_public_key(),
        private_key=None,
        contract_hash="bb" * 32,
        entry_point=step["entry_point"],
        runtime_args=step["args"],
        payment_motes=5_000_000_000,
        ttl="30m",
    )
    run = {
        "schema_id": "concordia.v3-live-proof-run.v1",
        "status": "waiting_for_browser_signature",
        "network": "casper-test",
        "package_hash": "aa" * 32,
        "contract_hash": "bb" * 32,
        "prepared": prepared,
        "role_accounts": role_accounts,
        "steps": [
            {
                "name": step["name"],
                "role": step["role"],
                "custody": "browser",
                "entry_point": step["entry_point"],
                "expected": step.get("expected"),
                "expected_error": step.get("expected_error"),
                "deploy_hash": unsigned["hash"],
                "deploy": unsigned,
            }
        ],
        "next_step": step["name"],
    }
    checkpoint = build_browser_checkpoint(
        run,
        next_step_index=0,
        prior_state_readback=_checkpoint_state_readback(
            package_hash="aa" * 32,
            contract_hash="bb" * 32,
            proposal_id=prepared["proposal_id"],
            action_id=prepared["action_id"],
        ),
    )
    deploy = serializer.from_json(unsigned, Deploy)
    deploy.approve(browser_private)
    signed = serializer.to_json(deploy)
    imported = build_browser_signature_import(checkpoint, signed)

    staged = validate_and_stage_browser_import(
        checkpoint,
        imported,
        now_seconds=deploy.header.timestamp.value + 1,
    )

    assert staged["status"] == "signed_deploy_staged"
    assert staged["run"]["steps"][0]["deploy"] == signed
    assert staged["consumed_import_deploy_hashes"] == [signed["hash"].lower()]
    assert len(staged["checkpoint_sha256"]) == 64


@pytest.mark.asyncio
async def test_live_runner_resumes_one_browser_step_and_checkpoints_next_without_reimport(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    document = _native_document()
    prepared = prepare_v3_envelope(document)
    role_keys = _role_private_keys()
    roles = {
        name: {
            "custody": "browser",
            "public_key": private.to_public_key().account_key.hex(),
        }
        for name, private in role_keys.items()
    }
    input_path = tmp_path / "input.json"
    roles_path = tmp_path / "roles.json"
    checkpoint_path = tmp_path / "checkpoint.json"
    import_path = tmp_path / "signed.json"
    input_path.write_text(json.dumps(document), encoding="utf-8")
    roles_path.write_text(json.dumps(roles), encoding="utf-8")

    def fake_checkpoint_state(**kwargs: object) -> dict[str, object]:
        return _checkpoint_state_readback(
            package_hash=str(kwargs["package_hash"]),
            contract_hash=str(kwargs["contract_hash"]),
            proposal_id=str(kwargs["proposal_id"]),
            action_id=str(kwargs["action_id"]),
            completed_steps=list(kwargs["completed_steps"]),
        )

    class FakeResponse:
        def __init__(self, request: dict[str, object]):
            deploy = request["params"]["deploy"]
            self._value = {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {
                    "api_version": "2.0.0",
                    "deploy_hash": deploy["hash"],
                },
            }

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return self._value

    class FakeAsyncClient:
        def __init__(self, **_: object):
            pass

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def post(self, _: str, *, json: dict[str, object]) -> FakeResponse:
            return FakeResponse(json)

    async def fake_finality(**kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
        deploy_hash = str(kwargs["deploy_hash"])
        transcript = _rpc(
            "info_get_deploy",
            {"deploy_hash": deploy_hash},
            {
                "api_version": "2.0.0",
                "deploy": {},
                "execution_info": None,
            },
        )
        return transcript, {
            "finalized": True,
            "success": True,
            "user_error": None,
            "error_message": None,
            "block_hash": "cc" * 32,
            "block_height": 9_002,
        }

    monkeypatch.setattr(live_proof_runner, "capture_v3_checkpoint_state", fake_checkpoint_state)
    monkeypatch.setattr(live_proof_runner.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(live_proof_runner, "_await_finality_transcript", fake_finality)
    args = argparse.Namespace(
        input=input_path,
        roles=roles_path,
        package_hash="aa" * 32,
        contract_hash="bb" * 32,
        rpc_url="https://node.testnet.casper.network/rpc",
        payment_motes=5_000_000_000,
        ttl="30m",
        max_attempts=1,
        poll_seconds=0.0,
        prepare_only=False,
        resume_checkpoint=None,
        signed_deploy=None,
        out=checkpoint_path,
    )
    first = await live_proof_runner.run(args)
    assert first["status"] == "waiting_for_browser_signature"
    assert first["next_step_index"] == 0

    unsigned = first["run"]["steps"][0]["deploy"]
    signed_deploy = serializer.from_json(unsigned, Deploy)
    signed_deploy.approve(role_keys["proposer"])
    import_path.write_text(
        json.dumps(serializer.to_json(signed_deploy)),
        encoding="utf-8",
    )
    args.resume_checkpoint = checkpoint_path
    args.signed_deploy = import_path
    second = await live_proof_runner.run(args)

    assert second["status"] == "waiting_for_browser_signature"
    assert second["next_step_index"] == 1
    assert second["run"]["steps"][0]["observed_outcome"]["success"] is True
    assert second["prior_state_readback"]["expected"]["completed_steps"][0][
        "name"
    ] == "propose_exact"
    assert second["run"]["prepared"] == prepared

    broken = copy.deepcopy(second)
    broken["prior_state_readback"]["expected"]["completed_steps"][0]["name"] = "forged"
    broken["prior_state_readback"]["facts"]["completed_steps"][0]["name"] = "forged"
    prior_unsigned = {
        key: value
        for key, value in broken["prior_state_readback"].items()
        if key != "artifact_sha256"
    }
    broken["prior_state_readback"]["artifact_sha256"] = hashlib.sha256(
        json.dumps(prior_unsigned, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    broken["signature_request"]["prior_state_readback_sha256"] = broken[
        "prior_state_readback"
    ]["artifact_sha256"]
    checkpoint_unsigned = {
        key: value for key, value in broken.items() if key != "checkpoint_sha256"
    }
    broken["checkpoint_sha256"] = hashlib.sha256(
        json.dumps(
            checkpoint_unsigned,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    next_unsigned = broken["run"]["steps"][1]["deploy"]
    next_signed = serializer.from_json(next_unsigned, Deploy)
    next_signed.approve(role_keys["finalizer"])
    with pytest.raises(LiveProofError, match="completed run prefix"):
        validate_and_stage_browser_import(
            broken,
            build_browser_signature_import(broken, serializer.to_json(next_signed)),
            now_seconds=next_signed.header.timestamp.value + 1,
        )


@pytest.mark.parametrize(
    "tamper",
    [
        "error_code",
        "runtime_arg",
        "broadcast_hash",
        "role",
        "payment",
        "header",
        "signature",
        "node_deploy",
        "unrelated_nested_success",
    ],
)
def test_live_proof_verifier_rejects_adversarial_raw_step_transcript_tampering(tamper: str) -> None:
    proof, _, _ = _bound_v3_proof()
    run = proof["run"]
    if tamper == "error_code":
        step = run["steps"][1]
        step["finality_transcript"]["response"]["result"]["execution_info"]["execution_result"]["Version2"][
            "error_message"
        ] = "User error: 10"
    elif tamper == "runtime_arg":
        run["steps"][5]["deploy"]["session"]["StoredContractByHash"]["args"][2][1]["parsed"] = 99
    elif tamper == "broadcast_hash":
        run["steps"][0]["broadcast_transcript"]["response"]["result"]["deploy_hash"] = "ff" * 32
    elif tamper == "role":
        run["role_accounts"]["signer_b"]["account_hash"] = run["role_accounts"]["signer_a"]["account_hash"]
    elif tamper == "payment":
        run["steps"][0]["deploy"]["payment"]["ModuleBytes"]["args"][0][1]["parsed"] = "1"
    elif tamper == "header":
        run["steps"][0]["deploy"]["header"]["chain_name"] = "casper"
    elif tamper == "signature":
        signature = run["steps"][0]["deploy"]["approvals"][0]["signature"]
        run["steps"][0]["deploy"]["approvals"][0]["signature"] = signature[:-2] + (
            "00" if signature[-2:] != "00" else "01"
        )
    elif tamper == "node_deploy":
        run["steps"][0]["finality_transcript"]["response"]["result"]["deploy"]["header"][
            "chain_name"
        ] = "casper"
    else:
        result = run["steps"][5]["finality_transcript"]["response"]["result"]["execution_info"][
            "execution_result"
        ]["Version2"]
        del result["error_message"]
        result["effects"] = [{"kind": {"Success": {}}}]

    for step in run["steps"]:
        for name in ("broadcast_transcript", "finality_transcript"):
            transcript = step[name]
            transcript["canonical_sha256"] = hashlib.sha256(
                json.dumps(
                    {"request": transcript["request"], "response": transcript["response"]},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()

    with pytest.raises(ProofVerificationError):
        verify_v3_proof_document(proof)
