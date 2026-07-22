#!/usr/bin/env python3
"""Build the only release-approved, permanently non-upgradable v3 install."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

import httpx
from pycspr import crypto, serializer
from pycspr.factory.accounts import parse_private_key
from pycspr.factory.deploys import create_deploy, create_deploy_parameters, create_standard_payment
from pycspr.factory.digests import create_digest_of_deploy, create_digest_of_deploy_body
from pycspr.types.cl import CLV_Bool, CLV_ByteArray, CLV_String, CLV_U512, CLV_U8
from pycspr.types.crypto import KeyAlgorithm
from pycspr.types.node.rpc import Deploy, DeployOfModuleBytes

from scripts.derive_deployment_domain_v3 import deployment_domain_record
from shared.casper_executor import await_casper_finality


PACKAGE_KEY_NAME = "concordia_governance_receipt_v3"
CHAIN_NAME = "casper-test"


class InstallValidationError(ValueError):
    pass


def _commit_hash(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 40 or value != value.lower():
        raise InstallValidationError(f"{field}: exact lowercase 40-hex commit required")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise InstallValidationError(f"{field}: exact lowercase 40-hex commit required") from exc
    return value


def _hash32(value: object, field: str) -> bytes:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        raise InstallValidationError(f"{field}: 64 lowercase hex characters required")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise InstallValidationError(f"{field}: invalid hexadecimal") from exc
    if result == bytes(32):
        raise InstallValidationError(f"{field}: zero account is forbidden")
    return result


def _role_account(role: object, field: str) -> bytes:
    if not isinstance(role, Mapping) or set(role) != {"kind", "account_hash"}:
        raise InstallValidationError(f"{field}: typed account-only identity required")
    if role["kind"] != "Account":
        raise InstallValidationError(f"{field}: account-only identity required")
    return _hash32(role["account_hash"], field)


def build_locked_install_args(
    *,
    installer_account_hash: str,
    roles: Mapping[str, object],
    threshold: int,
    casper_chain_name: str,
    installation_nonce: str,
) -> dict[str, object]:
    expected_roles = {"proposer", "finalizer", "signer_a", "signer_b", "signer_c"}
    if set(roles) != expected_roles:
        raise InstallValidationError("roles must contain exactly proposer, finalizer and signer_a/b/c")
    installer = _hash32(installer_account_hash, "installer_account_hash")
    role_values = {name: _role_account(roles[name], name) for name in sorted(expected_roles)}
    proposer = role_values["proposer"]
    finalizer = role_values["finalizer"]
    signers = [role_values[name] for name in ("signer_a", "signer_b", "signer_c")]
    if installer in role_values.values():
        raise InstallValidationError("installer must be distinct from every governance role")
    if proposer == finalizer or any(value in (proposer, finalizer) for value in signers):
        raise InstallValidationError("proposer, finalizer and signers must be pairwise distinct")
    if len(set(signers)) != 3:
        raise InstallValidationError("three pairwise-distinct signers are required")
    if type(threshold) is not int or threshold not in (2, 3):
        raise InstallValidationError("threshold must be exactly 2 or 3")
    try:
        nonce = _hash32(installation_nonce, "installation_nonce")
        deployment_domain_record(
            installation_nonce,
            chain_name=casper_chain_name,
            package_key_name=PACKAGE_KEY_NAME,
        )
    except ValueError as exc:
        raise InstallValidationError(str(exc)) from exc

    return {
        "odra_cfg_package_hash_key_name": CLV_String(PACKAGE_KEY_NAME),
        "odra_cfg_allow_key_override": CLV_Bool(False),
        "odra_cfg_is_upgradable": CLV_Bool(False),
        "odra_cfg_is_upgrade": CLV_Bool(False),
        "proposer": CLV_ByteArray(proposer),
        "finalizer": CLV_ByteArray(finalizer),
        "signer_a": CLV_ByteArray(signers[0]),
        "signer_b": CLV_ByteArray(signers[1]),
        "signer_c": CLV_ByteArray(signers[2]),
        "threshold": CLV_U8(threshold),
        "casper_chain_name": CLV_String(casper_chain_name),
        "installation_nonce": CLV_ByteArray(nonce),
    }


def _normalize_schema_type(value: object) -> object:
    if isinstance(value, dict):
        return {key: _normalize_schema_type(item) for key, item in value.items()}
    return value


def diff_entry_point_args_against_schema(
    schema: Mapping[str, Any],
    entry_point: str,
    runtime_args: Sequence[Mapping[str, Any]],
) -> list[str]:
    matches = [item for item in schema.get("entry_points", []) if item.get("name") == entry_point]
    if len(matches) != 1:
        return [f"schema entry point {entry_point!r} missing or duplicated"]
    expected = [(arg["name"], _normalize_schema_type(arg["ty"])) for arg in matches[0]["arguments"]]
    actual = [(arg.get("name"), _normalize_schema_type(arg.get("cl_type"))) for arg in runtime_args]
    failures: list[str] = []
    if [name for name, _ in actual] != [name for name, _ in expected]:
        failures.append("runtime argument names/order differ from generated schema")
    for position, (expected_item, actual_item) in enumerate(zip(expected, actual, strict=False)):
        if expected_item != actual_item:
            failures.append(f"argument {position}: expected {expected_item!r}, got {actual_item!r}")
    if len(expected) != len(actual):
        failures.append(f"argument count: expected {len(expected)}, got {len(actual)}")
    return failures


def build_signed_install_payload(
    *,
    secret_key_path: Path,
    key_algorithm: str,
    roles: Mapping[str, object],
    threshold: int,
    installation_nonce: str,
    wasm_path: Path,
    schema_path: Path,
    payment_amount_motes: int,
    ttl: str,
    source_commit: str,
    deployment_commit: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    source_commit = _commit_hash(source_commit, "source_commit")
    deployment_commit = _commit_hash(deployment_commit, "deployment_commit")
    if not wasm_path.is_file() or not wasm_path.read_bytes().startswith(b"\x00asm"):
        raise InstallValidationError("release Wasm is missing or not a WebAssembly module")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    expected_wasm_name = schema.get("call", {}).get("wasm_file_name")
    if wasm_path.name != expected_wasm_name:
        raise InstallValidationError(
            f"Wasm filename must be generated-schema authority {expected_wasm_name!r}"
        )
    try:
        algorithm = KeyAlgorithm[key_algorithm.strip().upper()]
        private_key = parse_private_key(secret_key_path, algorithm)
    except (KeyError, OSError, ValueError) as exc:
        raise InstallValidationError("installer key could not be loaded") from exc
    public_key = private_key.to_public_key()
    installer_hash = public_key.to_account_hash().hex()
    session_args = build_locked_install_args(
        installer_account_hash=installer_hash,
        roles=roles,
        threshold=threshold,
        casper_chain_name=CHAIN_NAME,
        installation_nonce=installation_nonce,
    )
    call_args = [{"name": name, **serializer.to_json(value)} for name, value in session_args.items()]
    expected_call = [(item["name"], item["ty"]) for item in schema["call"]["arguments"]]
    actual_call = [(item["name"], item["cl_type"]) for item in call_args]
    if expected_call != actual_call:
        raise InstallValidationError("locked installer args differ from generated Odra call schema")

    params = create_deploy_parameters(private_key, CHAIN_NAME, ttl=ttl)
    payment = create_standard_payment(payment_amount_motes)
    session = DeployOfModuleBytes(module_bytes=wasm_path.read_bytes(), args=session_args)
    deploy = create_deploy(params, payment, session)
    deploy.approve(private_key)
    deploy_json = serializer.to_json(deploy)
    payload = {
        "jsonrpc": "2.0",
        "id": "concordia-v3-install",
        "method": "account_put_deploy",
        "params": {"deploy": deploy_json},
    }
    template_path = wasm_path.parent.parent / "deployment.manifest.json"
    if not template_path.is_file():
        raise InstallValidationError("versioned deployment.manifest.json template is missing")
    manifest = json.loads(template_path.read_text(encoding="utf-8"))
    actual_wasm_hash = hashlib.sha256(wasm_path.read_bytes()).hexdigest()
    actual_schema_hash = hashlib.sha256(schema_path.read_bytes()).hexdigest()
    if manifest.get("build", {}).get("wasm_sha256") != actual_wasm_hash:
        raise InstallValidationError("release Wasm differs from deployment manifest")
    if manifest.get("build", {}).get("schema_sha256") != actual_schema_hash:
        raise InstallValidationError("generated schema differs from deployment manifest")
    manifest.update(
        {
            "status": "prepared",
            "installer_public_key": public_key.account_key.hex(),
            "installer_account_hash": installer_hash,
            "deployment_domain": deployment_domain_record(installation_nonce)["deployment_domain"],
            "installation_nonce": installation_nonce,
            "threshold": threshold,
            "roles": roles,
            "install_deploy_hash": str(deploy_json["hash"]),
            "install_payment_motes": payment_amount_motes,
            "install_ttl": ttl,
            "source_commit": source_commit,
            "deployment_commit": deployment_commit,
        }
    )
    return payload, manifest


def _rpc(rpc_url: str, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
    request = {
        "jsonrpc": "2.0",
        "id": "concordia-v3-install-" + method,
        "method": method,
        "params": dict(params),
    }
    response = httpx.post(rpc_url, json=request, timeout=60.0)
    response.raise_for_status()
    parsed = response.json()
    if (
        not isinstance(parsed, dict)
        or set(parsed) != {"jsonrpc", "id", "result"}
        or parsed.get("jsonrpc") != "2.0"
        or parsed.get("id") != request["id"]
    ):
        raise InstallValidationError(f"Casper RPC {method} failed")
    return {"request": request, "response": parsed}


def _strip_hash(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise InstallValidationError(f"{field} is missing")
    for prefix in ("contract-package-", "contract-", "package-", "hash-"):
        if value.startswith(prefix):
            value = value[len(prefix) :]
            break
    if len(value) != 64:
        raise InstallValidationError(f"{field} is not a 32-byte hash")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise InstallValidationError(f"{field} is not hexadecimal") from exc
    return value.lower()


def _find_named_key(value: object, name: str) -> str | None:
    if isinstance(value, Mapping):
        if value.get("name") == name and isinstance(value.get("key"), str):
            return str(value["key"])
        for item in value.values():
            found = _find_named_key(item, name)
            if found:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_named_key(item, name)
            if found:
                return found
    return None


def _normalize_deploy_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _normalize_deploy_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize_deploy_json(item) for item in value]
    if isinstance(value, str) and len(value) % 2 == 0:
        try:
            bytes.fromhex(value)
        except ValueError:
            return value
        return value.lower()
    return value


def validate_finalized_install_deploy(
    value: object,
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "approvals",
        "hash",
        "header",
        "payment",
        "session",
    }:
        raise InstallValidationError("install deploy JSON field set is invalid")
    try:
        deploy = serializer.from_json(dict(value), Deploy)
        canonical_json = serializer.to_json(deploy)
        body_hash = create_digest_of_deploy_body(deploy.payment, deploy.session)
        deploy_hash = create_digest_of_deploy(deploy.header)
    except Exception as exc:
        raise InstallValidationError("install deploy cannot be decoded canonically") from exc
    if _normalize_deploy_json(canonical_json) != _normalize_deploy_json(value):
        raise InstallValidationError("install deploy parsed fields disagree with canonical bytes")
    if deploy.header.body_hash != body_hash or deploy.hash != deploy_hash:
        raise InstallValidationError("install deploy body/deploy hash mismatch")
    if deploy_hash.hex() != _strip_hash(manifest.get("install_deploy_hash"), "install deploy hash"):
        raise InstallValidationError("finalized install deploy hash differs from prepared deploy")
    if deploy.header.chain_name != CHAIN_NAME:
        raise InstallValidationError("install deploy is not on casper-test")
    installer_public_key = manifest.get("installer_public_key")
    if (
        not isinstance(installer_public_key, str)
        or deploy.header.account.account_key.hex() != installer_public_key.lower()
    ):
        raise InstallValidationError("install deploy initiator differs from installer")
    if len(deploy.approvals) != 1:
        raise InstallValidationError("install deploy must carry exactly one installer approval")
    approval = deploy.approvals[0]
    signer = getattr(approval.signer, "account_key", None)
    if not isinstance(signer, bytes) or signer.hex() != installer_public_key.lower():
        raise InstallValidationError("install approval signer differs from installer")
    try:
        signature_valid = crypto.verify_deploy_approval_signature(
            deploy_hash,
            approval.signature,
            signer,
        )
    except Exception as exc:
        raise InstallValidationError("install approval signature is invalid") from exc
    if not signature_valid:
        raise InstallValidationError("install approval signature is invalid")

    if type(deploy.payment) is not DeployOfModuleBytes or deploy.payment.module_bytes != b"":
        raise InstallValidationError("install payment must be standard ModuleBytes")
    expected_payment = manifest.get("install_payment_motes")
    if type(expected_payment) is not int or expected_payment <= 0:
        raise InstallValidationError("install manifest payment amount is invalid")
    payment_json = serializer.to_json(deploy.payment)["ModuleBytes"]
    if _normalize_deploy_json(payment_json) != _normalize_deploy_json(
        {
            "module_bytes": "",
            "args": [("amount", serializer.to_json(CLV_U512(expected_payment)))],
        }
    ):
        raise InstallValidationError("install payment differs from prepared amount")

    if type(deploy.session) is not DeployOfModuleBytes:
        raise InstallValidationError("install session must be ModuleBytes")
    wasm_sha256 = hashlib.sha256(deploy.session.module_bytes).hexdigest()
    if wasm_sha256 != manifest.get("build", {}).get("wasm_sha256"):
        raise InstallValidationError("finalized install Wasm differs from release manifest")
    roles = manifest.get("roles")
    if not isinstance(roles, Mapping):
        raise InstallValidationError("install manifest roles are invalid")
    expected_args = build_locked_install_args(
        installer_account_hash=str(manifest.get("installer_account_hash")),
        roles=roles,
        threshold=manifest.get("threshold"),
        casper_chain_name=CHAIN_NAME,
        installation_nonce=str(manifest.get("installation_nonce")),
    )
    actual_args = [
        (argument.name, serializer.to_json(argument.value))
        for argument in deploy.session.arguments
    ]
    frozen_args = [(name, serializer.to_json(clv)) for name, clv in expected_args.items()]
    if _normalize_deploy_json(actual_args) != _normalize_deploy_json(frozen_args):
        raise InstallValidationError("finalized install arguments differ from locked constructor")
    return {
        "deploy_hash": deploy_hash.hex(),
        "body_hash": body_hash.hex(),
        "wasm_sha256": wasm_sha256,
        "installer_public_key": installer_public_key.lower(),
        "locked_argument_names": [name for name, _ in frozen_args],
    }


def _validate_successful_install_rpc(
    transcript: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    response = transcript.get("response")
    result = response.get("result") if isinstance(response, Mapping) else None
    if not isinstance(result, Mapping) or set(result) != {
        "api_version",
        "deploy",
        "execution_info",
    }:
        raise InstallValidationError("install finality is not the exact Casper v2 deploy shape")
    if not isinstance(result["api_version"], str) or not result["api_version"]:
        raise InstallValidationError("install finality lacks api_version")
    deploy_facts = validate_finalized_install_deploy(result["deploy"], manifest)
    execution_info = result["execution_info"]
    if not isinstance(execution_info, Mapping) or set(execution_info) != {
        "block_hash",
        "block_height",
        "execution_result",
    }:
        raise InstallValidationError("install execution_info field set is invalid")
    versioned = execution_info["execution_result"]
    if not isinstance(versioned, Mapping) or set(versioned) != {"Version2"}:
        raise InstallValidationError("install execution result is not Version2")
    outcome = versioned["Version2"]
    if not isinstance(outcome, Mapping) or set(outcome) != {
        "initiator",
        "error_message",
        "current_price",
        "limit",
        "consumed",
        "cost",
        "refund",
        "transfers",
        "size_estimate",
        "effects",
    }:
        raise InstallValidationError("install execution outcome is invalid")
    initiator = outcome["initiator"]
    if (
        not isinstance(initiator, Mapping)
        or set(initiator) != {"PublicKey"}
        or not isinstance(initiator["PublicKey"], str)
        or initiator["PublicKey"].lower()
        != str(manifest.get("installer_public_key", "")).lower()
    ):
        raise InstallValidationError("install execution initiator differs from installer")
    if outcome["error_message"] is not None:
        raise InstallValidationError("v3 install execution failed")
    block_hash = _strip_hash(execution_info["block_hash"], "install execution block hash")
    block_height = execution_info["block_height"]
    if type(block_height) is not int or block_height < 0:
        raise InstallValidationError("install execution block height is invalid")
    return {**deploy_facts, "block_hash": block_hash, "block_height": block_height}


def _resolve_locked_contract(package_value: object) -> tuple[int, str]:
    if not isinstance(package_value, Mapping):
        raise InstallValidationError("package state is missing")
    package = package_value.get("ContractPackage")
    if not isinstance(package, Mapping) or set(package) != {
        "access_key",
        "versions",
        "disabled_versions",
        "groups",
        "lock_status",
    }:
        raise InstallValidationError("package query did not return ContractPackage")
    if package["lock_status"] != "Locked":
        raise InstallValidationError("v3 package is not permanently locked")
    versions = package.get("versions")
    if not isinstance(versions, list) or len(versions) != 1:
        raise InstallValidationError("v3 package must contain exactly one contract version")
    version_record = versions[0]
    if not isinstance(version_record, Mapping) or set(version_record) != {
        "protocol_version_major",
        "contract_version",
        "contract_hash",
    }:
        raise InstallValidationError("v3 contract version record is invalid")
    if version_record["protocol_version_major"] != 2 or version_record["contract_version"] != 1:
        raise InstallValidationError("v3 package must install exactly protocol-2 contract version 1")
    if package["disabled_versions"] != []:
        raise InstallValidationError("v3 package contains disabled or historical versions")
    groups = package["groups"]
    if not isinstance(groups, list):
        raise InstallValidationError("v3 package groups are invalid")
    for group in groups:
        if (
            not isinstance(group, Mapping)
            or set(group) != {"group_name", "group_users"}
            or not isinstance(group["group_name"], str)
            or group["group_users"] != []
        ):
            raise InstallValidationError("v3 package exposes an upgrade-capable group")
    access_key = package["access_key"]
    if not isinstance(access_key, str):
        raise InstallValidationError("v3 package access key is invalid")
    parts = access_key.split("-")
    try:
        canonical_address = bytes.fromhex(parts[1]).hex()
    except (IndexError, ValueError) as exc:
        raise InstallValidationError("v3 package access key is invalid") from exc
    if (
        len(parts) != 3
        or parts[0] != "uref"
        or len(parts[1]) != 64
        or parts[1] != canonical_address
        or parts[2] not in {f"{rights:03d}" for rights in range(8)}
    ):
        raise InstallValidationError("v3 package access key is invalid")
    return 1, _strip_hash(version_record["contract_hash"], "contract_hash")


def finalize_deployment_manifest(
    *,
    rpc_url: str,
    manifest: dict[str, Any],
    broadcast_response: Mapping[str, Any],
) -> dict[str, Any]:
    deploy_hash = str((broadcast_response.get("result") or {}).get("deploy_hash") or "")
    if deploy_hash.lower() != str(manifest["install_deploy_hash"]).lower():
        raise InstallValidationError("node returned a different install deploy hash")
    finality = asyncio.run(await_casper_finality(deploy_hash, rpc_url=rpc_url, max_attempts=30, poll_interval_seconds=6))
    if finality.get("success") is not True:
        raise InstallValidationError("v3 install did not finalize successfully")
    block_hash = finality.get("block_hash")
    if not isinstance(block_hash, str):
        raise InstallValidationError("install finality lacks a block hash")
    install_rpc = _rpc(
        rpc_url,
        "info_get_deploy",
        {"deploy_hash": deploy_hash},
    )
    install_facts = _validate_successful_install_rpc(install_rpc, manifest)
    if install_facts["block_hash"] != _strip_hash(block_hash, "install block hash"):
        raise InstallValidationError("install finality summary disagrees with raw node response")
    root_rpc = _rpc(
        rpc_url,
        "chain_get_state_root_hash",
        {"block_identifier": {"Hash": _strip_hash(block_hash, "install block hash")}},
    )
    state_root = (root_rpc["response"].get("result") or {}).get("state_root_hash")
    state_root = _strip_hash(state_root, "install state root")
    account_rpc = _rpc(
        rpc_url,
        "query_global_state",
        {
            "state_identifier": {"StateRootHash": state_root},
            "key": "account-hash-" + manifest["installer_account_hash"],
            "path": [],
        },
    )
    account_value = (account_rpc["response"].get("result") or {}).get("stored_value")
    package_key = _find_named_key(account_value, PACKAGE_KEY_NAME)
    package_hash = _strip_hash(package_key, "v3 package named key")
    package_rpc = _rpc(
        rpc_url,
        "query_global_state",
        {
            "state_identifier": {"StateRootHash": state_root},
            "key": "hash-" + package_hash,
            "path": [],
        },
    )
    package_value = (package_rpc["response"].get("result") or {}).get("stored_value")
    version, contract_hash = _resolve_locked_contract(package_value)
    contract_rpc = _rpc(
        rpc_url,
        "query_global_state",
        {
            "state_identifier": {"StateRootHash": state_root},
            "key": "hash-" + contract_hash,
            "path": [],
        },
    )
    contract_value = (contract_rpc["response"].get("result") or {}).get("stored_value")
    contract = contract_value.get("Contract") if isinstance(contract_value, Mapping) else None
    if not isinstance(contract, Mapping) or _strip_hash(
        contract.get("contract_package_hash"), "contract package ownership"
    ) != package_hash:
        raise InstallValidationError("exact contract does not belong to the installed package")
    result = dict(manifest)
    canonical_finality = {
        "status": "finalized",
        "success": True,
        "block_hash": install_facts["block_hash"],
        "block_height": install_facts["block_height"],
        "deploy_hash": install_facts["deploy_hash"],
    }
    result.update(
        {
            "status": "finalized",
            "package_hash": package_hash,
            "contract_hash": contract_hash,
            "contract_version": version,
            "install_block_hash": _strip_hash(block_hash, "install block hash"),
            "install_block_height": finality.get("block_height"),
            "install_state_root_hash": state_root,
            "finality": canonical_finality,
            "verified_install_deploy": install_facts,
            "raw_rpc": {
                "broadcast_response": dict(broadcast_response),
                "install_deploy": install_rpc,
                "state_root": root_rpc,
                "installer_account": account_rpc,
                "package": package_rpc,
                "contract": contract_rpc,
            },
        }
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--secret-key", type=Path, required=True)
    parser.add_argument("--key-algorithm", default="ED25519")
    parser.add_argument("--roles", type=Path, required=True)
    parser.add_argument("--threshold", type=int, default=2)
    parser.add_argument("--installation-nonce", required=True)
    parser.add_argument("--wasm", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--payment-motes", type=int, default=30_000_000_000)
    parser.add_argument("--ttl", default="30m")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--deployment-commit", required=True)
    parser.add_argument("--node-rpc-url", default="https://node.testnet.casper.network/rpc")
    parser.add_argument("--submit", action="store_true")
    parser.add_argument("--manifest-out", type=Path, required=True)
    args = parser.parse_args()
    try:
        roles = json.loads(args.roles.read_text(encoding="utf-8"))
        payload, manifest = build_signed_install_payload(
            secret_key_path=args.secret_key,
            key_algorithm=args.key_algorithm,
            roles=roles,
            threshold=args.threshold,
            installation_nonce=args.installation_nonce,
            wasm_path=args.wasm,
            schema_path=args.schema,
            payment_amount_motes=args.payment_motes,
            ttl=args.ttl,
            source_commit=args.source_commit,
            deployment_commit=args.deployment_commit,
        )
        if args.submit:
            response = httpx.post(args.node_rpc_url, json=payload, timeout=60.0)
            response.raise_for_status()
            parsed = response.json()
            if parsed.get("error"):
                raise InstallValidationError(f"install RPC failed: {parsed['error']}")
            manifest = finalize_deployment_manifest(
                rpc_url=args.node_rpc_url,
                manifest=manifest,
                broadcast_response=parsed,
            )
        args.manifest_out.parent.mkdir(parents=True, exist_ok=True)
        args.manifest_out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        print(json.dumps({"status": "submitted" if args.submit else "prepared", "manifest": str(args.manifest_out)}))
        return 0
    except (InstallValidationError, OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
