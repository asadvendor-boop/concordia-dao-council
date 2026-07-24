#!/usr/bin/env python3
"""Offline verifier for Concordia's transcript-backed exact-envelope v3 proof."""

from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from pycspr import crypto, serializer
from pycspr.factory.accounts import create_public_key_from_account_key
from pycspr.factory.digests import create_digest_of_deploy, create_digest_of_deploy_body
from pycspr.types.cl import CLV_ByteArray, CLV_String, CLV_U32
from pycspr.types.node.rpc import Deploy

from scripts.derive_deployment_domain_v3 import deployment_domain_record
from scripts.install_governance_receipt_v3 import (
    InstallValidationError,
    _resolve_locked_contract,
    _validate_successful_install_rpc,
    verify_two_node_deploy_finality,
)
from scripts.prepare_v3_envelope import prepare_v3_envelope
from scripts.read_v3_state import validate_verified_readback, verify_and_seal_readback_artifact


class ProofVerificationError(ValueError):
    pass


def _same(name: str, actual: object, expected: object) -> None:
    if actual != expected:
        raise ProofVerificationError(f"{name} does not match independent recomputation")


_USER_ERROR = re.compile(r"(?:User error|ApiError::User)[:( ]+(\d+)")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_RFC3339_UTC = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z"
)
ROOT = Path(__file__).resolve().parents[1]
V3_ROOT = ROOT / "contracts/odra-governance-receipt-v3"


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _utc_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or _RFC3339_UTC.fullmatch(value) is None:
        raise ProofVerificationError(f"{field} must be exact RFC3339 UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ProofVerificationError(f"{field} must be exact RFC3339 UTC") from exc
    if parsed.tzinfo != timezone.utc:
        raise ProofVerificationError(f"{field} must be exact RFC3339 UTC")
    return parsed


def _verified_transcript(value: object, *, method: str) -> Mapping[str, Any]:
    expected = {
        "rpc_url_identity_or_node_id",
        "method",
        "params",
        "request",
        "response",
        "canonical_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != expected or value["method"] != method:
        raise ProofVerificationError(f"{method} transcript shape is invalid")
    request = value["request"]
    response = value["response"]
    if not isinstance(request, Mapping) or set(request) != {"jsonrpc", "id", "method", "params"}:
        raise ProofVerificationError(f"{method} raw request is invalid")
    if request["jsonrpc"] != "2.0" or request["method"] != method or request["params"] != value["params"]:
        raise ProofVerificationError(f"{method} request summary mismatch")
    if not isinstance(response, Mapping) or response.get("jsonrpc") != "2.0" or response.get("id") != request["id"]:
        raise ProofVerificationError(f"{method} response identity mismatch")
    if response.get("error") is not None or "result" not in response:
        raise ProofVerificationError(f"{method} response is not successful RPC evidence")
    digest = hashlib.sha256(_canonical_json({"request": request, "response": response})).hexdigest()
    if not hmac.compare_digest(str(value["canonical_sha256"]), digest):
        raise ProofVerificationError(f"{method} transcript digest mismatch")
    return value


def _install_rpc(value: object, *, method: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {"request", "response"}:
        raise ProofVerificationError(f"install {method} transcript shape is invalid")
    request = value["request"]
    response = value["response"]
    if (
        not isinstance(request, Mapping)
        or set(request) != {"jsonrpc", "id", "method", "params"}
        or request["jsonrpc"] != "2.0"
        or request["method"] != method
        or not isinstance(request["params"], Mapping)
    ):
        raise ProofVerificationError(f"install {method} request is invalid")
    if (
        not isinstance(response, Mapping)
        or set(response) != {"jsonrpc", "id", "result"}
        or response["jsonrpc"] != "2.0"
        or response["id"] != request["id"]
        or not isinstance(response["result"], Mapping)
    ):
        raise ProofVerificationError(f"install {method} response is invalid")
    return value


def _stored_value(transcript: Mapping[str, Any]) -> Mapping[str, Any]:
    result = transcript["response"]["result"]
    if (
        not isinstance(result, Mapping)
        or set(result) != {
            "api_version",
            "block_header",
            "merkle_proof",
            "stored_value",
        }
        or not isinstance(result["api_version"], str)
        or not result["api_version"]
        or result["block_header"] is not None
        or not isinstance(result["merkle_proof"], str)
        or not result["merkle_proof"]
    ):
        raise ProofVerificationError("install state query result shape is invalid")
    value = result.get("stored_value")
    if not isinstance(value, Mapping):
        raise ProofVerificationError("install state query lacks stored_value")
    return value


def _find_named_key(value: object, name: str) -> str | None:
    if isinstance(value, Mapping):
        if value.get("name") == name and isinstance(value.get("key"), str):
            return str(value["key"])
        for item in value.values():
            found = _find_named_key(item, name)
            if found is not None:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_named_key(item, name)
            if found is not None:
                return found
    return None


def _git_show_blob(commit: str, relpath: str) -> bytes:
    """Read one blob at an exact commit via argv-based git plumbing.

    argv form (never a shell string), rooted at the repository, so a path or
    commit value can never be interpolated into a command line.
    """

    import subprocess

    result = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{commit}:{relpath}"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ProofVerificationError(
            f"historical blob {relpath} is absent at commit {commit[:12]}"
        )
    return result.stdout


def _git_object_is_commit(commit: str) -> bool:
    import subprocess

    result = subprocess.run(
        ["git", "-C", str(ROOT), "cat-file", "-t", commit],
        capture_output=True,
        check=False,
    )
    return (
        result.returncode == 0
        and result.stdout.decode("utf-8", "replace").strip() == "commit"
    )


def verify_release_files_historical(
    manifest: Mapping[str, Any], *, source_commit: str
) -> None:
    """Historical verification (SEC/test-contract split).

    The frozen manifest pins (source, wasm, schema) are the immutable truth;
    this confirms them against the blobs AT the proof's declared build commit
    rather than the live worktree.  The expected commit is NOT caller-chosen:
    it is the finalized proof deployment's ``source_commit`` (validated as a
    full commit SHA by the caller).  A forger would need a real git commit
    whose blobs all hash to the frozen pins — which only the true historical
    commit satisfies.  Strict release-worktree verification stays a separate,
    unchanged function (:func:`_verify_release_files`).
    """

    if _COMMIT.fullmatch(source_commit) is None or not _git_object_is_commit(
        source_commit
    ):
        raise ProofVerificationError(
            "historical source commit is not a full, existing commit object"
        )
    local_template = json.loads(
        (V3_ROOT / "deployment.manifest.json").read_text(encoding="utf-8")
    )
    for field in ("schema_id", "network", "package_key_name", "contract_name", "toolchain", "abi"):
        _same(f"deployment {field}", manifest.get(field), local_template.get(field))
    build = manifest.get("build")
    if not isinstance(build, Mapping) or set(build) != set(local_template["build"]):
        raise ProofVerificationError("deployment build identity is invalid")
    for field in ("command", "schema_command", "wasm_path", "schema_path"):
        if build[field] != local_template["build"][field]:
            raise ProofVerificationError(f"deployment build {field} is not frozen")
    crate_rel = "contracts/odra-governance-receipt-v3"
    # Wasm + schema are COMMITTED at the historical commit, so git-show is a
    # legitimate provenance source for them here.
    for label, path_key, hash_key in (
        ("wasm", "wasm_path", "wasm_sha256"),
        ("schema", "schema_path", "schema_sha256"),
    ):
        relative = build[path_key]
        blob = _git_show_blob(source_commit, f"{crate_rel}/{relative}")
        if hashlib.sha256(blob).hexdigest() != build[hash_key]:
            raise ProofVerificationError(
                f"deployment {label} hash differs from historical commit blob"
            )
    if len(_git_show_blob(source_commit, f"{crate_rel}/{build['wasm_path']}")) != (
        build["wasm_size_bytes"]
    ):
        raise ProofVerificationError("deployment Wasm size differs at historical commit")
    source = manifest.get("source")
    expected_sources = {
        "lib_rs_sha256": "src/lib.rs",
        "encoding_rs_sha256": "src/encoding.rs",
        "cargo_lock_sha256": "Cargo.lock",
    }
    if not isinstance(source, Mapping) or set(source) != set(expected_sources):
        raise ProofVerificationError("deployment source identity is invalid")
    for field, relative in expected_sources.items():
        blob = _git_show_blob(source_commit, f"{crate_rel}/{relative}")
        if hashlib.sha256(blob).hexdigest() != source[field]:
            raise ProofVerificationError(
                f"deployment source hash differs for {field} at historical commit"
            )
    _verify_historical_isolation(manifest)


def _verify_historical_isolation(manifest: Mapping[str, Any]) -> None:
    historical = manifest.get("historical_isolation")
    inventory = ROOT / "handoff/HISTORICAL_ODRA_SHA256.txt"
    if (
        not isinstance(historical, Mapping)
        or historical.get("tracked_file_count") != 18
        or historical.get("pre_post_diff") != "empty"
        or historical.get("manifest_sha256") != hashlib.sha256(inventory.read_bytes()).hexdigest()
    ):
        raise ProofVerificationError("deployment historical-isolation evidence is invalid")


def _verify_release_files(manifest: Mapping[str, Any]) -> None:
    local_template = json.loads((V3_ROOT / "deployment.manifest.json").read_text(encoding="utf-8"))
    for field in ("schema_id", "network", "package_key_name", "contract_name", "toolchain", "abi"):
        _same(f"deployment {field}", manifest.get(field), local_template.get(field))
    locked = manifest.get("locked_install")
    if locked != {
        "odra_cfg_allow_key_override": False,
        "odra_cfg_is_upgradable": False,
        "odra_cfg_is_upgrade": False,
    }:
        raise ProofVerificationError("deployment locked-install flags are not exact")
    build = manifest.get("build")
    if not isinstance(build, Mapping) or set(build) != set(local_template["build"]):
        raise ProofVerificationError("deployment build identity is invalid")
    for field in ("command", "schema_command", "wasm_path", "schema_path"):
        if build[field] != local_template["build"][field]:
            raise ProofVerificationError(f"deployment build {field} is not frozen")
    build_paths = {
        "wasm": (build["wasm_path"], build["wasm_sha256"]),
        "schema": (build["schema_path"], build["schema_sha256"]),
    }
    for label, (relative, expected_hash) in build_paths.items():
        if not isinstance(relative, str) or not isinstance(expected_hash, str):
            raise ProofVerificationError(f"deployment {label} identity is invalid")
        path = V3_ROOT / relative
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
            raise ProofVerificationError(f"deployment {label} hash differs from release file")
    if (V3_ROOT / str(build["wasm_path"])).stat().st_size != build["wasm_size_bytes"]:
        raise ProofVerificationError("deployment Wasm size differs from release file")
    source = manifest.get("source")
    expected_sources = {
        "lib_rs_sha256": V3_ROOT / "src/lib.rs",
        "encoding_rs_sha256": V3_ROOT / "src/encoding.rs",
        "cargo_lock_sha256": V3_ROOT / "Cargo.lock",
    }
    if not isinstance(source, Mapping) or set(source) != set(expected_sources):
        raise ProofVerificationError("deployment source identity is invalid")
    for field, path in expected_sources.items():
        if hashlib.sha256(path.read_bytes()).hexdigest() != source[field]:
            raise ProofVerificationError(f"deployment source hash differs for {field}")
    historical = manifest.get("historical_isolation")
    inventory = ROOT / "handoff/HISTORICAL_ODRA_SHA256.txt"
    if (
        not isinstance(historical, Mapping)
        or historical.get("tracked_file_count") != 18
        or historical.get("pre_post_diff") != "empty"
        or historical.get("manifest_sha256") != hashlib.sha256(inventory.read_bytes()).hexdigest()
    ):
        raise ProofVerificationError("deployment historical-isolation evidence is invalid")


def _verify_deployment_manifest(value: object) -> dict[str, Any]:
    template = json.loads(
        (V3_ROOT / "deployment.manifest.json").read_text(encoding="utf-8")
    )
    template_keys = set(template)
    expected_keys = template_keys | {
        "installer_public_key",
        "installer_account_hash",
        "threshold",
        "install_payment_motes",
        "install_ttl",
        "finality",
        "verified_install_deploy",
        "two_node_finality",
        "raw_rpc",
    }
    if isinstance(value, Mapping) and "two_node_finality" not in value:
        raise ProofVerificationError("deployment two-node finality is required")
    if not isinstance(value, Mapping) or set(value) != expected_keys:
        raise ProofVerificationError("deployment manifest field set is not finalized/frozen")
    if value["status"] != "finalized" or value["network"] != "casper-test":
        raise ProofVerificationError("deployment manifest is not finalized on casper-test")
    # Split-API (Codex security correction): the finalized proof declares the
    # exact commit it was built at; the frozen manifest pins are verified
    # against the blobs AT THAT COMMIT via argv git plumbing, so a proof stays
    # verifiable on any branch whose live worktree has legitimately evolved.
    # The strict live-worktree verifier (`_verify_release_files`) remains a
    # SEPARATE release-gate function, unchanged.
    if not isinstance(value["source_commit"], str) or _COMMIT.fullmatch(value["source_commit"]) is None:
        raise ProofVerificationError("deployment source_commit is invalid")
    if not isinstance(value["deployment_commit"], str) or _COMMIT.fullmatch(value["deployment_commit"]) is None:
        raise ProofVerificationError("deployment deployment_commit is invalid")
    verify_release_files_historical(value, source_commit=value["source_commit"])
    package_hash = _lower_hash(value["package_hash"], "deployment package hash")
    contract_hash = _lower_hash(value["contract_hash"], "deployment contract hash")
    if value["contract_version"] != 1:
        raise ProofVerificationError("deployment contract version must be exactly 1")
    nonce = _lower_hash(value["installation_nonce"], "deployment installation nonce")
    expected_domain = deployment_domain_record(nonce)["deployment_domain"]
    if value["deployment_domain"] != expected_domain:
        raise ProofVerificationError("deployment domain does not derive from installation nonce")
    roles = value["roles"]
    role_names = ("proposer", "finalizer", "signer_a", "signer_b", "signer_c")
    if not isinstance(roles, Mapping) or set(roles) != set(role_names):
        raise ProofVerificationError("deployment role set is invalid")
    ordered_roles: dict[str, str] = {}
    for name in role_names:
        role = roles[name]
        if not isinstance(role, Mapping) or set(role) != {"kind", "account_hash"} or role["kind"] != "Account":
            raise ProofVerificationError("deployment role is not account-only")
        ordered_roles[name] = _lower_hash(role["account_hash"], f"deployment {name}")
    if len(set(ordered_roles.values())) != 5 or "00" * 32 in ordered_roles.values():
        raise ProofVerificationError("deployment governance roles are not nonzero/pairwise distinct")
    threshold = value["threshold"]
    if threshold != 2:
        raise ProofVerificationError("deployment threshold must be exactly 2")
    installer_hash = _lower_hash(value["installer_account_hash"], "deployment installer")
    if installer_hash in ordered_roles.values():
        raise ProofVerificationError("deployment installer collides with governance role")

    raw = value["raw_rpc"]
    if not isinstance(raw, Mapping) or set(raw) != {
        "broadcast_response",
        "install_deploy",
        "state_root",
        "installer_account",
        "package",
        "contract",
    }:
        raise ProofVerificationError("deployment raw RPC evidence is incomplete")
    broadcast = raw["broadcast_response"]
    broadcast_is_exact = (
        isinstance(broadcast, Mapping)
        and set(broadcast) == {"jsonrpc", "id", "result"}
        and broadcast["jsonrpc"] == "2.0"
        and broadcast["id"] == "concordia-v3-install"
        and isinstance(broadcast["result"], Mapping)
        and set(broadcast["result"]) == {"api_version", "deploy_hash"}
        and isinstance(broadcast["result"]["api_version"], str)
        and bool(broadcast["result"]["api_version"])
        and broadcast["result"].get("deploy_hash", "").lower()
        == str(value["install_deploy_hash"]).lower()
    )
    broadcast_was_reconciled = (
        isinstance(broadcast, Mapping)
        and broadcast
        == {
            "status": "response_lost_reconciled_by_hash",
            "deploy_hash": value["install_deploy_hash"],
        }
    )
    if not broadcast_is_exact and not broadcast_was_reconciled:
        raise ProofVerificationError("deployment broadcast evidence is invalid")
    install = _install_rpc(raw["install_deploy"], method="info_get_deploy")
    if install["request"]["params"] != {"deploy_hash": value["install_deploy_hash"]}:
        raise ProofVerificationError("deployment finality query targets another deploy")
    try:
        install_facts = _validate_successful_install_rpc(install, value)
    except (InstallValidationError, KeyError, TypeError) as exc:
        raise ProofVerificationError(f"deployment install deploy is invalid: {exc}") from exc
    if value["verified_install_deploy"] != install_facts:
        raise ProofVerificationError("deployment persisted install facts differ from raw deploy")
    if (
        install_facts["block_hash"] != _lower_hash(value["install_block_hash"], "install block hash")
        or install_facts["block_height"] != value["install_block_height"]
    ):
        raise ProofVerificationError("deployment install execution block mismatch")
    finality = value["finality"]
    if not isinstance(finality, Mapping) or finality != {
        "status": "finalized",
        "success": True,
        "block_hash": install_facts["block_hash"],
        "block_height": install_facts["block_height"],
        "deploy_hash": install_facts["deploy_hash"],
    }:
        raise ProofVerificationError("deployment finality summary differs from raw node evidence")
    raw_two_node = value["two_node_finality"]
    expected_two_node_fields = {
        "status",
        "block_hash",
        "block_height",
        "state_root_hash",
        "block_timestamp",
        "finalized_at",
        "observed_at",
        "deploy_hash",
        "corroboration_count",
        "success",
        "user_error",
        "node_observations",
        "endpoint_identities",
    }
    if (
        not isinstance(raw_two_node, Mapping)
        or set(raw_two_node) != expected_two_node_fields
        or not isinstance(raw_two_node["node_observations"], list)
        or len(raw_two_node["node_observations"]) != 2
        or any(
            not isinstance(observation, Mapping)
            for observation in raw_two_node["node_observations"]
        )
    ):
        raise ProofVerificationError("deployment two-node finality is invalid")
    try:
        two_node = verify_two_node_deploy_finality(
            raw_two_node["node_observations"],
            deploy_hash=install_facts["deploy_hash"],
        )
    except InstallValidationError as exc:
        raise ProofVerificationError(
            "deployment two-node finality is invalid"
        ) from exc
    derived_two_node_fields = {
        "block_hash",
        "block_height",
        "state_root_hash",
        "block_timestamp",
        "finalized_at",
        "deploy_hash",
        "corroboration_count",
        "success",
        "user_error",
        "endpoint_identities",
    }
    if (
        raw_two_node["status"] != "finalized"
        or any(
            raw_two_node[field] != two_node[field]
            for field in derived_two_node_fields
        )
        or two_node["block_hash"] != install_facts["block_hash"]
        or two_node["block_height"] != install_facts["block_height"]
        or two_node["state_root_hash"] != value["install_state_root_hash"]
    ):
        raise ProofVerificationError(
            "deployment two-node finality summary differs from raw evidence"
        )
    finalized_time = _utc_timestamp(
        raw_two_node["finalized_at"], "deployment two-node finality finalized_at"
    )
    observed_time = _utc_timestamp(
        raw_two_node["observed_at"], "deployment two-node finality observed_at"
    )
    if observed_time < finalized_time:
        raise ProofVerificationError(
            "deployment two-node finality observation predates finalization"
        )

    state_root = _install_rpc(raw["state_root"], method="chain_get_state_root_hash")
    if state_root["request"]["params"] != {"block_identifier": {"Hash": value["install_block_hash"]}}:
        raise ProofVerificationError("deployment state-root query is not block pinned")
    state_root_result = state_root["response"]["result"]
    if (
        set(state_root_result) != {"api_version", "state_root_hash"}
        or not isinstance(state_root_result["api_version"], str)
        or not state_root_result["api_version"]
        or state_root_result.get("state_root_hash") != value["install_state_root_hash"]
    ):
        raise ProofVerificationError("deployment state root differs from raw RPC")
    state_identifier = {"StateRootHash": value["install_state_root_hash"]}
    account = _install_rpc(raw["installer_account"], method="query_global_state")
    if account["request"]["params"] != {
        "state_identifier": state_identifier,
        "key": "account-hash-" + installer_hash,
        "path": [],
    }:
        raise ProofVerificationError("deployment installer query is not exact/state-pinned")
    named_key = _find_named_key(_stored_value(account), str(value["package_key_name"]))
    if not isinstance(named_key, str) or named_key.removeprefix("hash-").lower() != package_hash:
        raise ProofVerificationError("deployment installer named key differs from package")
    package = _install_rpc(raw["package"], method="query_global_state")
    if package["request"]["params"] != {
        "state_identifier": state_identifier,
        "key": "hash-" + package_hash,
        "path": [],
    }:
        raise ProofVerificationError("deployment package query is not exact/state-pinned")
    try:
        version, queried_contract = _resolve_locked_contract(_stored_value(package))
    except InstallValidationError as exc:
        raise ProofVerificationError(f"deployment package lock evidence is invalid: {exc}") from exc
    if version != 1 or queried_contract != contract_hash:
        raise ProofVerificationError("deployment package version/contract mismatch")
    contract = _install_rpc(raw["contract"], method="query_global_state")
    if contract["request"]["params"] != {
        "state_identifier": state_identifier,
        "key": "hash-" + contract_hash,
        "path": [],
    }:
        raise ProofVerificationError("deployment contract query is not exact/state-pinned")
    contract_record = _stored_value(contract).get("Contract")
    package_owner = contract_record.get("contract_package_hash") if isinstance(contract_record, Mapping) else None
    if not isinstance(package_owner, str) or package_owner.removeprefix("contract-package-").lower() != package_hash:
        raise ProofVerificationError("deployment exact contract does not belong to package")
    return {
        "package_hash": package_hash,
        "contract_hash": contract_hash,
        "deployment_domain": expected_domain,
        "threshold": threshold,
        "roles": ordered_roles,
        "install_deploy_hash": install_facts["deploy_hash"],
        "install_block_hash": install_facts["block_hash"],
        "install_block_height": install_facts["block_height"],
        "install_observed_at": raw_two_node["observed_at"],
    }


def _lower_hash(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ProofVerificationError(f"{field} must be a 32-byte hash")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ProofVerificationError(f"{field} must be hexadecimal") from exc
    return value.lower()


def _normalize_deploy_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _normalize_deploy_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize_deploy_json(item) for item in value]
    if isinstance(value, str) and len(value) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", value):
        return value.lower()
    return value


def _validated_deploy(
    value: object,
    *,
    expected_hash: str,
    expected_public_key: str,
) -> tuple[Deploy, bytes]:
    if not isinstance(value, Mapping) or set(value) != {
        "approvals",
        "hash",
        "header",
        "payment",
        "session",
    }:
        raise ProofVerificationError("deploy JSON field set is invalid")
    try:
        deploy = serializer.from_json(dict(value), Deploy)
        canonical = serializer.to_bytes(deploy)
        canonical_json = serializer.to_json(deploy)
        body_hash = create_digest_of_deploy_body(deploy.payment, deploy.session)
        deploy_hash = create_digest_of_deploy(deploy.header)
    except Exception as exc:
        raise ProofVerificationError("deploy JSON cannot be decoded canonically") from exc
    if _normalize_deploy_json(canonical_json) != _normalize_deploy_json(value):
        raise ProofVerificationError("deploy JSON parsed fields disagree with canonical CLValue bytes")
    if deploy.header.body_hash != body_hash:
        raise ProofVerificationError("deploy body hash does not match payment/session bytes")
    if deploy.hash != deploy_hash:
        raise ProofVerificationError("deploy hash does not match header bytes")
    if deploy_hash.hex() != _lower_hash(expected_hash, "expected deploy hash"):
        raise ProofVerificationError("recomputed deploy hash differs from step hash")
    if deploy.header.chain_name != "casper-test":
        raise ProofVerificationError("deploy chain must be exactly casper-test")
    expected_public = expected_public_key.lower()
    if deploy.header.account.account_key.hex() != expected_public:
        raise ProofVerificationError("deploy initiator differs from configured role")
    if len(deploy.approvals) != 1:
        raise ProofVerificationError("deploy must carry exactly one role approval")
    approval = deploy.approvals[0]
    signer = getattr(approval.signer, "account_key", None)
    if not isinstance(signer, bytes) or signer.hex() != expected_public:
        raise ProofVerificationError("deploy approval signer differs from configured role")
    try:
        valid = crypto.verify_deploy_approval_signature(
            deploy_hash,
            approval.signature,
            signer,
        )
    except Exception as exc:
        raise ProofVerificationError("deploy approval signature is invalid") from exc
    if not valid:
        raise ProofVerificationError("deploy approval signature is invalid")
    return deploy, canonical


def _finality_outcome(
    transcript: object,
    *,
    deploy_hash: str,
    recorded_deploy: Mapping[str, Any],
    expected_public_key: str,
) -> dict[str, Any]:
    value = _verified_transcript(transcript, method="info_get_deploy")
    if value["params"] != {"deploy_hash": deploy_hash}:
        raise ProofVerificationError("finality query is not pinned to the exact deploy hash")
    result = value["response"]["result"]
    if not isinstance(result, Mapping) or set(result) != {
        "api_version",
        "deploy",
        "execution_info",
    }:
        raise ProofVerificationError("finality result is not the exact Casper v2 deploy shape")
    if not isinstance(result["api_version"], str) or not result["api_version"]:
        raise ProofVerificationError("finality result lacks api_version")
    _, recorded_bytes = _validated_deploy(
        recorded_deploy,
        expected_hash=deploy_hash,
        expected_public_key=expected_public_key,
    )
    _, returned_bytes = _validated_deploy(
        result["deploy"],
        expected_hash=deploy_hash,
        expected_public_key=expected_public_key,
    )
    if not hmac.compare_digest(recorded_bytes, returned_bytes):
        raise ProofVerificationError("node-returned deploy differs from the broadcast deploy")
    execution_info = result["execution_info"]
    if not isinstance(execution_info, Mapping) or set(execution_info) != {
        "block_hash",
        "block_height",
        "execution_result",
    }:
        raise ProofVerificationError("execution_info field set is invalid")
    block_hash = _lower_hash(execution_info["block_hash"], "execution block hash")
    if block_hash == "00" * 32:
        raise ProofVerificationError("execution block hash cannot be zero")
    if (
        type(execution_info["block_height"]) is not int
        or not 0 <= execution_info["block_height"] < 1 << 64
    ):
        raise ProofVerificationError("execution block height is invalid")
    execution_result = execution_info["execution_result"]
    if not isinstance(execution_result, Mapping) or set(execution_result) != {"Version2"}:
        raise ProofVerificationError("execution result must contain exactly Version2")
    versioned = execution_result["Version2"]
    expected_fields = {
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
    }
    if not isinstance(versioned, Mapping) or set(versioned) != expected_fields:
        raise ProofVerificationError("Version2 execution result field set is invalid")
    if versioned["initiator"] != {"PublicKey": expected_public_key.lower()}:
        raise ProofVerificationError("execution initiator differs from configured role")
    if any(not isinstance(versioned[name], str) or not versioned[name].isdigit() for name in ("limit", "consumed", "cost", "refund")):
        raise ProofVerificationError("execution accounting fields are invalid")
    if type(versioned["current_price"]) is not int or type(versioned["size_estimate"]) is not int:
        raise ProofVerificationError("execution numeric metadata is invalid")
    if not isinstance(versioned["transfers"], list) or not isinstance(versioned["effects"], list):
        raise ProofVerificationError("execution transfers/effects must be lists")
    error_message = versioned["error_message"]
    if error_message is not None:
        if not isinstance(error_message, str):
            raise ProofVerificationError("execution error_message must be text or null")
        match = _USER_ERROR.search(error_message)
        return {
            "success": False,
            "user_error": int(match.group(1)) if match else None,
            "block_hash": block_hash,
            "block_height": execution_info["block_height"],
        }
    return {
        "success": True,
        "user_error": None,
        "block_hash": block_hash,
        "block_height": execution_info["block_height"],
    }


def _session(deploy: object, *, contract_hash: str, entry_point: str) -> list[list[Any]]:
    if not isinstance(deploy, Mapping) or not isinstance(deploy.get("hash"), str):
        raise ProofVerificationError("step deploy is invalid")
    header = deploy.get("header")
    if not isinstance(header, Mapping) or header.get("chain_name") != "casper-test":
        raise ProofVerificationError("step deploy is not on casper-test")
    session = deploy.get("session")
    stored = session.get("StoredContractByHash") if isinstance(session, Mapping) else None
    if not isinstance(stored, Mapping):
        raise ProofVerificationError("step must call the exact contract hash, not a moving package version")
    returned_hash = stored.get("hash")
    if not isinstance(returned_hash, str) or returned_hash.lower() != contract_hash.lower():
        raise ProofVerificationError("step deploy targets another contract")
    if stored.get("entry_point") != entry_point:
        raise ProofVerificationError("step entry point disagrees with deploy")
    args = stored.get("args")
    if not isinstance(args, list):
        raise ProofVerificationError("step runtime args are missing")
    normalized: list[list[Any]] = []
    for item in args:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise ProofVerificationError("step runtime argument shape is invalid")
        normalized.append([item[0], item[1]])
    return normalized


def _simple_args(proposal_id: str, envelope_hash: str) -> list[list[Any]]:
    return [
        ["proposal_id", serializer.to_json(CLV_String(proposal_id))],
        ["envelope_hash", serializer.to_json(CLV_ByteArray(bytes.fromhex(envelope_hash)))],
    ]


def _prepared_args(prepared: Mapping[str, Any], *, mutated: bool = False) -> list[list[Any]]:
    values = [[item["name"], {key: copy.deepcopy(item[key]) for key in ("cl_type", "bytes", "parsed")}] for item in prepared["runtime_args"]]
    if mutated:
        for item in values:
            if item[0] == "approved_allocation_bps":
                current = item[1].get("parsed")
                item[1] = serializer.to_json(
                    CLV_U32(2999 if current == 3000 else 3000)
                )
                break
    return values


def _verify_live_run(
    run: object,
    prepared: Mapping[str, Any],
    readback_artifact: object,
    *,
    install_block_height: int,
) -> dict[str, Any]:
    if not isinstance(run, Mapping) or run.get("schema_id") != "concordia.v3-live-proof-run.v1":
        raise ProofVerificationError("live contract run is missing")
    if run.get("status") != "contract_sequence_verified" or run.get("network") != "casper-test":
        raise ProofVerificationError("live contract run is not complete")
    _same("run prepared envelope", run.get("prepared"), prepared)
    _same("run readback", run.get("readback"), readback_artifact)
    contract_hash = run.get("contract_hash")
    package_hash = run.get("package_hash")
    if not isinstance(contract_hash, str) or len(contract_hash) != 64:
        raise ProofVerificationError("run exact contract hash is invalid")
    if not isinstance(package_hash, str) or len(package_hash) != 64:
        raise ProofVerificationError("run package hash is invalid")
    roles = run.get("role_accounts")
    expected_roles = {"proposer", "finalizer", "signer_a", "signer_b", "signer_c"}
    if not isinstance(roles, Mapping) or set(roles) != expected_roles:
        raise ProofVerificationError("run role-account evidence is incomplete")
    account_hashes = []
    for role in expected_roles:
        item = roles[role]
        if not isinstance(item, Mapping) or set(item) != {"custody", "public_key", "account_hash"}:
            raise ProofVerificationError("run role-account record is invalid")
        if item["custody"] not in ("browser", "server"):
            raise ProofVerificationError("run role custody is invalid")
        try:
            account_key = bytes.fromhex(item["public_key"])
            public_key = create_public_key_from_account_key(account_key)
        except (TypeError, ValueError) as exc:
            raise ProofVerificationError("run role public key is invalid") from exc
        account_hash = public_key.to_account_hash().hex()
        if item["account_hash"] != account_hash:
            raise ProofVerificationError("run role account hash is not derived from its public key")
        account_hashes.append(account_hash)
    if len(set(account_hashes)) != 5:
        raise ProofVerificationError("run governance roles are not pairwise distinct")

    expected_steps = [
        ("propose_exact", "proposer", "propose_envelope", "success", None, _simple_args(prepared["proposal_id"], prepared["envelope_hash"])),
        ("finalize_pre_quorum", "finalizer", prepared["entry_point"], None, 8, _prepared_args(prepared)),
        ("approve_a", "signer_a", "approve_envelope", "success", None, _simple_args(prepared["proposal_id"], prepared["envelope_hash"])),
        ("approve_b", "signer_b", "approve_envelope", "success", None, _simple_args(prepared["proposal_id"], prepared["envelope_hash"])),
        ("finalize_mutated_3000_bps", "finalizer", prepared["entry_point"], None, 10, _prepared_args(prepared, mutated=True)),
        ("finalize_exact", "finalizer", prepared["entry_point"], "success", None, _prepared_args(prepared)),
        ("finalize_again", "finalizer", prepared["entry_point"], None, 12, _prepared_args(prepared)),
    ]
    steps = run.get("steps")
    if not isinstance(steps, list) or len(steps) != len(expected_steps):
        raise ProofVerificationError("run must contain exactly seven ordered contract steps")
    outcomes: dict[str, Any] = {}
    previous_block_height = install_block_height
    previous_block_hash: str | None = None
    previous_observed_time: datetime | None = None
    for record, expected in zip(steps, expected_steps, strict=True):
        name, role, entry_point, success_label, error_code, expected_args = expected
        required = {
            "name", "role", "custody", "entry_point", "expected", "expected_error",
            "deploy_hash", "deploy", "finality_transcript", "observed_outcome",
        }
        durable_required = required | {
            "submission_state",
            "finality_block_evidence",
        }
        accepted_broadcast = durable_required | {"broadcast_transcript"}
        reconciled_broadcast = durable_required | {"broadcast_evidence"}
        if not isinstance(record, Mapping) or set(record) not in (
            accepted_broadcast,
            reconciled_broadcast,
        ):
            raise ProofVerificationError(f"{name}: step record shape is invalid")
        if (record["name"], record["role"], record["entry_point"], record["expected"], record["expected_error"]) != (name, role, entry_point, success_label, error_code):
            raise ProofVerificationError(f"{name}: asserted choreography differs from frozen sequence")
        deploy = record["deploy"]
        deploy_hash = record["deploy_hash"]
        if not isinstance(deploy_hash, str) or not isinstance(deploy, Mapping):
            raise ProofVerificationError(f"{name}: deploy hash record mismatch")
        _validated_deploy(
            deploy,
            expected_hash=deploy_hash,
            expected_public_key=str(roles[role]["public_key"]),
        )
        if _session(deploy, contract_hash=contract_hash, entry_point=entry_point) != expected_args:
            raise ProofVerificationError(f"{name}: deploy runtime args differ from frozen choreography")
        if "broadcast_transcript" in record:
            broadcast = _verified_transcript(
                record["broadcast_transcript"], method="account_put_deploy"
            )
            if broadcast["params"] != {"deploy": deploy}:
                raise ProofVerificationError(
                    f"{name}: broadcast request differs from recorded deploy"
                )
            broadcast_result = broadcast["response"]["result"]
            if not isinstance(broadcast_result, Mapping) or set(broadcast_result) != {
                "api_version",
                "deploy_hash",
            }:
                raise ProofVerificationError(f"{name}: broadcast response shape is invalid")
            returned_hash = broadcast_result["deploy_hash"]
            if (
                not isinstance(returned_hash, str)
                or returned_hash.lower() != deploy_hash.lower()
            ):
                raise ProofVerificationError(f"{name}: broadcast response hash mismatch")
        elif record["broadcast_evidence"] != {
            "status": "response_lost_reconciled_by_hash",
            "deploy_hash": deploy_hash.lower(),
        }:
            raise ProofVerificationError(
                f"{name}: ambiguous broadcast evidence is invalid"
            )
        outcome = _finality_outcome(
            record["finality_transcript"],
            deploy_hash=deploy_hash,
            recorded_deploy=deploy,
            expected_public_key=str(roles[role]["public_key"]),
        )
        if record["submission_state"] != "finalized":
            raise ProofVerificationError(
                f"{name}: durable submission state is not finalized"
            )
        block_evidence = record["finality_block_evidence"]
        expected_block_fields = {
            "status",
            "block_hash",
            "block_height",
            "state_root_hash",
            "block_timestamp",
            "finalized_at",
            "observed_at",
            "deploy_hash",
            "corroboration_count",
            "success",
            "user_error",
            "node_observations",
            "endpoint_identities",
        }
        if not isinstance(block_evidence, Mapping) or set(block_evidence) != expected_block_fields:
            raise ProofVerificationError(
                f"{name}: two-node block evidence is invalid"
            )
        try:
            corroborated = verify_two_node_deploy_finality(
                block_evidence["node_observations"],
                deploy_hash=deploy_hash,
                expected_user_error=error_code,
            )
        except InstallValidationError as exc:
            raise ProofVerificationError(
                f"{name}: two-node block evidence is invalid"
            ) from exc
        derived_fields = {
            "block_hash",
            "block_height",
            "state_root_hash",
            "block_timestamp",
            "deploy_hash",
            "corroboration_count",
            "success",
            "user_error",
            "endpoint_identities",
        }
        if (
            block_evidence["status"] != "finalized"
            or any(block_evidence[field] != corroborated[field] for field in derived_fields)
            or block_evidence["finalized_at"] != corroborated["block_timestamp"]
            or corroborated["block_hash"] != outcome["block_hash"]
            or corroborated["block_height"] != outcome["block_height"]
        ):
            raise ProofVerificationError(
                f"{name}: two-node block evidence disagrees with raw finality"
            )
        finalized_time = _utc_timestamp(
            block_evidence["finalized_at"], f"{name} finalized_at"
        )
        observed_time = _utc_timestamp(
            block_evidence["observed_at"], f"{name} observed_at"
        )
        if observed_time < finalized_time:
            raise ProofVerificationError(
                f"{name}: finality observation predates canonical finalization"
            )
        if previous_observed_time is not None and observed_time < previous_observed_time:
            raise ProofVerificationError(
                f"{name}: finality observation chronology predates the preceding step"
            )
        previous_observed_time = observed_time
        outcome["finalized_at"] = block_evidence["finalized_at"]
        outcome["observed_at"] = block_evidence["observed_at"]
        observed_result = {
            "success": outcome["success"],
            "user_error": outcome["user_error"],
        }
        if error_code is None and observed_result != {"success": True, "user_error": None}:
            raise ProofVerificationError(f"{name}: raw finality is not successful")
        if error_code is not None and observed_result != {"success": False, "user_error": error_code}:
            raise ProofVerificationError(f"{name}: raw finality does not prove User error {error_code}")
        if outcome["block_height"] <= install_block_height:
            raise ProofVerificationError(
                f"{name}: contract step must follow contract installation"
            )
        if outcome["block_height"] < previous_block_height:
            raise ProofVerificationError(
                f"{name}: finality block height predates the preceding contract step"
            )
        if (
            outcome["block_height"] == previous_block_height
            and previous_block_hash is not None
            and not hmac.compare_digest(outcome["block_hash"], previous_block_hash)
        ):
            raise ProofVerificationError(
                f"{name}: consecutive finality observations claim the same height on different blocks"
            )
        previous_block_height = outcome["block_height"]
        previous_block_hash = outcome["block_hash"]
        outcomes[name] = outcome
    return {
        "package_hash": package_hash,
        "contract_hash": contract_hash,
        "roles": {name: str(roles[name]["account_hash"]) for name in expected_roles},
        "outcomes": outcomes,
    }


def verify_v3_proof_document(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_id",
        "deployment",
        "input",
        "prepared",
        "run",
        "readback",
    }:
        raise ProofVerificationError("proof must be an object")
    if value.get("schema_id") != "concordia.v3-proof.v1":
        raise ProofVerificationError("unsupported proof schema")
    deployment = _verify_deployment_manifest(value["deployment"])
    try:
        recomputed = prepare_v3_envelope(value["input"])
    except (ValueError, KeyError, TypeError) as exc:
        raise ProofVerificationError(f"typed envelope is invalid: {exc}") from exc
    _same("prepared envelope", value["prepared"], recomputed)
    live_run = _verify_live_run(
        value["run"],
        recomputed,
        value["readback"],
        install_block_height=deployment["install_block_height"],
    )
    first_step = live_run["outcomes"]["propose_exact"]
    if _utc_timestamp(
        deployment["install_observed_at"], "deployment two-node finality observed_at"
    ) > _utc_timestamp(first_step["observed_at"], "propose_exact observed_at"):
        raise ProofVerificationError(
            "deployment two-node finality observation follows the first contract step"
        )
    try:
        readback = validate_verified_readback(
            verify_and_seal_readback_artifact(value["readback"])
        )
    except ValueError as exc:
        raise ProofVerificationError(f"chain readback is invalid: {exc}") from exc

    input_document = value["input"]
    header = input_document.get("header") if isinstance(input_document, Mapping) else None
    if not isinstance(header, Mapping):
        raise ProofVerificationError("typed header is missing")
    expected_action = bytes.fromhex(recomputed["action_id"])
    expected_envelope = bytes.fromhex(recomputed["envelope_hash"])
    expected_domain = bytes.fromhex(str(header["deployment_domain"]))
    _same("readback proposal_id", readback.proposal_id, header["proposal_id"])
    _same("readback action_id", readback.action_id, expected_action)
    _same("readback proposed_envelope", readback.proposed_envelope, expected_envelope)
    _same("readback finalized_envelope", readback.finalized_envelope, expected_envelope)
    _same("readback deployment_domain", readback.deployment_domain, expected_domain)
    if readback.finalized is not True or readback.action_authorized is not True:
        raise ProofVerificationError("on-chain action is not finalized and authorized")
    if readback.approval_count < readback.threshold:
        raise ProofVerificationError("on-chain approval count is below its configured threshold")
    exact_finalization = live_run["outcomes"]["finalize_exact"]
    if readback.observed_block_height < exact_finalization["block_height"]:
        raise ProofVerificationError("state readback predates exact finalization")
    if (
        readback.observed_block_height == exact_finalization["block_height"]
        and not hmac.compare_digest(
            readback.observed_block_hash.hex(), exact_finalization["block_hash"]
        )
    ):
        raise ProofVerificationError(
            "state readback observes a different block at exact finalization height"
        )
    if not hmac.compare_digest(readback.proposed_envelope, readback.finalized_envelope):
        raise ProofVerificationError("proposed/finalized envelope mismatch")
    _same("run package_hash", live_run["package_hash"], readback.package_hash.hex())
    _same("run contract_hash", live_run["contract_hash"], readback.contract_hash.hex())
    _same("deployment package_hash", deployment["package_hash"], readback.package_hash.hex())
    _same("deployment contract_hash", deployment["contract_hash"], readback.contract_hash.hex())
    _same("deployment domain", deployment["deployment_domain"], readback.deployment_domain.hex())
    _same("deployment threshold", deployment["threshold"], readback.threshold)
    expected_readback_roles = {
        "proposer": readback.proposer.hex(),
        "finalizer": readback.finalizer.hex(),
        "signer_a": readback.signers[0].hex(),
        "signer_b": readback.signers[1].hex(),
        "signer_c": readback.signers[2].hex(),
    }
    _same("deployment/readback roles", deployment["roles"], expected_readback_roles)
    _same("run/readback roles", live_run["roles"], expected_readback_roles)
    return {
        "schema_id": "concordia.v3-proof-verification.v1",
        "valid": True,
        "network": readback.network,
        "package_hash": readback.package_hash.hex(),
        "contract_hash": readback.contract_hash.hex(),
        "proposal_id": readback.proposal_id,
        "action_id": recomputed["action_id"],
        "envelope_hash": recomputed["envelope_hash"],
        "observed_block_hash": readback.observed_block_hash.hex(),
        "observed_block_height": readback.observed_block_height,
        "observed_state_root_hash": readback.observed_state_root_hash.hex(),
        "contract_step_outcomes": live_run["outcomes"],
        "install_deploy_hash": deployment["install_deploy_hash"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("proof", type=Path)
    args = parser.parse_args()
    try:
        proof = json.loads(args.proof.read_text(encoding="utf-8"))
        print(json.dumps(verify_v3_proof_document(proof), indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
