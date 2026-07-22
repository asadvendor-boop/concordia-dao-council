#!/usr/bin/env python3
"""Run or prepare the seven contract steps in Concordia's v3 live proof.

Each role may be server-held (a key path) or browser-held (a public key).  The
runner never exports a browser key: it stops at the first manual step and emits
the exact wallet payload plus expected outcome for a later resume.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from pycspr import crypto, serializer
from pycspr.factory.accounts import (
    create_public_key_from_account_key,
    parse_private_key,
    parse_public_key_bytes,
)
from pycspr.factory.deploys import (
    create_deploy,
    create_deploy_parameters,
    create_digest_of_deploy,
    create_digest_of_deploy_body,
    create_standard_payment,
)
from pycspr.types.cl import (
    CLV_ByteArray,
    CLV_String,
    CLV_U256,
    CLV_U32,
    CLV_U512,
    CLV_U64,
    CLV_U8,
)
from pycspr.types.crypto import KeyAlgorithm
from pycspr.types.node.rpc import Deploy, DeployArgument, DeployOfStoredContractByHash

from scripts.prepare_v3_envelope import prepare_v3_envelope
from scripts.install_governance_receipt_v3 import (
    InstallValidationError,
    _safe_rpc_payload,
    build_public_rpc_transport,
    deploy_expiry_epoch,
    reconcile_two_node_deploy,
)
from scripts.read_v3_state import (
    ReadbackValidationError,
    capture_v3_checkpoint_state,
    capture_v3_state,
    verify_checkpoint_state_readback_artifact,
)


class LiveProofError(RuntimeError):
    pass


ERROR_CODE_RE = re.compile(r"(?:User error|ApiError::User)[:( ]+(\d+)")
CHECKPOINT_SCHEMA_ID = "concordia.v3-browser-checkpoint.v1"
CHECKPOINT_READBACK_SCHEMA_ID = "concordia.v3-checkpoint-state-readback.v1"
SIGNATURE_IMPORT_SCHEMA_ID = "concordia.v3-browser-signature-import.v1"


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _normalize_deploy_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _normalize_deploy_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize_deploy_json(item) for item in value]
    if isinstance(value, str) and len(value) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", value):
        return value.lower()
    return value


def _hash32(value: object, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise LiveProofError(f"{field} must be a 32-byte hash")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise LiveProofError(f"{field} must be hexadecimal") from exc
    if raw == bytes(32):
        raise LiveProofError(f"{field} cannot be zero")
    return raw.hex()


def _validate_checkpoint_state_readback(
    value: object,
    *,
    network: str,
    package_hash: str,
    contract_hash: str,
    proposal_id: str,
    action_id: str,
) -> dict[str, Any]:
    try:
        verified = verify_checkpoint_state_readback_artifact(value)
    except ReadbackValidationError as exc:
        raise LiveProofError("checkpoint prior state-readback is invalid") from exc
    if verified["schema_id"] != CHECKPOINT_READBACK_SCHEMA_ID or verified["network"] != network:
        raise LiveProofError("checkpoint prior state-readback schema/network mismatch")
    expected = verified["expected"]
    exact_identities = {
        "package_hash": package_hash,
        "contract_hash": contract_hash,
        "proposal_id": proposal_id,
        "action_id": action_id,
    }
    for field, expected_value in exact_identities.items():
        actual = expected[field]
        if field in {"package_hash", "contract_hash", "action_id"}:
            actual = _hash32(actual, f"checkpoint readback {field}")
            expected_value = _hash32(expected_value, f"expected {field}")
        if actual != expected_value:
            raise LiveProofError(f"checkpoint prior state-readback {field} mismatch")
    facts = verified["facts"]
    _hash32(facts["observed_block_hash"], "checkpoint observed block hash")
    _hash32(facts["observed_state_root_hash"], "checkpoint observed state root")
    if type(facts["observed_block_height"]) is not int or facts["observed_block_height"] < 0:
        raise LiveProofError("checkpoint observed block height is invalid")
    completed = expected["completed_steps"]
    if not isinstance(completed, list):
        raise LiveProofError("checkpoint completed steps must be a list")
    for item in completed:
        if not isinstance(item, Mapping) or set(item) != {
            "name",
            "deploy_hash",
            "finality_transcript_sha256",
        }:
            raise LiveProofError("checkpoint completed-step readback is invalid")
        if not isinstance(item["name"], str) or not item["name"]:
            raise LiveProofError("checkpoint completed-step name is invalid")
        _hash32(item["deploy_hash"], "checkpoint completed deploy hash")
        _hash32(item["finality_transcript_sha256"], "checkpoint finality transcript hash")
    return verified


def _seal_checkpoint(value: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(dict(value))
    result.pop("checkpoint_sha256", None)
    result["checkpoint_sha256"] = hashlib.sha256(_canonical_json(result)).hexdigest()
    return result


def _validate_checkpoint(value: object) -> dict[str, Any]:
    expected = {
        "schema_id",
        "status",
        "run",
        "next_step_index",
        "prior_state_readback",
        "signature_request",
        "consumed_import_deploy_hashes",
        "checkpoint_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise LiveProofError("browser checkpoint field set is invalid")
    sealed = _seal_checkpoint(value)
    if not hmac.compare_digest(str(value["checkpoint_sha256"]), sealed["checkpoint_sha256"]):
        raise LiveProofError("browser checkpoint checksum mismatch")
    if value["schema_id"] != CHECKPOINT_SCHEMA_ID:
        raise LiveProofError("browser checkpoint schema mismatch")
    if value["status"] not in {
        "waiting_for_browser_signature",
        "signed_deploy_staged",
    }:
        raise LiveProofError("browser checkpoint status is invalid")
    run = value["run"]
    if not isinstance(run, Mapping) or run.get("schema_id") != "concordia.v3-live-proof-run.v1":
        raise LiveProofError("browser checkpoint run is invalid")
    if run.get("network") != "casper-test":
        raise LiveProofError("browser checkpoint network must be exactly casper-test")
    package_hash = _hash32(run.get("package_hash"), "checkpoint package hash")
    contract_hash = _hash32(run.get("contract_hash"), "checkpoint contract hash")
    prepared = run.get("prepared")
    if not isinstance(prepared, Mapping):
        raise LiveProofError("browser checkpoint prepared envelope is invalid")
    proposal_id = prepared.get("proposal_id")
    if not isinstance(proposal_id, str) or not proposal_id:
        raise LiveProofError("browser checkpoint proposal id is invalid")
    action_id = _hash32(prepared.get("action_id"), "checkpoint action id")
    prior = _validate_checkpoint_state_readback(
        value["prior_state_readback"],
        network="casper-test",
        package_hash=package_hash,
        contract_hash=contract_hash,
        proposal_id=proposal_id,
        action_id=action_id,
    )
    index = value["next_step_index"]
    steps = run.get("steps")
    if type(index) is not int or not isinstance(steps, list) or not 0 <= index < len(steps):
        raise LiveProofError("browser checkpoint step cursor is invalid")
    step = steps[index]
    if not isinstance(step, Mapping):
        raise LiveProofError("browser checkpoint next step is invalid")
    choreography = _steps(prepared)
    if index >= len(choreography) or len(steps) != index + 1:
        raise LiveProofError("browser checkpoint step prefix is not exact")
    frozen_step = choreography[index]
    if (
        step.get("name"),
        step.get("role"),
        step.get("entry_point"),
        step.get("expected"),
        step.get("expected_error"),
    ) != (
        frozen_step["name"],
        frozen_step["role"],
        frozen_step["entry_point"],
        frozen_step.get("expected"),
        frozen_step.get("expected_error"),
    ):
        raise LiveProofError("browser checkpoint differs from frozen choreography")
    expected_run_status = (
        "waiting_for_browser_signature"
        if value["status"] == "waiting_for_browser_signature"
        else "signed_deploy_staged"
    )
    if run.get("status") != expected_run_status or run.get("next_step") != step.get("name"):
        raise LiveProofError("browser checkpoint run status/cursor mismatch")
    request = value["signature_request"]
    if not isinstance(request, Mapping) or set(request) != {
        "network",
        "package_hash",
        "contract_hash",
        "step_index",
        "step_name",
        "role",
        "public_key",
        "entry_point",
        "unsigned_deploy_hash",
        "runtime_args_sha256",
        "prior_state_readback_sha256",
    }:
        raise LiveProofError("browser checkpoint signature request is invalid")
    role_accounts = run.get("role_accounts")
    role = step.get("role")
    role_account = role_accounts.get(role) if isinstance(role_accounts, Mapping) else None
    deploy_json = step.get("deploy")
    if not isinstance(role_account, Mapping) or role_account.get("custody") != "browser":
        raise LiveProofError("browser checkpoint step is not assigned to browser custody")
    if not isinstance(deploy_json, Mapping):
        raise LiveProofError("browser checkpoint deploy is invalid")
    approvals = deploy_json.get("approvals")
    if value["status"] == "waiting_for_browser_signature" and approvals != []:
        raise LiveProofError("waiting browser checkpoint must contain one unsigned deploy")
    if value["status"] == "signed_deploy_staged" and (
        not isinstance(approvals, list) or len(approvals) != 1
    ):
        raise LiveProofError("staged browser checkpoint must contain one signed deploy")
    session = deploy_json.get("session")
    stored = session.get("StoredContractByHash") if isinstance(session, Mapping) else None
    if not isinstance(stored, Mapping):
        raise LiveProofError("browser checkpoint deploy session is invalid")
    if set(stored) != {"hash", "entry_point", "args"}:
        raise LiveProofError("browser checkpoint stored-contract call shape is invalid")
    if (
        _hash32(stored.get("hash"), "checkpoint session contract hash") != contract_hash
        or stored.get("entry_point") != frozen_step["entry_point"]
        or _normalize_deploy_json(stored.get("args"))
        != _normalize_deploy_json(
            [
                [
                    item["name"],
                    {key: copy.deepcopy(item[key]) for key in ("cl_type", "bytes", "parsed")},
                ]
                for item in frozen_step["args"]
            ]
        )
    ):
        raise LiveProofError("browser checkpoint target/entry point/arguments are not frozen")
    try:
        parsed_deploy = serializer.from_json(dict(deploy_json), Deploy)
        canonical_deploy = serializer.to_json(parsed_deploy)
        body_hash = create_digest_of_deploy_body(
            parsed_deploy.payment,
            parsed_deploy.session,
        )
        deploy_hash = create_digest_of_deploy(parsed_deploy.header)
    except Exception as exc:
        raise LiveProofError("browser checkpoint deploy cannot be decoded canonically") from exc
    if _normalize_deploy_json(canonical_deploy) != _normalize_deploy_json(deploy_json):
        raise LiveProofError("browser checkpoint deploy parsed fields disagree with bytes")
    if (
        parsed_deploy.header.body_hash != body_hash
        or parsed_deploy.hash != deploy_hash
        or parsed_deploy.header.chain_name != "casper-test"
        or deploy_hash.hex() != _hash32(deploy_json.get("hash"), "checkpoint deploy hash")
        or parsed_deploy.header.account.account_key.hex()
        != str(role_account.get("public_key", "")).lower()
    ):
        raise LiveProofError("browser checkpoint deploy hash/network/role mismatch")
    completed = _completed_step_readbacks(run, before_index=index)
    if value["prior_state_readback"]["expected"]["completed_steps"] != completed:
        raise LiveProofError("browser checkpoint prior state does not bind completed run prefix")
    expected_request = {
        "network": "casper-test",
        "package_hash": package_hash,
        "contract_hash": contract_hash,
        "step_index": index,
        "step_name": step.get("name"),
        "role": role,
        "public_key": str(role_account.get("public_key", "")).lower(),
        "entry_point": step.get("entry_point"),
        "unsigned_deploy_hash": _hash32(deploy_json.get("hash"), "unsigned deploy hash"),
        "runtime_args_sha256": hashlib.sha256(_canonical_json(stored.get("args"))).hexdigest(),
        "prior_state_readback_sha256": prior["artifact_sha256"],
    }
    if _normalize_deploy_json(request) != _normalize_deploy_json(expected_request):
        raise LiveProofError("browser checkpoint signature request differs from frozen run")
    consumed = value["consumed_import_deploy_hashes"]
    if not isinstance(consumed, list) or len(set(consumed)) != len(consumed):
        raise LiveProofError("browser checkpoint consumed imports are invalid")
    for deploy_hash in consumed:
        _hash32(deploy_hash, "consumed import deploy hash")
    return copy.deepcopy(dict(value))


def build_browser_checkpoint(
    run_output: Mapping[str, Any],
    *,
    next_step_index: int,
    prior_state_readback: Mapping[str, Any],
) -> dict[str, Any]:
    run = copy.deepcopy(dict(run_output))
    if run.get("status") != "waiting_for_browser_signature":
        raise LiveProofError("checkpoint can only be built at a browser-signature boundary")
    steps = run.get("steps")
    if type(next_step_index) is not int or not isinstance(steps, list) or not 0 <= next_step_index < len(steps):
        raise LiveProofError("checkpoint next step index is invalid")
    step = steps[next_step_index]
    role_accounts = run.get("role_accounts")
    role_account = role_accounts.get(step.get("role")) if isinstance(role_accounts, Mapping) else None
    deploy_json = step.get("deploy") if isinstance(step, Mapping) else None
    session = deploy_json.get("session") if isinstance(deploy_json, Mapping) else None
    stored = session.get("StoredContractByHash") if isinstance(session, Mapping) else None
    if not isinstance(role_account, Mapping) or role_account.get("custody") != "browser":
        raise LiveProofError("checkpoint next role is not browser-held")
    if not isinstance(stored, Mapping) or deploy_json.get("approvals") != []:
        raise LiveProofError("checkpoint next deploy must be one unsigned stored-contract call")
    package_hash = _hash32(run.get("package_hash"), "checkpoint package hash")
    contract_hash = _hash32(run.get("contract_hash"), "checkpoint contract hash")
    prepared = run.get("prepared")
    if not isinstance(prepared, Mapping):
        raise LiveProofError("checkpoint prepared envelope is invalid")
    prior = _validate_checkpoint_state_readback(
        prior_state_readback,
        network="casper-test",
        package_hash=package_hash,
        contract_hash=contract_hash,
        proposal_id=str(prepared.get("proposal_id")),
        action_id=str(prepared.get("action_id")),
    )
    checkpoint = {
        "schema_id": CHECKPOINT_SCHEMA_ID,
        "status": "waiting_for_browser_signature",
        "run": run,
        "next_step_index": next_step_index,
        "prior_state_readback": prior,
        "signature_request": {
            "network": "casper-test",
            "package_hash": package_hash,
            "contract_hash": contract_hash,
            "step_index": next_step_index,
            "step_name": step.get("name"),
            "role": step.get("role"),
            "public_key": str(role_account.get("public_key", "")).lower(),
            "entry_point": step.get("entry_point"),
            "unsigned_deploy_hash": _hash32(deploy_json.get("hash"), "unsigned deploy hash"),
            "runtime_args_sha256": hashlib.sha256(_canonical_json(stored.get("args"))).hexdigest(),
            "prior_state_readback_sha256": prior["artifact_sha256"],
        },
        "consumed_import_deploy_hashes": [],
    }
    sealed = _seal_checkpoint(checkpoint)
    _validate_checkpoint(sealed)
    return sealed


def build_browser_signature_import(
    checkpoint: Mapping[str, Any],
    signed_deploy: Mapping[str, Any],
) -> dict[str, Any]:
    request = checkpoint.get("signature_request")
    if not isinstance(request, Mapping):
        raise LiveProofError("checkpoint lacks a signature request")
    return {
        "schema_id": SIGNATURE_IMPORT_SCHEMA_ID,
        "checkpoint_sha256": checkpoint.get("checkpoint_sha256"),
        "binding": copy.deepcopy(dict(request)),
        "deploy": copy.deepcopy(dict(signed_deploy)),
    }


def validate_and_stage_browser_import(
    checkpoint_value: object,
    imported_value: object,
    *,
    now_seconds: float | None = None,
) -> dict[str, Any]:
    checkpoint = _validate_checkpoint(checkpoint_value)
    if checkpoint["status"] != "waiting_for_browser_signature":
        raise LiveProofError("browser checkpoint is not awaiting a signature")
    if not isinstance(imported_value, Mapping) or set(imported_value) != {
        "schema_id",
        "checkpoint_sha256",
        "binding",
        "deploy",
    }:
        raise LiveProofError("browser signature import field set is invalid")
    if imported_value["schema_id"] != SIGNATURE_IMPORT_SCHEMA_ID:
        raise LiveProofError("browser signature import schema mismatch")
    if not hmac.compare_digest(
        str(imported_value["checkpoint_sha256"]), checkpoint["checkpoint_sha256"]
    ):
        raise LiveProofError("browser signature import belongs to another checkpoint")
    if _normalize_deploy_json(imported_value["binding"]) != _normalize_deploy_json(
        checkpoint["signature_request"]
    ):
        raise LiveProofError("browser signature import binding differs from checkpoint")
    index = checkpoint["next_step_index"]
    unsigned_json = checkpoint["run"]["steps"][index]["deploy"]
    signed_json = imported_value["deploy"]
    if not isinstance(signed_json, Mapping):
        raise LiveProofError("browser signed deploy is not an object")
    try:
        unsigned = serializer.from_json(dict(unsigned_json), Deploy)
        signed = serializer.from_json(dict(signed_json), Deploy)
        canonical_signed = serializer.to_json(signed)
        body_hash = create_digest_of_deploy_body(signed.payment, signed.session)
        deploy_hash = create_digest_of_deploy(signed.header)
    except Exception as exc:
        raise LiveProofError("browser signed deploy cannot be decoded canonically") from exc
    if _normalize_deploy_json(canonical_signed) != _normalize_deploy_json(signed_json):
        raise LiveProofError("browser signed deploy parsed fields disagree with canonical bytes")
    unsigned_without_approvals = serializer.to_json(unsigned)
    signed_without_approvals = copy.deepcopy(canonical_signed)
    unsigned_without_approvals["approvals"] = []
    signed_without_approvals["approvals"] = []
    if _normalize_deploy_json(unsigned_without_approvals) != _normalize_deploy_json(
        signed_without_approvals
    ):
        raise LiveProofError("browser signed deploy differs from the checkpoint payload")
    expected_hash = _hash32(checkpoint["signature_request"]["unsigned_deploy_hash"], "unsigned deploy hash")
    if signed.header.body_hash != body_hash or signed.hash != deploy_hash or deploy_hash.hex() != expected_hash:
        raise LiveProofError("browser signed deploy hash/body differs from checkpoint")
    if signed.header.chain_name != "casper-test":
        raise LiveProofError("browser signed deploy network must be exactly casper-test")
    expected_public_key = str(checkpoint["signature_request"]["public_key"]).lower()
    if signed.header.account.account_key.hex() != expected_public_key:
        raise LiveProofError("browser signed deploy initiator differs from exact role")
    if len(signed.approvals) != 1:
        raise LiveProofError("browser signed deploy requires exactly one role approval")
    approval = signed.approvals[0]
    signer = getattr(approval.signer, "account_key", None)
    if not isinstance(signer, bytes) or signer.hex() != expected_public_key:
        raise LiveProofError("browser signed deploy approval differs from exact role")
    try:
        signature_valid = crypto.verify_deploy_approval_signature(
            deploy_hash,
            approval.signature,
            signer,
        )
    except Exception as exc:
        raise LiveProofError("browser signed deploy signature is invalid") from exc
    if not signature_valid:
        raise LiveProofError("browser signed deploy signature is invalid")
    now = time.time() if now_seconds is None else now_seconds
    expires_at = signed.header.timestamp.value + signed.header.ttl.as_milliseconds / 1000
    if not isinstance(now, (int, float)) or now < signed.header.timestamp.value or now >= expires_at:
        raise LiveProofError("browser signed deploy checkpoint is stale or not yet valid")
    normalized_hash = deploy_hash.hex()
    if normalized_hash in checkpoint["consumed_import_deploy_hashes"]:
        raise LiveProofError("browser signed deploy import was already consumed")
    staged = copy.deepcopy(checkpoint)
    staged["status"] = "signed_deploy_staged"
    staged["run"]["status"] = "signed_deploy_staged"
    staged["run"]["steps"][index]["deploy"] = copy.deepcopy(dict(signed_json))
    staged["run"]["steps"][index]["deploy_hash"] = normalized_hash
    staged["consumed_import_deploy_hashes"].append(normalized_hash)
    return _seal_checkpoint(staged)


def _transcript(*, node_id: str, method: str, params: Mapping[str, Any], request: Mapping[str, Any], response: Mapping[str, Any]) -> dict[str, Any]:
    value: dict[str, Any] = {
        "rpc_url_identity_or_node_id": node_id,
        "method": method,
        "params": dict(params),
        "request": dict(request),
        "response": dict(response),
    }
    value["canonical_sha256"] = hashlib.sha256(
        _canonical_json({"request": request, "response": response})
    ).hexdigest()
    return value


def outcome_from_finality_response(response: Mapping[str, Any]) -> dict[str, Any]:
    if response.get("error") is not None:
        raise LiveProofError("finality RPC returned an error object")
    result = response.get("result")
    if not isinstance(result, Mapping):
        raise LiveProofError("finality RPC lacks a result object")
    if set(result) != {"api_version", "deploy", "execution_info"}:
        raise LiveProofError("finality RPC is not the exact Casper v2 deploy result")
    if not isinstance(result["api_version"], str) or not isinstance(result["deploy"], Mapping):
        raise LiveProofError("finality RPC has invalid api_version/deploy")
    execution_info = result["execution_info"]
    if execution_info is None:
        return {
            "finalized": False,
            "success": None,
            "user_error": None,
            "error_message": None,
            "block_hash": None,
            "block_height": None,
        }
    if not isinstance(execution_info, Mapping) or set(execution_info) != {
        "block_hash",
        "block_height",
        "execution_result",
    }:
        raise LiveProofError("finality execution_info field set is invalid")
    block_hash = execution_info["block_hash"]
    block_height = execution_info["block_height"]
    if not isinstance(block_hash, str) or len(block_hash) != 64:
        raise LiveProofError("finality block hash is invalid")
    try:
        bytes.fromhex(block_hash)
    except ValueError as exc:
        raise LiveProofError("finality block hash is invalid") from exc
    if type(block_height) is not int or block_height < 0:
        raise LiveProofError("finality block height is invalid")
    execution_result = execution_info["execution_result"]
    if not isinstance(execution_result, Mapping) or set(execution_result) != {"Version2"}:
        raise LiveProofError("finality execution result must contain exactly Version2")
    versioned = execution_result["Version2"]
    if not isinstance(versioned, Mapping) or set(versioned) != {
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
        raise LiveProofError("finality Version2 execution result field set is invalid")
    error_message = versioned["error_message"]
    if error_message is not None:
        if not isinstance(error_message, str):
            raise LiveProofError("finality execution error_message is invalid")
        match = ERROR_CODE_RE.search(error_message)
        return {
            "finalized": True,
            "success": False,
            "user_error": int(match.group(1)) if match else None,
            "error_message": error_message,
            "block_hash": block_hash,
            "block_height": block_height,
        }
    return {
        "finalized": True,
        "success": True,
        "user_error": None,
        "error_message": None,
        "block_hash": block_hash,
        "block_height": block_height,
    }


def _public_key(value: str) -> object:
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise LiveProofError("public key must be canonical Casper hexadecimal") from exc
    if len(raw) in (33, 34) and raw[0] in (1, 2):
        return create_public_key_from_account_key(raw)
    if len(raw) == 32:
        return parse_public_key_bytes(raw, KeyAlgorithm.ED25519)
    if len(raw) == 33:
        return parse_public_key_bytes(raw, KeyAlgorithm.SECP256K1)
    raise LiveProofError("unsupported Casper public-key encoding")


def _role_key(role: Mapping[str, Any]) -> tuple[object, object | None, str]:
    if set(role) == {"custody", "public_key"} and role["custody"] == "browser":
        public = _public_key(str(role["public_key"]))
        return public, None, "browser"
    if set(role) == {"custody", "secret_key_path", "key_algorithm"} and role["custody"] == "server":
        try:
            private = parse_private_key(
                Path(str(role["secret_key_path"])),
                KeyAlgorithm[str(role["key_algorithm"]).upper()],
            )
        except (OSError, ValueError, KeyError) as exc:
            raise LiveProofError("server-held role key could not be loaded") from exc
        return private, private, "server"
    raise LiveProofError("role must be an exact browser or server custody object")


def _runtime_value(arg: Mapping[str, Any]) -> object:
    cl_type = arg["cl_type"]
    cls: type
    if cl_type == "String":
        cls = CLV_String
    elif cl_type == "U8":
        cls = CLV_U8
    elif cl_type == "U32":
        cls = CLV_U32
    elif cl_type == "U64":
        cls = CLV_U64
    elif cl_type == "U256":
        cls = CLV_U256
    elif cl_type == "U512":
        cls = CLV_U512
    elif cl_type == {"ByteArray": 32}:
        cls = CLV_ByteArray
    else:
        raise LiveProofError(f"unsupported frozen runtime type: {cl_type!r}")
    return serializer.from_json(
        {"cl_type": arg["cl_type"], "bytes": arg["bytes"], "parsed": arg["parsed"]},
        cls,
    )


def _build_call(
    *,
    signer: object,
    private_key: object | None,
    contract_hash: str,
    entry_point: str,
    runtime_args: list[Mapping[str, Any]],
    payment_motes: int,
    ttl: str,
) -> dict[str, Any]:
    if len(contract_hash) != 64:
        raise LiveProofError("exact contract hash must be 64 hex characters")
    deploy_args = [DeployArgument(str(item["name"]), _runtime_value(item)) for item in runtime_args]
    deploy = create_deploy(
        create_deploy_parameters(signer, "casper-test", ttl=ttl),
        create_standard_payment(payment_motes),
        DeployOfStoredContractByHash(
            hash=bytes.fromhex(contract_hash),
            entry_point=entry_point,
            args=deploy_args,
        ),
    )
    if private_key is not None:
        deploy.approve(private_key)
    value = serializer.to_json(deploy)
    if private_key is None:
        value["approvals"] = []
    return value


def _simple_args(proposal_id: str, envelope_hash: str) -> list[dict[str, Any]]:
    return [
        {"name": "proposal_id", **serializer.to_json(CLV_String(proposal_id))},
        {"name": "envelope_hash", **serializer.to_json(CLV_ByteArray(bytes.fromhex(envelope_hash)))},
    ]


def choose_negative_allocation_bps(approved: object) -> int:
    if type(approved) is not int or not 0 <= approved <= 10_000:
        raise LiveProofError("approved_allocation_bps must be an exact basis-point value")
    return 2_999 if approved == 3_000 else 3_000


def _steps(prepared: Mapping[str, Any]) -> list[dict[str, Any]]:
    exact = copy.deepcopy(prepared["runtime_args"])
    mutated = copy.deepcopy(exact)
    for arg in mutated:
        if arg["name"] == "approved_allocation_bps":
            arg.update(
                serializer.to_json(
                    CLV_U32(choose_negative_allocation_bps(arg.get("parsed")))
                )
            )
            break
    proposal_id = str(prepared["proposal_id"])
    envelope_hash = str(prepared["envelope_hash"])
    return [
        {"name": "propose_exact", "role": "proposer", "entry_point": "propose_envelope", "args": _simple_args(proposal_id, envelope_hash), "expected": "success"},
        {"name": "finalize_pre_quorum", "role": "finalizer", "entry_point": prepared["entry_point"], "args": exact, "expected_error": 8},
        {"name": "approve_a", "role": "signer_a", "entry_point": "approve_envelope", "args": _simple_args(proposal_id, envelope_hash), "expected": "success"},
        {"name": "approve_b", "role": "signer_b", "entry_point": "approve_envelope", "args": _simple_args(proposal_id, envelope_hash), "expected": "success"},
        {"name": "finalize_mutated_3000_bps", "role": "finalizer", "entry_point": prepared["entry_point"], "args": mutated, "expected_error": 10},
        {"name": "finalize_exact", "role": "finalizer", "entry_point": prepared["entry_point"], "args": exact, "expected": "success"},
        {"name": "finalize_again", "role": "finalizer", "entry_point": prepared["entry_point"], "args": exact, "expected_error": 12},
    ]


def _persist_artifact(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=path.parent
    )
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(json.dumps(value, indent=2, sort_keys=True).encode("utf-8"))
            stream.write(b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()


def _persist_run_artifact(
    args: argparse.Namespace, value: Mapping[str, Any]
) -> None:
    _persist_artifact(args.journal, value)


def _execution_artifact(
    active_checkpoint: Mapping[str, Any] | None,
    output: Mapping[str, Any],
) -> dict[str, Any]:
    if active_checkpoint is None:
        return copy.deepcopy(dict(output))
    checkpoint = copy.deepcopy(dict(active_checkpoint))
    checkpoint["run"] = copy.deepcopy(dict(output))
    return _seal_checkpoint(checkpoint)


def _role_accounts(roles: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for role_name, role in roles.items():
        signer, private_key, custody = _role_key(role)
        public = private_key.to_public_key() if private_key is not None else signer
        result[role_name] = {
            "custody": custody,
            "public_key": public.account_key.hex(),
            "account_hash": public.to_account_hash().hex(),
        }
    if len({item["account_hash"] for item in result.values()}) != 5:
        raise LiveProofError("five governance roles must be pairwise distinct")
    return result


def _validate_journal_step(
    record: object,
    *,
    frozen_step: Mapping[str, Any],
    role_account: Mapping[str, str],
    contract_hash: str,
) -> None:
    """Reparse and bind an exact server-signed or browser-unsigned deploy."""

    if not isinstance(record, Mapping):
        raise LiveProofError("server journal step is invalid")
    if (
        record.get("name"),
        record.get("role"),
        record.get("entry_point"),
        record.get("expected"),
        record.get("expected_error"),
    ) != (
        frozen_step["name"],
        frozen_step["role"],
        frozen_step["entry_point"],
        frozen_step.get("expected"),
        frozen_step.get("expected_error"),
    ):
        raise LiveProofError("server journal differs from frozen choreography")
    custody = record.get("custody")
    if custody not in {"server", "browser"} or role_account.get("custody") != custody:
        raise LiveProofError("journal deploy custody differs from frozen role")
    state = record.get("submission_state")
    if state not in {
        "prepared",
        "broadcast_inflight",
        "broadcast_ambiguous",
        "submitted",
        "terminal_rejected",
        "finalized",
    }:
        raise LiveProofError("server journal submission state is invalid")
    deploy_json = record.get("deploy")
    if not isinstance(deploy_json, Mapping):
        raise LiveProofError("server journal deploy is invalid")
    try:
        deploy = serializer.from_json(dict(deploy_json), Deploy)
        canonical = serializer.to_json(deploy)
        body_hash = create_digest_of_deploy_body(deploy.payment, deploy.session)
        deploy_hash = create_digest_of_deploy(deploy.header)
    except Exception as exc:
        raise LiveProofError("server journal deploy cannot be decoded canonically") from exc
    if _normalize_deploy_json(canonical) != _normalize_deploy_json(deploy_json):
        raise LiveProofError("server journal deploy differs from canonical Casper bytes")
    expected_public_key = str(role_account.get("public_key", "")).lower()
    if (
        deploy.header.body_hash != body_hash
        or deploy.hash != deploy_hash
        or deploy.header.chain_name != "casper-test"
        or deploy_hash.hex() != _hash32(record.get("deploy_hash"), "journal deploy hash")
        or deploy.header.account.account_key.hex() != expected_public_key
    ):
        raise LiveProofError("server journal deploy hash/network/role is invalid")
    unsigned_browser = custody == "browser" and state == "prepared"
    if unsigned_browser:
        if deploy.approvals:
            raise LiveProofError(
                "browser journal deploy must be unsigned and prepared"
            )
    else:
        if len(deploy.approvals) != 1:
            raise LiveProofError("server journal deploy requires one approval")
        approval = deploy.approvals[0]
        signer = getattr(approval.signer, "account_key", None)
        if not isinstance(signer, bytes) or signer.hex() != expected_public_key:
            raise LiveProofError("server journal deploy approval differs from frozen role")
        try:
            valid_signature = crypto.verify_deploy_approval_signature(
                deploy_hash, approval.signature, signer
            )
        except Exception as exc:
            raise LiveProofError("server journal deploy signature is invalid") from exc
        if not valid_signature:
            raise LiveProofError("server journal deploy signature is invalid")
    session = deploy_json.get("session")
    stored = session.get("StoredContractByHash") if isinstance(session, Mapping) else None
    expected_args = [
        [
            item["name"],
            {key: copy.deepcopy(item[key]) for key in ("cl_type", "bytes", "parsed")},
        ]
        for item in frozen_step["args"]
    ]
    if (
        not isinstance(stored, Mapping)
        or set(stored) != {"hash", "entry_point", "args"}
        or _hash32(stored.get("hash"), "journal session contract hash")
        != contract_hash
        or stored.get("entry_point") != frozen_step["entry_point"]
        or _normalize_deploy_json(stored.get("args"))
        != _normalize_deploy_json(expected_args)
    ):
        raise LiveProofError("server journal target/entry point/arguments are not frozen")


def _completed_step_readbacks(
    output: Mapping[str, Any],
    *,
    before_index: int,
) -> list[dict[str, str]]:
    steps = output.get("steps")
    if not isinstance(steps, list) or len(steps) < before_index:
        raise LiveProofError("run does not contain the expected completed-step prefix")
    completed: list[dict[str, str]] = []
    for record in steps[:before_index]:
        if not isinstance(record, Mapping) or not isinstance(
            record.get("finality_transcript"), Mapping
        ):
            raise LiveProofError("completed step lacks a finality transcript")
        completed.append(
            {
                "name": str(record.get("name")),
                "deploy_hash": _hash32(
                    record.get("deploy_hash"), "completed-step deploy hash"
                ),
                "finality_transcript_sha256": _hash32(
                    record["finality_transcript"].get("canonical_sha256"),
                    "completed-step finality transcript checksum",
                ),
            }
        )
    return completed


def _expected_outcome(step: Mapping[str, Any], outcome: Mapping[str, Any]) -> None:
    if "expected_error" in step:
        if outcome.get("success") is not False or outcome.get("user_error") != step["expected_error"]:
            raise LiveProofError(
                f"{step['name']}: expected User error {step['expected_error']}"
            )
    elif outcome.get("success") is not True:
        raise LiveProofError(f"{step['name']}: expected finalized success")


def _validate_broadcast_response(
    response: object,
    *,
    request_id: str,
    deploy_hash: str,
) -> Mapping[str, Any]:
    if not isinstance(response, Mapping) or set(response) != {"jsonrpc", "id", "result"}:
        raise LiveProofError("broadcast response is not the exact Casper v2 result")
    if response["jsonrpc"] != "2.0" or response["id"] != request_id:
        raise LiveProofError("broadcast response request identity mismatch")
    result = response["result"]
    if not isinstance(result, Mapping) or set(result) != {"api_version", "deploy_hash"}:
        raise LiveProofError("broadcast result field set is invalid")
    if not isinstance(result["api_version"], str) or not result["api_version"]:
        raise LiveProofError("broadcast result api_version is missing")
    returned = _hash32(result["deploy_hash"], "broadcast deploy hash")
    if returned != _hash32(deploy_hash, "expected deploy hash"):
        raise LiveProofError("broadcast returned another deploy hash")
    return response


def _revalidate_staged_checkpoint(
    checkpoint: Mapping[str, Any],
    *,
    now_seconds: float | None = None,
) -> dict[str, Any]:
    verified = _validate_checkpoint(checkpoint)
    if verified["status"] != "signed_deploy_staged":
        raise LiveProofError("checkpoint is not a staged browser deploy")
    index = verified["next_step_index"]
    signed = copy.deepcopy(verified["run"]["steps"][index]["deploy"])
    unsigned = copy.deepcopy(signed)
    unsigned["approvals"] = []
    waiting = copy.deepcopy(verified)
    waiting["status"] = "waiting_for_browser_signature"
    waiting["run"]["status"] = "waiting_for_browser_signature"
    waiting["run"]["steps"][index]["deploy"] = unsigned
    waiting["consumed_import_deploy_hashes"] = []
    waiting = _seal_checkpoint(waiting)
    imported = build_browser_signature_import(waiting, signed)
    restaged = validate_and_stage_browser_import(
        waiting,
        imported,
        now_seconds=now_seconds,
    )
    if _normalize_deploy_json(restaged["run"]["steps"][index]["deploy"]) != _normalize_deploy_json(
        signed
    ):
        raise LiveProofError("staged browser deploy changed during revalidation")
    return verified


async def _run_unlocked(args: argparse.Namespace) -> dict[str, Any]:
    document = json.loads(args.input.read_text(encoding="utf-8"))
    prepared = prepare_v3_envelope(document)
    roles = json.loads(args.roles.read_text(encoding="utf-8"))
    if set(roles) != {"proposer", "finalizer", "signer_a", "signer_b", "signer_c"}:
        raise LiveProofError("role manifest must contain exactly five frozen governance roles")
    package_hash = _hash32(args.package_hash, "package hash")
    contract_hash = _hash32(args.contract_hash, "contract hash")
    configured_role_accounts = _role_accounts(roles)
    submit = bool(getattr(args, "submit", not args.prepare_only))
    rpc_urls: tuple[str, str] | tuple[()] = ()
    rpc_transport: object | None = None
    if submit:
        try:
            rpc_transport = build_public_rpc_transport(
                getattr(args, "rpc_urls", [])
            )
            rpc_urls = rpc_transport.endpoints
        except InstallValidationError as exc:
            raise LiveProofError(str(exc)) from exc
        args.rpc_url = rpc_urls[0]
    node_id = urlsplit(args.rpc_url).hostname if args.rpc_url else None
    choreography = _steps(prepared)
    start_index = 0
    active_checkpoint: dict[str, Any] | None = None
    if args.resume_checkpoint is not None:
        if not submit:
            raise LiveProofError("prepare-only cannot resume a browser checkpoint")
        if args.journal.resolve() != args.resume_checkpoint.resolve():
            raise LiveProofError("resume must use the authoritative journal path")
        resumed_value = json.loads(
            args.resume_checkpoint.read_text(encoding="utf-8")
        )
        if (
            isinstance(resumed_value, Mapping)
            and resumed_value.get("schema_id") == "concordia.v3-live-proof-run.v1"
        ):
            if args.signed_deploy is not None:
                raise LiveProofError("server journal rejects browser signed-deploy import")
            output = copy.deepcopy(dict(resumed_value))
            if (
                output.get("prepared") != prepared
                or _hash32(output.get("package_hash"), "journal package hash")
                != package_hash
                or _hash32(output.get("contract_hash"), "journal contract hash")
                != contract_hash
                or output.get("role_accounts") != configured_role_accounts
            ):
                raise LiveProofError(
                    "journal differs from current input, roles, package or contract"
                )
            steps = output.get("steps")
            if not isinstance(steps, list) or not steps:
                raise LiveProofError("server journal has no prepared step")
            if len(steps) > len(choreography):
                raise LiveProofError("server journal has an impossible step prefix")
            for index, item in enumerate(steps):
                frozen = choreography[index]
                role_account = configured_role_accounts[frozen["role"]]
                _validate_journal_step(
                    item,
                    frozen_step=frozen,
                    role_account=role_account,
                    contract_hash=contract_hash,
                )
            incomplete = [
                index
                for index, item in enumerate(steps)
                if not isinstance(item, Mapping)
                or item.get("submission_state") != "finalized"
            ]
            start_index = incomplete[0] if incomplete else len(steps)
            if start_index >= len(choreography):
                if (
                    len(steps) == len(choreography)
                    and output.get("status") == "contract_sequence_verified"
                    and isinstance(output.get("readback"), Mapping)
                ):
                    return output
                raise LiveProofError("completed run journal is internally inconsistent")
            if len(steps) != start_index + 1:
                raise LiveProofError("server journal step prefix is not exact")
            checkpoint = None
        else:
            checkpoint = _validate_checkpoint(resumed_value)
        if checkpoint is None:
            pass
        else:
            run_output = checkpoint["run"]
            if (
                run_output.get("prepared") != prepared
                or _hash32(run_output.get("package_hash"), "checkpoint package hash") != package_hash
                or _hash32(run_output.get("contract_hash"), "checkpoint contract hash") != contract_hash
                or run_output.get("role_accounts") != configured_role_accounts
            ):
                raise LiveProofError("checkpoint differs from current input, roles, package or contract")
            start_index = checkpoint["next_step_index"]
            if checkpoint["status"] == "waiting_for_browser_signature":
                if args.signed_deploy is None:
                    raise LiveProofError("waiting checkpoint requires --signed-deploy")
                imported = json.loads(args.signed_deploy.read_text(encoding="utf-8"))
                if isinstance(imported, Mapping) and set(imported) == {
                    "approvals",
                    "hash",
                    "header",
                    "payment",
                    "session",
                }:
                    imported = build_browser_signature_import(checkpoint, imported)
                active_checkpoint = validate_and_stage_browser_import(checkpoint, imported)
                active_checkpoint["run"]["steps"][start_index][
                    "submission_state"
                ] = "prepared"
                _persist_run_artifact(args, active_checkpoint)
            else:
                if args.signed_deploy is not None:
                    raise LiveProofError("staged checkpoint rejects duplicate signed-deploy imports")
                record = run_output["steps"][start_index]
                revalidation_time: float | None = None
                if "finality_transcript" in record:
                    try:
                        finalized_deploy = serializer.from_json(record["deploy"], Deploy)
                        revalidation_time = finalized_deploy.header.timestamp.value + 1
                    except Exception as exc:
                        raise LiveProofError(
                            "finalized staged deploy cannot be decoded for revalidation"
                        ) from exc
                active_checkpoint = _revalidate_staged_checkpoint(
                    checkpoint,
                    now_seconds=revalidation_time,
                )
            output = active_checkpoint["run"]
    else:
        if args.signed_deploy is not None:
            raise LiveProofError("--signed-deploy requires --resume-checkpoint")
        output = {
            "schema_id": "concordia.v3-live-proof-run.v1",
            "status": "running",
            "network": "casper-test",
            "package_hash": package_hash,
            "contract_hash": contract_hash,
            "prepared": prepared,
            "role_accounts": configured_role_accounts,
            "steps": [],
        }

    for step_index in range(start_index, len(choreography)):
        step = choreography[step_index]
        signer, private_key, custody = _role_key(roles[step["role"]])
        if step_index < len(output["steps"]):
            if step_index != start_index:
                raise LiveProofError("checkpoint contains an unexpected future step")
            record = output["steps"][step_index]
            deploy_json = record["deploy"]
        else:
            deploy_json = _build_call(
                signer=signer,
                private_key=private_key,
                contract_hash=contract_hash,
                entry_point=step["entry_point"],
                runtime_args=step["args"],
                payment_motes=args.payment_motes,
                ttl=args.ttl,
            )
            record = {
                "name": step["name"],
                "role": step["role"],
                "custody": custody,
                "entry_point": step["entry_point"],
                "expected": step.get("expected"),
                "expected_error": step.get("expected_error"),
                "deploy_hash": deploy_json["hash"],
                "deploy": deploy_json,
                "submission_state": "prepared",
            }
            output["steps"].append(record)
        if not submit or private_key is None:
            if private_key is None and active_checkpoint is not None and step_index == start_index:
                pass
            else:
                output["status"] = (
                    "prepared" if not submit else "waiting_for_browser_signature"
                )
                output["next_step"] = step["name"]
                if not submit:
                    _persist_run_artifact(args, output)
                    return output
                prior_state = capture_v3_checkpoint_state(
                    rpc_url=args.rpc_url,
                    package_hash=package_hash,
                    contract_hash=contract_hash,
                    proposal_id=prepared["proposal_id"],
                    action_id=prepared["action_id"],
                    completed_steps=_completed_step_readbacks(
                        output,
                        before_index=step_index,
                    ),
                )
                checkpoint = build_browser_checkpoint(
                    output,
                    next_step_index=step_index,
                    prior_state_readback=prior_state,
                )
                _persist_run_artifact(args, checkpoint)
                return checkpoint
        if "finality_transcript" in record:
            observed = outcome_from_finality_response(
                record["finality_transcript"]["response"]
            )
            _expected_outcome(step, observed)
            record["observed_outcome"] = observed
            active_checkpoint = None
            continue
        if private_key is None and active_checkpoint is None:
            raise LiveProofError("browser step lacks a validated staged signature")
        if record.get("submission_state") == "broadcast_inflight":
            record["submission_state"] = "broadcast_ambiguous"
            persisted = _execution_artifact(active_checkpoint, output)
            _persist_run_artifact(args, persisted)
            if active_checkpoint is not None:
                active_checkpoint = persisted
        if record.get("submission_state") == "terminal_rejected":
            raise LiveProofError(
                f"{step['name']}: deploy is terminally rejected; prepare a new run"
            )
        if record.get("submission_state") in {"broadcast_ambiguous", "submitted"}:
            try:
                reconciled = reconcile_two_node_deploy(
                    rpc_transport,
                    deploy_hash=deploy_json["hash"],
                    expected_user_error=step.get("expected_error"),
                    deploy_expires_at=deploy_expiry_epoch(deploy_json),
                )
            except InstallValidationError as exc:
                raise LiveProofError(str(exc)) from exc
            if reconciled["status"] == "terminal_rejected":
                record["submission_state"] = "terminal_rejected"
                record["terminal_evidence"] = reconciled
                persisted = _execution_artifact(active_checkpoint, output)
                _persist_run_artifact(args, persisted)
                return persisted
            if reconciled["status"] != "finalized":
                persisted = _execution_artifact(active_checkpoint, output)
                _persist_run_artifact(args, persisted)
                return persisted
        else:
            record["submission_state"] = "broadcast_inflight"
            persisted = _execution_artifact(active_checkpoint, output)
            _persist_run_artifact(args, persisted)
            if active_checkpoint is not None:
                active_checkpoint = persisted
        params = {"deploy": deploy_json}
        request_id = "concordia-v3-live-" + step["name"]
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "account_put_deploy",
            "params": params,
        }
        if record.get("submission_state") == "broadcast_inflight":
            try:
                raw_response = _safe_rpc_payload(
                    rpc_transport, rpc_urls[0], payload
                )
                rpc_response = _validate_broadcast_response(
                    raw_response,
                    request_id=request_id,
                    deploy_hash=deploy_json["hash"],
                )
            except (InstallValidationError, LiveProofError):
                record["submission_state"] = "broadcast_ambiguous"
                record["broadcast_evidence"] = {
                    "status": "response_lost_reconciled_by_hash",
                    "deploy_hash": str(deploy_json["hash"]).lower(),
                }
                persisted = _execution_artifact(active_checkpoint, output)
                _persist_run_artifact(args, persisted)
            else:
                record["broadcast_transcript"] = _transcript(
                    node_id=str(node_id),
                    method="account_put_deploy",
                    params=params,
                    request=payload,
                    response=rpc_response,
                )
                record["submission_state"] = "submitted"
                persisted = _execution_artifact(active_checkpoint, output)
                _persist_run_artifact(args, persisted)
                if active_checkpoint is not None:
                    active_checkpoint = persisted
            try:
                reconciled = reconcile_two_node_deploy(
                    rpc_transport,
                    deploy_hash=deploy_json["hash"],
                    expected_user_error=step.get("expected_error"),
                    deploy_expires_at=deploy_expiry_epoch(deploy_json),
                )
            except InstallValidationError as exc:
                raise LiveProofError(str(exc)) from exc
            if reconciled["status"] == "terminal_rejected":
                record["submission_state"] = "terminal_rejected"
                record["terminal_evidence"] = reconciled
                persisted = _execution_artifact(active_checkpoint, output)
                _persist_run_artifact(args, persisted)
                return persisted
            if reconciled["status"] != "finalized":
                return _execution_artifact(active_checkpoint, output)
        observations = reconciled["node_observations"]
        primary = observations[0]
        finality_transcript = _transcript(
            node_id=str(primary["node_id"]),
            method="info_get_deploy",
            params=primary["deploy_request"]["params"],
            request=primary["deploy_request"],
            response=primary["deploy_response"],
        )
        outcome = outcome_from_finality_response(primary["deploy_response"])
        record["finality_transcript"] = finality_transcript
        record["finality_block_evidence"] = reconciled
        record["observed_outcome"] = outcome
        record["submission_state"] = "finalized"
        _expected_outcome(step, outcome)
        output["status"] = "running"
        output.pop("next_step", None)
        if active_checkpoint is not None:
            active_checkpoint["run"] = output
            active_checkpoint = _seal_checkpoint(active_checkpoint)
            _persist_run_artifact(args, active_checkpoint)
            active_checkpoint = None
        else:
            _persist_run_artifact(args, output)

    output["readback"] = capture_v3_state(
        rpc_url=args.rpc_url,
        package_hash=package_hash,
        contract_hash=contract_hash,
        proposal_id=prepared["proposal_id"],
        action_id=prepared["action_id"],
    )
    output["status"] = "contract_sequence_verified"
    output.pop("next_step", None)
    _persist_run_artifact(args, output)
    return output


async def run(args: argparse.Namespace) -> dict[str, Any]:
    journal_path = getattr(args, "journal", args.out)
    args.journal = journal_path
    lock_path = journal_path.with_name(journal_path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        if journal_path.exists() and args.resume_checkpoint is None:
            raise LiveProofError(
                "authoritative journal already exists; resume it explicitly"
            )
        return await _run_unlocked(args)
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def build_live_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--roles", type=Path, required=True)
    parser.add_argument("--package-hash", required=True)
    parser.add_argument("--contract-hash", required=True)
    parser.add_argument("--rpc-url", dest="rpc_urls", action="append", default=[])
    parser.add_argument("--payment-motes", type=int, default=5_000_000_000)
    parser.add_argument("--ttl", default="30m")
    parser.add_argument("--max-attempts", type=int, default=30)
    parser.add_argument("--poll-seconds", type=float, default=6.0)
    parser.add_argument("--submit", action="store_true")
    parser.add_argument("--prepare-only", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--resume-checkpoint", type=Path)
    parser.add_argument("--signed-deploy", type=Path)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main() -> int:
    parser = build_live_parser()
    args = parser.parse_args()
    args.prepare_only = not args.submit
    args.rpc_url = args.rpc_urls[0] if args.rpc_urls else ""
    try:
        result = asyncio.run(run(args))
        if result.get("status") == "contract_sequence_verified":
            _persist_artifact(args.out, result)
        print(
            json.dumps(
                {
                    "status": result["status"],
                    "journal": str(args.journal),
                    "artifact": (
                        str(args.out)
                        if result.get("status") == "contract_sequence_verified"
                        else None
                    ),
                }
            )
        )
        return 0
    except (
        LiveProofError,
        ReadbackValidationError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
    ) as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
