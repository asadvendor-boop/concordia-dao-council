"""Derive one production NativeTransferV1 input from verified release evidence.

This module performs no network I/O and accepts no precomputed governance
roots, action IDs, transfer IDs, envelope hashes, or nonces.  Every derived
value is bound to the exact bytes of five strict evidence artifacts, with the
historical artifact additionally checked against its exact frozen inventory.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pycspr import serializer
from pycspr.types.node.rpc import Deploy

from scripts.derive_deployment_domain_v3 import deployment_domain_record
from scripts.install_governance_receipt_v3 import (
    PACKAGE_KEY_NAME,
    InstallValidationError,
    validate_finalized_install_deploy,
    verify_two_node_deploy_finality,
)
from scripts.verify_v3_proof import (
    ProofVerificationError,
    verify_v3_deployment_manifest,
)
from shared.actions_v3 import build_native_material
from shared.envelope_v3 import MACHINE_NAME_RE, blake2b256, length_prefix
from shared.evidence_manifest_v3 import encode_evidence_manifest
from shared.historical_odra_artifact import (
    HistoricalOdraArtifactError,
    verify_historical_odra_artifact,
)
from shared.metadata_manifest_v3 import (
    ManifestEncodingError,
    encode_authorized_metadata,
)
from shared.treasury_snapshot import (
    TreasurySnapshotError,
    verify_treasury_snapshot_artifact,
)


EXACT_TREASURY_BALANCE_MOTES = 625_000_000_000
EXACT_REQUESTED_ALLOCATION_BPS = 3_000
EXACT_APPROVED_ALLOCATION_BPS = 800
EXACT_TRANSFER_MOTES = 50_000_000_000

INTENT_SCHEMA_ID = "concordia.native-transfer-v3-intent.v1"
DERIVATION_SCHEMA_ID = "concordia.native-transfer-v3-input-build.v1"
TYPED_INPUT_SCHEMA_ID = "concordia.exact-envelope-v3.input.v1"
NETWORK = "casper-test"

_MAX_SOURCE_BYTES = 32 * 1024 * 1024
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_RFC3339_UTC_RE = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})T"
    r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?Z$"
)
_PROPOSAL_NONCE_DOMAIN = b"CONCORDIA_NATIVE_PROPOSAL_NONCE_V1\0"
_ACTION_NONCE_DOMAIN = b"CONCORDIA_NATIVE_ACTION_NONCE_V1\0"
_SOURCE_SEED_DOMAIN = b"CONCORDIA_NATIVE_TRANSFER_INPUT_SEED_V1\0"

_CANONICAL_RECEIPT_FIELDS = {
    "agent_action_hash",
    "approved_allocation_bps",
    "block_hash",
    "block_height",
    "caller_hash",
    "caller_public_key",
    "contract_hash",
    "contract_package_hash",
    "cspr_live_api_url",
    "decision",
    "deploy_hash",
    "dissent_hash",
    "entry_point",
    "evidence_uri",
    "explorer_url",
    "final_card_hash",
    "network",
    "plan_hash",
    "policy_hash",
    "proof_status",
    "proposal_hash",
    "proposal_id",
    "proposal_type",
    "risk_level",
    "risk_score",
    "transaction_hash",
    "typed_args",
    "verified_at_utc",
}
_CANONICAL_TYPED_ARGS = {
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
_ROOT_FIELDS = (
    "proposal_hash",
    "policy_hash",
    "plan_hash",
    "final_card_hash",
    "dissent_hash",
    "agent_action_hash",
)
_INTENT_FIELDS = {
    "schema_id",
    "network",
    "intent_id",
    "canonical_proposal_id",
    "source_account_hash",
    "recipient_account_hash",
    "requested_allocation_bps",
    "captured_at",
}


class NativeTransferInputError(ValueError):
    """One source artifact cannot authorize the exact native transfer."""


class _DuplicateJsonKey(ValueError):
    pass


@dataclass(frozen=True)
class NativeTransferInputBuild:
    typed_input: dict[str, Any]
    derivation_manifest: dict[str, Any]


@dataclass(frozen=True, order=True)
class _Timestamp:
    unix_seconds: int
    fractional_nanoseconds: int


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _strict_json(raw: object, label: str) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > _MAX_SOURCE_BYTES:
        raise NativeTransferInputError(f"{label} bytes are unavailable or oversized")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NativeTransferInputError(f"{label} is not UTF-8 JSON") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except _DuplicateJsonKey as exc:
        raise NativeTransferInputError(f"{label} contains a {exc}") from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise NativeTransferInputError(f"{label} is malformed JSON") from exc
    if type(value) is not dict:
        raise NativeTransferInputError(f"{label} must contain one JSON object")
    return value


def render_json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return (
            json.dumps(
                value,
                indent=2,
                sort_keys=True,
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise NativeTransferInputError("derived output is not canonical JSON") from exc


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _hash32(value: object, label: str, *, nonzero: bool = True) -> str:
    if type(value) is not str or _HEX32_RE.fullmatch(value) is None:
        raise NativeTransferInputError(f"{label} must be lowercase 32-byte hex")
    if nonzero and value == "00" * 32:
        raise NativeTransferInputError(f"{label} must be non-zero")
    return value


def _strip_hash(value: object, label: str) -> str:
    if type(value) is not str:
        raise NativeTransferInputError(f"{label} is missing")
    normalized = value
    for prefix in ("contract-package-", "contract-", "package-", "hash-"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
            break
    if re.fullmatch(r"[0-9A-Fa-f]{64}", normalized) is None:
        raise NativeTransferInputError(f"{label} must be 32-byte hex")
    return _hash32(normalized.lower(), label)


def _u64(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise NativeTransferInputError(f"{label} must be a non-negative u64")
    return value


def _timestamp(value: object, label: str) -> tuple[str, _Timestamp]:
    if type(value) is not str:
        raise NativeTransferInputError(f"{label} must be RFC3339 UTC")
    match = _RFC3339_UTC_RE.fullmatch(value)
    if match is None:
        raise NativeTransferInputError(f"{label} must be RFC3339 UTC")
    try:
        instant = datetime(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            tzinfo=UTC,
        )
    except ValueError as exc:
        raise NativeTransferInputError(f"{label} must be RFC3339 UTC") from exc
    fraction = match.group("fraction")
    fractional_nanoseconds = (
        int(fraction.ljust(9, "0")) if fraction is not None else 0
    )
    return value, _Timestamp(
        unix_seconds=int(instant.timestamp()),
        fractional_nanoseconds=fractional_nanoseconds,
    )


def _mapping(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise NativeTransferInputError(f"{label} is malformed")
    return value


def _rpc_result(transcript: object, method: str, label: str) -> dict[str, Any]:
    value = _mapping(transcript, f"{label} transcript")
    if set(value) != {"request", "response"}:
        raise NativeTransferInputError(f"{label} transcript fields are invalid")
    request = _mapping(value["request"], f"{label} request")
    response = _mapping(value["response"], f"{label} response")
    if (
        set(request) != {"jsonrpc", "id", "method", "params"}
        or request.get("jsonrpc") != "2.0"
        or request.get("method") != method
        or set(response) != {"jsonrpc", "id", "result"}
        or response.get("jsonrpc") != "2.0"
        or response.get("id") != request.get("id")
    ):
        raise NativeTransferInputError(f"{label} request/response is invalid")
    result = _mapping(response["result"], f"{label} result")
    if set(result) == {"name", "value"}:
        result = _mapping(result["value"], f"{label} result value")
    return result


def _historical_arguments(
    document: Mapping[str, Any],
) -> tuple[dict[str, object], str, str]:
    raw_rpc = _mapping(document.get("raw_rpc"), "historical raw RPC")
    deploy_result = _rpc_result(
        raw_rpc.get("deploy"),
        "info_get_deploy",
        "historical deploy",
    )
    raw_deploy = _mapping(deploy_result.get("deploy"), "historical deploy")
    try:
        deploy = serializer.from_json(raw_deploy, Deploy)
    except Exception as exc:
        raise NativeTransferInputError(
            "historical receipt deploy is not canonical Casper data"
        ) from exc
    values: dict[str, object] = {}
    for argument in deploy.session.arguments:
        value = argument.value.value
        values[argument.name] = value.hex() if type(value) is bytes else value
    if set(values) != {
        "proposal_id",
        "proposal_type",
        "proposal_hash",
        "final_card_hash",
        "plan_hash",
        "decision",
        "risk_level",
        "risk_score",
        "treasury_action",
        "policy_hash",
        "policy_version",
        "dissent_hash",
        "approved_allocation_bps",
        "casper_network",
        "agent_council_version",
        "evidence_uri",
        "agent_action_hash",
    }:
        raise NativeTransferInputError(
            "historical receipt runtime arguments are not the frozen set"
        )
    return (
        values,
        deploy.header.account.account_key.hex(),
        deploy.header.account.to_account_hash().hex(),
    )


def _verify_canonical_decision(
    *,
    historical_bytes: bytes,
    inventory_bytes: bytes,
    receipt_bytes: bytes,
) -> tuple[dict[str, object], dict[str, object], str, _Timestamp]:
    historical = _strict_json(historical_bytes, "historical Odra receipt")
    receipt = _strict_json(receipt_bytes, "canonical receipt")
    if set(receipt) != _CANONICAL_RECEIPT_FIELDS:
        raise NativeTransferInputError(
            "canonical receipt fields do not match the frozen schema"
        )
    try:
        facts = verify_historical_odra_artifact(
            historical_bytes,
            inventory_bytes=inventory_bytes,
        )
    except HistoricalOdraArtifactError as exc:
        raise NativeTransferInputError(
            "historical Odra receipt did not verify"
        ) from exc
    values, caller_public_key, caller_hash = _historical_arguments(historical)
    if receipt.get("network") != NETWORK or values.get("casper_network") != NETWORK:
        raise NativeTransferInputError("canonical receipt network must be casper-test")
    if (
        receipt.get("entry_point") != "store_governance_receipt"
        or receipt.get("proof_status") != "complete"
    ):
        raise NativeTransferInputError("canonical receipt is not the accepted receipt")
    exact_pairs = {
        "proposal_id": "proposal_id",
        "proposal_type": "proposal_type",
        "proposal_hash": "proposal_hash",
        "policy_hash": "policy_hash",
        "plan_hash": "plan_hash",
        "final_card_hash": "final_card_hash",
        "dissent_hash": "dissent_hash",
        "agent_action_hash": "agent_action_hash",
        "approved_allocation_bps": "approved_allocation_bps",
        "risk_score": "risk_score",
        "risk_level": "risk_level",
        "decision": "decision",
        "evidence_uri": "evidence_uri",
    }
    for receipt_field, argument_field in exact_pairs.items():
        if receipt.get(receipt_field) != values.get(argument_field):
            raise NativeTransferInputError(
                f"canonical receipt {receipt_field} disagrees with the verified deploy"
            )
    for root in _ROOT_FIELDS:
        _hash32(values[root], f"canonical {root}")
    if (
        values["decision"] != "APPROVED_WITH_LIMITS"
        or type(values["approved_allocation_bps"]) is not int
        or values["approved_allocation_bps"] != EXACT_APPROVED_ALLOCATION_BPS
    ):
        raise NativeTransferInputError(
            "canonical receipt must prove the exact capped 800 bps decision"
        )
    identity_pairs = (
        ("deploy_hash", "deployHash"),
        ("transaction_hash", "deployHash"),
        ("block_hash", "blockHash"),
        ("block_height", "blockHeight"),
    )
    for receipt_field, fact_field in identity_pairs:
        if receipt.get(receipt_field) != facts.get(fact_field):
            raise NativeTransferInputError(
                f"canonical receipt {receipt_field} disagrees with historical evidence"
            )
    deploy_hash = str(facts["deployHash"])
    if (
        receipt.get("caller_public_key") != caller_public_key
        or receipt.get("caller_hash") != caller_hash
        or receipt.get("typed_args") != _CANONICAL_TYPED_ARGS
        or receipt.get("cspr_live_api_url")
        != f"https://api.testnet.cspr.live/deploys/{deploy_hash}"
        or receipt.get("explorer_url")
        != f"https://testnet.cspr.live/deploy/{deploy_hash}"
    ):
        raise NativeTransferInputError(
            "canonical receipt caller, typed arguments, or URLs are inconsistent"
        )
    if (
        _strip_hash(receipt.get("contract_hash"), "canonical contract hash")
        != facts.get("contractHash")
        or _strip_hash(
            receipt.get("contract_package_hash"),
            "canonical package hash",
        )
        != facts.get("packageHash")
        or values["final_card_hash"] != facts.get("finalCardHash")
    ):
        raise NativeTransferInputError(
            "canonical receipt contract or final_card_hash is inconsistent"
        )
    verified_at, verified_time = _timestamp(
        receipt.get("verified_at_utc"),
        "canonical receipt verified_at_utc",
    )
    return facts, values, verified_at, verified_time


def _find_named_keys(value: object, name: str) -> list[str]:
    matches: list[str] = []
    if type(value) is dict:
        if value.get("name") == name and type(value.get("key")) is str:
            matches.append(str(value["key"]))
        for child in value.values():
            matches.extend(_find_named_keys(child, name))
    elif type(value) is list:
        for child in value:
            matches.extend(_find_named_keys(child, name))
    return matches


def _stored_value(result: Mapping[str, Any], label: str) -> dict[str, Any]:
    value = result.get("stored_value")
    return _mapping(value, f"{label} stored value")


def _verify_deployment_state(
    document: Mapping[str, Any],
    *,
    package_hash: str,
    contract_hash: str,
    block_hash: str,
    state_root: str,
) -> None:
    raw_rpc = _mapping(document.get("raw_rpc"), "v3 deployment raw RPC")
    state_transcript = _mapping(
        raw_rpc.get("state_root"),
        "v3 install state-root transcript",
    )
    state_request = _mapping(
        state_transcript.get("request"),
        "v3 install state-root request",
    )
    if state_request.get("params") != {"block_identifier": {"Hash": block_hash}}:
        raise NativeTransferInputError(
            "v3 install state-root query is not block-pinned"
        )
    state_result = _rpc_result(
        state_transcript,
        "chain_get_state_root_hash",
        "v3 install state root",
    )
    if state_result.get("state_root_hash") != state_root:
        raise NativeTransferInputError("v3 install state root disagrees")
    account_transcript = _mapping(
        raw_rpc.get("installer_account"),
        "v3 installer account transcript",
    )
    account_request = _mapping(
        account_transcript.get("request"), "installer account request"
    )
    expected_account = "account-hash-" + str(document.get("installer_account_hash"))
    if account_request.get("params") != {
        "state_identifier": {"StateRootHash": state_root},
        "key": expected_account,
        "path": [],
    }:
        raise NativeTransferInputError("v3 installer account query is not block-pinned")
    account_result = _rpc_result(
        account_transcript,
        "query_global_state",
        "v3 installer account",
    )
    package_keys = _find_named_keys(
        _stored_value(account_result, "v3 installer account"),
        PACKAGE_KEY_NAME,
    )
    if (
        len(package_keys) != 1
        or _strip_hash(package_keys[0], "v3 package named key") != package_hash
    ):
        raise NativeTransferInputError("v3 package named key disagrees")

    package_transcript = _mapping(raw_rpc.get("package"), "v3 package transcript")
    package_request = _mapping(package_transcript.get("request"), "v3 package request")
    if package_request.get("params") != {
        "state_identifier": {"StateRootHash": state_root},
        "key": "hash-" + package_hash,
        "path": [],
    }:
        raise NativeTransferInputError("v3 package query is not block-pinned")
    package_result = _rpc_result(
        package_transcript,
        "query_global_state",
        "v3 package",
    )
    package = _mapping(
        _stored_value(package_result, "v3 package").get("ContractPackage"),
        "v3 contract package",
    )
    versions = package.get("versions")
    if (
        set(package)
        != {
            "access_key",
            "versions",
            "disabled_versions",
            "groups",
            "lock_status",
        }
        or type(package.get("access_key")) is not str
        or re.fullmatch(
            r"uref-[0-9a-f]{64}-00[0-7]",
            str(package.get("access_key")),
        )
        is None
        or package.get("lock_status") != "Locked"
        or type(versions) is not list
        or len(versions) != 1
        or type(package.get("disabled_versions")) is not list
        or package.get("disabled_versions") != []
    ):
        raise NativeTransferInputError(
            "v3 package is not one permanently locked version"
        )
    groups = package.get("groups")
    if type(groups) is not list or any(
        type(group) is not dict
        or set(group) != {"group_name", "group_users"}
        or type(group.get("group_name")) is not str
        or group.get("group_users") != []
        for group in groups
    ):
        raise NativeTransferInputError("v3 package exposes an upgrade-capable group")
    version = _mapping(versions[0], "v3 contract version")
    if (
        set(version) != {"protocol_version_major", "contract_version", "contract_hash"}
        or version.get("protocol_version_major") != 2
        or version.get("contract_version") != 1
        or _strip_hash(version.get("contract_hash"), "v3 contract version hash")
        != contract_hash
    ):
        raise NativeTransferInputError("v3 package contract identity disagrees")

    contract_transcript = _mapping(raw_rpc.get("contract"), "v3 contract transcript")
    contract_request = _mapping(
        contract_transcript.get("request"), "v3 contract request"
    )
    if contract_request.get("params") != {
        "state_identifier": {"StateRootHash": state_root},
        "key": "hash-" + contract_hash,
        "path": [],
    }:
        raise NativeTransferInputError("v3 contract query is not block-pinned")
    contract_result = _rpc_result(
        contract_transcript,
        "query_global_state",
        "v3 contract",
    )
    contract = _mapping(
        _stored_value(contract_result, "v3 contract").get("Contract"),
        "v3 contract",
    )
    if (
        _strip_hash(
            contract.get("contract_package_hash"),
            "v3 contract package ownership",
        )
        != package_hash
    ):
        raise NativeTransferInputError("v3 contract package ownership disagrees")


def _verify_v3_deployment(
    raw: bytes,
) -> tuple[dict[str, object], str, _Timestamp]:
    document = _strict_json(raw, "v3 deployment manifest")
    if (
        document.get("schema_id") != "concordia.v3-deployment-manifest.v1"
        or document.get("network") != NETWORK
        or document.get("status") != "finalized"
        or document.get("package_key_name") != PACKAGE_KEY_NAME
    ):
        raise NativeTransferInputError(
            "v3 deployment is not the finalized casper-test manifest"
        )
    deployment_domain = _hash32(
        document.get("deployment_domain"),
        "v3 deployment domain",
    )
    try:
        record = deployment_domain_record(
            str(document.get("installation_nonce")),
            chain_name=NETWORK,
            package_key_name=PACKAGE_KEY_NAME,
        )
    except ValueError as exc:
        raise NativeTransferInputError("v3 deployment nonce is invalid") from exc
    if record["deployment_domain"] != deployment_domain:
        raise NativeTransferInputError("v3 deployment domain was not recomputed")
    package_hash = _strip_hash(document.get("package_hash"), "v3 package hash")
    contract_hash = _strip_hash(document.get("contract_hash"), "v3 contract hash")
    install_hash = _strip_hash(
        document.get("install_deploy_hash"),
        "v3 install deploy hash",
    )
    two_node = _mapping(document.get("two_node_finality"), "v3 two-node finality")
    observations = two_node.get("node_observations")
    if type(observations) is not list:
        raise NativeTransferInputError("v3 two-node finality is unavailable")
    try:
        finality = verify_two_node_deploy_finality(
            observations,
            deploy_hash=install_hash,
        )
    except InstallValidationError as exc:
        raise NativeTransferInputError(
            "v3 deployment two-node finality did not verify"
        ) from exc
    raw_rpc = _mapping(document.get("raw_rpc"), "v3 deployment raw RPC")
    install_result = _rpc_result(
        raw_rpc.get("install_deploy"),
        "info_get_deploy",
        "v3 install deploy",
    )
    raw_deploy = _mapping(install_result.get("deploy"), "v3 install deploy")
    try:
        deploy_facts = validate_finalized_install_deploy(raw_deploy, document)
    except InstallValidationError as exc:
        raise NativeTransferInputError("v3 install deploy did not verify") from exc
    finality_summary = _mapping(document.get("finality"), "v3 install finality summary")
    block_hash = _strip_hash(finality.get("block_hash"), "v3 install block hash")
    block_height = _u64(finality.get("block_height"), "v3 install block height")
    state_root = _hash32(
        document.get("install_state_root_hash"),
        "v3 install state root",
    )
    if (
        finality.get("success") is not True
        or finality.get("user_error") is not None
        or finality.get("corroboration_count") != 2
        or finality.get("deploy_hash") != install_hash
        or finality.get("state_root_hash") != state_root
        or document.get("install_block_hash") != block_hash
        or document.get("install_block_height") != block_height
        or finality_summary
        != {
            "status": "finalized",
            "success": True,
            "block_hash": block_hash,
            "block_height": block_height,
            "deploy_hash": install_hash,
        }
        or deploy_facts["deploy_hash"] != install_hash
    ):
        raise NativeTransferInputError(
            "v3 deployment summary disagrees with raw finalized observations"
        )
    _verify_deployment_state(
        document,
        package_hash=package_hash,
        contract_hash=contract_hash,
        block_hash=block_hash,
        state_root=state_root,
    )
    try:
        verified_release = verify_v3_deployment_manifest(document)
    except (ProofVerificationError, OSError) as exc:
        raise NativeTransferInputError(
            "v3 deployment differs from the frozen local release"
        ) from exc
    if (
        verified_release["package_hash"] != package_hash
        or verified_release["contract_hash"] != contract_hash
        or verified_release["deployment_domain"] != deployment_domain
        or verified_release["install_deploy_hash"] != install_hash
        or verified_release["install_block_hash"] != block_hash
        or verified_release["install_block_height"] != block_height
        or verified_release["install_observed_at"] != two_node.get("observed_at")
    ):
        raise NativeTransferInputError(
            "v3 deployment release identity disagrees with verified facts"
        )
    observed_at, observed_time = _timestamp(
        two_node.get("observed_at"),
        "v3 deployment observed_at",
    )
    return (
        {
            "deployment_domain": deployment_domain,
            "package_hash": package_hash,
            "contract_hash": contract_hash,
            "install_deploy_hash": install_hash,
            "install_block_hash": block_hash,
            "install_block_height": block_height,
            "install_state_root_hash": state_root,
        },
        observed_at,
        observed_time,
    )


def _block_facts(response: object) -> tuple[str, int, str]:
    payload = _mapping(response, "treasury snapshot block response")
    result = _mapping(payload.get("result"), "treasury snapshot block result")
    if set(result) == {"name", "value"}:
        result = _mapping(result["value"], "treasury snapshot block value")
    if "block_with_signatures" in result:
        wrapper = _mapping(result["block_with_signatures"], "treasury block wrapper")
        raw = _mapping(wrapper.get("block"), "treasury block")
    else:
        raw = _mapping(result.get("block"), "treasury block")
    versions = [name for name in ("Version1", "Version2") if name in raw]
    if versions:
        if len(versions) != 1 or len(raw) != 1:
            raise NativeTransferInputError("treasury snapshot block is ambiguous")
        raw = _mapping(raw[versions[0]], "treasury versioned block")
    header = _mapping(raw.get("header"), "treasury block header")
    return (
        _hash32(raw.get("hash"), "treasury snapshot block hash"),
        _u64(header.get("height"), "treasury snapshot block height"),
        _hash32(
            header.get("state_root_hash", header.get("stateRootHash")),
            "treasury snapshot state root",
        ),
    )


def _status_tip(response: object) -> tuple[str, int, str]:
    payload = _mapping(response, "treasury status response")
    result = _mapping(payload.get("result"), "treasury status result")
    if set(result) == {"name", "value"}:
        result = _mapping(result["value"], "treasury status value")
    if result.get("chainspec_name", result.get("chainspecName")) != NETWORK:
        raise NativeTransferInputError("treasury status network must be casper-test")
    tip = _mapping(result.get("last_added_block_info"), "treasury finalized tip")
    return (
        _hash32(tip.get("hash"), "treasury finalized tip hash"),
        _u64(tip.get("height"), "treasury finalized tip height"),
        NETWORK,
    )


def _verify_snapshot(
    raw: bytes,
) -> tuple[object, str, _Timestamp]:
    document = _strict_json(raw, "treasury snapshot")
    if (
        set(document)
        != {
            "schema_id",
            "network",
            "source_account_hash",
            "expected_balance_motes",
            "observations",
        }
        or document.get("network") != NETWORK
    ):
        raise NativeTransferInputError(
            "treasury snapshot fields or network are invalid"
        )
    source = _hash32(document.get("source_account_hash"), "treasury source account")
    if document.get("expected_balance_motes") != str(EXACT_TREASURY_BALANCE_MOTES):
        raise NativeTransferInputError(
            "treasury snapshot must prove the exact 625 CSPR baseline"
        )
    observations = document.get("observations")
    if type(observations) is not list or len(observations) != 2:
        raise NativeTransferInputError(
            "treasury snapshot requires exactly two node observations"
        )
    first = _mapping(observations[0], "treasury snapshot primary observation")
    block_hash, block_height, _ = _block_facts(first.get("block_response"))
    try:
        snapshot = verify_treasury_snapshot_artifact(
            document,
            expected_account_hash=bytes.fromhex(source),
            expected_block_hash=bytes.fromhex(block_hash),
            expected_block_height=block_height,
            expected_balance_motes=EXACT_TREASURY_BALANCE_MOTES,
        )
    except TreasurySnapshotError as exc:
        raise NativeTransferInputError("treasury snapshot did not verify") from exc
    capture_times: list[tuple[str, _Timestamp]] = []
    for index, (observation, proof) in enumerate(
        zip(observations, snapshot.observations, strict=True)
    ):
        item = _mapping(observation, f"treasury snapshot observation {index}")
        tip_hash, tip_height, _ = _status_tip(item.get("status_response"))
        if tip_height < block_height or (
            tip_height == block_height and tip_hash != block_hash
        ):
            raise NativeTransferInputError(
                "treasury snapshot block is not observed at a finalized node tip"
            )
        if (
            proof.available_balance_motes != EXACT_TREASURY_BALANCE_MOTES
            or proof.balance_holds_total_motes != 0
        ):
            raise NativeTransferInputError(
                "treasury snapshot has unavailable or held baseline funds"
            )
        capture_times.append(
            _timestamp(
                item.get("captured_at"),
                f"treasury snapshot observation {index} captured_at",
            )
        )
    captured_at, captured_time = max(capture_times, key=lambda item: item[1])
    return snapshot, captured_at, captured_time


def _verify_intent(
    raw: bytes,
    *,
    canonical_proposal_id: str,
    source_account: bytes,
) -> tuple[dict[str, object], str, _Timestamp]:
    intent = _strict_json(raw, "native transfer intent")
    if set(intent) != _INTENT_FIELDS or intent.get("schema_id") != INTENT_SCHEMA_ID:
        raise NativeTransferInputError(
            "native transfer intent fields do not match the frozen schema"
        )
    if intent.get("network") != NETWORK:
        raise NativeTransferInputError(
            "native transfer intent network must be casper-test"
        )
    intent_id = intent.get("intent_id")
    if type(intent_id) is not str or MACHINE_NAME_RE.fullmatch(intent_id) is None:
        raise NativeTransferInputError("native transfer intent_id is invalid")
    if intent.get("canonical_proposal_id") != canonical_proposal_id:
        raise NativeTransferInputError(
            "native transfer intent proposal differs from canonical receipt"
        )
    expected_source = _hash32(
        intent.get("source_account_hash"),
        "native transfer source account",
    )
    recipient = _hash32(
        intent.get("recipient_account_hash"),
        "native transfer recipient account",
    )
    if expected_source != source_account.hex():
        raise NativeTransferInputError(
            "native transfer source account differs from treasury snapshot"
        )
    if recipient == expected_source:
        raise NativeTransferInputError(
            "native transfer source and recipient must differ"
        )
    if intent.get("requested_allocation_bps") != EXACT_REQUESTED_ALLOCATION_BPS:
        raise NativeTransferInputError(
            "native transfer requested allocation must be exactly 3000 bps"
        )
    captured_at, captured_time = _timestamp(
        intent.get("captured_at"),
        "native transfer intent captured_at",
    )
    return (
        {
            "intent_id": intent_id,
            "recipient_account_hash": recipient,
        },
        captured_at,
        captured_time,
    )


def _evidence_entry(
    *,
    artifact_id: str,
    raw: bytes,
    artifact_kind: int,
    provenance_class: int,
    captured_at_unix_seconds: int,
) -> dict[str, object]:
    return {
        "artifact_id": artifact_id,
        "artifact_kind": str(artifact_kind),
        "content_sha256": _sha256(raw),
        "byte_length": str(len(raw)),
        "media_type": "application/json",
        "provenance_class": str(provenance_class),
        "captured_at_unix_seconds": str(captured_at_unix_seconds),
    }


def _derive_nonce_seed(
    entries: Sequence[Mapping[str, object]],
    *,
    evidence_root: bytes,
    metadata_root: bytes,
) -> bytes:
    ordered = sorted(entries, key=lambda item: str(item["artifact_id"]).encode("ascii"))
    preimage = bytearray(_SOURCE_SEED_DOMAIN)
    for entry in ordered:
        preimage.extend(length_prefix(str(entry["artifact_id"]), "artifact_id"))
        preimage.extend(bytes.fromhex(str(entry["content_sha256"])))
    preimage.extend(evidence_root)
    preimage.extend(metadata_root)
    return blake2b256(bytes(preimage))


def build_native_transfer_input(
    *,
    historical_receipt_bytes: bytes,
    historical_inventory_bytes: bytes,
    canonical_receipt_bytes: bytes,
    deployment_manifest_bytes: bytes,
    treasury_snapshot_bytes: bytes,
    intent_bytes: bytes,
) -> NativeTransferInputBuild:
    """Return the exact typed input plus a complete derivation manifest."""

    if type(historical_inventory_bytes) is not bytes or not historical_inventory_bytes:
        raise NativeTransferInputError("historical inventory bytes are unavailable")
    facts, receipt, receipt_captured_at, receipt_captured_time = (
        _verify_canonical_decision(
            historical_bytes=historical_receipt_bytes,
            inventory_bytes=historical_inventory_bytes,
            receipt_bytes=canonical_receipt_bytes,
        )
    )
    deployment, deployment_captured_at, deployment_captured_time = (
        _verify_v3_deployment(deployment_manifest_bytes)
    )
    snapshot, snapshot_captured_at, snapshot_captured_time = _verify_snapshot(
        treasury_snapshot_bytes
    )
    intent, intent_captured_at, intent_captured_time = _verify_intent(
        intent_bytes,
        canonical_proposal_id=str(receipt["proposal_id"]),
        source_account=snapshot.account_hash,
    )
    historical_captured_at, historical_captured_time = _timestamp(
        facts["capturedAt"],
        "historical receipt captured_at",
    )
    source_times = (
        historical_captured_time,
        receipt_captured_time,
        deployment_captured_time,
        snapshot_captured_time,
    )
    if intent_captured_time < max(source_times):
        raise NativeTransferInputError(
            "native transfer intent predates a required evidence artifact"
        )
    evidence_entries = [
        _evidence_entry(
            artifact_id="historical_odra_receipt",
            raw=historical_receipt_bytes,
            artifact_kind=7,
            provenance_class=0,
            captured_at_unix_seconds=historical_captured_time.unix_seconds,
        ),
        _evidence_entry(
            artifact_id="canonical_receipt",
            raw=canonical_receipt_bytes,
            artifact_kind=5,
            provenance_class=0,
            captured_at_unix_seconds=receipt_captured_time.unix_seconds,
        ),
        _evidence_entry(
            artifact_id="v3_deployment",
            raw=deployment_manifest_bytes,
            artifact_kind=7,
            provenance_class=1,
            captured_at_unix_seconds=deployment_captured_time.unix_seconds,
        ),
        _evidence_entry(
            artifact_id="treasury_snapshot",
            raw=treasury_snapshot_bytes,
            artifact_kind=7,
            provenance_class=7,
            captured_at_unix_seconds=snapshot_captured_time.unix_seconds,
        ),
        _evidence_entry(
            artifact_id="native_transfer_intent",
            raw=intent_bytes,
            artifact_kind=5,
            provenance_class=1,
            captured_at_unix_seconds=intent_captured_time.unix_seconds,
        ),
    ]
    try:
        evidence = encode_evidence_manifest(evidence_entries)
        metadata_entries = [
            {
                "name": "canonical_receipt_deploy_hash",
                "type": "Bytes32",
                "value": facts["deployHash"],
            },
            {
                "name": "historical_artifact_sha256",
                "type": "Bytes32",
                "value": _sha256(historical_receipt_bytes),
            },
            {
                "name": "historical_inventory_sha256",
                "type": "Bytes32",
                "value": _sha256(historical_inventory_bytes),
            },
            {
                "name": "intent_id",
                "type": "String",
                "value": intent["intent_id"],
            },
            {
                "name": "snapshot_artifact_sha256",
                "type": "Bytes32",
                "value": snapshot.artifact_sha256,
            },
            {
                "name": "snapshot_state_root_hash",
                "type": "Bytes32",
                "value": snapshot.state_root_hash.hex(),
            },
            {
                "name": "v3_contract_hash",
                "type": "Bytes32",
                "value": deployment["contract_hash"],
            },
            {
                "name": "v3_package_hash",
                "type": "Bytes32",
                "value": deployment["package_hash"],
            },
        ]
        metadata = encode_authorized_metadata(metadata_entries)
    except (ManifestEncodingError, ValueError) as exc:
        raise NativeTransferInputError(
            "subordinate evidence or metadata manifest is invalid"
        ) from exc
    seed = _derive_nonce_seed(
        evidence_entries,
        evidence_root=evidence.root,
        metadata_root=metadata.root,
    )
    proposal_nonce = blake2b256(_PROPOSAL_NONCE_DOMAIN + seed)
    action_nonce = blake2b256(_ACTION_NONCE_DOMAIN + seed)
    if (
        proposal_nonce == bytes(32)
        or action_nonce == bytes(32)
        or proposal_nonce == action_nonce
    ):
        raise NativeTransferInputError("derived v3 nonces are invalid")

    amount_motes = snapshot.balance_motes * EXACT_APPROVED_ALLOCATION_BPS // 10_000
    if (
        snapshot.balance_motes != EXACT_TREASURY_BALANCE_MOTES
        or amount_motes != EXACT_TRANSFER_MOTES
    ):
        raise NativeTransferInputError(
            "625 CSPR at 800 bps did not derive exactly 50 CSPR"
        )
    header: dict[str, object] = {
        "schema_version": "3",
        "deployment_domain": deployment["deployment_domain"],
        "casper_chain_name": NETWORK,
        "proposal_id": receipt["proposal_id"],
        "proposal_nonce": proposal_nonce.hex(),
        "decision_code": "2",
        "requested_allocation_bps": str(EXACT_REQUESTED_ALLOCATION_BPS),
        "approved_allocation_bps": str(EXACT_APPROVED_ALLOCATION_BPS),
        "action_kind": "1",
        "action_version": "1",
        "action_id": "00" * 32,
        "proposal_hash": receipt["proposal_hash"],
        "policy_hash": receipt["policy_hash"],
        "plan_hash": receipt["plan_hash"],
        "final_card_hash": receipt["final_card_hash"],
        "dissent_hash": receipt["dissent_hash"],
        "agent_action_hash": receipt["agent_action_hash"],
        "preauth_evidence_root": evidence.root.hex(),
        "authorized_metadata_root": metadata.root.hex(),
    }
    body: dict[str, object] = {
        "asset_kind": "0",
        "source_account": snapshot.account_hash.hex(),
        "recipient_account": intent["recipient_account_hash"],
        "amount_motes": str(amount_motes),
        "treasury_snapshot_balance_motes": str(snapshot.balance_motes),
        "snapshot_block_hash": snapshot.block_hash.hex(),
        "snapshot_block_height": str(snapshot.block_height),
        "transfer_id": "0",
        "action_nonce": action_nonce.hex(),
        "execution_target": "native-transfer",
        "execution_version": "1",
    }
    try:
        built_header, built_body, material = build_native_material(header, body)
    except ValueError as exc:
        raise NativeTransferInputError(
            "derived NativeTransferV1 input violates the frozen encoder"
        ) from exc
    typed_input = {
        "schema_id": TYPED_INPUT_SCHEMA_ID,
        "action": "NativeTransferV1",
        "header": built_header,
        "body": built_body,
    }
    input_sha256 = _sha256(render_json_bytes(typed_input))
    sources = [
        {
            "artifact_id": entry["artifact_id"],
            "sha256": entry["content_sha256"],
            "byte_length": entry["byte_length"],
            "captured_at_unix_seconds": entry["captured_at_unix_seconds"],
        }
        for entry in sorted(
            evidence_entries,
            key=lambda item: str(item["artifact_id"]).encode("ascii"),
        )
    ]
    derivation_manifest = {
        "schema_id": DERIVATION_SCHEMA_ID,
        "network": NETWORK,
        "input_filename": "typed-input.json",
        "input_sha256": input_sha256,
        "verification_authorities": {
            "historical_inventory_sha256": _sha256(historical_inventory_bytes),
            "historical_inventory_byte_length": str(len(historical_inventory_bytes)),
        },
        "sources": sources,
        "evidence_manifest": {
            "version": "1",
            "entries": evidence_entries,
            "canonical_hex": evidence.canonical_bytes.hex(),
            "root": evidence.root.hex(),
        },
        "authorized_metadata_manifest": {
            "version": "1",
            "entries": metadata_entries,
            "canonical_hex": metadata.canonical_bytes.hex(),
            "root": metadata.root.hex(),
        },
        "derived": {
            "historical_captured_at": historical_captured_at,
            "canonical_receipt_captured_at": receipt_captured_at,
            "deployment_captured_at": deployment_captured_at,
            "snapshot_captured_at": snapshot_captured_at,
            "intent_captured_at": intent_captured_at,
            "proposal_nonce": proposal_nonce.hex(),
            "action_nonce": action_nonce.hex(),
            "preauth_evidence_root": evidence.root.hex(),
            "authorized_metadata_root": metadata.root.hex(),
            "action_id": material.action_id.hex(),
            "transfer_id": str(material.transfer_id),
            "envelope_hash": material.envelope_hash.hex(),
            "amount_motes": str(amount_motes),
        },
    }
    return NativeTransferInputBuild(
        typed_input=typed_input,
        derivation_manifest=derivation_manifest,
    )


__all__ = [
    "DERIVATION_SCHEMA_ID",
    "EXACT_APPROVED_ALLOCATION_BPS",
    "EXACT_REQUESTED_ALLOCATION_BPS",
    "EXACT_TRANSFER_MOTES",
    "EXACT_TREASURY_BALANCE_MOTES",
    "INTENT_SCHEMA_ID",
    "NativeTransferInputBuild",
    "NativeTransferInputError",
    "build_native_transfer_input",
    "render_json_bytes",
]
