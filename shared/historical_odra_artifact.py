"""Strict offline verification of one historical Odra receipt artifact.

The artifact is an evidence bundle, not an assertion bundle.  This module
derives every returned fact from duplicate-key-free JSON, exact card
preimages, canonical Casper deploy bytes, and block-pinned state queries.  It
performs no network I/O and deliberately reports the preserved source to
deployed Wasm relationship as unproven.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pycspr import crypto, serializer
from pycspr.factory.digests import create_digest_of_deploy
from pycspr.types.cl import CLV_ByteArray, CLV_String, CLV_U32
from pycspr.types.node.rpc import (
    Deploy,
    DeployOfStoredContractByHash,
    DeployOfStoredContractByHashVersioned,
)

from shared.exact_casper_deploy_json import (
    canonical_deploy_rpc_json,
    exact_deploy_body_hash,
    normalize_deploy_rpc_json,
)


SCHEMA_VERSION = "concordia.historical_odra_receipt.v1"
INVENTORY_SCHEMA_VERSION = "concordia.historical_odra_inventory.v1"
CARD_CHAIN_SCHEMA_VERSION = "concordia.card_chain.v1"
FROZEN_INVENTORY_SHA256 = (
    "3c73db58180d19e3d91e360d650c6765023487e3c5b11b3a266d40e85dc26e4d"
)
PACKAGED_INVENTORY_PATH = (
    Path(__file__).resolve().parents[1] / "handoff" / "HISTORICAL_ODRA_RECEIPTS_V1.json"
)

MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_INVENTORY_BYTES = 256 * 1024
MAX_CARD_COUNT = 256
MAX_CARD_PREIMAGE_BYTES = 1024 * 1024
MAX_TOTAL_CARD_PREIMAGE_BYTES = 8 * 1024 * 1024

_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT40_RE = re.compile(r"^[0-9a-f]{40}$")
_PROPOSAL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_RFC3339_UTC_Z_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z$"
)
_RFC3339_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:Z|\+00:00)$"
)

_TOP_LEVEL_KEYS = {
    "schema_version",
    "proposal_id",
    "generation",
    "captured_at",
    "source_commit",
    "deployment_commit",
    "source_url",
    "network",
    "lineage_inventory",
    "contract_identity",
    "card_chain",
    "raw_rpc",
}
_RAW_RPC_KEYS = {"deploy", "canonical_block", "state_root", "package", "contract"}
_CONTRACT_IDENTITY_KEYS = {
    "package_hash",
    "contract_hash",
    "contract_wasm_state_hash",
    "contract_version",
    "protocol_version_major",
    "entry_point",
    "session_variant",
    "session_target_kind",
    "session_target_hash",
    "session_version",
}
_CARD_IDENTITY_FIELD = {
    "ProposalCard": "signal_id",
    "TriageDecision": "proposal_id",
    "Assessment": "proposal_id",
    "Verdict": "proposal_id",
    "ResponsePlan": "proposal_id",
    "StructuredApproval": "proposal_id",
    "PolicyAuthorization": "proposal_id",
    "CasperExecutionReceipt": "proposal_id",
    "GovernanceSummary": "proposal_id",
}
_ARGUMENT_TYPE_NAMES = {
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
}
_CL_VALUE_TYPES = {
    "String": CLV_String,
    "ByteArray(32)": CLV_ByteArray,
    "U32": CLV_U32,
}
_BYTE_ARRAY_ARGUMENTS = frozenset(
    {
        "proposal_hash",
        "final_card_hash",
        "plan_hash",
        "policy_hash",
        "dissent_hash",
        "agent_action_hash",
    }
)


class HistoricalOdraArtifactError(ValueError):
    """A present historical Odra artifact is malformed or contradictory."""


class HistoricalOdraArtifactUnavailable(HistoricalOdraArtifactError):
    """Required artifact or raw transcript evidence is absent."""


class _DuplicateJsonKey(ValueError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _strict_json(raw: object, *, label: str, limit: int) -> dict[str, Any]:
    if type(raw) is bytes:
        encoded = raw
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HistoricalOdraArtifactError(f"{label} is not UTF-8 JSON") from exc
    elif type(raw) is str:
        text = raw
        try:
            encoded = raw.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise HistoricalOdraArtifactError(f"{label} is not UTF-8 JSON") from exc
    else:
        raise HistoricalOdraArtifactError(f"{label} must be raw JSON bytes or text")
    if len(encoded) > limit:
        raise HistoricalOdraArtifactError(f"{label} exceeds size limit")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateJsonKey as exc:
        raise HistoricalOdraArtifactError(f"{label} contains a {exc}") from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise HistoricalOdraArtifactError(f"{label} is invalid JSON") from exc
    if type(value) is not dict:
        raise HistoricalOdraArtifactError(f"{label} must contain a JSON object")
    return value


def _object(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise HistoricalOdraArtifactError(f"{label} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise HistoricalOdraArtifactError(f"{label} fields must match the frozen schema exactly")


def _reject_asserted_summary_booleans(value: object) -> None:
    forbidden = {"passed", "processed", "chain_valid", "verified", "success"}
    if type(value) is dict:
        for key, child in value.items():
            if key in forbidden and type(child) is bool:
                raise HistoricalOdraArtifactError(
                    f"raw RPC contains forbidden asserted summary boolean: {key}"
                )
            _reject_asserted_summary_booleans(child)
    elif type(value) is list:
        for child in value:
            _reject_asserted_summary_booleans(child)


def _lower_hash(value: object, label: str, *, prefixes: Sequence[str] = ()) -> str:
    if type(value) is not str:
        raise HistoricalOdraArtifactError(f"{label} must be lowercase 32-byte hex")
    normalized = value
    for prefix in sorted(prefixes, key=len, reverse=True):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
            break
    if _HEX32_RE.fullmatch(normalized) is None:
        raise HistoricalOdraArtifactError(f"{label} must be lowercase 32-byte hex")
    return normalized


def _height(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise HistoricalOdraArtifactError(f"{label} must be a non-negative u64")
    return value


def _timestamp(value: object, label: str, *, utc_z: bool = True) -> str:
    pattern = _RFC3339_UTC_Z_RE if utc_z else _RFC3339_UTC_RE
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise HistoricalOdraArtifactError(f"{label} must be RFC3339 UTC")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise HistoricalOdraArtifactError(f"{label} must be RFC3339 UTC") from exc
    if parsed.utcoffset() != timedelta(0):
        raise HistoricalOdraArtifactError(f"{label} must be RFC3339 UTC")
    return value


def _public_artifact_url(value: object, proposal_id: str, suffix: str, label: str) -> str:
    if type(value) is not str or len(value.encode("utf-8")) > 2048:
        raise HistoricalOdraArtifactError(f"{label} is invalid")
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise HistoricalOdraArtifactError(f"{label} is invalid") from exc
    expected_path = f"/proof-artifacts/v1/{proposal_id}/{suffix}"
    if (
        parts.scheme != "https"
        or hostname is None
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or parts.path != expected_path
        or any(ord(character) < 0x20 for character in value)
    ):
        raise HistoricalOdraArtifactError(f"{label} is invalid")
    lower_host = hostname.casefold()
    if lower_host in {"localhost", "localhost.localdomain"} or lower_host.endswith(".local"):
        raise HistoricalOdraArtifactError(f"{label} must use a public host")
    try:
        address = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        if "." not in hostname:
            raise HistoricalOdraArtifactError(f"{label} must use a public host")
    else:
        if not address.is_global:
            raise HistoricalOdraArtifactError(f"{label} must use a public host")
    if port is not None and not 1 <= port <= 65535:  # pragma: no cover - urlsplit guards this
        raise HistoricalOdraArtifactError(f"{label} is invalid")
    return value


def _normalize_deploy_json(value: object) -> object:
    return normalize_deploy_rpc_json(value)


def _request_id(value: object, label: str) -> int | str:
    if type(value) not in (int, str) or value == "":
        raise HistoricalOdraArtifactError(f"{label} JSON-RPC id is invalid")
    return value


def _rpc(
    transcript: object,
    *,
    label: str,
    method: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    value = _object(transcript, f"{label} transcript")
    _exact_keys(value, {"request", "response"}, f"{label} transcript")
    request = _object(value["request"], f"{label} request")
    _exact_keys(request, {"jsonrpc", "id", "method", "params"}, f"{label} request")
    if request["jsonrpc"] != "2.0" or request["method"] != method:
        raise HistoricalOdraArtifactError(f"{label} request must call {method}")
    request_id = _request_id(request["id"], label)
    response = _object(value["response"], f"{label} response")
    _exact_keys(response, {"jsonrpc", "id", "result"}, f"{label} response")
    if response["jsonrpc"] != "2.0" or response["id"] != request_id:
        raise HistoricalOdraArtifactError(f"{label} response id does not match request id")
    result = _object(response["result"], f"{label} result")
    if "name" in result or "value" in result:
        _exact_keys(result, {"name", "value"}, f"{label} result")
        if type(result["name"]) is not str or result["name"] != f"{method}_result":
            raise HistoricalOdraArtifactError(f"{label} result wrapper is invalid")
        result = _object(result["value"], f"{label} result value")
    return request, result


def _load_inventory(
    lineage: object,
    inventory_bytes: bytes | None,
) -> tuple[dict[str, Any], bytes]:
    value = _object(lineage, "lineage_inventory")
    _exact_keys(
        value,
        {"schema_version", "sha256", "canonical_json"},
        "lineage_inventory",
    )
    if value["schema_version"] != INVENTORY_SCHEMA_VERSION:
        raise HistoricalOdraArtifactError("lineage inventory schema is invalid")
    if inventory_bytes is None:
        try:
            inventory_bytes = PACKAGED_INVENTORY_PATH.read_bytes()
        except OSError as exc:
            raise HistoricalOdraArtifactUnavailable(
                "packaged historical Odra inventory is unavailable"
            ) from exc
    if type(inventory_bytes) is not bytes or not inventory_bytes:
        raise HistoricalOdraArtifactUnavailable(
            "packaged historical Odra inventory is unavailable"
        )
    if len(inventory_bytes) > MAX_INVENTORY_BYTES:
        raise HistoricalOdraArtifactError("packaged inventory exceeds size limit")
    packaged_sha = hashlib.sha256(inventory_bytes).hexdigest()
    if not hmac.compare_digest(packaged_sha, FROZEN_INVENTORY_SHA256):
        raise HistoricalOdraArtifactError("packaged inventory hash does not match frozen inventory")
    canonical_json = value["canonical_json"]
    if type(canonical_json) is not str:
        raise HistoricalOdraArtifactError("lineage inventory canonical_json is invalid")
    try:
        canonical_bytes = canonical_json.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise HistoricalOdraArtifactError("lineage inventory canonical_json is invalid") from exc
    if not hmac.compare_digest(canonical_bytes, inventory_bytes):
        raise HistoricalOdraArtifactError("lineage inventory differs from packaged inventory")
    claimed_sha = _lower_hash(value["sha256"], "lineage inventory sha256")
    if not hmac.compare_digest(claimed_sha, packaged_sha):
        raise HistoricalOdraArtifactError("lineage inventory sha256 mismatch")
    inventory = _strict_json(
        inventory_bytes,
        label="packaged inventory",
        limit=MAX_INVENTORY_BYTES,
    )
    _exact_keys(
        inventory,
        {
            "schema_version",
            "network",
            "receipt_argument_types",
            "chain_identity",
            "preserved_repo_source",
        },
        "packaged inventory",
    )
    if inventory["schema_version"] != INVENTORY_SCHEMA_VERSION:
        raise HistoricalOdraArtifactError("packaged inventory schema is invalid")
    if inventory["network"] != "casper-test":
        raise HistoricalOdraArtifactError("packaged inventory network is invalid")
    argument_types = _object(
        inventory["receipt_argument_types"], "inventory receipt_argument_types"
    )
    if argument_types != _ARGUMENT_TYPE_NAMES:
        raise HistoricalOdraArtifactError(
            "inventory receipt_argument_types do not match the frozen 17 types"
        )
    chain_identity = _object(inventory["chain_identity"], "inventory chain_identity")
    _exact_keys(chain_identity, {"v1", "v2"}, "inventory chain_identity")
    preserved = _object(
        inventory["preserved_repo_source"], "inventory preserved_repo_source"
    )
    if preserved.get("source_deployment_equivalence") != "unproven":
        raise HistoricalOdraArtifactError(
            "source deployment equivalence must remain unproven"
        )
    return inventory, inventory_bytes


def _selected_identity(inventory: Mapping[str, Any], generation: str) -> dict[str, Any]:
    identity = _object(
        _object(inventory["chain_identity"], "inventory chain_identity").get(generation),
        f"inventory {generation} identity",
    )
    _exact_keys(
        identity,
        {
            "package_hash",
            "contract_hash",
            "contract_wasm_state_hash",
            "contract_version",
            "protocol_version_major",
            "install_deploy_hash",
            "install_block_height",
            "entry_point",
            "accepted_session",
            "receipt_deploys",
        },
        f"inventory {generation} identity",
    )
    for field in (
        "package_hash",
        "contract_hash",
        "contract_wasm_state_hash",
        "install_deploy_hash",
    ):
        _lower_hash(identity[field], f"inventory {generation} {field}")
    if (
        identity["contract_version"] != 1
        or identity["protocol_version_major"] != 2
        or identity["entry_point"] != "store_governance_receipt"
    ):
        raise HistoricalOdraArtifactError(f"inventory {generation} identity is invalid")
    _height(identity["install_block_height"], f"inventory {generation} install block height")
    session = _object(identity["accepted_session"], f"inventory {generation} accepted_session")
    _exact_keys(
        session,
        {
            "variant",
            "target_kind",
            "target_hash",
            "version",
            "final_card_hash",
            "card_chain_binding",
            "argument_order",
        },
        f"inventory {generation} accepted_session",
    )
    expected_session = (
        {
            "variant": "StoredContractByHash",
            "target_kind": "contract",
            "target_hash": identity["contract_hash"],
            "version": None,
            "card_chain_binding": "canonical_export_required",
        }
        if generation == "v1"
        else {
            "variant": "StoredVersionedContractByHash",
            "target_kind": "package",
            "target_hash": identity["package_hash"],
            "version": 1,
            "card_chain_binding": "separate_export_required",
        }
    )
    for field, expected in expected_session.items():
        if session[field] != expected:
            raise HistoricalOdraArtifactError(
                f"inventory {generation} accepted session {field} is invalid"
            )
    _lower_hash(session["target_hash"], f"inventory {generation} session target hash")
    _lower_hash(session["final_card_hash"], f"inventory {generation} final card hash")
    order = session["argument_order"]
    if (
        type(order) is not list
        or len(order) != 17
        or any(type(name) is not str for name in order)
    ):
        raise HistoricalOdraArtifactError(
            f"inventory {generation} argument order is not the exact 17-argument schema"
        )
    if len(set(order)) != 17 or set(order) != set(_ARGUMENT_TYPE_NAMES):
        raise HistoricalOdraArtifactError(
            f"inventory {generation} argument order is not the exact 17-argument schema"
        )
    receipt_deploys = _object(
        identity["receipt_deploys"], f"inventory {generation} receipt_deploys"
    )
    expected_receipt_keys = (
        {"canonical_accepted"}
        if generation == "v1"
        else {"pre_quorum_expected_rejection", "post_quorum_accepted"}
    )
    _exact_keys(receipt_deploys, expected_receipt_keys, f"inventory {generation} receipts")
    for name, deploy_hash in receipt_deploys.items():
        _lower_hash(deploy_hash, f"inventory {generation} receipt {name}")
    return identity


def _verify_contract_identity(value: object, identity: Mapping[str, Any]) -> None:
    contract = _object(value, "contract_identity")
    _exact_keys(contract, _CONTRACT_IDENTITY_KEYS, "contract_identity")
    session = _object(identity["accepted_session"], "inventory accepted_session")
    expected = {
        "package_hash": identity["package_hash"],
        "contract_hash": identity["contract_hash"],
        "contract_wasm_state_hash": identity["contract_wasm_state_hash"],
        "contract_version": identity["contract_version"],
        "protocol_version_major": identity["protocol_version_major"],
        "entry_point": identity["entry_point"],
        "session_variant": session["variant"],
        "session_target_kind": session["target_kind"],
        "session_target_hash": session["target_hash"],
        "session_version": session["version"],
    }
    if any(
        type(contract[key]) is not type(expected[key]) or contract[key] != expected[key]
        for key in expected
    ):
        raise HistoricalOdraArtifactError(
            "contract_identity does not match packaged inventory"
        )


def _parse_preimage(raw: object, sequence: int) -> tuple[str, dict[str, Any]]:
    if type(raw) is not str:
        raise HistoricalOdraArtifactError(
            f"card {sequence} canonical_card_json must be text"
        )
    try:
        encoded = raw.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise HistoricalOdraArtifactError(
            f"card {sequence} canonical_card_json must be UTF-8"
        ) from exc
    if len(encoded) > MAX_CARD_PREIMAGE_BYTES:
        raise HistoricalOdraArtifactError(f"card {sequence} preimage exceeds size limit")
    return raw, _strict_json(
        raw,
        label=f"card {sequence} canonical_card_json",
        limit=MAX_CARD_PREIMAGE_BYTES,
    )


def _verify_card_chain(value: object, proposal_id: str) -> str:
    chain = _object(value, "card_chain")
    _exact_keys(
        chain,
        {"schema_version", "proposal_id", "captured_at", "source_url", "cards"},
        "card_chain",
    )
    if chain["schema_version"] != CARD_CHAIN_SCHEMA_VERSION:
        raise HistoricalOdraArtifactError("card_chain schema is invalid")
    if chain["proposal_id"] != proposal_id:
        raise HistoricalOdraArtifactError("card_chain proposal does not match artifact")
    _timestamp(chain["captured_at"], "card_chain captured_at")
    _public_artifact_url(chain["source_url"], proposal_id, "card-chain", "card_chain source_url")
    cards = chain["cards"]
    if type(cards) is not list or not cards:
        raise HistoricalOdraArtifactError("card_chain cards must be non-empty")
    if len(cards) > MAX_CARD_COUNT:
        raise HistoricalOdraArtifactError("card_chain card-count limit exceeded")
    previous_hash: str | None = None
    total_bytes = 0
    for expected_sequence, raw_card in enumerate(cards, start=1):
        card = _object(raw_card, f"card {expected_sequence}")
        _exact_keys(
            card,
            {
                "sequence_number",
                "card_type",
                "card_hash",
                "canonical_card_json",
                "published_at",
            },
            f"card {expected_sequence}",
        )
        if (
            type(card["sequence_number"]) is not int
            or card["sequence_number"] != expected_sequence
        ):
            raise HistoricalOdraArtifactError("card sequence is not exactly contiguous")
        card_type = card["card_type"]
        if type(card_type) is not str or card_type not in _CARD_IDENTITY_FIELD:
            raise HistoricalOdraArtifactError(f"card {expected_sequence} card_type is invalid")
        if expected_sequence == 1 and card_type != "ProposalCard":
            raise HistoricalOdraArtifactError("first card must be ProposalCard")
        if expected_sequence > 1 and card_type == "ProposalCard":
            raise HistoricalOdraArtifactError("only the first card may be ProposalCard")
        card_hash = _lower_hash(card["card_hash"], f"card {expected_sequence} card_hash")
        canonical, parsed = _parse_preimage(card["canonical_card_json"], expected_sequence)
        total_bytes += len(canonical.encode("utf-8"))
        if total_bytes > MAX_TOTAL_CARD_PREIMAGE_BYTES:
            raise HistoricalOdraArtifactError("card_chain preimages exceed total size limit")
        computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(computed, card_hash):
            raise HistoricalOdraArtifactError(f"card {expected_sequence} card_hash mismatch")
        if "card_hash" in parsed:
            raise HistoricalOdraArtifactError(
                f"card {expected_sequence} preimage must exclude card_hash"
            )
        if (
            type(parsed.get("sequence_number")) is not int
            or parsed["sequence_number"] != expected_sequence
        ):
            raise HistoricalOdraArtifactError(
                f"card {expected_sequence} sequence_number does not match wrapper"
            )
        if parsed.get("card_type") != card_type:
            raise HistoricalOdraArtifactError(
                f"card {expected_sequence} card_type does not match wrapper"
            )
        identity_field = _CARD_IDENTITY_FIELD[card_type]
        if parsed.get(identity_field) != proposal_id:
            raise HistoricalOdraArtifactError(
                f"card {expected_sequence} proposal identity does not match artifact"
            )
        if "previous_card_hash" not in parsed or parsed["previous_card_hash"] != previous_hash:
            raise HistoricalOdraArtifactError(
                f"card {expected_sequence} previous_card_hash does not match prior card"
            )
        published_at = card["published_at"]
        if published_at is not None:
            _timestamp(published_at, f"card {expected_sequence} published_at", utc_z=False)
        previous_hash = card_hash
    return previous_hash or ""  # non-empty cards are required above


def _accepted_receipt_hash(identity: Mapping[str, Any], generation: str) -> str:
    receipts = _object(identity["receipt_deploys"], "inventory receipt_deploys")
    key = "canonical_accepted" if generation == "v1" else "post_quorum_accepted"
    return _lower_hash(receipts[key], f"inventory {generation} accepted receipt deploy")


def _verify_runtime_arguments(
    deploy: Deploy,
    *,
    proposal_id: str,
    argument_order: Sequence[str],
    argument_types: Mapping[str, str],
) -> tuple[str, str]:
    arguments = deploy.session.arguments
    if len(arguments) != 17:
        raise HistoricalOdraArtifactError("receipt must contain exactly 17 runtime arguments")
    actual_names = [argument.name for argument in arguments]
    if actual_names != list(argument_order):
        raise HistoricalOdraArtifactError(
            "receipt runtime arguments must use the exact frozen ordered names"
        )
    for argument in arguments:
        expected_name = argument.name
        type_name = argument_types.get(expected_name)
        expected_type = _CL_VALUE_TYPES.get(type_name or "")
        if expected_type is None:
            raise HistoricalOdraArtifactError(
                f"receipt argument {expected_name} has no frozen CL type"
            )
        if type(argument.value) is not expected_type:
            raise HistoricalOdraArtifactError(
                f"receipt argument {expected_name} has the wrong CL type"
            )
        if expected_name in _BYTE_ARRAY_ARGUMENTS and len(argument.value.value) != 32:
            raise HistoricalOdraArtifactError(
                f"receipt argument {expected_name} must be ByteArray(32)"
            )
    values = {argument.name: argument.value.value for argument in arguments}
    if values["proposal_id"] != proposal_id:
        raise HistoricalOdraArtifactError("receipt proposal_id does not match artifact")
    if values["casper_network"] != "casper-test":
        raise HistoricalOdraArtifactError("receipt casper_network must be casper-test")
    final_card_hash = bytes(values["final_card_hash"]).hex()
    argument_bytes = len(arguments).to_bytes(4, "little") + b"".join(
        serializer.to_bytes(argument) for argument in arguments
    )
    return final_card_hash, hashlib.sha256(argument_bytes).hexdigest()


def _approval_signer_bytes(value: object) -> bytes:
    if type(value) is bytes:
        signer = value
    else:
        signer = getattr(value, "account_key", None)
    if type(signer) is not bytes or len(signer) not in (33, 34):
        raise HistoricalOdraArtifactError("approval signer public key is invalid")
    return signer


def _verify_deploy(
    transcript: object,
    *,
    accepted_deploy_hash: str,
    proposal_id: str,
    entry_point: str,
    session: Mapping[str, Any],
    argument_types: Mapping[str, str],
) -> tuple[str, str, int, str, str]:
    request, result = _rpc(transcript, label="deploy", method="info_get_deploy")
    params = _object(request["params"], "deploy request params")
    allowed_params = (
        {"deploy_hash": accepted_deploy_hash},
        {"deploy_hash": accepted_deploy_hash, "finalized_approvals": True},
    )
    if params not in allowed_params:
        raise HistoricalOdraArtifactError(
            "deploy request must select the exact accepted frozen receipt deploy"
        )
    _exact_keys(result, {"api_version", "deploy", "execution_info"}, "deploy result")
    if type(result["api_version"]) is not str or not result["api_version"]:
        raise HistoricalOdraArtifactError("deploy result api_version is invalid")
    raw_deploy = _object(result["deploy"], "returned deploy")
    _exact_keys(
        raw_deploy,
        {"approvals", "hash", "header", "payment", "session"},
        "returned deploy",
    )
    try:
        deploy = serializer.from_json(dict(raw_deploy), Deploy)
        canonical_json = canonical_deploy_rpc_json(deploy)
    except Exception as exc:
        raise HistoricalOdraArtifactError("returned deploy is not canonical Casper JSON") from exc
    if _normalize_deploy_json(canonical_json) != _normalize_deploy_json(raw_deploy):
        raise HistoricalOdraArtifactError(
            "returned deploy JSON disagrees with canonical Casper encoding"
        )
    if deploy.header.chain_name != "casper-test":
        raise HistoricalOdraArtifactError("receipt deploy chain must be casper-test")
    session_variant = session["variant"]
    if session_variant == "StoredContractByHash":
        if type(deploy.session) is not DeployOfStoredContractByHash:
            raise HistoricalOdraArtifactError(
                "receipt deploy does not use the frozen StoredContractByHash session"
            )
    elif session_variant == "StoredVersionedContractByHash":
        if type(deploy.session) is not DeployOfStoredContractByHashVersioned:
            raise HistoricalOdraArtifactError(
                "receipt deploy does not use the frozen StoredVersionedContractByHash session"
            )
        if deploy.session.version != session["version"]:
            raise HistoricalOdraArtifactError("receipt deploy targets a different session version")
    else:  # guarded by the inventory parser
        raise HistoricalOdraArtifactError("receipt session variant is invalid")
    if deploy.session.hash.hex() != session["target_hash"]:
        raise HistoricalOdraArtifactError("receipt deploy targets a different frozen session hash")
    if deploy.session.entry_point != entry_point:
        raise HistoricalOdraArtifactError("receipt deploy targets a different entry point")
    final_card_hash, argument_digest = _verify_runtime_arguments(
        deploy,
        proposal_id=proposal_id,
        argument_order=session["argument_order"],
        argument_types=argument_types,
    )
    body_hash = exact_deploy_body_hash(deploy)
    if deploy.header.body_hash != body_hash:
        raise HistoricalOdraArtifactError("receipt deploy body hash mismatch")
    deploy_hash = create_digest_of_deploy(deploy.header)
    if deploy.hash != deploy_hash:
        raise HistoricalOdraArtifactError("receipt deploy hash mismatch")
    if not hmac.compare_digest(deploy_hash.hex(), accepted_deploy_hash):
        raise HistoricalOdraArtifactError("returned deploy is not the frozen accepted receipt")
    if not deploy.approvals:
        raise HistoricalOdraArtifactError("receipt deploy has no approval signatures")
    seen_signers: set[bytes] = set()
    for approval in deploy.approvals:
        signer = _approval_signer_bytes(approval.signer)
        if signer in seen_signers:
            raise HistoricalOdraArtifactError("receipt deploy has a duplicate approval signer")
        seen_signers.add(signer)
        try:
            valid = crypto.verify_deploy_approval_signature(
                deploy_hash,
                approval.signature,
                signer,
            )
        except Exception as exc:
            raise HistoricalOdraArtifactError("receipt deploy approval signature is invalid") from exc
        if not valid:
            raise HistoricalOdraArtifactError("receipt deploy approval signature is invalid")
    execution_info = _object(result["execution_info"], "deploy execution_info")
    _exact_keys(
        execution_info,
        {"block_hash", "block_height", "execution_result"},
        "deploy execution_info",
    )
    block_hash = _lower_hash(execution_info["block_hash"], "execution block hash")
    block_height = _height(execution_info["block_height"], "execution block height")
    execution_result = _object(
        execution_info["execution_result"], "deploy execution_result"
    )
    _exact_keys(execution_result, {"Version2"}, "deploy execution_result")
    outcome = _object(execution_result["Version2"], "Version2 execution result")
    _exact_keys(
        outcome,
        {
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
        },
        "Version2 execution result",
    )
    expected_initiator = {"PublicKey": deploy.header.account.account_key.hex()}
    if outcome["initiator"] != expected_initiator:
        raise HistoricalOdraArtifactError("execution initiator differs from deploy initiator")
    if outcome["error_message"] is not None:
        raise HistoricalOdraArtifactError("receipt execution failed")
    if type(outcome["transfers"]) is not list or type(outcome["effects"]) is not list:
        raise HistoricalOdraArtifactError("execution transfers/effects are malformed")
    return deploy_hash.hex(), block_hash, block_height, final_card_hash, argument_digest


def _unwrap_block(result: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    has_signed = "block_with_signatures" in result
    has_block = "block" in result
    if has_signed == has_block:
        raise HistoricalOdraArtifactError("canonical block result is ambiguous or missing")
    if has_signed:
        wrapper = _object(result["block_with_signatures"], "canonical block wrapper")
        _exact_keys(wrapper, {"block", "proofs"}, "canonical block wrapper")
        if type(wrapper["proofs"]) is not list:
            raise HistoricalOdraArtifactError("canonical block proofs are malformed")
        raw_block = _object(wrapper["block"], "canonical block")
    else:
        raw_block = _object(result["block"], "canonical block")
    versions = [name for name in ("Version1", "Version2") if name in raw_block]
    if versions:
        if len(versions) != 1 or len(raw_block) != 1:
            raise HistoricalOdraArtifactError("canonical block version is ambiguous")
        return _object(raw_block[versions[0]], "canonical block"), versions[0]
    return raw_block, "Legacy"


def _block_inclusion_count(body: Mapping[str, Any], version: str, deploy_hash: str) -> int:
    count = 0
    if version in {"Legacy", "Version1"}:
        for name in ("deploy_hashes", "transfer_hashes"):
            values = body.get(name, [])
            if type(values) is not list:
                raise HistoricalOdraArtifactError("canonical block hash lists are malformed")
            count += sum(
                _lower_hash(value, f"canonical block {name} entry") == deploy_hash
                for value in values
            )
        return count
    transactions = _object(body.get("transactions"), "canonical block transactions")
    for lane, raw_items in transactions.items():
        if type(lane) is not str or type(raw_items) is not list:
            raise HistoricalOdraArtifactError("canonical block transactions are malformed")
        for raw_item in raw_items:
            item = _object(raw_item, "canonical block transaction")
            variants = [name for name in ("Deploy", "Version1") if name in item]
            if len(variants) != 1 or len(item) != 1:
                raise HistoricalOdraArtifactError("canonical block transaction is malformed")
            if _lower_hash(item[variants[0]], "canonical block transaction hash") == deploy_hash:
                count += 1
    return count


def _verify_block(
    transcript: object,
    *,
    deploy_hash: str,
    block_hash: str,
    block_height: int,
) -> str:
    request, result = _rpc(
        transcript,
        label="canonical block",
        method="chain_get_block",
    )
    if request["params"] != {"block_identifier": {"Hash": block_hash}}:
        raise HistoricalOdraArtifactError(
            "canonical block request block hash does not match execution"
        )
    block, version = _unwrap_block(result)
    returned_hash = _lower_hash(block.get("hash"), "canonical block hash")
    if not hmac.compare_digest(returned_hash, block_hash):
        raise HistoricalOdraArtifactError("canonical block hash does not match execution")
    header = _object(block.get("header"), "canonical block header")
    if _height(header.get("height"), "canonical block height") != block_height:
        raise HistoricalOdraArtifactError("canonical block height does not match execution")
    state_roots = [
        header[name]
        for name in ("state_root_hash", "stateRootHash")
        if name in header
    ]
    if len(state_roots) != 1:
        raise HistoricalOdraArtifactError("canonical block state root is ambiguous or missing")
    state_root = _lower_hash(state_roots[0], "canonical block state root")
    body = _object(block.get("body"), "canonical block body")
    if _block_inclusion_count(body, version, deploy_hash) != 1:
        raise HistoricalOdraArtifactError(
            "receipt deploy must appear exactly once in canonical block"
        )
    return state_root


def _verify_state_root(transcript: object, *, block_hash: str, expected: str) -> None:
    request, result = _rpc(
        transcript,
        label="state root",
        method="chain_get_state_root_hash",
    )
    if request["params"] != {"block_identifier": {"Hash": block_hash}}:
        raise HistoricalOdraArtifactError(
            "state root request block hash does not match execution"
        )
    root = _lower_hash(result.get("state_root_hash"), "returned state root")
    if not hmac.compare_digest(root, expected):
        raise HistoricalOdraArtifactError("returned state root does not match canonical block")


def _state_value(
    transcript: object,
    *,
    label: str,
    state_root: str,
    key: str,
) -> dict[str, Any]:
    request, result = _rpc(transcript, label=label, method="query_global_state")
    expected_params = {
        "state_identifier": {"StateRootHash": state_root},
        "key": key,
        "path": [],
    }
    if request["params"] != expected_params:
        raise HistoricalOdraArtifactError(
            f"{label} request is not pinned to the exact state root and key"
        )
    return _object(result.get("stored_value"), f"{label} stored_value")


def _verify_package(
    transcript: object,
    *,
    state_root: str,
    package_hash: str,
    contract_hash: str,
    contract_version: int,
    protocol_version_major: int,
) -> None:
    stored = _state_value(
        transcript,
        label="package",
        state_root=state_root,
        key="hash-" + package_hash,
    )
    package = _object(stored.get("ContractPackage"), "package ContractPackage")
    versions = package.get("versions")
    if type(versions) is not list or not versions:
        raise HistoricalOdraArtifactError("package has no contract versions")
    selected = []
    seen_versions: set[tuple[int, int]] = set()
    for raw_version in versions:
        version = _object(raw_version, "package version")
        _exact_keys(
            version,
            {"protocol_version_major", "contract_version", "contract_hash"},
            "package version",
        )
        protocol_major = _height(
            version["protocol_version_major"], "package protocol version major"
        )
        contract_number = _height(version["contract_version"], "package contract version")
        version_key = (protocol_major, contract_number)
        if version_key in seen_versions:
            raise HistoricalOdraArtifactError("package contains duplicate contract versions")
        seen_versions.add(version_key)
        if version_key == (protocol_version_major, contract_version):
            selected.append(version)
    if len(selected) != 1:
        raise HistoricalOdraArtifactError(
            "package does not contain exactly the frozen protocol/contract version"
        )
    selected_hash = _lower_hash(
        selected[0]["contract_hash"],
        "package selected contract hash",
        prefixes=("contract-", "hash-"),
    )
    if not hmac.compare_digest(selected_hash, contract_hash):
        raise HistoricalOdraArtifactError("package selected contract hash is invalid")
    disabled = package.get("disabled_versions")
    if type(disabled) is not list:
        raise HistoricalOdraArtifactError("package disabled_versions is malformed")
    for raw_disabled in disabled:
        disabled_version = _object(raw_disabled, "package disabled version")
        if (
            disabled_version.get("protocol_version_major") == protocol_version_major
            and disabled_version.get("contract_version") == contract_version
        ):
            raise HistoricalOdraArtifactError("frozen package contract version is disabled")


def _verify_contract_state(
    transcript: object,
    *,
    state_root: str,
    package_hash: str,
    contract_hash: str,
    wasm_hash: str,
    protocol_version_major: int,
) -> None:
    stored = _state_value(
        transcript,
        label="contract",
        state_root=state_root,
        key="hash-" + contract_hash,
    )
    contract = _object(stored.get("Contract"), "contract stored value")
    returned_package = _lower_hash(
        contract.get("contract_package_hash"),
        "contract package ownership",
        prefixes=("contract-package-", "package-", "hash-"),
    )
    if not hmac.compare_digest(returned_package, package_hash):
        raise HistoricalOdraArtifactError("contract package ownership is invalid")
    returned_wasm = _lower_hash(
        contract.get("contract_wasm_hash"),
        "contract Wasm state hash",
        prefixes=("contract-wasm-", "wasm-", "hash-"),
    )
    if not hmac.compare_digest(returned_wasm, wasm_hash):
        raise HistoricalOdraArtifactError("contract Wasm state hash is invalid")
    protocol_version = contract.get("protocol_version")
    if type(protocol_version) is not str:
        raise HistoricalOdraArtifactError("contract protocol_version is missing")
    try:
        returned_major = int(protocol_version.split(".", 1)[0])
    except ValueError as exc:
        raise HistoricalOdraArtifactError("contract protocol_version is invalid") from exc
    if returned_major != protocol_version_major:
        raise HistoricalOdraArtifactError("contract protocol major is invalid")


def verify_historical_odra_artifact(
    raw_json: bytes | str | None,
    *,
    inventory_bytes: bytes | None = None,
) -> dict[str, object]:
    """Validate raw evidence and return only independently derived facts.

    ``raw_json`` must be the original JSON bytes or text so duplicate keys can
    be rejected before any value is consumed.  ``inventory_bytes`` exists for
    deterministic packaging/tests; regardless of source, its SHA-256 must equal
    :data:`FROZEN_INVENTORY_SHA256` and the embedded canonical string must be
    byte-identical to it.
    """

    if raw_json is None:
        raise HistoricalOdraArtifactUnavailable(
            "historical Odra receipt artifact is unavailable"
        )
    document = _strict_json(
        raw_json,
        label="historical Odra artifact",
        limit=MAX_ARTIFACT_BYTES,
    )
    raw_rpc_value = document.get("raw_rpc")
    if type(raw_rpc_value) is dict:
        missing = _RAW_RPC_KEYS - set(raw_rpc_value)
        if missing:
            names = ", ".join(sorted(missing))
            raise HistoricalOdraArtifactUnavailable(
                f"historical Odra raw evidence is unavailable: {names}"
            )
    elif "raw_rpc" not in document:
        raise HistoricalOdraArtifactUnavailable(
            "historical Odra raw evidence is unavailable: raw_rpc"
        )
    _exact_keys(document, _TOP_LEVEL_KEYS, "historical Odra top-level")
    raw_rpc = _object(document["raw_rpc"], "raw_rpc")
    _exact_keys(raw_rpc, _RAW_RPC_KEYS, "raw_rpc")
    _reject_asserted_summary_booleans(raw_rpc)
    if document["schema_version"] != SCHEMA_VERSION:
        raise HistoricalOdraArtifactError("historical Odra schema_version is invalid")
    proposal_id = document["proposal_id"]
    if type(proposal_id) is not str or _PROPOSAL_ID_RE.fullmatch(proposal_id) is None:
        raise HistoricalOdraArtifactError("proposal_id is invalid")
    generation = document["generation"]
    if generation not in {"v1", "v2"}:
        raise HistoricalOdraArtifactError("generation must be exactly v1 or v2")
    captured_at = _timestamp(document["captured_at"], "captured_at")
    source_commit = document["source_commit"]
    deployment_commit = document["deployment_commit"]
    if type(source_commit) is not str or _GIT40_RE.fullmatch(source_commit) is None:
        raise HistoricalOdraArtifactError("source_commit must be lowercase git40")
    if (
        type(deployment_commit) is not str
        or _GIT40_RE.fullmatch(deployment_commit) is None
    ):
        raise HistoricalOdraArtifactError("deployment_commit must be lowercase git40")
    _public_artifact_url(
        document["source_url"],
        proposal_id,
        "historical-odra-receipt",
        "source_url",
    )
    if document["network"] != "casper-test":
        raise HistoricalOdraArtifactError("network must be exactly casper-test")
    inventory, _ = _load_inventory(document["lineage_inventory"], inventory_bytes)
    identity = _selected_identity(inventory, generation)
    _verify_contract_identity(document["contract_identity"], identity)
    session = _object(identity["accepted_session"], "inventory accepted_session")
    if generation == "v2":
        raise HistoricalOdraArtifactUnavailable(
            "v2 combined proof is unavailable until a separate matching exact card chain exists"
        )
    package_hash = str(identity["package_hash"])
    contract_hash = str(identity["contract_hash"])
    wasm_hash = str(identity["contract_wasm_state_hash"])
    terminal_card_hash = _verify_card_chain(document["card_chain"], proposal_id)
    inventory_final_card_hash = str(session["final_card_hash"])
    if not hmac.compare_digest(terminal_card_hash, inventory_final_card_hash):
        raise HistoricalOdraArtifactError(
            "card chain terminal hash does not match frozen final_card_hash"
        )
    accepted_deploy_hash = _accepted_receipt_hash(identity, generation)
    (
        deploy_hash,
        execution_block_hash,
        execution_block_height,
        receipt_final_card_hash,
        receipt_argument_digest,
    ) = _verify_deploy(
        raw_rpc["deploy"],
        accepted_deploy_hash=accepted_deploy_hash,
        proposal_id=proposal_id,
        entry_point=str(identity["entry_point"]),
        session=session,
        argument_types=_object(
            inventory["receipt_argument_types"], "inventory receipt_argument_types"
        ),
    )
    if not hmac.compare_digest(receipt_final_card_hash, terminal_card_hash):
        raise HistoricalOdraArtifactError(
            "receipt final_card_hash does not match terminal card"
        )
    state_root = _verify_block(
        raw_rpc["canonical_block"],
        deploy_hash=deploy_hash,
        block_hash=execution_block_hash,
        block_height=execution_block_height,
    )
    _verify_state_root(
        raw_rpc["state_root"],
        block_hash=execution_block_hash,
        expected=state_root,
    )
    _verify_package(
        raw_rpc["package"],
        state_root=state_root,
        package_hash=package_hash,
        contract_hash=contract_hash,
        contract_version=int(identity["contract_version"]),
        protocol_version_major=int(identity["protocol_version_major"]),
    )
    _verify_contract_state(
        raw_rpc["contract"],
        state_root=state_root,
        package_hash=package_hash,
        contract_hash=contract_hash,
        wasm_hash=wasm_hash,
        protocol_version_major=int(identity["protocol_version_major"]),
    )
    return {
        "proposalId": proposal_id,
        "generation": generation,
        "deployHash": deploy_hash,
        "blockHash": execution_block_hash,
        "blockHeight": execution_block_height,
        "stateRootHash": state_root,
        "packageHash": package_hash,
        "contractHash": contract_hash,
        "contractWasmStateHash": wasm_hash,
        "sessionVariant": session["variant"],
        "sessionTargetKind": session["target_kind"],
        "sessionTargetHash": session["target_hash"],
        "sessionVersion": session["version"],
        "finalCardHash": terminal_card_hash,
        "receiptArgumentDigest": receipt_argument_digest,
        "sourceCommit": source_commit,
        "deploymentCommit": deployment_commit,
        "capturedAt": captured_at,
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


def load_and_verify_historical_odra_artifact(
    path: str | Path,
    *,
    inventory_path: str | Path = PACKAGED_INVENTORY_PATH,
) -> dict[str, object]:
    """Load one local artifact and classify missing files as unavailable."""

    try:
        raw_json = Path(path).read_bytes()
    except OSError as exc:
        raise HistoricalOdraArtifactUnavailable(
            "historical Odra receipt artifact is unavailable"
        ) from exc
    try:
        inventory_bytes = Path(inventory_path).read_bytes()
    except OSError as exc:
        raise HistoricalOdraArtifactUnavailable(
            "packaged historical Odra inventory is unavailable"
        ) from exc
    return verify_historical_odra_artifact(raw_json, inventory_bytes=inventory_bytes)


verify_historical_odra_receipt_artifact = verify_historical_odra_artifact


__all__ = [
    "FROZEN_INVENTORY_SHA256",
    "HistoricalOdraArtifactError",
    "HistoricalOdraArtifactUnavailable",
    "PACKAGED_INVENTORY_PATH",
    "load_and_verify_historical_odra_artifact",
    "verify_historical_odra_artifact",
    "verify_historical_odra_receipt_artifact",
]
