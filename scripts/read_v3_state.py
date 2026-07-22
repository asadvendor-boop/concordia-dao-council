#!/usr/bin/env python3
"""State-root-pinned, transcript-backed Concordia v3 chain readback.

No caller boolean is accepted as evidence.  Persisted artifacts contain the raw
JSON-RPC request/response pairs.  Runtime consumers receive an opaque,
process-sealed object only after those pairs are reparsed and cross-checked.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import json
import secrets
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

import httpx


SCHEMA_ID = "concordia.v3-chain-readback.v1"
CHECKPOINT_SCHEMA_ID = "concordia.v3-checkpoint-state-readback.v1"
NETWORK = "casper-test"
_PROCESS_SEAL_KEY = secrets.token_bytes(32)
_FACTORY_TOKEN = object()


class ReadbackValidationError(ValueError):
    pass


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _hex32(value: object, field: str) -> bytes:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        raise ReadbackValidationError(f"{field}: exact lowercase Bytes32 required")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise ReadbackValidationError(f"{field}: invalid hexadecimal") from exc
    if result == bytes(32):
        raise ReadbackValidationError(f"{field}: zero value is not proof")
    return result


def _mapping_key(index: int, mapping_key: bytes) -> bytes:
    if type(index) is not int or not 0 <= index <= 255:
        raise ReadbackValidationError("Odra storage index must be a u8")
    if not isinstance(mapping_key, bytes):
        raise ReadbackValidationError("Odra mapping key must be bytes")
    path = index.to_bytes(4, "big") if index <= 15 else bytes((0xFF, 1, index))
    return path + mapping_key


def state_dictionary_key(index: int, mapping_key: bytes = b"") -> str:
    """Derive Odra 2.8.2's exact ASCII dictionary item key."""

    return hashlib.blake2b(_mapping_key(index, mapping_key), digest_size=32).hexdigest()


class VerifiedV3Readback:
    """Opaque runtime evidence; construction is restricted to the transcript parser."""

    __slots__ = (
        "schema_id",
        "network",
        "package_hash",
        "contract_hash",
        "schema_version",
        "deployment_domain",
        "casper_chain_name",
        "proposer",
        "finalizer",
        "signers",
        "threshold",
        "proposal_id",
        "proposed_envelope",
        "approval_count",
        "finalized",
        "finalized_envelope",
        "action_id",
        "action_authorized",
        "observed_block_hash",
        "observed_block_height",
        "observed_state_root_hash",
        "_artifact_json",
        "_process_seal",
        "_locked",
    )

    def __init__(self, token: object, facts: Mapping[str, Any], artifact_json: bytes):
        if token is not _FACTORY_TOKEN:
            raise TypeError("VerifiedV3Readback is factory-only")
        object.__setattr__(self, "schema_id", SCHEMA_ID)
        object.__setattr__(self, "network", facts["network"])
        for name in (
            "package_hash",
            "contract_hash",
            "deployment_domain",
            "proposer",
            "finalizer",
            "proposed_envelope",
            "finalized_envelope",
            "action_id",
            "observed_block_hash",
            "observed_state_root_hash",
        ):
            object.__setattr__(self, name, bytes.fromhex(facts[name]))
        object.__setattr__(self, "schema_version", facts["schema_version"])
        object.__setattr__(self, "casper_chain_name", facts["casper_chain_name"])
        object.__setattr__(self, "signers", tuple(bytes.fromhex(item) for item in facts["signers"]))
        object.__setattr__(self, "threshold", facts["threshold"])
        object.__setattr__(self, "proposal_id", facts["proposal_id"])
        object.__setattr__(self, "approval_count", facts["approval_count"])
        object.__setattr__(self, "finalized", facts["finalized"])
        object.__setattr__(self, "action_authorized", facts["action_authorized"])
        object.__setattr__(self, "observed_block_height", facts["observed_block_height"])
        object.__setattr__(self, "_artifact_json", artifact_json)
        object.__setattr__(
            self,
            "_process_seal",
            hmac.new(_PROCESS_SEAL_KEY, artifact_json, hashlib.sha256).digest(),
        )
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_locked", False):
            raise AttributeError("VerifiedV3Readback is immutable")
        object.__setattr__(self, name, value)

    def persisted_artifact(self) -> dict[str, Any]:
        return json.loads(self._artifact_json)


def _validate_transcript(value: object) -> dict[str, Any]:
    expected = {
        "rpc_url_identity_or_node_id",
        "method",
        "params",
        "request",
        "response",
        "canonical_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ReadbackValidationError("every transcript must have the exact frozen field set")
    node_id = value["rpc_url_identity_or_node_id"]
    if not isinstance(node_id, str) or not node_id or "@" in node_id:
        raise ReadbackValidationError("RPC node identity is missing or contains credentials")
    method = value["method"]
    params = value["params"]
    request = value["request"]
    response = value["response"]
    if not isinstance(method, str) or not isinstance(params, Mapping):
        raise ReadbackValidationError("invalid transcript method/params")
    if not isinstance(request, Mapping) or set(request) != {"jsonrpc", "id", "method", "params"}:
        raise ReadbackValidationError("raw RPC request shape is not canonical")
    if request["jsonrpc"] != "2.0" or request["method"] != method or request["params"] != params:
        raise ReadbackValidationError("transcript summary does not match raw RPC request")
    if not isinstance(response, Mapping) or set(response) != {"jsonrpc", "id", "result"}:
        raise ReadbackValidationError("RPC response must contain result and no error")
    if response["jsonrpc"] != "2.0" or response["id"] != request["id"]:
        raise ReadbackValidationError("RPC request/response identity mismatch")
    digest = hashlib.sha256(_canonical_json({"request": request, "response": response})).hexdigest()
    if not hmac.compare_digest(str(value["canonical_sha256"]), digest):
        raise ReadbackValidationError("raw RPC transcript checksum mismatch")
    return copy.deepcopy(dict(value))


def _stored_value(transcript: Mapping[str, Any]) -> Mapping[str, Any]:
    try:
        value = transcript["response"]["result"]["stored_value"]
    except (KeyError, TypeError) as exc:
        raise ReadbackValidationError("state RPC response lacks stored_value") from exc
    if not isinstance(value, Mapping):
        raise ReadbackValidationError("stored_value must be an object")
    return value


def _inner_state_bytes(transcript: Mapping[str, Any]) -> bytes:
    cl_value = _stored_value(transcript).get("CLValue")
    if not isinstance(cl_value, Mapping) or set(cl_value) != {"cl_type", "bytes", "parsed"}:
        raise ReadbackValidationError("Odra state item must be one exact CLValue")
    if cl_value["cl_type"] != {"List": "U8"}:
        raise ReadbackValidationError("Odra state dictionary value must be List<U8>")
    parsed = cl_value["parsed"]
    if not isinstance(parsed, list) or any(type(item) is not int or not 0 <= item <= 255 for item in parsed):
        raise ReadbackValidationError("Odra state parsed bytes are invalid")
    inner = bytes(parsed)
    raw_hex = cl_value["bytes"]
    if not isinstance(raw_hex, str):
        raise ReadbackValidationError("Odra state raw CLValue bytes are missing")
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise ReadbackValidationError("Odra state raw CLValue bytes are malformed") from exc
    if raw != len(inner).to_bytes(4, "little") + inner:
        raise ReadbackValidationError("Odra state parsed value disagrees with raw CLValue bytes")
    return inner


def _u32(inner: bytes, field: str) -> int:
    if len(inner) != 4:
        raise ReadbackValidationError(f"{field}: expected canonical u32 bytes")
    return int.from_bytes(inner, "little")


def _u8(inner: bytes, field: str) -> int:
    if len(inner) != 1:
        raise ReadbackValidationError(f"{field}: expected canonical u8 bytes")
    return inner[0]


def _bool(inner: bytes, field: str) -> bool:
    if inner not in (b"\x00", b"\x01"):
        raise ReadbackValidationError(f"{field}: expected canonical Bool bytes")
    return inner == b"\x01"


def _bytes32(inner: bytes, field: str) -> str:
    if len(inner) != 32:
        raise ReadbackValidationError(f"{field}: expected canonical Bytes32")
    return inner.hex()


def _string(inner: bytes, field: str) -> str:
    if len(inner) < 4:
        raise ReadbackValidationError(f"{field}: malformed String")
    size = int.from_bytes(inner[:4], "little")
    if size != len(inner) - 4:
        raise ReadbackValidationError(f"{field}: non-canonical String length")
    try:
        return inner[4:].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReadbackValidationError(f"{field}: invalid UTF-8") from exc


def _extract_package_hash(transcript: Mapping[str, Any]) -> str:
    stored = _stored_value(transcript)
    contract = stored.get("Contract")
    if not isinstance(contract, Mapping):
        raise ReadbackValidationError("exact contract query did not return a legacy Contract record")
    value = contract.get("contract_package_hash")
    if not isinstance(value, str):
        raise ReadbackValidationError("contract record lacks contract_package_hash")
    for prefix in ("contract-package-", "hash-"):
        if value.startswith(prefix):
            value = value[len(prefix) :]
            break
    return _hex32(value, "contract_package_hash").hex()


def _unwrap_block_with_signatures(response: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return one exact Casper Version1/Version2 block payload.

    Casper RPC 2.0 wraps the block enum below
    ``result.block_with_signatures.block``.  Treating that enum as the legacy
    direct ``result.block`` silently drops live provenance, so only the exact
    tagged response shape is accepted here.
    """

    result = response.get("result")
    if not isinstance(result, Mapping) or set(result) != {"api_version", "block_with_signatures"}:
        raise ReadbackValidationError("block RPC result is not the exact Casper v2 wrapper")
    if not isinstance(result["api_version"], str) or not result["api_version"]:
        raise ReadbackValidationError("block RPC api_version is missing")
    wrapped = result["block_with_signatures"]
    if not isinstance(wrapped, Mapping) or set(wrapped) != {"block", "proofs"}:
        raise ReadbackValidationError("block_with_signatures field set is invalid")
    if not isinstance(wrapped["proofs"], list):
        raise ReadbackValidationError("block_with_signatures proofs must be a list")
    versioned = wrapped["block"]
    if not isinstance(versioned, Mapping) or len(versioned) != 1:
        raise ReadbackValidationError("Casper block must contain exactly one version")
    version = next(iter(versioned))
    if version not in ("Version1", "Version2"):
        raise ReadbackValidationError("unsupported Casper block version")
    block = versioned[version]
    if not isinstance(block, Mapping) or not {"hash", "header", "body"}.issubset(block):
        raise ReadbackValidationError("versioned block lacks hash/header/body")
    if not isinstance(block["header"], Mapping) or not isinstance(block["body"], Mapping):
        raise ReadbackValidationError("versioned block header/body must be objects")
    return block


def _expected_state_items(proposal_id: str, action_id: bytes) -> dict[str, tuple[int, bytes]]:
    proposal_raw = proposal_id.encode("ascii")
    proposal_key = len(proposal_raw).to_bytes(4, "little") + proposal_raw
    return {
        "schema_version": (1, b""),
        "deployment_domain": (2, b""),
        "casper_chain_name": (3, b""),
        "proposer": (4, b""),
        "finalizer": (5, b""),
        "signer_a": (6, b""),
        "signer_b": (7, b""),
        "signer_c": (8, b""),
        "threshold": (9, b""),
        "proposed_envelope": (11, proposal_key),
        "approval_count": (12, proposal_key),
        "finalized": (14, proposal_key),
        "finalized_envelope": (15, proposal_key),
        "action_authorized": (16, action_id),
    }


def _parse_transcripts(
    transcripts_value: object,
    *,
    network: str,
    expected: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if network != NETWORK:
        raise ReadbackValidationError("network must be exactly casper-test")
    if not isinstance(transcripts_value, Sequence) or isinstance(transcripts_value, (str, bytes)):
        raise ReadbackValidationError("transcripts must be a list")
    transcripts = [_validate_transcript(item) for item in transcripts_value]
    package_hash = _hex32(expected.get("package_hash"), "expected package_hash").hex()
    contract_hash = _hex32(expected.get("contract_hash"), "expected contract_hash").hex()
    action_id = _hex32(expected.get("action_id"), "expected action_id")
    proposal_id = expected.get("proposal_id")
    if not isinstance(proposal_id, str) or not proposal_id or len(proposal_id) > 64:
        raise ReadbackValidationError("expected proposal_id is invalid")
    try:
        proposal_id.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ReadbackValidationError("proposal_id must be ASCII") from exc

    block_calls = [item for item in transcripts if item["method"] == "chain_get_block"]
    contract_calls = [item for item in transcripts if item["method"] == "query_global_state"]
    dictionary_calls = [item for item in transcripts if item["method"] == "state_get_dictionary_item"]
    if len(block_calls) != 1 or len(contract_calls) != 1:
        raise ReadbackValidationError("exactly one block and one contract-identity query are required")
    if len(dictionary_calls) != 14 or len(transcripts) != 16:
        raise ReadbackValidationError("readback requires exactly fourteen state queries")
    try:
        block = _unwrap_block_with_signatures(block_calls[0]["response"])
        block_hash = _hex32(block["hash"], "block hash").hex()
        state_root = _hex32(block["header"]["state_root_hash"], "state root").hex()
        block_height = block["header"]["height"]
    except (KeyError, TypeError) as exc:
        raise ReadbackValidationError("block transcript lacks hash/header provenance") from exc
    if type(block_height) is not int or not 0 <= block_height < 1 << 64:
        raise ReadbackValidationError("block height must be u64")
    block_identifier = block_calls[0]["params"].get("block_identifier")
    if block_identifier is not None and block_identifier != {"Hash": block_hash}:
        raise ReadbackValidationError("block query identifier disagrees with returned block")

    contract_params = contract_calls[0]["params"]
    if contract_params != {
        "state_identifier": {"StateRootHash": state_root},
        "key": "hash-" + contract_hash,
        "path": [],
    }:
        raise ReadbackValidationError("contract identity query is not pinned to exact hash/state root")
    if _extract_package_hash(contract_calls[0]) != package_hash:
        raise ReadbackValidationError("exact contract does not belong to expected package")

    by_key: dict[str, dict[str, Any]] = {}
    exact_dictionary = {
        "ContractNamedKey": {"key": "hash-" + contract_hash, "dictionary_name": "state"}
    }
    for transcript in dictionary_calls:
        params = transcript["params"]
        if params.get("state_root_hash") != state_root or params.get("dictionary_identifier") != exact_dictionary:
            raise ReadbackValidationError("dictionary query is not pinned to exact state root/contract")
        item_key = params.get("dictionary_item_key")
        if not isinstance(item_key, str) or item_key in by_key:
            raise ReadbackValidationError("dictionary item query key is missing or duplicated")
        by_key[item_key] = transcript

    observed: dict[str, bytes] = {}
    for name, (index, mapping_key) in _expected_state_items(proposal_id, action_id).items():
        key = state_dictionary_key(index, mapping_key)
        if key not in by_key:
            raise ReadbackValidationError(f"missing exact state query for {name}")
        observed[name] = _inner_state_bytes(by_key[key])
    if len(by_key) != len(observed):
        raise ReadbackValidationError("unexpected state query present")

    facts = {
        "schema_id": SCHEMA_ID,
        "network": network,
        "package_hash": package_hash,
        "contract_hash": contract_hash,
        "schema_version": _u32(observed["schema_version"], "schema_version"),
        "deployment_domain": _bytes32(observed["deployment_domain"], "deployment_domain"),
        "casper_chain_name": _string(observed["casper_chain_name"], "casper_chain_name"),
        "proposer": _bytes32(observed["proposer"], "proposer"),
        "finalizer": _bytes32(observed["finalizer"], "finalizer"),
        "signers": [
            _bytes32(observed["signer_a"], "signer_a"),
            _bytes32(observed["signer_b"], "signer_b"),
            _bytes32(observed["signer_c"], "signer_c"),
        ],
        "threshold": _u8(observed["threshold"], "threshold"),
        "proposal_id": proposal_id,
        "proposed_envelope": _bytes32(observed["proposed_envelope"], "proposed_envelope"),
        "approval_count": _u8(observed["approval_count"], "approval_count"),
        "finalized": _bool(observed["finalized"], "finalized"),
        "finalized_envelope": _bytes32(observed["finalized_envelope"], "finalized_envelope"),
        "action_id": action_id.hex(),
        "action_authorized": _bool(observed["action_authorized"], "action_authorized"),
        "observed_block_hash": block_hash,
        "observed_block_height": block_height,
        "observed_state_root_hash": state_root,
    }
    if facts["schema_version"] != 3 or facts["casper_chain_name"] != NETWORK:
        raise ReadbackValidationError("on-chain schema/network is not Concordia v3 Testnet")
    governance_roles = [facts["proposer"], facts["finalizer"], *facts["signers"]]
    if (
        any(role == "00" * 32 for role in governance_roles)
        or len(set(governance_roles)) != 5
        or facts["threshold"] not in (2, 3)
    ):
        raise ReadbackValidationError("on-chain governance roles/threshold are invalid")
    return transcripts, facts


def build_readback_artifact_from_transcripts(
    *,
    transcripts: Sequence[Mapping[str, Any]],
    expected_network: str,
    expected_package_hash: str,
    expected_contract_hash: str,
    proposal_id: str,
    action_id: str,
) -> dict[str, Any]:
    expected = {
        "package_hash": expected_package_hash,
        "contract_hash": expected_contract_hash,
        "proposal_id": proposal_id,
        "action_id": action_id,
    }
    validated, facts = _parse_transcripts(transcripts, network=expected_network, expected=expected)
    artifact: dict[str, Any] = {
        "schema_id": SCHEMA_ID,
        "network": expected_network,
        "expected": expected,
        "transcripts": validated,
        "facts": facts,
    }
    artifact["artifact_sha256"] = hashlib.sha256(_canonical_json(artifact)).hexdigest()
    return artifact


def _parse_checkpoint_state_transcripts(
    transcripts_value: object,
    *,
    network: str,
    expected: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if network != NETWORK:
        raise ReadbackValidationError("checkpoint network must be exactly casper-test")
    if not isinstance(transcripts_value, Sequence) or isinstance(
        transcripts_value, (str, bytes)
    ):
        raise ReadbackValidationError("checkpoint transcripts must be a list")
    transcripts = [_validate_transcript(item) for item in transcripts_value]
    if len(transcripts) != 2:
        raise ReadbackValidationError(
            "checkpoint state readback requires exactly block and contract queries"
        )
    block_calls = [item for item in transcripts if item["method"] == "chain_get_block"]
    contract_calls = [
        item for item in transcripts if item["method"] == "query_global_state"
    ]
    if len(block_calls) != 1 or len(contract_calls) != 1:
        raise ReadbackValidationError("checkpoint state readback method set is invalid")
    package_hash = _hex32(expected.get("package_hash"), "expected package_hash").hex()
    contract_hash = _hex32(expected.get("contract_hash"), "expected contract_hash").hex()
    action_id = _hex32(expected.get("action_id"), "expected action_id").hex()
    proposal_id = expected.get("proposal_id")
    if not isinstance(proposal_id, str) or not proposal_id or len(proposal_id) > 64:
        raise ReadbackValidationError("checkpoint proposal_id is invalid")
    try:
        proposal_id.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ReadbackValidationError("checkpoint proposal_id must be ASCII") from exc
    completed = expected.get("completed_steps")
    if not isinstance(completed, list):
        raise ReadbackValidationError("checkpoint completed_steps must be a list")
    seen_names: set[str] = set()
    for item in completed:
        if not isinstance(item, Mapping) or set(item) != {
            "name",
            "deploy_hash",
            "finality_transcript_sha256",
        }:
            raise ReadbackValidationError("checkpoint completed step is invalid")
        name = item["name"]
        if not isinstance(name, str) or not name or name in seen_names:
            raise ReadbackValidationError("checkpoint completed-step names are invalid")
        seen_names.add(name)
        _hex32(item["deploy_hash"], "checkpoint completed deploy hash")
        _hex32(
            item["finality_transcript_sha256"],
            "checkpoint completed finality transcript hash",
        )

    block = _unwrap_block_with_signatures(block_calls[0]["response"])
    try:
        block_hash = _hex32(block["hash"], "checkpoint block hash").hex()
        state_root = _hex32(
            block["header"]["state_root_hash"], "checkpoint state root"
        ).hex()
        block_height = block["header"]["height"]
    except (KeyError, TypeError) as exc:
        raise ReadbackValidationError(
            "checkpoint block transcript lacks hash/header provenance"
        ) from exc
    if type(block_height) is not int or not 0 <= block_height < 1 << 64:
        raise ReadbackValidationError("checkpoint block height must be u64")
    if block_calls[0]["params"] != {"block_identifier": {"Hash": block_hash}}:
        raise ReadbackValidationError("checkpoint block query is not hash-pinned")
    if contract_calls[0]["params"] != {
        "state_identifier": {"StateRootHash": state_root},
        "key": "hash-" + contract_hash,
        "path": [],
    }:
        raise ReadbackValidationError(
            "checkpoint contract query is not pinned to exact state root/hash"
        )
    if _extract_package_hash(contract_calls[0]) != package_hash:
        raise ReadbackValidationError(
            "checkpoint contract does not belong to expected package"
        )
    facts = {
        "package_hash": package_hash,
        "contract_hash": contract_hash,
        "proposal_id": proposal_id,
        "action_id": action_id,
        "observed_block_hash": block_hash,
        "observed_block_height": block_height,
        "observed_state_root_hash": state_root,
        "completed_steps": copy.deepcopy(completed),
    }
    return transcripts, facts


def build_checkpoint_state_readback_from_transcripts(
    *,
    transcripts: Sequence[Mapping[str, Any]],
    expected_network: str,
    expected_package_hash: str,
    expected_contract_hash: str,
    proposal_id: str,
    action_id: str,
    completed_steps: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    expected = {
        "package_hash": expected_package_hash,
        "contract_hash": expected_contract_hash,
        "proposal_id": proposal_id,
        "action_id": action_id,
        "completed_steps": [copy.deepcopy(dict(item)) for item in completed_steps],
    }
    validated, facts = _parse_checkpoint_state_transcripts(
        transcripts,
        network=expected_network,
        expected=expected,
    )
    artifact: dict[str, Any] = {
        "schema_id": CHECKPOINT_SCHEMA_ID,
        "network": expected_network,
        "expected": expected,
        "transcripts": validated,
        "facts": facts,
    }
    artifact["artifact_sha256"] = hashlib.sha256(_canonical_json(artifact)).hexdigest()
    return artifact


def verify_checkpoint_state_readback_artifact(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_id",
        "network",
        "expected",
        "transcripts",
        "facts",
        "artifact_sha256",
    }:
        raise ReadbackValidationError(
            "checkpoint state-readback artifact field set is invalid"
        )
    if value["schema_id"] != CHECKPOINT_SCHEMA_ID or value["network"] != NETWORK:
        raise ReadbackValidationError("checkpoint state-readback schema/network mismatch")
    expected = value["expected"]
    if not isinstance(expected, Mapping) or set(expected) != {
        "package_hash",
        "contract_hash",
        "proposal_id",
        "action_id",
        "completed_steps",
    }:
        raise ReadbackValidationError("checkpoint expected identity field set is invalid")
    unsigned = {
        key: copy.deepcopy(item) for key, item in value.items() if key != "artifact_sha256"
    }
    digest = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
    if not hmac.compare_digest(str(value["artifact_sha256"]), digest):
        raise ReadbackValidationError("checkpoint state-readback checksum mismatch")
    transcripts, facts = _parse_checkpoint_state_transcripts(
        value["transcripts"],
        network=value["network"],
        expected=expected,
    )
    if value["facts"] != facts:
        raise ReadbackValidationError(
            "checkpoint persisted facts differ from raw transcript recomputation"
        )
    return {
        "schema_id": CHECKPOINT_SCHEMA_ID,
        "network": NETWORK,
        "expected": copy.deepcopy(dict(expected)),
        "transcripts": transcripts,
        "facts": facts,
        "artifact_sha256": digest,
    }


def verify_and_seal_readback_artifact(value: object) -> VerifiedV3Readback:
    if not isinstance(value, Mapping) or set(value) != {
        "schema_id",
        "network",
        "expected",
        "transcripts",
        "facts",
        "artifact_sha256",
    }:
        raise ReadbackValidationError("readback artifact field set is not frozen")
    if value["schema_id"] != SCHEMA_ID or value["network"] != NETWORK:
        raise ReadbackValidationError("readback schema/network mismatch")
    expected = value["expected"]
    if not isinstance(expected, Mapping) or set(expected) != {
        "package_hash",
        "contract_hash",
        "proposal_id",
        "action_id",
    }:
        raise ReadbackValidationError("readback expected identity field set is invalid")
    artifact_without_hash = {key: copy.deepcopy(item) for key, item in value.items() if key != "artifact_sha256"}
    digest = hashlib.sha256(_canonical_json(artifact_without_hash)).hexdigest()
    if not hmac.compare_digest(str(value["artifact_sha256"]), digest):
        raise ReadbackValidationError("readback artifact checksum mismatch")
    transcripts, facts = _parse_transcripts(value["transcripts"], network=value["network"], expected=expected)
    if value["facts"] != facts:
        raise ReadbackValidationError("persisted facts differ from raw RPC transcript recomputation")
    canonical_artifact = {
        "schema_id": SCHEMA_ID,
        "network": NETWORK,
        "expected": dict(expected),
        "transcripts": transcripts,
        "facts": facts,
        "artifact_sha256": digest,
    }
    artifact_json = _canonical_json(canonical_artifact)
    return VerifiedV3Readback(_FACTORY_TOKEN, facts, artifact_json)


def validate_verified_readback(value: object) -> VerifiedV3Readback:
    if type(value) is not VerifiedV3Readback:
        raise ReadbackValidationError("consumer requires a factory-verified v3 readback")
    expected = hmac.new(_PROCESS_SEAL_KEY, value._artifact_json, hashlib.sha256).digest()
    if not hmac.compare_digest(value._process_seal, expected):
        raise ReadbackValidationError("v3 readback process seal mismatch")
    reparsed = verify_and_seal_readback_artifact(json.loads(value._artifact_json))
    if reparsed._artifact_json != value._artifact_json:
        raise ReadbackValidationError("v3 readback changed during revalidation")
    public_slots = (
        "schema_id",
        "network",
        "package_hash",
        "contract_hash",
        "schema_version",
        "deployment_domain",
        "casper_chain_name",
        "proposer",
        "finalizer",
        "signers",
        "threshold",
        "proposal_id",
        "proposed_envelope",
        "approval_count",
        "finalized",
        "finalized_envelope",
        "action_id",
        "action_authorized",
        "observed_block_hash",
        "observed_block_height",
        "observed_state_root_hash",
    )
    if any(getattr(value, name) != getattr(reparsed, name) for name in public_slots):
        raise ReadbackValidationError("v3 readback public facts changed after factory verification")
    return value


def _node_identity(rpc_url: str) -> str:
    parsed = urlsplit(rpc_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ReadbackValidationError("RPC URL must be credential-free HTTPS")
    return parsed.hostname


def _rpc_transcript(
    client: httpx.Client,
    rpc_url: str,
    node_id: str,
    method: str,
    params: Mapping[str, Any],
    sequence: int,
) -> dict[str, Any]:
    request = {"jsonrpc": "2.0", "id": f"concordia-v3-readback-{sequence}", "method": method, "params": dict(params)}
    response = client.post(rpc_url, json=request)
    response.raise_for_status()
    parsed = response.json()
    if not isinstance(parsed, Mapping) or parsed.get("error") is not None:
        raise ReadbackValidationError(f"Casper RPC {method} failed")
    transcript = {
        "rpc_url_identity_or_node_id": node_id,
        "method": method,
        "params": dict(params),
        "request": request,
        "response": parsed,
    }
    transcript["canonical_sha256"] = hashlib.sha256(
        _canonical_json({"request": request, "response": parsed})
    ).hexdigest()
    return transcript


def capture_v3_checkpoint_state(
    *,
    rpc_url: str,
    package_hash: str,
    contract_hash: str,
    proposal_id: str,
    action_id: str,
    completed_steps: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Capture the exact state-root/contract anchor before a browser handoff.

    Lifecycle-specific state remains proven by the finalized deploy transcripts
    named in ``completed_steps``.  This checkpoint readback independently pins
    those prior outcomes to a concrete block, state root, contract and package
    before any unsigned deploy leaves the trusted runner.
    """

    node_id = _node_identity(rpc_url)
    package = _hex32(package_hash, "checkpoint package_hash").hex()
    contract = _hex32(contract_hash, "checkpoint contract_hash").hex()
    action = _hex32(action_id, "checkpoint action_id").hex()
    with httpx.Client(timeout=60.0) as client:
        latest = _rpc_transcript(client, rpc_url, node_id, "chain_get_block", {}, 0)
        latest_block = _unwrap_block_with_signatures(latest["response"])
        returned_hash = _hex32(
            latest_block["hash"], "checkpoint returned block_hash"
        ).hex()
        block_call = _rpc_transcript(
            client,
            rpc_url,
            node_id,
            "chain_get_block",
            {"block_identifier": {"Hash": returned_hash}},
            1,
        )
        pinned = _unwrap_block_with_signatures(block_call["response"])
        pinned_hash = _hex32(pinned["hash"], "checkpoint pinned block_hash").hex()
        if pinned_hash != returned_hash:
            raise ReadbackValidationError(
                "checkpoint hash-pinned block query returned another block"
            )
        state_root = _hex32(
            pinned["header"]["state_root_hash"], "checkpoint pinned state root"
        ).hex()
        contract_call = _rpc_transcript(
            client,
            rpc_url,
            node_id,
            "query_global_state",
            {
                "state_identifier": {"StateRootHash": state_root},
                "key": "hash-" + contract,
                "path": [],
            },
            2,
        )
    return build_checkpoint_state_readback_from_transcripts(
        transcripts=[block_call, contract_call],
        expected_network=NETWORK,
        expected_package_hash=package,
        expected_contract_hash=contract,
        proposal_id=proposal_id,
        action_id=action,
        completed_steps=completed_steps,
    )


def capture_v3_state(
    *,
    rpc_url: str,
    package_hash: str,
    contract_hash: str,
    proposal_id: str,
    action_id: str,
    block_hash: str | None = None,
) -> dict[str, Any]:
    node_id = _node_identity(rpc_url)
    action = _hex32(action_id, "action_id")
    block_params: dict[str, Any] = {} if block_hash is None else {"block_identifier": {"Hash": _hex32(block_hash, "block_hash").hex()}}
    with httpx.Client(timeout=60.0) as client:
        block_call = _rpc_transcript(client, rpc_url, node_id, "chain_get_block", block_params, 0)
        block = _unwrap_block_with_signatures(block_call["response"])
        returned_block = _hex32(block["hash"], "returned block_hash").hex()
        state_root = _hex32(block["header"]["state_root_hash"], "returned state_root_hash").hex()
        if block_hash is None:
            # Persist an explicitly hash-pinned request rather than a moving latest query.
            block_call = _rpc_transcript(
                client,
                rpc_url,
                node_id,
                "chain_get_block",
                {"block_identifier": {"Hash": returned_block}},
                0,
            )
            pinned_block = _unwrap_block_with_signatures(block_call["response"])
            pinned_hash = _hex32(pinned_block["hash"], "pinned block_hash").hex()
            if pinned_hash != returned_block:
                raise ReadbackValidationError("hash-pinned block query returned a different block")
            state_root = _hex32(
                pinned_block["header"]["state_root_hash"],
                "pinned state_root_hash",
            ).hex()
        contract_call = _rpc_transcript(
            client,
            rpc_url,
            node_id,
            "query_global_state",
            {"state_identifier": {"StateRootHash": state_root}, "key": "hash-" + contract_hash, "path": []},
            1,
        )
        transcripts = [block_call, contract_call]
        exact_dictionary = {
            "ContractNamedKey": {"key": "hash-" + contract_hash, "dictionary_name": "state"}
        }
        for sequence, (name, (index, mapping_key)) in enumerate(
            _expected_state_items(proposal_id, action).items(), start=2
        ):
            del name
            transcripts.append(
                _rpc_transcript(
                    client,
                    rpc_url,
                    node_id,
                    "state_get_dictionary_item",
                    {
                        "state_root_hash": state_root,
                        "dictionary_identifier": exact_dictionary,
                        "dictionary_item_key": state_dictionary_key(index, mapping_key),
                    },
                    sequence,
                )
            )
    return build_readback_artifact_from_transcripts(
        transcripts=transcripts,
        expected_network=NETWORK,
        expected_package_hash=package_hash,
        expected_contract_hash=contract_hash,
        proposal_id=proposal_id,
        action_id=action_id,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc-url", default="https://node.testnet.casper.network/rpc")
    parser.add_argument("--package-hash", required=True)
    parser.add_argument("--contract-hash", required=True)
    parser.add_argument("--proposal-id", required=True)
    parser.add_argument("--action-id", required=True)
    parser.add_argument("--block-hash")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        artifact = capture_v3_state(
            rpc_url=args.rpc_url,
            package_hash=args.package_hash,
            contract_hash=args.contract_hash,
            proposal_id=args.proposal_id,
            action_id=args.action_id,
            block_hash=args.block_hash,
        )
        verify_and_seal_readback_artifact(artifact)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({"status": "verified", "artifact": str(args.out), "block_height": artifact["facts"]["observed_block_height"]}))
        return 0
    except (ReadbackValidationError, httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
