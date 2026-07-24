"""Offline, fail-closed two-node evidence for one exact native transfer.

Network I/O intentionally lives outside this module.  Callers provide
the exact requests and responses captured from at least two distinct public
Casper RPC nodes plus the exact signed deploy bytes persisted before broadcast.
The result proves that those nodes agree on successful execution and canonical
block inclusion.  It does not verify validator signatures and is not a
trustless Casper light-client proof.  No explorer or artifact boolean is
accepted as a substitute.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Sequence
from urllib.parse import urlsplit, urlunsplit

from shared.native_transfer_deploy import (
    DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
    NativeTransferDeployError,
    NativeTransferDeployFacts,
    validate_signed_native_transfer_deploy,
)


_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_DECIMAL_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")
_CAPTURED_AT_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
_MAX_U512 = (1 << 512) - 1
_MAX_TRANSCRIPT_BYTES = 8 * 1024 * 1024

FINALITY_PREDICATE_CHECKS = (
    "each_status_response_proves_casper_test",
    "each_rpc_request_response_id_and_params_match",
    "requested_hash_matches_returned_item",
    "processed_execution_result_exists",
    "execution_succeeded_without_error",
    "canonical_block_hash_matches_execution",
    "canonical_block_height_is_consistent",
    "canonical_state_root_hash_is_explicit",
    "deploy_is_included_exactly_once_in_canonical_block",
    "two_distinct_public_rpc_nodes_agree",
    "signed_deploy_bytes_validate_exact_native_transfer",
)


class NativeTransferFinalityError(ValueError):
    """Node evidence does not prove finality for the exact requested transfer."""


_PARSER_FACTORY_SEAL = object()
_PARSER_INTEGRITY_KEY = secrets.token_bytes(32)


@dataclass(frozen=True, slots=True, init=False)
class FinalizedNativeTransferProof:
    """Immutable facts constructible only by the strict parser factory.

    Integration code must call :func:`require_verified_finalized_native_transfer`
    before transitioning a journal entry to ``FINALIZED``.  Disabling the
    public dataclass constructor prevents a caller from satisfying that gate by
    merely copying values into a lookalike result.
    """

    requested_deploy_hash: str
    deploy_hash: str
    network: str
    block_hash: str
    block_height: int
    state_root_hash: str
    rpc_method: str
    execution_result_kind: str
    gas_motes: int
    block_inclusion_path: str
    finality_predicate: bool
    finality_checks: tuple[str, ...]
    node_observation_count: int
    corroboration_count: int
    node_urls: tuple[str, ...]
    captured_at: tuple[str, ...]
    rpc_methods: tuple[str, ...]
    node_observation_json: tuple[str, ...]
    node_observation_sha256: tuple[str, ...]
    verification_scope: str
    signed_deploy: NativeTransferDeployFacts
    _factory_seal: object = field(repr=False, compare=False)
    _integrity_tag: bytes = field(repr=False, compare=False)

    def __new__(cls, *_args: object, **_kwargs: object) -> FinalizedNativeTransferProof:
        raise TypeError(
            "FinalizedNativeTransferProof is created only by "
            "verify_finalized_native_transfer"
        )


@dataclass(frozen=True, slots=True)
class _RpcObservation:
    deploy_hash: str
    block_hash: str
    block_height: int | None
    rpc_method: str
    execution_result_kind: str
    gas_motes: int


@dataclass(frozen=True, slots=True)
class _CanonicalBlock:
    block_hash: str
    block_height: int
    state_root_hash: str
    inclusion_path: str


@dataclass(frozen=True, slots=True)
class _VerifiedNodeObservation:
    node_url: str
    captured_at: str
    rpc: _RpcObservation
    block: _CanonicalBlock
    transcript_json: str
    transcript_sha256: str


def _make_finalized_proof(**values: object) -> FinalizedNativeTransferProof:
    proof = object.__new__(FinalizedNativeTransferProof)
    for name, value in values.items():
        object.__setattr__(proof, name, value)
    object.__setattr__(proof, "_factory_seal", _PARSER_FACTORY_SEAL)
    object.__setattr__(proof, "_integrity_tag", _proof_integrity_tag(proof))
    return proof


def _proof_integrity_tag(proof: FinalizedNativeTransferProof) -> bytes:
    material = {
        "requested_deploy_hash": proof.requested_deploy_hash,
        "deploy_hash": proof.deploy_hash,
        "network": proof.network,
        "block_hash": proof.block_hash,
        "block_height": proof.block_height,
        "state_root_hash": proof.state_root_hash,
        "rpc_method": proof.rpc_method,
        "execution_result_kind": proof.execution_result_kind,
        "gas_motes": proof.gas_motes,
        "block_inclusion_path": proof.block_inclusion_path,
        "finality_predicate": proof.finality_predicate,
        "finality_checks": list(proof.finality_checks),
        "node_observation_count": proof.node_observation_count,
        "corroboration_count": proof.corroboration_count,
        "node_urls": list(proof.node_urls),
        "captured_at": list(proof.captured_at),
        "rpc_methods": list(proof.rpc_methods),
        "node_observation_sha256": list(proof.node_observation_sha256),
        "verification_scope": proof.verification_scope,
        "signed_deploy_sha256": hashlib.sha256(
            proof.signed_deploy.canonical_signed_bytes
        ).hexdigest(),
        "signed_deploy_hash": proof.signed_deploy.deploy_hash_hex,
        "source_account_hash": proof.signed_deploy.source_account_hash.hex(),
        "recipient_account_hash": proof.signed_deploy.recipient_account_hash.hex(),
        "amount_motes": proof.signed_deploy.amount_motes,
        "transfer_id": proof.signed_deploy.transfer_id,
    }
    encoded = json.dumps(
        material, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hmac.new(_PARSER_INTEGRITY_KEY, encoded, hashlib.sha256).digest()


def require_verified_finalized_native_transfer(
    proof: object,
) -> FinalizedNativeTransferProof:
    """Return only a proof issued by this module's strict parser factory."""

    if (
        type(proof) is not FinalizedNativeTransferProof
        or getattr(proof, "_factory_seal", None) is not _PARSER_FACTORY_SEAL
    ):
        raise NativeTransferFinalityError(
            "native transfer finality proof is not parser-verified"
        )
    integrity_tag = getattr(proof, "_integrity_tag", None)
    if type(integrity_tag) is not bytes or not hmac.compare_digest(
        integrity_tag, _proof_integrity_tag(proof)
    ):
        raise NativeTransferFinalityError(
            "native transfer finality proof integrity check failed"
        )
    if (
        proof.finality_predicate is not True
        or proof.finality_checks != FINALITY_PREDICATE_CHECKS
        or proof.network != "casper-test"
        or proof.requested_deploy_hash != proof.deploy_hash
        or proof.deploy_hash != proof.signed_deploy.deploy_hash_hex
        or type(proof.gas_motes) is not int
        or not 0 <= proof.gas_motes <= _MAX_U512
        or _HASH_RE.fullmatch(proof.block_hash) is None
        or _HASH_RE.fullmatch(proof.state_root_hash) is None
        or type(proof.block_height) is not int
        or proof.block_height < 0
        or not proof.block_inclusion_path
        or type(proof.node_observation_count) is not int
        or proof.node_observation_count < 2
        or proof.corroboration_count != proof.node_observation_count - 1
        or type(proof.node_urls) is not tuple
        or len(proof.node_urls) != proof.node_observation_count
        or len(set(proof.node_urls)) != proof.node_observation_count
        or type(proof.captured_at) is not tuple
        or len(proof.captured_at) != proof.node_observation_count
        or type(proof.rpc_methods) is not tuple
        or len(proof.rpc_methods) != proof.node_observation_count
        or type(proof.node_observation_json) is not tuple
        or len(proof.node_observation_json) != proof.node_observation_count
        or type(proof.node_observation_sha256) is not tuple
        or len(proof.node_observation_sha256) != proof.node_observation_count
        or proof.verification_scope
        != "two-or-more-public-rpc-nodes-agree;validator-signatures-not-verified"
    ):
        raise NativeTransferFinalityError(
            "native transfer finality proof integrity check failed"
        )
    for transcript, expected_sha256 in zip(
        proof.node_observation_json,
        proof.node_observation_sha256,
        strict=True,
    ):
        if type(transcript) is not str or type(expected_sha256) is not str:
            raise NativeTransferFinalityError(
                "native transfer finality proof integrity check failed"
            )
        try:
            decoded = json.loads(transcript)
        except json.JSONDecodeError as exc:
            raise NativeTransferFinalityError(
                "native transfer finality proof integrity check failed"
            ) from exc
        canonical = _canonical_json(decoded, "node observation transcript")
        if (
            canonical.decode("ascii") != transcript
            or hashlib.sha256(canonical).hexdigest() != expected_sha256
        ):
            raise NativeTransferFinalityError(
                "native transfer finality proof integrity check failed"
            )
    return proof


def _canonical_json(value: object, label: str) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise NativeTransferFinalityError(f"{label} is not canonical JSON") from exc
    if len(encoded) > _MAX_TRANSCRIPT_BYTES:
        raise NativeTransferFinalityError(f"{label} exceeds transcript size limit")
    return encoded


def _dict(value: object, error: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise NativeTransferFinalityError(error)
    return value


def _request_id(value: object, label: str) -> int | str:
    if type(value) not in (int, str) or value == "":
        raise NativeTransferFinalityError(f"{label} request id is invalid")
    return value


def _parse_exact_request(
    request: object,
    *,
    method: str,
    params: dict[str, Any],
    label: str,
) -> int | str:
    body = _dict(request, f"{label} request is malformed")
    if set(body) != {"jsonrpc", "id", "method", "params"}:
        raise NativeTransferFinalityError(
            f"{label} request must contain exactly frozen fields"
        )
    if body["jsonrpc"] != "2.0" or body["method"] != method:
        raise NativeTransferFinalityError(f"{label} request must call {method}")
    if body["params"] != params:
        raise NativeTransferFinalityError(
            f"{label} request params do not match exactly"
        )
    return _request_id(body["id"], label)


def _require_exact_response(
    payload: object, expected_id: int | str, label: str
) -> dict[str, Any]:
    body = _dict(payload, f"{label} response is malformed")
    if body.get("jsonrpc") != "2.0":
        raise NativeTransferFinalityError(f"{label} response must use JSON-RPC 2.0")
    if body.get("id") != expected_id:
        raise NativeTransferFinalityError(
            f"{label} response id does not match request id"
        )
    if body.get("error") is not None:
        raise NativeTransferFinalityError(f"{label} payload contains error")
    return body


def _parse_status_network(payload: object) -> str:
    value = _unwrap_result(payload, kind="status")
    names = [
        item
        for item in (
            value.get("chainspec_name"),
            value.get("chainspecName"),
            value.get("chain_name"),
        )
        if item is not None
    ]
    if len(names) != 1 or names[0] != "casper-test":
        raise NativeTransferFinalityError("status must prove chain casper-test")
    return "casper-test"


def _public_node_url(value: object) -> str:
    if type(value) is not str or not value:
        raise NativeTransferFinalityError(
            "node URL must identify a public credential-free HTTPS RPC endpoint"
        )
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise NativeTransferFinalityError(
            "node URL must identify a public credential-free HTTPS RPC endpoint"
        ) from exc
    hostname = parts.hostname
    if (
        parts.scheme != "https"
        or hostname is None
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or parts.path not in ("", "/", "/rpc")
    ):
        raise NativeTransferFinalityError(
            "node URL must identify a public credential-free HTTPS RPC endpoint"
        )
    lower_hostname = hostname.casefold()
    if lower_hostname in (
        "localhost",
        "localhost.localdomain",
    ) or lower_hostname.endswith(".local"):
        raise NativeTransferFinalityError(
            "node URL must identify a public credential-free HTTPS RPC endpoint"
        )
    try:
        address = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        if "." not in hostname:
            raise NativeTransferFinalityError(
                "node URL must identify a public credential-free HTTPS RPC endpoint"
            )
    else:
        if not address.is_global:
            raise NativeTransferFinalityError(
                "node URL must identify a public credential-free HTTPS RPC endpoint"
            )
    netloc = lower_hostname
    if ":" in lower_hostname and not lower_hostname.startswith("["):
        netloc = f"[{lower_hostname}]"
    if port is not None:
        netloc = f"{netloc}:{port}"
    normalized = urlunsplit(("https", netloc, parts.path or "/", "", ""))
    if value != normalized:
        raise NativeTransferFinalityError(
            "node URL must identify a public credential-free HTTPS RPC endpoint"
        )
    return normalized


def _node_origin(value: str) -> tuple[str, int]:
    parts = urlsplit(value)
    hostname = parts.hostname
    if hostname is None:  # pragma: no cover - guarded by _public_node_url
        raise NativeTransferFinalityError(
            "node URL must identify a public credential-free HTTPS RPC endpoint"
        )
    return hostname.casefold(), parts.port or 443


def _capture_timestamp(value: object) -> str:
    if type(value) is not str or _CAPTURED_AT_RE.fullmatch(value) is None:
        raise NativeTransferFinalityError(
            "capture timestamp must be canonical UTC RFC3339"
        )
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise NativeTransferFinalityError(
            "capture timestamp must be canonical UTC RFC3339"
        ) from exc
    return value


def _lower_hash(value: object, label: str) -> str:
    if type(value) is not str or _HASH_RE.fullmatch(value) is None:
        raise NativeTransferFinalityError(f"{label} must be lowercase 32-byte hex")
    return value


def _height(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise NativeTransferFinalityError(f"{label} must be a non-negative integer")
    return value


def _unwrap_result(payload: object, *, kind: str) -> dict[str, Any]:
    body = _dict(payload, f"{kind} result is malformed")
    if body.get("error") is not None:
        raise NativeTransferFinalityError(f"{kind} payload contains error")
    result = _dict(body.get("result"), f"{kind} result is malformed")
    if not result:
        raise NativeTransferFinalityError(f"{kind} result is malformed")
    if "value" in result or "name" in result:
        value = _dict(result.get("value"), f"{kind} result is malformed")
        if not value:
            raise NativeTransferFinalityError(f"{kind} result is malformed")
        return value
    return result


def _returned_deploy(value: dict[str, Any]) -> tuple[str, str]:
    has_deploy = "deploy" in value and value.get("deploy") is not None
    has_transaction = "transaction" in value and value.get("transaction") is not None
    if has_deploy == has_transaction:
        raise NativeTransferFinalityError(
            "RPC result must contain exactly one deploy or transaction"
        )
    if has_deploy:
        deploy = _dict(value["deploy"], "returned deploy is malformed")
        return "info_get_deploy", _lower_hash(
            deploy.get("hash"), "returned deploy hash"
        )

    transaction = _dict(value["transaction"], "returned transaction is malformed")
    variants = [name for name in ("Deploy", "Version1") if name in transaction]
    if len(variants) != 1 or len(transaction) != 1:
        raise NativeTransferFinalityError("returned transaction is malformed")
    transaction_body = _dict(
        transaction[variants[0]], "returned transaction is malformed"
    )
    return (
        "info_get_transaction",
        _lower_hash(transaction_body.get("hash"), "returned transaction hash"),
    )


def _walk_failure_markers(value: object) -> tuple[bool, bool]:
    """Return ``(failure_marker, non_null_error_message)`` recursively."""

    failure = False
    error = False
    if type(value) is dict:
        for key, child in value.items():
            if key in ("Failure", "failure"):
                failure = True
            if key in ("error_message", "errorMessage") and child not in (None, ""):
                error = True
            nested_failure, nested_error = _walk_failure_markers(child)
            failure = failure or nested_failure
            error = error or nested_error
    elif type(value) is list:
        for child in value:
            nested_failure, nested_error = _walk_failure_markers(child)
            failure = failure or nested_failure
            error = error or nested_error
    return failure, error


def _execution_cost(result_body: dict[str, Any]) -> int:
    cost_keys = [
        key for key in result_body if type(key) is str and key.casefold() == "cost"
    ]
    if not cost_keys:
        raise NativeTransferFinalityError("execution cost is required")
    if cost_keys != ["cost"]:
        raise NativeTransferFinalityError("execution cost is ambiguous")
    raw_cost = result_body["cost"]
    if type(raw_cost) is int:
        cost = raw_cost
    elif type(raw_cost) is str and _DECIMAL_RE.fullmatch(raw_cost) is not None:
        cost = int(raw_cost)
    else:
        raise NativeTransferFinalityError(
            "execution cost must be canonical non-negative U512 decimal"
        )
    if not 0 <= cost <= _MAX_U512:
        raise NativeTransferFinalityError(
            "execution cost must be canonical non-negative U512 decimal"
        )
    return cost


def _execution_success(execution_result: object) -> tuple[str, int]:
    result = _dict(execution_result, "processed execution result is required")
    if not result:
        raise NativeTransferFinalityError("processed execution result is required")

    has_success = "Success" in result
    has_failure = "Failure" in result or "failure" in result
    if has_success and has_failure:
        raise NativeTransferFinalityError("execution result is conflicting")
    if has_failure:
        raise NativeTransferFinalityError("execution failed")
    if has_success:
        success_body = _dict(
            result["Success"], "processed execution result is required"
        )
        failure, error = _walk_failure_markers(success_body)
        if failure or error:
            raise NativeTransferFinalityError("execution failed")
        return "Success", _execution_cost(success_body)

    variants = [name for name in ("Version1", "Version2") if name in result]
    if len(variants) != 1 or len(result) != 1:
        raise NativeTransferFinalityError(
            "execution result has no explicit success form"
        )
    name = variants[0]
    versioned = _dict(result[name], "processed execution result is required")
    if name == "Version1":
        nested_kind, gas_motes = _execution_success(versioned)
        return f"Version1.{nested_kind}", gas_motes

    failure, error = _walk_failure_markers(versioned)
    if failure or error:
        raise NativeTransferFinalityError("execution failed")
    if "error_message" not in versioned and "errorMessage" not in versioned:
        raise NativeTransferFinalityError(
            "execution result has no explicit success form"
        )
    error_message = versioned.get("error_message", versioned.get("errorMessage"))
    if error_message not in (None, ""):
        raise NativeTransferFinalityError("execution failed")
    return "Version2", _execution_cost(versioned)


def _parse_rpc_observation(payload: object) -> _RpcObservation:
    value = _unwrap_result(payload, kind="RPC")
    rpc_method, deploy_hash = _returned_deploy(value)

    has_info = "execution_info" in value or "executionInfo" in value
    has_results = "execution_results" in value or "executionResults" in value
    if has_info and has_results:
        raise NativeTransferFinalityError("execution evidence is ambiguous")
    if not has_info and not has_results:
        raise NativeTransferFinalityError("processed execution result is required")

    if has_info:
        raw_info = value.get("execution_info", value.get("executionInfo"))
        info = _dict(raw_info, "processed execution result is required")
        if not info:
            raise NativeTransferFinalityError("processed execution result is required")
        execution_result = info.get("execution_result", info.get("executionResult"))
        kind, gas_motes = _execution_success(execution_result)
        block_hash = _lower_hash(
            info.get("block_hash", info.get("blockHash")), "execution block hash"
        )
        block_height = _height(
            info.get("block_height", info.get("blockHeight")),
            "execution block height",
        )
    else:
        raw_results = value.get("execution_results", value.get("executionResults"))
        if type(raw_results) is not list or len(raw_results) != 1:
            raise NativeTransferFinalityError(
                "exactly one execution result is required"
            )
        item = _dict(raw_results[0], "processed execution result is required")
        kind, gas_motes = _execution_success(
            item.get("result", item.get("execution_result"))
        )
        block_hash = _lower_hash(
            item.get("block_hash", item.get("blockHash")), "execution block hash"
        )
        raw_height = item.get("block_height", item.get("blockHeight"))
        block_height = (
            None
            if raw_height is None
            else _height(raw_height, "execution block height")
        )

    return _RpcObservation(
        deploy_hash=deploy_hash,
        block_hash=block_hash,
        block_height=block_height,
        rpc_method=rpc_method,
        execution_result_kind=kind,
        gas_motes=gas_motes,
    )


def _unwrap_block(value: dict[str, Any]) -> tuple[dict[str, Any], str]:
    if "block_with_signatures" in value:
        wrapper = _dict(
            value["block_with_signatures"], "canonical block result is malformed"
        )
        raw_block = _dict(wrapper.get("block"), "canonical block result is malformed")
    elif "block" in value:
        raw_block = _dict(value["block"], "canonical block result is malformed")
    else:
        raise NativeTransferFinalityError("canonical block result is malformed")

    versions = [name for name in ("Version1", "Version2") if name in raw_block]
    if versions:
        if len(versions) != 1 or len(raw_block) != 1:
            raise NativeTransferFinalityError("canonical block result is malformed")
        return _dict(
            raw_block[versions[0]], "canonical block result is malformed"
        ), versions[0]
    return raw_block, "Legacy"


def _hash_list(value: object, label: str) -> list[str]:
    if value is None:
        return []
    if type(value) is not list:
        raise NativeTransferFinalityError("canonical block result is malformed")
    return [_lower_hash(item, label) for item in value]


def _find_block_inclusion(body: dict[str, Any], deploy_hash: str, version: str) -> str:
    paths: list[str] = []
    if version in ("Legacy", "Version1"):
        if "deploy_hashes" not in body and "transfer_hashes" not in body:
            raise NativeTransferFinalityError("canonical block result is malformed")
        for field in ("deploy_hashes", "transfer_hashes"):
            hashes = _hash_list(body.get(field), f"canonical block {field} entry")
            paths.extend(field for item in hashes if item == deploy_hash)
    else:
        transactions = _dict(
            body.get("transactions"), "canonical block result is malformed"
        )
        for lane, items in transactions.items():
            if type(lane) is not str or type(items) is not list:
                raise NativeTransferFinalityError("canonical block result is malformed")
            for item in items:
                entry = _dict(item, "canonical block result is malformed")
                variants = [name for name in ("Deploy", "Version1") if name in entry]
                if len(variants) != 1 or len(entry) != 1:
                    raise NativeTransferFinalityError(
                        "canonical block result is malformed"
                    )
                candidate = _lower_hash(
                    entry[variants[0]], "canonical block transaction hash"
                )
                if candidate == deploy_hash:
                    paths.append(f"transactions.{lane}")

    if not paths:
        raise NativeTransferFinalityError(
            "requested deploy is absent from canonical block"
        )
    if len(paths) != 1:
        raise NativeTransferFinalityError(
            "requested deploy appears multiple times in canonical block"
        )
    return paths[0]


def _parse_canonical_block(payload: object, deploy_hash: str) -> _CanonicalBlock:
    value = _unwrap_result(payload, kind="canonical block")
    block, version = _unwrap_block(value)
    block_hash = _lower_hash(block.get("hash"), "canonical block hash")
    header = _dict(block.get("header"), "canonical block result is malformed")
    block_height = _height(header.get("height"), "canonical block height")
    state_root_hash = _lower_hash(
        header.get("state_root_hash", header.get("stateRootHash")),
        "canonical state root hash",
    )
    body = _dict(block.get("body"), "canonical block result is malformed")
    inclusion_path = _find_block_inclusion(body, deploy_hash, version)
    return _CanonicalBlock(
        block_hash=block_hash,
        block_height=block_height,
        state_root_hash=state_root_hash,
        inclusion_path=inclusion_path,
    )


def _require_result_name(payload: object, expected: str, label: str) -> None:
    body = _dict(payload, f"{label} response is malformed")
    result = _dict(body.get("result"), f"{label} result is malformed")
    if "name" in result and result.get("name") != expected:
        raise NativeTransferFinalityError(
            f"{label} result name does not match request method"
        )


def _transaction_params(method: str, deploy_hash: str) -> dict[str, Any]:
    if method == "info_get_deploy":
        return {"deploy_hash": deploy_hash, "finalized_approvals": True}
    if method == "info_get_transaction":
        return {
            "transaction_hash": {"Deploy": deploy_hash},
            "finalized_approvals": True,
        }
    raise NativeTransferFinalityError("transaction request method is unsupported")


def _parse_node_observation(
    value: object, requested_hash: str
) -> _VerifiedNodeObservation:
    try:
        raw = _dict(value, "node observation is malformed")
        expected_fields = {
            "node_url",
            "captured_at",
            "status_request",
            "status_response",
            "transaction_request",
            "transaction_response",
            "canonical_block_request",
            "canonical_block_response",
        }
        if set(raw) != expected_fields:
            raise NativeTransferFinalityError(
                "node observation must contain exactly frozen fields"
            )
        node_url = _public_node_url(raw["node_url"])
        captured_at = _capture_timestamp(raw["captured_at"])

        status_id = _parse_exact_request(
            raw["status_request"],
            method="info_get_status",
            params={},
            label="status",
        )
        status_response = _require_exact_response(
            raw["status_response"], status_id, "status"
        )
        _require_result_name(status_response, "info_get_status_result", "status")
        _parse_status_network(status_response)

        transaction_response_body = _dict(
            raw["transaction_response"], "transaction response is malformed"
        )
        rpc = _parse_rpc_observation(transaction_response_body)
        if rpc.deploy_hash != requested_hash:
            raise NativeTransferFinalityError(
                "returned deploy hash does not match requested hash"
            )
        transaction_id = _parse_exact_request(
            raw["transaction_request"],
            method=rpc.rpc_method,
            params=_transaction_params(rpc.rpc_method, requested_hash),
            label="transaction",
        )
        _require_exact_response(
            transaction_response_body, transaction_id, "transaction"
        )
        _require_result_name(
            transaction_response_body, f"{rpc.rpc_method}_result", "transaction"
        )
        block_id = _parse_exact_request(
            raw["canonical_block_request"],
            method="chain_get_block",
            params={"block_identifier": {"Hash": rpc.block_hash}},
            label="canonical block",
        )
        canonical_block_response = _require_exact_response(
            raw["canonical_block_response"], block_id, "canonical block"
        )
        _require_result_name(
            canonical_block_response,
            "chain_get_block_result",
            "canonical block",
        )
        block = _parse_canonical_block(canonical_block_response, requested_hash)
        if block.block_hash != rpc.block_hash:
            raise NativeTransferFinalityError(
                "canonical block hash does not match execution block"
            )
        if rpc.block_height is not None and rpc.block_height != block.block_height:
            raise NativeTransferFinalityError(
                "execution block height does not match canonical block"
            )

        transcript = _canonical_json(raw, "node observation transcript")
        return _VerifiedNodeObservation(
            node_url=node_url,
            captured_at=captured_at,
            rpc=rpc,
            block=block,
            transcript_json=transcript.decode("ascii"),
            transcript_sha256=hashlib.sha256(transcript).hexdigest(),
        )
    except NativeTransferFinalityError as exc:
        message = str(exc)
        if (
            message.startswith("node observation")
            or "node URL" in message
            or "capture timestamp" in message
        ):
            raise
        raise NativeTransferFinalityError(
            f"node observation is malformed: {message}"
        ) from exc


def verify_finalized_native_transfer(
    *,
    requested_deploy_hash: str,
    node_observations: Sequence[dict[str, Any]],
    signed_deploy_bytes: bytes,
    expected_source_account_hash: bytes,
    expected_recipient_account_hash: bytes,
    expected_amount_motes: int,
    expected_transfer_id: int,
    expected_payment_amount_motes: int = DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
    max_payment_amount_motes: int = DEFAULT_NATIVE_TRANSFER_PAYMENT_MOTES,
) -> FinalizedNativeTransferProof:
    """Verify two-node execution agreement, block inclusion, and signed bytes.

    This is deliberately an RPC-observation proof, not validator-signature or
    trustless consensus verification.  Every node observation must carry its
    credential-free public URL, capture time, and exact raw requests/responses.
    """

    requested_hash = _lower_hash(requested_deploy_hash, "requested deploy hash")
    if type(node_observations) not in (tuple, list) or len(node_observations) < 2:
        raise NativeTransferFinalityError(
            "at least two distinct public RPC node observations are required"
        )
    observations = tuple(
        _parse_node_observation(value, requested_hash) for value in node_observations
    )
    node_urls = tuple(item.node_url for item in observations)
    node_origins = tuple(_node_origin(url) for url in node_urls)
    if len(set(node_origins)) != len(node_origins):
        raise NativeTransferFinalityError(
            "node observations must use distinct public RPC node URLs"
        )

    observation = observations[0].rpc
    block = observations[0].block
    expected_agreement = (
        observation.deploy_hash,
        observation.block_hash,
        block.block_height,
        block.state_root_hash,
        observation.gas_motes,
    )
    for item in observations[1:]:
        actual_agreement = (
            item.rpc.deploy_hash,
            item.rpc.block_hash,
            item.block.block_height,
            item.block.state_root_hash,
            item.rpc.gas_motes,
        )
        if actual_agreement != expected_agreement:
            raise NativeTransferFinalityError("node observations conflict")

    try:
        signed_deploy = validate_signed_native_transfer_deploy(
            signed_deploy_bytes,
            expected_source_account_hash=expected_source_account_hash,
            expected_recipient_account_hash=expected_recipient_account_hash,
            expected_amount_motes=expected_amount_motes,
            expected_transfer_id=expected_transfer_id,
            expected_payment_amount_motes=expected_payment_amount_motes,
            max_payment_amount_motes=max_payment_amount_motes,
        )
    except NativeTransferDeployError as exc:
        raise NativeTransferFinalityError("signed deploy validation failed") from exc
    if signed_deploy.deploy_hash_hex != requested_hash:
        raise NativeTransferFinalityError(
            "signed deploy hash does not match requested hash"
        )

    return _make_finalized_proof(
        requested_deploy_hash=requested_hash,
        deploy_hash=signed_deploy.deploy_hash_hex,
        network="casper-test",
        block_hash=block.block_hash,
        block_height=block.block_height,
        state_root_hash=block.state_root_hash,
        rpc_method=observation.rpc_method,
        execution_result_kind=observation.execution_result_kind,
        gas_motes=observation.gas_motes,
        block_inclusion_path=block.inclusion_path,
        finality_predicate=True,
        finality_checks=FINALITY_PREDICATE_CHECKS,
        node_observation_count=len(observations),
        corroboration_count=len(observations) - 1,
        node_urls=node_urls,
        captured_at=tuple(item.captured_at for item in observations),
        rpc_methods=tuple(item.rpc.rpc_method for item in observations),
        node_observation_json=tuple(item.transcript_json for item in observations),
        node_observation_sha256=tuple(item.transcript_sha256 for item in observations),
        verification_scope=(
            "two-or-more-public-rpc-nodes-agree;validator-signatures-not-verified"
        ),
        signed_deploy=signed_deploy,
    )


__all__ = [
    "FINALITY_PREDICATE_CHECKS",
    "FinalizedNativeTransferProof",
    "NativeTransferFinalityError",
    "require_verified_finalized_native_transfer",
    "verify_finalized_native_transfer",
]
