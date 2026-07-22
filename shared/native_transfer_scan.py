"""Strict, time-bounded proof that one governed native transfer executed once.

The proof scans every canonical block from the v3 authorization block through
an observed Casper tip using ``chain_get_block`` and
``chain_get_block_transfers``.  It is intentionally time-bounded: it proves no
second transfer with the governed source/transfer-id existed through the stated
height, while the executor journal prevents future rebroadcasts.

Network I/O lives in release tooling.  This module accepts and seals exact raw
JSON-RPC request/response transcripts only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Sequence

from shared.native_transfer_finality import (
    FinalizedNativeTransferProof,
    require_verified_finalized_native_transfer,
)


_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ACCOUNT_RE = re.compile(r"^account-hash-([0-9a-f]{64})$")
_DECIMAL_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")
_MAX_TRANSCRIPT_BYTES = 32 * 1024 * 1024
_MAX_SCAN_BLOCKS = 2_048
_FACTORY_SEAL = object()
_INTEGRITY_KEY = secrets.token_bytes(32)


class NativeTransferScanError(ValueError):
    """Raw chain evidence does not prove exactly one governed transfer."""


@dataclass(frozen=True, slots=True, init=False)
class VerifiedNoDuplicateNativeTransfer:
    """Immutable facts created only by the exact block-scan parser."""

    network: str
    authorization_block_height: int
    authorization_block_hash: str
    inclusion_block_height: int
    observed_through_block_height: int
    observed_through_block_hash: str
    scanned_block_count: int
    matched_transfer_count: int
    deploy_hash: str
    source_account_hash: bytes
    recipient_account_hash: bytes
    amount_motes: int
    transfer_id: int
    transcript_json: str
    transcript_sha256: str
    _factory_seal: object = field(repr=False, compare=False)
    _integrity_tag: bytes = field(repr=False, compare=False)

    def __new__(cls, *_args: object, **_kwargs: object) -> VerifiedNoDuplicateNativeTransfer:
        raise TypeError(
            "VerifiedNoDuplicateNativeTransfer is created only by "
            "verify_no_duplicate_native_transfer"
        )


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
        raise NativeTransferScanError(f"{label} is not canonical JSON") from exc
    if len(encoded) > _MAX_TRANSCRIPT_BYTES:
        raise NativeTransferScanError(f"{label} exceeds transcript size limit")
    return encoded


def _integrity_tag(proof: VerifiedNoDuplicateNativeTransfer) -> bytes:
    material = {
        "network": proof.network,
        "authorization_block_height": proof.authorization_block_height,
        "authorization_block_hash": proof.authorization_block_hash,
        "inclusion_block_height": proof.inclusion_block_height,
        "observed_through_block_height": proof.observed_through_block_height,
        "observed_through_block_hash": proof.observed_through_block_hash,
        "scanned_block_count": proof.scanned_block_count,
        "matched_transfer_count": proof.matched_transfer_count,
        "deploy_hash": proof.deploy_hash,
        "source_account_hash": proof.source_account_hash.hex(),
        "recipient_account_hash": proof.recipient_account_hash.hex(),
        "amount_motes": str(proof.amount_motes),
        "transfer_id": proof.transfer_id,
        "transcript_sha256": proof.transcript_sha256,
    }
    return hmac.new(
        _INTEGRITY_KEY,
        _canonical_json(material, "scan proof"),
        hashlib.sha256,
    ).digest()


def _make_proof(**values: object) -> VerifiedNoDuplicateNativeTransfer:
    proof = object.__new__(VerifiedNoDuplicateNativeTransfer)
    for name, value in values.items():
        object.__setattr__(proof, name, value)
    object.__setattr__(proof, "_factory_seal", _FACTORY_SEAL)
    object.__setattr__(proof, "_integrity_tag", _integrity_tag(proof))
    return proof


def require_verified_no_duplicate_native_transfer(
    value: object,
) -> VerifiedNoDuplicateNativeTransfer:
    """Accept only an untampered proof created by this parser process."""

    if (
        type(value) is not VerifiedNoDuplicateNativeTransfer
        or getattr(value, "_factory_seal", None) is not _FACTORY_SEAL
    ):
        raise NativeTransferScanError("transfer scan is not parser-verified")
    tag = getattr(value, "_integrity_tag", None)
    if type(tag) is not bytes or not hmac.compare_digest(tag, _integrity_tag(value)):
        raise NativeTransferScanError("transfer scan proof integrity check failed")
    if (
        value.network != "casper-test"
        or value.matched_transfer_count != 1
        or value.scanned_block_count
        != value.observed_through_block_height - value.authorization_block_height + 1
        or value.inclusion_block_height < value.authorization_block_height
        or value.inclusion_block_height > value.observed_through_block_height
        or _HASH_RE.fullmatch(value.authorization_block_hash) is None
        or _HASH_RE.fullmatch(value.deploy_hash) is None
        or _HASH_RE.fullmatch(value.observed_through_block_hash) is None
        or type(value.source_account_hash) is not bytes
        or len(value.source_account_hash) != 32
        or type(value.recipient_account_hash) is not bytes
        or len(value.recipient_account_hash) != 32
        or type(value.amount_motes) is not int
        or value.amount_motes <= 0
        or type(value.transfer_id) is not int
        or not 0 <= value.transfer_id < 1 << 64
    ):
        raise NativeTransferScanError("transfer scan proof integrity check failed")
    try:
        decoded = json.loads(value.transcript_json)
    except (TypeError, json.JSONDecodeError) as exc:
        raise NativeTransferScanError("transfer scan proof integrity check failed") from exc
    encoded = _canonical_json(decoded, "scan transcript")
    if (
        encoded.decode("ascii") != value.transcript_json
        or hashlib.sha256(encoded).hexdigest() != value.transcript_sha256
    ):
        raise NativeTransferScanError("transfer scan proof integrity check failed")
    return value


def _object(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise NativeTransferScanError(f"{label} must be an object")
    return value


def _list(value: object, label: str) -> list[Any]:
    if type(value) is not list:
        raise NativeTransferScanError(f"{label} must be a list")
    return value


def _hash(value: object, label: str) -> str:
    if type(value) is not str or _HASH_RE.fullmatch(value) is None:
        raise NativeTransferScanError(f"{label} must be lowercase 32-byte hex")
    return value


def _height(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise NativeTransferScanError(f"{label} must be a non-negative u64")
    return value


def _request_id(value: object, label: str) -> int | str:
    if type(value) not in (int, str) or value == "":
        raise NativeTransferScanError(f"{label} request id is invalid")
    return value


def _unwrap_result(payload: object, label: str) -> tuple[dict[str, Any], int | str]:
    body = _object(payload, f"{label} response")
    if body.get("jsonrpc") != "2.0" or body.get("error") is not None:
        raise NativeTransferScanError(f"{label} response is invalid")
    response_id = _request_id(body.get("id"), label)
    result = _object(body.get("result"), f"{label} result")
    if "name" in result or "value" in result:
        if set(result) != {"name", "value"} or type(result.get("name")) is not str:
            raise NativeTransferScanError(f"{label} result is malformed")
        result = _object(result.get("value"), f"{label} result")
    return result, response_id


def _exact_request(
    request: object,
    *,
    method: str,
    params: dict[str, Any],
    label: str,
) -> int | str:
    body = _object(request, f"{label} request")
    if set(body) != {"jsonrpc", "id", "method", "params"}:
        raise NativeTransferScanError(f"{label} request fields are not exact")
    if body.get("jsonrpc") != "2.0" or body.get("method") != method:
        raise NativeTransferScanError(f"{label} request must call {method}")
    if body.get("params") != params:
        raise NativeTransferScanError(f"{label} request params do not match")
    return _request_id(body.get("id"), label)


def _require_response_id(actual: int | str, expected: int | str, label: str) -> None:
    if actual != expected:
        raise NativeTransferScanError(f"{label} response id does not match request id")


def _parse_status(request: object, response: object) -> tuple[int, str]:
    request_id = _exact_request(
        request,
        method="info_get_status",
        params={},
        label="status",
    )
    result, response_id = _unwrap_result(response, "status")
    _require_response_id(response_id, request_id, "status")
    names = [
        item
        for item in (
            result.get("chainspec_name"),
            result.get("chainspecName"),
            result.get("chain_name"),
        )
        if item is not None
    ]
    if len(names) != 1 or names[0] != "casper-test":
        raise NativeTransferScanError("status must prove chain casper-test")
    tip = _object(
        result.get("last_added_block_info", result.get("lastAddedBlockInfo")),
        "status observed tip",
    )
    return _height(tip.get("height"), "status observed tip height"), _hash(
        tip.get("hash", tip.get("block_hash")),
        "status observed tip block hash",
    )


def _parse_block(
    request: object,
    response: object,
    expected_height: int,
) -> tuple[str, str]:
    request_id = _exact_request(
        request,
        method="chain_get_block",
        params={"block_identifier": {"Height": expected_height}},
        label=f"block {expected_height}",
    )
    result, response_id = _unwrap_result(response, f"block {expected_height}")
    _require_response_id(response_id, request_id, f"block {expected_height}")
    if "block_with_signatures" in result:
        wrapper = _object(result["block_with_signatures"], "canonical block wrapper")
        raw = _object(wrapper.get("block"), "canonical block")
    else:
        raw = _object(result.get("block"), "canonical block")
    variants = [variant for variant in ("Version1", "Version2") if variant in raw]
    if variants:
        if len(variants) != 1 or len(raw) != 1:
            raise NativeTransferScanError("canonical block is ambiguous")
        raw = _object(raw[variants[0]], "canonical block")
    block_hash = _hash(raw.get("hash"), "canonical block hash")
    header = _object(raw.get("header"), "canonical block header")
    if _height(header.get("height"), "canonical block height") != expected_height:
        raise NativeTransferScanError("canonical block height does not match request")
    parent_hash = _hash(header.get("parent_hash"), "canonical parent hash")
    _object(raw.get("body"), "canonical block body")
    return block_hash, parent_hash


def _account_hash(value: object, label: str) -> bytes:
    if type(value) is dict:
        obj = _object(value, label)
        if set(obj) != {"AccountHash"}:
            raise NativeTransferScanError(f"{label} must be an account hash")
        value = obj["AccountHash"]
    if type(value) is not str:
        raise NativeTransferScanError(f"{label} must be an account hash")
    match = _ACCOUNT_RE.fullmatch(value)
    if match is None and _HASH_RE.fullmatch(value) is not None:
        return bytes.fromhex(value)
    if match is None:
        raise NativeTransferScanError(f"{label} must be an account hash")
    return bytes.fromhex(match.group(1))


def _transaction_hash(value: object, label: str) -> str:
    if type(value) is str:
        return _hash(value, label)
    obj = _object(value, label)
    variants = [name for name in ("Deploy", "Version1") if name in obj]
    if len(variants) != 1 or len(obj) != 1:
        raise NativeTransferScanError(f"{label} is malformed")
    return _hash(obj[variants[0]], label)


def _canonical_amount(value: object, label: str) -> int:
    if type(value) is not str or _DECIMAL_RE.fullmatch(value) is None:
        raise NativeTransferScanError(f"{label} must be canonical decimal")
    return int(value)


def _parse_transfers(
    request: object,
    response: object,
    *,
    expected_block_hash: str,
    expected_height: int,
) -> list[dict[str, object]]:
    request_id = _exact_request(
        request,
        method="chain_get_block_transfers",
        params={"block_identifier": {"Hash": expected_block_hash}},
        label=f"block transfers {expected_height}",
    )
    result, response_id = _unwrap_result(response, f"block transfers {expected_height}")
    _require_response_id(response_id, request_id, f"block transfers {expected_height}")
    if _hash(result.get("block_hash"), "transfer response block hash") != expected_block_hash:
        raise NativeTransferScanError("transfer response block hash does not match block")
    transfers = _list(result.get("transfers"), "block transfers")
    parsed: list[dict[str, object]] = []
    for index, wrapped in enumerate(transfers):
        wrapper = _object(wrapped, f"transfer {index}")
        variants = [name for name in ("Version1", "Version2") if name in wrapper]
        if len(variants) != 1 or len(wrapper) != 1:
            raise NativeTransferScanError(f"transfer {index} is ambiguous")
        version = variants[0]
        transfer = _object(wrapper[version], f"transfer {index}")
        hash_field = "deploy_hash" if version == "Version1" else "transaction_hash"
        parsed.append(
            {
                "deploy_hash": _transaction_hash(transfer.get(hash_field), f"transfer {index} hash"),
                "source": _account_hash(transfer.get("from"), f"transfer {index} source"),
                "recipient": _account_hash(transfer.get("to"), f"transfer {index} recipient"),
                "amount": _canonical_amount(transfer.get("amount"), f"transfer {index} amount"),
                "id": transfer.get("id"),
            }
        )
    return parsed


def verify_no_duplicate_native_transfer(
    *,
    chain_status_request: dict[str, Any],
    chain_status_response: dict[str, Any],
    block_observations: Sequence[dict[str, Any]],
    authorization_block_height: int,
    finality_proof: FinalizedNativeTransferProof,
) -> VerifiedNoDuplicateNativeTransfer:
    """Verify a contiguous canonical scan contains one governed transfer."""

    finality = require_verified_finalized_native_transfer(finality_proof)
    start = _height(authorization_block_height, "authorization block height")
    if start > finality.block_height:
        raise NativeTransferScanError(
            "authorization block height cannot follow transfer inclusion"
        )
    observed_height, observed_hash = _parse_status(
        chain_status_request,
        chain_status_response,
    )
    if observed_height < finality.block_height:
        raise NativeTransferScanError("observed tip precedes transfer inclusion")
    expected_count = observed_height - start + 1
    if expected_count > _MAX_SCAN_BLOCKS:
        raise NativeTransferScanError("block scan exceeds bounded range")
    if len(block_observations) != expected_count:
        raise NativeTransferScanError("block scan is not contiguous")

    signed = finality.signed_deploy
    relevant: list[tuple[int, str, dict[str, object]]] = []
    seen_hashes: set[str] = set()
    previous_hash: str | None = None
    authorization_block_hash: str | None = None
    for offset, observation in enumerate(block_observations):
        height = start + offset
        item = _object(observation, f"block observation {height}")
        if set(item) != {
            "block_request",
            "block_response",
            "transfers_request",
            "transfers_response",
        }:
            raise NativeTransferScanError("block observation fields are not exact")
        block_hash, parent_hash = _parse_block(
            item["block_request"], item["block_response"], height
        )
        if height == start:
            authorization_block_hash = block_hash
        if block_hash in seen_hashes:
            raise NativeTransferScanError("canonical block hash repeats within scan")
        if previous_hash is not None and parent_hash != previous_hash:
            raise NativeTransferScanError("block scan parent chain is not contiguous")
        seen_hashes.add(block_hash)
        previous_hash = block_hash
        for transfer in _parse_transfers(
            item["transfers_request"],
            item["transfers_response"],
            expected_block_hash=block_hash,
            expected_height=height,
        ):
            transfer_id = transfer["id"]
            if (
                transfer["source"] == signed.source_account_hash
                and type(transfer_id) is int
                and transfer_id == signed.transfer_id
            ):
                relevant.append((height, block_hash, transfer))

    if block_hash != observed_hash:
        raise NativeTransferScanError("block scan does not end at observed tip")
    if authorization_block_hash is None:
        raise NativeTransferScanError("authorization block was not observed")
    if len(relevant) != 1:
        raise NativeTransferScanError(
            "scan must contain exactly one transfer for source and transfer id"
        )
    matched_height, matched_block_hash, matched = relevant[0]
    if (
        matched_height != finality.block_height
        or matched_block_hash != finality.block_hash
        or matched["deploy_hash"] != finality.deploy_hash
        or matched["recipient"] != signed.recipient_account_hash
        or matched["amount"] != signed.amount_motes
    ):
        raise NativeTransferScanError(
            "only matching transfer does not equal the finalized action"
        )

    transcript = {
        "authorization_block_height": start,
        "chain_status_request": chain_status_request,
        "chain_status_response": chain_status_response,
        "block_observations": list(block_observations),
    }
    encoded = _canonical_json(transcript, "scan transcript")
    proof = _make_proof(
        network="casper-test",
        authorization_block_height=start,
        authorization_block_hash=authorization_block_hash,
        inclusion_block_height=finality.block_height,
        observed_through_block_height=observed_height,
        observed_through_block_hash=observed_hash,
        scanned_block_count=expected_count,
        matched_transfer_count=1,
        deploy_hash=finality.deploy_hash,
        source_account_hash=signed.source_account_hash,
        recipient_account_hash=signed.recipient_account_hash,
        amount_motes=signed.amount_motes,
        transfer_id=signed.transfer_id,
        transcript_json=encoded.decode("ascii"),
        transcript_sha256=hashlib.sha256(encoded).hexdigest(),
    )
    return require_verified_no_duplicate_native_transfer(proof)


def verify_no_duplicate_native_transfer_transcript(
    transcript_json: str,
    *,
    finality_proof: FinalizedNativeTransferProof,
) -> VerifiedNoDuplicateNativeTransfer:
    """Reparse a persisted scan transcript instead of trusting summary fields."""

    if type(transcript_json) is not str:
        raise NativeTransferScanError("scan transcript must be JSON text")
    try:
        transcript = json.loads(transcript_json)
    except json.JSONDecodeError as exc:
        raise NativeTransferScanError("scan transcript is malformed") from exc
    encoded = _canonical_json(transcript, "scan transcript")
    if encoded.decode("ascii") != transcript_json:
        raise NativeTransferScanError("scan transcript is not canonical")
    body = _object(transcript, "scan transcript")
    if set(body) != {
        "authorization_block_height",
        "chain_status_request",
        "chain_status_response",
        "block_observations",
    }:
        raise NativeTransferScanError("scan transcript fields are not exact")
    return verify_no_duplicate_native_transfer(
        chain_status_request=_object(body["chain_status_request"], "status request"),
        chain_status_response=_object(body["chain_status_response"], "status response"),
        block_observations=_list(body["block_observations"], "block observations"),
        authorization_block_height=body["authorization_block_height"],
        finality_proof=finality_proof,
    )
