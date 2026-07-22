"""Strict offline proof of an account balance at one canonical Casper block.

The verifier accepts raw node JSON-RPC observations and the exact
``query_balance_details`` request.  It binds chain, block hash, height, state
root, account identity, total balance, active holds, and available balance
without trusting artifact booleans or a caller's pre-decoded fields.  The
node-provided Merkle proof is retained verbatim but is not cryptographically
verified by this module.  Network I/O intentionally lives in release tooling.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any


_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_DECIMAL_RE = re.compile(r"^(0|[1-9][0-9]*)$")
_PROOF_RE = re.compile(r"^(?:[0-9a-f]{2})+$")
_MAX_U512 = (1 << 512) - 1
_MAX_TRANSCRIPT_BYTES = 4 * 1024 * 1024
_FACTORY_SEAL = object()
_INTEGRITY_KEY = secrets.token_bytes(32)


class CasperStateProofError(ValueError):
    """Node evidence does not prove the expected historical account balance."""


@dataclass(frozen=True, slots=True, init=False)
class VerifiedAccountBalance:
    """Immutable balance facts constructible only by the strict parser."""

    network: str
    account_hash: bytes
    block_hash: bytes
    block_height: int
    state_root_hash: bytes
    balance_motes: int
    available_balance_motes: int
    balance_holds_total_motes: int
    balance_holds_json: str
    node_provided_merkle_proof: bytes
    merkle_proof_verification_scope: str
    balance_request_method: str
    balance_request_id: int | str
    status_request_json: str
    status_json: str
    block_request_json: str
    block_json: str
    balance_request_json: str
    balance_response_json: str
    status_request_sha256: str
    status_sha256: str
    block_request_sha256: str
    block_sha256: str
    balance_request_sha256: str
    balance_response_sha256: str
    _factory_seal: object = field(repr=False, compare=False)
    _integrity_tag: bytes = field(repr=False, compare=False)

    def __new__(cls, *_args: object, **_kwargs: object) -> VerifiedAccountBalance:
        raise TypeError(
            "VerifiedAccountBalance is created only by verify_account_balance_at_block"
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
        raise CasperStateProofError(f"{label} is not canonical JSON") from exc
    if len(encoded) > _MAX_TRANSCRIPT_BYTES:
        raise CasperStateProofError(f"{label} exceeds transcript size limit")
    return encoded


def _integrity_tag(proof: VerifiedAccountBalance) -> bytes:
    fields = {
        "network": proof.network,
        "account_hash": proof.account_hash.hex(),
        "block_hash": proof.block_hash.hex(),
        "block_height": proof.block_height,
        "state_root_hash": proof.state_root_hash.hex(),
        "balance_motes": str(proof.balance_motes),
        "available_balance_motes": str(proof.available_balance_motes),
        "balance_holds_total_motes": str(proof.balance_holds_total_motes),
        "balance_holds_sha256": hashlib.sha256(
            proof.balance_holds_json.encode("ascii")
        ).hexdigest(),
        "node_provided_merkle_proof_sha256": hashlib.sha256(
            proof.node_provided_merkle_proof
        ).hexdigest(),
        "merkle_proof_verification_scope": proof.merkle_proof_verification_scope,
        "balance_request_method": proof.balance_request_method,
        "balance_request_id": proof.balance_request_id,
        "status_request_sha256": proof.status_request_sha256,
        "status_sha256": proof.status_sha256,
        "block_request_sha256": proof.block_request_sha256,
        "block_sha256": proof.block_sha256,
        "balance_request_sha256": proof.balance_request_sha256,
        "balance_response_sha256": proof.balance_response_sha256,
    }
    return hmac.new(
        _INTEGRITY_KEY,
        _canonical_json(fields, "balance proof"),
        hashlib.sha256,
    ).digest()


def _make_proof(**values: object) -> VerifiedAccountBalance:
    proof = object.__new__(VerifiedAccountBalance)
    for name, value in values.items():
        object.__setattr__(proof, name, value)
    object.__setattr__(proof, "_factory_seal", _FACTORY_SEAL)
    object.__setattr__(proof, "_integrity_tag", _integrity_tag(proof))
    return proof


def require_verified_account_balance(value: object) -> VerifiedAccountBalance:
    """Return only an untampered proof issued by this parser process."""

    if (
        type(value) is not VerifiedAccountBalance
        or getattr(value, "_factory_seal", None) is not _FACTORY_SEAL
    ):
        raise CasperStateProofError("account balance proof is not parser-verified")
    tag = getattr(value, "_integrity_tag", None)
    if type(tag) is not bytes or not hmac.compare_digest(tag, _integrity_tag(value)):
        raise CasperStateProofError("account balance proof integrity check failed")
    if (
        value.network != "casper-test"
        or type(value.account_hash) is not bytes
        or len(value.account_hash) != 32
        or type(value.block_hash) is not bytes
        or len(value.block_hash) != 32
        or type(value.state_root_hash) is not bytes
        or len(value.state_root_hash) != 32
        or type(value.block_height) is not int
        or value.block_height < 0
        or type(value.balance_motes) is not int
        or not 0 <= value.balance_motes <= _MAX_U512
        or type(value.available_balance_motes) is not int
        or not 0 <= value.available_balance_motes <= value.balance_motes
        or type(value.balance_holds_total_motes) is not int
        or value.balance_holds_total_motes
        != value.balance_motes - value.available_balance_motes
        or type(value.balance_holds_json) is not str
        or type(value.node_provided_merkle_proof) is not bytes
        or not value.node_provided_merkle_proof
        or value.merkle_proof_verification_scope != "node-provided-not-locally-verified"
        or value.balance_request_method != "query_balance_details"
    ):
        raise CasperStateProofError("account balance proof integrity check failed")
    transcript_pairs = (
        (
            value.status_request_json,
            value.status_request_sha256,
            "status request transcript",
        ),
        (value.status_json, value.status_sha256, "status transcript"),
        (
            value.block_request_json,
            value.block_request_sha256,
            "block request transcript",
        ),
        (value.block_json, value.block_sha256, "block transcript"),
        (
            value.balance_request_json,
            value.balance_request_sha256,
            "balance request transcript",
        ),
        (
            value.balance_response_json,
            value.balance_response_sha256,
            "balance response transcript",
        ),
    )
    for encoded, expected_sha256, label in transcript_pairs:
        if type(encoded) is not str or type(expected_sha256) is not str:
            raise CasperStateProofError("account balance proof integrity check failed")
        try:
            decoded = json.loads(encoded)
        except json.JSONDecodeError as exc:
            raise CasperStateProofError(
                "account balance proof integrity check failed"
            ) from exc
        canonical = _canonical_json(decoded, label)
        if (
            canonical.decode("ascii") != encoded
            or hashlib.sha256(canonical).hexdigest() != expected_sha256
        ):
            raise CasperStateProofError("account balance proof integrity check failed")
    try:
        holds = json.loads(value.balance_holds_json)
    except json.JSONDecodeError as exc:
        raise CasperStateProofError(
            "account balance proof integrity check failed"
        ) from exc
    holds_json = _canonical_json(holds, "balance holds")
    if holds_json.decode("ascii") != value.balance_holds_json:
        raise CasperStateProofError("account balance proof integrity check failed")
    return value


def _object(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise CasperStateProofError(f"{label} must be an object")
    return value


def _lower_hash(value: object, label: str) -> str:
    if type(value) is not str or _HASH_RE.fullmatch(value) is None:
        raise CasperStateProofError(f"{label} must be lowercase 32-byte hex")
    return value


def _bytes32(value: object, label: str) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise CasperStateProofError(f"{label} must be exactly 32 bytes")
    return value


def _height(value: object, label: str) -> int:
    if type(value) is not int or value < 0 or value >= 1 << 64:
        raise CasperStateProofError(f"{label} must be a non-negative u64")
    return value


def _unwrap_result(payload: object, label: str) -> dict[str, Any]:
    body = _object(payload, f"{label} payload")
    if body.get("error") is not None:
        raise CasperStateProofError(f"{label} payload contains error")
    if body.get("jsonrpc") != "2.0":
        raise CasperStateProofError(f"{label} payload must use JSON-RPC 2.0")
    result = _object(body.get("result"), f"{label} result")
    if not result:
        raise CasperStateProofError(f"{label} result is malformed")
    has_wrapper = "name" in result or "value" in result
    if has_wrapper:
        if set(result) != {"name", "value"} or type(result.get("name")) is not str:
            raise CasperStateProofError(f"{label} result is malformed")
        value = _object(result.get("value"), f"{label} result")
        if not value:
            raise CasperStateProofError(f"{label} result is malformed")
        return value
    return result


def _parse_network(payload: object) -> str:
    value = _unwrap_result(payload, "status")
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
        raise CasperStateProofError("status must prove chain casper-test")
    return "casper-test"


def _parse_exact_request(
    request: object,
    *,
    method: str,
    params: dict[str, Any],
    label: str,
) -> int | str:
    body = _object(request, f"{label} request")
    if set(body) != {"jsonrpc", "id", "method", "params"}:
        raise CasperStateProofError(
            f"{label} request must contain exactly frozen fields"
        )
    if body["jsonrpc"] != "2.0" or body["method"] != method:
        raise CasperStateProofError(f"{label} request must call {method}")
    if body["params"] != params:
        if method == "chain_get_block":
            raise CasperStateProofError(
                "canonical block request block hash or params do not match exactly"
            )
        raise CasperStateProofError(f"{label} request params do not match exactly")
    return _request_id(body["id"])


def _require_response_id(payload: object, expected_id: int | str, label: str) -> None:
    body = _object(payload, f"{label} payload")
    if body.get("id") != expected_id:
        raise CasperStateProofError(f"{label} response id does not match request id")


def _parse_block(payload: object) -> tuple[str, int, str]:
    value = _unwrap_result(payload, "canonical block")
    if "block_with_signatures" in value:
        wrapper = _object(value["block_with_signatures"], "canonical block result")
        raw_block = _object(wrapper.get("block"), "canonical block result")
    elif "block" in value:
        raw_block = _object(value["block"], "canonical block result")
    else:
        raise CasperStateProofError("canonical block result is malformed")
    versions = [name for name in ("Version1", "Version2") if name in raw_block]
    if versions:
        if len(versions) != 1 or len(raw_block) != 1:
            raise CasperStateProofError("canonical block result is malformed")
        block = _object(raw_block[versions[0]], "canonical block result")
    else:
        block = raw_block
    block_hash = _lower_hash(block.get("hash"), "canonical block hash")
    header = _object(block.get("header"), "canonical block header")
    block_height = _height(header.get("height"), "canonical block height")
    state_root = _lower_hash(
        header.get("state_root_hash", header.get("stateRootHash")),
        "canonical state root",
    )
    _object(block.get("body"), "canonical block body")
    return block_hash, block_height, state_root


def _request_id(value: object) -> int | str:
    if type(value) not in (int, str) or value == "":
        raise CasperStateProofError("balance request id is invalid")
    return value


def _parse_balance_request(
    request: object,
    *,
    account_hash: bytes,
    state_root_hash: str,
) -> tuple[int | str, str]:
    body = _object(request, "balance request")
    if set(body) != {"jsonrpc", "id", "method", "params"}:
        raise CasperStateProofError(
            "balance request must contain exactly frozen fields"
        )
    if body["jsonrpc"] != "2.0" or body["method"] != "query_balance_details":
        raise CasperStateProofError("balance request must call query_balance_details")
    request_id = _request_id(body["id"])
    params = _object(body["params"], "balance request params")
    if set(params) != {"state_identifier", "purse_identifier"}:
        raise CasperStateProofError(
            "balance request params must contain exactly frozen fields"
        )
    state_identifier = _object(params["state_identifier"], "balance state identifier")
    if state_identifier != {"StateRootHash": state_root_hash}:
        raise CasperStateProofError("balance request state root does not match block")
    purse_identifier = _object(params["purse_identifier"], "balance purse identifier")
    expected_account = f"account-hash-{account_hash.hex()}"
    if purse_identifier != {"main_purse_under_account_hash": expected_account}:
        raise CasperStateProofError("balance request account hash does not match")
    return request_id, "query_balance_details"


def _u512_decimal(value: object, label: str) -> int:
    if type(value) is not str or _DECIMAL_RE.fullmatch(value) is None:
        raise CasperStateProofError(
            f"{label} must be canonical non-negative U512 decimal"
        )
    parsed = int(value)
    if parsed > _MAX_U512:
        raise CasperStateProofError(f"{label} exceeds U512")
    return parsed


def _proof_bytes(value: object, label: str) -> bytes:
    if type(value) is not str or _PROOF_RE.fullmatch(value) is None:
        raise CasperStateProofError(f"{label} must be nonempty canonical lowercase hex")
    return bytes.fromhex(value)


def _parse_holds(value: object) -> tuple[int, str]:
    if type(value) is not list:
        raise CasperStateProofError("balance holds must be an array")
    total = 0
    normalized: list[dict[str, object]] = []
    for index, raw_hold in enumerate(value):
        hold = _object(raw_hold, f"balance hold {index}")
        if set(hold) != {"time", "amount", "proof"}:
            raise CasperStateProofError("balance hold fields must be exactly frozen")
        raw_time = hold["time"]
        if type(raw_time) is not int or not 0 <= raw_time < 1 << 64:
            raise CasperStateProofError("balance hold time must be a non-negative u64")
        amount = _u512_decimal(hold["amount"], "balance hold amount")
        proof = _proof_bytes(hold["proof"], "balance hold proof")
        if total > _MAX_U512 - amount:
            raise CasperStateProofError("balance hold total exceeds U512")
        total += amount
        normalized.append(
            {"time": raw_time, "amount": str(amount), "proof": proof.hex()}
        )
    return total, _canonical_json(normalized, "balance holds").decode("ascii")


def _parse_balance_response(
    payload: object, request_id: int | str
) -> tuple[int, int, int, str, bytes]:
    body = _object(payload, "balance response")
    if body.get("jsonrpc") != "2.0":
        raise CasperStateProofError("balance response must use JSON-RPC 2.0")
    if body.get("id") != request_id:
        raise CasperStateProofError("balance response id does not match request id")
    result_wrapper = _object(body.get("result"), "balance response result")
    if set(result_wrapper) != {"name", "value"}:
        raise CasperStateProofError(
            "balance response must use the exact named result wrapper"
        )
    if result_wrapper.get("name") != "query_balance_details_result":
        raise CasperStateProofError(
            "balance response result name must be query_balance_details_result"
        )
    value = _unwrap_result(body, "balance response")
    expected_fields = {
        "api_version",
        "total_balance",
        "available_balance",
        "total_balance_proof",
        "holds",
    }
    if set(value) != expected_fields:
        raise CasperStateProofError(
            "balance details result must contain exactly frozen fields"
        )
    if type(value["api_version"]) is not str or not value["api_version"]:
        raise CasperStateProofError("balance details api_version is malformed")
    total_balance = _u512_decimal(value["total_balance"], "total balance")
    available_balance = _u512_decimal(value["available_balance"], "available balance")
    holds_total, holds_json = _parse_holds(value["holds"])
    if holds_total > total_balance or total_balance - holds_total != available_balance:
        raise CasperStateProofError(
            "available balance does not match total balance and hold arithmetic"
        )
    node_provided_merkle_proof = _proof_bytes(
        value["total_balance_proof"], "total balance Merkle proof"
    )
    return (
        total_balance,
        available_balance,
        holds_total,
        holds_json,
        node_provided_merkle_proof,
    )


def verify_account_balance_at_block(
    *,
    chain_status_request: dict[str, Any],
    chain_status_payload: dict[str, Any],
    canonical_block_request: dict[str, Any],
    canonical_block_payload: dict[str, Any],
    balance_request: dict[str, Any],
    balance_response: dict[str, Any],
    expected_account_hash: bytes,
    expected_block_hash: bytes,
    expected_block_height: int,
    expected_state_root_hash: bytes,
    expected_balance_motes: int | None = None,
) -> VerifiedAccountBalance:
    """Parse raw RPC evidence and prove one exact historical balance."""

    account_hash = _bytes32(expected_account_hash, "expected account hash")
    expected_block = _bytes32(expected_block_hash, "expected block hash")
    expected_root = _bytes32(expected_state_root_hash, "expected state root hash")
    expected_height = _height(expected_block_height, "expected block height")
    if expected_balance_motes is not None and (
        type(expected_balance_motes) is not int
        or not 0 <= expected_balance_motes <= _MAX_U512
    ):
        raise CasperStateProofError("expected balance must be U512")

    status_request_id = _parse_exact_request(
        chain_status_request,
        method="info_get_status",
        params={},
        label="status",
    )
    _require_response_id(chain_status_payload, status_request_id, "status")
    network = _parse_network(chain_status_payload)
    block_request_id = _parse_exact_request(
        canonical_block_request,
        method="chain_get_block",
        params={"block_identifier": {"Hash": expected_block.hex()}},
        label="canonical block",
    )
    _require_response_id(
        canonical_block_payload,
        block_request_id,
        "canonical block",
    )
    block_hash, block_height, state_root_hash = _parse_block(canonical_block_payload)
    if block_hash != expected_block.hex():
        raise CasperStateProofError(
            "canonical block hash does not match expected block hash"
        )
    if block_height != expected_height:
        raise CasperStateProofError(
            "canonical block height does not match expected block height"
        )
    if state_root_hash != expected_root.hex():
        raise CasperStateProofError(
            "canonical state root does not match expected state root"
        )

    request_id, method = _parse_balance_request(
        balance_request,
        account_hash=account_hash,
        state_root_hash=state_root_hash,
    )
    (
        balance,
        available_balance,
        holds_total,
        holds_json,
        node_provided_merkle_proof,
    ) = _parse_balance_response(balance_response, request_id)
    if expected_balance_motes is not None and balance != expected_balance_motes:
        raise CasperStateProofError("observed balance does not match expected balance")

    status_request_json = _canonical_json(chain_status_request, "status request")
    status_json = _canonical_json(chain_status_payload, "status payload")
    block_request_json = _canonical_json(
        canonical_block_request, "canonical block request"
    )
    block_json = _canonical_json(canonical_block_payload, "block payload")
    balance_request_json = _canonical_json(balance_request, "balance request")
    balance_response_json = _canonical_json(balance_response, "balance response")
    return _make_proof(
        network=network,
        account_hash=account_hash,
        block_hash=bytes.fromhex(block_hash),
        block_height=block_height,
        state_root_hash=bytes.fromhex(state_root_hash),
        balance_motes=balance,
        available_balance_motes=available_balance,
        balance_holds_total_motes=holds_total,
        balance_holds_json=holds_json,
        node_provided_merkle_proof=node_provided_merkle_proof,
        merkle_proof_verification_scope="node-provided-not-locally-verified",
        balance_request_method=method,
        balance_request_id=request_id,
        status_request_json=status_request_json.decode("ascii"),
        status_json=status_json.decode("ascii"),
        block_request_json=block_request_json.decode("ascii"),
        block_json=block_json.decode("ascii"),
        balance_request_json=balance_request_json.decode("ascii"),
        balance_response_json=balance_response_json.decode("ascii"),
        status_request_sha256=hashlib.sha256(status_request_json).hexdigest(),
        status_sha256=hashlib.sha256(status_json).hexdigest(),
        block_request_sha256=hashlib.sha256(block_request_json).hexdigest(),
        block_sha256=hashlib.sha256(block_json).hexdigest(),
        balance_request_sha256=hashlib.sha256(balance_request_json).hexdigest(),
        balance_response_sha256=hashlib.sha256(balance_response_json).hexdigest(),
    )


__all__ = [
    "CasperStateProofError",
    "VerifiedAccountBalance",
    "require_verified_account_balance",
    "verify_account_balance_at_block",
]
