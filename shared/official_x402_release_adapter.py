"""Independent fail-closed verifier for the official x402 release artifact.

The artifact is deliberately treated as untrusted input.  Producer summaries,
booleans, hashes, parsed projections, and row counts are corroborating fields
only; this module derives the release facts again from canonical byte
transcripts, the v3 proof, cryptographic authorization, Casper RPC evidence,
and the embedded append-only SQLite journal.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import sqlite3
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from scripts.verify_v3_proof import verify_v3_proof_document


class OfficialX402ReleaseAdapterError(ValueError):
    """The raw evidence does not prove the official x402 release claim."""


_ROOT = Path(__file__).resolve().parents[1]
_SCHEMA_ROOT = _ROOT / "handoff" / "schemas"
_BINDING_MANIFEST = (
    _ROOT / "handoff" / "RELEASE_REGISTRY_ADAPTER_SCHEMAS.json"
)
_ARTIFACT_SCHEMA = "official-x402-live-artifact.schema.json"
_RESULT_SCHEMA = "official-x402-adapter-result.schema.json"
_ARTIFACT_SOURCE = "artifacts/live/official-x402-settlement-v1.json"
_NETWORK = "casper:casper-test"
_CHAIN_NAME = "casper-test"
_WCSPR_PACKAGE = (
    "3d80df21ba4ee4d66a2a1f60c32570dd5685e4b279f6538162a5fd1314847c1e"
)
_WCSPR_CONTRACT = (
    "032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a"
)
_WCSPR_VERSION = 8
_JOURNAL_MIGRATION_SHA256 = (
    "c660abcce78e05edfebb475661dd8ee636a699e822956ac05a990cbe1fb51c5f"
)
_JOURNAL_MIGRATION_LENGTH = 5_206
_JOURNAL_TABLE = "x402_upstream_settle_calls"
_SETTLE_URL = "https://x402-facilitator.cspr.cloud/settle"
_VERIFY_URL = "https://x402-facilitator.cspr.cloud/verify"
_SUPPORTED_URL = "https://x402-facilitator.cspr.cloud/supported"
_CASPER_RPC_URL = "https://node.testnet.casper.network/rpc"
_SETTLEMENT_RPC_ENDPOINTS = {
    "casper-testnet-rpc": _CASPER_RPC_URL,
    "cspr-cloud-testnet": "https://node.testnet.cspr.cloud/rpc",
}

_CHECKS = (
    "exact_envelope_v3_verified_for_registry_record_returned_by_signed_payload_hash",
    "resource_object_equals_configured_resource",
    "accepted_equals_current_payment_requirements",
    "payment_requirements_argument_equals_accepted",
    "eip712_signature_verified",
    "public_key_account_hash_equals_payer",
    "authorization_equals_envelope_payer_payee_value_nonce_and_window",
    "resource_url_hash_matches_envelope",
    "report_hash_matches_envelope",
    "payment_requirements_hash_matches_envelope",
    "signed_payment_payload_hash_matches_envelope",
    "active_wcspr_v8_pre_verify_drift_guard_passed",
    "facilitator_verify_returned_is_valid_true",
    "active_wcspr_v8_pre_settle_drift_guard_passed",
    "facilitator_settlement_response_success_true",
    "settlement_transaction_finalized_without_execution_error",
    "active_wcspr_v8_post_settle_target_and_args_readback_passed",
    "fulfillment_authorization_nonce_unique_binding_matches",
    "fulfillment_restart_reconciliation_passed",
    "exact_retry_returned_stored_fulfillment_without_second_settlement",
    "cross_binding_or_authorization_reuse_returned_terminal_409_before_submission",
    "protected_report_released_only_after_finalized_state",
)

_EXACT_V3_CHECKS = (
    "source_tree_sha256_matches_release_manifest",
    "wasm_sha256_matches_release_manifest",
    "generated_schema_sha256_matches_release_manifest",
    "envelope_hash_recomputed_from_typed_fields",
    "proposal_commitment_matches_envelope_hash",
    "signer_set_and_threshold_match_deployment",
    "pre_quorum_finalize_reverted_with_code_8",
    "post_quorum_mutated_envelope_reverted_with_code_10",
    "exact_envelope_finalization_accepted",
    "repeat_finalization_reverted_with_code_12",
    "finalization_deploy_processed_without_execution_error",
    "contract_readback_marks_proposal_finalized",
    "contract_readback_marks_action_authorized",
    "package_contract_and_deployment_domain_match_manifest",
)

_EIP712_DOMAIN_FIELDS = (
    ("name", "string"),
    ("version", "string"),
    ("chain_name", "string"),
    ("contract_package_hash", "bytes32"),
)
_EIP712_AUTHORIZATION_FIELDS = (
    ("from", "address"),
    ("to", "address"),
    ("value", "uint256"),
    ("validAfter", "uint256"),
    ("validBefore", "uint256"),
    ("nonce", "bytes32"),
)

_MASK_64 = (1 << 64) - 1
_KECCAK_ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)
_KECCAK_ROTATIONS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

_JOURNAL_COLUMNS = (
    "sequence",
    "event_type",
    "call_id",
    "network",
    "wcspr_contract",
    "signed_payment_payload_hash",
    "payer_account_hash",
    "authorization_nonce",
    "resource_id",
    "action_id",
    "envelope_hash",
    "request_method",
    "request_url",
    "request_headers_canonical_json",
    "request_body",
    "request_body_sha256",
    "response_status",
    "response_headers_canonical_json",
    "response_body",
    "response_body_sha256",
    "failure_code",
    "observed_at",
)
_JOURNAL_BLOBS = {
    "request_headers_canonical_json",
    "request_body",
    "response_headers_canonical_json",
    "response_body",
}
_JOURNAL_SCHEMA_OBJECTS = {
    ("table", "x402_upstream_settle_calls"),
    ("index", "x402_upstream_settle_calls_one_start"),
    ("index", "x402_upstream_settle_calls_one_terminal"),
    ("index", "x402_upstream_settle_calls_authorization_once"),
    ("index", "x402_upstream_settle_calls_payload_once"),
    ("trigger", "x402_upstream_settle_calls_terminal_binding"),
    ("trigger", "x402_upstream_settle_calls_no_update"),
    ("trigger", "x402_upstream_settle_calls_no_delete"),
}


def _fail(check: str, message: str) -> None:
    raise OfficialX402ReleaseAdapterError(f"{check}: {message}")


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value!r}")


def _pairs(items: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _strict_json_any(raw: bytes, label: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise OfficialX402ReleaseAdapterError(
            f"{label} is not strict JSON"
        ) from exc


def _strict_json_object(raw: bytes, label: str) -> dict[str, Any]:
    value = _strict_json_any(raw, label)
    if type(value) is not dict:
        raise OfficialX402ReleaseAdapterError(f"{label} must be one object")
    return value


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise OfficialX402ReleaseAdapterError(
            "evidence is not canonical ASCII JSON"
        ) from exc


def _mapping(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise OfficialX402ReleaseAdapterError(f"{label} must be an object")
    return value


def _sequence(value: object, label: str) -> list[Any]:
    if type(value) is not list:
        raise OfficialX402ReleaseAdapterError(f"{label} must be an array")
    return value


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _blake2b256(raw: bytes) -> bytes:
    return hashlib.blake2b(raw, digest_size=32).digest()


def _lp(raw: bytes) -> bytes:
    return len(raw).to_bytes(4, "big") + raw


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _u256(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _b64(value: object, label: str) -> bytes:
    if type(value) is not str:
        raise OfficialX402ReleaseAdapterError(f"{label} must be base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise OfficialX402ReleaseAdapterError(
            f"{label} is not canonical base64"
        ) from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise OfficialX402ReleaseAdapterError(
            f"{label} is not canonical base64"
        )
    return decoded


def _hex(value: object, length: int, label: str) -> bytes:
    if type(value) is not str or len(value) != length * 2:
        raise OfficialX402ReleaseAdapterError(
            f"{label} must be {length} bytes of lowercase hex"
        )
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise OfficialX402ReleaseAdapterError(
            f"{label} must be lowercase hex"
        ) from exc
    if decoded.hex() != value:
        raise OfficialX402ReleaseAdapterError(
            f"{label} must be lowercase hex"
        )
    return decoded


def _casper_public_key(value: object, label: str) -> str:
    if (
        type(value) is not str
        or (
            not (value.startswith("01") and len(value) == 66)
            and not (value.startswith("02") and len(value) == 68)
        )
    ):
        raise OfficialX402ReleaseAdapterError(
            f"{label} is not one tagged Casper public key"
        )
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise OfficialX402ReleaseAdapterError(
            f"{label} is not lowercase hexadecimal"
        ) from exc
    if decoded.hex() != value:
        raise OfficialX402ReleaseAdapterError(
            f"{label} is not lowercase hexadecimal"
        )
    return value


def _casper_signature(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 130
        or value[:2] not in {"01", "02"}
    ):
        raise OfficialX402ReleaseAdapterError(
            f"{label} is not one tagged Casper signature"
        )
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise OfficialX402ReleaseAdapterError(
            f"{label} is not lowercase hexadecimal"
        ) from exc
    if decoded.hex() != value:
        raise OfficialX402ReleaseAdapterError(
            f"{label} is not lowercase hexadecimal"
        )
    return value


def _decimal(value: object, bits: int, label: str) -> int:
    if (
        type(value) is not str
        or not value
        or (value != "0" and value.startswith("0"))
        or not value.isascii()
        or not value.isdecimal()
    ):
        raise OfficialX402ReleaseAdapterError(
            f"{label} must be canonical unsigned decimal text"
        )
    parsed = int(value)
    if parsed >= 1 << bits:
        raise OfficialX402ReleaseAdapterError(f"{label} exceeds U{bits}")
    return parsed


def _timestamp(value: object, label: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise OfficialX402ReleaseAdapterError(
            f"{label} must be an RFC3339 UTC timestamp"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise OfficialX402ReleaseAdapterError(
            f"{label} is not a real UTC instant"
        ) from exc
    if parsed.tzinfo != UTC:
        raise OfficialX402ReleaseAdapterError(f"{label} must be UTC")
    return parsed


def _load_schema(name: str) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = (_SCHEMA_ROOT / name).read_bytes()
    except OSError as exc:
        raise OfficialX402ReleaseAdapterError(
            f"{name} schema is unavailable"
        ) from exc
    return raw, _strict_json_object(raw, f"{name} schema")


def _assert_schema_pins() -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        manifest_raw = _BINDING_MANIFEST.read_bytes()
    except OSError as exc:
        raise OfficialX402ReleaseAdapterError(
            "release adapter schema-binding manifest is unavailable"
        ) from exc
    manifest = _strict_json_object(
        manifest_raw, "release adapter schema-binding manifest"
    )
    bindings = _mapping(
        manifest.get("exact_json_schemas"), "exact JSON schema bindings"
    )
    artifact_raw, artifact_schema = _load_schema(_ARTIFACT_SCHEMA)
    result_raw, result_schema = _load_schema(_RESULT_SCHEMA)
    expected = (
        (
            "official_x402_artifact",
            _ARTIFACT_SCHEMA,
            artifact_raw,
        ),
        (
            "official_x402_result",
            _RESULT_SCHEMA,
            result_raw,
        ),
    )
    for binding_name, schema_name, schema_raw in expected:
        binding = _mapping(
            bindings.get(binding_name), f"{binding_name} schema binding"
        )
        if (
            set(binding) != {"path", "sha256"}
            or binding.get("path") != f"handoff/schemas/{schema_name}"
            or binding.get("sha256") != _sha256(schema_raw)
        ):
            raise OfficialX402ReleaseAdapterError(
                f"{schema_name} schema differs from its exact release pin"
            )
    return artifact_schema, result_schema


def _validate_artifact_schema(
    document: Mapping[str, Any], schema: Mapping[str, Any]
) -> None:
    errors = sorted(
        Draft202012Validator(schema).iter_errors(document),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if not errors:
        return
    error = errors[0]
    path = tuple(error.absolute_path)
    routed_checks = (
        (("wcspr_readbacks", "pre_verify"), _CHECKS[11]),
        (("wcspr_readbacks", "pre_settle"), _CHECKS[13]),
        (("wcspr_readbacks", "post_settle"), _CHECKS[16]),
        (("fulfillment", "cross_binding_reuse"), _CHECKS[20]),
    )
    for prefix, check in routed_checks:
        if path[: len(prefix)] == prefix:
            _fail(check, "artifact schema mismatch")
    raise OfficialX402ReleaseAdapterError(
        "official x402 artifact schema mismatch"
    ) from error


def _decode_hashed(
    container: Mapping[str, Any],
    *,
    data_key: str,
    hash_key: str,
    label: str,
    check: str,
) -> bytes:
    raw = _b64(container.get(data_key), label)
    if _sha256(raw) != container.get(hash_key):
        _fail(check, f"{label} SHA-256 differs")
    return raw


def _decode_canonical_json(
    container: Mapping[str, Any],
    *,
    data_key: str,
    hash_key: str | None,
    label: str,
    check: str,
) -> Any:
    if hash_key is None:
        raw = _b64(container.get(data_key), label)
    else:
        raw = _decode_hashed(
            container,
            data_key=data_key,
            hash_key=hash_key,
            label=label,
            check=check,
        )
    try:
        value = _strict_json_any(raw, label)
    except OfficialX402ReleaseAdapterError as exc:
        _fail(check, str(exc))
    if raw != _canonical(value):
        _fail(check, f"{label} is not canonical JSON")
    return value


def _rotate_left_64(value: int, shift: int) -> int:
    if shift == 0:
        return value & _MASK_64
    return ((value << shift) | (value >> (64 - shift))) & _MASK_64


def _keccak_f1600(state: list[int]) -> None:
    for round_constant in _KECCAK_ROUND_CONSTANTS:
        columns = [
            state[x]
            ^ state[x + 5]
            ^ state[x + 10]
            ^ state[x + 15]
            ^ state[x + 20]
            for x in range(5)
        ]
        deltas = [
            columns[(x - 1) % 5]
            ^ _rotate_left_64(columns[(x + 1) % 5], 1)
            for x in range(5)
        ]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= deltas[x]
        rotated = [0] * 25
        for y in range(5):
            for x in range(5):
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] = _rotate_left_64(
                    state[x + 5 * y], _KECCAK_ROTATIONS[x][y]
                )
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] = (
                    rotated[x + 5 * y]
                    ^ (
                        (~rotated[(x + 1) % 5 + 5 * y])
                        & rotated[(x + 2) % 5 + 5 * y]
                    )
                ) & _MASK_64
        state[0] ^= round_constant


def _keccak256(raw: bytes) -> bytes:
    rate = 136
    padded = bytearray(raw)
    padded.append(0x01)
    padded.extend(b"\x00" * ((rate - len(padded) % rate) % rate))
    padded[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for lane in range(rate // 8):
            start = lane * 8
            state[lane] ^= int.from_bytes(block[start : start + 8], "little")
        _keccak_f1600(state)
    return b"".join(lane.to_bytes(8, "little") for lane in state)[:32]


def _eip712_type(
    name: str, fields: tuple[tuple[str, str], ...]
) -> bytes:
    rendered = (
        f"{name}("
        + ",".join(f"{kind} {field}" for field, kind in fields)
        + ")"
    )
    return _keccak256(rendered.encode("ascii"))


def _eip712_address(value: bytes) -> bytes:
    if len(value) != 33 or value[0] != 0:
        raise OfficialX402ReleaseAdapterError(
            "EIP-712 account address must be a tagged account hash"
        )
    return _keccak256(value)


def _eip712_digest(
    *,
    token_name: str,
    domain_version: str,
    network: str,
    package_hash: bytes,
    payer: bytes,
    payee: bytes,
    value: int,
    valid_after: int,
    valid_before: int,
    nonce: bytes,
) -> bytes:
    domain_hash = _keccak256(
        b"".join(
            (
                _eip712_type("EIP712Domain", _EIP712_DOMAIN_FIELDS),
                _keccak256(token_name.encode("utf-8")),
                _keccak256(domain_version.encode("utf-8")),
                _keccak256(network.encode("utf-8")),
                package_hash,
            )
        )
    )
    struct_hash = _keccak256(
        b"".join(
            (
                _eip712_type(
                    "TransferWithAuthorization",
                    _EIP712_AUTHORIZATION_FIELDS,
                ),
                _eip712_address(b"\x00" + payer),
                _eip712_address(b"\x00" + payee),
                _u256(value),
                _u256(valid_after),
                _u256(valid_before),
                nonce,
            )
        )
    )
    return _keccak256(b"\x19\x01" + domain_hash + struct_hash)


def _resource_url_hash(url: str) -> bytes:
    return _blake2b256(
        b"CONCORDIA_RESOURCE_URL_V1\x00" + _lp(url.encode("ascii"))
    )


def _report_hash(raw: bytes) -> bytes:
    return _blake2b256(b"CONCORDIA_X402_REPORT_V1\x00" + _lp(raw))


def _payment_requirements_hash(requirements: Mapping[str, Any]) -> bytes:
    extra = _mapping(requirements.get("extra"), "payment requirements extra")
    try:
        return _blake2b256(
            b"".join(
                (
                    b"CONCORDIA_PAYMENT_REQUIREMENTS_V1\x00",
                    _lp(str(requirements["scheme"]).encode("ascii")),
                    _lp(str(requirements["network"]).encode("ascii")),
                    _hex(requirements["asset"], 32, "payment asset"),
                    _u256(
                        _decimal(
                            requirements["amount"],
                            256,
                            "payment amount",
                        )
                    ),
                    _tagged_account_hash(
                        requirements["payTo"], "payment payTo"
                    ),
                    _u32(_integer(requirements["maxTimeoutSeconds"], "timeout")),
                    _lp(str(extra["name"]).encode("ascii")),
                    _lp(str(extra["version"]).encode("ascii")),
                    bytes([_decimal(extra["decimals"], 8, "token decimals")]),
                    _lp(str(extra["symbol"]).encode("ascii")),
                )
            )
        )
    except (KeyError, UnicodeEncodeError, OverflowError) as exc:
        raise OfficialX402ReleaseAdapterError(
            "payment requirements preimage is invalid"
        ) from exc


def _signed_payload_hash(
    *,
    payment_payload: Mapping[str, Any],
    requirements_hash: bytes,
    signature: bytes,
    public_key: bytes,
    payer: bytes,
    payee: bytes,
    value: int,
    valid_after: int,
    valid_before: int,
    nonce: bytes,
) -> bytes:
    resource = _mapping(payment_payload.get("resource"), "signed resource")
    return _blake2b256(
        b"".join(
            (
                b"CONCORDIA_SIGNED_PAYMENT_PAYLOAD_V1\x00",
                _u32(_integer(payment_payload.get("x402Version"), "x402 version")),
                _lp(str(resource["url"]).encode("ascii")),
                _lp(str(resource["description"]).encode("ascii")),
                _lp(str(resource["mimeType"]).encode("ascii")),
                requirements_hash,
                _lp(signature),
                public_key,
                payer,
                payee,
                _u256(value),
                _u64(valid_after),
                _u64(valid_before),
                nonce,
                _u32(0),
            )
        )
    )


def _integer(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise OfficialX402ReleaseAdapterError(
            f"{label} must be a non-negative integer"
        )
    return value


def _tagged_account_hash(value: object, label: str) -> bytes:
    if type(value) is not str or not value.startswith("00"):
        raise OfficialX402ReleaseAdapterError(
            f"{label} must be a tagged account hash"
        )
    return _hex(value[2:], 32, label)


def _account_hash_from_public_key(public_key: bytes) -> bytes:
    if len(public_key) != 33 or public_key[0] != 1:
        raise OfficialX402ReleaseAdapterError(
            "official x402 release requires an Ed25519 payer key"
        )
    return _blake2b256(b"ed25519\x00" + public_key[1:])


def _verify_v3(
    document: Mapping[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    check = _CHECKS[0]
    binding = _mapping(
        document.get("governance_binding"), "governance binding"
    )
    try:
        proof_raw = _b64(
            binding.get("v3_proof_bytes_base64"), "v3 proof bytes"
        )
        if _sha256(proof_raw) != binding.get("v3_proof_sha256"):
            _fail(check, "v3 proof SHA-256 differs")
        proof = _strict_json_object(proof_raw, "v3 proof")
        if proof_raw != _canonical(proof):
            _fail(check, "v3 proof is not canonical JSON")
        verification = verify_v3_proof_document(proof)
    except OfficialX402ReleaseAdapterError:
        raise
    except Exception as exc:
        _fail(check, f"v3 proof verification failed: {exc}")
    input_document = _mapping(proof.get("input"), "v3 typed input")
    header = _mapping(input_document.get("header"), "v3 typed header")
    body = _mapping(input_document.get("body"), "v3 typed body")
    prepared = _mapping(proof.get("prepared"), "v3 prepared envelope")
    outcomes = _mapping(
        verification.get("contract_step_outcomes"),
        "v3 contract step outcomes",
    )
    finalization = _mapping(
        outcomes.get("finalize_exact"), "exact finalization outcome"
    )
    try:
        finalization_step = next(
            step
            for step in _sequence(
                _mapping(proof.get("run"), "v3 live run").get("steps"),
                "v3 live steps",
            )
            if _mapping(step, "v3 live step").get("name")
            == "finalize_exact"
        )
    except StopIteration as exc:
        _fail(check, "v3 proof has no exact finalization step")
        raise AssertionError from exc
    expected_binding = {
        "proposal_id": header.get("proposal_id"),
        "proposal_hash": header.get("proposal_hash"),
        "proposal_nonce": header.get("proposal_nonce"),
        "action_id": verification.get("action_id"),
        "action_kind": "OfficialX402SettlementV1",
        "action_version": 1,
        "envelope_hash": verification.get("envelope_hash"),
        "deployment_domain": header.get("deployment_domain"),
        "network": body.get("caip2_network"),
        "package_hash": verification.get("package_hash"),
        "contract_hash": verification.get("contract_hash"),
        "finalization_transaction": finalization_step.get("deploy_hash"),
        "finalized_at": finalization.get("finalized_at"),
        "observed_at": finalization.get("observed_at"),
    }
    if (
        verification.get("valid") is not True
        or input_document.get("action") != "OfficialX402SettlementV1"
        or prepared.get("action") != "OfficialX402SettlementV1"
        or header.get("action_kind") != "2"
        or header.get("action_version") != "1"
        or prepared.get("action_id") != verification.get("action_id")
        or prepared.get("envelope_hash") != verification.get("envelope_hash")
        or any(binding.get(key) != value for key, value in expected_binding.items())
    ):
        _fail(check, "v3 proof identities differ from governance binding")
    return binding, proof, verification, header, body


def _verify_authorization(
    document: Mapping[str, Any],
    *,
    body: Mapping[str, Any],
) -> dict[str, Any]:
    resource_payment = _mapping(
        document.get("resource_and_payment"), "resource and payment evidence"
    )
    authorization = _mapping(document.get("authorization"), "authorization")
    governance_binding = _mapping(
        document.get("governance_binding"), "governance binding"
    )

    configured_resource = _decode_canonical_json(
        resource_payment,
        data_key="configured_resource_json_base64",
        hash_key="configured_resource_sha256",
        label="configured resource",
        check=_CHECKS[1],
    )
    accepted = _decode_canonical_json(
        resource_payment,
        data_key="accepted_json_base64",
        hash_key="accepted_sha256",
        label="accepted payment requirements",
        check=_CHECKS[2],
    )
    requirement_argument = _decode_canonical_json(
        resource_payment,
        data_key="payment_requirements_argument_json_base64",
        hash_key="payment_requirements_argument_sha256",
        label="payment requirements argument",
        check=_CHECKS[3],
    )
    signed_payload = _decode_canonical_json(
        authorization,
        data_key="signed_payment_payload_json_base64",
        hash_key=None,
        label="signed payment payload",
        check=_CHECKS[10],
    )
    signed_payload = _mapping(signed_payload, "signed payment payload")
    payload = _mapping(signed_payload.get("payload"), "payment payload body")
    signed_authorization = _mapping(
        payload.get("authorization"), "signed payment authorization"
    )
    signature = _hex(authorization.get("signature_hex"), 65, "signature")
    public_key = _hex(authorization.get("public_key_hex"), 33, "public key")
    if (
        payload.get("signature") != signature.hex()
        or payload.get("publicKey") != public_key.hex()
    ):
        _fail(_CHECKS[4], "signed payload signature fields differ")
    payer = _account_hash_from_public_key(public_key)
    if (
        authorization.get("payer_account_hash") != payer.hex()
        or authorization.get("recovered_payer_account_hash") != payer.hex()
    ):
        _fail(_CHECKS[5], "public key account hash differs from payer")

    payer_from_authorization = _tagged_account_hash(
        signed_authorization.get("from"), "authorization from"
    )
    payee = _tagged_account_hash(
        signed_authorization.get("to"), "authorization to"
    )
    value = _decimal(
        signed_authorization.get("value"), 256, "authorization value"
    )
    valid_after = _decimal(
        signed_authorization.get("validAfter"),
        64,
        "authorization validAfter",
    )
    valid_before = _decimal(
        signed_authorization.get("validBefore"),
        64,
        "authorization validBefore",
    )
    nonce = _hex(
        signed_authorization.get("nonce"), 32, "authorization nonce"
    )
    domain = _decode_canonical_json(
        authorization,
        data_key="eip712_domain_json_base64",
        hash_key=None,
        label="EIP-712 domain",
        check=_CHECKS[4],
    )
    domain = _mapping(domain, "EIP-712 domain")
    extra = _mapping(accepted.get("extra"), "accepted token metadata")
    expected_domain = {
        "name": extra.get("name"),
        "version": extra.get("version"),
        "chain_name": accepted.get("network"),
        "contract_package_hash": "0x" + str(accepted.get("asset")),
    }
    if domain != expected_domain:
        _fail(_CHECKS[4], "EIP-712 domain differs from payment requirements")
    digest = _eip712_digest(
        token_name=str(extra["name"]),
        domain_version=str(extra["version"]),
        network=str(accepted["network"]),
        package_hash=_hex(accepted["asset"], 32, "accepted asset"),
        payer=payer,
        payee=payee,
        value=value,
        valid_after=valid_after,
        valid_before=valid_before,
        nonce=nonce,
    )
    preimage = _b64(
        authorization.get("eip712_authorization_preimage_base64"),
        "EIP-712 authorization digest",
    )
    if preimage != digest or signature[0] != 1:
        _fail(_CHECKS[4], "EIP-712 digest or signature algorithm differs")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key[1:]).verify(
            signature[1:], digest
        )
    except (ValueError, InvalidSignature) as exc:
        _fail(_CHECKS[4], "Ed25519 EIP-712 signature is invalid")
        raise AssertionError from exc

    top_level_expected = {
        "payer_account_hash": payer.hex(),
        "payee_account_hash": payee.hex(),
        "value_atomic": str(value),
        "nonce_hex": nonce.hex(),
        "valid_after": str(valid_after),
        "valid_before": str(valid_before),
    }
    body_expected = {
        "payer": payer.hex(),
        "payee": payee.hex(),
        "value": str(value),
        "eip712_auth_nonce": nonce.hex(),
        "valid_after": str(valid_after),
        "valid_before": str(valid_before),
    }
    accepted_expected = {
        "scheme": body.get("scheme"),
        "network": body.get("caip2_network"),
        "asset": body.get("wcspr_package"),
        "amount": str(value),
        "payTo": "00" + payee.hex(),
        "maxTimeoutSeconds": accepted.get("maxTimeoutSeconds"),
        "extra": {
            "name": body.get("token_name"),
            "version": body.get("eip712_domain_version"),
            "decimals": body.get("token_decimals"),
            "symbol": body.get("token_symbol"),
        },
    }
    if (
        payer_from_authorization != payer
        or any(
            authorization.get(key) != expected
            for key, expected in top_level_expected.items()
        )
        or any(body.get(key) != expected for key, expected in body_expected.items())
        or accepted != accepted_expected
        or signed_payload.get("x402Version") != 2
        or body.get("x402_version") != "2"
        or valid_after >= valid_before
    ):
        _fail(
            _CHECKS[6],
            "authorization fields differ from the exact typed envelope",
        )

    requirements_hash = _payment_requirements_hash(accepted)
    if (
        authorization.get("payment_requirements_hash")
        != requirements_hash.hex()
        or body.get("payment_requirements_hash") != requirements_hash.hex()
        or governance_binding.get("payment_requirements_hash")
        != requirements_hash.hex()
    ):
        _fail(
            _CHECKS[9],
            "payment requirements hash differs from exact preimage",
        )
    signed_payload_hash = _signed_payload_hash(
        payment_payload=signed_payload,
        requirements_hash=requirements_hash,
        signature=signature,
        public_key=public_key,
        payer=payer,
        payee=payee,
        value=value,
        valid_after=valid_after,
        valid_before=valid_before,
        nonce=nonce,
    )
    if (
        authorization.get("signed_payment_payload_hash")
        != signed_payload_hash.hex()
        or body.get("signed_payment_payload_hash")
        != signed_payload_hash.hex()
        or governance_binding.get("signed_payment_payload_hash")
        != signed_payload_hash.hex()
    ):
        _fail(
            _CHECKS[10],
            "signed payment payload hash differs from exact preimage",
        )
    if signed_payload.get("resource") != configured_resource:
        _fail(_CHECKS[1], "signed resource differs from configured resource")
    if signed_payload.get("accepted") != accepted:
        _fail(
            _CHECKS[2],
            "signed accepted requirements differ from current requirements",
        )
    if requirement_argument != accepted:
        _fail(
            _CHECKS[3],
            "facilitator requirements argument differs from accepted",
        )
    return {
        "resource": configured_resource,
        "accepted": accepted,
        "signed_payload": signed_payload,
        "signature": signature,
        "public_key": public_key,
        "payer": payer,
        "payee": payee,
        "value": value,
        "valid_after": valid_after,
        "valid_before": valid_before,
        "nonce": nonce,
        "requirements_hash": requirements_hash,
        "signed_payload_hash": signed_payload_hash,
    }


def _verify_resource_and_report(
    document: Mapping[str, Any],
    *,
    body: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> bytes:
    binding = _mapping(document.get("governance_binding"), "governance binding")
    resource = _mapping(authorization["resource"], "configured resource")
    try:
        resource_hash = _resource_url_hash(str(resource["url"]))
    except (KeyError, UnicodeEncodeError) as exc:
        _fail(_CHECKS[7], "resource URL is not canonical ASCII")
        raise AssertionError from exc
    if (
        binding.get("resource_url_hash") != resource_hash.hex()
        or body.get("resource_url_hash") != resource_hash.hex()
    ):
        _fail(_CHECKS[7], "resource URL hash differs from typed envelope")

    report = _mapping(document.get("protected_report"), "protected report")
    report_raw = _b64(report.get("content_base64"), "protected report bytes")
    report_hash = _report_hash(report_raw)
    if (
        report.get("decoded_length") != len(report_raw)
        or report.get("response_hash") != _sha256(report_raw)
        or report.get("report_hash") != report_hash.hex()
        or binding.get("report_hash") != report_hash.hex()
        or body.get("report_hash") != report_hash.hex()
    ):
        _fail(_CHECKS[8], "protected report bytes or hashes differ")
    try:
        report_object = _strict_json_object(report_raw, "protected report")
    except OfficialX402ReleaseAdapterError as exc:
        _fail(_CHECKS[8], str(exc))
    if (
        report_raw != _canonical(report_object)
        or report_object.get("proposal_id") != binding.get("proposal_id")
        or report_object.get("resource_id")
        != _resource_id_from_url(str(resource["url"]))
    ):
        _fail(_CHECKS[8], "protected report identity differs")
    return report_raw


def _resource_id_from_url(url: str) -> str:
    value = url.rsplit("/", 1)[-1]
    if not value or len(value) > 128:
        raise OfficialX402ReleaseAdapterError(
            "configured resource URL has no bounded resource ID"
        )
    return value


def _decode_rpc_exchange(
    value: object, *, label: str, check: str, expected_url: str
) -> tuple[Any, Any, datetime]:
    exchange = _mapping(value, label)
    request = _decode_canonical_json(
        exchange,
        data_key="request_body_base64",
        hash_key="request_body_sha256",
        label=f"{label} request",
        check=check,
    )
    response = _decode_canonical_json(
        exchange,
        data_key="response_body_base64",
        hash_key="response_body_sha256",
        label=f"{label} response",
        check=check,
    )
    if (
        exchange.get("url") != expected_url
        or exchange.get("response_status") != 200
        or exchange.get("response_content_type") != "application/json"
    ):
        _fail(check, f"{label} is not a successful JSON RPC transcript")
    return request, response, _timestamp(
        exchange.get("observed_at"), f"{label} observed_at"
    )


def _rpc_result(
    request: object,
    response: object,
    *,
    method: str,
    params: object,
    label: str,
    check: str,
) -> Mapping[str, Any]:
    request_map = _mapping(request, f"{label} request")
    response_map = _mapping(response, f"{label} response")
    if (
        set(request_map) != {"jsonrpc", "id", "method", "params"}
        or request_map.get("jsonrpc") != "2.0"
        or request_map.get("method") != method
        or request_map.get("params") != params
        or set(response_map) != {"jsonrpc", "id", "result"}
        or response_map.get("jsonrpc") != "2.0"
        or response_map.get("id") != request_map.get("id")
    ):
        _fail(check, f"{label} is not the exact successful JSON-RPC call")
    return _mapping(response_map.get("result"), f"{label} result")


def _runtime_args_expected(
    authorization: Mapping[str, Any],
) -> list[dict[str, str]]:
    def u256_bytes(value: int) -> bytes:
        if value == 0:
            return b"\x00"
        width = (value.bit_length() + 7) // 8
        return bytes((width,)) + value.to_bytes(width, "little")

    def list_u8_bytes(value: bytes) -> bytes:
        return len(value).to_bytes(4, "little") + value

    values = (
        (
            "from",
            "Key",
            b"\x00" + bytes(authorization["payer"]),
        ),
        (
            "to",
            "Key",
            b"\x00" + bytes(authorization["payee"]),
        ),
        ("value", "U256", u256_bytes(int(authorization["value"]))),
        (
            "valid_after",
            "U64",
            int(authorization["valid_after"]).to_bytes(8, "little"),
        ),
        (
            "valid_before",
            "U64",
            int(authorization["valid_before"]).to_bytes(8, "little"),
        ),
        ("nonce", "List<U8>", list_u8_bytes(bytes(authorization["nonce"]))),
        ("public_key", "PublicKey", bytes(authorization["public_key"])),
        (
            "signature",
            "List<U8>",
            list_u8_bytes(bytes(authorization["signature"])),
        ),
    )
    return [
        {
            "name": name,
            "cl_type": cl_type,
            "canonical_value_base64": base64.b64encode(raw).decode("ascii"),
        }
        for name, cl_type, raw in values
    ]


def _verify_wcspr_readback(
    value: object,
    *,
    label: str,
    check: str,
    expected_args: list[dict[str, str]],
) -> dict[str, Any]:
    readback = _mapping(value, label)
    if (
        readback.get("package_hash") != _WCSPR_PACKAGE
        or readback.get("contract_hash") != _WCSPR_CONTRACT
        or readback.get("contract_version") != _WCSPR_VERSION
        or readback.get("lock_status") != "Unlocked"
        or readback.get("entry_point") != "transfer_with_authorization"
        or readback.get("runtime_args") != expected_args
    ):
        _fail(check, f"{label} active package, contract, or arguments drifted")
    request, response, transcript_at = _decode_rpc_exchange(
        readback.get("rpc_transcript"),
        label=f"{label} RPC transcript",
        check=check,
        expected_url=_CASPER_RPC_URL,
    )
    requests = _sequence(request, f"{label} RPC requests")
    responses = _sequence(response, f"{label} RPC responses")
    if len(requests) != 3 or len(responses) != 3:
        _fail(
            check,
            f"{label} must contain exact status, package, and contract reads",
        )
    status_result = _rpc_result(
        requests[0],
        responses[0],
        method="info_get_status",
        params=[],
        label=f"{label} status",
        check=check,
    )
    try:
        tip = status_result["last_added_block_info"]
        tip_hash = str(tip["hash"])
        tip_height = tip["height"]
        tip_state_root = str(tip["state_root_hash"])
        tip_timestamp = str(tip["timestamp"])
        signing_key = str(status_result["our_public_signing_key"])
    except (KeyError, TypeError) as exc:
        _fail(check, f"{label} status response is malformed")
        raise AssertionError from exc
    if (
        status_result.get("chainspec_name") != _CHAIN_NAME
        or type(tip_height) is not int
        or type(tip_height) is bool
        or tip_height < 0
        or _hex(tip_hash, 32, f"{label} tip hash").hex() != tip_hash
        or _hex(tip_state_root, 32, f"{label} tip state root").hex()
        != tip_state_root
        or len(_hex(signing_key, 33, f"{label} signing key")) != 33
    ):
        _fail(check, f"{label} status does not identify a canonical Testnet tip")
    package_result = _rpc_result(
        requests[1],
        responses[1],
        method="state_get_package",
        params={
            "package_identifier": {
                "ContractPackageHash": f"contract-package-{_WCSPR_PACKAGE}"
            },
            "block_identifier": {"Hash": tip_hash},
        },
        label=f"{label} package",
        check=check,
    )
    contract_result = _rpc_result(
        requests[2],
        responses[2],
        method="query_global_state",
        params={
            "state_identifier": {"StateRootHash": tip_state_root},
            "key": f"hash-{_WCSPR_CONTRACT}",
            "path": [],
        },
        label=f"{label} contract",
        check=check,
    )
    try:
        package = package_result["package"]["ContractPackage"]
        stored_contract = contract_result["stored_value"]["Contract"]
        versions = package["versions"]
        disabled_versions = {
            tuple(item) for item in package["disabled_versions"]
        }
        active = sorted(
            (
                item
                for item in versions
                if (
                    item.get("protocol_version_major"),
                    item.get("contract_version"),
                )
                not in disabled_versions
            ),
            key=lambda item: (
                item.get("contract_version", -1),
                item.get("protocol_version_major", -1),
            ),
            reverse=True,
        )
        entry_points = stored_contract["entry_points"]
    except (KeyError, TypeError) as exc:
        _fail(check, f"{label} RPC responses are malformed")
        raise AssertionError from exc
    expected_entry_args = [
        {
            "name": item["name"],
            "cl_type": (
                {"List": "U8"}
                if item["cl_type"] == "List<U8>"
                else item["cl_type"]
            ),
        }
        for item in expected_args
    ]
    matching_entry_points = [
        entry
        for entry in entry_points
        if entry.get("name") == "transfer_with_authorization"
        and entry.get("args") == expected_entry_args
    ]
    if (
        not active
        or active[0].get("protocol_version_major") != 2
        or active[0].get("contract_version") != _WCSPR_VERSION
        or active[0].get("contract_hash") != f"contract-{_WCSPR_CONTRACT}"
        or sum(
            1
            for item in active
            if item.get("protocol_version_major") == 2
            and item.get("contract_version") == _WCSPR_VERSION
        )
        != 1
        or package.get("lock_status") != "Unlocked"
        or stored_contract.get("contract_package_hash")
        != f"contract-package-{_WCSPR_PACKAGE}"
        or len(matching_entry_points) != 1
    ):
        _fail(check, f"{label} raw RPC readback differs from WCSPR v8")
    observed = _timestamp(readback.get("observed_at"), f"{label} observed_at")
    tip_at = _timestamp(tip_timestamp, f"{label} tip timestamp")
    if transcript_at != observed or tip_at > observed:
        _fail(check, f"{label} transcript and summary timestamps differ")
    return {
        "observed_at": observed,
        "tip_timestamp": tip_at,
        "tip_height": tip_height,
        "tip_hash": tip_hash,
        "tip_state_root": tip_state_root,
        "signing_key": signing_key,
    }


def _decode_http_exchange(
    value: object,
    *,
    label: str,
    check: str,
) -> tuple[dict[str, Any], dict[str, Any], datetime]:
    exchange = _mapping(value, label)
    request_raw = _decode_hashed(
        exchange,
        data_key="request_body_base64",
        hash_key="request_body_sha256",
        label=f"{label} request",
        check=check,
    )
    response_raw = _decode_hashed(
        exchange,
        data_key="response_body_base64",
        hash_key="response_body_sha256",
        label=f"{label} response",
        check=check,
    )
    if (
        exchange.get("response_content_type") != "application/json"
        or exchange.get("response_status") != 200
    ):
        _fail(check, f"{label} is not successful JSON")
    if request_raw:
        request = _strict_json_object(request_raw, f"{label} request")
        if request_raw != _canonical(request):
            _fail(check, f"{label} request is not canonical JSON")
    else:
        request = {}
    response = _strict_json_object(response_raw, f"{label} response")
    if response_raw != _canonical(response):
        _fail(check, f"{label} response is not canonical JSON")
    return request, response, _timestamp(
        exchange.get("observed_at"), f"{label} observed_at"
    )


def _verify_facilitator(
    document: Mapping[str, Any],
    *,
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    facilitator = _mapping(document.get("facilitator"), "facilitator evidence")
    supported_request, supported_response, supported_at = _decode_http_exchange(
        facilitator.get("supported"),
        label="facilitator supported",
        check=_CHECKS[12],
    )
    supported_exchange = _mapping(
        facilitator.get("supported"), "facilitator supported"
    )
    kinds = _sequence(supported_response.get("kinds"), "supported kinds")
    if (
        supported_request
        or supported_exchange.get("method") != "GET"
        or supported_exchange.get("url") != _SUPPORTED_URL
        or not any(
            item
            == {
                "x402Version": 2,
                "scheme": "exact",
                "network": _NETWORK,
            }
            for item in kinds
        )
    ):
        _fail(_CHECKS[12], "facilitator supported response lacks exact Testnet")

    expected_request = {
        "x402Version": 2,
        "paymentPayload": authorization["signed_payload"],
        "paymentRequirements": authorization["accepted"],
    }
    verify_request, verify_response, verify_at = _decode_http_exchange(
        facilitator.get("verify"),
        label="facilitator verify",
        check=_CHECKS[12],
    )
    verify_exchange = _mapping(facilitator.get("verify"), "facilitator verify")
    expected_payer = "00" + bytes(authorization["payer"]).hex()
    if (
        verify_exchange.get("method") != "POST"
        or verify_exchange.get("url") != _VERIFY_URL
        or verify_request != expected_request
        or verify_response
        != {"isValid": True, "payer": expected_payer}
        or facilitator.get("parsed_verify")
        != {
            "is_valid": True,
            "payer_account_hash": bytes(authorization["payer"]).hex(),
        }
    ):
        _fail(_CHECKS[12], "facilitator verify does not prove exact validity")

    settle_request, settle_response, settle_at = _decode_http_exchange(
        facilitator.get("settle"),
        label="facilitator settle",
        check=_CHECKS[14],
    )
    settle_exchange = _mapping(facilitator.get("settle"), "facilitator settle")
    parsed_settle = _mapping(
        facilitator.get("parsed_settle"), "parsed facilitator settlement"
    )
    if (
        settle_exchange.get("method") != "POST"
        or settle_exchange.get("url") != _SETTLE_URL
        or settle_request != expected_request
        or settle_response.get("success") is not True
        or settle_response.get("network") != _NETWORK
        or settle_response.get("payer") != expected_payer
        or parsed_settle
        != {
            "success": True,
            "transaction": settle_response.get("transaction"),
            "network": _NETWORK,
            "payer_account_hash": bytes(authorization["payer"]).hex(),
        }
    ):
        _fail(_CHECKS[14], "facilitator settle does not prove exact success")
    return {
        "request": expected_request,
        "request_raw": _canonical(expected_request),
        "settle_response": settle_response,
        "settle_response_raw": _canonical(settle_response),
        "transaction": settle_response.get("transaction"),
        "supported_at": supported_at,
        "verify_at": verify_at,
        "settle_at": settle_at,
    }


def _runtime_args_from_transaction(value: object) -> list[dict[str, str]]:
    args = _sequence(value, "settlement runtime arguments")
    result: list[dict[str, str]] = []
    for entry in args:
        pair = _sequence(entry, "settlement runtime argument")
        if len(pair) != 2 or type(pair[0]) is not str:
            raise OfficialX402ReleaseAdapterError(
                "settlement runtime argument is malformed"
            )
        encoded = _mapping(pair[1], "settlement runtime argument value")
        parsed = encoded.get("parsed")
        if not isinstance(parsed, (str, int)):
            raise OfficialX402ReleaseAdapterError(
                "settlement runtime argument parsed value is invalid"
            )
        result.append(
            {
                "name": pair[0],
                "cl_type": str(encoded.get("cl_type"))
                if type(encoded.get("cl_type")) is not str
                else encoded["cl_type"],
                "canonical_value_base64": base64.b64encode(
                    str(parsed).encode("ascii")
                ).decode("ascii"),
            }
        )
    return result


def _verify_chain_provider(
    value: object,
    *,
    transaction: str,
    expected_args: list[dict[str, str]],
) -> tuple[dict[str, Any], datetime, str]:
    check = _CHECKS[15]
    provider = _mapping(value, "settlement RPC provider")
    endpoint_id = provider.get("endpoint_id")
    expected_origin = _SETTLEMENT_RPC_ENDPOINTS.get(str(endpoint_id))
    if expected_origin is None or provider.get("origin") != expected_origin:
        _fail(check, "settlement RPC provider identity is not release-pinned")
    tx_request, tx_response, tx_at = _decode_rpc_exchange(
        provider.get("info_get_transaction"),
        label=f"{endpoint_id} transaction RPC",
        check=check,
        expected_url=expected_origin,
    )
    block_request, block_response, block_at = _decode_rpc_exchange(
        provider.get("chain_get_block"),
        label=f"{endpoint_id} block RPC",
        check=check,
        expected_url=expected_origin,
    )
    status_request, status_response, status_at = _decode_rpc_exchange(
        provider.get("info_get_status"),
        label=f"{endpoint_id} status RPC",
        check=check,
        expected_url=expected_origin,
    )
    result = _rpc_result(
        tx_request,
        tx_response,
        method="info_get_transaction",
        params={
            "transaction_hash": {"Version1": transaction},
            "finalized_approvals": True,
        },
        label=f"{endpoint_id} transaction",
        check=check,
    )
    try:
        transaction_v1 = result["transaction"]["Version1"]
        execution_info = result["execution_info"]
        execution_result = execution_info["execution_result"]["Version2"]
        payload = transaction_v1["payload"]
        fields = payload["fields"]
        target = fields["target"]["Stored"]["id"]["ByPackageHash"]["addr"]
        entry_point = fields["entry_point"]["Custom"]
        runtime_args = fields["args"]["Named"]
        block_hash = execution_info["block_hash"]
        block_height = execution_info["block_height"]
        block_result = _rpc_result(
            block_request,
            block_response,
            method="chain_get_block",
            params={"block_identifier": {"Hash": block_hash}},
            label=f"{endpoint_id} block",
            check=check,
        )
        block_with_signatures = block_result["block_with_signatures"]
        block = block_with_signatures["block"]["Version2"]
        block_header = block["header"]
        transactions = block["body"]["transactions"]["4"]
        block_proofs = block_with_signatures["proofs"]
    except (KeyError, TypeError, IndexError) as exc:
        _fail(check, "settlement RPC response is malformed")
        raise AssertionError from exc
    if len(runtime_args) != len(expected_args):
        _fail(check, "settlement runtime argument count differs")
    for actual, expected in zip(runtime_args, expected_args, strict=True):
        pair = _sequence(actual, "settlement runtime argument")
        if len(pair) != 2 or pair[0] != expected["name"]:
            _fail(check, "settlement runtime argument order differs")
        encoded = _mapping(pair[1], "settlement runtime CLValue")
        expected_cl_type: object = expected["cl_type"]
        if expected_cl_type == "List<U8>":
            expected_cl_type = {"List": "U8"}
        expected_bytes = _b64(
            expected["canonical_value_base64"],
            f"{expected['name']} canonical CLValue",
        )
        if (
            set(encoded) not in ({"cl_type", "bytes"}, {"cl_type", "bytes", "parsed"})
            or encoded.get("cl_type") != expected_cl_type
            or encoded.get("bytes") != expected_bytes.hex()
        ):
            _fail(
                check,
                f"settlement runtime argument {expected['name']} "
                "differs from canonical CLValue bytes",
            )
    if (
        transaction_v1.get("hash") != transaction
        or payload.get("chain_name") != _CHAIN_NAME
        or "error_message" not in execution_result
        or execution_result.get("error_message") is not None
        or target != _WCSPR_PACKAGE
        or entry_point != "transfer_with_authorization"
        or block.get("hash") != block_hash
        or block_header.get("height") != block_height
        or transactions.count({"Version1": transaction}) != 1
        or type(block_proofs) is not list
        or not block_proofs
    ):
        _fail(check, "settlement is not finalized with exact WCSPR arguments")
    proof_public_keys: set[str] = set()
    for proof in block_proofs:
        proof_map = _mapping(proof, "settlement block proof")
        if set(proof_map) != {"public_key", "signature"}:
            _fail(check, "settlement block proof is malformed")
        try:
            proof_public_key = _casper_public_key(
                proof_map["public_key"],
                "settlement block proof public key",
            )
            proof_signature = _casper_signature(
                proof_map["signature"],
                "settlement block proof signature",
            )
        except OfficialX402ReleaseAdapterError as exc:
            _fail(check, str(exc))
        if (
            proof_public_key[:2] != proof_signature[:2]
            or proof_public_key in proof_public_keys
        ):
            _fail(check, "settlement block proof identity is invalid")
        proof_public_keys.add(proof_public_key)
    status_result = _rpc_result(
        status_request,
        status_response,
        method="info_get_status",
        params=[],
        label=f"{endpoint_id} status",
        check=check,
    )
    try:
        tip = status_result["last_added_block_info"]
        tip_height = tip["height"]
        tip_timestamp = _timestamp(
            tip["timestamp"], f"{endpoint_id} status tip timestamp"
        )
        node_signing_key = _casper_public_key(
            status_result["our_public_signing_key"],
            f"{endpoint_id} node signing key",
        )
        _hex(str(tip["hash"]), 32, f"{endpoint_id} status tip hash")
        _hex(
            str(tip["state_root_hash"]),
            32,
            f"{endpoint_id} status tip state root",
        )
    except OfficialX402ReleaseAdapterError as exc:
        _fail(check, str(exc))
        raise AssertionError from exc
    except (KeyError, TypeError) as exc:
        _fail(check, "settlement status response is malformed")
        raise AssertionError from exc
    if (
        status_result.get("chainspec_name") != _CHAIN_NAME
        or type(tip_height) is not int
        or type(tip_height) is bool
        or tip_height - block_height < 8
        or tip_timestamp < _timestamp(
            block_header.get("timestamp"), "settlement block timestamp"
        )
        or status_at < tip_timestamp
    ):
        _fail(check, "settlement finality depth or node identity is insufficient")
    return (
        {
            "block_hash": block_hash,
            "block_height": block_height,
            "state_root_hash": block_header.get("state_root_hash"),
            "block_timestamp": block_header.get("timestamp"),
            "execution_success": True,
            "execution_error": None,
            "target_contract_hash": _WCSPR_CONTRACT,
            "contract_version": _WCSPR_VERSION,
            "entry_point": "transfer_with_authorization",
            "runtime_args": expected_args,
        },
        max(tx_at, block_at, status_at),
        node_signing_key,
    )


def _verify_settlement_chain(
    document: Mapping[str, Any],
    *,
    transaction: str,
    expected_args: list[dict[str, str]],
) -> tuple[dict[str, Any], datetime]:
    check = _CHECKS[15]
    chain = _mapping(
        document.get("settlement_chain_evidence"),
        "settlement chain evidence",
    )
    if (
        chain.get("network") != _NETWORK
        or chain.get("settlement_transaction") != transaction
    ):
        _fail(check, "settlement chain identity differs")
    providers = _sequence(chain.get("providers"), "settlement providers")
    if len(providers) != 2:
        _fail(check, "exactly two settlement RPC providers are required")
    identities = [
        (
            _mapping(item, "settlement provider").get("endpoint_id"),
            _mapping(item, "settlement provider").get("origin"),
        )
        for item in providers
    ]
    if (
        {str(identity[0]) for identity in identities}
        != set(_SETTLEMENT_RPC_ENDPOINTS)
        or {
            str(identity[1]) for identity in identities
        }
        != set(_SETTLEMENT_RPC_ENDPOINTS.values())
        or any(
            _SETTLEMENT_RPC_ENDPOINTS.get(str(endpoint_id)) != origin
            for endpoint_id, origin in identities
        )
    ):
        _fail(check, "settlement RPC providers are not release-pinned and disjoint")
    observations = [
        _verify_chain_provider(
            provider,
            transaction=transaction,
            expected_args=expected_args,
        )
        for provider in providers
    ]
    parsed, observed_at, first_node_key = observations[0]
    if observations[1][0] != parsed:
        _fail(check, "two settlement RPC providers disagree")
    if observations[1][2] == first_node_key:
        _fail(check, "settlement RPC observations have one node identity")
    if chain.get("parsed_settlement") != parsed:
        _fail(check, "parsed settlement differs from raw RPC evidence")
    return parsed, max(observed_at, observations[1][1])


def _decode_row_observation(
    value: object, *, label: str, check: str
) -> tuple[dict[str, Any], datetime, str]:
    observation = _mapping(value, label)
    row = _decode_canonical_json(
        observation,
        data_key="row_canonical_json_base64",
        hash_key="row_canonical_json_sha256",
        label=f"{label} row",
        check=check,
    )
    return (
        _mapping(row, f"{label} row"),
        _timestamp(observation.get("observed_at"), f"{label} observed_at"),
        str(observation.get("service_instance_id")),
    )


def _expected_fulfillment_row(
    *,
    document: Mapping[str, Any],
    authorization: Mapping[str, Any],
    facilitator: Mapping[str, Any],
) -> dict[str, Any]:
    binding = _mapping(document.get("governance_binding"), "governance binding")
    resource_id = _resource_id_from_url(
        str(_mapping(authorization["resource"], "resource")["url"])
    )
    response_raw = bytes(facilitator["settle_response_raw"])
    return {
        "network": _NETWORK,
        "signedPaymentPayloadHash": bytes(
            authorization["signed_payload_hash"]
        ).hex(),
        "resourceId": resource_id,
        "actionId": binding["action_id"],
        "envelopeHash": binding["envelope_hash"],
        "resourceUrlHash": binding["resource_url_hash"],
        "reportHash": binding["report_hash"],
        "paymentRequirementsHash": binding["payment_requirements_hash"],
        "payerAccountHash": bytes(authorization["payer"]).hex(),
        "payeeAccountHash": bytes(authorization["payee"]).hex(),
        "valueAtomic": str(authorization["value"]),
        "validAfter": str(authorization["valid_after"]),
        "validBefore": str(authorization["valid_before"]),
        "authorizationNonce": bytes(authorization["nonce"]).hex(),
        "publicKey": bytes(authorization["public_key"]).hex(),
        "signature": bytes(authorization["signature"]).hex(),
        "wcsprContract": _WCSPR_CONTRACT,
        "state": "finalized",
        "settlementTransactionHash": facilitator["transaction"],
        "settlementResponseHash": _sha256(response_raw),
        "responseJson": response_raw.decode("ascii"),
        "settledAt": None,
        "failureReason": None,
        "recoveryLeaseId": None,
        "recoveryLeaseExpiresAt": None,
        "createdAt": None,
        "updatedAt": None,
    }


def _verify_fulfillment_rows(
    document: Mapping[str, Any],
    *,
    authorization: Mapping[str, Any],
    facilitator: Mapping[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    datetime,
    datetime,
    str,
    str,
]:
    fulfillment = _mapping(document.get("fulfillment"), "fulfillment")
    first, first_at, first_instance = _decode_row_observation(
        fulfillment.get("first_row"),
        label="first fulfillment",
        check=_CHECKS[17],
    )
    restarted, restart_at, restart_instance = _decode_row_observation(
        fulfillment.get("post_restart_row"),
        label="post-restart fulfillment",
        check=_CHECKS[18],
    )
    expected = _expected_fulfillment_row(
        document=document,
        authorization=authorization,
        facilitator=facilitator,
    )
    stable_fields = set(expected) - {"settledAt", "createdAt", "updatedAt"}
    if (
        any(first.get(key) != expected[key] for key in stable_fields)
        or first.get("settledAt") is None
        or first.get("createdAt") is None
        or first.get("updatedAt") is None
    ):
        _fail(_CHECKS[17], "persisted fulfillment binding differs")
    if restarted != first:
        _fail(_CHECKS[18], "post-restart fulfillment row differs")
    if (
        first_instance == restart_instance
        or restart_at <= first_at
        or _timestamp(first["createdAt"], "fulfillment createdAt")
        > _timestamp(first["settledAt"], "fulfillment settledAt")
        or _timestamp(first["settledAt"], "fulfillment settledAt")
        != _timestamp(first["updatedAt"], "fulfillment updatedAt")
    ):
        _fail(_CHECKS[18], "fulfillment restart or chronology is not proven")
    return (
        first,
        restarted,
        first_at,
        restart_at,
        first_instance,
        restart_instance,
    )


def _decode_paid_exchange(
    value: object,
    *,
    label: str,
    check: str,
    expect_payment_response: bool,
) -> dict[str, Any]:
    exchange = _mapping(value, label)
    request_headers = _decode_canonical_json(
        exchange,
        data_key="request_headers_canonical_json_base64",
        hash_key="request_headers_canonical_json_sha256",
        label=f"{label} request headers",
        check=check,
    )
    response_headers = _decode_canonical_json(
        exchange,
        data_key="response_headers_canonical_json_base64",
        hash_key="response_headers_canonical_json_sha256",
        label=f"{label} response headers",
        check=check,
    )
    request_headers = _mapping(request_headers, f"{label} request headers")
    response_headers = _mapping(response_headers, f"{label} response headers")
    signature_raw = _decode_hashed(
        exchange,
        data_key="payment_signature_raw_value_base64",
        hash_key="payment_signature_raw_value_sha256",
        label=f"{label} payment-signature raw value",
        check=check,
    )
    signed_payload_raw = _decode_hashed(
        exchange,
        data_key="payment_signature_decoded_payload_base64",
        hash_key="payment_signature_decoded_payload_sha256",
        label=f"{label} decoded payment-signature",
        check=check,
    )
    try:
        decoded_header_payload = base64.b64decode(signature_raw, validate=True)
    except (ValueError, binascii.Error) as exc:
        _fail(check, f"{label} payment-signature value is not base64")
        raise AssertionError from exc
    if (
        request_headers != {"payment-signature": signature_raw.decode("ascii")}
        or decoded_header_payload != signed_payload_raw
    ):
        _fail(check, f"{label} request header map differs from raw payment")
    signed_payload = _strict_json_object(
        signed_payload_raw, f"{label} signed payment"
    )
    if signed_payload_raw != _canonical(signed_payload):
        _fail(check, f"{label} signed payment is not canonical JSON")
    response_raw = _decode_hashed(
        exchange,
        data_key="response_body_base64",
        hash_key="response_body_sha256",
        label=f"{label} response body",
        check=check,
    )
    result: dict[str, Any] = {
        "exchange": exchange,
        "signed_payload": signed_payload,
        "response_body": response_raw,
        "observed_at": _timestamp(
            exchange.get("observed_at"), f"{label} observed_at"
        ),
    }
    response_fields = {
        "payment_response_raw_value_base64",
        "payment_response_raw_value_sha256",
        "payment_response_decoded_settlement_base64",
        "payment_response_decoded_settlement_sha256",
    }
    if expect_payment_response:
        if not response_fields.issubset(exchange):
            _fail(check, f"{label} payment-response evidence is absent")
        payment_response_raw = _decode_hashed(
            exchange,
            data_key="payment_response_raw_value_base64",
            hash_key="payment_response_raw_value_sha256",
            label=f"{label} payment-response raw value",
            check=check,
        )
        settlement_raw = _decode_hashed(
            exchange,
            data_key="payment_response_decoded_settlement_base64",
            hash_key="payment_response_decoded_settlement_sha256",
            label=f"{label} decoded payment-response",
            check=check,
        )
        try:
            decoded_header_settlement = base64.b64decode(
                payment_response_raw, validate=True
            )
        except (ValueError, binascii.Error) as exc:
            _fail(check, f"{label} payment-response value is not base64")
            raise AssertionError from exc
        if (
            response_headers
            != {"payment-response": payment_response_raw.decode("ascii")}
            or decoded_header_settlement != settlement_raw
        ):
            _fail(check, f"{label} response header differs from settlement")
        settlement = _strict_json_object(
            settlement_raw, f"{label} settlement"
        )
        if settlement_raw != _canonical(settlement):
            _fail(check, f"{label} settlement is not canonical JSON")
        result["settlement"] = settlement
        result["settlement_raw"] = settlement_raw
    elif response_fields.intersection(exchange) or response_headers:
        _fail(check, f"{label} rejected response contains payment-response")
    return result


def _canonical_journal_rows(
    connection: sqlite3.Connection,
) -> list[dict[str, Any]]:
    connection.row_factory = sqlite3.Row
    selected = connection.execute(
        "SELECT "
        + ",".join(_JOURNAL_COLUMNS)
        + f" FROM {_JOURNAL_TABLE} ORDER BY sequence"
    ).fetchall()
    rows: list[dict[str, Any]] = []
    for selected_row in selected:
        row: dict[str, Any] = {}
        for key in _JOURNAL_COLUMNS:
            value = selected_row[key]
            if key in _JOURNAL_BLOBS:
                row[f"{key}_base64"] = (
                    None
                    if value is None
                    else base64.b64encode(bytes(value)).decode("ascii")
                )
            else:
                row[key] = value
        rows.append(row)
    return rows


def _journal_root(rows: Sequence[Mapping[str, Any]]) -> str:
    return _sha256(
        b"".join(
            (
                b"CONCORDIA_X402_SETTLE_CALL_JOURNAL_V1\x00",
                len(rows).to_bytes(8, "big"),
                *(hashlib.sha256(_canonical(row)).digest() for row in rows),
            )
        )
    )


def _journal_blob(row: Mapping[str, Any], field: str) -> bytes:
    value = row.get(f"{field}_base64")
    if type(value) is not str:
        raise OfficialX402ReleaseAdapterError(
            f"journal {field} is not encoded bytes"
        )
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise OfficialX402ReleaseAdapterError(
            f"journal {field} is not canonical base64"
        ) from exc
    if base64.b64encode(raw).decode("ascii") != value:
        raise OfficialX402ReleaseAdapterError(
            f"journal {field} is not canonical base64"
        )
    return raw


def _database_schema(connection: sqlite3.Connection) -> list[tuple[Any, ...]]:
    return connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
    ).fetchall()


def _verify_journal_snapshot(
    value: object,
    *,
    label: str,
    migration: bytes,
) -> tuple[bytes, list[dict[str, Any]], str, datetime, str]:
    check = _CHECKS[19]
    snapshot = _mapping(value, label)
    database = _decode_hashed(
        snapshot,
        data_key="sqlite_backup_base64",
        hash_key="sqlite_backup_sha256",
        label=f"{label} SQLite image",
        check=check,
    )
    projected_rows_raw = _decode_hashed(
        snapshot,
        data_key="rows_canonical_json_base64",
        hash_key="rows_canonical_json_sha256",
        label=f"{label} canonical rows",
        check=check,
    )
    connection = sqlite3.connect(":memory:")
    expected = sqlite3.connect(":memory:")
    try:
        connection.deserialize(database)
        connection.execute("PRAGMA query_only = ON")
        integrity = connection.execute("PRAGMA integrity_check").fetchall()
        if integrity != [("ok",)]:
            _fail(check, f"{label} SQLite integrity check failed")
        expected.executescript(migration.decode("utf-8"))
        if _database_schema(connection) != _database_schema(expected):
            _fail(check, f"{label} SQLite schema differs from migration")
        observed_objects = {
            (row[0], row[1]) for row in _database_schema(connection)
        }
        if observed_objects != _JOURNAL_SCHEMA_OBJECTS:
            _fail(check, f"{label} SQLite append-only objects differ")
        rows = _canonical_journal_rows(connection)
    except (sqlite3.Error, UnicodeDecodeError) as exc:
        _fail(check, f"{label} SQLite evidence is invalid")
        raise AssertionError from exc
    finally:
        connection.close()
        expected.close()
    rows_raw = _canonical(rows)
    if rows_raw != projected_rows_raw:
        _fail(check, f"{label} row projection differs from SQLite")
    root = _journal_root(rows)
    if snapshot.get("journal_root_sha256") != root:
        _fail(check, f"{label} journal root differs")
    return (
        database,
        rows,
        root,
        _timestamp(snapshot.get("observed_at"), f"{label} observed_at"),
        str(snapshot.get("service_instance_id")),
    )


def _verify_journal(
    document: Mapping[str, Any],
    *,
    first_row: Mapping[str, Any],
    facilitator: Mapping[str, Any],
    first_release_at: datetime,
    retry_at: datetime,
    cross_at: datetime,
    first_fulfillment_at: datetime,
    restart_fulfillment_at: datetime,
    first_fulfillment_instance: str,
    restart_fulfillment_instance: str,
) -> None:
    check = _CHECKS[19]
    fulfillment = _mapping(document.get("fulfillment"), "fulfillment")
    journal = _mapping(
        fulfillment.get("upstream_settle_journal"),
        "upstream settle journal",
    )
    migration = _decode_hashed(
        journal,
        data_key="migration_sql_base64",
        hash_key="migration_sql_sha256",
        label="upstream settle journal migration",
        check=check,
    )
    if (
        journal.get("schema_id")
        != "concordia.x402_upstream_settle_journal.v1"
        or len(migration) != _JOURNAL_MIGRATION_LENGTH
        or journal.get("migration_sql_sha256") != _JOURNAL_MIGRATION_SHA256
        or _sha256(migration) != _JOURNAL_MIGRATION_SHA256
    ):
        _fail(check, "upstream settle journal migration differs from release pin")
    repository_migration = (
        _ROOT
        / "services"
        / "x402-official"
        / "migrations"
        / "0002_upstream_settle_journal.sql"
    )
    if repository_migration.exists():
        try:
            if repository_migration.read_bytes() != migration:
                _fail(check, "artifact migration differs from repository migration")
        except OSError as exc:
            _fail(check, f"repository migration cannot be read: {exc}")
    snapshots = _mapping(journal.get("snapshots"), "journal snapshots")
    values = [
        _verify_journal_snapshot(
            snapshots.get(name),
            label=name.replace("_", " "),
            migration=migration,
        )
        for name in (
            "after_first_release",
            "after_exact_retry",
            "after_cross_binding_reuse",
        )
    ]
    first_database, first_rows, first_root, first_at, first_instance = values[0]
    if any(
        database != first_database or rows != first_rows or root != first_root
        for database, rows, root, _, _ in values[1:]
    ):
        _fail(check, "journal changed during retry or cross-binding rejection")
    if (
        len(first_rows) != 2
        or first_rows[0].get("event_type") != "request_started"
        or first_rows[1].get("event_type") != "response_observed"
        or first_rows[0].get("sequence") != 1
        or first_rows[1].get("sequence") != 2
    ):
        _fail(check, "journal does not prove one start and one response")
    start, response = first_rows
    binding_fields = (
        "call_id",
        "network",
        "wcspr_contract",
        "signed_payment_payload_hash",
        "payer_account_hash",
        "authorization_nonce",
        "resource_id",
        "action_id",
        "envelope_hash",
    )
    if any(start.get(field) != response.get(field) for field in binding_fields):
        _fail(check, "journal terminal event differs from request binding")
    expected_call_id = _sha256(
        b"".join(
            (
                b"CONCORDIA_X402_UPSTREAM_SETTLE_CALL_V1\x00",
                bytes.fromhex(first_row["signedPaymentPayloadHash"]),
                bytes.fromhex(first_row["authorizationNonce"]),
            )
        )
    )
    expected_binding = {
        "call_id": expected_call_id,
        "network": first_row["network"],
        "wcspr_contract": first_row["wcsprContract"],
        "signed_payment_payload_hash": first_row[
            "signedPaymentPayloadHash"
        ],
        "payer_account_hash": first_row["payerAccountHash"],
        "authorization_nonce": first_row["authorizationNonce"],
        "resource_id": first_row["resourceId"],
        "action_id": first_row["actionId"],
        "envelope_hash": first_row["envelopeHash"],
    }
    if any(start.get(key) != value for key, value in expected_binding.items()):
        _fail(check, "journal request binding differs from fulfillment")
    try:
        request_raw = _journal_blob(start, "request_body")
        response_raw = _journal_blob(response, "response_body")
        request_headers_raw = _journal_blob(
            start, "request_headers_canonical_json"
        )
        response_headers_raw = _journal_blob(
            response, "response_headers_canonical_json"
        )
    except OfficialX402ReleaseAdapterError as exc:
        _fail(check, str(exc))
    if (
        start.get("request_method") != "POST"
        or start.get("request_url") != _SETTLE_URL
        or request_headers_raw
        != _canonical({"content-type": "application/json"})
        or start.get("request_body_sha256") != _sha256(request_raw)
        or request_raw != facilitator["request_raw"]
        or response.get("response_status") != 200
        or response_headers_raw
        != _canonical({"content-type": "application/json"})
        or response.get("response_body_sha256") != _sha256(response_raw)
        or response_raw != facilitator["settle_response_raw"]
        or first_row.get("settlementResponseHash") != _sha256(response_raw)
        or first_row.get("settlementTransactionHash")
        != facilitator["transaction"]
    ):
        _fail(check, "journal transcript differs from settlement fulfillment")
    request_at = _timestamp(start["observed_at"], "journal request time")
    response_at = _timestamp(response["observed_at"], "journal response time")
    settled_at = _timestamp(first_row["settledAt"], "fulfillment settled time")
    if not (
        request_at
        <= response_at
        <= settled_at
        <= first_release_at
        <= first_at
        and settled_at <= first_fulfillment_at <= first_at
        < restart_fulfillment_at
        <= retry_at
        <= values[1][3]
        <= cross_at
        <= values[2][3]
    ):
        _fail(check, "journal or fulfillment chronology is invalid")
    if (
        first_fulfillment_instance == restart_fulfillment_instance
        or first_instance != first_fulfillment_instance
        or values[1][4] != restart_fulfillment_instance
        or values[2][4] != restart_fulfillment_instance
    ):
        _fail(
            check,
            "journal snapshots do not bind the fulfillment service restart",
        )


def _verify_paid_resource_and_journal(
    document: Mapping[str, Any],
    *,
    authorization: Mapping[str, Any],
    facilitator: Mapping[str, Any],
    report_raw: bytes,
    first_row: Mapping[str, Any],
    first_fulfillment_at: datetime,
    restart_fulfillment_at: datetime,
    first_fulfillment_instance: str,
    restart_fulfillment_instance: str,
) -> tuple[datetime, datetime, datetime]:
    fulfillment = _mapping(document.get("fulfillment"), "fulfillment")
    first = _decode_paid_exchange(
        fulfillment.get("first_release"),
        label="first paid-resource release",
        check=_CHECKS[21],
        expect_payment_response=True,
    )
    retry = _decode_paid_exchange(
        fulfillment.get("exact_retry"),
        label="exact paid-resource retry",
        check=_CHECKS[19],
        expect_payment_response=True,
    )
    cross = _decode_paid_exchange(
        fulfillment.get("cross_binding_reuse"),
        label="cross-binding paid-resource reuse",
        check=_CHECKS[20],
        expect_payment_response=False,
    )
    configured_payload = authorization["signed_payload"]
    expected_resource_url = _mapping(
        authorization["resource"], "configured resource"
    )["url"]
    if (
        first["exchange"].get("method") != "GET"
        or first["exchange"].get("url") != expected_resource_url
        or first["exchange"].get("response_status") != 200
        or first["signed_payload"] != configured_payload
        or first["response_body"] != report_raw
        or first.get("settlement") != facilitator["settle_response"]
        or first["observed_at"]
        < _timestamp(first_row.get("settledAt"), "fulfillment settledAt")
    ):
        _fail(_CHECKS[21], "first report release differs from finalized payment")
    if (
        retry["exchange"].get("method") != "GET"
        or retry["exchange"].get("url") != expected_resource_url
        or retry["exchange"].get("response_status") != 200
        or retry["signed_payload"] != configured_payload
        or retry["response_body"] != report_raw
        or retry.get("settlement") != facilitator["settle_response"]
        or retry["exchange"].get("payment_signature_raw_value_base64")
        != first["exchange"].get("payment_signature_raw_value_base64")
        or retry["exchange"].get("payment_response_raw_value_base64")
        != first["exchange"].get("payment_response_raw_value_base64")
    ):
        _fail(_CHECKS[19], "exact retry did not return stored fulfillment")
    cross_payload = _mapping(cross["signed_payload"], "cross-binding payload")
    cross_authorization = _mapping(
        _mapping(cross_payload.get("payload"), "cross payload body").get(
            "authorization"
        ),
        "cross authorization",
    )
    original_authorization = _mapping(
        _mapping(configured_payload.get("payload"), "payment payload").get(
            "authorization"
        ),
        "payment authorization",
    )
    expected_cross_payload = _strict_json_object(
        _canonical(configured_payload), "expected cross-binding payload"
    )
    expected_cross_resource = _mapping(
        expected_cross_payload.get("resource"),
        "expected cross-binding resource",
    )
    expected_cross_resource["url"] = cross["exchange"].get("url")
    if (
        cross["exchange"].get("method") != "GET"
        or cross["exchange"].get("response_status") != 409
        or cross["exchange"].get("url") == expected_resource_url
        or cross_payload == configured_payload
        or cross_payload != expected_cross_payload
        or cross_payload.get("accepted") != configured_payload.get("accepted")
        or cross_authorization != original_authorization
        or _mapping(cross_payload.get("payload"), "cross payload").get(
            "signature"
        )
        != _mapping(configured_payload.get("payload"), "payment payload").get(
            "signature"
        )
        or cross["response_body"]
        != _canonical({"error": "cross_binding_rejected"})
    ):
        _fail(
            _CHECKS[20],
            "cross-binding reuse is not a terminal pre-submission rejection",
        )
    if not first["observed_at"] < retry["observed_at"] < cross["observed_at"]:
        _fail(
            _CHECKS[19],
            "paid-resource first, retry, and rejection chronology differs",
        )
    _verify_journal(
        document,
        first_row=first_row,
        facilitator=facilitator,
        first_release_at=first["observed_at"],
        retry_at=retry["observed_at"],
        cross_at=cross["observed_at"],
        first_fulfillment_at=first_fulfillment_at,
        restart_fulfillment_at=restart_fulfillment_at,
        first_fulfillment_instance=first_fulfillment_instance,
        restart_fulfillment_instance=restart_fulfillment_instance,
    )
    return first["observed_at"], retry["observed_at"], cross["observed_at"]


def _pointer_get(document: object, pointer: str) -> object:
    value = document
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if type(value) is list:
            value = value[int(token)]
        elif type(value) is dict:
            value = value[token]
        else:
            raise OfficialX402ReleaseAdapterError(
                "evidence pointer does not resolve"
            )
    return value


def _check_result(
    document: Mapping[str, Any],
    *,
    name: str,
    paths: Sequence[str],
    observed_at: str,
) -> dict[str, Any]:
    projection = {path: _pointer_get(document, path) for path in paths}
    return {
        "name": name,
        "passed": True,
        "source": _ARTIFACT_SOURCE,
        "observed_at": observed_at,
        "evidence_paths": list(paths),
        "evidence_sha256": _sha256(_canonical(projection)),
    }


def _exact_checks(observed_at: str) -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "required": True,
            "passed": True,
            "source": _ARTIFACT_SOURCE + "#/governance_binding/v3_proof_bytes_base64",
            "observed_at": observed_at,
        }
        for name in _EXACT_V3_CHECKS
    ]


def verify_official_x402_artifact(
    raw: bytes, artifact_name: str
) -> dict[str, Any]:
    """Verify one canonical official-x402 artifact and return derived facts."""

    if type(raw) is not bytes or type(artifact_name) is not str or not artifact_name:
        raise OfficialX402ReleaseAdapterError(
            "official x402 adapter input is invalid"
        )
    artifact_schema, result_schema = _assert_schema_pins()
    document = _strict_json_object(raw, artifact_name)
    if raw != _canonical(document):
        raise OfficialX402ReleaseAdapterError(
            "official x402 artifact is not canonical ASCII JSON"
        )
    _validate_artifact_schema(document, artifact_schema)

    captured_at = document["captured_at"]
    captured_instant = _timestamp(captured_at, "artifact captured_at")
    if captured_instant > datetime.now(UTC) + timedelta(minutes=5):
        raise OfficialX402ReleaseAdapterError(
            "official x402 artifact captured_at is in the future"
        )
    capture_identity = _mapping(
        document["capture_identity"], "capture identity"
    )
    if (
        capture_identity.get("capture_tool_commit")
        != document["source_commit"]
        or capture_identity.get("service_url")
        != "https://x402.concordiadao.xyz"
        or capture_identity.get("service_deployment_id")
        != f"official-x402-{document['deployment_commit'][:12]}"
    ):
        raise OfficialX402ReleaseAdapterError(
            "official x402 capture identity differs from the release"
        )
    binding, _, _, header, body = _verify_v3(document)
    authorization = _verify_authorization(document, body=body)
    report_raw = _verify_resource_and_report(
        document, body=body, authorization=authorization
    )
    expected_args = _runtime_args_expected(authorization)
    readbacks = _mapping(document["wcspr_readbacks"], "WCSPR readbacks")
    pre_verify_readback = _verify_wcspr_readback(
        readbacks["pre_verify"],
        label="pre-verify WCSPR readback",
        check=_CHECKS[11],
        expected_args=expected_args,
    )
    facilitator = _verify_facilitator(
        document, authorization=authorization
    )
    pre_settle_readback = _verify_wcspr_readback(
        readbacks["pre_settle"],
        label="pre-settle WCSPR readback",
        check=_CHECKS[13],
        expected_args=expected_args,
    )
    parsed_settlement, settlement_observed_at = _verify_settlement_chain(
        document,
        transaction=str(facilitator["transaction"]),
        expected_args=expected_args,
    )
    post_settle_readback = _verify_wcspr_readback(
        readbacks["post_settle"],
        label="post-settle WCSPR readback",
        check=_CHECKS[16],
        expected_args=expected_args,
    )
    (
        first_row,
        _,
        first_row_at,
        restart_row_at,
        first_instance,
        restart_instance,
    ) = _verify_fulfillment_rows(
        document,
        authorization=authorization,
        facilitator=facilitator,
    )
    first_release_at, retry_at, cross_at = _verify_paid_resource_and_journal(
        document,
        authorization=authorization,
        facilitator=facilitator,
        report_raw=report_raw,
        first_row=first_row,
        first_fulfillment_at=first_row_at,
        restart_fulfillment_at=restart_row_at,
        first_fulfillment_instance=first_instance,
        restart_fulfillment_instance=restart_instance,
    )

    release_order = _mapping(document["release_order"], "release order")
    v3_finalized = _timestamp(
        release_order["v3_finalized_at"], "v3 finalized_at"
    )
    settlement_finalized = _timestamp(
        release_order["settlement_finalized_at"],
        "settlement finalized_at",
    )
    report_released = _timestamp(
        release_order["report_released_at"], "report released_at"
    )
    settlement_block_at = _timestamp(
        parsed_settlement["block_timestamp"],
        "settlement block timestamp",
    )
    authorization_valid_after = datetime.fromtimestamp(
        int(authorization["valid_after"]), UTC
    )
    authorization_valid_before = datetime.fromtimestamp(
        int(authorization["valid_before"]), UTC
    )
    if not (
        pre_verify_readback["tip_height"]
        <= pre_settle_readback["tip_height"]
        <= post_settle_readback["tip_height"]
        and pre_verify_readback["tip_timestamp"]
        <= pre_settle_readback["tip_timestamp"]
        <= post_settle_readback["tip_timestamp"]
        and post_settle_readback["tip_height"]
        - int(parsed_settlement["block_height"])
        >= 8
        and post_settle_readback["tip_timestamp"] >= settlement_block_at
    ):
        _fail(_CHECKS[16], "WCSPR readback tips are stale or reordered")
    if (
        release_order["v3_finalized_at"] != binding["finalized_at"]
        or release_order["settlement_finalized_at"] != first_row["settledAt"]
        or release_order["report_released_at"]
        != document["fulfillment"]["first_release"]["observed_at"]
        or not (
            v3_finalized
            <= facilitator["supported_at"]
            <= pre_verify_readback["observed_at"]
            <= facilitator["verify_at"]
            <= pre_settle_readback["observed_at"]
            <= facilitator["settle_at"]
            <= settlement_block_at
            <= settlement_finalized
            <= settlement_observed_at
            <= post_settle_readback["observed_at"]
            <= captured_instant
        )
        or not (
            authorization_valid_after
            <= settlement_block_at
            < authorization_valid_before
        )
        or not (
            settlement_finalized
            <= first_row_at
            <= restart_row_at
            <= retry_at
            <= cross_at
            <= captured_instant
        )
        or not (
            settlement_finalized
            <= report_released
            <= captured_instant
        )
        or first_release_at != report_released
    ):
        _fail(_CHECKS[21], "release chronology does not prove finalized-first")

    check_paths = (
        ("/governance_binding",),
        (
            "/resource_and_payment/configured_resource_json_base64",
            "/authorization/signed_payment_payload_json_base64",
        ),
        (
            "/resource_and_payment/accepted_json_base64",
            "/authorization/signed_payment_payload_json_base64",
        ),
        (
            "/resource_and_payment/payment_requirements_argument_json_base64",
            "/resource_and_payment/accepted_json_base64",
        ),
        ("/authorization",),
        (
            "/authorization/public_key_hex",
            "/authorization/payer_account_hash",
            "/authorization/recovered_payer_account_hash",
        ),
        (
            "/authorization",
            "/governance_binding",
        ),
        (
            "/resource_and_payment/configured_resource_json_base64",
            "/governance_binding/resource_url_hash",
        ),
        (
            "/protected_report",
            "/governance_binding/report_hash",
        ),
        (
            "/resource_and_payment/accepted_json_base64",
            "/governance_binding/payment_requirements_hash",
        ),
        (
            "/authorization/signed_payment_payload_json_base64",
            "/governance_binding/signed_payment_payload_hash",
        ),
        ("/wcspr_readbacks/pre_verify",),
        ("/facilitator/supported", "/facilitator/verify"),
        ("/wcspr_readbacks/pre_settle",),
        ("/facilitator/settle",),
        ("/settlement_chain_evidence",),
        ("/wcspr_readbacks/post_settle",),
        ("/fulfillment/first_row",),
        ("/fulfillment/post_restart_row",),
        (
            "/fulfillment/first_release",
            "/fulfillment/exact_retry",
            "/fulfillment/upstream_settle_journal",
        ),
        (
            "/fulfillment/cross_binding_reuse",
            "/fulfillment/upstream_settle_journal",
        ),
        (
            "/release_order",
            "/fulfillment/first_release",
            "/protected_report",
        ),
    )
    checks = [
        _check_result(
            document,
            name=name,
            paths=paths,
            observed_at=captured_at,
        )
        for name, paths in zip(_CHECKS, check_paths, strict=True)
    ]
    derived = {
        "proposal_id": binding["proposal_id"],
        "proposal_hash": binding["proposal_hash"],
        "proposal_nonce": binding["proposal_nonce"],
        "action_id": binding["action_id"],
        "action_kind": "OfficialX402SettlementV1",
        "action_version": 1,
        "envelope_hash": binding["envelope_hash"],
        "deployment_domain": binding["deployment_domain"],
        "network": _NETWORK,
        "package_hash": binding["package_hash"],
        "contract_hash": binding["contract_hash"],
        "v3_finalized_exact": True,
        "finalization_transaction": binding["finalization_transaction"],
        "finalized_at": binding["finalized_at"],
        "observed_at": binding["observed_at"],
        "resource_url_hash": binding["resource_url_hash"],
        "payment_requirements_hash": binding["payment_requirements_hash"],
        "signed_payment_payload_hash": binding["signed_payment_payload_hash"],
        "report_hash": binding["report_hash"],
        "settlement_transaction": facilitator["transaction"],
        "source_commit": document["source_commit"],
        "deployment_commit": document["deployment_commit"],
        "captured_at": captured_at,
    }
    internal = {
        "schema_version": 1,
        "proposal_id": header["proposal_id"],
        "proposal_hash": header["proposal_hash"],
        "proposal_nonce": header["proposal_nonce"],
        "action_id": binding["action_id"],
        "action_kind": "OfficialX402SettlementV1",
        "action_version": 1,
        "envelope_hash": binding["envelope_hash"],
        "deployment_domain": header["deployment_domain"],
        "network": _NETWORK,
        "package_hash": binding["package_hash"],
        "contract_hash": binding["contract_hash"],
        "v3_finalized_exact": True,
        "finalization_transaction": binding["finalization_transaction"],
        "finalized_at": binding["finalized_at"],
        "resource_url_hash": binding["resource_url_hash"],
        "report_hash": binding["report_hash"],
        "payment_requirements_hash": binding["payment_requirements_hash"],
        "signed_payment_payload_hash": binding["signed_payment_payload_hash"],
        "settlement_transaction": facilitator["transaction"],
        "verification_status": "verified",
        "observed_at": binding["observed_at"],
        "checks": _exact_checks(binding["observed_at"]),
    }
    result = {
        "schema_version": "concordia.official_x402_adapter_result.v1",
        "proof_type": "official_x402_settlement_v1",
        "artifact_sha256": _sha256(raw),
        "derived_facts": derived,
        "internal_record": internal,
        "checks": checks,
    }
    try:
        Draft202012Validator(result_schema).validate(result)
    except ValidationError as exc:
        raise OfficialX402ReleaseAdapterError(
            "official x402 adapter result schema mismatch"
        ) from exc
    return result
