"""Canonical scalar and common-header encoding for Concordia v3 envelopes.

This module is intentionally dependency-free.  It is one of three independent
implementations (Python, Rust, and JavaScript) checked against the immutable G1
golden vectors.  All integers are fixed-width big-endian and all strings are
ASCII length-prefixed with a four-byte big-endian length.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


DEPLOYMENT_DOMAIN_SEPARATOR = b"CONCORDIA_DOMAIN_V3\0"
ENVELOPE_DOMAIN_SEPARATOR = b"CONCORDIA_GOVERNANCE_ENVELOPE_V3\0"
ACTION_ID_DOMAIN_SEPARATOR = b"CONCORDIA_ACTION_ID_V3\0"
TRANSFER_ID_DOMAIN_SEPARATOR = b"CONCORDIA_TRANSFER_ID_V3\0"

PROPOSAL_ID_RE = re.compile(r"^[A-Z0-9-]{1,64}$")
MACHINE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
HEX_32_RE = re.compile(r"^[0-9a-f]{64}$")
DECIMAL_RE = re.compile(r"^(?:0|[1-9][0-9]*)$")

TYPE_TAGS: dict[str, int] = {
    "bool": 1,
    "u8": 2,
    "u32": 3,
    "u64": 4,
    "U256": 5,
    "U512": 6,
    "Bytes32": 7,
    "AccountHash": 8,
    "Key": 9,
    "String": 10,
    "Bytes": 11,
    "List<Key>": 12,
    "PublicKey": 13,
    "Option<u64>": 14,
}

HEADER_SCHEMA: tuple[tuple[str, str], ...] = (
    ("schema_version", "u32"),
    ("deployment_domain", "Bytes32"),
    ("casper_chain_name", "String"),
    ("proposal_id", "String"),
    ("proposal_nonce", "Bytes32"),
    ("decision_code", "u8"),
    ("requested_allocation_bps", "u32"),
    ("approved_allocation_bps", "u32"),
    ("action_kind", "u8"),
    ("action_version", "u32"),
    ("action_id", "Bytes32"),
    ("proposal_hash", "Bytes32"),
    ("policy_hash", "Bytes32"),
    ("plan_hash", "Bytes32"),
    ("final_card_hash", "Bytes32"),
    ("dissent_hash", "Bytes32"),
    ("agent_action_hash", "Bytes32"),
    ("preauth_evidence_root", "Bytes32"),
    ("authorized_metadata_root", "Bytes32"),
)


class EnvelopeEncodingError(ValueError):
    """A typed envelope cannot be encoded under the frozen v3 contract."""

    def __init__(self, error_name: str, field_name: str | None, detail: str):
        self.error_name = error_name
        self.field_name = field_name
        super().__init__(f"{error_name}: {field_name or 'envelope'}: {detail}")


@dataclass(frozen=True)
class EncodedEnvelope:
    header_bytes: bytes
    body_bytes: bytes
    action_core_bytes: bytes
    action_id: bytes
    envelope_hash: bytes
    transfer_id: int | None = None


def blake2b256(value: bytes) -> bytes:
    return hashlib.blake2b(value, digest_size=32).digest()


def _uint(value: object, bits: int, field_name: str) -> int:
    if isinstance(value, bool):
        raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, "boolean is not an integer")
    if isinstance(value, str):
        if not DECIMAL_RE.fullmatch(value):
            raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, "non-canonical decimal")
        parsed = int(value)
    elif isinstance(value, int):
        parsed = value
    else:
        raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, "integer required")
    if parsed < 0 or parsed >= 1 << bits:
        raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, f"outside u{bits} range")
    return parsed


def uint_value(value: object, bits: int, field_name: str) -> int:
    """Validate and return a frozen unsigned scalar."""

    return _uint(value, bits, field_name)


def _ascii(value: object, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, "string required")
    if "\0" in value:
        raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, "embedded NUL")
    try:
        return value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, "ASCII required") from exc


def length_prefix(value: str | bytes, field_name: str = "value") -> bytes:
    raw = _ascii(value, field_name) if isinstance(value, str) else value
    if not isinstance(raw, bytes):
        raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, "bytes required")
    if len(raw) >= 1 << 32:
        raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, "value too large")
    return len(raw).to_bytes(4, "big") + raw


def bytes32(value: object, field_name: str) -> bytes:
    if isinstance(value, bytes):
        if len(value) != 32:
            raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, "exactly 32 bytes required")
        return value
    if not isinstance(value, str) or not HEX_32_RE.fullmatch(value):
        raise EnvelopeEncodingError(
            "InvalidEnvelopeField", field_name, "64 lowercase hexadecimal characters required"
        )
    return bytes.fromhex(value)


def canonical_value(type_name: str, value: Any, field_name: str = "value") -> bytes:
    """Encode one frozen scalar value without any JSON/string coercion."""

    if type_name == "bool":
        if value is True:
            return b"\x01"
        if value is False:
            return b"\x00"
        raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, "JSON boolean required")
    if type_name in {"u8", "u32", "u64"}:
        bits = int(type_name[1:])
        return _uint(value, bits, field_name).to_bytes(bits // 8, "big")
    if type_name == "U256":
        return _uint(value, 256, field_name).to_bytes(32, "big")
    if type_name == "U512":
        return _uint(value, 512, field_name).to_bytes(64, "big")
    if type_name in {"Bytes32", "AccountHash"}:
        return bytes32(value, field_name)
    if type_name == "String":
        return length_prefix(_ascii(value, field_name), field_name)
    if type_name == "Bytes":
        if not isinstance(value, str) or len(value) % 2 or not re.fullmatch(r"[0-9a-f]*", value):
            raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, "lowercase hex bytes required")
        return length_prefix(bytes.fromhex(value), field_name)
    if type_name == "Key":
        if not isinstance(value, Mapping):
            raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, "typed Key required")
        variant = {"Account": 0, "Hash": 1}.get(value.get("variant"))
        if variant is None:
            raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, "unsupported Key variant")
        return bytes([variant]) + bytes32(value.get("value"), field_name)
    if type_name == "List<Key>":
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, "Key list required")
        members = [canonical_value("Key", item, field_name) for item in value]
        return len(members).to_bytes(4, "big") + b"".join(members)
    if type_name == "PublicKey":
        if not isinstance(value, Mapping):
            raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, "typed PublicKey required")
        raw_value = value.get("value")
        if not isinstance(raw_value, str) or len(raw_value) % 2 or not re.fullmatch(r"[0-9a-f]+", raw_value):
            raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, "public key hex required")
        raw = bytes.fromhex(raw_value)
        algorithm = value.get("algorithm")
        if algorithm == "Ed25519" and len(raw) == 32:
            return b"\x01" + raw
        if algorithm == "Secp256k1" and len(raw) == 33 and raw[0] in (2, 3):
            return b"\x02" + raw
        raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, "invalid public key")
    if type_name == "Option<u64>":
        if not isinstance(value, Mapping):
            raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, "typed Option required")
        if value.get("variant") == "None" and value.get("value") is None:
            return b"\x00"
        if value.get("variant") == "Some":
            return b"\x01" + canonical_value("u64", value.get("value"), field_name)
        raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, "invalid Option<u64>")
    raise EnvelopeEncodingError("InvalidEnvelopeField", field_name, f"unsupported type {type_name}")


def require_exact_fields(values: Mapping[str, Any], schema: Sequence[tuple[str, str]]) -> None:
    expected = [name for name, _ in schema]
    missing = [name for name in expected if name not in values]
    extra = sorted(set(values).difference(expected))
    if missing or extra:
        raise EnvelopeEncodingError(
            "InvalidEnvelopeField",
            missing[0] if missing else extra[0],
            "field set does not match frozen schema",
        )


def encode_fields(values: Mapping[str, Any], schema: Sequence[tuple[str, str]]) -> bytes:
    require_exact_fields(values, schema)
    return b"".join(canonical_value(type_name, values[name], name) for name, type_name in schema)


def _validate_header(values: Mapping[str, Any]) -> None:
    require_exact_fields(values, HEADER_SCHEMA)
    if _uint(values["schema_version"], 32, "schema_version") != 3:
        raise EnvelopeEncodingError("InvalidEnvelopeField", "schema_version", "must equal 3")
    if values["casper_chain_name"] != "casper-test":
        raise EnvelopeEncodingError("InvalidEnvelopeField", "casper_chain_name", "must equal casper-test")
    proposal_id = values["proposal_id"]
    if not isinstance(proposal_id, str) or not PROPOSAL_ID_RE.fullmatch(proposal_id):
        raise EnvelopeEncodingError("InvalidProposalId", "proposal_id", "frozen grammar mismatch")
    if _uint(values["decision_code"], 8, "decision_code") > 4:
        raise EnvelopeEncodingError("InvalidEnvelopeField", "decision_code", "unknown decision")
    for field in ("requested_allocation_bps", "approved_allocation_bps"):
        if _uint(values[field], 32, field) > 10_000:
            raise EnvelopeEncodingError("InvalidEnvelopeField", field, "basis points exceed 10000")
    if _uint(values["action_kind"], 8, "action_kind") not in (1, 2):
        raise EnvelopeEncodingError("InvalidEnvelopeField", "action_kind", "unsupported action")
    if _uint(values["action_version"], 32, "action_version") != 1:
        raise EnvelopeEncodingError("InvalidEnvelopeField", "action_version", "must equal 1")
    for name, type_name in HEADER_SCHEMA:
        canonical_value(type_name, values[name], name)


def encode_header(values: Mapping[str, Any]) -> bytes:
    _validate_header(values)
    return encode_fields(values, HEADER_SCHEMA)


def derive_deployment_domain(
    *,
    chain_name: str,
    package_name: str,
    installation_nonce: bytes,
) -> bytes:
    if chain_name != "casper-test":
        raise EnvelopeEncodingError("InvalidEnvelopeField", "casper_chain_name", "must equal casper-test")
    if package_name != "concordia_governance_receipt_v3":
        raise EnvelopeEncodingError("InvalidEnvelopeField", "package_name", "unexpected package")
    nonce = bytes32(installation_nonce, "installation_nonce")
    if nonce == bytes(32):
        raise EnvelopeEncodingError("InvalidEnvelopeField", "installation_nonce", "must be non-zero")
    return blake2b256(
        DEPLOYMENT_DOMAIN_SEPARATOR
        + length_prefix(chain_name, "casper_chain_name")
        + length_prefix(package_name, "package_name")
        + nonce
    )
