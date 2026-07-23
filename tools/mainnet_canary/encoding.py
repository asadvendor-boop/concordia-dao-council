"""Fresh, from-spec implementation of the frozen Concordia v3 encoding.

This module is written directly from ``handoff/G1_INTERFACE_SPEC.md`` §2, §4,
§5 and §7 and deliberately imports nothing from ``shared/``: it is one of the
two independent recomputation implementations required by the Mainnet canary
assignment (the second path composes the frozen ``shared/`` primitives; see
``tools/mainnet_canary/crosscheck.py``).

Unlike the Testnet-frozen ``shared/envelope_v3.py``, the header chain name
here is parameterised so the same frozen byte layout can be computed for the
Mainnet chain name ``casper``.  Every other rule is identical:

- BLAKE2b-256 is RFC 7693 BLAKE2b with ``digest_size=32`` (not a truncation).
- Integers are fixed-width unsigned big-endian; U256/U512 include leading
  zeroes; strings are printable-ASCII, ``u32_be(len) || bytes``.
- Domain separators are exact ASCII followed by one 0x00 byte.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

# Domain separators (G1 §2 authoritative table; final byte is 0x00).
# The DEPLOYMENT domain is network-specific: the Mainnet-native contract
# profile pins a disjoint separator so a Mainnet deployment domain can never
# collide with (or replay against) a Testnet one.  Byte-frozen against the
# Rust constants in contracts/odra-governance-receipt-v3/src/encoding.rs.
DOMAIN_DEPLOYMENT_TESTNET = b"CONCORDIA_DOMAIN_V3\x00"
DOMAIN_DEPLOYMENT_MAINNET = b"CONCORDIA_DOMAIN_V3_MAINNET\x00"
# Historical alias (Testnet value) kept for the frozen v1 call sites.
DOMAIN_DEPLOYMENT = DOMAIN_DEPLOYMENT_TESTNET
DOMAIN_ENVELOPE = b"CONCORDIA_GOVERNANCE_ENVELOPE_V3\x00"
DOMAIN_ACTION_ID = b"CONCORDIA_ACTION_ID_V3\x00"
DOMAIN_TRANSFER_ID = b"CONCORDIA_TRANSFER_ID_V3\x00"

SUPPORTED_CHAIN_NAMES = ("casper", "casper-test")

_DEPLOYMENT_DOMAIN_BY_CHAIN = {
    "casper-test": DOMAIN_DEPLOYMENT_TESTNET,
    "casper": DOMAIN_DEPLOYMENT_MAINNET,
}

_PROPOSAL_ID = re.compile(r"[A-Z0-9-]{1,64}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")

NATIVE_TRANSFER_ACTION_KIND = 1

# Frozen field orders (G1 §4 header, §5 NativeTransferV1 body).
HEADER_FIELDS = (
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

NATIVE_BODY_FIELDS = (
    ("asset_kind", "u8"),
    ("source_account", "AccountHash"),
    ("recipient_account", "AccountHash"),
    ("amount_motes", "U512"),
    ("treasury_snapshot_balance_motes", "U512"),
    ("snapshot_block_hash", "Bytes32"),
    ("snapshot_block_height", "u64"),
    ("transfer_id", "u64"),
    ("action_nonce", "Bytes32"),
    ("execution_target", "String"),
    ("execution_version", "u32"),
)

# Native action core: exactly body fields 1,2,3,4,5,6,7,10,11 (G1 §5) — the
# core excludes transfer_id and action_nonce.
NATIVE_CORE_FIELD_NAMES = (
    "asset_kind",
    "source_account",
    "recipient_account",
    "amount_motes",
    "treasury_snapshot_balance_motes",
    "snapshot_block_hash",
    "snapshot_block_height",
    "execution_target",
    "execution_version",
)


class FreshEncodingError(ValueError):
    """Fail-closed encoding refusal from the from-spec implementation."""

    def __init__(self, error_name: str, field: str, detail: str):
        self.error_name = error_name
        self.field = field
        super().__init__(f"{error_name}: {field}: {detail}")


def _fail(error_name: str, field: str, detail: str) -> FreshEncodingError:
    return FreshEncodingError(error_name, field, detail)


def blake2b_256(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def _as_unsigned(field: str, value: object, bits: int) -> int:
    if isinstance(value, bool):
        raise _fail("InvalidEnvelopeField", field, "bool is not an unsigned int")
    if isinstance(value, str):
        if _DECIMAL.match(value) is None:
            raise _fail("InvalidEnvelopeField", field, "non-canonical decimal")
        number = int(value, 10)
    elif isinstance(value, int):
        number = value
    else:
        raise _fail("InvalidEnvelopeField", field, "unsigned integer required")
    if not 0 <= number < (1 << bits):
        raise _fail("InvalidEnvelopeField", field, f"outside u{bits} range")
    return number


def _as_bytes32(field: str, value: object) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) != 32:
            raise _fail("InvalidEnvelopeField", field, "exactly 32 bytes required")
        return raw
    if isinstance(value, str) and _HEX64.match(value) is not None:
        return bytes.fromhex(value)
    raise _fail("InvalidEnvelopeField", field, "64 lowercase hex chars required")


def _as_printable_ascii(field: str, value: object) -> bytes:
    if not isinstance(value, str):
        raise _fail("InvalidEnvelopeField", field, "string required")
    raw = bytearray()
    for char in value:
        point = ord(char)
        if point < 0x20 or point > 0x7E:
            raise _fail(
                "InvalidEnvelopeField", field, "printable ASCII 0x20..0x7e only"
            )
        raw.append(point)
    return bytes(raw)


def _lp(raw: bytes) -> bytes:
    return len(raw).to_bytes(4, "big") + raw


def encode_scalar(field: str, type_name: str, value: object) -> bytes:
    """Encode one frozen scalar exactly per G1 §2."""

    if type_name == "u8":
        return _as_unsigned(field, value, 8).to_bytes(1, "big")
    if type_name == "u32":
        return _as_unsigned(field, value, 32).to_bytes(4, "big")
    if type_name == "u64":
        return _as_unsigned(field, value, 64).to_bytes(8, "big")
    if type_name == "U256":
        return _as_unsigned(field, value, 256).to_bytes(32, "big")
    if type_name == "U512":
        return _as_unsigned(field, value, 512).to_bytes(64, "big")
    if type_name in ("Bytes32", "AccountHash"):
        return _as_bytes32(field, value)
    if type_name == "String":
        return _lp(_as_printable_ascii(field, value))
    raise _fail("InvalidEnvelopeField", field, f"unsupported type {type_name}")


def _encode_record(
    values: dict[str, object],
    fields: tuple[tuple[str, str], ...],
    error_name: str,
) -> bytes:
    expected = {name for name, _ in fields}
    unknown = sorted(set(values) - expected)
    absent = [name for name, _ in fields if name not in values]
    if unknown or absent:
        offender = absent[0] if absent else unknown[0]
        raise _fail(error_name, offender, "field set differs from frozen schema")
    pieces: list[bytes] = []
    for name, type_name in fields:
        try:
            pieces.append(encode_scalar(name, type_name, values[name]))
        except FreshEncodingError as exc:
            raise _fail(error_name, name, str(exc)) from exc
    return b"".join(pieces)


def validate_header(values: dict[str, object], *, chain_name: str) -> None:
    """Frozen header validation (G1 §4) with a parameterised chain name."""

    if chain_name not in SUPPORTED_CHAIN_NAMES:
        raise _fail("InvalidEnvelopeField", "casper_chain_name", "unknown chain")
    _encode_record(values, HEADER_FIELDS, "InvalidEnvelopeField")
    if _as_unsigned("schema_version", values["schema_version"], 32) != 3:
        raise _fail("InvalidEnvelopeField", "schema_version", "must equal 3")
    if values["casper_chain_name"] != chain_name:
        raise _fail(
            "InvalidEnvelopeField",
            "casper_chain_name",
            f"must equal {chain_name}",
        )
    proposal_id = values["proposal_id"]
    if not isinstance(proposal_id, str) or _PROPOSAL_ID.match(proposal_id) is None:
        raise _fail("InvalidProposalId", "proposal_id", "grammar [A-Z0-9-]{1,64}")
    if _as_unsigned("decision_code", values["decision_code"], 8) > 4:
        raise _fail("InvalidEnvelopeField", "decision_code", "unknown decision")
    for bps_field in ("requested_allocation_bps", "approved_allocation_bps"):
        if _as_unsigned(bps_field, values[bps_field], 32) > 10_000:
            raise _fail("InvalidEnvelopeField", bps_field, "exceeds 10000 bps")
    if _as_unsigned("action_kind", values["action_kind"], 8) not in (1, 2):
        raise _fail("InvalidActionField", "action_kind", "unsupported action kind")
    if _as_unsigned("action_version", values["action_version"], 32) != 1:
        raise _fail("InvalidActionField", "action_version", "must equal 1")


def encode_header(values: dict[str, object], *, chain_name: str) -> bytes:
    validate_header(values, chain_name=chain_name)
    return _encode_record(values, HEADER_FIELDS, "InvalidEnvelopeField")


def derive_deployment_domain(
    *, chain_name: str, package_key_name: str, installation_nonce: object
) -> bytes:
    """G1 §3 deployment-domain formula with a parameterised chain name."""

    if chain_name not in SUPPORTED_CHAIN_NAMES:
        raise _fail("InvalidEnvelopeField", "casper_chain_name", "unknown chain")
    if package_key_name != "concordia_governance_receipt_v3":
        raise _fail("InvalidEnvelopeField", "package_key_name", "wrong package")
    nonce = _as_bytes32("installation_nonce", installation_nonce)
    if nonce == bytes(32):
        raise _fail("InvalidEnvelopeField", "installation_nonce", "must be non-zero")
    return blake2b_256(
        _DEPLOYMENT_DOMAIN_BY_CHAIN[chain_name]
        + _lp(chain_name.encode("ascii"))
        + _lp(package_key_name.encode("ascii"))
        + nonce
    )


@dataclass(frozen=True)
class NativeEnvelopeMaterial:
    """Recomputed identifiers and canonical bytes for one native envelope."""

    header_bytes: bytes
    body_bytes: bytes
    action_core_bytes: bytes
    action_id: bytes
    transfer_id: int
    envelope_hash: bytes


def _validate_native_semantics(
    header: dict[str, object], body: dict[str, object]
) -> None:
    """Cross-field native invariants (G1 §5), checked wide-integer arithmetic."""

    if _as_unsigned("asset_kind", body["asset_kind"], 8) != 0:
        raise _fail("InvalidActionField", "asset_kind", "native CSPR is kind 0")
    source = _as_bytes32("source_account", body["source_account"])
    recipient = _as_bytes32("recipient_account", body["recipient_account"])
    if source == bytes(32) or recipient == bytes(32):
        raise _fail("InvalidActionField", "source_account", "must be non-zero")
    if source == recipient:
        raise _fail("InvalidActionField", "recipient_account", "must differ")
    amount = _as_unsigned("amount_motes", body["amount_motes"], 512)
    balance = _as_unsigned(
        "treasury_snapshot_balance_motes",
        body["treasury_snapshot_balance_motes"],
        512,
    )
    approved = _as_unsigned(
        "approved_allocation_bps", header["approved_allocation_bps"], 32
    )
    requested = _as_unsigned(
        "requested_allocation_bps", header["requested_allocation_bps"], 32
    )
    decision = _as_unsigned("decision_code", header["decision_code"], 8)
    if amount == 0 or balance == 0 or approved == 0:
        raise _fail(
            "InvalidActionField",
            "amount_motes",
            "amount, snapshot balance, and approved bps must be non-zero",
        )
    wide_product = balance * approved
    if wide_product >= 1 << 512:
        raise _fail(
            "InvalidActionField",
            "treasury_snapshot_balance_motes",
            "checked multiplication overflow",
        )
    if amount != wide_product // 10_000:
        raise _fail(
            "InvalidActionField",
            "amount_motes",
            "amount must equal floor(balance * approved_bps / 10000)",
        )
    if not (0 < approved <= requested <= 10_000):
        raise _fail(
            "InvalidEnvelopeField",
            "approved_allocation_bps",
            "allocation relationship violated",
        )
    if decision not in (1, 2):
        raise _fail(
            "InvalidEnvelopeField", "decision_code", "not an executable decision"
        )
    if decision == 1 and approved != requested:
        raise _fail(
            "InvalidEnvelopeField", "decision_code", "APPROVED must be exact"
        )
    if decision == 2 and approved >= requested:
        raise _fail(
            "InvalidEnvelopeField",
            "decision_code",
            "APPROVED_WITH_LIMITS must reduce the allocation",
        )
    if body["execution_target"] != "native-transfer":
        raise _fail(
            "InvalidActionField", "execution_target", "must be native-transfer"
        )
    if _as_unsigned("execution_version", body["execution_version"], 32) != 1:
        raise _fail("InvalidActionField", "execution_version", "must equal 1")


def derive_native_envelope(
    header: dict[str, object],
    body: dict[str, object],
    *,
    chain_name: str,
) -> NativeEnvelopeMaterial:
    """Recompute action_id, transfer_id, and envelope hash per G1 §7.

    Fails closed if any supplied identifier disagrees with recomputation.
    """

    body_probe = _encode_record(body, NATIVE_BODY_FIELDS, "InvalidActionField")
    del body_probe  # scalar validation only; canonical body computed below

    core = b"".join(
        encode_scalar(
            name,
            dict(NATIVE_BODY_FIELDS)[name],
            body[name],
        )
        for name in NATIVE_CORE_FIELD_NAMES
    )
    nonce = _as_bytes32("action_nonce", body["action_nonce"])
    if nonce == bytes(32):
        raise _fail("InvalidActionField", "action_nonce", "must be non-zero")
    action_id = blake2b_256(
        DOMAIN_ACTION_ID
        + NATIVE_TRANSFER_ACTION_KIND.to_bytes(1, "big")
        + nonce
        + core
    )

    header_bytes = encode_header(header, chain_name=chain_name)
    if _as_unsigned("action_kind", header["action_kind"], 8) != 1:
        raise _fail("InvalidActionField", "action_kind", "header/body mismatch")
    if _as_bytes32("action_id", header["action_id"]) != action_id:
        raise _fail("InvalidActionField", "action_id", "recomputation mismatch")

    transfer_digest = blake2b_256(
        DOMAIN_TRANSFER_ID
        + _lp(_as_printable_ascii("proposal_id", header["proposal_id"]))
        + _as_bytes32("proposal_nonce", header["proposal_nonce"])
        + action_id
    )
    transfer_id = int.from_bytes(transfer_digest[:8], "big")
    if _as_unsigned("transfer_id", body["transfer_id"], 64) != transfer_id:
        raise _fail("InvalidActionField", "transfer_id", "recomputation mismatch")

    _validate_native_semantics(header, body)
    body_bytes = _encode_record(body, NATIVE_BODY_FIELDS, "InvalidActionField")
    envelope_hash = blake2b_256(DOMAIN_ENVELOPE + header_bytes + body_bytes)
    return NativeEnvelopeMaterial(
        header_bytes=header_bytes,
        body_bytes=body_bytes,
        action_core_bytes=core,
        action_id=action_id,
        transfer_id=transfer_id,
        envelope_hash=envelope_hash,
    )
