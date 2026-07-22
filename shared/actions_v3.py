"""Typed NativeTransferV1 and OfficialX402SettlementV1 v3 encoders."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from shared.envelope_v3 import (
    ACTION_ID_DOMAIN_SEPARATOR,
    ENVELOPE_DOMAIN_SEPARATOR,
    TRANSFER_ID_DOMAIN_SEPARATOR,
    EncodedEnvelope,
    EnvelopeEncodingError,
    blake2b256,
    bytes32,
    canonical_value,
    encode_fields,
    encode_header,
    length_prefix,
    require_exact_fields,
    uint_value,
)


NATIVE_SCHEMA: tuple[tuple[str, str], ...] = (
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
NATIVE_CORE_SCHEMA = tuple(
    item for item in NATIVE_SCHEMA if item[0] not in {"transfer_id", "action_nonce"}
)

X402_SCHEMA: tuple[tuple[str, str], ...] = (
    ("x402_version", "u32"),
    ("scheme", "String"),
    ("caip2_network", "String"),
    ("wcspr_package", "Bytes32"),
    ("wcspr_contract", "Bytes32"),
    ("token_name", "String"),
    ("token_symbol", "String"),
    ("eip712_domain_version", "String"),
    ("token_decimals", "u8"),
    ("payer", "AccountHash"),
    ("payee", "AccountHash"),
    ("value", "U256"),
    ("resource_url_hash", "Bytes32"),
    ("report_hash", "Bytes32"),
    ("payment_requirements_hash", "Bytes32"),
    ("signed_payment_payload_hash", "Bytes32"),
    ("eip712_auth_nonce", "Bytes32"),
    ("valid_after", "u64"),
    ("valid_before", "u64"),
    ("action_nonce", "Bytes32"),
    ("settlement_target", "String"),
    ("settlement_version", "u32"),
)
X402_CORE_SCHEMA = tuple(item for item in X402_SCHEMA if item[0] != "action_nonce")

TESTNET_WCSPR_PACKAGE = "3d80df21ba4ee4d66a2a1f60c32570dd5685e4b279f6538162a5fd1314847c1e"
TESTNET_WCSPR_CONTRACT = "032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a"
MAX_U512 = (1 << 512) - 1


def _action_error(field: str, detail: str) -> EnvelopeEncodingError:
    return EnvelopeEncodingError("InvalidActionField", field, detail)


def _validate_body_scalars(values: Mapping[str, Any], schema: tuple[tuple[str, str], ...]) -> None:
    try:
        require_exact_fields(values, schema)
        for name, type_name in schema:
            canonical_value(type_name, values[name], name)
    except EnvelopeEncodingError as exc:
        raise _action_error(exc.field_name or "action", str(exc)) from exc


def _derive_action_id(action_kind: int, action_nonce: object, core: bytes) -> bytes:
    nonce = bytes32(action_nonce, "action_nonce")
    if nonce == bytes(32):
        raise _action_error("action_nonce", "must be non-zero")
    return blake2b256(ACTION_ID_DOMAIN_SEPARATOR + bytes([action_kind]) + nonce + core)


def _encode_projection(
    values: Mapping[str, Any],
    schema: tuple[tuple[str, str], ...],
) -> bytes:
    return encode_fields({name: values[name] for name, _ in schema}, schema)


def _require_header_action(
    header: Mapping[str, Any],
    *,
    action_kind: int,
    action_id: bytes,
) -> bytes:
    header_bytes = encode_header(header)
    if uint_value(header["action_kind"], 8, "action_kind") != action_kind:
        raise _action_error("action_kind", "header/body action mismatch")
    if bytes32(header["action_id"], "action_id") != action_id:
        raise _action_error("action_id", "does not match recomputed action ID")
    return header_bytes


def _validate_native_semantics(header: Mapping[str, Any], body: Mapping[str, Any]) -> None:
    if uint_value(body["asset_kind"], 8, "asset_kind") != 0:
        raise _action_error("asset_kind", "native CSPR must use discriminant 0")
    source = bytes32(body["source_account"], "source_account")
    recipient = bytes32(body["recipient_account"], "recipient_account")
    if source == bytes(32):
        raise _action_error("source_account", "must be non-zero")
    if recipient == bytes(32):
        raise _action_error("recipient_account", "must be non-zero")
    if source == recipient:
        raise _action_error("recipient_account", "source and recipient must differ")
    amount = uint_value(body["amount_motes"], 512, "amount_motes")
    balance = uint_value(
        body["treasury_snapshot_balance_motes"], 512, "treasury_snapshot_balance_motes"
    )
    approved = uint_value(header["approved_allocation_bps"], 32, "approved_allocation_bps")
    requested = uint_value(header["requested_allocation_bps"], 32, "requested_allocation_bps")
    decision = uint_value(header["decision_code"], 8, "decision_code")
    if not amount or not balance or not approved:
        raise _action_error("amount_motes", "amount, balance, and approved bps must be non-zero")
    product = balance * approved
    if product > MAX_U512:
        raise _action_error("treasury_snapshot_balance_motes", "checked multiplication overflow")
    if amount != product // 10_000:
        raise _action_error("amount_motes", "does not equal the exact approved allocation")
    if not 0 < approved <= requested <= 10_000:
        raise EnvelopeEncodingError(
            "InvalidEnvelopeField", "approved_allocation_bps", "invalid allocation relationship"
        )
    if decision == 1 and approved != requested:
        raise EnvelopeEncodingError("InvalidEnvelopeField", "decision_code", "APPROVED must be exact")
    if decision == 2 and approved >= requested:
        raise EnvelopeEncodingError(
            "InvalidEnvelopeField", "decision_code", "APPROVED_WITH_LIMITS must reduce allocation"
        )
    if decision not in (1, 2):
        raise EnvelopeEncodingError("InvalidEnvelopeField", "decision_code", "action is not executable")
    if body["execution_target"] != "native-transfer":
        raise _action_error("execution_target", "must equal native-transfer")
    if uint_value(body["execution_version"], 32, "execution_version") != 1:
        raise _action_error("execution_version", "must equal 1")


def derive_native_material(
    header: Mapping[str, Any],
    body: Mapping[str, Any],
) -> EncodedEnvelope:
    """Validate and recompute all NativeTransferV1 identifiers and bytes."""

    _validate_body_scalars(body, NATIVE_SCHEMA)
    core = _encode_projection(body, NATIVE_CORE_SCHEMA)
    computed_action_id = _derive_action_id(1, body["action_nonce"], core)
    header_bytes = _require_header_action(
        header,
        action_kind=1,
        action_id=computed_action_id,
    )
    transfer_digest = blake2b256(
        TRANSFER_ID_DOMAIN_SEPARATOR
        + length_prefix(header["proposal_id"], "proposal_id")
        + bytes32(header["proposal_nonce"], "proposal_nonce")
        + computed_action_id
    )
    computed_transfer_id = int.from_bytes(transfer_digest[:8], "big")
    if uint_value(body["transfer_id"], 64, "transfer_id") != computed_transfer_id:
        raise _action_error("transfer_id", "does not match recomputed transfer ID")
    _validate_native_semantics(header, body)
    body_bytes = encode_fields(body, NATIVE_SCHEMA)
    envelope_hash = blake2b256(ENVELOPE_DOMAIN_SEPARATOR + header_bytes + body_bytes)
    return EncodedEnvelope(
        header_bytes=header_bytes,
        body_bytes=body_bytes,
        action_core_bytes=core,
        action_id=computed_action_id,
        transfer_id=computed_transfer_id,
        envelope_hash=envelope_hash,
    )


def build_native_material(
    header: Mapping[str, Any],
    body: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], EncodedEnvelope]:
    """Derive action/transfer IDs, then run the same strict verifier.

    Callers provide all frozen typed fields but may leave ``action_id`` and
    ``transfer_id`` as placeholders.  The returned dictionaries are copies;
    input mappings are never mutated.
    """

    built_header = dict(header)
    built_body = dict(body)
    _validate_body_scalars(built_body, NATIVE_SCHEMA)
    # Validate the complete header field set and all non-derived scalars before
    # replacing the supplied placeholder action ID.
    encode_header(built_header)
    core = _encode_projection(built_body, NATIVE_CORE_SCHEMA)
    computed_action_id = _derive_action_id(1, built_body["action_nonce"], core)
    built_header["action_id"] = computed_action_id.hex()
    transfer_digest = blake2b256(
        TRANSFER_ID_DOMAIN_SEPARATOR
        + length_prefix(built_header["proposal_id"], "proposal_id")
        + bytes32(built_header["proposal_nonce"], "proposal_nonce")
        + computed_action_id
    )
    built_body["transfer_id"] = str(int.from_bytes(transfer_digest[:8], "big"))
    material = derive_native_material(built_header, built_body)
    return built_header, built_body, material


def _validate_x402_semantics(header: Mapping[str, Any], body: Mapping[str, Any]) -> None:
    expected_values = {
        "x402_version": 2,
        "scheme": "exact",
        "caip2_network": "casper:casper-test",
        "wcspr_package": TESTNET_WCSPR_PACKAGE,
        "wcspr_contract": TESTNET_WCSPR_CONTRACT,
        "token_name": "Wrapped CSPR",
        "token_symbol": "WCSPR",
        "eip712_domain_version": "1",
        "token_decimals": 9,
        "settlement_target": "cspr-cloud-facilitator",
        "settlement_version": 1,
    }
    for field, expected in expected_values.items():
        value = body[field]
        if isinstance(expected, int):
            value = uint_value(value, 32 if field not in {"token_decimals"} else 8, field)
        if value != expected:
            raise _action_error(field, f"must equal {expected}")
    payer = bytes32(body["payer"], "payer")
    payee = bytes32(body["payee"], "payee")
    if payer == bytes(32):
        raise _action_error("payer", "must be non-zero")
    if payee == bytes(32):
        raise _action_error("payee", "must be non-zero")
    if payer == payee:
        raise _action_error("payee", "payer and payee must differ")
    if uint_value(body["value"], 256, "value") == 0:
        raise _action_error("value", "must be non-zero")
    for field in (
        "resource_url_hash",
        "report_hash",
        "payment_requirements_hash",
        "signed_payment_payload_hash",
        "eip712_auth_nonce",
    ):
        if bytes32(body[field], field) == bytes(32):
            raise _action_error(field, "must be non-zero")
    valid_after = uint_value(body["valid_after"], 64, "valid_after")
    valid_before = uint_value(body["valid_before"], 64, "valid_before")
    if valid_before <= valid_after:
        raise _action_error("valid_before", "must be greater than valid_after")
    if uint_value(header["decision_code"], 8, "decision_code") != 1:
        raise EnvelopeEncodingError("InvalidEnvelopeField", "decision_code", "x402 requires APPROVED")
    if any(
        uint_value(header[field], 32, field) != 0
        for field in ("requested_allocation_bps", "approved_allocation_bps")
    ):
        raise EnvelopeEncodingError("InvalidEnvelopeField", "requested_allocation_bps", "x402 bps must be zero")


def derive_x402_material(
    header: Mapping[str, Any],
    body: Mapping[str, Any],
) -> EncodedEnvelope:
    """Validate and recompute OfficialX402SettlementV1 identifiers and bytes."""

    _validate_body_scalars(body, X402_SCHEMA)
    # Window validation precedes header loading per the frozen validation order.
    valid_after = uint_value(body["valid_after"], 64, "valid_after")
    valid_before = uint_value(body["valid_before"], 64, "valid_before")
    if valid_before <= valid_after:
        raise _action_error("valid_before", "must be greater than valid_after")
    core = _encode_projection(body, X402_CORE_SCHEMA)
    computed_action_id = _derive_action_id(2, body["action_nonce"], core)
    header_bytes = _require_header_action(
        header,
        action_kind=2,
        action_id=computed_action_id,
    )
    _validate_x402_semantics(header, body)
    body_bytes = encode_fields(body, X402_SCHEMA)
    envelope_hash = blake2b256(ENVELOPE_DOMAIN_SEPARATOR + header_bytes + body_bytes)
    return EncodedEnvelope(
        header_bytes=header_bytes,
        body_bytes=body_bytes,
        action_core_bytes=core,
        action_id=computed_action_id,
        transfer_id=None,
        envelope_hash=envelope_hash,
    )
