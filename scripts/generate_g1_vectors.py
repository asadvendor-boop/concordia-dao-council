#!/usr/bin/env python3
"""Generate the deterministic Concordia G1 cross-language golden vectors.

The generator is intentionally dependency-free.  It is the executable form of
the G1 scalar and manifest encodings so the Rust, Python and JavaScript
implementations can consume the same byte-for-byte fixtures.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
VECTOR_ROOT = REPO_ROOT / "tests" / "golden" / "envelope_v3"

ACTION_ID_DOMAIN = b"CONCORDIA_ACTION_ID_V3\0"
TRANSFER_ID_DOMAIN = b"CONCORDIA_TRANSFER_ID_V3\0"
ENVELOPE_DOMAIN = b"CONCORDIA_GOVERNANCE_ENVELOPE_V3\0"
DEPLOYMENT_DOMAIN = b"CONCORDIA_DOMAIN_V3\0"
RESOURCE_URL_DOMAIN = b"CONCORDIA_RESOURCE_URL_V1\0"
EVIDENCE_DOMAIN = b"CONCORDIA_PREAUTH_EVIDENCE_V1\0"
METADATA_DOMAIN = b"CONCORDIA_AUTHORIZED_METADATA_V1\0"
EXEC_ARGS_DOMAIN = b"CONCORDIA_EXEC_ARGS_V1\0"
PAYMENT_REQUIREMENTS_DOMAIN = b"CONCORDIA_PAYMENT_REQUIREMENTS_V1\0"
SIGNED_PAYMENT_PAYLOAD_DOMAIN = b"CONCORDIA_SIGNED_PAYMENT_PAYLOAD_V1\0"
X402_REPORT_DOMAIN = b"CONCORDIA_X402_REPORT_V1\0"

X402_RESOURCE_URL = "https://x402.concordiadao.xyz/reports/DAO-PROP-V3-X402"
X402_RESOURCE_DESCRIPTION = "Concordia governed specialist risk report"
X402_RESOURCE_MIME_TYPE = "application/json"
X402_REPORT_BYTES = b'{"risk_level":"medium-after-policy-cap"}'
X402_SIGNATURE_HEX = "01" + ("ab" * 64)
X402_PUBLIC_KEY = {"algorithm": "Ed25519", "value": "51" * 32}

TYPE_TAGS = {
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

HEADER_TYPES = (
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

NATIVE_TYPES = (
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
NATIVE_CORE_NAMES = (
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

# G1.2 freezes the live EIP-712 identity fields explicitly.  The body contains
# 22 fields; the action core excludes only the explicit action nonce.
X402_TYPES = (
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
X402_CORE_NAMES = tuple(name for name, _ in X402_TYPES if name != "action_nonce")

PROPOSAL_ID_RE = re.compile(r"^[A-Z0-9-]{1,64}$")
MACHINE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def blake(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def uint(value: Any, bits: int) -> int:
    result = int(value)
    if result < 0 or result >= 1 << bits:
        raise ValueError(f"integer outside u{bits} range")
    return result


def fixed_uint(value: Any, bits: int) -> bytes:
    return uint(value, bits).to_bytes(bits // 8, "big")


def hex32(value: str) -> bytes:
    raw = bytes.fromhex(value)
    if len(raw) != 32:
        raise ValueError("expected exactly 32 bytes")
    return raw


def ascii_bytes(value: str) -> bytes:
    if "\0" in value:
        raise ValueError("embedded NUL is forbidden")
    try:
        return value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("non-ASCII string") from exc


def lp(value: str | bytes) -> bytes:
    raw = ascii_bytes(value) if isinstance(value, str) else value
    return fixed_uint(len(raw), 32) + raw


def canonical_value(type_name: str, value: Any) -> bytes:
    if type_name == "bool":
        if value is True:
            return b"\x01"
        if value is False:
            return b"\x00"
        raise ValueError("bool must be a JSON boolean")
    if type_name in {"u8", "u32", "u64"}:
        return fixed_uint(value, int(type_name[1:]))
    if type_name == "U256":
        return fixed_uint(value, 256)
    if type_name == "U512":
        return fixed_uint(value, 512)
    if type_name in {"Bytes32", "AccountHash"}:
        return hex32(value)
    if type_name == "String":
        return lp(value)
    if type_name == "Bytes":
        return lp(bytes.fromhex(value))
    if type_name == "Key":
        variant = {"Account": 0, "Hash": 1}.get(value["variant"])
        if variant is None:
            raise ValueError("unsupported Key variant")
        return bytes([variant]) + hex32(value["value"])
    if type_name == "List<Key>":
        keys = [canonical_value("Key", item) for item in value]
        return fixed_uint(len(keys), 32) + b"".join(keys)
    if type_name == "PublicKey":
        algorithm = value["algorithm"]
        raw = bytes.fromhex(value["value"])
        if algorithm == "Ed25519":
            if len(raw) != 32:
                raise ValueError("Ed25519 public key must contain exactly 32 bytes")
            return b"\x01" + raw
        if algorithm == "Secp256k1":
            if len(raw) != 33 or raw[0] not in (2, 3):
                raise ValueError("Secp256k1 public key must be a 33-byte compressed point")
            return b"\x02" + raw
        raise ValueError("unsupported PublicKey algorithm")
    if type_name == "Option<u64>":
        variant = value["variant"]
        if variant == "None":
            if value.get("value") is not None:
                raise ValueError("None Option<u64> cannot carry a value")
            return b"\x00"
        if variant == "Some":
            return b"\x01" + fixed_uint(value["value"], 64)
        raise ValueError("unsupported Option<u64> variant")
    raise ValueError(f"unknown type: {type_name}")


def encode_fields(values: dict[str, Any], schema: Sequence[tuple[str, str]]) -> bytes:
    return b"".join(canonical_value(type_name, values[name]) for name, type_name in schema)


def typed_fields(values: dict[str, Any], schema: Sequence[tuple[str, str]]) -> list[dict[str, Any]]:
    return [
        {"name": name, "type": type_name, "value": values[name]}
        for name, type_name in schema
    ]


def pattern(byte: int) -> str:
    return f"{byte:02x}" * 32


def deployment_domain(installation_nonce: str = pattern(0xA5)) -> str:
    return blake(
        DEPLOYMENT_DOMAIN
        + lp("casper-test")
        + lp("concordia_governance_receipt_v3")
        + hex32(installation_nonce)
    ).hex()


def deployment_domain_preimage(installation_nonce: str = pattern(0xA5)) -> bytes:
    return (
        DEPLOYMENT_DOMAIN
        + lp("casper-test")
        + lp("concordia_governance_receipt_v3")
        + hex32(installation_nonce)
    )


def default_header(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "schema_version": "3",
        "deployment_domain": deployment_domain(),
        "casper_chain_name": "casper-test",
        "proposal_id": "DAO-PROP-V3-001",
        "proposal_nonce": pattern(0x10),
        "decision_code": "2",
        "requested_allocation_bps": "3000",
        "approved_allocation_bps": "800",
        "action_kind": "1",
        "action_version": "1",
        "action_id": pattern(0x20),
        "proposal_hash": pattern(0x31),
        "policy_hash": pattern(0x32),
        "plan_hash": pattern(0x33),
        "final_card_hash": pattern(0x34),
        "dissent_hash": pattern(0x35),
        "agent_action_hash": pattern(0x36),
        "preauth_evidence_root": pattern(0x37),
        "authorized_metadata_root": pattern(0x38),
    }
    values.update(overrides)
    return values


def default_native(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "asset_kind": "0",
        "source_account": pattern(0x41),
        "recipient_account": pattern(0x42),
        "amount_motes": "50000000000",
        "treasury_snapshot_balance_motes": "625000000000",
        "snapshot_block_hash": pattern(0x43),
        "snapshot_block_height": "8590556",
        "transfer_id": "0",
        "action_nonce": pattern(0x44),
        "execution_target": "native-transfer",
        "execution_version": "1",
    }
    values.update(overrides)
    return values


def resource_hash(url: str) -> str:
    return blake(RESOURCE_URL_DOMAIN + lp(url)).hex()


def account_hash_for_public_key(public_key: dict[str, str]) -> str:
    """Match casper_types::AccountHash::from_public_key exactly."""
    algorithm = public_key["algorithm"]
    algorithm_name = {"Ed25519": b"ed25519", "Secp256k1": b"secp256k1"}.get(algorithm)
    if algorithm_name is None:
        raise ValueError("unsupported PublicKey algorithm")
    raw_key = bytes.fromhex(public_key["value"])
    canonical_value("PublicKey", public_key)  # validates key length/form first
    return blake(algorithm_name + b"\0" + raw_key).hex()


def payment_requirements_preimage(values: dict[str, Any], *, max_timeout_seconds: int = 300) -> bytes:
    return (
        PAYMENT_REQUIREMENTS_DOMAIN
        + lp(values["scheme"])
        + lp(values["caip2_network"])
        + hex32(values["wcspr_package"])
        + fixed_uint(values["value"], 256)
        + hex32(values["payee"])
        + fixed_uint(max_timeout_seconds, 32)
        + lp(values["token_name"])
        + lp(values["eip712_domain_version"])
        + fixed_uint(values["token_decimals"], 8)
        + lp(values["token_symbol"])
    )


def payment_requirements_hash(values: dict[str, Any], *, max_timeout_seconds: int = 300) -> str:
    return blake(payment_requirements_preimage(values, max_timeout_seconds=max_timeout_seconds)).hex()


def signed_payment_payload_preimage(values: dict[str, Any]) -> bytes:
    return (
        SIGNED_PAYMENT_PAYLOAD_DOMAIN
        + fixed_uint(values["x402_version"], 32)
        + lp(X402_RESOURCE_URL)
        + lp(X402_RESOURCE_DESCRIPTION)
        + lp(X402_RESOURCE_MIME_TYPE)
        + hex32(values["payment_requirements_hash"])
        + lp(bytes.fromhex(X402_SIGNATURE_HEX))
        + canonical_value("PublicKey", X402_PUBLIC_KEY)
        + hex32(values["payer"])
        + hex32(values["payee"])
        + fixed_uint(values["value"], 256)
        + fixed_uint(values["valid_after"], 64)
        + fixed_uint(values["valid_before"], 64)
        + hex32(values["eip712_auth_nonce"])
        + fixed_uint(0, 32)
    )


def signed_payment_payload_hash(values: dict[str, Any]) -> str:
    return blake(signed_payment_payload_preimage(values)).hex()


def default_x402(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "x402_version": "2",
        "scheme": "exact",
        "caip2_network": "casper:casper-test",
        "wcspr_package": "3d80df21ba4ee4d66a2a1f60c32570dd5685e4b279f6538162a5fd1314847c1e",
        "wcspr_contract": "032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a",
        "token_name": "Wrapped CSPR",
        "token_symbol": "WCSPR",
        "eip712_domain_version": "1",
        "token_decimals": "9",
        "payer": account_hash_for_public_key(X402_PUBLIC_KEY),
        "payee": pattern(0x52),
        "value": "25000000000",
        "resource_url_hash": resource_hash(X402_RESOURCE_URL),
        "report_hash": blake(X402_REPORT_DOMAIN + lp(X402_REPORT_BYTES)).hex(),
        "eip712_auth_nonce": pattern(0x56),
        "valid_after": "1784750400",
        "valid_before": "1784754000",
        "action_nonce": pattern(0x57),
        "settlement_target": "cspr-cloud-facilitator",
        "settlement_version": "1",
    }
    values.update(overrides)
    if "payment_requirements_hash" not in overrides:
        values["payment_requirements_hash"] = payment_requirements_hash(values)
    if "signed_payment_payload_hash" not in overrides:
        values["signed_payment_payload_hash"] = signed_payment_payload_hash(values)
    return values


def x402_binding_projection(values: dict[str, Any]) -> dict[str, Any]:
    resource_preimage = RESOURCE_URL_DOMAIN + lp(X402_RESOURCE_URL)
    report_preimage = X402_REPORT_DOMAIN + lp(X402_REPORT_BYTES)
    requirements_preimage = payment_requirements_preimage(values)
    payload_preimage = signed_payment_payload_preimage(values)
    payment_requirements = {
        "scheme": values["scheme"],
        "network": values["caip2_network"],
        "asset": values["wcspr_package"],
        "amount": values["value"],
        "payTo": "00" + values["payee"],
        "maxTimeoutSeconds": 300,
        "extra": {
            "name": values["token_name"],
            "version": values["eip712_domain_version"],
            "decimals": values["token_decimals"],
            "symbol": values["token_symbol"],
        },
    }
    return {
        "validation_scope": "typed_contract_encoding_and_subordinate_hashes_only",
        "facilitator_signature_validity": "not_asserted_by_this_dependency_free_vector; WP5 must verify a real deterministic EIP-712 fixture with the pinned SDK",
        "resource": {
            "url": X402_RESOURCE_URL,
            "description": X402_RESOURCE_DESCRIPTION,
            "mimeType": X402_RESOURCE_MIME_TYPE,
        },
        "payment_requirements": payment_requirements,
        "payment_payload": {
            "x402Version": int(values["x402_version"]),
            "resource": {
                "url": X402_RESOURCE_URL,
                "description": X402_RESOURCE_DESCRIPTION,
                "mimeType": X402_RESOURCE_MIME_TYPE,
            },
            "accepted": copy.deepcopy(payment_requirements),
            "payload": {
                "signature": X402_SIGNATURE_HEX,
                "publicKey": canonical_value("PublicKey", X402_PUBLIC_KEY).hex(),
                "authorization": {
                    "from": "00" + values["payer"],
                    "to": "00" + values["payee"],
                    "value": values["value"],
                    "validAfter": values["valid_after"],
                    "validBefore": values["valid_before"],
                    "nonce": values["eip712_auth_nonce"],
                },
            },
            "extensions": {},
        },
        "report": {
            "media_type": "application/json",
            "exact_bytes_hex": X402_REPORT_BYTES.hex(),
            "exact_bytes_utf8": X402_REPORT_BYTES.decode("ascii"),
        },
        "public_key_account_binding": {
            "canonical_public_key_hex": canonical_value("PublicKey", X402_PUBLIC_KEY).hex(),
            "account_hash_preimage_hex": (
                b"ed25519" + b"\0" + bytes.fromhex(X402_PUBLIC_KEY["value"])
            ).hex(),
            "derivation": "BLAKE2b-256(algorithm_name_ascii || 0x00 || raw_public_key_bytes_without_tag)",
            "derived_account_hash": account_hash_for_public_key(X402_PUBLIC_KEY),
            "equals_typed_payer": account_hash_for_public_key(X402_PUBLIC_KEY) == values["payer"],
        },
        "preimages": {
            "resource_url_hash": resource_preimage.hex(),
            "report_hash": report_preimage.hex(),
            "payment_requirements_hash": requirements_preimage.hex(),
            "signed_payment_payload_hash": payload_preimage.hex(),
        },
        "hashes": {
            "resource_url_hash": blake(resource_preimage).hex(),
            "report_hash": blake(report_preimage).hex(),
            "payment_requirements_hash": blake(requirements_preimage).hex(),
            "signed_payment_payload_hash": blake(payload_preimage).hex(),
        },
    }


def action_id(action_kind: int, nonce_hex: str, core: bytes) -> str:
    return blake(ACTION_ID_DOMAIN + bytes([action_kind]) + hex32(nonce_hex) + core).hex()


def native_material(
    *,
    proposal_id: str = "DAO-PROP-V3-001",
    proposal_nonce: str = pattern(0x10),
    body_overrides: dict[str, Any] | None = None,
    header_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = default_native(**(body_overrides or {}))
    core_schema = tuple(item for item in NATIVE_TYPES if item[0] in NATIVE_CORE_NAMES)
    core = encode_fields(body, core_schema)
    computed_action_id = action_id(1, body["action_nonce"], core)
    transfer_digest = blake(
        TRANSFER_ID_DOMAIN + lp(proposal_id) + hex32(proposal_nonce) + hex32(computed_action_id)
    )
    computed_transfer_id = int.from_bytes(transfer_digest[:8], "big")
    body["transfer_id"] = str(computed_transfer_id)
    header = default_header(
        proposal_id=proposal_id,
        proposal_nonce=proposal_nonce,
        action_kind="1",
        action_id=computed_action_id,
        **(header_overrides or {}),
    )
    header_bytes = encode_fields(header, HEADER_TYPES)
    body_bytes = encode_fields(body, NATIVE_TYPES)
    envelope_preimage = ENVELOPE_DOMAIN + header_bytes + body_bytes
    return {
        "header": header,
        "body": body,
        "header_bytes": header_bytes,
        "body_bytes": body_bytes,
        "core_bytes": core,
        "action_id": computed_action_id,
        "transfer_id": str(computed_transfer_id),
        "transfer_digest": transfer_digest.hex(),
        "envelope_preimage": envelope_preimage,
        "envelope_hash": blake(envelope_preimage).hex(),
    }


def x402_material(
    *,
    proposal_id: str = "DAO-PROP-V3-X402",
    proposal_nonce: str = pattern(0x60),
    body_overrides: dict[str, Any] | None = None,
    header_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = default_x402(**(body_overrides or {}))
    core_schema = tuple(item for item in X402_TYPES if item[0] in X402_CORE_NAMES)
    core = encode_fields(body, core_schema)
    computed_action_id = action_id(2, body["action_nonce"], core)
    header = default_header(
        proposal_id=proposal_id,
        proposal_nonce=proposal_nonce,
        action_kind="2",
        action_id=computed_action_id,
        requested_allocation_bps="0",
        approved_allocation_bps="0",
        decision_code="1",
        **(header_overrides or {}),
    )
    header_bytes = encode_fields(header, HEADER_TYPES)
    body_bytes = encode_fields(body, X402_TYPES)
    envelope_preimage = ENVELOPE_DOMAIN + header_bytes + body_bytes
    return {
        "header": header,
        "body": body,
        "header_bytes": header_bytes,
        "body_bytes": body_bytes,
        "core_bytes": core,
        "action_id": computed_action_id,
        "envelope_preimage": envelope_preimage,
        "envelope_hash": blake(envelope_preimage).hex(),
    }


def valid_vector(
    vector_id: str,
    kind: str,
    description: str,
    typed_input: Any,
    canonical: bytes,
    hashes: dict[str, Any],
    **extra: Any,
) -> dict[str, Any]:
    result = {
        "vector_id": vector_id,
        "kind": kind,
        "description": description,
        "valid": True,
        "typed_input": typed_input,
        "canonical_hex": canonical.hex(),
        "canonical_length": len(canonical),
        "hashes": hashes,
        "expected_error": None,
    }
    result.update(extra)
    return result


def invalid_vector(
    vector_id: str,
    kind: str,
    description: str,
    typed_input: Any,
    error_name: str,
    error_code: int | None = None,
    **extra: Any,
) -> dict[str, Any]:
    result = {
        "vector_id": vector_id,
        "kind": kind,
        "description": description,
        "valid": False,
        "typed_input": typed_input,
        "canonical_hex": None,
        "canonical_length": None,
        "hashes": {},
        "expected_error": {"name": error_name, "code": error_code},
    }
    result.update(extra)
    return result


def header_vectors() -> dict[str, dict[str, Any]]:
    vectors: dict[str, dict[str, Any]] = {}
    cases = [
        (
            "GV-HDR-01",
            "Baseline 30 percent request limited to 8 percent for NativeTransferV1.",
            default_header(),
        ),
        (
            "GV-HDR-02",
            "Official x402 approved header with zero allocation fields.",
            default_header(
                proposal_id="DAO-PROP-V3-X402",
                proposal_nonce=pattern(0x60),
                decision_code="1",
                requested_allocation_bps="0",
                approved_allocation_bps="0",
                action_kind="2",
                action_id=pattern(0x61),
            ),
        ),
        (
            "GV-HDR-03",
            "Maximum proposal-id and allocation boundaries remain canonical for an approved native action.",
            default_header(
                proposal_id="A" * 64,
                proposal_nonce=pattern(0xFF),
                decision_code="1",
                requested_allocation_bps="10000",
                approved_allocation_bps="10000",
            ),
        ),
    ]
    for vector_id, description, values in cases:
        encoded = encode_fields(values, HEADER_TYPES)
        extra: dict[str, Any] = {"field_order": [name for name, _ in HEADER_TYPES]}
        if vector_id == "GV-HDR-01":
            installation_nonce = pattern(0xA5)
            domain_preimage = deployment_domain_preimage(installation_nonce)
            extra["deployment_domain_derivation"] = {
                "chain_name": "casper-test",
                "package_key_name": "concordia_governance_receipt_v3",
                "installation_nonce": installation_nonce,
                "preimage_hex": domain_preimage.hex(),
                "blake2b256": blake(domain_preimage).hex(),
            }
        vectors[f"header/{vector_id}.json"] = valid_vector(
            vector_id,
            "envelope_header_v3",
            description,
            {"fields": typed_fields(values, HEADER_TYPES)},
            encoded,
            {"canonical_blake2b256": blake(encoded).hex()},
            **extra,
        )

    invalid_id = default_header(proposal_id="dao-prop-lowercase")
    vectors["header/GV-HDR-04.json"] = invalid_vector(
        "GV-HDR-04",
        "envelope_header_v3",
        "Lowercase proposal IDs are rejected before encoding.",
        {"fields": typed_fields(invalid_id, HEADER_TYPES)},
        "InvalidProposalId",
        14,
        failed_field="proposal_id",
    )
    invalid_bps = default_header(requested_allocation_bps="10001")
    vectors["header/GV-HDR-05.json"] = invalid_vector(
        "GV-HDR-05",
        "envelope_header_v3",
        "Basis points above 10000 are rejected before encoding.",
        {"fields": typed_fields(invalid_bps, HEADER_TYPES)},
        "InvalidEnvelopeField",
        15,
        failed_field="requested_allocation_bps",
    )
    return vectors


def material_input(material: dict[str, Any], body_schema: Sequence[tuple[str, str]]) -> dict[str, Any]:
    return {
        "header": typed_fields(material["header"], HEADER_TYPES),
        "body": typed_fields(material["body"], body_schema),
    }


def native_projection(material: dict[str, Any]) -> dict[str, Any]:
    return {
        "proposal_id": material["header"]["proposal_id"],
        "proposal_nonce": material["header"]["proposal_nonce"],
        "action_nonce": material["body"]["action_nonce"],
        "action_core_hex": material["core_bytes"].hex(),
        "action_id": material["action_id"],
        "transfer_id": material["transfer_id"],
        "transfer_digest": material["transfer_digest"],
        "envelope_hash": material["envelope_hash"],
    }


def native_vectors() -> dict[str, dict[str, Any]]:
    vectors: dict[str, dict[str, Any]] = {}
    base = native_material()
    vectors["native_transfer/GV-NT-01.json"] = valid_vector(
        "GV-NT-01",
        "native_transfer_v1",
        "Baseline exact native transfer authorization.",
        material_input(base, NATIVE_TYPES),
        base["body_bytes"],
        {
            "action_core_blake2b256": blake(base["core_bytes"]).hex(),
            "action_id": base["action_id"],
            "transfer_derivation_blake2b256": base["transfer_digest"],
            "envelope_hash": base["envelope_hash"],
        },
        action_core_hex=base["core_bytes"].hex(),
        header_canonical_hex=base["header_bytes"].hex(),
        envelope_preimage_hex=base["envelope_preimage"].hex(),
    )

    largest_non_overflowing_snapshot = ((1 << 512) - 1) // 800
    boundary_amount = largest_non_overflowing_snapshot * 800 // 10000
    boundary = native_material(
        proposal_id="NATIVE-BOUNDARY",
        proposal_nonce=pattern(0x7E),
        body_overrides={
            "amount_motes": str(boundary_amount),
            "treasury_snapshot_balance_motes": str(largest_non_overflowing_snapshot),
            "snapshot_block_height": str((1 << 64) - 1),
            "action_nonce": pattern(0x7F),
        },
    )
    vectors["native_transfer/GV-NT-02.json"] = valid_vector(
        "GV-NT-02",
        "native_transfer_v1",
        "Largest snapshot whose checked multiplication by 800 does not overflow U512 remains contract-valid.",
        material_input(boundary, NATIVE_TYPES),
        boundary["body_bytes"],
        {"action_id": boundary["action_id"], "envelope_hash": boundary["envelope_hash"]},
        action_core_hex=boundary["core_bytes"].hex(),
        exact_cap_calculation={
            "approved_allocation_bps": "800",
            "formula": "floor(treasury_snapshot_balance_motes * approved_allocation_bps / 10000)",
            "expected_amount_motes": str(boundary_amount),
            "matches_body": boundary["body"]["amount_motes"] == str(boundary_amount),
            "checked_product_fits_u512": largest_non_overflowing_snapshot * 800 < (1 << 512),
        },
        largest_non_overflowing_snapshot_decimal=str(largest_non_overflowing_snapshot),
        u64_max_hex=f"{(1 << 64) - 1:016x}",
    )

    changed = native_material(body_overrides={"recipient_account": pattern(0x49)})
    vectors["native_transfer/GV-NT-03.json"] = valid_vector(
        "GV-NT-03",
        "native_transfer_v1_relationship",
        "Changing one semantic recipient byte changes action_id and envelope hash while preserving financial invariants.",
        material_input(changed, NATIVE_TYPES),
        changed["body_bytes"],
        {"action_id": changed["action_id"], "envelope_hash": changed["envelope_hash"]},
        comparison={
            "baseline": native_projection(base),
            "changed": native_projection(changed),
            "assertions": {
                "action_id_differs": changed["action_id"] != base["action_id"],
                "transfer_id_differs": changed["transfer_id"] != base["transfer_id"],
                "envelope_hash_differs": changed["envelope_hash"] != base["envelope_hash"],
            },
        },
    )

    other_proposal = native_material(
        proposal_id="DAO-PROP-V3-002",
        proposal_nonce=pattern(0x11),
    )
    vectors["native_transfer/GV-NT-04.json"] = valid_vector(
        "GV-NT-04",
        "native_transfer_v1_relationship",
        "The same semantic action and nonce under another proposal keeps action_id but changes transfer_id.",
        {
            "cases": [
                material_input(base, NATIVE_TYPES),
                material_input(other_proposal, NATIVE_TYPES),
            ]
        },
        other_proposal["body_bytes"],
        {"case_a_envelope_hash": base["envelope_hash"], "case_b_envelope_hash": other_proposal["envelope_hash"]},
        comparison={
            "case_a": native_projection(base),
            "case_b": native_projection(other_proposal),
            "assertions": {
                "action_id_equal": base["action_id"] == other_proposal["action_id"],
                "transfer_id_differs": base["transfer_id"] != other_proposal["transfer_id"],
                "envelope_hash_differs": base["envelope_hash"] != other_proposal["envelope_hash"],
            },
        },
    )

    new_nonce = native_material(body_overrides={"action_nonce": pattern(0x45)})
    vectors["native_transfer/GV-NT-05.json"] = valid_vector(
        "GV-NT-05",
        "native_transfer_v1_relationship",
        "A fresh action nonce authorizes a new action_id for otherwise identical semantics.",
        {
            "cases": [
                material_input(base, NATIVE_TYPES),
                material_input(new_nonce, NATIVE_TYPES),
            ]
        },
        new_nonce["body_bytes"],
        {"case_a_envelope_hash": base["envelope_hash"], "case_b_envelope_hash": new_nonce["envelope_hash"]},
        comparison={
            "case_a": native_projection(base),
            "case_b": native_projection(new_nonce),
            "assertions": {
                "action_id_differs": base["action_id"] != new_nonce["action_id"],
                "transfer_id_differs": base["transfer_id"] != new_nonce["transfer_id"],
            },
        },
    )
    return vectors


def x402_vectors() -> dict[str, dict[str, Any]]:
    vectors: dict[str, dict[str, Any]] = {}
    base = x402_material()
    vectors["x402_settlement/GV-X4-01.json"] = valid_vector(
        "GV-X4-01",
        "official_x402_settlement_v1",
        "Baseline WCSPR envelope with live Testnet contract parameters and deterministic encoding identities.",
        material_input(base, X402_TYPES),
        base["body_bytes"],
        {"action_id": base["action_id"], "envelope_hash": base["envelope_hash"]},
        action_core_hex=base["core_bytes"].hex(),
        header_canonical_hex=base["header_bytes"].hex(),
        envelope_preimage_hex=base["envelope_preimage"].hex(),
        body_field_order=[name for name, _ in X402_TYPES],
        action_core_field_order=list(X402_CORE_NAMES),
        x402_binding_projection=x402_binding_projection(base["body"]),
        contract_encoding_valid=True,
        live_or_facilitator_success_claimed=False,
    )

    changed = x402_material(body_overrides={"payer": pattern(0x59)})
    vectors["x402_settlement/GV-X4-02.json"] = valid_vector(
        "GV-X4-02",
        "official_x402_settlement_v1_relationship",
        "Changing the exact payer and recomputing its payload hash changes action_id and envelope hash.",
        material_input(changed, X402_TYPES),
        changed["body_bytes"],
        {"action_id": changed["action_id"], "envelope_hash": changed["envelope_hash"]},
        comparison={
            "baseline_action_id": base["action_id"],
            "changed_action_id": changed["action_id"],
            "action_id_differs": base["action_id"] != changed["action_id"],
            "envelope_hash_differs": base["envelope_hash"] != changed["envelope_hash"],
        },
    )

    invalid = default_x402(valid_after="1784754000", valid_before="1784754000")
    vectors["x402_settlement/GV-X4-03.json"] = invalid_vector(
        "GV-X4-03",
        "official_x402_settlement_v1",
        "valid_before must be strictly greater than valid_after.",
        {"body": typed_fields(invalid, X402_TYPES)},
        "InvalidActionField",
        16,
        failed_fields=["valid_after", "valid_before"],
    )

    maximum = x402_material(
        proposal_id="X402-U256-MAX",
        body_overrides={"value": str((1 << 256) - 1), "action_nonce": pattern(0x58)},
    )
    vectors["x402_settlement/GV-X4-04.json"] = valid_vector(
        "GV-X4-04",
        "official_x402_settlement_v1",
        "U256 is always fixed 32-byte big-endian at zero, one, and maximum.",
        material_input(maximum, X402_TYPES),
        maximum["body_bytes"],
        {"action_id": maximum["action_id"], "envelope_hash": maximum["envelope_hash"]},
        action_core_hex=maximum["core_bytes"].hex(),
        u256_cases=[
            {"decimal": "0", "canonical_hex": fixed_uint(0, 256).hex(), "scalar_encoding_only": True, "valid_settlement_value": False},
            {"decimal": "1", "canonical_hex": fixed_uint(1, 256).hex()},
            {"decimal": str((1 << 256) - 1), "canonical_hex": fixed_uint((1 << 256) - 1, 256).hex()},
        ],
    )
    return vectors


EVIDENCE_SCHEMA = (
    ("artifact_id", "String"),
    ("artifact_kind", "u8"),
    ("content_sha256", "Bytes32"),
    ("byte_length", "u64"),
    ("media_type", "String"),
    ("provenance_class", "u8"),
    ("captured_at_unix_seconds", "u64"),
)


def encode_evidence(entries: Sequence[dict[str, Any]]) -> tuple[bytes, list[dict[str, Any]]]:
    ordered = sorted(entries, key=lambda item: ascii_bytes(item["artifact_id"]))
    if len({entry["artifact_id"] for entry in ordered}) != len(ordered):
        raise ValueError("DuplicateArtifactId")
    for entry in ordered:
        if not MACHINE_NAME_RE.fullmatch(entry["artifact_id"]):
            raise ValueError("InvalidArtifactId")
    encoded = fixed_uint(1, 32) + fixed_uint(len(ordered), 32)
    encoded += b"".join(encode_fields(entry, EVIDENCE_SCHEMA) for entry in ordered)
    return encoded, ordered


def evidence_vectors() -> dict[str, dict[str, Any]]:
    proposal_content = b'{"proposal":"DAO-PROP-V3-001"}\n'
    policy_content = b'{"approved_allocation_bps":800}\n'
    entries = [
        {
            "artifact_id": "policy_evaluation",
            "artifact_kind": "2",
            "content_sha256": sha256(policy_content).hex(),
            "byte_length": str(len(policy_content)),
            "media_type": "application/json",
            "provenance_class": "1",
            "captured_at_unix_seconds": "1784745601",
        },
        {
            "artifact_id": "proposal",
            "artifact_kind": "1",
            "content_sha256": sha256(proposal_content).hex(),
            "byte_length": str(len(proposal_content)),
            "media_type": "application/json",
            "provenance_class": "1",
            "captured_at_unix_seconds": "1784745600",
        },
    ]
    encoded, ordered = encode_evidence(entries)
    valid = valid_vector(
        "GV-EM-01",
        "preauthorization_evidence_manifest_v1",
        "Input entries are canonicalized by ascending raw ASCII artifact_id.",
        {
            "version": {"type": "u32", "value": "1"},
            "entries_in_input_order": [typed_fields(entry, EVIDENCE_SCHEMA) for entry in entries],
        },
        encoded,
        {"preauth_evidence_root": blake(EVIDENCE_DOMAIN + encoded).hex()},
        canonical_entry_order=[entry["artifact_id"] for entry in ordered],
        root_preimage_hex=(EVIDENCE_DOMAIN + encoded).hex(),
    )
    duplicate = [entries[0], dict(entries[0])]
    invalid = invalid_vector(
        "GV-EM-02",
        "preauthorization_evidence_manifest_v1",
        "Duplicate artifact IDs are rejected rather than collapsed.",
        {
            "version": {"type": "u32", "value": "1"},
            "entries_in_input_order": [typed_fields(entry, EVIDENCE_SCHEMA) for entry in duplicate],
        },
        "DuplicateArtifactId",
        None,
    )
    return {
        "evidence_manifest/GV-EM-01.json": valid,
        "evidence_manifest/GV-EM-02.json": invalid,
    }


def encode_ancillary(entries: Sequence[dict[str, Any]], *, sort_entries: bool) -> tuple[bytes, list[dict[str, Any]]]:
    ordered = sorted(entries, key=lambda item: ascii_bytes(item["name"])) if sort_entries else list(entries)
    names = [entry["name"] for entry in ordered]
    if len(set(names)) != len(names):
        raise ValueError("DuplicateArgumentName")
    for name in names:
        if not MACHINE_NAME_RE.fullmatch(name):
            raise ValueError("InvalidArgumentName")
    encoded_entries = []
    for entry in ordered:
        type_name = entry["type"]
        encoded_entries.append(
            lp(entry["name"]) + bytes([TYPE_TAGS[type_name]]) + canonical_value(type_name, entry["value"])
        )
    return fixed_uint(len(ordered), 32) + b"".join(encoded_entries), ordered


def metadata_vectors() -> dict[str, dict[str, Any]]:
    entries = [
        {"name": "z_note", "type": "String", "value": "Judge-visible context"},
        {"name": "attempt", "type": "u32", "value": "1"},
        {"name": "verified", "type": "bool", "value": True},
        {"name": "receipt_hash", "type": "Bytes32", "value": pattern(0x81)},
    ]
    ancillary, ordered = encode_ancillary(entries, sort_entries=True)
    encoded = fixed_uint(1, 32) + ancillary
    valid = valid_vector(
        "GV-MM-01",
        "authorized_metadata_manifest_v1",
        "Metadata entries are sorted by raw ASCII name and preserve explicit type tags.",
        {"version": {"type": "u32", "value": "1"}, "entries_in_input_order": entries},
        encoded,
        {"authorized_metadata_root": blake(METADATA_DOMAIN + encoded).hex()},
        canonical_entry_order=[entry["name"] for entry in ordered],
        root_preimage_hex=(METADATA_DOMAIN + encoded).hex(),
    )
    duplicates = [
        {"name": "network", "type": "String", "value": "casper-test"},
        {"name": "network", "type": "String", "value": "casper:casper-test"},
    ]
    invalid = invalid_vector(
        "GV-MM-02",
        "authorized_metadata_manifest_v1",
        "Duplicate metadata names are rejected before canonicalization.",
        {"version": {"type": "u32", "value": "1"}, "entries_in_input_order": duplicates},
        "DuplicateArgumentName",
        None,
    )
    return {
        "metadata_manifest/GV-MM-01.json": valid,
        "metadata_manifest/GV-MM-02.json": invalid,
    }


def encode_exec(target: str, entry_point: str, args: Sequence[dict[str, Any]]) -> bytes:
    names = [item["name"] for item in args]
    if len(set(names)) != len(names):
        raise ValueError("DuplicateArgumentName")
    encoded_args = b"".join(
        lp(arg["name"])
        + bytes([TYPE_TAGS[arg["type"]]])
        + canonical_value(arg["type"], arg["value"])
        for arg in args
    )
    return fixed_uint(1, 32) + lp(target) + lp(entry_point) + fixed_uint(len(args), 32) + encoded_args


def exec_input(target: str, entry_point: str, args: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {
        "version": {"type": "u32", "value": "1"},
        "target": {"type": "String", "value": target},
        "entry_point": {"type": "String", "value": entry_point},
        "args_in_abi_order": list(args),
    }


def exec_vectors() -> dict[str, dict[str, Any]]:
    native_authorization = native_material()
    native_args = [
        {"name": "target", "type": "Key", "value": {"variant": "Account", "value": pattern(0x42)}},
        {"name": "amount", "type": "U512", "value": "50000000000"},
        {
            "name": "id",
            "type": "Option<u64>",
            "value": {"variant": "Some", "value": native_authorization["transfer_id"]},
        },
    ]
    native_encoded = encode_exec("native-transfer", "transfer", native_args)
    native = valid_vector(
        "GV-EA-01",
        "execution_argument_manifest_v1",
        "Native transfer arguments preserve target ABI order.",
        exec_input("native-transfer", "transfer", native_args),
        native_encoded,
        {"execution_argument_root": blake(EXEC_ARGS_DOMAIN + native_encoded).hex()},
        root_preimage_hex=(EXEC_ARGS_DOMAIN + native_encoded).hex(),
        related_authorization_vector="GV-NT-01",
        related_action_id=native_authorization["action_id"],
        related_transfer_id=native_authorization["transfer_id"],
    )

    x402_args = [
        {"name": "from", "type": "Key", "value": {"variant": "Account", "value": pattern(0x51)}},
        {"name": "to", "type": "Key", "value": {"variant": "Account", "value": pattern(0x52)}},
        {"name": "value", "type": "U256", "value": "25000000000"},
        {"name": "valid_after", "type": "u64", "value": "1784750400"},
        {"name": "valid_before", "type": "u64", "value": "1784754000"},
        {"name": "nonce", "type": "Bytes", "value": pattern(0x56)},
        {
            "name": "public_key",
            "type": "PublicKey",
            "value": {"algorithm": "Ed25519", "value": pattern(0x51)},
        },
        {"name": "signature", "type": "Bytes", "value": "01" + ("ab" * 64)},
    ]
    x402_encoded = encode_exec(
        "contract-032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a",
        "transfer_with_authorization",
        x402_args,
    )
    x402 = valid_vector(
        "GV-EA-02",
        "execution_argument_manifest_v1",
        "Live v8 WCSPR ABI uses value, never amount, and account-variant Keys.",
        exec_input(
            "contract-032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a",
            "transfer_with_authorization",
            x402_args,
        ),
        x402_encoded,
        {"execution_argument_root": blake(EXEC_ARGS_DOMAIN + x402_encoded).hex()},
        root_preimage_hex=(EXEC_ARGS_DOMAIN + x402_encoded).hex(),
        additional_scalar_coverage={
            "key_hash": {
                "typed_value": {"variant": "Hash", "value": pattern(0x61)},
                "canonical_hex": canonical_value("Key", {"variant": "Hash", "value": pattern(0x61)}).hex(),
            },
            "list_key": {
                "typed_value": [
                    {"variant": "Account", "value": pattern(0x62)},
                    {"variant": "Hash", "value": pattern(0x63)},
                ],
                "canonical_hex": canonical_value(
                    "List<Key>",
                    [
                        {"variant": "Account", "value": pattern(0x62)},
                        {"variant": "Hash", "value": pattern(0x63)},
                    ],
                ).hex(),
            },
            "public_key_secp256k1": {
                "typed_value": {"algorithm": "Secp256k1", "value": "02" + ("64" * 32)},
                "canonical_hex": canonical_value(
                    "PublicKey", {"algorithm": "Secp256k1", "value": "02" + ("64" * 32)}
                ).hex(),
            },
            "option_u64_none": {
                "typed_value": {"variant": "None", "value": None},
                "canonical_hex": canonical_value("Option<u64>", {"variant": "None", "value": None}).hex(),
            },
        },
    )

    wrong_order = [x402_args[1], x402_args[0], *x402_args[2:]]
    invalid = invalid_vector(
        "GV-EA-03",
        "execution_argument_manifest_v1",
        "Reordered WCSPR arguments are rejected even when names and values are otherwise valid.",
        exec_input(
            "contract-032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a",
            "transfer_with_authorization",
            wrong_order,
        ),
        "ExecutionArgumentOrderMismatch",
        None,
        expected_order=[item["name"] for item in x402_args],
        supplied_order=[item["name"] for item in wrong_order],
    )
    return {
        "exec_args/GV-EA-01.json": native,
        "exec_args/GV-EA-02.json": x402,
        "exec_args/GV-EA-03.json": invalid,
    }


def all_vectors() -> dict[str, dict[str, Any]]:
    vectors: dict[str, dict[str, Any]] = {}
    for group in (
        header_vectors(),
        native_vectors(),
        x402_vectors(),
        evidence_vectors(),
        metadata_vectors(),
        exec_vectors(),
    ):
        overlap = vectors.keys() & group.keys()
        if overlap:
            raise AssertionError(f"duplicate paths: {sorted(overlap)}")
        vectors.update(group)
    if len(vectors) != 21:
        raise AssertionError(f"expected 21 vectors, generated {len(vectors)}")
    return vectors


def json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")


def write_vectors(vectors: dict[str, dict[str, Any]], check: bool) -> int:
    failures: list[str] = []
    for relative in sorted(vectors):
        path = VECTOR_ROOT / relative
        expected = json_bytes(vectors[relative])
        if check:
            if not path.exists():
                failures.append(f"missing {path.relative_to(REPO_ROOT)}")
            elif path.read_bytes() != expected:
                failures.append(f"stale {path.relative_to(REPO_ROOT)}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(expected)
        digest = hashlib.sha256(expected).hexdigest()
        print(f"{digest}  {path.relative_to(REPO_ROOT)}")
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    mode = "verified" if check else "generated"
    print(f"{mode} {len(vectors)} deterministic G1 vectors")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if any tracked vector differs from deterministic generation",
    )
    args = parser.parse_args()
    return write_vectors(all_vectors(), args.check)


if __name__ == "__main__":
    raise SystemExit(main())
