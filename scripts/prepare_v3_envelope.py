#!/usr/bin/env python3
"""Prepare and independently recompute a typed Concordia v3 finalization."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from pycspr import serializer
from pycspr.types.cl import (
    CLV_ByteArray,
    CLV_String,
    CLV_U256,
    CLV_U32,
    CLV_U512,
    CLV_U64,
    CLV_U8,
)

from shared.actions_v3 import (
    NATIVE_SCHEMA,
    X402_SCHEMA,
    derive_native_material,
    derive_x402_material,
)
from shared.envelope_v3 import HEADER_SCHEMA, bytes32, uint_value


class EnvelopePreparationError(ValueError):
    pass


INJECTED_HEADER_FIELDS = {"schema_version", "deployment_domain", "casper_chain_name"}


def _cl_value(type_name: str, value: object, field_name: str) -> object:
    if type_name in {"Bytes32", "AccountHash"}:
        return CLV_ByteArray(bytes32(value, field_name))
    if type_name == "String":
        if not isinstance(value, str):
            raise EnvelopePreparationError(f"{field_name}: String required")
        return CLV_String(value)
    if type_name == "u8":
        return CLV_U8(uint_value(value, 8, field_name))
    if type_name == "u32":
        return CLV_U32(uint_value(value, 32, field_name))
    if type_name == "u64":
        return CLV_U64(uint_value(value, 64, field_name))
    if type_name == "U256":
        return CLV_U256(uint_value(value, 256, field_name))
    if type_name == "U512":
        return CLV_U512(uint_value(value, 512, field_name))
    raise EnvelopePreparationError(f"{field_name}: unsupported runtime type {type_name}")


def _runtime_args(
    header: Mapping[str, Any],
    body: Mapping[str, Any],
    body_schema: tuple[tuple[str, str], ...],
) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for name, type_name in HEADER_SCHEMA:
        if name in INJECTED_HEADER_FIELDS:
            continue
        clv = _cl_value(type_name, header[name], name)
        values.append({"name": name, **serializer.to_json(clv)})
    for name, type_name in body_schema:
        clv = _cl_value(type_name, body[name], name)
        values.append({"name": name, **serializer.to_json(clv)})
    return values


def prepare_v3_envelope(document: Mapping[str, Any]) -> dict[str, Any]:
    if set(document) != {"schema_id", "action", "header", "body"}:
        raise EnvelopePreparationError("input must contain only schema_id, action, header and body")
    if document["schema_id"] != "concordia.exact-envelope-v3.input.v1":
        raise EnvelopePreparationError("unsupported input schema")
    header = document["header"]
    body = document["body"]
    if not isinstance(header, Mapping) or not isinstance(body, Mapping):
        raise EnvelopePreparationError("header and body must be objects")

    if document["action"] == "NativeTransferV1":
        entry_point = "finalize_native_transfer"
        material = derive_native_material(header, body)
        body_schema = NATIVE_SCHEMA
    elif document["action"] == "OfficialX402SettlementV1":
        entry_point = "finalize_official_x402"
        material = derive_x402_material(header, body)
        body_schema = X402_SCHEMA
    else:
        raise EnvelopePreparationError("action must be a frozen executable v3 action")

    result: dict[str, Any] = {
        "schema_id": "concordia.exact-envelope-v3.prepared.v1",
        "action": document["action"],
        "entry_point": entry_point,
        "proposal_id": header["proposal_id"],
        "action_id": material.action_id.hex(),
        "envelope_hash": material.envelope_hash.hex(),
        "canonical": {
            "header_hex": material.header_bytes.hex(),
            "body_hex": material.body_bytes.hex(),
            "action_core_hex": material.action_core_bytes.hex(),
        },
        "runtime_args": _runtime_args(header, body, body_schema),
    }
    if material.transfer_id is not None:
        result["transfer_id"] = str(material.transfer_id)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        document = json.loads(args.input.read_text(encoding="utf-8"))
        result = prepare_v3_envelope(document)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))
        return 2
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
