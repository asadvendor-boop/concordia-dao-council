"""Canonical authorized-metadata and execution-argument manifests."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from shared.envelope_v3 import (
    MACHINE_NAME_RE,
    TYPE_TAGS,
    EnvelopeEncodingError,
    blake2b256,
    canonical_value,
    length_prefix,
)


METADATA_DOMAIN_SEPARATOR = b"CONCORDIA_AUTHORIZED_METADATA_V1\0"
EXEC_ARGS_DOMAIN_SEPARATOR = b"CONCORDIA_EXEC_ARGS_V1\0"


class ManifestEncodingError(ValueError):
    """A subordinate manifest violates its frozen schema."""


@dataclass(frozen=True)
class ManifestMaterial:
    canonical_bytes: bytes
    root: bytes
    entry_order: tuple[str, ...] = ()


def _encode_typed_entry(entry: Mapping[str, Any]) -> bytes:
    name = entry.get("name")
    type_name = entry.get("type")
    if not isinstance(name, str) or not MACHINE_NAME_RE.fullmatch(name):
        raise ManifestEncodingError("InvalidArgumentName")
    if not isinstance(type_name, str) or type_name not in TYPE_TAGS:
        raise ManifestEncodingError("InvalidArgumentType")
    try:
        value = canonical_value(type_name, entry.get("value"), name)
    except EnvelopeEncodingError as exc:
        raise ManifestEncodingError(str(exc)) from exc
    return length_prefix(name, "name") + bytes([TYPE_TAGS[type_name]]) + value


def _reject_duplicate_names(entries: Sequence[Mapping[str, Any]]) -> None:
    names = [entry.get("name") for entry in entries]
    if len(names) != len(set(names)):
        raise ManifestEncodingError("DuplicateArgumentName")


def encode_authorized_metadata(entries: Sequence[Mapping[str, Any]]) -> ManifestMaterial:
    _reject_duplicate_names(entries)
    ordered = sorted(entries, key=lambda entry: str(entry.get("name", "")).encode("ascii"))
    encoded_entries = b"".join(_encode_typed_entry(entry) for entry in ordered)
    encoded = (1).to_bytes(4, "big") + len(ordered).to_bytes(4, "big") + encoded_entries
    return ManifestMaterial(
        canonical_bytes=encoded,
        root=blake2b256(METADATA_DOMAIN_SEPARATOR + encoded),
        entry_order=tuple(str(entry["name"]) for entry in ordered),
    )


def _expected_argument_order(target: str, entry_point: str) -> tuple[str, ...]:
    if target == "native-transfer" and entry_point == "transfer":
        return ("target", "amount", "id")
    if target.startswith("contract-") and entry_point == "transfer_with_authorization":
        return (
            "from",
            "to",
            "value",
            "valid_after",
            "valid_before",
            "nonce",
            "public_key",
            "signature",
        )
    raise ManifestEncodingError("ExecutionTargetMismatch")


def encode_execution_arguments(
    *,
    target: str,
    entry_point: str,
    arguments: Sequence[Mapping[str, Any]],
) -> ManifestMaterial:
    _reject_duplicate_names(arguments)
    names = tuple(str(argument.get("name")) for argument in arguments)
    if names != _expected_argument_order(target, entry_point):
        raise ManifestEncodingError("ExecutionArgumentOrderMismatch")
    encoded_args = b"".join(_encode_typed_entry(argument) for argument in arguments)
    encoded = (
        (1).to_bytes(4, "big")
        + length_prefix(target, "target")
        + length_prefix(entry_point, "entry_point")
        + len(arguments).to_bytes(4, "big")
        + encoded_args
    )
    return ManifestMaterial(
        canonical_bytes=encoded,
        root=blake2b256(EXEC_ARGS_DOMAIN_SEPARATOR + encoded),
        entry_order=names,
    )
