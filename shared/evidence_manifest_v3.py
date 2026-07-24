"""Canonical pre-authorization evidence manifest for Concordia v3."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from shared.envelope_v3 import MACHINE_NAME_RE, blake2b256, encode_fields
from shared.metadata_manifest_v3 import ManifestEncodingError, ManifestMaterial


EVIDENCE_DOMAIN_SEPARATOR = b"CONCORDIA_PREAUTH_EVIDENCE_V1\0"
EVIDENCE_SCHEMA: tuple[tuple[str, str], ...] = (
    ("artifact_id", "String"),
    ("artifact_kind", "u8"),
    ("content_sha256", "Bytes32"),
    ("byte_length", "u64"),
    ("media_type", "String"),
    ("provenance_class", "u8"),
    ("captured_at_unix_seconds", "u64"),
)


def encode_evidence_manifest(entries: Sequence[Mapping[str, Any]]) -> ManifestMaterial:
    ids = [entry.get("artifact_id") for entry in entries]
    if len(ids) != len(set(ids)):
        raise ManifestEncodingError("DuplicateArtifactId")
    for artifact_id in ids:
        if not isinstance(artifact_id, str) or not MACHINE_NAME_RE.fullmatch(artifact_id):
            raise ManifestEncodingError("InvalidArtifactId")
    ordered = sorted(entries, key=lambda entry: str(entry["artifact_id"]).encode("ascii"))
    try:
        encoded_entries = b"".join(encode_fields(entry, EVIDENCE_SCHEMA) for entry in ordered)
    except ValueError as exc:
        raise ManifestEncodingError(str(exc)) from exc
    encoded = (1).to_bytes(4, "big") + len(ordered).to_bytes(4, "big") + encoded_entries
    return ManifestMaterial(
        canonical_bytes=encoded,
        root=blake2b256(EVIDENCE_DOMAIN_SEPARATOR + encoded),
        entry_order=tuple(str(entry["artifact_id"]) for entry in ordered),
    )
