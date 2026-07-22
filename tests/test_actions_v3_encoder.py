"""Golden tests for v3 subordinate evidence, metadata and execution manifests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shared.evidence_manifest_v3 import encode_evidence_manifest
from shared.metadata_manifest_v3 import (
    ManifestEncodingError,
    encode_authorized_metadata,
    encode_execution_arguments,
)


VECTOR_ROOT = Path(__file__).parent / "golden" / "envelope_v3"


def _load(relative: str) -> dict[str, object]:
    return json.loads((VECTOR_ROOT / relative).read_text(encoding="utf-8"))


def _values(fields: list[dict[str, object]]) -> dict[str, object]:
    return {str(field["name"]): field["value"] for field in fields}


def test_evidence_manifest_matches_frozen_root() -> None:
    vector = _load("evidence_manifest/GV-EM-01.json")
    entries = [_values(fields) for fields in vector["typed_input"]["entries_in_input_order"]]

    material = encode_evidence_manifest(entries)

    assert material.canonical_bytes.hex() == vector["canonical_hex"]
    assert material.root.hex() == vector["hashes"]["preauth_evidence_root"]
    assert material.entry_order == tuple(vector["canonical_entry_order"])


def test_duplicate_evidence_id_is_rejected() -> None:
    vector = _load("evidence_manifest/GV-EM-02.json")
    entries = [_values(fields) for fields in vector["typed_input"]["entries_in_input_order"]]

    with pytest.raises(ManifestEncodingError, match="DuplicateArtifactId"):
        encode_evidence_manifest(entries)


def test_authorized_metadata_matches_frozen_root() -> None:
    vector = _load("metadata_manifest/GV-MM-01.json")

    material = encode_authorized_metadata(vector["typed_input"]["entries_in_input_order"])

    assert material.canonical_bytes.hex() == vector["canonical_hex"]
    assert material.root.hex() == vector["hashes"]["authorized_metadata_root"]
    assert material.entry_order == tuple(vector["canonical_entry_order"])


def test_duplicate_metadata_name_is_rejected() -> None:
    vector = _load("metadata_manifest/GV-MM-02.json")

    with pytest.raises(ManifestEncodingError, match="DuplicateArgumentName"):
        encode_authorized_metadata(vector["typed_input"]["entries_in_input_order"])


@pytest.mark.parametrize("vector_name", ["GV-EA-01", "GV-EA-02"])
def test_execution_argument_manifest_matches_frozen_root(vector_name: str) -> None:
    vector = _load(f"exec_args/{vector_name}.json")
    typed_input = vector["typed_input"]

    material = encode_execution_arguments(
        target=typed_input["target"]["value"],
        entry_point=typed_input["entry_point"]["value"],
        arguments=typed_input["args_in_abi_order"],
    )

    assert material.canonical_bytes.hex() == vector["canonical_hex"]
    assert material.root.hex() == vector["hashes"]["execution_argument_root"]


def test_execution_argument_order_mismatch_is_rejected() -> None:
    vector = _load("exec_args/GV-EA-03.json")
    typed_input = vector["typed_input"]

    with pytest.raises(ManifestEncodingError, match="ExecutionArgumentOrderMismatch"):
        encode_execution_arguments(
            target=typed_input["target"]["value"],
            entry_point=typed_input["entry_point"]["value"],
            arguments=typed_input["args_in_abi_order"],
        )
