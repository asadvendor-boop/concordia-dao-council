"""Cross-language golden tests for Concordia's frozen v3 binary envelope."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shared.actions_v3 import derive_native_material, derive_x402_material
from shared.envelope_v3 import (
    EnvelopeEncodingError,
    derive_deployment_domain,
    encode_header,
)


VECTOR_ROOT = Path(__file__).parent / "golden" / "envelope_v3"


def _load(relative: str) -> dict[str, object]:
    return json.loads((VECTOR_ROOT / relative).read_text(encoding="utf-8"))


def _values(fields: list[dict[str, object]]) -> dict[str, object]:
    return {str(field["name"]): field["value"] for field in fields}


@pytest.mark.parametrize("vector_name", ["GV-HDR-01", "GV-HDR-02", "GV-HDR-03"])
def test_header_matches_frozen_canonical_bytes_and_hash(vector_name: str) -> None:
    vector = _load(f"header/{vector_name}.json")
    encoded = encode_header(_values(vector["typed_input"]["fields"]))

    assert encoded.hex() == vector["canonical_hex"]
    assert len(encoded) == vector["canonical_length"]


def test_deployment_domain_matches_frozen_installation_derivation() -> None:
    vector = _load("header/GV-HDR-01.json")
    derivation = vector["deployment_domain_derivation"]

    result = derive_deployment_domain(
        chain_name=derivation["chain_name"],
        package_name=derivation["package_key_name"],
        installation_nonce=bytes.fromhex(derivation["installation_nonce"]),
    )

    assert result.hex() == derivation["blake2b256"]
    assert derivation["preimage_hex"].endswith(derivation["installation_nonce"])


@pytest.mark.parametrize("vector_name", ["GV-HDR-04", "GV-HDR-05"])
def test_invalid_header_vectors_fail_closed(vector_name: str) -> None:
    vector = _load(f"header/{vector_name}.json")

    with pytest.raises(EnvelopeEncodingError) as exc_info:
        encode_header(_values(vector["typed_input"]["fields"]))

    assert exc_info.value.error_name == vector["expected_error"]["name"]
    assert exc_info.value.field_name == vector["failed_field"]


@pytest.mark.parametrize(
    "vector_name",
    ["GV-NT-01", "GV-NT-02", "GV-NT-03", "GV-NT-04", "GV-NT-05"],
)
def test_native_material_matches_all_frozen_vectors(vector_name: str) -> None:
    vector = _load(f"native_transfer/{vector_name}.json")
    typed_input = vector["typed_input"]
    cases = typed_input.get("cases", [typed_input])

    materials = []
    for case in cases:
        material = derive_native_material(
            _values(case["header"]),
            _values(case["body"]),
        )
        materials.append(material)

    if len(materials) == 1:
        material = materials[0]
        assert material.body_bytes.hex() == vector["canonical_hex"]
        assert len(material.body_bytes) == vector["canonical_length"]
        if "action_core_hex" in vector:
            assert material.action_core_bytes.hex() == vector["action_core_hex"]
        assert material.action_id.hex() == vector["hashes"]["action_id"]
        assert material.transfer_id == int(vector["typed_input"]["body"][7]["value"])
        assert material.envelope_hash.hex() == vector["hashes"]["envelope_hash"]
    else:
        comparison = vector["comparison"]["assertions"]
        if "action_id_equal" in comparison:
            assert (materials[0].action_id == materials[1].action_id) is comparison["action_id_equal"]
        if "action_id_differs" in comparison:
            assert (materials[0].action_id != materials[1].action_id) is comparison["action_id_differs"]
        if "transfer_id_differs" in comparison:
            assert (materials[0].transfer_id != materials[1].transfer_id) is comparison["transfer_id_differs"]
        if "envelope_hash_differs" in comparison:
            assert (materials[0].envelope_hash != materials[1].envelope_hash) is comparison["envelope_hash_differs"]


@pytest.mark.parametrize("vector_name", ["GV-X4-01", "GV-X4-02", "GV-X4-04"])
def test_x402_material_matches_frozen_vectors(vector_name: str) -> None:
    vector = _load(f"x402_settlement/{vector_name}.json")
    typed_input = vector["typed_input"]
    cases = typed_input.get("cases", [typed_input])
    materials = [
        derive_x402_material(_values(case["header"]), _values(case["body"]))
        for case in cases
    ]

    if len(materials) == 1:
        material = materials[0]
        assert material.body_bytes.hex() == vector["canonical_hex"]
        assert len(material.body_bytes) == vector["canonical_length"]
        assert material.action_id.hex() == vector["hashes"]["action_id"]
        assert material.envelope_hash.hex() == vector["hashes"]["envelope_hash"]
    else:
        assert (materials[0].action_id != materials[1].action_id) is vector["comparison"]["action_id_differs"]
        assert (materials[0].envelope_hash != materials[1].envelope_hash) is vector["comparison"]["envelope_hash_differs"]


def test_invalid_x402_window_fails_closed() -> None:
    vector = _load("x402_settlement/GV-X4-03.json")

    with pytest.raises(EnvelopeEncodingError) as exc_info:
        derive_x402_material({}, _values(vector["typed_input"]["body"]))

    assert exc_info.value.error_name == "InvalidActionField"
    assert exc_info.value.field_name in vector["failed_fields"]
