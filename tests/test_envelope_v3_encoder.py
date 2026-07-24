"""Cross-language golden tests for Concordia's frozen v3 binary envelope."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shared.actions_v3 import (
    X402_CORE_SCHEMA,
    build_native_material,
    derive_native_material,
    derive_x402_material,
)
from shared.envelope_v3 import (
    ACTION_ID_DOMAIN_SEPARATOR,
    EnvelopeEncodingError,
    blake2b256,
    bytes32,
    canonical_value,
    derive_deployment_domain,
    encode_fields,
    encode_header,
)


VECTOR_ROOT = Path(__file__).parent / "golden" / "envelope_v3"


def _load(relative: str) -> dict[str, object]:
    return json.loads((VECTOR_ROOT / relative).read_text(encoding="utf-8"))


def _values(fields: list[dict[str, object]]) -> dict[str, object]:
    return {str(field["name"]): field["value"] for field in fields}


@pytest.mark.parametrize(
    "value",
    ["line\nbreak", "tab\tvalue", "delete\x7fvalue", "control\x1f"],
)
def test_frozen_strings_reject_every_non_printable_ascii_byte(value: str) -> None:
    with pytest.raises(EnvelopeEncodingError, match="printable ASCII"):
        canonical_value("String", value, "metadata")


def test_frozen_strings_accept_ascii_space_through_tilde() -> None:
    value = " " + "".join(chr(code) for code in range(0x21, 0x7F))
    assert canonical_value("String", value, "metadata").endswith(value.encode("ascii"))


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
    ("field", "value"),
    [("action_kind", 0), ("action_kind", 3), ("action_version", 2)],
)
def test_unsupported_action_selector_uses_frozen_action_error_precedence(
    field: str,
    value: int,
) -> None:
    vector = _load("header/GV-HDR-01.json")
    header = _values(vector["typed_input"]["fields"])
    header[field] = value

    with pytest.raises(EnvelopeEncodingError) as exc_info:
        encode_header(header)

    assert exc_info.value.error_name == "InvalidActionField"
    assert exc_info.value.field_name == field


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


@pytest.mark.parametrize("field", ["source_account", "recipient_account"])
def test_native_transfer_rejects_zero_financial_account(field: str) -> None:
    vector = _load("native_transfer/GV-NT-01.json")
    header = _values(vector["typed_input"]["header"])
    body = _values(vector["typed_input"]["body"])
    body[field] = "00" * 32

    with pytest.raises(EnvelopeEncodingError) as exc_info:
        build_native_material(header, body)

    assert exc_info.value.error_name == "InvalidActionField"
    assert exc_info.value.field_name == field


@pytest.mark.parametrize(
    "field",
    [
        "resource_url_hash",
        "report_hash",
        "payment_requirements_hash",
        "signed_payment_payload_hash",
        "eip712_auth_nonce",
        "payer",
        "payee",
    ],
)
def test_x402_rejects_zero_binding_hashes_before_deploy(field: str) -> None:
    vector = _load("x402_settlement/GV-X4-01.json")
    header = _values(vector["typed_input"]["header"])
    body = _values(vector["typed_input"]["body"])
    body[field] = "00" * 32
    core = encode_fields(
        {name: body[name] for name, _type_name in X402_CORE_SCHEMA},
        X402_CORE_SCHEMA,
    )
    action_id = blake2b256(
        ACTION_ID_DOMAIN_SEPARATOR
        + bytes([2])
        + bytes32(body["action_nonce"], "action_nonce")
        + core
    )
    header["action_id"] = action_id.hex()

    with pytest.raises(EnvelopeEncodingError) as exc_info:
        derive_x402_material(header, body)

    assert exc_info.value.error_name == "InvalidActionField"
    assert exc_info.value.field_name == field


def test_native_builder_derives_ids_before_strict_verification() -> None:
    vector = _load("native_transfer/GV-NT-01.json")
    header = _values(vector["typed_input"]["header"])
    body = _values(vector["typed_input"]["body"])
    header["action_id"] = "00" * 32
    body["transfer_id"] = "0"

    built_header, built_body, material = build_native_material(header, body)

    assert built_header["action_id"] == vector["hashes"]["action_id"]
    assert built_body["transfer_id"] == vector["typed_input"]["body"][7]["value"]
    assert material.envelope_hash.hex() == vector["hashes"]["envelope_hash"]
