"""Golden-vector and dual-implementation recomputation tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.mainnet_canary.crosscheck import (
    recompute_native_identifiers,
    run_golden_vector_gate,
)
from tools.mainnet_canary.encoding import (
    FreshEncodingError,
    derive_deployment_domain,
    derive_native_envelope,
)
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode

REPO_ROOT = Path(__file__).resolve().parents[2]
VECTOR_ROOT = REPO_ROOT / "tests" / "golden" / "envelope_v3"


def _load_vector(relative: str) -> dict[str, object]:
    return json.loads((VECTOR_ROOT / relative).read_text(encoding="utf-8"))


def _values(fields: list[dict[str, object]]) -> dict[str, object]:
    return {str(field["name"]): field["value"] for field in fields}


def _baseline() -> tuple[dict[str, object], dict[str, object]]:
    vector = _load_vector("native_transfer/GV-NT-01.json")
    return (
        _values(vector["typed_input"]["header"]),
        _values(vector["typed_input"]["body"]),
    )


def test_golden_vector_gate_passes_against_frozen_vectors() -> None:
    summary = run_golden_vector_gate(REPO_ROOT)
    assert summary["native_transfer"]["valid_vectors"] >= 3
    assert summary["native_transfer"]["relationship_vectors"] >= 2
    assert summary["header"]["valid_vectors"] >= 3
    assert summary["header"]["invalid_vectors"] >= 2
    assert summary["header"]["domain_derivations"] >= 1


def test_fresh_implementation_reproduces_frozen_gv_nt_01_exactly() -> None:
    vector = _load_vector("native_transfer/GV-NT-01.json")
    header, body = _baseline()
    material = derive_native_envelope(header, body, chain_name="casper-test")
    assert material.action_id.hex() == vector["hashes"]["action_id"]
    assert material.envelope_hash.hex() == vector["hashes"]["envelope_hash"]
    assert material.body_bytes.hex() == vector["canonical_hex"]
    assert material.header_bytes.hex() == vector["header_canonical_hex"]
    assert str(material.transfer_id) == body["transfer_id"]


def test_dual_implementations_agree_on_testnet_chain() -> None:
    header, body = _baseline()
    material = recompute_native_identifiers(header, body, chain_name="casper-test")
    vector = _load_vector("native_transfer/GV-NT-01.json")
    assert material.action_id_hex == vector["hashes"]["action_id"]
    assert material.envelope_hash_hex == vector["hashes"]["envelope_hash"]


def test_dual_implementations_agree_on_mainnet_chain() -> None:
    header, body = _baseline()
    header["casper_chain_name"] = "casper"
    material = recompute_native_identifiers(header, body, chain_name="casper")
    testnet_header, _ = _baseline()
    testnet = recompute_native_identifiers(
        testnet_header, body, chain_name="casper-test"
    )
    # action_id excludes the header, so it survives the chain change; the
    # envelope hash binds the chain name and must differ.
    assert material.action_id_hex == testnet.action_id_hex
    assert material.envelope_hash_hex != testnet.envelope_hash_hex


def test_shared_full_deriver_cannot_encode_mainnet_chain() -> None:
    """Documents WHY the fresh from-spec implementation must exist."""

    from shared.actions_v3 import derive_native_material
    from shared.envelope_v3 import EnvelopeEncodingError

    header, body = _baseline()
    header["casper_chain_name"] = "casper"
    with pytest.raises(EnvelopeEncodingError):
        derive_native_material(header, body)


def test_wrong_action_id_is_refused_by_recomputation() -> None:
    header, body = _baseline()
    header["action_id"] = "9" * 64
    with pytest.raises(FreshEncodingError, match="action_id"):
        derive_native_envelope(header, body, chain_name="casper-test")


def test_wrong_transfer_id_is_refused_by_recomputation() -> None:
    header, body = _baseline()
    body["transfer_id"] = "1"
    with pytest.raises(FreshEncodingError, match="transfer_id"):
        derive_native_envelope(header, body, chain_name="casper-test")


def test_wrong_amount_formula_is_refused() -> None:
    header, body = _baseline()
    body["amount_motes"] = "50000000001"
    with pytest.raises(FreshEncodingError):
        derive_native_envelope(header, body, chain_name="casper-test")


def test_zero_action_nonce_is_refused() -> None:
    header, body = _baseline()
    body["action_nonce"] = "0" * 64
    with pytest.raises(FreshEncodingError, match="non-zero"):
        derive_native_envelope(header, body, chain_name="casper-test")


def test_relationship_new_nonce_changes_action_id() -> None:
    header, body = _baseline()
    baseline = derive_native_envelope(header, body, chain_name="casper-test")
    body2 = dict(body)
    body2["action_nonce"] = "45" * 32
    with pytest.raises(FreshEncodingError):
        # stale action_id/transfer_id must be refused after the nonce change
        derive_native_envelope(header, body2, chain_name="casper-test")
    del baseline


def test_deployment_domain_differs_between_chains() -> None:
    nonce = "a5" * 32
    testnet = derive_deployment_domain(
        chain_name="casper-test",
        package_key_name="concordia_governance_receipt_v3",
        installation_nonce=nonce,
    )
    mainnet = derive_deployment_domain(
        chain_name="casper",
        package_key_name="concordia_governance_receipt_v3",
        installation_nonce=nonce,
    )
    assert testnet != mainnet


def test_deployment_domain_refuses_unknown_chain_and_zero_nonce() -> None:
    with pytest.raises(FreshEncodingError):
        derive_deployment_domain(
            chain_name="casper-mainnet",
            package_key_name="concordia_governance_receipt_v3",
            installation_nonce="a5" * 32,
        )
    with pytest.raises(FreshEncodingError):
        derive_deployment_domain(
            chain_name="casper",
            package_key_name="concordia_governance_receipt_v3",
            installation_nonce="00" * 32,
        )


def test_implementation_disagreement_is_a_stable_refusal(monkeypatch) -> None:
    import tools.mainnet_canary.crosscheck as crosscheck_module

    header, body = _baseline()

    original = crosscheck_module._shared_primitive_native_material

    def corrupted(header_arg, body_arg):
        material = original(header_arg, body_arg)
        return type(material)(
            header_bytes=material.header_bytes,
            body_bytes=material.body_bytes,
            action_core_bytes=material.action_core_bytes,
            action_id=bytes(32),
            transfer_id=material.transfer_id,
            envelope_hash=material.envelope_hash,
        )

    monkeypatch.setattr(
        crosscheck_module, "_shared_primitive_native_material", corrupted
    )
    with pytest.raises(CanaryRefusal) as refusal:
        recompute_native_identifiers(header, body, chain_name="casper-test")
    assert refusal.value.code == RefusalCode.ID_RECOMPUTATION_MISMATCH
