"""Offline bootstrap producer for the official-x402 governance interlock."""

from __future__ import annotations

import base64
import copy
import importlib
import importlib.util
import json
import stat
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from shared.proof_registry import (
    ProofRegistryRepository,
    validate_internal_record,
    validate_registry_document,
)


ROOT = Path(__file__).resolve().parents[1]


def _official_fixture_module() -> ModuleType:
    name = "_concordia_official_x402_fixture"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    path = ROOT / "tests" / "test_release_official_x402_adapter.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _producer() -> ModuleType:
    try:
        return importlib.import_module("scripts.stage_official_x402_governance")
    except ModuleNotFoundError:
        pytest.fail("the official-x402 governance staging producer is missing")


def _inputs_from_artifact(
    artifact: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    proof = json.loads(
        base64.b64decode(
            artifact["governance_binding"]["v3_proof_bytes_base64"],
            validate=True,
        )
    )
    resource = json.loads(
        base64.b64decode(
            artifact["resource_and_payment"]["configured_resource_json_base64"],
            validate=True,
        )
    )
    requirements = json.loads(
        base64.b64decode(
            artifact["resource_and_payment"]["accepted_json_base64"],
            validate=True,
        )
    )
    signed_payload = json.loads(
        base64.b64decode(
            artifact["authorization"]["signed_payment_payload_json_base64"],
            validate=True,
        )
    )
    payment_envelope = {
        "schema_version": "concordia.official_x402_staging_input.v1",
        "typed_action_input": copy.deepcopy(proof["input"]),
        "configured_resource": resource,
        "payment_requirements": requirements,
        "protected_report_base64": artifact["protected_report"]["content_base64"],
    }
    return proof, payment_envelope, signed_payload


@pytest.fixture(scope="module")
def valid_inputs() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    official_fixture = _official_fixture_module()
    return _inputs_from_artifact(official_fixture.official_x402_artifact.__wrapped__())


def _copy_inputs(
    valid_inputs: tuple[dict[str, Any], dict[str, Any], dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    return copy.deepcopy(valid_inputs)


def _base_registry(official_record: dict[str, Any]) -> dict[str, Any]:
    observed_at = official_record["observed_at"]
    native = copy.deepcopy(official_record)
    native.update(
        {
            "proposal_id": "DAO-PROP-BASE",
            "proposal_hash": "91" * 32,
            "proposal_nonce": "92" * 32,
            "action_id": "93" * 32,
            "action_kind": "NativeTransferV1",
            "envelope_hash": "94" * 32,
            "resource_url_hash": None,
            "report_hash": None,
            "payment_requirements_hash": None,
            "signed_payment_payload_hash": None,
        }
    )
    snapshot = {
        "proof_id": "base_snapshot",
        "proof_type": "snapshot",
        "generation": "none",
        "lineage": "supplemental",
        "observation_mode": "snapshot",
        "temporal_scope": "current",
        "verification_status": "verified",
        "execution_outcome": "not_applicable",
        "claim_scope": "Pre-existing base registry proof",
        "enforcement_scope": "Snapshot provenance only",
        "proposal_id": "DAO-PROP-BASE",
        "action_id": None,
        "envelope_hash": None,
        "artifact_path": "artifacts/live/base-snapshot.json",
        "artifact_sha256": "95" * 32,
        "source_commit": "96" * 20,
        "deployment_commit": None,
        "network": None,
        "package_hash": None,
        "contract_hash": None,
        "deployment_domain": None,
        "schema_version": "concordia.base-snapshot.v1",
        "captured_at": observed_at,
        "payment_requirements_hash": None,
        "signed_payment_payload_hash": None,
        "report_hash": None,
        "settlement_transaction": None,
        "checks": [
            {
                "name": name,
                "required": True,
                "passed": True,
                "source": "https://concordia.example/base-snapshot.json",
                "observed_at": observed_at,
            }
            for name in (
                "artifact_sha256_recomputed",
                "capture_time_present",
                "source_https_url_present",
                "staleness_check_passed",
            )
        ],
        "links": [
            {
                "rel": "source",
                "label": "Base snapshot",
                "href": "https://concordia.example/base-snapshot.json",
                "kind": "source",
            }
        ],
    }
    return validate_registry_document(
        {
            "schema_version": 1,
            "public_items": [snapshot],
            "internal_records": [native],
        }
    )


def test_stager_derives_exact_pre_settlement_internal_record(
    valid_inputs: tuple[dict[str, Any], dict[str, Any], dict[str, Any]],
) -> None:
    proof, payment_envelope, signed_payload = _copy_inputs(valid_inputs)

    record = _producer().stage_official_x402_governance(
        v3_proof=proof,
        payment_envelope=payment_envelope,
        signed_payment_payload=signed_payload,
    )

    typed = proof["input"]
    prepared = proof["prepared"]
    assert set(record) == {
        "schema_version",
        "proposal_id",
        "proposal_hash",
        "proposal_nonce",
        "action_id",
        "action_kind",
        "action_version",
        "envelope_hash",
        "deployment_domain",
        "network",
        "package_hash",
        "contract_hash",
        "v3_finalized_exact",
        "finalization_transaction",
        "finalized_at",
        "resource_url_hash",
        "report_hash",
        "payment_requirements_hash",
        "signed_payment_payload_hash",
        "verification_status",
        "observed_at",
        "checks",
    }
    assert record["proposal_id"] == typed["header"]["proposal_id"]
    assert record["action_id"] == prepared["action_id"]
    assert record["envelope_hash"] == prepared["envelope_hash"]
    assert record["action_kind"] == "OfficialX402SettlementV1"
    assert record["network"] == "casper:casper-test"
    assert record["verification_status"] == "verified"
    assert record["v3_finalized_exact"] is True
    assert "settlement_transaction" not in record
    assert validate_internal_record(record) == record


def test_stager_accepts_the_official_cspr_click_secp256k1_path() -> None:
    path = ROOT / "tests" / "test_release_official_x402_hardening.py"
    spec = importlib.util.spec_from_file_location(
        "_concordia_official_x402_hardening_fixture",
        path,
    )
    assert spec is not None and spec.loader is not None
    hardening = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hardening)
    proof, payment_envelope, signed_payload = _inputs_from_artifact(
        hardening._secp256k1_artifact()
    )

    record = _producer().stage_official_x402_governance(
        v3_proof=proof,
        payment_envelope=payment_envelope,
        signed_payment_payload=signed_payload,
    )

    assert record["v3_finalized_exact"] is True
    assert signed_payload["payload"]["publicKey"].startswith("02")


def test_stager_pins_the_reviewed_adapter_crypto_primitives() -> None:
    import shared.official_x402_release_adapter as adapter

    producer = _producer()
    for name in (
        "_account_hash_from_public_key",
        "_casper_public_key",
        "_casper_signature",
        "_decimal",
        "_eip712_digest",
        "_payment_requirements_hash",
        "_report_hash",
        "_resource_url_hash",
        "_signed_payload_hash",
        "_tagged_account_hash",
        "_verify_casper_eip712_signature",
    ):
        assert getattr(producer, name) is getattr(adapter, name)


def test_stager_recomputes_every_payment_binding_and_signature(
    valid_inputs: tuple[dict[str, Any], dict[str, Any], dict[str, Any]],
) -> None:
    proof, payment_envelope, signed_payload = _copy_inputs(valid_inputs)
    body = proof["input"]["body"]

    record = _producer().stage_official_x402_governance(
        v3_proof=proof,
        payment_envelope=payment_envelope,
        signed_payment_payload=signed_payload,
    )

    assert record["resource_url_hash"] == body["resource_url_hash"]
    assert record["report_hash"] == body["report_hash"]
    assert record["payment_requirements_hash"] == body["payment_requirements_hash"]
    assert record["signed_payment_payload_hash"] == body["signed_payment_payload_hash"]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("wrong_action", "OfficialX402SettlementV1|action"),
        ("wrong_network", "network"),
        ("wrong_proposal", "typed action input|proposal"),
        ("wrong_report", "report hash"),
        ("unfinalized", "proof verification|finalized"),
        ("supplied_boolean", "field set|boolean"),
    ],
)
def test_stager_refuses_mismatched_unfinalized_or_asserted_inputs(
    mutation: str,
    message: str,
    valid_inputs: tuple[dict[str, Any], dict[str, Any], dict[str, Any]],
) -> None:
    proof, payment_envelope, signed_payload = _copy_inputs(valid_inputs)
    if mutation == "wrong_action":
        payment_envelope["typed_action_input"]["action"] = "NativeTransferV1"
    elif mutation == "wrong_network":
        payment_envelope["payment_requirements"]["network"] = "casper-testnet"
    elif mutation == "wrong_proposal":
        payment_envelope["typed_action_input"]["header"]["proposal_id"] += "-OTHER"
    elif mutation == "wrong_report":
        payment_envelope["protected_report_base64"] = base64.b64encode(
            b"different report"
        ).decode("ascii")
    elif mutation == "unfinalized":
        exact = next(
            step for step in proof["run"]["steps"] if step["name"] == "finalize_exact"
        )
        exact["submission_state"] = "submitted"
    elif mutation == "supplied_boolean":
        payment_envelope["verified"] = True
    else:  # pragma: no cover - parametrization is closed above.
        raise AssertionError(mutation)

    with pytest.raises(
        _producer().GovernanceStagingError,
        match=message,
    ):
        _producer().stage_official_x402_governance(
            v3_proof=proof,
            payment_envelope=payment_envelope,
            signed_payment_payload=signed_payload,
        )


def test_stager_refuses_tampered_signature(
    valid_inputs: tuple[dict[str, Any], dict[str, Any], dict[str, Any]],
) -> None:
    proof, payment_envelope, signed_payload = _copy_inputs(valid_inputs)
    signature = signed_payload["payload"]["signature"]
    signed_payload["payload"]["signature"] = signature[:-2] + (
        "00" if signature[-2:] != "00" else "01"
    )

    with pytest.raises(
        _producer().GovernanceStagingError,
        match="signature|signed payment payload hash",
    ):
        _producer().stage_official_x402_governance(
            v3_proof=proof,
            payment_envelope=payment_envelope,
            signed_payment_payload=signed_payload,
        )


def test_writer_is_canonical_private_write_once_and_refuses_symlinks(
    valid_inputs: tuple[dict[str, Any], dict[str, Any], dict[str, Any]],
    tmp_path: Path,
) -> None:
    proof, payment_envelope, signed_payload = _copy_inputs(valid_inputs)
    output = tmp_path / "official-x402-governance.json"
    producer = _producer()
    record = producer.stage_official_x402_governance(
        v3_proof=proof,
        payment_envelope=payment_envelope,
        signed_payment_payload=signed_payload,
    )
    base_registry = _base_registry(record)

    document = producer.write_official_x402_governance(
        output=output,
        base_registry=base_registry,
        v3_proof=proof,
        payment_envelope=payment_envelope,
        signed_payment_payload=signed_payload,
    )

    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert output.read_bytes() == producer.canonical_json_bytes(document)
    assert document["public_items"] == base_registry["public_items"]
    assert document["internal_records"][:-1] == base_registry["internal_records"]
    assert document["internal_records"][-1] == record
    before = output.read_bytes()
    with pytest.raises(producer.GovernanceStagingError, match="already exists"):
        producer.write_official_x402_governance(
            output=output,
            base_registry=base_registry,
            v3_proof=proof,
            payment_envelope=payment_envelope,
            signed_payment_payload=signed_payload,
        )
    assert output.read_bytes() == before

    outside = tmp_path / "outside.json"
    outside.write_text("do not replace", encoding="utf-8")
    linked = tmp_path / "linked.json"
    linked.symlink_to(outside)
    with pytest.raises(
        producer.GovernanceStagingError,
        match="symlink|already exists|safely",
    ):
        producer.write_official_x402_governance(
            output=linked,
            base_registry=base_registry,
            v3_proof=proof,
            payment_envelope=payment_envelope,
            signed_payment_payload=signed_payload,
        )
    assert outside.read_text(encoding="utf-8") == "do not replace"


def test_combined_registry_is_immediately_consumable_by_gateway_repository(
    valid_inputs: tuple[dict[str, Any], dict[str, Any], dict[str, Any]],
    tmp_path: Path,
) -> None:
    proof, payment_envelope, signed_payload = _copy_inputs(valid_inputs)
    producer = _producer()
    record = producer.stage_official_x402_governance(
        v3_proof=proof,
        payment_envelope=payment_envelope,
        signed_payment_payload=signed_payload,
    )
    base_registry = _base_registry(record)
    output = tmp_path / "isolated-staging-registry" / "registry.json"
    output.parent.mkdir()

    document = producer.write_official_x402_governance(
        output=output,
        base_registry=base_registry,
        v3_proof=proof,
        payment_envelope=payment_envelope,
        signed_payment_payload=signed_payload,
    )

    repository = ProofRegistryRepository(output.parent)
    assert (
        repository.by_signed_payment_payload_hash(record["signed_payment_payload_hash"])
        == record
    )
    public = repository.public_document(
        "DAO-PROP-BASE",
        known=True,
        generated_at=record["observed_at"],
    )
    assert [item["proof_id"] for item in public["items"]] == ["base_snapshot"]
    assert validate_registry_document(document) == document


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_action",
        "duplicate_payment",
        "invalid_base",
    ],
)
def test_combined_registry_refuses_duplicates_and_base_tampering(
    mutation: str,
    valid_inputs: tuple[dict[str, Any], dict[str, Any], dict[str, Any]],
    tmp_path: Path,
) -> None:
    proof, payment_envelope, signed_payload = _copy_inputs(valid_inputs)
    producer = _producer()
    record = producer.stage_official_x402_governance(
        v3_proof=proof,
        payment_envelope=payment_envelope,
        signed_payment_payload=signed_payload,
    )
    base_registry = _base_registry(record)
    if mutation == "duplicate_action":
        base_registry["internal_records"][0]["action_id"] = record["action_id"]
    elif mutation == "duplicate_payment":
        duplicate = copy.deepcopy(record)
        duplicate["action_id"] = "fe" * 32
        base_registry["internal_records"].append(duplicate)
    elif mutation == "invalid_base":
        base_registry["public_items"][0]["checks"][0]["passed"] = False
    else:  # pragma: no cover - parametrization is closed above.
        raise AssertionError(mutation)

    output = tmp_path / f"{mutation}.json"
    with pytest.raises(
        producer.GovernanceStagingError,
        match="base registry|duplicate|ambiguous|invalid",
    ):
        producer.write_official_x402_governance(
            output=output,
            base_registry=base_registry,
            v3_proof=proof,
            payment_envelope=payment_envelope,
            signed_payment_payload=signed_payload,
        )
    assert not output.exists()


def test_cli_is_offline_deterministic_and_requires_all_three_inputs(
    valid_inputs: tuple[dict[str, Any], dict[str, Any], dict[str, Any]],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    proof, payment_envelope, signed_payload = _copy_inputs(valid_inputs)
    producer = _producer()
    proof_path = tmp_path / "proof.json"
    envelope_path = tmp_path / "payment-envelope.json"
    signed_path = tmp_path / "signed-payload.json"
    base_path = tmp_path / "base-registry.json"
    output = tmp_path / "registry-record.json"
    for path, value in (
        (proof_path, proof),
        (envelope_path, payment_envelope),
        (signed_path, signed_payload),
    ):
        path.write_text(json.dumps(value), encoding="utf-8")
    record = producer.stage_official_x402_governance(
        v3_proof=proof,
        payment_envelope=payment_envelope,
        signed_payment_payload=signed_payload,
    )
    base_path.write_text(json.dumps(_base_registry(record)), encoding="utf-8")

    assert (
        producer.main(
            [
                "--base-registry",
                str(base_path),
                "--v3-proof",
                str(proof_path),
                "--payment-envelope",
                str(envelope_path),
                "--signed-payment-payload",
                str(signed_path),
                "--out",
                str(output),
            ]
        )
        == 0
    )
    summary = json.loads(capsys.readouterr().out)
    assert summary == {
        "action_id": proof["prepared"]["action_id"],
        "output": str(output),
        "proposal_id": proof["input"]["header"]["proposal_id"],
        "signed_payment_payload_hash": proof["input"]["body"][
            "signed_payment_payload_hash"
        ],
        "valid": True,
        "written": True,
    }
    assert output.exists()

    source = Path(producer.__file__).read_text(encoding="utf-8")
    for banned in (
        "requests.",
        "urllib.request",
        "httpx.",
        "PrivateKey",
        ".sign(",
    ):
        assert banned not in source
