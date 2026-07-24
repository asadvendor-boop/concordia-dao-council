"""Production composition gates for the canonical exact-envelope v3 proof."""

from __future__ import annotations

import copy
import importlib
import json
import stat
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

from scripts.verify_v3_proof import ProofVerificationError, verify_v3_proof_document
from tests import test_clvalue_roundtrip as v3_fixtures


def _composer() -> ModuleType:
    try:
        return importlib.import_module("scripts.compose_v3_release_proof")
    except ModuleNotFoundError:
        pytest.fail("the production v3 proof composer CLI does not exist")


@pytest.fixture(scope="module")
def native_proof() -> dict[str, object]:
    proof, _, _ = v3_fixtures._bound_v3_proof()
    return proof


def _documents(
    proof: dict[str, object],
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    return (
        copy.deepcopy(proof["deployment"]),
        copy.deepcopy(proof["input"]),
        copy.deepcopy(proof["run"]),
    )


@pytest.mark.parametrize(
    ("action", "document_factory"),
    [
        ("NativeTransferV1", v3_fixtures._native_document),
        ("OfficialX402SettlementV1", v3_fixtures._x402_document),
    ],
)
def test_composer_derives_the_exact_six_field_proof_for_both_frozen_actions(
    action: str,
    document_factory: Callable[[], dict[str, object]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(v3_fixtures, "_native_document", document_factory)
    expected, _, _ = v3_fixtures._bound_v3_proof()
    deployment, typed_input, finalized_run = _documents(expected)

    composed = _composer().compose_v3_release_proof(
        deployment=deployment,
        typed_input=typed_input,
        finalized_run=finalized_run,
    )

    assert set(composed) == {
        "schema_id",
        "deployment",
        "input",
        "prepared",
        "run",
        "readback",
    }
    assert composed == expected
    assert composed["prepared"]["action"] == action
    assert verify_v3_proof_document(composed)["valid"] is True


def test_composer_does_not_mutate_any_source_document(
    native_proof: dict[str, object],
) -> None:
    deployment, typed_input, finalized_run = _documents(native_proof)
    originals = copy.deepcopy((deployment, typed_input, finalized_run))

    _composer().compose_v3_release_proof(
        deployment=deployment,
        typed_input=typed_input,
        finalized_run=finalized_run,
    )

    assert (deployment, typed_input, finalized_run) == originals


def _mutate_network(
    deployment: dict[str, object],
    typed_input: dict[str, object],
    finalized_run: dict[str, object],
) -> None:
    del deployment, typed_input
    finalized_run["network"] = "casper-main"


def _mutate_package(
    deployment: dict[str, object],
    typed_input: dict[str, object],
    finalized_run: dict[str, object],
) -> None:
    del deployment, typed_input
    finalized_run["package_hash"] = "ff" * 32


def _mutate_contract(
    deployment: dict[str, object],
    typed_input: dict[str, object],
    finalized_run: dict[str, object],
) -> None:
    del deployment, typed_input
    finalized_run["contract_hash"] = "ff" * 32


def _mutate_domain(
    deployment: dict[str, object],
    typed_input: dict[str, object],
    finalized_run: dict[str, object],
) -> None:
    del deployment, finalized_run
    typed_input["header"]["deployment_domain"] = "ff" * 32


def _mutate_proposal(
    deployment: dict[str, object],
    typed_input: dict[str, object],
    finalized_run: dict[str, object],
) -> None:
    del deployment, finalized_run
    typed_input["header"]["proposal_id"] += "-FORGED"


def _mutate_action(
    deployment: dict[str, object],
    typed_input: dict[str, object],
    finalized_run: dict[str, object],
) -> None:
    del deployment, typed_input
    finalized_run["prepared"]["action"] = "OfficialX402SettlementV1"


def _mutate_envelope(
    deployment: dict[str, object],
    typed_input: dict[str, object],
    finalized_run: dict[str, object],
) -> None:
    del deployment, typed_input
    finalized_run["prepared"]["envelope_hash"] = "ff" * 32


def _mutate_deploy(
    deployment: dict[str, object],
    typed_input: dict[str, object],
    finalized_run: dict[str, object],
) -> None:
    del deployment, typed_input
    finalized_run["steps"][0]["deploy_hash"] = "ff" * 32


def _mutate_deployment_evidence(
    deployment: dict[str, object],
    typed_input: dict[str, object],
    finalized_run: dict[str, object],
) -> None:
    del typed_input, finalized_run
    deployment["status"] = "operator_asserted"


@pytest.mark.parametrize(
    ("evidence", "mutate"),
    [
        ("network", _mutate_network),
        ("package", _mutate_package),
        ("contract", _mutate_contract),
        ("domain", _mutate_domain),
        ("proposal", _mutate_proposal),
        ("action", _mutate_action),
        ("envelope", _mutate_envelope),
        ("deploy", _mutate_deploy),
        ("deployment", _mutate_deployment_evidence),
    ],
)
def test_composer_fails_closed_before_write_on_cross_evidence_mismatch(
    evidence: str,
    mutate: Callable[
        [dict[str, object], dict[str, object], dict[str, object]], None
    ],
    native_proof: dict[str, object],
    tmp_path: Path,
) -> None:
    composer = _composer()
    deployment, typed_input, finalized_run = _documents(native_proof)
    mutate(deployment, typed_input, finalized_run)
    output = tmp_path / f"{evidence}-proof.json"

    with pytest.raises(composer.ProofCompositionError):
        composer.write_v3_release_proof(
            output=output,
            deployment=deployment,
            typed_input=typed_input,
            finalized_run=finalized_run,
        )

    assert not output.exists()


def test_composer_rejects_secret_bearing_extra_fields_without_echoing_secret(
    native_proof: dict[str, object],
) -> None:
    composer = _composer()
    deployment, typed_input, finalized_run = _documents(native_proof)
    sentinel = "DO-NOT-ECHO-THIS-PRIVATE-KEY"
    finalized_run["private_key"] = sentinel

    with pytest.raises(composer.ProofCompositionError) as caught:
        composer.compose_v3_release_proof(
            deployment=deployment,
            typed_input=typed_input,
            finalized_run=finalized_run,
        )

    assert sentinel not in str(caught.value)


def test_existing_verifier_must_accept_before_atomic_writer_is_called(
    native_proof: dict[str, object],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    composer = _composer()
    deployment, typed_input, finalized_run = _documents(native_proof)
    events: list[str] = []

    def reject(_: object) -> dict[str, object]:
        events.append("verify")
        raise ProofVerificationError("independent verifier rejected proof")

    def write(_: Path, __: object) -> None:
        events.append("write")

    monkeypatch.setattr(composer, "verify_v3_proof_document", reject)
    monkeypatch.setattr(composer, "_atomic_write_json_once", write)

    with pytest.raises(
        composer.ProofCompositionError, match="independent verifier rejected proof"
    ):
        composer.write_v3_release_proof(
            output=tmp_path / "proof.json",
            deployment=deployment,
            typed_input=typed_input,
            finalized_run=finalized_run,
        )

    assert events == ["verify"]


def test_atomic_write_once_refuses_a_destination_created_during_verification(
    native_proof: dict[str, object],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    composer = _composer()
    deployment, typed_input, finalized_run = _documents(native_proof)
    output = tmp_path / "proof.json"
    raced_content = b"another process won the write-once race\n"

    def race(_: object) -> dict[str, object]:
        output.write_bytes(raced_content)
        return {
            "schema_id": "concordia.v3-proof-verification.v1",
            "valid": True,
        }

    monkeypatch.setattr(composer, "verify_v3_proof_document", race)

    with pytest.raises(composer.ProofCompositionError, match="overwrite|exists"):
        composer.write_v3_release_proof(
            output=output,
            deployment=deployment,
            typed_input=typed_input,
            finalized_run=finalized_run,
        )

    assert output.read_bytes() == raced_content


def test_cli_requires_explicit_output_and_writes_mode_0600_atomically(
    native_proof: dict[str, object],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    composer = _composer()
    deployment, typed_input, finalized_run = _documents(native_proof)
    deployment_path = tmp_path / "deployment.json"
    input_path = tmp_path / "input.json"
    run_path = tmp_path / "run.json"
    output = tmp_path / "nested" / "proof.json"
    for path, document in (
        (deployment_path, deployment),
        (input_path, typed_input),
        (run_path, finalized_run),
    ):
        path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(SystemExit) as missing_output:
        composer.main(
            [
                "--deployment",
                str(deployment_path),
                "--input",
                str(input_path),
                "--run",
                str(run_path),
            ]
        )
    assert missing_output.value.code == 2

    assert (
        composer.main(
            [
                "--deployment",
                str(deployment_path),
                "--input",
                str(input_path),
                "--run",
                str(run_path),
                "--out",
                str(output),
            ]
        )
        == 0
    )

    written = json.loads(output.read_text(encoding="utf-8"))
    assert written == json.loads(json.dumps(native_proof))
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert list(output.parent.glob("proof.json.*.tmp")) == []
    assert json.loads(capsys.readouterr().out)["written"] is True


def test_cli_refuses_even_identical_overwrite_and_preserves_existing_bytes(
    native_proof: dict[str, object],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    composer = _composer()
    deployment, typed_input, finalized_run = _documents(native_proof)
    paths = {
        "deployment": tmp_path / "deployment.json",
        "input": tmp_path / "input.json",
        "run": tmp_path / "run.json",
    }
    for label, document in (
        ("deployment", deployment),
        ("input", typed_input),
        ("run", finalized_run),
    ):
        paths[label].write_text(json.dumps(document), encoding="utf-8")
    output = tmp_path / "proof.json"
    original = b'{"existing":"write-once"}\n'
    output.write_bytes(original)

    assert (
        composer.main(
            [
                "--deployment",
                str(paths["deployment"]),
                "--input",
                str(paths["input"]),
                "--run",
                str(paths["run"]),
                "--out",
                str(output),
            ]
        )
        == 1
    )

    assert output.read_bytes() == original
    assert "overwrite" in capsys.readouterr().err


def test_cli_rejects_duplicate_json_keys_before_composition(
    native_proof: dict[str, object],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    composer = _composer()
    _, typed_input, finalized_run = _documents(native_proof)
    deployment_path = tmp_path / "deployment.json"
    deployment_path.write_text(
        '{"schema_id":"first","schema_id":"second"}', encoding="utf-8"
    )
    input_path = tmp_path / "input.json"
    input_path.write_text(json.dumps(typed_input), encoding="utf-8")
    run_path = tmp_path / "run.json"
    run_path.write_text(json.dumps(finalized_run), encoding="utf-8")
    output = tmp_path / "proof.json"

    assert (
        composer.main(
            [
                "--deployment",
                str(deployment_path),
                "--input",
                str(input_path),
                "--run",
                str(run_path),
                "--out",
                str(output),
            ]
        )
        == 1
    )

    assert not output.exists()
    assert "duplicate JSON field" in capsys.readouterr().err
