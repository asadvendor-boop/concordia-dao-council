from __future__ import annotations

import importlib.util
import json
import os
import stat
from pathlib import Path
from types import ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/generate_x402_governance_v3_config.py"


def _load_module() -> ModuleType:
    assert SCRIPT.is_file(), "the production governance-config generator is missing"
    spec = importlib.util.spec_from_file_location("generate_x402_governance_v3_config", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _proof() -> dict[str, object]:
    return {
        "schema_id": "concordia.v3-proof.v1",
        "deployment": {},
        "input": {
            "schema_id": "concordia.exact-envelope-v3.input.v1",
            "action": "OfficialX402SettlementV1",
            "header": {"deployment_domain": "33" * 32},
            "body": {"caip2_network": "casper:casper-test"},
        },
        "prepared": {},
        "run": {},
        "readback": {},
    }


def _verification() -> dict[str, object]:
    return {
        "schema_id": "concordia.v3-proof-verification.v1",
        "valid": True,
        "network": "casper-test",
        "package_hash": "11" * 32,
        "contract_hash": "22" * 32,
    }


def test_config_is_derived_only_after_the_v3_proof_verifier_accepts(monkeypatch) -> None:
    module = _load_module()
    proof = _proof()
    observed: list[object] = []

    def verified(document: object) -> dict[str, object]:
        observed.append(document)
        return _verification()

    monkeypatch.setattr(module, "verify_v3_proof_document", verified)

    assert module.derive_x402_governance_v3_config(proof) == {
        "schema_version": "concordia.x402-governance-v3-binding.v1",
        "network": "casper:casper-test",
        "package_hash": "11" * 32,
        "contract_hash": "22" * 32,
        "deployment_domain": "33" * 32,
    }
    assert observed == [proof]


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (
            lambda proof: proof["input"].__setitem__("action", "NativeTransferV1"),
            "OfficialX402SettlementV1",
        ),
        (
            lambda proof: proof["input"]["body"].__setitem__(
                "caip2_network", "casper-test"
            ),
            "casper:casper-test",
        ),
    ],
)
def test_non_official_or_non_caip2_proof_is_refused(
    monkeypatch, mutation, match
) -> None:
    module = _load_module()
    proof = _proof()
    mutation(proof)
    monkeypatch.setattr(
        module, "verify_v3_proof_document", lambda _proof: _verification()
    )

    with pytest.raises(module.GovernanceConfigError, match=match):
        module.derive_x402_governance_v3_config(proof)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_id", "wrong"),
        ("valid", False),
        ("network", "casper"),
        ("package_hash", "not-a-hash"),
        ("contract_hash", "AA" * 32),
    ],
)
def test_non_exact_verifier_result_is_refused(
    monkeypatch, field: str, value: object
) -> None:
    module = _load_module()
    verification = _verification()
    verification[field] = value
    monkeypatch.setattr(
        module, "verify_v3_proof_document", lambda _proof: verification
    )

    with pytest.raises(module.GovernanceConfigError):
        module.derive_x402_governance_v3_config(_proof())


def test_invalid_deployment_domain_is_refused_after_verification(monkeypatch) -> None:
    module = _load_module()
    proof = _proof()
    proof["input"]["header"]["deployment_domain"] = "ab"
    monkeypatch.setattr(
        module, "verify_v3_proof_document", lambda _proof: _verification()
    )

    with pytest.raises(module.GovernanceConfigError, match="deployment_domain"):
        module.derive_x402_governance_v3_config(proof)


def test_write_is_canonical_atomic_create_once_and_mode_0600(
    tmp_path: Path, monkeypatch
) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module, "verify_v3_proof_document", lambda _proof: _verification()
    )
    output = tmp_path / "runtime-config" / "x402-governance-v3.json"

    config = module.write_x402_governance_v3_config(
        proof=_proof(),
        output=output,
    )

    expected = json.dumps(
        config,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    assert output.read_bytes() == expected
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert list(output.parent.iterdir()) == [output]

    original = output.read_bytes()
    with pytest.raises(module.GovernanceConfigError, match="overwrite"):
        module.write_x402_governance_v3_config(
            proof=_proof(),
            output=output,
        )
    assert output.read_bytes() == original


def test_existing_symlink_output_is_refused_without_touching_target(
    tmp_path: Path, monkeypatch
) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module, "verify_v3_proof_document", lambda _proof: _verification()
    )
    target = tmp_path / "target.json"
    target.write_text("untouched", encoding="utf-8")
    output = tmp_path / "x402-governance-v3.json"
    output.symlink_to(target)

    with pytest.raises(module.GovernanceConfigError, match="symlink|overwrite"):
        module.write_x402_governance_v3_config(
            proof=_proof(),
            output=output,
        )

    assert target.read_text(encoding="utf-8") == "untouched"
    assert output.is_symlink()


def test_symlinked_output_directory_is_refused(tmp_path: Path, monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module, "verify_v3_proof_document", lambda _proof: _verification()
    )
    target_directory = tmp_path / "target"
    target_directory.mkdir()
    linked_directory = tmp_path / "runtime-config"
    linked_directory.symlink_to(target_directory, target_is_directory=True)

    with pytest.raises(module.GovernanceConfigError, match="directory.*symlink"):
        module.write_x402_governance_v3_config(
            proof=_proof(),
            output=linked_directory / "x402-governance-v3.json",
        )
    assert list(target_directory.iterdir()) == []


def test_cli_reads_one_proof_and_reports_the_exact_written_sha256(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module, "verify_v3_proof_document", lambda _proof: _verification()
    )
    proof_path = tmp_path / "official-v3-proof.json"
    proof_path.write_text(json.dumps(_proof()), encoding="utf-8")
    output = tmp_path / "x402-governance-v3.json"

    assert (
        module.main(
            [
                "--proof",
                os.fspath(proof_path),
                "--out",
                os.fspath(output),
            ]
        )
        == 0
    )

    summary = json.loads(capsys.readouterr().out)
    assert summary == {
        "config_sha256": module.hash_file(output),
        "output": os.fspath(output),
        "status": "written",
    }


def test_duplicate_json_fields_and_nonstandard_constants_are_refused(
    tmp_path: Path, capsys
) -> None:
    module = _load_module()
    output = tmp_path / "x402-governance-v3.json"

    for name, document in (
        ("duplicate", '{"schema_id":"one","schema_id":"two"}'),
        ("constant", '{"schema_id":NaN}'),
    ):
        proof_path = tmp_path / f"{name}.json"
        proof_path.write_text(document, encoding="utf-8")
        assert (
            module.main(
                [
                    "--proof",
                    os.fspath(proof_path),
                    "--out",
                    os.fspath(output),
                ]
            )
            == 1
        )
        report = json.loads(capsys.readouterr().out)
        assert report["status"] == "refused"
        assert not output.exists()


def test_cli_exposes_no_caller_supplied_governance_identity_arguments() -> None:
    module = _load_module()
    parser = module.build_parser()
    destinations = {action.dest for action in parser._actions}

    assert destinations == {"help", "proof", "out"}
    assert not {
        "network",
        "package_hash",
        "contract_hash",
        "deployment_domain",
    } & destinations
