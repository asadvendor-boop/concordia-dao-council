"""Runtime proof bytes must be mounted, immutable, and internally consistent."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
DOCKERIGNORE = ROOT / ".dockerignore"
ENTRYPOINT = ROOT / "docker/entrypoint.sh"
COMPOSE = ROOT / "deploy/shared-host/compose.prod.yml"


def _compose() -> dict[str, object]:
    value = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _write_json(path: Path, value: object) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("ascii")
    path.write_bytes(raw)
    return raw


def _mounted_release(tmp_path: Path) -> tuple[Path, Path]:
    artifacts = tmp_path / "artifacts"
    live = artifacts / "live"
    rwa = artifacts / "rwa"
    live.mkdir(parents=True)
    rwa.mkdir()

    for relative in (
        "live/casper-final-receipt-cspr-live.json",
        "live/odra-topology-genesis-proof.json",
        "live/odra-quorum-exercise-plan.json",
        "rwa/sample-invoice-pool-DAO-PROP-RWA-001.json",
    ):
        _write_json(artifacts / relative, {"fixture": relative})

    roots_raw = _write_json(
        live / "card-chain-roots-v1.json",
        {
            "schema_version": "concordia.card_chain_roots.v1",
            "roots": {"DAO-PROP-6CB25C": "11" * 32},
        },
    )
    registry = tmp_path / "selected-registry"
    _write_json(
        registry / "registry.json",
        {
            "schema_version": 1,
            "public_items": [],
            "internal_records": [],
            "card_chain_roots": {
                "artifact_path": "artifacts/live/card-chain-roots-v1.json",
                "artifact_sha256": hashlib.sha256(roots_raw).hexdigest(),
            },
        },
    )
    return artifacts, registry


def test_python_runtime_image_contains_no_proof_or_release_artifact_bytes() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    dockerignore = DOCKERIGNORE.read_text(encoding="utf-8").splitlines()

    assert "COPY artifacts/live" not in dockerfile
    assert "COPY artifacts/rwa" not in dockerfile
    assert "artifacts/" in dockerignore


def test_gateway_has_two_mandatory_release_scoped_read_only_directory_binds() -> None:
    gateway = _compose()["services"]["gateway"]
    environment = gateway["environment"]

    assert environment["CONCORDIA_RELEASE_ARTIFACTS_DIR"] == "/app/artifacts"
    assert environment["CONCORDIA_PROOF_REGISTRY_DIR"] == (
        "/run/config/proof-registry"
    )
    assert environment["CONCORDIA_CARD_CHAIN_ROOTS_FILE"] == (
        "/app/artifacts/live/card-chain-roots-v1.json"
    )
    assert gateway["volumes"] == [
        "concordia-data:/data",
        {
            "type": "bind",
            "source": (
                "${CONCORDIA_RELEASE_ARTIFACTS_HOST_DIR:"
                "?Set CONCORDIA_RELEASE_ARTIFACTS_HOST_DIR}"
            ),
            "target": "/app/artifacts",
            "read_only": True,
            "bind": {"create_host_path": False},
        },
        {
            "type": "bind",
            "source": (
                "${CONCORDIA_PROOF_REGISTRY_HOST_DIR:"
                "?Set CONCORDIA_PROOF_REGISTRY_HOST_DIR}"
            ),
            "target": "/run/config/proof-registry",
            "read_only": True,
            "bind": {"create_host_path": False},
        },
    ]


def test_release_artifact_directories_are_not_mounted_into_other_services() -> None:
    services = _compose()["services"]
    for service_name, service in services.items():
        if service_name == "gateway":
            continue
        for volume in service.get("volumes", []):
            if isinstance(volume, str):
                rendered = volume
            else:
                rendered = json.dumps(volume, sort_keys=True)
            assert "CONCORDIA_RELEASE_ARTIFACTS_HOST_DIR" not in rendered
            assert "CONCORDIA_PROOF_REGISTRY_HOST_DIR" not in rendered
            assert "/app/artifacts" not in rendered
            assert "/run/config/proof-registry" not in rendered


def test_gateway_entrypoint_validates_mounts_before_starting_uvicorn() -> None:
    entrypoint = ENTRYPOINT.read_text(encoding="utf-8")
    validation = "python -m shared.runtime_release_mounts"
    uvicorn = "uvicorn gateway.app:app"

    assert validation in entrypoint
    assert entrypoint.index(validation) < entrypoint.index(uvicorn)


def test_runtime_mount_validator_accepts_one_consistent_selected_registry(
    tmp_path: Path,
) -> None:
    from shared.runtime_release_mounts import validate_runtime_release_mounts

    artifacts, registry = _mounted_release(tmp_path)

    result = validate_runtime_release_mounts(
        artifacts_dir=artifacts,
        proof_registry_dir=registry,
        card_chain_roots_file=artifacts / "live/card-chain-roots-v1.json",
    )

    assert result == {
        "artifact_root": "/app/artifacts",
        "proof_registry": "/run/config/proof-registry",
        "registry_documents": 1,
        "status": "ready",
    }


@pytest.mark.parametrize(
    "missing",
    ["artifact_root", "registry_root", "registry_file", "historical_file"],
)
def test_runtime_mount_validator_refuses_missing_release_inputs(
    tmp_path: Path,
    missing: str,
) -> None:
    from shared.runtime_release_mounts import (
        RuntimeReleaseMountError,
        validate_runtime_release_mounts,
    )

    artifacts, registry = _mounted_release(tmp_path)
    artifacts_arg = artifacts
    registry_arg = registry
    if missing == "artifact_root":
        artifacts_arg = tmp_path / "missing-artifacts"
    elif missing == "registry_root":
        registry_arg = tmp_path / "missing-registry"
    elif missing == "registry_file":
        (registry / "registry.json").unlink()
    else:
        (artifacts / "live/odra-quorum-exercise-plan.json").unlink()

    with pytest.raises(RuntimeReleaseMountError):
        validate_runtime_release_mounts(
            artifacts_dir=artifacts_arg,
            proof_registry_dir=registry_arg,
            card_chain_roots_file=artifacts
            / "live/card-chain-roots-v1.json",
        )


@pytest.mark.parametrize(
    "unsafe",
    ["artifact_root_symlink", "registry_symlink", "extra_registry", "bad_registry"],
)
def test_runtime_mount_validator_refuses_unsafe_or_ambiguous_inputs(
    tmp_path: Path,
    unsafe: str,
) -> None:
    from shared.runtime_release_mounts import (
        RuntimeReleaseMountError,
        validate_runtime_release_mounts,
    )

    artifacts, registry = _mounted_release(tmp_path)
    artifacts_arg = artifacts
    registry_arg = registry
    if unsafe == "artifact_root_symlink":
        artifacts_arg = tmp_path / "artifact-link"
        artifacts_arg.symlink_to(artifacts, target_is_directory=True)
    elif unsafe == "registry_symlink":
        registry_arg = tmp_path / "registry-link"
        registry_arg.symlink_to(registry, target_is_directory=True)
    elif unsafe == "extra_registry":
        _write_json(
            registry / "second.json",
            {"schema_version": 1, "public_items": [], "internal_records": []},
        )
    else:
        (registry / "registry.json").write_text(
            '{"schema_version":1,"schema_version":1}\n',
            encoding="ascii",
        )

    with pytest.raises(RuntimeReleaseMountError):
        validate_runtime_release_mounts(
            artifacts_dir=artifacts_arg,
            proof_registry_dir=registry_arg,
            card_chain_roots_file=artifacts
            / "live/card-chain-roots-v1.json",
        )


def test_runtime_mount_validator_refuses_registry_to_artifact_digest_drift(
    tmp_path: Path,
) -> None:
    from shared.runtime_release_mounts import (
        RuntimeReleaseMountError,
        validate_runtime_release_mounts,
    )

    artifacts, registry = _mounted_release(tmp_path)
    roots = artifacts / "live/card-chain-roots-v1.json"
    roots.write_bytes(roots.read_bytes() + b" ")

    with pytest.raises(RuntimeReleaseMountError, match="card-chain roots"):
        validate_runtime_release_mounts(
            artifacts_dir=artifacts,
            proof_registry_dir=registry,
            card_chain_roots_file=roots,
        )


def test_runtime_mount_entrypoint_refuses_incomplete_configuration(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from shared.runtime_release_mounts import main

    for name in (
        "CONCORDIA_RELEASE_ARTIFACTS_DIR",
        "CONCORDIA_PROOF_REGISTRY_DIR",
        "CONCORDIA_CARD_CHAIN_ROOTS_FILE",
    ):
        monkeypatch.delenv(name, raising=False)

    assert main() == 78
    assert json.loads(capsys.readouterr().err) == {
        "error": "runtime release mount configuration is incomplete",
        "status": "blocked",
    }


def test_runtime_mount_entrypoint_reports_only_safe_ready_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from shared.runtime_release_mounts import main

    artifacts, registry = _mounted_release(tmp_path)
    monkeypatch.setenv("CONCORDIA_RELEASE_ARTIFACTS_DIR", str(artifacts))
    monkeypatch.setenv("CONCORDIA_PROOF_REGISTRY_DIR", str(registry))
    monkeypatch.setenv(
        "CONCORDIA_CARD_CHAIN_ROOTS_FILE",
        str(artifacts / "live/card-chain-roots-v1.json"),
    )

    assert main() == 0
    assert json.loads(capsys.readouterr().out) == {
        "artifact_root": "/app/artifacts",
        "proof_registry": "/run/config/proof-registry",
        "registry_documents": 1,
        "status": "ready",
    }
