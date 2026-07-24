"""CLI tests for the offline NativeTransferV1 production-input builder."""

from __future__ import annotations

import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import build_native_transfer_v3_input as builder_cli
from scripts.prepare_v3_envelope import prepare_v3_envelope
from tests.native_transfer_input_fixtures import (
    canonical_bytes,
    source_documents,
    write_source_documents,
)


def _arguments(paths: dict[str, Path], output: Path) -> list[str]:
    return [
        "--historical-receipt",
        str(paths["historical"]),
        "--historical-inventory",
        str(paths["inventory"]),
        "--canonical-receipt",
        str(paths["canonical_receipt"]),
        "--deployment-manifest",
        str(paths["deployment"]),
        "--treasury-snapshot",
        str(paths["snapshot"]),
        "--intent",
        str(paths["intent"]),
        "--out-dir",
        str(output),
    ]


def _sources(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[dict[str, object], dict[str, Path]]:
    documents = source_documents(monkeypatch)
    source_root = tmp_path / "sources"
    source_root.mkdir(mode=0o700)
    return documents, write_source_documents(source_root, documents)


def test_direct_script_entrypoint_imports_from_repository_root() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(
                Path(__file__).resolve().parents[1]
                / "scripts/build_native_transfer_v3_input.py"
            ),
            "--help",
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        check=False,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "--historical-receipt" in completed.stdout
    assert "--out-dir" in completed.stdout


def test_cli_builds_two_private_files_accepted_by_prepare_v3_envelope(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, paths = _sources(monkeypatch, tmp_path)
    output = tmp_path / "native-transfer-input"

    assert builder_cli.main(_arguments(paths, output)) == 0

    typed_path = output / "typed-input.json"
    manifest_path = output / "derivation-manifest.json"
    assert sorted(path.name for path in output.iterdir()) == [
        "derivation-manifest.json",
        "typed-input.json",
    ]
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert stat.S_IMODE(typed_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o600
    typed = json.loads(typed_path.read_bytes())
    manifest = json.loads(manifest_path.read_bytes())
    prepared = prepare_v3_envelope(typed)
    assert manifest["derived"]["envelope_hash"] == prepared["envelope_hash"]
    assert json.loads(capsys.readouterr().out) == {
        "derivation_manifest": str(manifest_path),
        "output_directory": str(output),
        "typed_input": str(typed_path),
    }


def test_cli_output_is_byte_deterministic_for_identical_source_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, paths = _sources(monkeypatch, tmp_path)
    first = tmp_path / "first"
    second = tmp_path / "second"

    assert builder_cli.main(_arguments(paths, first)) == 0
    capsys.readouterr()
    assert builder_cli.main(_arguments(paths, second)) == 0

    assert (first / "typed-input.json").read_bytes() == (
        second / "typed-input.json"
    ).read_bytes()
    assert (first / "derivation-manifest.json").read_bytes() == (
        second / "derivation-manifest.json"
    ).read_bytes()


def test_cli_refuses_existing_output_without_changing_it(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, paths = _sources(monkeypatch, tmp_path)
    output = tmp_path / "existing"
    output.mkdir()
    sentinel = output / "keep.txt"
    sentinel.write_bytes(b"untouched\n")

    with pytest.raises(SystemExit) as refusal:
        builder_cli.main(_arguments(paths, output))

    assert refusal.value.code == 2
    assert sentinel.read_bytes() == b"untouched\n"
    assert list(output.iterdir()) == [sentinel]


def test_cli_validation_failure_leaves_no_output_or_temporary_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    documents, paths = _sources(monkeypatch, tmp_path)
    receipt = json.loads(documents["canonical_receipt"])
    receipt["plan_hash"] = "fe" * 32
    paths["canonical_receipt"].write_bytes(canonical_bytes(receipt))
    output = tmp_path / "must-not-exist"

    with pytest.raises(SystemExit) as refusal:
        builder_cli.main(_arguments(paths, output))

    assert refusal.value.code == 2
    assert not output.exists()
    assert list(tmp_path.glob(f".{output.name}.*.tmp")) == []


def test_cli_refuses_relative_output_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, paths = _sources(monkeypatch, tmp_path)

    with pytest.raises(SystemExit) as refusal:
        builder_cli.main(_arguments(paths, Path("relative-output")))

    assert refusal.value.code == 2
    assert not (tmp_path / "relative-output").exists()


def test_cli_refuses_missing_output_parent_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, paths = _sources(monkeypatch, tmp_path)
    output = tmp_path / "missing-parent" / "output"

    with pytest.raises(SystemExit) as refusal:
        builder_cli.main(_arguments(paths, output))

    assert refusal.value.code == 2
    assert "Traceback" not in capsys.readouterr().err
    assert not output.exists()


def test_cli_refuses_any_output_inside_repository_live_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, paths = _sources(monkeypatch, tmp_path)
    live_output = builder_cli.REPOSITORY_ROOT / "artifacts/live/native-input"

    with pytest.raises(SystemExit) as refusal:
        builder_cli.main(_arguments(paths, live_output))

    assert refusal.value.code == 2
    assert not live_output.exists()


def test_cli_refuses_symlinked_source_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, paths = _sources(monkeypatch, tmp_path)
    real_intent = paths["intent"]
    linked_intent = tmp_path / "intent-link.json"
    linked_intent.symlink_to(real_intent)
    paths["intent"] = linked_intent
    output = tmp_path / "must-not-exist"

    with pytest.raises(SystemExit) as refusal:
        builder_cli.main(_arguments(paths, output))

    assert refusal.value.code == 2
    assert not output.exists()


def test_atomic_publisher_removes_temporary_directory_after_write_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, paths = _sources(monkeypatch, tmp_path)
    output = tmp_path / "must-not-exist"
    original = builder_cli._write_private_file
    calls = 0

    def fail_second(directory_fd: int, name: str, payload: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated write failure")
        original(directory_fd, name, payload)

    monkeypatch.setattr(builder_cli, "_write_private_file", fail_second)

    with pytest.raises(SystemExit) as refusal:
        builder_cli.main(_arguments(paths, output))

    assert refusal.value.code == 2
    assert not output.exists()
    assert list(tmp_path.glob(f".{output.name}.*.tmp")) == []
