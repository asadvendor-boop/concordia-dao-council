from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import time
import types
from pathlib import Path

import pytest

from scripts import release_gate_runner, run_g11_claim_audit
from scripts.release_gate_runner import GateRunError, run_gate
from scripts.run_g11_claim_audit import ClaimAuditError, verify_claim_artifacts
from shared import release_gate_contract
from shared import g11_claim_policy_authority
from shared.proof_registry import REQUIRED_CHECKS_BY_PROOF_TYPE
from shared.release_gate_contract import (
    COMMAND_GATE_COMMANDS,
    COMMAND_GATE_NORMALIZATION,
    COMMAND_GATE_PRODUCED_ARTIFACT_PATHS,
    COMMAND_GATE_RECEIPT_PATHS,
    COMMAND_GATE_REQUIRED_RUNTIMES,
    COMMAND_GATE_RUNNER_PATHS,
    collector_contract_sha256,
)


FROZEN_COLLECTOR_CONTRACT_SHA256 = (
    "1d7a7a38ff0cf103783a27269fa1d4347237fd873a154c1f9f509397acb710a0"
)
NOW = "2026-07-23T00:00:00Z"
OTHER = "2026-07-23T00:00:01Z"
EXPECTED_RUNTIME_VERSIONS = {
    "cargo": "cargo 1.86.0-nightly (cecde95c1 2025-01-24)",
    "node": "v22.12.0",
    "npm": "11.6.2",
    "odra": "cargo-odra 0.1.7",
    "pytest": "pytest 9.0.3",
    "python": "Python 3.12.11",
    "rustc": (
        "rustc 1.86.0-nightly (854f22563 2025-01-31)\n"
        "binary: rustc\n"
        "commit-hash: 854f22563c8daf92709fae18ee6aed52953835cd\n"
        "commit-date: 2025-01-31\n"
        "host: aarch64-apple-darwin\n"
        "release: 1.86.0-nightly\n"
        "LLVM version: 19.1.7"
    ),
    "uv": "uv 0.10.12 (00d72dac7 2026-03-19 aarch64-apple-darwin)",
    "next": "Next.js v16.2.11",
    "playwright": "Version 1.58.2",
}


def _git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _write(repository: Path, relative: str, raw: bytes) -> None:
    target = repository / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _gate_repository(tmp_path: Path, gate_id: str) -> tuple[Path, str, str]:
    repository = tmp_path / "repository"
    repository.mkdir(parents=True)
    _git(repository, "init", "-b", "main")
    _git(repository, "config", "user.name", "Gate Test")
    _git(repository, "config", "user.email", "gate@example.invalid")

    identity_paths = {
        path
        for paths in release_gate_contract.COMMAND_GATE_IDENTITY_PATHS.values()
        for path in paths
        if path != "handoff/G11_CLAIM_POLICY.json"
    }
    for identity_path in identity_paths:
        if identity_path == "deploy/shared-host/compose.prod.yml":
            _write(repository, identity_path, b"services: {}\nsecrets: {}\n")
        else:
            _write(repository, identity_path, b"#!/usr/bin/env python3\n")
    for _, working_directory, _ in COMMAND_GATE_COMMANDS[gate_id]:
        if working_directory != ".":
            _write(repository, f"{working_directory}/.gate-test-keep", b"fixture\n")
    if gate_id == "G9":
        _write(repository, "dashboard/.gitignore", b".next/\nnode_modules/\n")
        for executable in ("next", "playwright"):
            target = repository / f"dashboard/node_modules/.bin/{executable}"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"#!/bin/sh\necho tool-test-1.0\n")
            target.chmod(0o755)
    _write(repository, "shared/release_gate_contract.py", b"# frozen contract\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "gate runners")
    frozen_commit = _git(repository, "rev-parse", "HEAD")
    _git(
        repository,
        "tag",
        "-a",
        "concordia-g1-freeze-v2.0-a",
        "-m",
        "G1 freeze",
        frozen_commit,
    )
    release_gate_runner.G1_FREEZE_COMMIT = frozen_commit
    release_gate_runner.G1_FREEZE_TAG_OBJECT = _git(
        repository, "rev-parse", "concordia-g1-freeze-v2.0-a^{tag}"
    )

    for relative in COMMAND_GATE_PRODUCED_ARTIFACT_PATHS[gate_id]:
        _write(repository, relative, f"{gate_id}:{relative}\n".encode())
    _write(repository, "integration.marker", b"integration\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "integration outputs")
    return repository, frozen_commit, _git(repository, "rev-parse", "HEAD")


class _SuccessfulExecutor:
    def __init__(self, repository: Path) -> None:
        self.repository = repository
        self.calls: list[tuple[tuple[str, ...], Path, dict[str, str], int]] = []

    def __call__(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        env: dict[str, str],
        timeout: int,
        resolved_executable: str | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        del resolved_executable
        self.calls.append((argv, cwd, env, timeout))
        runtime: str | None = None
        if argv == ("cargo", "--version"):
            runtime = "cargo"
        elif argv == ("node", "--version"):
            runtime = "node"
        elif argv == ("npm", "--version"):
            runtime = "npm"
        elif argv == ("cargo", "odra", "--version"):
            runtime = "odra"
        elif argv[-4:] == ("python", "-m", "pytest", "--version"):
            runtime = "pytest"
        elif argv[-2:] == ("python", "--version"):
            runtime = "python"
        elif argv == ("rustc", "-vV"):
            runtime = "rustc"
        elif argv == ("uv", "--version"):
            runtime = "uv"
        elif argv == ("node_modules/.bin/next", "--version"):
            runtime = "next"
        elif argv == ("node_modules/.bin/playwright", "--version"):
            runtime = "playwright"
        if runtime is not None:
            stdout = (EXPECTED_RUNTIME_VERSIONS[runtime] + "\n").encode()
        else:
            stdout = (
                f"passed in {self.repository}\r\ntemporary files at {env['TMPDIR']}\r"
            ).encode()
        return subprocess.CompletedProcess(argv, 0, stdout, b"")


def test_shared_contract_is_exact_immutable_and_matches_collector_hash() -> None:
    assert COMMAND_GATE_COMMANDS == {
        "G2": (
            (
                "python_components",
                ".",
                (
                    "uv",
                    "run",
                    "--frozen",
                    "--isolated",
                    "--python",
                    "python3.12",
                    "python",
                    "-m",
                    "pytest",
                    "-q",
                ),
            ),
            (
                "v3_rust",
                "contracts/odra-governance-receipt-v3",
                ("cargo", "test", "--locked"),
            ),
            (
                "v3_wasm",
                ".",
                (
                    "uv",
                    "run",
                    "--frozen",
                    "--isolated",
                    "--python",
                    "python3.12",
                    "python",
                    "scripts/run_locked_odra_build.py",
                    "--verify-only",
                ),
            ),
            ("verifier_install", "packages/verify", ("npm", "ci")),
            ("verifier_test", "packages/verify", ("npm", "test")),
            ("verifier_lint", "packages/verify", ("npm", "run", "lint")),
            (
                "verifier_audit",
                "packages/verify",
                ("npm", "audit", "--audit-level=high"),
            ),
            ("official_x402_install", "services/x402-official", ("npm", "ci")),
            (
                "official_x402_build",
                "services/x402-official",
                ("npm", "run", "build"),
            ),
            (
                "official_x402_typecheck",
                "services/x402-official",
                ("npm", "run", "typecheck"),
            ),
            ("official_x402_test", "services/x402-official", ("npm", "test")),
            (
                "official_x402_audit",
                "services/x402-official",
                ("npm", "audit", "--audit-level=high"),
            ),
        ),
        "G9": (
            ("dashboard_install", "dashboard", ("npm", "ci")),
            ("dashboard_build", "dashboard", ("npm", "run", "build")),
            ("dashboard_e2e", "dashboard", ("npm", "run", "test:e2e")),
            (
                "dashboard_audit",
                "dashboard",
                ("npm", "audit", "--audit-level=high"),
            ),
        ),
        "G11": (
            (
                "claim_audit",
                ".",
                (
                    "uv",
                    "run",
                    "--frozen",
                    "--isolated",
                    "--python",
                    "python3.12",
                    "python",
                    "scripts/run_g11_claim_audit.py",
                    "--verify-only",
                ),
            ),
        ),
    }
    assert COMMAND_GATE_RECEIPT_PATHS == {
        "G2": "release/receipts/G2_COMPONENT_GATES.json",
        "G9": "release/receipts/G9_FRONTEND_GATES.json",
        "G11": "release/receipts/G11_CLAIM_AUDIT.json",
    }
    assert COMMAND_GATE_RUNNER_PATHS == {
        "G2": "scripts/run_g2_component_gates.py",
        "G9": "scripts/run_g9_frontend_gates.py",
        "G11": "scripts/run_g11_claim_audit.py",
    }
    assert COMMAND_GATE_REQUIRED_RUNTIMES == {
        "G2": ("cargo", "node", "npm", "odra", "pytest", "python", "rustc", "uv"),
        "G9": ("next", "node", "npm", "playwright"),
        "G11": ("python", "uv"),
    }
    assert COMMAND_GATE_PRODUCED_ARTIFACT_PATHS == {
        "G2": (
            "contracts/odra-governance-receipt-v3/wasm/GovernanceReceiptV3.wasm",
            (
                "contracts/odra-governance-receipt-v3/resources/"
                "casper_contract_schemas/governance_receiptv3_schema.json"
            ),
        ),
        "G9": (
            "dashboard/.next/BUILD_ID",
            "dashboard/.next/build-manifest.json",
            "dashboard/.next/routes-manifest.json",
        ),
        "G11": (
            "README.md",
            "docs/POLICY_TEMPLATES.md",
            "docs/TECHNICAL_JURY_NOTE.md",
            "docs/DORAHACKS_SUBMISSION_TEXT.md",
            "docs/DEMO_SCRIPT.md",
            "docs/CLAIM_TO_ARTIFACT_MAP.json",
        ),
    }
    assert release_gate_contract.G1_FREEZE_COMMIT == (
        "b24c0409023e6c4b56287d4fddc17bdb42d9b1ac"
    )
    assert release_gate_contract.G1_FREEZE_TAG_OBJECT == (
        "65772a09bf73e50f061a2e7728fa5d48538cdc61"
    )
    assert release_gate_contract.COMMAND_GATE_EXECUTABLE_CHAIN_POLICY == {
        "maximum_shebang_depth": 8,
        "bind_shebang_interpreter": True,
        "bind_env_shebang_target": True,
        "uv_python": "python3.12",
        "uv_python_preference": "only-system",
        "cargo_odra_subcommand": "cargo-odra",
        "cargo_compiler": "rustc",
        "cargo_compiler_commands": ("build", "test"),
        "locked_odra_wrapper": "scripts/run_locked_odra_build.py",
        "locked_odra_dependencies": ("cargo", "cargo-odra", "rustc"),
    }
    assert release_gate_contract.COMMAND_GATE_EXPECTED_RUNTIME_VERSIONS == (
        EXPECTED_RUNTIME_VERSIONS
    )
    assert release_gate_contract.COMMAND_GATE_EXECUTION_POLICY == {
        "trusted_git_path": "/usr/bin/git",
        "trusted_git_owner_uid": 0,
        "trusted_git_reject_group_or_other_write": True,
        "working_directory_descriptor_walk": "validation_only_not_execution_binding",
        "working_directory_execution_binding": (
            "path_revalidated_before_and_after_execution"
        ),
        "working_directory_reject_symlink_ancestors": True,
        "bind_resolved_entrypoint_once": True,
        "revalidate_executable_chain_before_and_after": True,
        "output_capture": "bounded_temporary_files",
        "maximum_output_stream_bytes": 64 * 1024 * 1024,
        "darwin_rosetta_native_architecture_detection": True,
        "credential_reversible_encodings": (
            "raw",
            "base64_standard_padded",
            "base64_standard_unpadded",
            "base64_urlsafe_padded",
            "base64_urlsafe_unpadded",
            "hex_lower",
            "hex_upper",
            "percent_upper",
        ),
        "arbitrary_encryption_detection": False,
        "post_receipt_link_full_revalidation": True,
        "receipt_account_home_path_redaction": "tokenized_without_username",
    }
    assert release_gate_contract.BOUND_GIT_CONFIG_OVERRIDES == (
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "diff.external=",
        "-c",
        "core.pager=cat",
        "-c",
        "interactive.diffFilter=",
    )
    assert {
        runtime: working_directory
        for runtime, working_directory, _argv in (
            release_gate_contract.COMMAND_GATE_RUNTIME_PROBES["G2"]
        )
        if runtime in {"cargo", "odra", "rustc"}
    } == {
        "cargo": "contracts/odra-governance-receipt-v3",
        "odra": "contracts/odra-governance-receipt-v3",
        "rustc": "contracts/odra-governance-receipt-v3",
    }
    assert next(
        argv
        for runtime, _working_directory, argv in (
            release_gate_contract.COMMAND_GATE_RUNTIME_PROBES["G2"]
        )
        if runtime == "rustc"
    ) == ("rustc", "-vV")
    assert "--python" in COMMAND_GATE_COMMANDS["G2"][0][2]
    assert "python3.12" in COMMAND_GATE_COMMANDS["G2"][0][2]
    assert release_gate_contract.COMMAND_GATE_FRESH_OUTPUT_PATHS["G9"] == (
        "dashboard/.next",
    )
    assert release_gate_contract.COMMAND_GATE_INPUT_ARTIFACT_PATHS["G11"] == (
        "handoff/G11_CLAIM_POLICY.json",
        "artifacts/live/proof-registry/registry.json",
    )
    assert release_gate_contract.COMMAND_GATE_IDENTITY_PATHS["G2"][-1] == (
        "scripts/run_locked_odra_build.py"
    )
    assert all(
        "shared/bound_command.py"
        in release_gate_contract.COMMAND_GATE_IDENTITY_PATHS[gate_id]
        for gate_id in ("G2", "G9", "G11")
    )
    assert collector_contract_sha256() == FROZEN_COLLECTOR_CONTRACT_SHA256
    with pytest.raises(TypeError):
        COMMAND_GATE_RECEIPT_PATHS["G2"] = "forged.json"  # type: ignore[index]


def test_successful_gate_binds_identity_normalizes_logs_and_writes_exact_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, frozen_commit, integration_commit = _gate_repository(tmp_path, "G2")
    executor = _SuccessfulExecutor(repository)
    monkeypatch.setenv("CONCORDIA_TEST_SECRET_TOKEN", "DO-NOT-FORWARD-CANARY")

    result = run_gate("G2", repository_root=repository, executor=executor)

    receipt_path = repository / COMMAND_GATE_RECEIPT_PATHS["G2"]
    receipt_raw = receipt_path.read_bytes()
    receipt = json.loads(receipt_raw)
    assert receipt_raw == _canonical(receipt)
    assert receipt["schema_version"] == "concordia.command_gate_receipt.v1"
    assert receipt["gate_id"] == "G2"
    assert receipt["frozen_commit"] == frozen_commit
    assert receipt["integration_commit"] == integration_commit
    assert receipt["clean_tree_sha256"] == hashlib.sha256(b"").hexdigest()
    assert receipt["normalization"] == json.loads(
        json.dumps(dict(COMMAND_GATE_NORMALIZATION))
    )
    assert receipt["freeze_tag"]["name"] == release_gate_contract.G1_FREEZE_TAG
    assert receipt["freeze_tag"]["peeled_commit"] == frozen_commit
    assert len(receipt["freeze_tag"]["object"]) == 40
    assert [row["path"] for row in receipt["runner"]] == list(
        release_gate_contract.COMMAND_GATE_IDENTITY_PATHS["G2"]
    )
    assert set(receipt["runtime_versions"]) == set(COMMAND_GATE_REQUIRED_RUNTIMES["G2"])
    assert [row["command_id"] for row in receipt["commands"]] == [
        row[0] for row in COMMAND_GATE_COMMANDS["G2"]
    ]
    assert all("executable_chain" in row for row in receipt["commands"])
    assert all(row["executable_chain"] for row in receipt["commands"])
    assert receipt["executable_chain_schema_version"] == (
        release_gate_contract.COMMAND_GATE_EXECUTABLE_CHAIN_SCHEMA_VERSION
    )
    assert set(receipt["runtime_executable_chains"]) == set(
        COMMAND_GATE_REQUIRED_RUNTIMES["G2"]
    )
    assert [row["path"] for row in receipt["produced_artifacts"]] == list(
        COMMAND_GATE_PRODUCED_ARTIFACT_PATHS["G2"]
    )
    assert receipt["input_artifacts"] == []
    assert receipt["fresh_outputs"] == []
    assert result.receipt_sha256 == hashlib.sha256(receipt_raw).hexdigest()

    expected_logs: set[str] = set()
    for command in receipt["commands"]:
        for stream in ("stdout", "stderr"):
            relative = command[stream]["path"]
            expected_logs.add(Path(relative).name)
            raw = (repository / relative).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == command[stream]["sha256"]
            assert b"\r" not in raw
            assert str(repository).encode() not in raw
            assert b"DO-NOT-FORWARD-CANARY" not in raw
            if stream == "stdout":
                assert b"<REPOSITORY_ROOT>" in raw
                assert b"<TEMP_ROOT>" in raw
    log_directory = repository / "release/receipts/logs/G2"
    assert {path.name for path in log_directory.iterdir()} == expected_logs
    assert all(
        "CONCORDIA_TEST_SECRET_TOKEN" not in environment
        for _, _, environment, _ in executor.calls
    )
    allowed_environment = {
        "CARGO_HOME",
        "CARGO_TARGET_DIR",
        "CI",
        "HOME",
        "LANG",
        "LC_ALL",
        "NO_COLOR",
        "NPM_CONFIG_CACHE",
        "NPM_CONFIG_USERCONFIG",
        "PATH",
        "RUSTUP_HOME",
        "TMPDIR",
        "UV_CACHE_DIR",
        "UV_PYTHON_DOWNLOADS",
        "UV_PYTHON_PREFERENCE",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
    }
    assert all(
        set(environment) <= allowed_environment
        for _, _, environment, _ in executor.calls
    )
    cargo_environment = next(
        environment
        for argv, _, environment, _ in executor.calls
        if argv == ("cargo", "test", "--locked")
    )
    assert cargo_environment["CARGO_TARGET_DIR"] != str(
        repository / "contracts/odra-governance-receipt-v3/target"
    )
    assert str(repository) not in cargo_environment["CARGO_TARGET_DIR"]


@pytest.mark.parametrize("runtime", sorted(EXPECTED_RUNTIME_VERSIONS))
def test_runtime_version_validation_rejects_any_mismatch(runtime: str) -> None:
    expected = EXPECTED_RUNTIME_VERSIONS[runtime]
    release_gate_runner._validate_runtime_version(runtime, expected)
    with pytest.raises(GateRunError, match="toolchain|version"):
        release_gate_runner._validate_runtime_version(runtime, expected + "-forged")


@pytest.mark.parametrize("failure", ["nonzero", "timeout", "secret"])
def test_gate_failure_before_publish_writes_no_receipt_or_logs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    repository, _, _ = _gate_repository(tmp_path, "G2")
    canary = "NO-PERSIST-CANARY-0123456789"
    monkeypatch.setenv("CONCORDIA_TEST_SECRET_TOKEN", canary)

    def executor(
        argv: tuple[str, ...],
        *,
        cwd: Path,
        env: dict[str, str],
        timeout: int,
        resolved_executable: str | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        del cwd, env, timeout, resolved_executable
        if failure == "timeout" and "--version" not in argv:
            raise subprocess.TimeoutExpired(argv, 1)
        if failure == "nonzero" and "--version" not in argv:
            return subprocess.CompletedProcess(argv, 7, b"failed\n", b"boom\n")
        output = canary.encode() if failure == "secret" else b"tool test 1.0\n"
        return subprocess.CompletedProcess(argv, 0, output, b"")

    with pytest.raises(GateRunError):
        run_gate("G2", repository_root=repository, executor=executor)

    assert not (repository / COMMAND_GATE_RECEIPT_PATHS["G2"]).exists()
    assert not (repository / "release/receipts/logs/G2").exists()


def test_gate_rejects_dirty_head_existing_output_and_symlink_ancestor(
    tmp_path: Path,
) -> None:
    dirty_repository, _, _ = _gate_repository(tmp_path / "dirty", "G2")
    _write(dirty_repository, "untracked.txt", b"dirty\n")
    with pytest.raises(GateRunError, match="clean"):
        run_gate(
            "G2",
            repository_root=dirty_repository,
            executor=_SuccessfulExecutor(dirty_repository),
        )

    existing_repository, _, _ = _gate_repository(tmp_path / "existing", "G2")
    existing = existing_repository / COMMAND_GATE_RECEIPT_PATHS["G2"]
    existing.parent.mkdir(parents=True)
    existing.write_bytes(b"preserve\n")
    _git(existing_repository, "add", ".")
    _git(existing_repository, "commit", "-m", "preexisting receipt")
    with pytest.raises(GateRunError, match="exists|overwrite"):
        run_gate(
            "G2",
            repository_root=existing_repository,
            executor=_SuccessfulExecutor(existing_repository),
        )
    assert existing.read_bytes() == b"preserve\n"

    symlink_repository, _, _ = _gate_repository(tmp_path / "symlink", "G2")
    outside = tmp_path / "outside"
    outside.mkdir()
    (symlink_repository / "release").symlink_to(outside, target_is_directory=True)
    _git(symlink_repository, "add", "release")
    _git(symlink_repository, "commit", "-m", "unsafe release symlink")
    with pytest.raises(GateRunError, match="symlink|safe"):
        run_gate(
            "G2",
            repository_root=symlink_repository,
            executor=_SuccessfulExecutor(symlink_repository),
        )
    assert list(outside.iterdir()) == []


def test_gate_requires_annotated_tag_and_exact_peeled_freeze_commit(
    tmp_path: Path,
) -> None:
    repository, frozen_commit, _ = _gate_repository(tmp_path / "lightweight", "G2")
    _git(repository, "tag", "-d", release_gate_contract.G1_FREEZE_TAG)
    _git(repository, "tag", release_gate_contract.G1_FREEZE_TAG, frozen_commit)
    with pytest.raises(GateRunError, match="annotated"):
        run_gate(
            "G2",
            repository_root=repository,
            executor=_SuccessfulExecutor(repository),
        )

    repository2, _, _ = _gate_repository(tmp_path / "peeled", "G2")
    release_gate_runner.G1_FREEZE_COMMIT = "f" * 40
    with pytest.raises(GateRunError, match="freeze"):
        run_gate(
            "G2",
            repository_root=repository2,
            executor=_SuccessfulExecutor(repository2),
        )

    repository3, frozen_commit3, _ = _gate_repository(tmp_path / "retagged", "G2")
    expected_tag_object = release_gate_runner.G1_FREEZE_TAG_OBJECT
    _git(repository3, "tag", "-d", release_gate_contract.G1_FREEZE_TAG)
    _git(
        repository3,
        "tag",
        "-a",
        release_gate_contract.G1_FREEZE_TAG,
        "-m",
        "replacement annotation",
        frozen_commit3,
    )
    assert (
        _git(repository3, "rev-parse", f"{release_gate_contract.G1_FREEZE_TAG}^{{tag}}")
        != expected_tag_object
    )
    with pytest.raises(GateRunError, match="tag object identity"):
        run_gate(
            "G2",
            repository_root=repository3,
            executor=_SuccessfulExecutor(repository3),
        )


@pytest.mark.parametrize("user_bin", [".local/bin", ".cargo/bin"])
def test_git_checks_ignore_user_controlled_path_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    user_bin: str,
) -> None:
    repository, _, _ = _gate_repository(tmp_path / "gate", "G2")
    _write(repository, "untracked.txt", b"dirty\n")
    home = tmp_path / "home"
    fake_bin = home / user_bin
    fake_bin.mkdir(parents=True)
    marker = tmp_path / f"{user_bin.replace('/', '-')}-git-ran"
    fake_git = fake_bin / "git"
    fake_git.write_text(
        f'#!/bin/sh\ntouch "{marker}"\nexec /usr/bin/git "$@"\n',
        encoding="utf-8",
    )
    fake_git.chmod(0o755)
    monkeypatch.setattr(
        release_gate_runner.pwd,
        "getpwuid",
        lambda _uid: types.SimpleNamespace(pw_dir=str(home)),
    )

    with pytest.raises(GateRunError, match="clean"):
        release_gate_runner._preflight_repository(repository, "G2")

    assert not marker.exists()


def test_trusted_git_ignores_repository_fsmonitor_configuration(
    tmp_path: Path,
) -> None:
    repository, _, _ = _gate_repository(tmp_path / "gate", "G2")
    marker = tmp_path / "trusted-git-fsmonitor-executed"
    hook = tmp_path / "fsmonitor-hook"
    hook.write_text(
        f"#!/bin/sh\ntouch {marker.as_posix()!r}\nprintf '2\\n'\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)
    _git(repository, "config", "core.fsmonitor", hook.as_posix())

    output = release_gate_runner._git(
        repository,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
    )

    assert output == b""
    assert not marker.exists()


def test_trusted_git_output_limit_kills_process_group_before_continuation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    fake_git = tmp_path / "git"
    marker = tmp_path / "continued-after-git-overflow"
    fake_git.write_text(
        "#!/bin/sh\n"
        "printf '012345678901234567890123456789012'\n"
        "sleep 0.5\n"
        f'touch "{marker}"\n',
        encoding="utf-8",
    )
    fake_git.chmod(0o755)
    identity = {"sha256": "a" * 64}
    monkeypatch.setattr(release_gate_runner, "_TRUSTED_GIT_PATH", fake_git)
    monkeypatch.setattr(
        release_gate_runner,
        "_trusted_git_identity",
        lambda: identity.copy(),
    )
    monkeypatch.setattr(release_gate_runner, "_GIT_OUTPUT_LIMIT", 32)

    with pytest.raises(GateRunError, match="git identity check failed"):
        release_gate_runner._git(repository, "status", "--porcelain")

    time.sleep(0.7)
    assert not marker.exists()


@pytest.mark.parametrize("unsafe_prefix", ["symlink", "regular_file"])
def test_contract_working_directory_rejects_unsafe_prefix_before_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_prefix: str,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    outside = tmp_path / "outside"
    (outside / "verify").mkdir(parents=True)
    if unsafe_prefix == "symlink":
        (repository / "packages").symlink_to(outside, target_is_directory=True)
    else:
        (repository / "packages").write_bytes(b"not a directory\n")
    monkeypatch.setattr(
        release_gate_runner,
        "COMMAND_GATE_COMMANDS",
        {"G2": (("escape", "packages/verify", ("/usr/bin/true",)),)},
    )
    monkeypatch.setattr(
        release_gate_runner,
        "COMMAND_GATE_TIMEOUT_SECONDS",
        {"G2": (5,)},
    )
    called = False

    def executor(
        argv: tuple[str, ...],
        *,
        cwd: Path,
        env: dict[str, str],
        timeout: int,
        **_kwargs,
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal called
        called = True
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    with pytest.raises(GateRunError, match="working directory|symlink|directory"):
        release_gate_runner._capture_commands(
            "G2",
            repository_root=repository,
            temporary_root=tmp_path / "temporary",
            environment={"PATH": "/usr/bin:/bin"},
            canaries=(),
            executor=executor,
        )

    assert called is False


def test_sensitive_file_environment_is_safely_dereferenced_as_a_canary(
    tmp_path: Path,
) -> None:
    credential = tmp_path / "credential"
    credential.write_bytes(b"FILE-CANARY-0123456789\n")
    canaries = release_gate_runner._load_canaries(
        {"SERVICE_SECRET_FILE": str(credential)}
    )
    assert b"FILE-CANARY-0123456789" in canaries

    credential.unlink()
    credential.symlink_to(tmp_path / "outside-secret")
    with pytest.raises(GateRunError, match="sensitive|symlink|regular"):
        release_gate_runner._load_canaries({"SERVICE_SECRET_FILE": str(credential)})


def test_secret_inventory_policy_is_contract_bound_and_not_name_hardcoded() -> None:
    assert (
        release_gate_contract.COMMAND_GATE_SECRET_COMPOSE_PATH
        in (release_gate_contract.COMMAND_GATE_IDENTITY_PATHS["G2"])
    )
    assert release_gate_contract.COMMAND_GATE_SECRET_DIRECTORIES == (
        "/run/secrets",
        "/opt/apps/concordia/secrets",
    )
    assert not hasattr(release_gate_runner, "_RUN_SECRET_NAMES")
    assert not hasattr(release_gate_runner, "_HOST_SECRET_NAMES")
    assert not hasattr(release_gate_runner, "_CANARY_PATHS")


def test_safe_tool_path_includes_owned_user_local_bin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    local_bin = home / ".local/bin"
    local_bin.mkdir(parents=True)
    monkeypatch.setattr(
        release_gate_runner.pwd,
        "getpwuid",
        lambda _uid: types.SimpleNamespace(pw_dir=str(home)),
    )

    assert str(local_bin) in release_gate_runner._safe_tool_path().split(os.pathsep)
    local_bin.chmod(0o777)
    assert str(local_bin) not in release_gate_runner._safe_tool_path().split(os.pathsep)


def test_executable_identity_rejects_same_version_replacement_and_symlink_retarget(
    tmp_path: Path,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    first = bin_dir / "first"
    second = bin_dir / "second"
    first.write_bytes(b"#!/bin/sh\necho tool-test-1.0\n")
    second.write_bytes(b"#!/bin/sh\necho tool-test-1.0\n")
    first.chmod(0o755)
    second.chmod(0o755)
    invoked = bin_dir / "tool"
    invoked.symlink_to(first)
    environment = {"PATH": str(bin_dir)}

    captured = release_gate_runner._executable_identity(
        ("tool",),
        cwd=tmp_path,
        environment=environment,
    )
    invoked.unlink()
    invoked.symlink_to(second)

    with pytest.raises(GateRunError, match="executable.*changed|identity"):
        release_gate_runner._assert_executable_identity(
            ("tool",),
            cwd=tmp_path,
            environment=environment,
            expected=captured,
        )


def test_executable_chain_binds_uv_python_and_rejects_nested_replacement(
    tmp_path: Path,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    arm64_header = b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01"
    uv = bin_dir / "uv"
    python = bin_dir / "python3.12"
    uv.write_bytes(arm64_header + b"u" * 24)
    python.write_bytes(arm64_header + b"p" * 24)
    uv.chmod(0o755)
    python.chmod(0o755)
    environment = {"PATH": f"{bin_dir}{os.pathsep}/usr/bin{os.pathsep}/bin"}

    captured = release_gate_runner._executable_chain(
        ("uv", "run", "--python", "python3.12", "python", "--version"),
        cwd=tmp_path,
        environment=environment,
    )

    assert [row["role"] for row in captured] == ["entrypoint", "uv_python"]
    python.write_bytes(arm64_header + b"q" * 24)
    with pytest.raises(GateRunError, match="executable chain changed"):
        release_gate_runner._assert_executable_chain(
            ("uv", "run", "--python", "python3.12", "python", "--version"),
            cwd=tmp_path,
            environment=environment,
            expected=captured,
        )


def test_executable_chain_redacts_every_account_home_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    username = "private-judge-host-user"
    account_home = tmp_path / username
    uv_bin = account_home / ".local/share/uv/bin"
    uv_bin.mkdir(parents=True)
    arm64_header = b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01"
    uv = uv_bin / "uv"
    python = uv_bin / "python3.12"
    uv.write_bytes(arm64_header + b"u" * 24)
    python.write_bytes(arm64_header + b"p" * 24)
    uv.chmod(0o755)
    python.chmod(0o755)
    repository = tmp_path / "repository"
    (repository / ".git").mkdir(parents=True)
    environment = {"PATH": f"{uv_bin}{os.pathsep}/usr/bin{os.pathsep}/bin"}
    monkeypatch.setattr(
        release_gate_runner.pwd,
        "getpwuid",
        lambda _uid: types.SimpleNamespace(pw_dir=account_home.as_posix()),
    )

    chain = release_gate_runner._executable_chain(
        ("uv", "run", "--python", "python3.12", "python", "--version"),
        cwd=repository,
        environment=environment,
    )
    serialized = json.dumps(chain, sort_keys=True)

    assert "<USER_UV_DATA>/" in serialized
    assert account_home.as_posix() not in serialized
    assert username not in serialized


def test_normalized_command_log_redacts_account_home_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    username = "private-judge-host-user"
    account_home = tmp_path / username
    account_home.mkdir()
    repository = tmp_path / "repository"
    repository.mkdir()
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    monkeypatch.setattr(
        release_gate_runner.pwd,
        "getpwuid",
        lambda _uid: types.SimpleNamespace(pw_dir=account_home.as_posix()),
    )

    normalized = release_gate_runner._normalize_log(
        f"warning: cache at {account_home}/.cargo/registry\n".encode(),
        repository_root=repository,
        temporary_root=temporary,
        canaries=(),
        label="test command log",
    )

    assert normalized == b"warning: cache at <USER_HOME>/.cargo/registry\n"
    assert account_home.as_posix().encode() not in normalized
    assert username.encode() not in normalized


def test_executable_chain_recursively_binds_env_node_shebang(
    tmp_path: Path,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    npm = bin_dir / "npm"
    first_node = bin_dir / "node-first"
    second_node = bin_dir / "node-second"
    node = bin_dir / "node"
    npm.write_bytes(b"#!/usr/bin/env node\nconsole.log('npm')\n")
    first_node.write_bytes(b"synthetic-node-binary\n")
    second_node.write_bytes(b"synthetic-node-binary\n")
    npm.chmod(0o755)
    first_node.chmod(0o755)
    second_node.chmod(0o755)
    node.symlink_to(first_node)
    environment = {"PATH": f"{bin_dir}{os.pathsep}/usr/bin{os.pathsep}/bin"}

    chain = release_gate_runner._executable_chain(
        ("npm", "--version"),
        cwd=tmp_path,
        environment=environment,
    )

    assert [row["role"] for row in chain] == [
        "entrypoint",
        "entrypoint.shebang_interpreter",
        "entrypoint.shebang_target",
    ]
    assert str(chain[-1]["invoked_path"]).endswith("/node")

    node.unlink()
    node.symlink_to(second_node)
    with pytest.raises(GateRunError, match="executable chain changed"):
        release_gate_runner._assert_executable_chain(
            ("npm", "--version"),
            cwd=tmp_path,
            environment=environment,
            expected=chain,
        )


def test_executable_chain_binds_cargo_subcommand_compiler_and_locked_wrapper(
    tmp_path: Path,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("cargo", "cargo-odra", "rustc"):
        path = bin_dir / name
        path.write_bytes(f"synthetic-{name}-binary\n".encode())
        path.chmod(0o755)
    arm64_header = b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01"
    for name, marker in (("uv", b"u"), ("python3.12", b"p")):
        path = bin_dir / name
        path.write_bytes(arm64_header + marker * 24)
        path.chmod(0o755)
    environment = {"PATH": f"{bin_dir}{os.pathsep}/usr/bin{os.pathsep}/bin"}

    cargo_chain = release_gate_runner._executable_chain(
        ("cargo", "odra", "build"),
        cwd=tmp_path,
        environment=environment,
    )
    assert [row["role"] for row in cargo_chain] == [
        "entrypoint",
        "cargo_subcommand",
        "rust_compiler",
    ]

    wrapper_chain = release_gate_runner._executable_chain(
        (
            "uv",
            "run",
            "--python",
            "python3.12",
            "python",
            "scripts/run_locked_odra_build.py",
            "--verify-only",
        ),
        cwd=tmp_path,
        environment=environment,
    )
    assert [row["role"] for row in wrapper_chain] == [
        "entrypoint",
        "uv_python",
        "locked_odra.cargo",
        "locked_odra.cargo_subcommand",
        "locked_odra.rust_compiler",
    ]


def test_bound_entrypoint_prevents_swap_execute_restore_attack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    good = bin_dir / "good-tool"
    malicious = bin_dir / "malicious-tool"
    invoked = bin_dir / "tool"
    marker = tmp_path / "malicious-executed"
    good.write_text("#!/bin/sh\nprintf 'GOOD\\n'\n", encoding="utf-8")
    malicious.write_text(
        f"#!/bin/sh\ntouch \"{marker}\"\nprintf 'EVIL\\n'\n",
        encoding="utf-8",
    )
    good.chmod(0o755)
    malicious.chmod(0o755)
    invoked.symlink_to(good)
    saved_invoked = bin_dir / "tool-original-link"
    malicious_invoked = bin_dir / "tool-malicious-link"
    malicious_invoked.symlink_to(malicious)
    monkeypatch.setattr(
        release_gate_runner,
        "COMMAND_GATE_COMMANDS",
        {"G2": (("swap", ".", ("tool",)),)},
    )
    monkeypatch.setattr(
        release_gate_runner,
        "COMMAND_GATE_TIMEOUT_SECONDS",
        {"G2": (5,)},
    )
    environment = {"PATH": f"{bin_dir}{os.pathsep}/usr/bin{os.pathsep}/bin"}

    def executor(
        argv: tuple[str, ...],
        *,
        cwd: Path,
        env: dict[str, str],
        timeout: int,
        resolved_executable: str | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        # Rename the original symlink aside and restore that same inode after
        # execution so a before/after path check alone cannot detect the swap.
        invoked.rename(saved_invoked)
        malicious_invoked.rename(invoked)
        try:
            target = resolved_executable or str(invoked)
            result = subprocess.run(
                list(argv),
                executable=target,
                cwd=cwd,
                env=env,
                timeout=timeout,
                check=False,
                capture_output=True,
            )
        finally:
            invoked.rename(malicious_invoked)
            saved_invoked.rename(invoked)
        return result

    captured = release_gate_runner._capture_commands(
        "G2",
        repository_root=repository,
        temporary_root=tmp_path,
        environment=environment,
        canaries=(),
        executor=executor,
    )

    assert captured[0].stdout == b"GOOD\n"
    assert not marker.exists()


def test_uv_architecture_policy_rejects_x86_and_accepts_arm64() -> None:
    x86_64 = b"\xcf\xfa\xed\xfe\x07\x00\x00\x01" + b"\0" * 24
    arm64 = b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01" + b"\0" * 24

    with pytest.raises(GateRunError, match="uv.*architecture"):
        release_gate_runner._validate_uv_binary(x86_64, expected_architecture="arm64")
    release_gate_runner._validate_uv_binary(arm64, expected_architecture="arm64")


def test_native_architecture_detects_rosetta_and_preserves_true_intel() -> None:
    translated_values = {
        "sysctl.proc_translated": "1",
        "hw.optional.arm64": "1",
    }
    intel_values = {
        "sysctl.proc_translated": "0",
        "hw.optional.arm64": "0",
    }

    assert (
        release_gate_runner._native_darwin_architecture(
            machine="x86_64",
            sysctl_reader=translated_values.get,
        )
        == "arm64"
    )
    assert (
        release_gate_runner._native_darwin_architecture(
            machine="x86_64",
            sysctl_reader=intel_values.get,
        )
        == "x86_64"
    )


def test_secret_canaries_include_common_reversible_representations() -> None:
    raw = b"Ab?/9+"
    variants = set(release_gate_runner.secret_variants(raw))
    standard = base64.b64encode(raw)
    urlsafe = base64.urlsafe_b64encode(raw)
    percent_encoded = b"".join(f"%{value:02X}".encode() for value in raw)

    assert {
        raw,
        standard,
        standard.rstrip(b"="),
        urlsafe,
        urlsafe.rstrip(b"="),
        raw.hex().encode(),
        raw.hex().upper().encode(),
        percent_encoded,
    } <= variants

    loaded = set(
        release_gate_runner._load_canaries(
            {"SERVICE_SECRET_TOKEN": raw.decode("ascii")}
        )
    )
    assert variants <= loaded


def test_real_executor_spools_and_rejects_oversized_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool = tmp_path / "bounded-tool"
    marker = tmp_path / "ran-past-output-limit"
    tool.write_text(
        "#!/bin/sh\n"
        "printf '012345678901234567890123456789012'\n"
        "sleep 1\n"
        f'touch "{marker}"\n',
        encoding="utf-8",
    )
    tool.chmod(0o755)
    monkeypatch.setattr(release_gate_runner, "_MAX_LOG_BYTES", 32)

    with pytest.raises(GateRunError, match="output.*limit|exceeds"):
        release_gate_runner._execute_command(
            (str(tool),),
            cwd=tmp_path,
            env={"PATH": "/usr/bin:/bin"},
            timeout=5,
            resolved_executable=str(tool.resolve()),
        )
    assert not marker.exists()


def test_dynamic_secret_inventory_loads_new_compose_and_directory_secret(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    secret_directory = tmp_path / "mounted-secrets"
    secret_directory.mkdir()
    future_secret = secret_directory / "future_release_secret"
    future_secret.write_bytes(b"FUTURE-SECRET-CANARY\n")
    _write(
        repository,
        "deploy/shared-host/compose.prod.yml",
        (
            "services: {}\n"
            "secrets:\n"
            "  future_release_secret:\n"
            f"    file: {future_secret}\n"
        ).encode(),
    )

    canaries = release_gate_runner._load_canaries(
        {},
        repository_root=repository,
        secret_directories=(secret_directory,),
    )

    assert b"FUTURE-SECRET-CANARY" in canaries


def test_dynamic_secret_inventory_rejects_symlinked_directory_entry(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    secret_directory = tmp_path / "mounted-secrets"
    secret_directory.mkdir()
    outside = tmp_path / "outside-secret"
    outside.write_bytes(b"OUTSIDE\n")
    (secret_directory / "unsafe").symlink_to(outside)
    _write(
        repository,
        "deploy/shared-host/compose.prod.yml",
        b"services: {}\nsecrets: {}\n",
    )

    with pytest.raises(GateRunError, match="secret.*symlink|regular"):
        release_gate_runner._load_canaries(
            {},
            repository_root=repository,
            secret_directories=(secret_directory,),
        )


def test_batch_publication_rolls_back_every_exact_output_on_late_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _, _ = _gate_repository(tmp_path, "G2")
    real_fsync = release_gate_runner._fsync_directory

    def fail_after_receipt_link(path: Path) -> None:
        if path == repository / "release/receipts":
            raise OSError("simulated directory fsync failure")
        real_fsync(path)

    monkeypatch.setattr(
        release_gate_runner,
        "_fsync_directory",
        fail_after_receipt_link,
    )

    with pytest.raises(GateRunError, match="publication"):
        run_gate(
            "G2",
            repository_root=repository,
            executor=_SuccessfulExecutor(repository),
        )

    assert not (repository / COMMAND_GATE_RECEIPT_PATHS["G2"]).exists()
    assert not (repository / "release/receipts/logs/G2").exists()


def test_batch_fsyncs_complete_log_tree_before_receipt_commit_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    events: list[tuple[str, str]] = []
    real_link = release_gate_runner.os.link
    real_fsync = release_gate_runner._fsync_directory

    def recording_link(source, destination, **kwargs):
        events.append(("link", Path(destination).as_posix()))
        return real_link(source, destination, **kwargs)

    def recording_fsync(path: Path) -> None:
        events.append(("fsync", path.as_posix()))
        real_fsync(path)

    monkeypatch.setattr(release_gate_runner.os, "link", recording_link)
    monkeypatch.setattr(release_gate_runner, "_fsync_directory", recording_fsync)
    release_gate_runner._publish_batch(
        repository,
        "G2",
        receipt_raw=b"{}\n",
        logs={"command.stdout": b"ok\n", "command.stderr": b""},
        before_commit=lambda _allowed: events.append(("check", "final-identity")),
    )

    receipt = (repository / COMMAND_GATE_RECEIPT_PATHS["G2"]).as_posix()
    receipt_link = events.index(("link", receipt))
    assert (
        events.index(("fsync", (repository / "release/receipts/logs/G2").as_posix()))
        < receipt_link
    )
    assert (
        events.index(("fsync", (repository / "release/receipts/logs").as_posix()))
        < receipt_link
    )
    assert events.index(("check", "final-identity")) < receipt_link
    assert events[-1] == (
        "fsync",
        (repository / "release/receipts").as_posix(),
    )


def test_final_identity_recheck_rejects_artifact_swap_after_log_fsync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _, _ = _gate_repository(tmp_path, "G2")
    target = repository / COMMAND_GATE_PRODUCED_ARTIFACT_PATHS["G2"][0]
    real_fsync = release_gate_runner._fsync_directory
    mutated = False

    def mutate_after_logs(path: Path) -> None:
        nonlocal mutated
        real_fsync(path)
        if path == repository / "release/receipts/logs/G2" and not mutated:
            target.write_bytes(b"swapped after initial artifact hash\n")
            mutated = True

    monkeypatch.setattr(release_gate_runner, "_fsync_directory", mutate_after_logs)
    with pytest.raises(GateRunError, match="artifact|worktree"):
        run_gate(
            "G2",
            repository_root=repository,
            executor=_SuccessfulExecutor(repository),
        )
    assert not (repository / COMMAND_GATE_RECEIPT_PATHS["G2"]).exists()
    assert not (repository / "release/receipts/logs/G2").exists()


@pytest.mark.parametrize("mutation", ["overwrite", "unlink"])
def test_final_identity_recheck_rejects_log_swap_after_log_fsync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    repository, _, _ = _gate_repository(tmp_path, "G2")
    repository = repository.resolve()
    real_fsync = release_gate_runner._fsync_directory
    mutated = False

    def mutate_after_logs(path: Path) -> None:
        nonlocal mutated
        real_fsync(path)
        target = repository / "release/receipts/logs/G2/python_components.stdout"
        if path == repository / "release/receipts" and target.exists() and not mutated:
            if mutation == "overwrite":
                target.write_bytes(b"tampered after log fsync\n")
            else:
                target.unlink()
            mutated = True

    monkeypatch.setattr(release_gate_runner, "_fsync_directory", mutate_after_logs)
    with pytest.raises(GateRunError, match="log|worktree"):
        run_gate(
            "G2",
            repository_root=repository,
            executor=_SuccessfulExecutor(repository),
        )
    assert mutated
    assert not (repository / COMMAND_GATE_RECEIPT_PATHS["G2"]).exists()


@pytest.mark.parametrize("mutation", ["artifact", "log", "receipt"])
def test_post_receipt_link_revalidation_rolls_back_late_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    repository, _, _ = _gate_repository(tmp_path, "G2")
    repository = repository.resolve()
    receipt_path = repository / COMMAND_GATE_RECEIPT_PATHS["G2"]
    artifact_path = repository / COMMAND_GATE_PRODUCED_ARTIFACT_PATHS["G2"][0]
    log_path = repository / "release/receipts/logs/G2/python_components.stdout"
    real_link = release_gate_runner.os.link
    mutated = False

    def mutate_after_receipt_link(source, destination, **kwargs):
        nonlocal mutated
        result = real_link(source, destination, **kwargs)
        if Path(destination) == receipt_path and not mutated:
            if mutation == "artifact":
                artifact_path.write_bytes(b"late artifact mutation\n")
            elif mutation == "log":
                log_path.write_bytes(b"late log mutation\n")
            else:
                receipt_path.write_bytes(b'{"late":"receipt mutation"}\n')
            mutated = True
        return result

    monkeypatch.setattr(release_gate_runner.os, "link", mutate_after_receipt_link)

    with pytest.raises(GateRunError, match="artifact|log|receipt|worktree"):
        run_gate(
            "G2",
            repository_root=repository,
            executor=_SuccessfulExecutor(repository),
        )

    assert mutated
    assert not receipt_path.exists()
    assert not (repository / "release/receipts/logs/G2").exists()


def test_failed_publication_fsyncs_rollback_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    fsyncs: list[Path] = []
    real_fsync = release_gate_runner._fsync_directory
    real_link = release_gate_runner.os.link

    def record_fsync(path: Path) -> None:
        fsyncs.append(path)
        real_fsync(path)

    def fail_receipt_link(source, destination, **kwargs):
        if Path(destination) == repository / COMMAND_GATE_RECEIPT_PATHS["G2"]:
            raise OSError("simulated receipt-link failure")
        return real_link(source, destination, **kwargs)

    monkeypatch.setattr(release_gate_runner, "_fsync_directory", record_fsync)
    monkeypatch.setattr(release_gate_runner.os, "link", fail_receipt_link)
    with pytest.raises(GateRunError, match="publication"):
        release_gate_runner._publish_batch(
            repository,
            "G2",
            receipt_raw=b"{}\n",
            logs={"command.stdout": b"ok\n", "command.stderr": b""},
            before_commit=lambda _allowed: None,
        )

    for directory in (
        repository / "release/receipts/logs/G2",
        repository / "release/receipts/logs",
        repository / "release/receipts",
    ):
        assert fsyncs.count(directory) >= 2


def test_g9_hashes_exact_ignored_next_outputs_without_dirtying_head(
    tmp_path: Path,
) -> None:
    repository, _, _ = _gate_repository(tmp_path, "G9")
    assert _git(repository, "status", "--short") == ""
    assert _git(repository, "ls-files", "dashboard/.next") == ""
    stale = repository / "dashboard/.next/stale-marker"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_bytes(b"must disappear\n")
    installed = False

    def executor(
        argv: tuple[str, ...],
        *,
        cwd: Path,
        env: dict[str, str],
        timeout: int,
        resolved_executable: str | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        nonlocal installed
        del env, timeout, resolved_executable
        if argv == ("npm", "ci"):
            installed = True
            return subprocess.CompletedProcess(argv, 0, b"installed\n", b"")
        if argv == ("npm", "run", "build"):
            assert not stale.exists()
            for relative in COMMAND_GATE_PRODUCED_ARTIFACT_PATHS["G9"]:
                _write(repository, relative, f"fresh:{relative}\n".encode())
            return subprocess.CompletedProcess(argv, 0, b"built\n", b"")
        if argv[0].startswith("node_modules/") and not installed:
            return subprocess.CompletedProcess(argv, 127, b"", b"not installed\n")
        version_runtime = {
            ("node", "--version"): "node",
            ("npm", "--version"): "npm",
            ("node_modules/.bin/next", "--version"): "next",
            ("node_modules/.bin/playwright", "--version"): "playwright",
        }.get(argv)
        if version_runtime is not None:
            return subprocess.CompletedProcess(
                argv,
                0,
                (EXPECTED_RUNTIME_VERSIONS[version_runtime] + "\n").encode(),
                b"",
            )
        return subprocess.CompletedProcess(argv, 0, b"passed\n", b"")

    run_gate(
        "G9",
        repository_root=repository,
        executor=executor,
    )

    receipt = json.loads((repository / COMMAND_GATE_RECEIPT_PATHS["G9"]).read_bytes())
    assert [row["path"] for row in receipt["produced_artifacts"]] == list(
        COMMAND_GATE_PRODUCED_ARTIFACT_PATHS["G9"]
    )
    assert receipt["fresh_outputs"] == [
        {"path": "dashboard/.next", "state_before": "removed_or_absent"}
    ]


def _snapshot_item(artifact_path: str, artifact_sha256: str) -> dict[str, object]:
    return {
        "proof_id": "snapshot-current",
        "proof_type": "snapshot",
        "generation": "none",
        "lineage": "supplemental",
        "observation_mode": "snapshot",
        "temporal_scope": "current",
        "verification_status": "verified",
        "execution_outcome": "not_applicable",
        "claim_scope": "The release includes one current proof artifact.",
        "enforcement_scope": "Evidence capture only; no execution authority.",
        "proposal_id": "DAO-PROP-TEST",
        "action_id": None,
        "envelope_hash": None,
        "artifact_path": artifact_path,
        "artifact_sha256": artifact_sha256,
        "source_commit": "1" * 40,
        "deployment_commit": None,
        "network": None,
        "package_hash": None,
        "contract_hash": None,
        "deployment_domain": None,
        "schema_version": "snapshot-v1",
        "captured_at": NOW,
        "payment_requirements_hash": None,
        "signed_payment_payload_hash": None,
        "report_hash": None,
        "settlement_transaction": None,
        "checks": [
            {
                "name": name,
                "required": True,
                "passed": True,
                "source": artifact_path,
                "observed_at": NOW,
            }
            for name in REQUIRED_CHECKS_BY_PROOF_TYPE["snapshot"]
        ],
        "links": [
            {
                "rel": "source",
                "label": "Source artifact",
                "href": "/dashboard/proof",
                "kind": "ui",
            }
        ],
    }


def _claim_audit_repository(tmp_path: Path) -> Path:
    repository = tmp_path / "claim-repository"
    repository.mkdir()
    artifact_path = "artifacts/live/example-proof.json"
    artifact_raw = _canonical({"proof": "current"})
    _write(repository, artifact_path, artifact_raw)
    artifact_sha256 = hashlib.sha256(artifact_raw).hexdigest()
    registry = {
        "schema_version": 1,
        "public_items": [_snapshot_item(artifact_path, artifact_sha256)],
        "internal_records": [],
    }
    _write(
        repository,
        "artifacts/live/proof-registry/registry.json",
        _canonical(registry),
    )
    documents = {
        "README.md": "# Concordia\n\nThe release includes one current proof artifact.\n",
        "docs/POLICY_TEMPLATES.md": (
            "# Policies\n\nThe release includes one current proof artifact.\n"
        ),
        "docs/TECHNICAL_JURY_NOTE.md": (
            "# Technical note\n\nThe release includes one current proof artifact.\n"
        ),
        "docs/DEMO_SCRIPT.md": (
            "# Demo\n\nThe release includes one current proof artifact.\n"
        ),
        "docs/DORAHACKS_SUBMISSION_TEXT.md": (
            "# Submission\n\nThe release includes one current proof artifact.\n"
        ),
    }
    for relative, text in documents.items():
        _write(repository, relative, text.encode())
    sources = [
        {
            "path": relative,
            "exact_text": "The release includes one current proof artifact.",
            "occurrence": 1,
        }
        for relative in sorted(documents)
    ]
    audited_documents = [
        {
            "path": relative,
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
        }
        for relative, text in sorted(documents.items())
    ]
    policy = {
        "schema_version": "concordia.g11_claim_policy.v1",
        "audited_documents": audited_documents,
        "claims": [
            {
                "claim_id": "current-proof-artifact",
                "exact_text": "The release includes one current proof artifact.",
                "sources": sources,
                "claim_class": "verified_current",
                "allowed_proof_profiles": [
                    {
                        "proof_type": "snapshot",
                        "temporal_scope": "current",
                        "outcome_kind": "not_applicable",
                        "provenance_class": {
                            "generation": "none",
                            "lineage": "supplemental",
                            "observation_mode": "snapshot",
                        },
                        "verification_scope": {
                            "claim_scope": (
                                "The release includes one current proof artifact."
                            ),
                            "enforcement_scope": (
                                "Evidence capture only; no execution authority."
                            ),
                        },
                        "required_checks": list(
                            REQUIRED_CHECKS_BY_PROOF_TYPE["snapshot"]
                        ),
                    }
                ],
            }
        ],
    }
    policy_raw = _canonical(policy)
    _write(repository, "handoff/G11_CLAIM_POLICY.json", policy_raw)
    g11_claim_policy_authority.G11_CLAIM_POLICY_SHA256 = hashlib.sha256(
        policy_raw
    ).hexdigest()
    claim_map = {
        "schema_version": "concordia.claim_to_artifact_map.v1",
        "audited_documents": audited_documents,
        "claims": [
            {
                "claim_id": "current-proof-artifact",
                "claim_text": "The release includes one current proof artifact.",
                "sources": sources,
                "artifacts": [
                    {
                        "proof_id": "snapshot-current",
                        "path": artifact_path,
                        "sha256": artifact_sha256,
                    }
                ],
            }
        ],
    }
    _write(
        repository,
        "docs/CLAIM_TO_ARTIFACT_MAP.json",
        _canonical(claim_map),
    )
    return repository


def test_g11_verify_only_audits_claim_sources_registry_and_artifact_hashes(
    tmp_path: Path,
) -> None:
    repository = _claim_audit_repository(tmp_path)

    summary = verify_claim_artifacts(repository)

    assert summary == {
        "artifact_count": 1,
        "claim_count": 1,
        "document_count": 5,
        "proof_count": 1,
        "status": "verified",
    }

    artifact = repository / "artifacts/live/example-proof.json"
    artifact.write_bytes(b"tampered\n")
    with pytest.raises(ClaimAuditError, match="digest|SHA-256|hash"):
        verify_claim_artifacts(repository)


def test_g11_verify_only_is_nonrecursive_and_normal_mode_runs_the_fixed_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _claim_audit_repository(tmp_path)
    calls: list[tuple[str, Path]] = []

    def fake_run_gate(gate_id: str, *, repository_root: Path):
        calls.append((gate_id, repository_root))
        return type(
            "Result",
            (),
            {
                "gate_id": gate_id,
                "receipt_path": COMMAND_GATE_RECEIPT_PATHS[gate_id],
                "receipt_sha256": "ab" * 32,
            },
        )()

    monkeypatch.setattr(run_g11_claim_audit, "run_gate", fake_run_gate)

    assert (
        run_g11_claim_audit.main(
            ["--verify-only", "--repository-root", str(repository)]
        )
        == 0
    )
    assert calls == []
    assert run_g11_claim_audit.main(["--repository-root", str(repository)]) == 0
    assert calls == [("G11", repository.resolve())]


def test_g11_fails_closed_when_claim_map_is_missing(tmp_path: Path) -> None:
    repository = _claim_audit_repository(tmp_path)
    (repository / "docs/CLAIM_TO_ARTIFACT_MAP.json").unlink()

    with pytest.raises(ClaimAuditError, match="CLAIM_TO_ARTIFACT_MAP"):
        verify_claim_artifacts(repository)


def test_g11_rejects_unapproved_document_and_policy_map_coedit(
    tmp_path: Path,
) -> None:
    repository = _claim_audit_repository(tmp_path)
    readme = repository / "README.md"
    readme.write_text(
        readme.read_text() + "\nConcordia has guaranteed every action forever.\n"
    )
    claim_map_path = repository / "docs/CLAIM_TO_ARTIFACT_MAP.json"
    claim_map = json.loads(claim_map_path.read_bytes())
    next(row for row in claim_map["audited_documents"] if row["path"] == "README.md")[
        "sha256"
    ] = hashlib.sha256(readme.read_bytes()).hexdigest()
    claim_map_path.write_bytes(_canonical(claim_map))

    with pytest.raises(ClaimAuditError, match="document|policy|digest"):
        verify_claim_artifacts(repository)

    policy_path = repository / "handoff/G11_CLAIM_POLICY.json"
    policy = json.loads(policy_path.read_bytes())
    next(row for row in policy["audited_documents"] if row["path"] == "README.md")[
        "sha256"
    ] = hashlib.sha256(readme.read_bytes()).hexdigest()
    policy_path.write_bytes(_canonical(policy))
    with pytest.raises(ClaimAuditError, match="policy.*digest|approved"):
        verify_claim_artifacts(repository)


@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_g11_rejects_missing_or_extra_map_claim(tmp_path: Path, mutation: str) -> None:
    repository = _claim_audit_repository(tmp_path)
    path = repository / "docs/CLAIM_TO_ARTIFACT_MAP.json"
    claim_map = json.loads(path.read_bytes())
    if mutation == "missing":
        claim_map["claims"] = []
    else:
        claim_map["claims"].append(
            {
                "claim_id": "invented-extra",
                "claim_text": "Invented.",
                "sources": [
                    {
                        "path": "README.md",
                        "exact_text": "Invented.",
                        "occurrence": 1,
                    }
                ],
                "artifacts": [],
            }
        )
    path.write_bytes(_canonical(claim_map))
    with pytest.raises(ClaimAuditError, match="inventory|policy|claim"):
        verify_claim_artifacts(repository)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("claim_scope", "An unrelated exact-envelope assertion."),
        ("enforcement_scope", "Execution authority."),
    ],
)
def test_g11_rejects_semantically_incompatible_green_proof(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    repository = _claim_audit_repository(tmp_path)
    registry_path = repository / "artifacts/live/proof-registry/registry.json"
    registry = json.loads(registry_path.read_bytes())
    registry["public_items"][0][field] = value
    registry_path.write_bytes(_canonical(registry))
    with pytest.raises(ClaimAuditError, match="compatible|policy|scope"):
        verify_claim_artifacts(repository)


@pytest.mark.parametrize("mutation", ["proof_type", "weak_checks", "limitation"])
def test_g11_rejects_incompatible_policy_type_checks_or_green_implication(
    tmp_path: Path, mutation: str
) -> None:
    repository = _claim_audit_repository(tmp_path)
    policy_path = repository / "handoff/G11_CLAIM_POLICY.json"
    policy = json.loads(policy_path.read_bytes())
    claim = policy["claims"][0]
    profile = claim["allowed_proof_profiles"][0]
    if mutation == "proof_type":
        profile["proof_type"] = "exact_envelope_v3"
        profile["required_checks"] = list(
            REQUIRED_CHECKS_BY_PROOF_TYPE["exact_envelope_v3"]
        )
    elif mutation == "weak_checks":
        profile["required_checks"] = profile["required_checks"][:-1]
    else:
        claim["claim_class"] = "limitation"
        claim["allowed_proof_profiles"] = []
    policy_raw = _canonical(policy)
    policy_path.write_bytes(policy_raw)
    g11_claim_policy_authority.G11_CLAIM_POLICY_SHA256 = hashlib.sha256(
        policy_raw
    ).hexdigest()

    with pytest.raises(
        ClaimAuditError,
        match="compatible|frozen registry|non-verified|green",
    ):
        verify_claim_artifacts(repository)


def test_g11_rejects_unenumerated_duplicate_source_occurrence(
    tmp_path: Path,
) -> None:
    repository = _claim_audit_repository(tmp_path)
    readme = repository / "README.md"
    claim_text = "The release includes one current proof artifact."
    readme.write_text(readme.read_text() + f"\n{claim_text}\n")
    digest = hashlib.sha256(readme.read_bytes()).hexdigest()

    map_path = repository / "docs/CLAIM_TO_ARTIFACT_MAP.json"
    claim_map = json.loads(map_path.read_bytes())
    next(row for row in claim_map["audited_documents"] if row["path"] == "README.md")[
        "sha256"
    ] = digest
    map_path.write_bytes(_canonical(claim_map))

    policy_path = repository / "handoff/G11_CLAIM_POLICY.json"
    policy = json.loads(policy_path.read_bytes())
    next(row for row in policy["audited_documents"] if row["path"] == "README.md")[
        "sha256"
    ] = digest
    policy_raw = _canonical(policy)
    policy_path.write_bytes(policy_raw)
    g11_claim_policy_authority.G11_CLAIM_POLICY_SHA256 = hashlib.sha256(
        policy_raw
    ).hexdigest()

    with pytest.raises(ClaimAuditError, match="occurrence|exhaustive"):
        verify_claim_artifacts(repository)


def test_g11_rejects_duplicate_allowed_proof_profiles(tmp_path: Path) -> None:
    repository = _claim_audit_repository(tmp_path)
    policy_path = repository / "handoff/G11_CLAIM_POLICY.json"
    policy = json.loads(policy_path.read_bytes())
    profiles = policy["claims"][0]["allowed_proof_profiles"]
    profiles.append(json.loads(json.dumps(profiles[0])))
    policy_raw = _canonical(policy)
    policy_path.write_bytes(policy_raw)
    g11_claim_policy_authority.G11_CLAIM_POLICY_SHA256 = hashlib.sha256(
        policy_raw
    ).hexdigest()

    with pytest.raises(ClaimAuditError, match="duplicate.*profile"):
        verify_claim_artifacts(repository)


def test_g11_rejects_unenumerated_cross_document_source_occurrence(
    tmp_path: Path,
) -> None:
    repository = _claim_audit_repository(tmp_path)
    policy_path = repository / "handoff/G11_CLAIM_POLICY.json"
    map_path = repository / "docs/CLAIM_TO_ARTIFACT_MAP.json"
    policy = json.loads(policy_path.read_bytes())
    claim_map = json.loads(map_path.read_bytes())
    policy["claims"][0]["sources"] = [policy["claims"][0]["sources"][0]]
    claim_map["claims"][0]["sources"] = [claim_map["claims"][0]["sources"][0]]
    headers = (
        ("docs/POLICY_TEMPLATES.md", "# Policies"),
        ("docs/TECHNICAL_JURY_NOTE.md", "# Technical note"),
        ("docs/DEMO_SCRIPT.md", "# Demo"),
        ("docs/DORAHACKS_SUBMISSION_TEXT.md", "# Submission"),
    )
    for index, (relative, exact_text) in enumerate(headers, 1):
        sources = [{"path": relative, "exact_text": exact_text, "occurrence": 1}]
        claim_id = f"limitation-{index}"
        policy["claims"].append(
            {
                "claim_id": claim_id,
                "exact_text": exact_text,
                "sources": sources,
                "claim_class": "limitation",
                "allowed_proof_profiles": [],
            }
        )
        claim_map["claims"].append(
            {
                "claim_id": claim_id,
                "claim_text": exact_text,
                "sources": sources,
                "artifacts": [],
            }
        )
    policy_raw = _canonical(policy)
    policy_path.write_bytes(policy_raw)
    map_path.write_bytes(_canonical(claim_map))
    g11_claim_policy_authority.G11_CLAIM_POLICY_SHA256 = hashlib.sha256(
        policy_raw
    ).hexdigest()

    with pytest.raises(ClaimAuditError, match="occurrence|exhaustive"):
        verify_claim_artifacts(repository)


def test_g11_authority_is_split_from_stable_command_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = collector_contract_sha256()
    assert (
        release_gate_contract.G11_CLAIM_POLICY_AUTHORITY_PATH
        == "shared/g11_claim_policy_authority.py"
    )
    assert (
        release_gate_contract.COMMAND_GATE_IDENTITY_PATHS["G11"][-1]
        == release_gate_contract.G11_CLAIM_POLICY_AUTHORITY_PATH
    )

    def malicious_authority() -> str:
        raise RuntimeError("G11 authority must not execute in G2/G9")

    monkeypatch.setattr(
        g11_claim_policy_authority,
        "approved_policy_sha256",
        malicious_authority,
    )
    assert collector_contract_sha256() == before

    g2_repository, _, _ = _gate_repository(tmp_path / "g2", "G2")
    run_gate(
        "G2",
        repository_root=g2_repository,
        executor=_SuccessfulExecutor(g2_repository),
    )

    g9_repository, _, _ = _gate_repository(tmp_path / "g9", "G9")

    class _G9Executor(_SuccessfulExecutor):
        def __call__(
            self,
            argv: tuple[str, ...],
            *,
            cwd: Path,
            env: dict[str, str],
            timeout: int,
            resolved_executable: str | None = None,
        ) -> subprocess.CompletedProcess[bytes]:
            if argv == ("npm", "run", "build"):
                for relative in COMMAND_GATE_PRODUCED_ARTIFACT_PATHS["G9"]:
                    _write(self.repository, relative, f"G9:{relative}\n".encode())
            return super().__call__(
                argv,
                cwd=cwd,
                env=env,
                timeout=timeout,
                resolved_executable=resolved_executable,
            )

    run_gate(
        "G9",
        repository_root=g9_repository,
        executor=_G9Executor(g9_repository),
    )


def test_g11_authority_rejects_zero_or_malformed_policy_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from shared import g11_claim_policy_authority

    for digest in ("0" * 64, "A" * 64, "a" * 63):
        monkeypatch.setattr(
            g11_claim_policy_authority,
            "G11_CLAIM_POLICY_SHA256",
            digest,
        )
        with pytest.raises(ValueError, match="approved.*policy.*digest"):
            g11_claim_policy_authority.approved_policy_sha256()
