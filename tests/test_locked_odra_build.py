from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from scripts import release_gate_runner
from scripts.run_locked_odra_build import (
    LockedOdraBuildError,
    _safe_tool_path as locked_odra_safe_tool_path,
    verify_locked_odra_build,
)


WASM_PATH = "wasm/GovernanceReceiptV3.wasm"
SCHEMA_PATH = "resources/casper_contract_schemas/governance_receiptv3_schema.json"
CRATE_PATH = "contracts/odra-governance-receipt-v3"
EXPECTED_CARGO = "cargo 1.86.0-nightly (cecde95c1 2025-01-24)"
EXPECTED_CARGO_ODRA = "cargo-odra 0.1.7"
EXPECTED_RUSTC = (
    "rustc 1.86.0-nightly (854f22563 2025-01-31)\n"
    "binary: rustc\n"
    "commit-hash: 854f22563c8daf92709fae18ee6aed52953835cd\n"
    "commit-date: 2025-01-31\n"
    "host: aarch64-apple-darwin\n"
    "release: 1.86.0-nightly\n"
    "LLVM version: 19.1.7"
)


def test_locked_wrapper_uses_the_release_gate_tool_resolution_policy() -> None:
    assert locked_odra_safe_tool_path() == release_gate_runner._safe_tool_path()


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


def _repository(tmp_path: Path) -> tuple[Path, bytes, bytes, bytes]:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-b", "main")
    _git(repository, "config", "user.name", "Odra Test")
    _git(repository, "config", "user.email", "odra@example.invalid")

    lock = b"# locked dependencies\n"
    wasm = b"\0asm" + b"verified-wasm" * 8
    lib_rs = b"pub struct GovernanceReceiptV3;\n"
    encoding_rs = b"pub const SCHEMA_VERSION: u32 = 3;\n"
    schema = _canonical(
        {
            "authors": [],
            "call": {
                "arguments": [],
                "description": "",
                "wasm_file_name": "GovernanceReceiptV3.wasm",
            },
            "casper_contract_schema_version": 1,
            "contract_name": "GovernanceReceiptV3",
            "contract_version": "0.1.0",
            "entry_points": [
                {
                    "access": "public",
                    "arguments": [],
                    "description": "",
                    "is_contract_context": True,
                    "is_mutable": True,
                    "name": "write",
                    "return_ty": "Unit",
                },
                {
                    "access": "public",
                    "arguments": [],
                    "description": "",
                    "is_contract_context": True,
                    "is_mutable": False,
                    "name": "read",
                    "return_ty": "Bool",
                },
            ],
            "errors": [{"description": "", "discriminant": 1, "name": "Rejected"}],
            "events": [{"name": "Changed", "ty": "Changed"}],
            "homepage": None,
            "repository": None,
            "toolchain": ("rustc 1.86.0-nightly (854f22563 2025-01-31)"),
            "types": [
                {
                    "struct": {
                        "description": None,
                        "members": [],
                        "name": "Changed",
                    }
                }
            ],
        }
    )
    _write(
        repository,
        f"{CRATE_PATH}/Cargo.toml",
        b"[package]\nname='test'\nversion='0.1.0'\n",
    )
    _write(repository, f"{CRATE_PATH}/Cargo.lock", lock)
    _write(repository, f"{CRATE_PATH}/src/lib.rs", lib_rs)
    _write(repository, f"{CRATE_PATH}/src/encoding.rs", encoding_rs)
    _write(repository, f"{CRATE_PATH}/{WASM_PATH}", wasm)
    _write(repository, f"{CRATE_PATH}/{SCHEMA_PATH}", schema)

    historical_files = {
        "contracts/odra-governance-receipt/Cargo.lock": b"# historical lock\n",
        (
            "contracts/odra-governance-receipt/wasm/GovernanceReceipt.wasm"
        ): b"\0asmhistorical",
    }
    for relative, raw in historical_files.items():
        _write(repository, relative, raw)
    historical_manifest = (
        "# tracked historical files\n"
        + "".join(
            f"{hashlib.sha256(raw).hexdigest()}  {relative}\n"
            for relative, raw in sorted(historical_files.items())
        )
    ).encode()
    _write(repository, "handoff/HISTORICAL_ODRA_SHA256.txt", historical_manifest)
    historical_wasm = historical_files[
        "contracts/odra-governance-receipt/wasm/GovernanceReceipt.wasm"
    ]
    _write(
        repository,
        "handoff/HISTORICAL_ODRA_RECEIPTS_V1.json",
        _canonical(
            {
                "schema_version": "concordia.historical_odra_inventory.v1",
                "preserved_repo_source": {
                    "manifest_path": "handoff/HISTORICAL_ODRA_SHA256.txt",
                    "manifest_sha256": hashlib.sha256(historical_manifest).hexdigest(),
                    "governance_receipt_wasm_path": (
                        "contracts/odra-governance-receipt/wasm/GovernanceReceipt.wasm"
                    ),
                    "governance_receipt_wasm_sha256": hashlib.sha256(
                        historical_wasm
                    ).hexdigest(),
                },
            }
        ),
    )
    _write(
        repository,
        f"{CRATE_PATH}/deployment.manifest.json",
        _canonical(
            {
                "schema_id": "concordia.v3-deployment-manifest.v1",
                "status": "built_uninstalled",
                "network": "casper-test",
                "package_key_name": "concordia_governance_receipt_v3",
                "contract_name": "GovernanceReceiptV3",
                "contract_version": None,
                "package_hash": None,
                "contract_hash": None,
                "install_deploy_hash": None,
                "install_block_hash": None,
                "install_block_height": None,
                "install_state_root_hash": None,
                "locked_install": {
                    "odra_cfg_allow_key_override": False,
                    "odra_cfg_is_upgradable": False,
                    "odra_cfg_is_upgrade": False,
                },
                "build": {
                    "command": ("cargo --locked odra build -c GovernanceReceiptV3"),
                    "schema_command": (
                        "cargo --locked odra schema -c GovernanceReceiptV3"
                    ),
                    "wasm_path": WASM_PATH,
                    "wasm_sha256": hashlib.sha256(wasm).hexdigest(),
                    "wasm_size_bytes": len(wasm),
                    "schema_path": SCHEMA_PATH,
                    "schema_sha256": hashlib.sha256(schema).hexdigest(),
                },
                "source": {
                    "lib_rs_sha256": hashlib.sha256(lib_rs).hexdigest(),
                    "encoding_rs_sha256": hashlib.sha256(encoding_rs).hexdigest(),
                    "cargo_lock_sha256": hashlib.sha256(lock).hexdigest(),
                },
                "historical_isolation": {
                    "tracked_file_count": len(historical_files),
                    "pre_post_diff": "empty",
                    "manifest_sha256": hashlib.sha256(historical_manifest).hexdigest(),
                },
                "abi": {
                    "entry_point_count": 2,
                    "mutable_entry_point_count": 1,
                    "query_entry_point_count": 1,
                    "event_count": 1,
                    "error_count": 1,
                },
                "deployment_domain": None,
                "installation_nonce": None,
                "roles": None,
                "source_commit": None,
                "deployment_commit": None,
                "note": "test build",
                "toolchain": {
                    "cargo_odra": "0.1.7",
                    "odra": "2.8.2",
                    "rustc": "1.86.0-nightly (854f22563 2025-01-31)",
                },
            }
        ),
    )
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "tracked Odra build inputs")
    return repository, lock, wasm, schema


class _BuildExecutor:
    def __init__(
        self,
        *,
        lock: bytes,
        wasm: bytes,
        schema: bytes,
        mode: str = "success",
    ) -> None:
        self.lock = lock
        self.wasm = wasm
        self.schema = schema
        self.mode = mode
        self.calls: list[tuple[tuple[str, ...], Path, dict[str, str], int]] = []

    def __call__(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        env: dict[str, str],
        timeout: int,
    ) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((argv, cwd, env, timeout))
        if argv == ("cargo", "--version"):
            return subprocess.CompletedProcess(
                argv,
                0,
                (EXPECTED_CARGO + "\n").encode(),
                b"",
            )
        if argv == ("cargo", "odra", "--version"):
            return subprocess.CompletedProcess(
                argv,
                0,
                (EXPECTED_CARGO_ODRA + "\n").encode(),
                b"",
            )
        if argv == ("rustc", "-vV"):
            observed = (
                EXPECTED_RUSTC
                if self.mode != "toolchain_mismatch"
                else EXPECTED_RUSTC.replace("LLVM version: 19.1.7", "LLVM version: 0")
            )
            return subprocess.CompletedProcess(
                argv,
                0,
                (observed + "\n").encode(),
                b"",
            )
        if argv == ("cargo", "fetch", "--locked"):
            assert env.get("CARGO_NET_OFFLINE") is None
            return subprocess.CompletedProcess(argv, 0, b"fetched\n", b"")
        if argv == (
            "cargo",
            "metadata",
            "--locked",
            "--offline",
            "--format-version",
            "1",
            "--no-deps",
        ):
            assert env["CARGO_NET_OFFLINE"] == "true"
            return subprocess.CompletedProcess(argv, 0, b'{"packages":[]}\n', b"")
        if argv == (
            "cargo",
            "--locked",
            "odra",
            "build",
            "-c",
            "GovernanceReceiptV3",
        ):
            assert env["CARGO_NET_OFFLINE"] == "true"
            assert not (cwd / WASM_PATH).exists()
            assert not (cwd / SCHEMA_PATH).exists()
            (cwd / WASM_PATH).parent.mkdir(parents=True, exist_ok=True)
            (cwd / WASM_PATH).write_bytes(
                b"wrong" if self.mode == "wrong_hash" else self.wasm
            )
            if self.mode == "lock_mutation":
                (cwd / "Cargo.lock").write_bytes(self.lock + b"mutated\n")
            stdout = b"built\n"
            stderr = b""
            if self.mode == "error":
                stdout = b"ERROR build failed but cargo-odra returned zero\n"
            elif self.mode == "ansi_error":
                stdout = b"\x1b[1;31mERROR\x1b[0m build failed but cargo-odra returned zero\n"
            elif self.mode == "prefixed_error":
                stdout = (
                    b"\xf0\x9f\xa4\xa6  \x1b[1;31mERROR :\x1b[0m "
                    b"build failed but cargo-odra returned zero\n"
                )
            elif self.mode == "dcs_error":
                stdout = (
                    b"\x1bP0;1|terminal-prefix\x1b\\ERROR "
                    b"build failed but cargo-odra returned zero\n"
                )
            elif self.mode == "c1_dcs_error":
                stdout = (
                    b"\x90terminal-prefix\x9cERROR "
                    b"build failed but cargo-odra returned zero\n"
                )
            elif self.mode == "long_prefixed_error":
                stdout = (
                    b"x" * 1024 + b" ERROR build failed but cargo-odra returned zero\n"
                )
            elif self.mode == "fatal":
                stderr = b"fatal: cargo-odra could not produce the contract\n"
            elif self.mode == "title_error":
                stderr = b"Error: contract generation failed\n"
            elif self.mode == "title_fatal":
                stderr = b"Fatal: contract generation failed\n"
            elif self.mode == "cr_error":
                stderr = b"progress\rerror: contract generation failed\n"
            elif self.mode == "tool_error":
                stderr = b"cargo-odra: error: contract generation failed\n"
            elif self.mode == "tool_error_no_colon":
                stderr = b"cargo-odra error: contract generation failed\n"
            elif self.mode == "routine_error_crate_names":
                stderr = (
                    b"   Compiling proc-macro-error-attr v1.0.4\n"
                    b"   Compiling proc-macro-error v1.0.4\n"
                    b"   Compiling proc-macro-error2 v2.0.1\n"
                    b"   Compiling thiserror v1.0.69\n"
                )
            return subprocess.CompletedProcess(argv, 0, stdout, stderr)

        assert argv == (
            "cargo",
            "--locked",
            "odra",
            "schema",
            "-c",
            "GovernanceReceiptV3",
        )
        assert env["CARGO_NET_OFFLINE"] == "true"
        assert (cwd / WASM_PATH).exists()
        assert not (cwd / SCHEMA_PATH).exists()
        (cwd / SCHEMA_PATH).parent.mkdir(parents=True, exist_ok=True)
        (cwd / SCHEMA_PATH).write_bytes(self.schema)
        if self.mode == "schema_lock_mutation":
            (cwd / "Cargo.lock").write_bytes(self.lock + b"schema mutated\n")
        schema_diagnostics = {
            "schema_error": b"ERROR schema failed but cargo-odra returned zero\n",
            "schema_title_error": b"Error: schema generation failed\n",
            "schema_title_fatal": b"Fatal: schema generation failed\n",
            "schema_cr_error": b"progress\rerror: schema generation failed\n",
            "schema_tool_error": b"cargo-odra: error: schema generation failed\n",
            "schema_tool_error_no_colon": (
                b"cargo-odra error: schema generation failed\n"
            ),
        }
        stdout = schema_diagnostics.get(self.mode, b"schema generated\n")
        return subprocess.CompletedProcess(argv, 0, stdout, b"")


def test_locked_odra_build_uses_fresh_archive_and_proves_exact_outputs(
    tmp_path: Path,
) -> None:
    repository, lock, wasm, schema = _repository(tmp_path)
    executor = _BuildExecutor(lock=lock, wasm=wasm, schema=schema)

    summary = verify_locked_odra_build(repository, executor=executor)

    assert [call[0] for call in executor.calls] == [
        ("cargo", "--version"),
        ("cargo", "odra", "--version"),
        ("rustc", "-vV"),
        ("cargo", "fetch", "--locked"),
        (
            "cargo",
            "metadata",
            "--locked",
            "--offline",
            "--format-version",
            "1",
            "--no-deps",
        ),
        (
            "cargo",
            "--locked",
            "odra",
            "build",
            "-c",
            "GovernanceReceiptV3",
        ),
        (
            "cargo",
            "--locked",
            "odra",
            "schema",
            "-c",
            "GovernanceReceiptV3",
        ),
    ]
    assert summary == {
        "cargo_lock_sha256": hashlib.sha256(lock).hexdigest(),
        "historical_file_count": 2,
        "schema_sha256": hashlib.sha256(schema).hexdigest(),
        "status": "verified",
        "toolchain": {
            "cargo": EXPECTED_CARGO,
            "cargo_odra": EXPECTED_CARGO_ODRA,
            "rustc": EXPECTED_RUSTC,
        },
        "wasm_sha256": hashlib.sha256(wasm).hexdigest(),
    }
    assert (repository / f"{CRATE_PATH}/{WASM_PATH}").read_bytes() == wasm
    assert (repository / f"{CRATE_PATH}/{SCHEMA_PATH}").read_bytes() == schema
    assert _git(repository, "status", "--short") == ""


def test_locked_odra_git_ignores_repository_fsmonitor_configuration(
    tmp_path: Path,
) -> None:
    repository, lock, wasm, schema = _repository(tmp_path)
    marker = tmp_path / "locked-odra-fsmonitor-executed"
    hook = tmp_path / "fsmonitor-hook"
    hook.write_text(
        f"#!/bin/sh\ntouch {marker.as_posix()!r}\nprintf '2\\n'\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)
    _git(repository, "config", "core.fsmonitor", hook.as_posix())
    _git(repository, "status", "--porcelain")
    assert marker.exists()
    marker.unlink()
    executor = _BuildExecutor(lock=lock, wasm=wasm, schema=schema)

    verify_locked_odra_build(repository, executor=executor)

    assert not marker.exists()


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        ("error", "ERROR"),
        ("ansi_error", "ERROR"),
        ("prefixed_error", "ERROR"),
        ("dcs_error", "ERROR"),
        ("c1_dcs_error", "ERROR"),
        ("long_prefixed_error", "ERROR"),
        ("fatal", "fatal"),
        ("title_error", "Error"),
        ("title_fatal", "Fatal"),
        ("cr_error", "error"),
        ("tool_error", "error"),
        ("tool_error_no_colon", "error"),
        ("schema_error", "ERROR"),
        ("schema_title_error", "Error"),
        ("schema_title_fatal", "Fatal"),
        ("schema_cr_error", "error"),
        ("schema_tool_error", "error"),
        ("schema_tool_error_no_colon", "error"),
        ("wrong_hash", "Wasm|digest|hash"),
        ("lock_mutation", "Cargo.lock"),
        ("schema_lock_mutation", "Cargo.lock"),
    ],
)
def test_locked_odra_build_rejects_false_green_or_mutated_outputs(
    tmp_path: Path,
    mode: str,
    message: str,
) -> None:
    repository, lock, wasm, schema = _repository(tmp_path)
    executor = _BuildExecutor(lock=lock, wasm=wasm, schema=schema, mode=mode)

    with pytest.raises(LockedOdraBuildError, match=message):
        verify_locked_odra_build(repository, executor=executor)

    assert _git(repository, "status", "--short") == ""


def test_locked_odra_build_allows_routine_dependency_names_containing_error(
    tmp_path: Path,
) -> None:
    repository, lock, wasm, schema = _repository(tmp_path)
    executor = _BuildExecutor(
        lock=lock,
        wasm=wasm,
        schema=schema,
        mode="routine_error_crate_names",
    )

    summary = verify_locked_odra_build(repository, executor=executor)

    assert summary["status"] == "verified"
    assert _git(repository, "status", "--short") == ""


def test_locked_odra_build_rejects_historical_inventory_drift_before_cargo(
    tmp_path: Path,
) -> None:
    repository, lock, wasm, schema = _repository(tmp_path)
    historical = repository / "contracts/odra-governance-receipt/Cargo.lock"
    historical.write_bytes(b"tampered historical lock\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "tamper historical inventory")
    executor = _BuildExecutor(lock=lock, wasm=wasm, schema=schema)

    with pytest.raises(LockedOdraBuildError, match="historical"):
        verify_locked_odra_build(repository, executor=executor)

    assert executor.calls == []


def test_locked_odra_build_rejects_manifest_toolchain_mismatch(
    tmp_path: Path,
) -> None:
    repository, lock, wasm, schema = _repository(tmp_path)
    manifest_path = repository / f"{CRATE_PATH}/deployment.manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["toolchain"]["cargo_odra"] = "0.1.6"
    manifest_path.write_bytes(_canonical(manifest))
    _git(repository, "add", str(manifest_path.relative_to(repository)))
    _git(repository, "commit", "-m", "forge manifest toolchain")
    executor = _BuildExecutor(lock=lock, wasm=wasm, schema=schema)

    with pytest.raises(LockedOdraBuildError, match="toolchain|cargo-odra"):
        verify_locked_odra_build(repository, executor=executor)


def test_locked_odra_build_rejects_manifest_command_mismatch(
    tmp_path: Path,
) -> None:
    repository, lock, wasm, schema = _repository(tmp_path)
    manifest_path = repository / f"{CRATE_PATH}/deployment.manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["build"]["schema_command"] = "cargo odra schema"
    manifest_path.write_bytes(_canonical(manifest))
    _git(repository, "add", str(manifest_path.relative_to(repository)))
    _git(repository, "commit", "-m", "forge manifest command")
    executor = _BuildExecutor(lock=lock, wasm=wasm, schema=schema)

    with pytest.raises(LockedOdraBuildError, match="commands|build contract"):
        verify_locked_odra_build(repository, executor=executor)

    assert executor.calls == []


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("unknown_key", "schema|field"),
        ("missing_key", "schema|field"),
        ("source_hash", "source|lib.rs"),
        ("abi_count", "ABI|entry"),
    ],
)
def test_locked_odra_build_rejects_manifest_claim_drift(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    repository, lock, wasm, schema = _repository(tmp_path)
    manifest_path = repository / f"{CRATE_PATH}/deployment.manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    if mutation == "unknown_key":
        manifest["unreviewed_release_claim"] = True
    elif mutation == "missing_key":
        del manifest["deployment_commit"]
    elif mutation == "source_hash":
        manifest["source"]["lib_rs_sha256"] = "0" * 64
    else:
        manifest["abi"]["entry_point_count"] = 999
    manifest_path.write_bytes(_canonical(manifest))
    _git(repository, "add", str(manifest_path.relative_to(repository)))
    _git(repository, "commit", "-m", f"forge manifest {mutation}")
    executor = _BuildExecutor(lock=lock, wasm=wasm, schema=schema)

    with pytest.raises(LockedOdraBuildError, match=message):
        verify_locked_odra_build(repository, executor=executor)

    assert executor.calls == []


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown_key",
        "wrong_contract",
        "invalid_mutability",
        "float_schema_version",
        "call_arguments_not_list",
        "entry_arguments_not_list",
        "entry_missing_return_type",
        "entry_access_not_text",
        "event_missing_type",
        "error_discriminant_not_integer",
        "invalid_type_descriptor",
    ],
)
def test_locked_odra_build_rejects_semantically_invalid_generated_schema(
    tmp_path: Path,
    mutation: str,
) -> None:
    repository, lock, wasm, schema = _repository(tmp_path)
    schema_path = repository / f"{CRATE_PATH}/{SCHEMA_PATH}"
    document = json.loads(schema)
    if mutation == "unknown_key":
        document["unreviewed_schema_claim"] = True
    elif mutation == "wrong_contract":
        document["contract_name"] = "OtherContract"
    elif mutation == "invalid_mutability":
        document["entry_points"][0]["is_mutable"] = "true"
    elif mutation == "float_schema_version":
        document["casper_contract_schema_version"] = 1.0
    elif mutation == "call_arguments_not_list":
        document["call"]["arguments"] = "not-a-list"
    elif mutation == "entry_arguments_not_list":
        document["entry_points"][0]["arguments"] = "not-a-list"
    elif mutation == "entry_missing_return_type":
        del document["entry_points"][0]["return_ty"]
    elif mutation == "entry_access_not_text":
        document["entry_points"][0]["access"] = {"public": True}
    elif mutation == "event_missing_type":
        del document["events"][0]["ty"]
    elif mutation == "error_discriminant_not_integer":
        document["errors"][0]["discriminant"] = "1"
    else:
        document["entry_points"][0]["return_ty"] = {"Unknown": "Unit"}
    mutated_schema = _canonical(document)
    schema_path.write_bytes(mutated_schema)
    manifest_path = repository / f"{CRATE_PATH}/deployment.manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["build"]["schema_sha256"] = hashlib.sha256(mutated_schema).hexdigest()
    manifest_path.write_bytes(_canonical(manifest))
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", f"forge generated schema {mutation}")
    executor = _BuildExecutor(
        lock=lock,
        wasm=wasm,
        schema=mutated_schema,
    )

    with pytest.raises(LockedOdraBuildError, match="schema|contract|mutable"):
        verify_locked_odra_build(repository, executor=executor)


def test_locked_odra_build_rejects_observed_toolchain_mismatch(
    tmp_path: Path,
) -> None:
    repository, lock, wasm, schema = _repository(tmp_path)
    executor = _BuildExecutor(
        lock=lock,
        wasm=wasm,
        schema=schema,
        mode="toolchain_mismatch",
    )

    with pytest.raises(LockedOdraBuildError, match="toolchain|rustc|LLVM"):
        verify_locked_odra_build(repository, executor=executor)
