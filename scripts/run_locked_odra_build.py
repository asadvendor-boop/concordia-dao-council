#!/usr/bin/env python3
"""Rebuild the v3 Odra artifacts from a fresh tracked copy, fail closed."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from shared.bound_command import BoundCommandError, run_bound_command
from shared.release_gate_contract import BOUND_GIT_CONFIG_OVERRIDES


ROOT = Path(__file__).resolve().parents[1]
CRATE_PATH = "contracts/odra-governance-receipt-v3"
HISTORICAL_PATH = "contracts/odra-governance-receipt"
HISTORICAL_SHA_PATH = "handoff/HISTORICAL_ODRA_SHA256.txt"
HISTORICAL_INVENTORY_PATH = "handoff/HISTORICAL_ODRA_RECEIPTS_V1.json"
DEPLOYMENT_MANIFEST_PATH = f"{CRATE_PATH}/deployment.manifest.json"
WASM_PATH = "wasm/GovernanceReceiptV3.wasm"
SCHEMA_PATH = "resources/casper_contract_schemas/governance_receiptv3_schema.json"
BUILD_COMMAND = (
    "cargo",
    "--locked",
    "odra",
    "build",
    "-c",
    "GovernanceReceiptV3",
)
SCHEMA_COMMAND = (
    "cargo",
    "--locked",
    "odra",
    "schema",
    "-c",
    "GovernanceReceiptV3",
)
_MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
_MAX_FILE_BYTES = 64 * 1024 * 1024
_MAX_COMMAND_OUTPUT = 64 * 1024 * 1024
_HEX32 = re.compile(r"^[0-9a-f]{64}$")
_HISTORICAL_ROW = re.compile(r"^([0-9a-f]{64})  ([^\s]+)$")
_ANSI_ESCAPE = re.compile(
    rb"(?:"
    rb"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]"
    rb"|(?:\x1b\]|\x9d)(?:[^\x07\x1b\x9c]|\x1b(?!\\))*"
    rb"(?:\x07|\x1b\\|\x9c)"
    rb"|(?:\x1b[PX^_]|\x90|\x98|\x9e|\x9f).*?(?:\x07|\x1b\\|\x9c)"
    rb"|\x1b[ -/]*[0-~]"
    rb")",
    re.DOTALL,
)
_CARGO_FATAL = re.compile(
    rb"("
    rb"\b(?:ERROR|FATAL)\b"
    rb"|(?m:^[ \t]*(?:error|fatal)(?:\[[^\]\r\n]{1,32}\])?:)"
    rb"|(?i:\bthread [^\r\n]* panicked)\b"
    rb")"
)
_EXPECTED_MANIFEST_TOOLCHAIN = {
    "cargo_odra": "0.1.7",
    "odra": "2.8.2",
    "rustc": "1.86.0-nightly (854f22563 2025-01-31)",
}
_EXPECTED_OBSERVED_TOOLCHAIN = {
    "cargo": "cargo 1.86.0-nightly (cecde95c1 2025-01-24)",
    "cargo_odra": "cargo-odra 0.1.7",
    "rustc": (
        "rustc 1.86.0-nightly (854f22563 2025-01-31)\n"
        "binary: rustc\n"
        "commit-hash: 854f22563c8daf92709fae18ee6aed52953835cd\n"
        "commit-date: 2025-01-31\n"
        "host: aarch64-apple-darwin\n"
        "release: 1.86.0-nightly\n"
        "LLVM version: 19.1.7"
    ),
}


class LockedOdraBuildError(RuntimeError):
    """The locked, isolated Odra build could not be proven."""


Executor = Callable[..., subprocess.CompletedProcess[bytes]]


def _safe_tool_path() -> str:
    locations = [
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
        "/usr/local/bin",
        "/opt/homebrew/bin",
    ]
    cargo_bin = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".cargo/bin"
    if cargo_bin.is_dir():
        locations.append(str(cargo_bin))
    return os.pathsep.join(locations)


def _execute(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int,
) -> subprocess.CompletedProcess[bytes]:
    executable = shutil.which(argv[0], path=env["PATH"])
    if not executable:
        raise LockedOdraBuildError(f"required build tool is unavailable: {argv[0]}")
    return subprocess.run(
        [executable, *argv[1:]],
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )


def _git(repository_root: Path, *arguments: str, limit: int) -> bytes:
    try:
        result = run_bound_command(
            cwd=repository_root,
            tool_id="git",
            argv=(
                "git",
                "--no-replace-objects",
                *BOUND_GIT_CONFIG_OVERRIDES,
                "-C",
                repository_root.as_posix(),
                *arguments,
            ),
            env={
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
                "LANG": "C",
                "LC_ALL": "C",
            },
            stdout_limit=limit,
            stderr_limit=4 * 1024 * 1024,
            timeout_s=120,
            check=False,
        )
    except BoundCommandError as exc:
        raise LockedOdraBuildError("tracked-source Git operation failed") from exc
    if result.returncode != 0:
        raise LockedOdraBuildError("tracked-source Git operation returned an error")
    return result.stdout


def _git_text(repository_root: Path, *arguments: str) -> str:
    try:
        return (
            _git(
                repository_root,
                *arguments,
                limit=4 * 1024 * 1024,
            )
            .decode("ascii")
            .strip()
        )
    except UnicodeDecodeError as exc:
        raise LockedOdraBuildError("tracked-source Git output is not ASCII") from exc


def _canonical_json(value: object) -> bytes:
    try:
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
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise LockedOdraBuildError("build summary is not canonical JSON") from exc


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise LockedOdraBuildError(f"{label} has duplicate key {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise LockedOdraBuildError(f"{label} has invalid constant {value}")

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LockedOdraBuildError(f"{label} is not strict UTF-8 JSON") from exc
    if type(value) is not dict:
        raise LockedOdraBuildError(f"{label} must be a JSON object")
    return value


def _mapping(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise LockedOdraBuildError(f"{label} must be an object")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise LockedOdraBuildError(f"{label} must be nonempty text")
    return value


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or _HEX32.fullmatch(value) is None:
        raise LockedOdraBuildError(f"{label} must be a lowercase SHA-256")
    return value


def _safe_archive_path(name: str) -> tuple[str, ...]:
    path = PurePosixPath(name)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in name
    ):
        raise LockedOdraBuildError("git archive contains an unsafe path")
    return path.parts


def _extract_archive(raw: bytes, destination: Path) -> None:
    total = 0
    try:
        archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
    except tarfile.TarError as exc:
        raise LockedOdraBuildError("tracked-source archive is invalid") from exc
    with archive:
        for member in archive.getmembers():
            parts = _safe_archive_path(member.name)
            if member.isdir():
                (destination.joinpath(*parts)).mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile() or member.size > _MAX_FILE_BYTES:
                raise LockedOdraBuildError(
                    "tracked-source archive contains a non-regular member"
                )
            total += member.size
            if total > _MAX_ARCHIVE_BYTES:
                raise LockedOdraBuildError("tracked-source archive is too large")
            source = archive.extractfile(member)
            if source is None:
                raise LockedOdraBuildError(
                    "tracked-source archive member is unreadable"
                )
            target = destination.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            raw_member = source.read(_MAX_FILE_BYTES + 1)
            if len(raw_member) != member.size:
                raise LockedOdraBuildError(
                    "tracked-source archive member changed while read"
                )
            target.write_bytes(raw_member)


def _read_regular(root: Path, relative: str) -> bytes:
    parts = PurePosixPath(relative).parts
    for part in parts:
        if part in {"", ".", ".."}:
            raise LockedOdraBuildError(f"unsafe build path: {relative}")
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(root, directory_flags)
    try:
        for part in parts[:-1]:
            next_descriptor = os.open(part, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        try:
            file_descriptor = os.open(
                parts[-1],
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
        except OSError as exc:
            raise LockedOdraBuildError(
                f"required build file is missing: {relative}"
            ) from exc
        try:
            before = os.fstat(file_descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_FILE_BYTES:
                raise LockedOdraBuildError(
                    f"build file is not bounded and regular: {relative}"
                )
            chunks: list[bytes] = []
            remaining = _MAX_FILE_BYTES + 1
            while remaining:
                chunk = os.read(file_descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(file_descriptor)
            if (
                len(raw) != before.st_size
                or len(raw) > _MAX_FILE_BYTES
                or (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                )
                != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                )
            ):
                raise LockedOdraBuildError(f"build file changed while read: {relative}")
            return raw
        finally:
            os.close(file_descriptor)
    except LockedOdraBuildError:
        raise
    except OSError as exc:
        raise LockedOdraBuildError(
            f"build path cannot be read without symlinks: {relative}"
        ) from exc
    finally:
        os.close(descriptor)


def _verify_historical_inventory(
    archive_root: Path, manifest: Mapping[str, Any]
) -> int:
    sha_raw = _read_regular(archive_root, HISTORICAL_SHA_PATH)
    isolation = _mapping(manifest.get("historical_isolation"), "historical isolation")
    expected_manifest_hash = _sha256(
        isolation.get("manifest_sha256"), "historical manifest SHA-256"
    )
    if hashlib.sha256(sha_raw).hexdigest() != expected_manifest_hash:
        raise LockedOdraBuildError("historical SHA inventory digest differs")

    rows: dict[str, str] = {}
    try:
        lines = sha_raw.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise LockedOdraBuildError("historical SHA inventory is not UTF-8") from exc
    for line in lines:
        if not line or line.startswith("#"):
            continue
        match = _HISTORICAL_ROW.fullmatch(line)
        if match is None:
            raise LockedOdraBuildError("historical SHA inventory row is malformed")
        digest, relative = match.groups()
        if relative in rows or not relative.startswith(HISTORICAL_PATH + "/"):
            raise LockedOdraBuildError("historical SHA inventory path is invalid")
        rows[relative] = digest
    tracked = {
        path.relative_to(archive_root).as_posix()
        for path in (archive_root / HISTORICAL_PATH).rglob("*")
        if path.is_file()
    }
    if set(rows) != tracked or isolation.get("tracked_file_count") != len(rows):
        raise LockedOdraBuildError("historical tracked-file inventory differs")
    for relative, expected in rows.items():
        if (
            hashlib.sha256(_read_regular(archive_root, relative)).hexdigest()
            != expected
        ):
            raise LockedOdraBuildError(f"historical file digest differs: {relative}")

    inventory = _strict_json(
        _read_regular(archive_root, HISTORICAL_INVENTORY_PATH),
        "historical Odra inventory",
    )
    preserved = _mapping(
        inventory.get("preserved_repo_source"), "preserved historical source"
    )
    if (
        preserved.get("manifest_path") != HISTORICAL_SHA_PATH
        or preserved.get("manifest_sha256") != expected_manifest_hash
    ):
        raise LockedOdraBuildError("historical preserved manifest binding differs")
    wasm_path = _text(
        preserved.get("governance_receipt_wasm_path"),
        "historical governance receipt Wasm path",
    )
    wasm_sha = _sha256(
        preserved.get("governance_receipt_wasm_sha256"),
        "historical governance receipt Wasm SHA-256",
    )
    if (
        wasm_path not in rows
        or rows[wasm_path] != wasm_sha
        or hashlib.sha256(_read_regular(archive_root, wasm_path)).hexdigest()
        != wasm_sha
    ):
        raise LockedOdraBuildError("historical governance receipt Wasm differs")
    return len(rows)


def _build_environment(temporary_root: Path) -> dict[str, str]:
    environment = {
        "CARGO_HOME": str(temporary_root / "cargo-home"),
        "HOME": str(temporary_root / "home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "PATH": _safe_tool_path(),
        "TMPDIR": str(temporary_root / "tmp"),
    }
    for relative in ("cargo-home", "home", "tmp"):
        (temporary_root / relative).mkdir(mode=0o700)
    rustup_home = os.environ.get("RUSTUP_HOME")
    if rustup_home and Path(rustup_home).is_absolute():
        environment["RUSTUP_HOME"] = rustup_home
    else:
        account_rustup = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".rustup"
        if account_rustup.is_dir():
            environment["RUSTUP_HOME"] = str(account_rustup)
    return environment


def _run_cargo(
    executor: Executor,
    argv: tuple[str, ...],
    *,
    cwd: Path,
    environment: dict[str, str],
    offline: bool,
    timeout: int,
) -> subprocess.CompletedProcess[bytes]:
    env = dict(environment)
    if offline:
        env["CARGO_NET_OFFLINE"] = "true"
    try:
        result = executor(argv, cwd=cwd, env=env, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise LockedOdraBuildError(f"{' '.join(argv)} timed out") from exc
    except OSError as exc:
        raise LockedOdraBuildError(f"{' '.join(argv)} failed to execute") from exc
    if (
        len(result.stdout) > _MAX_COMMAND_OUTPUT
        or len(result.stderr) > _MAX_COMMAND_OUTPUT
    ):
        raise LockedOdraBuildError(f"{' '.join(argv)} output exceeded its bound")
    if result.returncode != 0:
        raise LockedOdraBuildError(f"{' '.join(argv)} returned an error")
    if offline and b"Updating crates.io index" in result.stdout + result.stderr:
        raise LockedOdraBuildError(f"{' '.join(argv)} attempted network access")
    return result


def _fatal_cargo_diagnostic(stdout: bytes, stderr: bytes) -> str | None:
    """Return a fatal cargo-odra diagnostic after removing terminal controls."""

    combined = _ANSI_ESCAPE.sub(b"", stdout + b"\n" + stderr)
    combined = bytes(
        value
        for value in combined
        if value in {0x09, 0x0A, 0x0D} or 0x20 <= value <= 0x7E
    )
    match = _CARGO_FATAL.search(combined)
    if match is None:
        return None
    return match.group(1).decode("ascii", errors="replace")


def _observed_toolchain_version(
    result: subprocess.CompletedProcess[bytes],
    *,
    label: str,
) -> str:
    try:
        streams = [
            raw.decode("utf-8", errors="strict")
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .strip()
            for raw in (result.stdout, result.stderr)
            if raw
        ]
    except UnicodeDecodeError as exc:
        raise LockedOdraBuildError(f"{label} toolchain output is not UTF-8") from exc
    observed = "\n".join(value for value in streams if value)
    if (
        not observed
        or len(observed.encode("utf-8")) > 4096
        or any(
            character != "\n" and not character.isprintable() for character in observed
        )
    ):
        raise LockedOdraBuildError(f"{label} toolchain output is malformed")
    return observed


def _verify_observed_toolchain(
    executor: Executor,
    *,
    cwd: Path,
    environment: dict[str, str],
) -> dict[str, str]:
    probes = (
        ("cargo", ("cargo", "--version")),
        ("cargo_odra", ("cargo", "odra", "--version")),
        ("rustc", ("rustc", "-vV")),
    )
    observed: dict[str, str] = {}
    for label, argv in probes:
        result = _run_cargo(
            executor,
            argv,
            cwd=cwd,
            environment=environment,
            offline=False,
            timeout=60,
        )
        version = _observed_toolchain_version(result, label=label)
        if version != _EXPECTED_OBSERVED_TOOLCHAIN[label]:
            raise LockedOdraBuildError(
                f"{label} toolchain differs from the frozen build contract"
            )
        observed[label] = version
    return observed


def verify_locked_odra_build(
    repository_root: str | Path,
    *,
    executor: Executor = _execute,
) -> dict[str, object]:
    """Rebuild from tracked bytes and verify every release-relevant invariant."""

    root = Path(repository_root)
    if root.is_symlink():
        raise LockedOdraBuildError("repository root cannot be a symlink")
    root = root.resolve(strict=True)
    if Path(_git_text(root, "rev-parse", "--show-toplevel")).resolve() != root:
        raise LockedOdraBuildError("repository root is not the Git worktree root")
    if _git(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        limit=4 * 1024 * 1024,
    ):
        raise LockedOdraBuildError("locked Odra build requires a clean Git worktree")
    source_commit = _git_text(root, "rev-parse", "HEAD^{commit}")
    archive = _git(
        root,
        "archive",
        "--format=tar",
        source_commit,
        "--",
        CRATE_PATH,
        HISTORICAL_PATH,
        HISTORICAL_SHA_PATH,
        HISTORICAL_INVENTORY_PATH,
        limit=_MAX_ARCHIVE_BYTES,
    )

    with tempfile.TemporaryDirectory(prefix="concordia-locked-odra-") as name:
        temporary_root = Path(name).resolve()
        archive_root = temporary_root / "tracked"
        archive_root.mkdir(mode=0o700)
        _extract_archive(archive, archive_root)
        manifest = _strict_json(
            _read_regular(archive_root, DEPLOYMENT_MANIFEST_PATH),
            "v3 deployment manifest",
        )
        build = _mapping(manifest.get("build"), "v3 build manifest")
        source = _mapping(manifest.get("source"), "v3 source manifest")
        toolchain_manifest = _mapping(
            manifest.get("toolchain"),
            "v3 toolchain manifest",
        )
        if toolchain_manifest != _EXPECTED_MANIFEST_TOOLCHAIN:
            raise LockedOdraBuildError(
                "v3 deployment manifest toolchain differs from the frozen contract"
            )
        if (
            build.get("command") != " ".join(BUILD_COMMAND)
            or build.get("schema_command") != " ".join(SCHEMA_COMMAND)
            or build.get("wasm_path") != WASM_PATH
            or build.get("schema_path") != SCHEMA_PATH
        ):
            raise LockedOdraBuildError(
                "v3 commands or output paths differ from the build contract"
            )
        expected_wasm = _sha256(build.get("wasm_sha256"), "v3 Wasm SHA-256")
        expected_schema = _sha256(build.get("schema_sha256"), "v3 schema SHA-256")
        expected_lock = _sha256(source.get("cargo_lock_sha256"), "Cargo.lock SHA-256")
        crate = archive_root / CRATE_PATH
        lock_path = crate / "Cargo.lock"
        lock_before = hashlib.sha256(
            _read_regular(archive_root, f"{CRATE_PATH}/Cargo.lock")
        ).hexdigest()
        if lock_before != expected_lock:
            raise LockedOdraBuildError(
                "Cargo.lock digest differs from deployment manifest"
            )
        tracked_wasm = _read_regular(archive_root, f"{CRATE_PATH}/{WASM_PATH}")
        tracked_schema = _read_regular(archive_root, f"{CRATE_PATH}/{SCHEMA_PATH}")
        if (
            hashlib.sha256(tracked_wasm).hexdigest() != expected_wasm
            or hashlib.sha256(tracked_schema).hexdigest() != expected_schema
            or build.get("wasm_size_bytes") != len(tracked_wasm)
        ):
            raise LockedOdraBuildError(
                "tracked v3 artifacts differ from deployment manifest"
            )
        historical_count = _verify_historical_inventory(archive_root, manifest)

        environment = _build_environment(temporary_root)
        observed_toolchain = _verify_observed_toolchain(
            executor,
            cwd=crate,
            environment=environment,
        )
        (crate / WASM_PATH).unlink()
        (crate / SCHEMA_PATH).unlink()
        if (crate / WASM_PATH).exists() or (crate / SCHEMA_PATH).exists():
            raise LockedOdraBuildError("stale v3 output removal failed")

        _run_cargo(
            executor,
            ("cargo", "fetch", "--locked"),
            cwd=crate,
            environment=environment,
            offline=False,
            timeout=900,
        )
        if hashlib.sha256(lock_path.read_bytes()).hexdigest() != lock_before:
            raise LockedOdraBuildError("Cargo.lock changed during locked fetch")
        metadata = _run_cargo(
            executor,
            (
                "cargo",
                "metadata",
                "--locked",
                "--offline",
                "--format-version",
                "1",
                "--no-deps",
            ),
            cwd=crate,
            environment=environment,
            offline=True,
            timeout=300,
        )
        metadata_document = _strict_json(metadata.stdout, "offline Cargo metadata")
        if type(metadata_document.get("packages")) is not list:
            raise LockedOdraBuildError("offline Cargo metadata is malformed")
        if hashlib.sha256(lock_path.read_bytes()).hexdigest() != lock_before:
            raise LockedOdraBuildError("Cargo.lock changed during offline metadata")
        built = _run_cargo(
            executor,
            BUILD_COMMAND,
            cwd=crate,
            environment=environment,
            offline=True,
            timeout=1800,
        )
        fatal_diagnostic = _fatal_cargo_diagnostic(built.stdout, built.stderr)
        if fatal_diagnostic is not None:
            raise LockedOdraBuildError(
                f"cargo-odra printed {fatal_diagnostic} despite returning exit code zero"
            )
        if hashlib.sha256(lock_path.read_bytes()).hexdigest() != lock_before:
            raise LockedOdraBuildError("Cargo.lock changed during cargo-odra build")
        generated_schema = _run_cargo(
            executor,
            SCHEMA_COMMAND,
            cwd=crate,
            environment=environment,
            offline=True,
            timeout=1800,
        )
        fatal_diagnostic = _fatal_cargo_diagnostic(
            generated_schema.stdout,
            generated_schema.stderr,
        )
        if fatal_diagnostic is not None:
            raise LockedOdraBuildError(
                "cargo-odra schema printed "
                f"{fatal_diagnostic} despite returning exit code zero"
            )
        if hashlib.sha256(lock_path.read_bytes()).hexdigest() != lock_before:
            raise LockedOdraBuildError(
                "Cargo.lock changed during cargo-odra schema generation"
            )
        generated_wasm = _read_regular(archive_root, f"{CRATE_PATH}/{WASM_PATH}")
        generated_schema_bytes = _read_regular(
            archive_root,
            f"{CRATE_PATH}/{SCHEMA_PATH}",
        )
        if hashlib.sha256(generated_wasm).hexdigest() != expected_wasm or len(
            generated_wasm
        ) != build.get("wasm_size_bytes"):
            raise LockedOdraBuildError("regenerated Wasm digest or size differs")
        if hashlib.sha256(generated_schema_bytes).hexdigest() != expected_schema:
            raise LockedOdraBuildError("regenerated schema digest differs")

    if _git_text(root, "rev-parse", "HEAD^{commit}") != source_commit:
        raise LockedOdraBuildError("source commit changed during locked Odra build")
    if _git(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        limit=4 * 1024 * 1024,
    ):
        raise LockedOdraBuildError("locked Odra build changed the source worktree")
    return {
        "cargo_lock_sha256": lock_before,
        "historical_file_count": historical_count,
        "schema_sha256": expected_schema,
        "status": "verified",
        "toolchain": observed_toolchain,
        "wasm_sha256": expected_wasm,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    if not args.verify_only:
        print(
            json.dumps(
                {
                    "error": "--verify-only is required",
                    "status": "invalid",
                },
                sort_keys=True,
            )
        )
        return 2
    try:
        result = verify_locked_odra_build(args.repository_root)
    except (LockedOdraBuildError, OSError) as exc:
        print(json.dumps({"error": str(exc), "status": "invalid"}, sort_keys=True))
        return 1
    print(_canonical_json(result).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
