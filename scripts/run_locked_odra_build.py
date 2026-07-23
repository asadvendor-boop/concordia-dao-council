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
    rb"|(?im:(?:^|[\r\n])[ \t]*"
    rb"(?:(?:cargo(?:-odra)?|rustc)[ \t]*:[ \t]*)?"
    rb"(?:error|fatal)(?:\[[^\]\r\n]{1,32}\])?[ \t]*:)"
    rb"|(?i:\bthread [^\r\n]* panicked)\b"
    rb")"
)
_DEPLOYMENT_MANIFEST_FIELDS = frozenset(
    {
        "abi",
        "build",
        "contract_hash",
        "contract_name",
        "contract_version",
        "deployment_commit",
        "deployment_domain",
        "historical_isolation",
        "install_block_hash",
        "install_block_height",
        "install_deploy_hash",
        "install_state_root_hash",
        "installation_nonce",
        "locked_install",
        "network",
        "note",
        "package_hash",
        "package_key_name",
        "roles",
        "schema_id",
        "source",
        "source_commit",
        "status",
        "toolchain",
    }
)
_BUILD_MANIFEST_FIELDS = frozenset(
    {
        "command",
        "schema_command",
        "schema_path",
        "schema_sha256",
        "wasm_path",
        "wasm_sha256",
        "wasm_size_bytes",
    }
)
_SOURCE_MANIFEST_FIELDS = frozenset(
    {"cargo_lock_sha256", "encoding_rs_sha256", "lib_rs_sha256"}
)
_HISTORICAL_ISOLATION_FIELDS = frozenset(
    {"manifest_sha256", "pre_post_diff", "tracked_file_count"}
)
_ABI_MANIFEST_FIELDS = frozenset(
    {
        "entry_point_count",
        "error_count",
        "event_count",
        "mutable_entry_point_count",
        "query_entry_point_count",
    }
)
_TOOLCHAIN_MANIFEST_FIELDS = frozenset({"cargo_odra", "odra", "rustc"})
_LOCKED_INSTALL_FIELDS = frozenset(
    {
        "odra_cfg_allow_key_override",
        "odra_cfg_is_upgradable",
        "odra_cfg_is_upgrade",
    }
)
_CASPER_SCHEMA_FIELDS = frozenset(
    {
        "authors",
        "call",
        "casper_contract_schema_version",
        "contract_name",
        "contract_version",
        "entry_points",
        "errors",
        "events",
        "homepage",
        "repository",
        "toolchain",
        "types",
    }
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


def _exact_fields(
    value: Mapping[str, Any],
    expected: frozenset[str],
    label: str,
) -> None:
    observed = set(value)
    if observed != expected:
        missing = sorted(expected - observed)
        unknown = sorted(observed - expected)
        detail = []
        if missing:
            detail.append("missing=" + ",".join(missing))
        if unknown:
            detail.append("unknown=" + ",".join(unknown))
        raise LockedOdraBuildError(
            f"{label} field schema differs ({'; '.join(detail)})"
        )


def _bounded_count(
    value: object,
    label: str,
    *,
    maximum: int = 10_000,
) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise LockedOdraBuildError(f"{label} must be a bounded nonnegative integer")
    return value


def _verify_deployment_manifest_schema(
    archive_root: Path,
    manifest: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Validate every tracked template claim before invoking a build tool."""

    _exact_fields(manifest, _DEPLOYMENT_MANIFEST_FIELDS, "v3 deployment manifest")
    build = _mapping(manifest.get("build"), "v3 build manifest")
    source = _mapping(manifest.get("source"), "v3 source manifest")
    historical = _mapping(
        manifest.get("historical_isolation"),
        "historical isolation manifest",
    )
    abi = _mapping(manifest.get("abi"), "v3 ABI manifest")
    toolchain = _mapping(manifest.get("toolchain"), "v3 toolchain manifest")
    locked_install = _mapping(
        manifest.get("locked_install"),
        "v3 locked-install manifest",
    )
    _exact_fields(build, _BUILD_MANIFEST_FIELDS, "v3 build manifest")
    _exact_fields(source, _SOURCE_MANIFEST_FIELDS, "v3 source manifest")
    _exact_fields(
        historical,
        _HISTORICAL_ISOLATION_FIELDS,
        "historical isolation manifest",
    )
    _exact_fields(abi, _ABI_MANIFEST_FIELDS, "v3 ABI manifest")
    _exact_fields(toolchain, _TOOLCHAIN_MANIFEST_FIELDS, "v3 toolchain manifest")
    _exact_fields(
        locked_install,
        _LOCKED_INSTALL_FIELDS,
        "v3 locked-install manifest",
    )
    if (
        manifest.get("schema_id") != "concordia.v3-deployment-manifest.v1"
        or manifest.get("status") != "built_uninstalled"
        or manifest.get("network") != "casper-test"
        or manifest.get("package_key_name") != "concordia_governance_receipt_v3"
        or manifest.get("contract_name") != "GovernanceReceiptV3"
    ):
        raise LockedOdraBuildError(
            "v3 deployment manifest identity differs from the frozen template"
        )
    nullable_template_fields = (
        "contract_hash",
        "contract_version",
        "deployment_commit",
        "deployment_domain",
        "install_block_hash",
        "install_block_height",
        "install_deploy_hash",
        "install_state_root_hash",
        "installation_nonce",
        "package_hash",
        "roles",
        "source_commit",
    )
    if any(manifest.get(field) is not None for field in nullable_template_fields):
        raise LockedOdraBuildError(
            "v3 deployment manifest contains premature live-install claims"
        )
    if locked_install != {
        "odra_cfg_allow_key_override": False,
        "odra_cfg_is_upgradable": False,
        "odra_cfg_is_upgrade": False,
    }:
        raise LockedOdraBuildError(
            "v3 locked-install manifest differs from the frozen policy"
        )
    if toolchain != _EXPECTED_MANIFEST_TOOLCHAIN:
        raise LockedOdraBuildError(
            "v3 deployment manifest toolchain differs from the frozen contract"
        )
    _text(manifest.get("note"), "v3 deployment manifest note")
    _bounded_count(
        build.get("wasm_size_bytes"),
        "v3 Wasm size",
        maximum=_MAX_FILE_BYTES,
    )
    _bounded_count(historical.get("tracked_file_count"), "historical file count")
    for field in _ABI_MANIFEST_FIELDS:
        _bounded_count(abi.get(field), f"v3 ABI {field}")
    if (
        _sha256(source.get("lib_rs_sha256"), "v3 source lib.rs SHA-256")
        != hashlib.sha256(
            _read_regular(archive_root, f"{CRATE_PATH}/src/lib.rs")
        ).hexdigest()
    ):
        raise LockedOdraBuildError("v3 source lib.rs digest differs")
    if (
        _sha256(
            source.get("encoding_rs_sha256"),
            "v3 source encoding.rs SHA-256",
        )
        != hashlib.sha256(
            _read_regular(archive_root, f"{CRATE_PATH}/src/encoding.rs")
        ).hexdigest()
    ):
        raise LockedOdraBuildError("v3 source encoding.rs digest differs")
    return build, source, abi


def _named_schema_rows(value: object, label: str) -> list[dict[str, Any]]:
    if type(value) is not list:
        raise LockedOdraBuildError(f"v3 schema {label} must be a list")
    rows: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, item in enumerate(value):
        row = _mapping(item, f"v3 schema {label}[{index}]")
        name = _text(row.get("name"), f"v3 schema {label}[{index}].name")
        if name in names:
            raise LockedOdraBuildError(f"v3 schema {label} names must be unique")
        names.add(name)
        rows.append(row)
    return rows


def _verify_generated_schema(
    raw: bytes,
    *,
    abi: Mapping[str, Any],
    manifest_toolchain: Mapping[str, Any],
) -> dict[str, Any]:
    schema = _strict_json(raw, "generated v3 Casper schema")
    _exact_fields(schema, _CASPER_SCHEMA_FIELDS, "generated v3 Casper schema")
    if (
        schema.get("casper_contract_schema_version") != 1
        or schema.get("contract_name") != "GovernanceReceiptV3"
        or schema.get("toolchain") != f"rustc {manifest_toolchain.get('rustc')}"
    ):
        raise LockedOdraBuildError(
            "generated v3 Casper schema contract or toolchain differs"
        )
    _text(schema.get("contract_version"), "generated v3 contract version")
    if type(schema.get("authors")) is not list or type(schema.get("types")) is not list:
        raise LockedOdraBuildError("generated v3 Casper schema lists are malformed")
    if (
        schema.get("repository") is not None
        and type(schema.get("repository")) is not str
    ):
        raise LockedOdraBuildError("generated v3 schema repository is malformed")
    if schema.get("homepage") is not None and type(schema.get("homepage")) is not str:
        raise LockedOdraBuildError("generated v3 schema homepage is malformed")
    call = _mapping(schema.get("call"), "generated v3 call schema")
    if call.get("wasm_file_name") != Path(WASM_PATH).name:
        raise LockedOdraBuildError("generated v3 schema Wasm filename differs")
    entry_points = _named_schema_rows(schema.get("entry_points"), "entry points")
    events = _named_schema_rows(schema.get("events"), "events")
    errors = _named_schema_rows(schema.get("errors"), "errors")
    mutable = 0
    for index, row in enumerate(entry_points):
        is_mutable = row.get("is_mutable")
        if type(is_mutable) is not bool:
            raise LockedOdraBuildError(
                f"generated v3 schema entry point {index} mutable flag is invalid"
            )
        mutable += int(is_mutable)
    observed = {
        "entry_point_count": len(entry_points),
        "mutable_entry_point_count": mutable,
        "query_entry_point_count": len(entry_points) - mutable,
        "event_count": len(events),
        "error_count": len(errors),
    }
    if any(abi.get(field) != count for field, count in observed.items()):
        raise LockedOdraBuildError(
            "generated v3 schema ABI entry/event/error counts differ from manifest"
        )
    return schema


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
    if isolation.get("pre_post_diff") != "empty":
        raise LockedOdraBuildError(
            "historical isolation pre/post diff must remain empty"
        )
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
        build, source, abi = _verify_deployment_manifest_schema(
            archive_root,
            manifest,
        )
        toolchain_manifest = _mapping(manifest["toolchain"], "v3 toolchain manifest")
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
        _verify_generated_schema(
            tracked_schema,
            abi=abi,
            manifest_toolchain=toolchain_manifest,
        )
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
        _verify_generated_schema(
            generated_schema_bytes,
            abi=abi,
            manifest_toolchain=toolchain_manifest,
        )

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
