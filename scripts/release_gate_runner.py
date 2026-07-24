"""Fail-closed executor for Concordia's fixed command-gate receipts."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import platform
import pwd
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

import yaml

from shared.bound_command import (
    BoundCommandError,
    bound_process_launcher_identity,
    run_bounded_process,
)
from shared.release_gate_contract import (
    BOUND_GIT_CONFIG_OVERRIDES,
    COMMAND_GATE_COMMANDS,
    COMMAND_GATE_EXECUTION_POLICY,
    COMMAND_GATE_EXPECTED_RUNTIME_VERSIONS,
    COMMAND_GATE_EXECUTABLE_CHAIN_POLICY,
    COMMAND_GATE_EXECUTABLE_CHAIN_SCHEMA_VERSION,
    COMMAND_GATE_FRESH_OUTPUT_PATHS,
    COMMAND_GATE_G9_LIVE_TEST_BUILD_PROFILE,
    COMMAND_GATE_G9_PUBLIC_BUILD_PROFILE,
    COMMAND_GATE_IDENTITY_PATHS,
    COMMAND_GATE_INPUT_ARTIFACT_PATHS,
    COMMAND_GATE_NORMALIZATION,
    COMMAND_GATE_PRODUCED_ARTIFACT_PATHS,
    COMMAND_GATE_PUBLIC_BUILD_PROFILE_SCHEMA_VERSION,
    COMMAND_GATE_RECEIPT_PATHS,
    COMMAND_GATE_RECEIPT_SCHEMA_VERSION,
    COMMAND_GATE_REQUIRED_RUNTIMES,
    COMMAND_GATE_RUNTIME_PROBES,
    COMMAND_GATE_RUNTIME_TIMEOUT_SECONDS,
    COMMAND_GATE_SECRET_COMPOSE_PATH,
    COMMAND_GATE_SECRET_DIRECTORIES,
    COMMAND_GATE_TIMEOUT_SECONDS,
    COMMAND_GATE_UV_PYTHON,
    G1_FREEZE_COMMIT,
    G1_FREEZE_TAG,
    G1_FREEZE_TAG_OBJECT,
)
from shared.secret_variants import normalize_sensitive_key, secret_variants


_MAX_LOG_BYTES = int(COMMAND_GATE_EXECUTION_POLICY["maximum_output_stream_bytes"])
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
_MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
_GIT_OUTPUT_LIMIT = 70 * 1024 * 1024
_TRUSTED_GIT_PATH = Path(str(COMMAND_GATE_EXECUTION_POLICY["trusted_git_path"]))
_SENSITIVE_ENV_PARTS = frozenset(
    {
        "token",
        "authorization",
        "credential",
        "password",
        "privatekey",
        "apikey",
        "secret",
    }
)
_SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(rb"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(rb"\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{12,}\b"),
    re.compile(rb"\bnpm_[A-Za-z0-9]{24,}\b"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(
        rb"(?i)\b(?:authorization|credential|password|private[_ -]?key|secret|token)"
        rb"\s*[:=]\s*[^\s]{4,}"
    ),
)
_APPROVED_SECRET_DIRECTORIES = tuple(
    Path(path) for path in COMMAND_GATE_SECRET_DIRECTORIES
)
_MAX_SECRET_BYTES = 1024 * 1024
_COMPOSE_ENV_DEFAULT = re.compile(r"^\$\{([A-Z][A-Z0-9_]*):-([^}]+)\}$")
_MACHO_ARCHITECTURES = {
    0x01000007: "x86_64",
    0x0100000C: "arm64",
}


class GateRunError(RuntimeError):
    """A command gate failed without publishing a receipt batch."""


@dataclass(frozen=True)
class GateRunResult:
    gate_id: str
    receipt_path: str
    receipt_sha256: str


@dataclass(frozen=True)
class _CapturedCommand:
    command_id: str
    working_directory: str
    argv: tuple[str, ...]
    started_at: str
    ended_at: str
    stdout: bytes
    stderr: bytes
    executable_chain: tuple[dict[str, object], ...]


Executor = Callable[
    ...,
    subprocess.CompletedProcess[bytes],
]


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
        raise GateRunError("command-gate receipt is not canonical JSON") from exc


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _read_descriptor_file(
    root: Path,
    parts: Sequence[str],
    *,
    limit: int,
    label: str,
) -> bytes:
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(root, directory_flags)
    try:
        for part in parts[:-1]:
            next_descriptor = os.open(part, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        file_descriptor = os.open(parts[-1], file_flags, dir_fd=descriptor)
        try:
            before = os.fstat(file_descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                raise GateRunError(f"{label} is not a bounded regular file")
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining:
                chunk = os.read(file_descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(file_descriptor)
            identity_before = (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            identity_after = (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            if (
                len(raw) != before.st_size
                or len(raw) > limit
                or identity_before != identity_after
            ):
                raise GateRunError(f"{label} changed while read")
            return raw
        finally:
            os.close(file_descriptor)
    except GateRunError:
        raise
    except OSError as exc:
        raise GateRunError(f"{label} cannot be read without symlinks") from exc
    finally:
        os.close(descriptor)


def _read_absolute_secret(path: Path, *, optional: bool) -> bytes | None:
    if not path.is_absolute():
        raise GateRunError("sensitive file environment path must be absolute")
    parts = path.parts[1:]
    if not parts:
        raise GateRunError("sensitive file environment path is unsafe")
    try:
        return _read_descriptor_file(
            Path("/"),
            parts,
            limit=_MAX_SECRET_BYTES,
            label=f"sensitive file {path}",
        )
    except GateRunError:
        if optional:
            try:
                os.lstat(path)
            except FileNotFoundError:
                return None
            except OSError:
                pass
        raise


def _directory_secret_values(path: Path, *, optional: bool) -> list[bytes]:
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, directory_flags)
    except FileNotFoundError:
        if optional:
            return []
        raise GateRunError(f"approved secret directory is missing: {path}") from None
    except OSError as exc:
        raise GateRunError(
            f"approved secret directory cannot be opened safely: {path}"
        ) from exc
    try:
        with os.scandir(descriptor) as entries:
            names = sorted(entry.name for entry in entries)
        values: list[bytes] = []
        for name in names:
            try:
                file_descriptor = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=descriptor,
                )
            except OSError as exc:
                raise GateRunError(
                    "secret directory entry is a symlink, non-regular file, "
                    "or changed during scan"
                ) from exc
            try:
                before = os.fstat(file_descriptor)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_size > _MAX_SECRET_BYTES
                ):
                    raise GateRunError(
                        "secret directory entry is a symlink or non-regular file: "
                        f"{name}"
                    )
                chunks: list[bytes] = []
                remaining = _MAX_SECRET_BYTES + 1
                while remaining:
                    chunk = os.read(file_descriptor, min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw = b"".join(chunks)
                after = os.fstat(file_descriptor)
                before_identity = (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                )
                after_identity = (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                )
                if (
                    len(raw) != before.st_size
                    or len(raw) > _MAX_SECRET_BYTES
                    or before_identity != after_identity
                ):
                    raise GateRunError("secret directory entry changed during scan")
            finally:
                os.close(file_descriptor)
            raw = raw.strip()
            if raw:
                values.append(raw)
        with os.scandir(descriptor) as entries:
            names_after = sorted(entry.name for entry in entries)
        if names_after != names:
            raise GateRunError("secret directory inventory changed during scan")
        return values
    finally:
        os.close(descriptor)


def _compose_secret_paths(
    repository_root: Path,
    environment: Mapping[str, str],
) -> tuple[Path, ...]:
    raw = _read_descriptor_file(
        repository_root,
        tuple(PurePosixPath(COMMAND_GATE_SECRET_COMPOSE_PATH).parts),
        limit=4 * 1024 * 1024,
        label="Compose secret inventory",
    )
    try:
        document = yaml.safe_load(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise GateRunError("Compose secret inventory is not valid UTF-8 YAML") from exc
    if not isinstance(document, dict):
        raise GateRunError("Compose secret inventory must be an object")
    secrets_document = document.get("secrets", {})
    if not isinstance(secrets_document, dict):
        raise GateRunError("Compose top-level secrets inventory must be an object")
    resolved: list[Path] = []
    for name, config in sorted(secrets_document.items()):
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,127}", name) is None
            or not isinstance(config, dict)
            or not isinstance(config.get("file"), str)
        ):
            raise GateRunError("Compose secret entry is not an exact file source")
        source = config["file"]
        match = _COMPOSE_ENV_DEFAULT.fullmatch(source)
        if match is not None:
            variable, default = match.groups()
            source = environment.get(variable, default)
        path = Path(source)
        if not path.is_absolute():
            raise GateRunError(f"Compose secret source is not absolute: {name}")
        if path not in resolved:
            resolved.append(path)
    return tuple(resolved)


def _load_canaries(
    environment: Mapping[str, str],
    *,
    repository_root: Path | None = None,
    secret_directories: Sequence[Path] = (),
) -> tuple[bytes, ...]:
    values: list[bytes] = []

    def add_canary(raw: bytes) -> None:
        # The release DLP boundary covers common reversible text
        # representations. Arbitrary encryption is intentionally out of scope.
        for variant in secret_variants(raw):
            if variant not in values:
                values.append(variant)

    for key, value in environment.items():
        normalized = normalize_sensitive_key(key)
        if any(part in normalized for part in _SENSITIVE_ENV_PARTS) and len(value) >= 4:
            encoded = value.encode("utf-8", errors="ignore")
            if encoded:
                add_canary(encoded)
            if key.upper().endswith(("_FILE", "_PATH")):
                raw = _read_absolute_secret(Path(value), optional=False)
                assert raw is not None
                stripped = raw.strip()
                if stripped:
                    add_canary(stripped)
    compose_paths = (
        _compose_secret_paths(repository_root, environment)
        if repository_root is not None
        else ()
    )
    for path in compose_paths:
        raw = _read_absolute_secret(path, optional=True)
        if raw is None:
            continue
        raw = raw.strip()
        if raw:
            add_canary(raw)
    for directory in secret_directories:
        for raw in _directory_secret_values(directory, optional=True):
            add_canary(raw)
    return tuple(values)


def _assert_safe_bytes(raw: bytes, canaries: Sequence[bytes], label: str) -> None:
    if any(canary in raw for canary in canaries if canary):
        raise GateRunError(f"{label} contains reflected credential material")
    if any(pattern.search(raw) for pattern in _SECRET_PATTERNS):
        raise GateRunError(f"{label} contains sensitive text")


def _path_aliases(path: Path) -> tuple[str, ...]:
    values = {str(path), str(path.resolve())}
    for value in tuple(values):
        if value.startswith("/var/") or value == "/var":
            values.add("/private" + value)
        elif value.startswith("/private/var/"):
            values.add(value.removeprefix("/private"))
        if value.startswith("/tmp/") or value == "/tmp":
            values.add("/private" + value)
        elif value.startswith("/private/tmp/"):
            values.add(value.removeprefix("/private"))
    return tuple(sorted(values, key=len, reverse=True))


def _normalize_log(
    raw: bytes,
    *,
    repository_root: Path,
    temporary_root: Path,
    canaries: Sequence[bytes],
    label: str,
) -> bytes:
    if len(raw) > _MAX_LOG_BYTES:
        raise GateRunError(f"{label} exceeds the command-log size limit")
    _assert_safe_bytes(raw, canaries, label)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise GateRunError(f"{label} is not UTF-8") from exc
    for value in _path_aliases(repository_root):
        text = text.replace(value, "<REPOSITORY_ROOT>")
    for value in _path_aliases(temporary_root):
        text = text.replace(value, "<TEMP_ROOT>")
    try:
        account_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (KeyError, OSError) as exc:
        raise GateRunError("account home path is unavailable") from exc
    if not account_home.is_absolute():
        raise GateRunError("account home path is malformed")
    for value in _path_aliases(account_home):
        text = text.replace(value, "<USER_HOME>")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    normalized = text.encode("utf-8")
    _assert_safe_bytes(normalized, canaries, label)
    if any(value.encode() in normalized for value in _path_aliases(repository_root)):
        raise GateRunError(f"{label} contains an unnormalized repository path")
    if any(value.encode() in normalized for value in _path_aliases(temporary_root)):
        raise GateRunError(f"{label} contains an unnormalized temporary path")
    if any(value.encode() in normalized for value in _path_aliases(account_home)):
        raise GateRunError(f"{label} contains an unnormalized account home path")
    return normalized


def _owned_tool_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and metadata.st_mode & 0o022 == 0
    )


def _safe_tool_path() -> str:
    locations: list[str] = []
    account_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    for relative in (".cargo/bin", ".local/bin"):
        user_bin = account_home / relative
        if _owned_tool_directory(user_bin):
            locations.append(str(user_bin))
    locations.extend(
        [
            "/usr/bin",
            "/bin",
            "/usr/sbin",
            "/sbin",
            "/usr/local/bin",
            "/opt/homebrew/bin",
        ]
    )
    return os.pathsep.join(locations)


def _g9_public_build_environment(
    environment: Mapping[str, str],
) -> dict[str, str]:
    required = tuple(COMMAND_GATE_G9_PUBLIC_BUILD_PROFILE)
    if any(name not in environment for name in required):
        raise GateRunError("public dashboard build profile is incomplete")
    profile = {name: environment[name] for name in required}
    if profile != dict(COMMAND_GATE_G9_PUBLIC_BUILD_PROFILE):
        raise GateRunError("public dashboard build profile is invalid")
    return profile


def _command_gate_public_build_profile(
    gate_id: str,
    environment: Mapping[str, str],
) -> dict[str, object] | None:
    if gate_id != "G9":
        return None
    values = _g9_public_build_environment(environment)
    live_test_values = dict(COMMAND_GATE_G9_LIVE_TEST_BUILD_PROFILE)
    return {
        "schema_version": COMMAND_GATE_PUBLIC_BUILD_PROFILE_SCHEMA_VERSION,
        "values": values,
        "sha256": hashlib.sha256(_canonical_json(values)).hexdigest(),
        "live_test": {
            "values": live_test_values,
            "sha256": hashlib.sha256(
                _canonical_json(live_test_values)
            ).hexdigest(),
        },
    }


def _sanitized_environment(
    temporary_root: Path,
    *,
    gate_id: str,
    caller_environment: Mapping[str, str],
) -> dict[str, str]:
    home = temporary_root / "home"
    tmp = temporary_root / "tmp"
    config = temporary_root / "config"
    cache = temporary_root / "cache"
    cargo_home = temporary_root / "cargo"
    cargo_target = temporary_root / "cargo-target"
    npm_cache = temporary_root / "npm-cache"
    for path in (
        home,
        tmp,
        config,
        cache,
        cargo_home,
        cargo_target,
        npm_cache,
    ):
        path.mkdir(mode=0o700)
    environment = {
        "CARGO_HOME": str(cargo_home),
        "CARGO_TARGET_DIR": str(cargo_target),
        "CI": "1",
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "NPM_CONFIG_CACHE": str(npm_cache),
        "NPM_CONFIG_USERCONFIG": str(temporary_root / "empty-npmrc"),
        "PATH": _safe_tool_path(),
        "TMPDIR": str(tmp),
        "XDG_CACHE_HOME": str(cache),
        "XDG_CONFIG_HOME": str(config),
        "UV_CACHE_DIR": str(temporary_root / "uv-cache"),
        "UV_PYTHON_DOWNLOADS": "never",
        "UV_PYTHON_PREFERENCE": "only-system",
    }
    (temporary_root / "empty-npmrc").touch(mode=0o600)
    rustup_home = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".rustup"
    if rustup_home.is_dir():
        environment["RUSTUP_HOME"] = str(rustup_home)
    if gate_id == "G9":
        environment.update(_g9_public_build_environment(caller_environment))
    return environment


def _validate_uv_binary(
    raw: bytes,
    *,
    expected_architecture: str | None = None,
) -> None:
    """Require uv's native binary architecture to match the release host."""

    expected = expected_architecture or _native_darwin_architecture()
    if expected == "aarch64":
        expected = "arm64"
    if platform.system() != "Darwin" and expected_architecture is None:
        return
    if len(raw) < 8:
        raise GateRunError("uv executable architecture is not verifiable")
    magic = raw[:4]
    if magic == b"\xcf\xfa\xed\xfe":
        cpu_type = int.from_bytes(raw[4:8], "little")
    elif magic == b"\xfe\xed\xfa\xcf":
        cpu_type = int.from_bytes(raw[4:8], "big")
    else:
        raise GateRunError("uv executable architecture is not a thin Mach-O binary")
    observed = _MACHO_ARCHITECTURES.get(cpu_type)
    if observed != expected:
        raise GateRunError(
            f"uv executable architecture differs: expected {expected}, got {observed}"
        )


def _read_darwin_sysctl(name: str) -> str | None:
    if name not in {"sysctl.proc_translated", "hw.optional.arm64"}:
        raise GateRunError("unsupported Darwin architecture probe")
    path = "/usr/sbin/sysctl"
    try:
        result = subprocess.run(
            [path, "-n", name],
            executable=path,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateRunError("Darwin native architecture probe failed") from exc
    if len(result.stdout) > 64:
        raise GateRunError("Darwin native architecture probe is malformed")
    if result.returncode != 0:
        return None
    try:
        value = result.stdout.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise GateRunError("Darwin native architecture probe is malformed") from exc
    return value or None


def _native_darwin_architecture(
    *,
    machine: str | None = None,
    sysctl_reader: Callable[[str], str | None] | None = None,
) -> str:
    """Return the hardware architecture, accounting for Rosetta translation."""

    observed = (machine or platform.machine()).lower()
    if observed == "aarch64":
        return "arm64"
    if observed != "x86_64":
        return observed
    if machine is None and platform.system() != "Darwin":
        return observed
    reader = sysctl_reader or _read_darwin_sysctl
    try:
        translated = reader("sysctl.proc_translated")
        arm64_capable = reader("hw.optional.arm64")
    except (OSError, ValueError) as exc:
        raise GateRunError("Darwin native architecture probe failed") from exc
    if translated == "1" or arm64_capable == "1":
        return "arm64"
    if translated in {None, "0"} and arm64_capable in {None, "0"}:
        return "x86_64"
    raise GateRunError("Darwin native architecture probe is malformed")


def _validate_python_binary(
    raw: bytes,
    *,
    expected_architecture: str | None = None,
) -> None:
    """Require the uv-selected Python binary to match the release host."""

    try:
        _validate_uv_binary(raw, expected_architecture=expected_architecture)
    except GateRunError as exc:
        raise GateRunError(
            str(exc).replace("uv executable", "Python executable")
        ) from exc


def _display_executable_path(path: Path, repository_root: Path) -> str:
    resolved_repository = repository_root.resolve()
    absolute_path = path if path.is_absolute() else path.absolute()
    try:
        return (
            "<REPOSITORY_ROOT>/"
            + absolute_path.relative_to(resolved_repository).as_posix()
        )
    except ValueError:
        pass
    account_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    for relative, token in (
        (".local/bin", "<USER_LOCAL_BIN>"),
        (".local/share/uv", "<USER_UV_DATA>"),
        (".cargo/bin", "<USER_CARGO_BIN>"),
    ):
        directory = account_home / relative
        try:
            suffix = absolute_path.relative_to(directory)
        except ValueError:
            continue
        return f"{token}/{suffix.as_posix()}"
    try:
        suffix = absolute_path.relative_to(account_home)
    except ValueError:
        pass
    else:
        return (
            "<USER_HOME>" if suffix == Path(".") else f"<USER_HOME>/{suffix.as_posix()}"
        )
    return absolute_path.as_posix()


def _snapshot_executable(
    invoked: Path,
    *,
    executable_name: str,
    cwd: Path,
) -> tuple[dict[str, object], bytes, Path]:
    try:
        invoked_metadata = invoked.lstat()
        resolved = invoked.resolve(strict=True)
        resolved_metadata = resolved.stat()
    except OSError as exc:
        raise GateRunError("fixed gate executable identity cannot be read") from exc
    if (
        not stat.S_ISREG(resolved_metadata.st_mode)
        or not os.access(resolved, os.X_OK)
        or resolved_metadata.st_uid not in {0, os.getuid()}
        or resolved_metadata.st_mode & 0o022
    ):
        raise GateRunError("fixed gate executable ownership or mode is unsafe")
    raw = _read_descriptor_file(
        resolved.parent,
        (resolved.name,),
        limit=_MAX_EXECUTABLE_BYTES,
        label=f"fixed gate executable {executable_name}",
    )
    name = Path(executable_name).name
    if name == "uv":
        _validate_uv_binary(raw)
    elif name == COMMAND_GATE_UV_PYTHON:
        _validate_python_binary(raw)
    repository_root = cwd
    while (
        repository_root.parent != repository_root
        and not (repository_root / ".git").exists()
    ):
        repository_root = repository_root.parent
    identity = {
        "invoked_path": _display_executable_path(invoked, repository_root),
        "resolved_path": _display_executable_path(resolved, repository_root),
        "invoked_device": invoked_metadata.st_dev,
        "invoked_inode": invoked_metadata.st_ino,
        "resolved_device": resolved_metadata.st_dev,
        "resolved_inode": resolved_metadata.st_ino,
        "size": resolved_metadata.st_size,
        "mode": resolved_metadata.st_mode & 0o7777,
        "owner_uid": resolved_metadata.st_uid,
        "mtime_ns": resolved_metadata.st_mtime_ns,
        "ctime_ns": resolved_metadata.st_ctime_ns,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    return identity, raw, resolved


def _executable_identity(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> dict[str, object]:
    invoked = Path(_resolve_executable(argv, cwd=cwd, environment=environment)[0])
    identity, _raw, _resolved = _snapshot_executable(
        invoked,
        executable_name=argv[0],
        cwd=cwd,
    )
    return identity


def _shebang_argv(raw: bytes) -> tuple[str, ...]:
    if not raw.startswith(b"#!"):
        return ()
    first_line = raw.splitlines()[0][2:]
    try:
        text = first_line.decode("utf-8", errors="strict").strip()
        values = tuple(shlex.split(text, posix=True))
    except (UnicodeDecodeError, ValueError) as exc:
        raise GateRunError("fixed gate executable has a malformed shebang") from exc
    if not values or not Path(values[0]).is_absolute():
        raise GateRunError("fixed gate executable shebang is not absolute")
    return values


def _env_shebang_target(arguments: Sequence[str]) -> tuple[str, ...]:
    values = list(arguments)
    while values and "=" in values[0] and not values[0].startswith(("-", "/")):
        name, _, _value = values.pop(0).partition("=")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None:
            raise GateRunError("fixed gate env shebang assignment is malformed")
    if values[:1] == ["-S"]:
        values = values[1:]
    else:
        while values and values[0].startswith("-"):
            option = values.pop(0)
            if option in {"-u", "--unset", "-C", "--chdir"}:
                if not values:
                    raise GateRunError("fixed gate env shebang option is incomplete")
                values.pop(0)
    if not values:
        raise GateRunError("fixed gate env shebang has no target")
    return tuple(values)


def _append_executable_with_shebang(
    chain: list[dict[str, object]],
    argv: tuple[str, ...],
    *,
    role: str,
    cwd: Path,
    environment: Mapping[str, str],
    depth: int = 0,
    invoked_path: Path | None = None,
) -> Path:
    if depth > COMMAND_GATE_EXECUTABLE_CHAIN_POLICY["maximum_shebang_depth"]:
        raise GateRunError("fixed gate executable shebang chain is too deep")
    invoked = invoked_path or Path(
        _resolve_executable(argv, cwd=cwd, environment=environment)[0]
    )
    identity, raw, resolved = _snapshot_executable(
        invoked,
        executable_name=argv[0],
        cwd=cwd,
    )
    chain.append({"role": role, **identity})
    shebang = _shebang_argv(raw)
    if not shebang:
        return resolved
    interpreter = (shebang[0],)
    _append_executable_with_shebang(
        chain,
        interpreter,
        role=f"{role}.shebang_interpreter",
        cwd=cwd,
        environment=environment,
        depth=depth + 1,
    )
    if Path(shebang[0]).name == "env":
        target = _env_shebang_target(shebang[1:])
        _append_executable_with_shebang(
            chain,
            target,
            role=f"{role}.shebang_target",
            cwd=cwd,
            environment=environment,
            depth=depth + 1,
        )
    return resolved


def _append_named_dependency(
    chain: list[dict[str, object]],
    executable: str,
    *,
    role: str,
    cwd: Path,
    environment: Mapping[str, str],
) -> None:
    _append_executable_with_shebang(
        chain,
        (executable,),
        role=role,
        cwd=cwd,
        environment=environment,
    )


def _bind_executable_invocation(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> tuple[tuple[dict[str, object], ...], str]:
    """Resolve once and bind every runtime entry point for a fixed command."""

    chain: list[dict[str, object]] = []
    invoked = Path(_resolve_executable(argv, cwd=cwd, environment=environment)[0])
    resolved_entrypoint = _append_executable_with_shebang(
        chain,
        argv,
        role="entrypoint",
        cwd=cwd,
        environment=environment,
        invoked_path=invoked,
    )
    entrypoint = Path(argv[0]).name
    if entrypoint == "uv":
        _append_named_dependency(
            chain,
            COMMAND_GATE_UV_PYTHON,
            role="uv_python",
            cwd=cwd,
            environment=environment,
        )
    if entrypoint == "cargo":
        if len(argv) > 1 and argv[1] == "odra":
            _append_named_dependency(
                chain,
                str(COMMAND_GATE_EXECUTABLE_CHAIN_POLICY["cargo_odra_subcommand"]),
                role="cargo_subcommand",
                cwd=cwd,
                environment=environment,
            )
        compiler_commands = set(
            COMMAND_GATE_EXECUTABLE_CHAIN_POLICY["cargo_compiler_commands"]
        )
        if any(value in compiler_commands for value in argv[1:]):
            _append_named_dependency(
                chain,
                str(COMMAND_GATE_EXECUTABLE_CHAIN_POLICY["cargo_compiler"]),
                role="rust_compiler",
                cwd=cwd,
                environment=environment,
            )
    wrapper = str(COMMAND_GATE_EXECUTABLE_CHAIN_POLICY["locked_odra_wrapper"])
    if wrapper in argv[1:]:
        roles = (
            "locked_odra.cargo",
            "locked_odra.cargo_subcommand",
            "locked_odra.rust_compiler",
        )
        dependencies = COMMAND_GATE_EXECUTABLE_CHAIN_POLICY["locked_odra_dependencies"]
        for executable, role in zip(dependencies, roles, strict=True):
            _append_named_dependency(
                chain,
                executable,
                role=role,
                cwd=cwd,
                environment=environment,
            )
    return tuple(chain), resolved_entrypoint.as_posix()


def _executable_chain(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> tuple[dict[str, object], ...]:
    """Bind every stable runtime entry point selected by a fixed gate command."""

    chain, _resolved_entrypoint = _bind_executable_invocation(
        argv,
        cwd=cwd,
        environment=environment,
    )
    return chain


def _assert_executable_identity(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    expected: Mapping[str, object],
) -> None:
    if _executable_identity(argv, cwd=cwd, environment=environment) != dict(expected):
        raise GateRunError("fixed gate executable identity changed during execution")


def _assert_executable_chain(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    expected: Sequence[Mapping[str, object]],
) -> None:
    observed = _executable_chain(argv, cwd=cwd, environment=environment)
    if observed != tuple(dict(row) for row in expected):
        raise GateRunError("fixed gate executable chain changed during execution")


def _resolve_executable(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> tuple[str, ...]:
    executable = argv[0]
    if "/" in executable:
        candidate = Path(executable)
        if not candidate.is_absolute():
            candidate = cwd / candidate
        try:
            resolved = candidate.resolve(strict=True)
            if not Path(executable).is_absolute():
                resolved.relative_to(cwd.resolve())
        except (OSError, ValueError) as exc:
            raise GateRunError("fixed gate executable escapes the repository") from exc
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise GateRunError("fixed gate executable is unavailable")
        return (str(candidate.absolute()), *argv[1:])
    resolved_name = shutil.which(executable, path=environment["PATH"])
    if not resolved_name:
        raise GateRunError(f"fixed gate executable is unavailable: {executable}")
    resolved = Path(resolved_name)
    if not resolved.is_absolute() or not resolved.is_file():
        raise GateRunError("fixed gate executable is not a regular absolute path")
    return (str(resolved), *argv[1:])


def _execute_command(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int,
    resolved_executable: str,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return run_bounded_process(
            cwd=cwd,
            argv=argv,
            executable=Path(resolved_executable),
            env=env,
            stdout_limit=_MAX_LOG_BYTES,
            stderr_limit=_MAX_LOG_BYTES,
            timeout_s=timeout,
        )
    except BoundCommandError as exc:
        raise GateRunError(str(exc).replace("bound command", "command")) from exc


def _trusted_git_identity() -> dict[str, object]:
    path = _TRUSTED_GIT_PATH
    expected_owner = int(COMMAND_GATE_EXECUTION_POLICY["trusted_git_owner_uid"])
    reject_writable = bool(
        COMMAND_GATE_EXECUTION_POLICY["trusted_git_reject_group_or_other_write"]
    )
    try:
        before = path.lstat()
    except OSError as exc:
        raise GateRunError("trusted system Git is unavailable") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_uid != expected_owner
        or (reject_writable and before.st_mode & 0o022)
        or not os.access(path, os.X_OK)
    ):
        raise GateRunError("trusted system Git ownership or mode is unsafe")
    raw = _read_descriptor_file(
        path.parent,
        (path.name,),
        limit=_MAX_EXECUTABLE_BYTES,
        label="trusted system Git",
    )
    try:
        after = path.lstat()
    except OSError as exc:
        raise GateRunError("trusted system Git changed while inspected") from exc
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mode,
        before.st_uid,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mode,
        after.st_uid,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if before_identity != after_identity:
        raise GateRunError("trusted system Git changed while inspected")
    return {
        "path": path.as_posix(),
        "device": before.st_dev,
        "inode": before.st_ino,
        "size": before.st_size,
        "mode": before.st_mode & 0o7777,
        "owner_uid": before.st_uid,
        "mtime_ns": before.st_mtime_ns,
        "ctime_ns": before.st_ctime_ns,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _git(repository_root: Path, *arguments: str) -> bytes:
    identity_before = _trusted_git_identity()
    result: subprocess.CompletedProcess[bytes] | None = None
    execution_error: BoundCommandError | None = None
    try:
        result = run_bounded_process(
            cwd=repository_root,
            argv=(
                "git",
                "--no-replace-objects",
                *BOUND_GIT_CONFIG_OVERRIDES,
                "-C",
                str(repository_root),
                *arguments,
            ),
            executable=_TRUSTED_GIT_PATH,
            env={
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
            stdout_limit=_GIT_OUTPUT_LIMIT,
            stderr_limit=_GIT_OUTPUT_LIMIT,
            timeout_s=60,
        )
    except BoundCommandError as exc:
        execution_error = exc
    identity_after = _trusted_git_identity()
    if identity_after != identity_before:
        raise GateRunError("trusted system Git changed during invocation")
    if execution_error is not None:
        raise GateRunError("git identity check failed") from execution_error
    assert result is not None
    if result.returncode != 0:
        raise GateRunError("git identity check failed")
    return result.stdout


def _git_text(repository_root: Path, *arguments: str) -> str:
    try:
        return _git(repository_root, *arguments).decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise GateRunError("git identity output is not ASCII") from exc


def _validate_relative_path(relative: str) -> tuple[str, ...]:
    path = PurePosixPath(relative)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in relative
    ):
        raise GateRunError(f"unsafe repository-relative path: {relative}")
    return path.parts


def _contract_working_directory(
    repository_root: Path,
    working_directory: str,
) -> Path:
    if repository_root.is_symlink():
        raise GateRunError("repository root cannot be a symlink")
    try:
        resolved_root = repository_root.resolve(strict=True)
        root_metadata = repository_root.lstat()
    except OSError as exc:
        raise GateRunError("repository root is unavailable") from exc
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise GateRunError("repository root is not a directory")
    parts: tuple[str, ...]
    if working_directory == ".":
        parts = ()
    else:
        parts = _validate_relative_path(working_directory)
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(resolved_root, directory_flags)
    except OSError as exc:
        raise GateRunError("repository root cannot be opened safely") from exc
    try:
        for part in parts:
            next_descriptor = os.open(part, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
    except OSError as exc:
        raise GateRunError(
            f"contract working directory has a symlink or non-directory prefix: "
            f"{working_directory}"
        ) from exc
    finally:
        os.close(descriptor)
    candidate = resolved_root.joinpath(*parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise GateRunError(
            f"contract working directory escapes the repository: {working_directory}"
        ) from exc
    if not resolved.is_dir():
        raise GateRunError(
            f"contract working directory is not a directory: {working_directory}"
        )
    return resolved


def _assert_no_symlink_prefix(repository_root: Path, relative: str) -> None:
    parts = _validate_relative_path(relative)
    current = repository_root
    for part in parts[:-1]:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(metadata.st_mode):
            raise GateRunError(f"release output path contains a symlink: {relative}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise GateRunError(f"release output parent is not a directory: {relative}")


def _read_regular_file(
    repository_root: Path,
    relative: str,
    *,
    limit: int,
) -> bytes:
    parts = _validate_relative_path(relative)
    return _read_descriptor_file(
        repository_root,
        parts,
        limit=limit,
        label=f"required artifact {relative}",
    )


def _identity_rows(repository_root: Path, gate_id: str) -> list[dict[str, str]]:
    integration_commit = _git_text(repository_root, "rev-parse", "HEAD^{commit}")
    rows: list[dict[str, str]] = []
    for relative in COMMAND_GATE_IDENTITY_PATHS[gate_id]:
        raw = _read_regular_file(repository_root, relative, limit=4 * 1024 * 1024)
        commit = _git_text(repository_root, "log", "-1", "--format=%H", "--", relative)
        if not commit:
            raise GateRunError(f"command-gate identity has no commit: {relative}")
        _git(
            repository_root,
            "merge-base",
            "--is-ancestor",
            commit,
            integration_commit,
        )
        rows.append(
            {
                "path": relative,
                "commit": commit,
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    return rows


def _preflight_repository(
    repository_root: Path, gate_id: str
) -> tuple[str, str, str, list[dict[str, str]]]:
    if repository_root.is_symlink():
        raise GateRunError("repository root cannot be a symlink")
    try:
        root = repository_root.resolve(strict=True)
    except OSError as exc:
        raise GateRunError("repository root is unavailable") from exc
    top_level = Path(_git_text(root, "rev-parse", "--show-toplevel")).resolve()
    if top_level != root:
        raise GateRunError("repository root is not the Git worktree root")
    if _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all"):
        raise GateRunError("command gate requires a clean Git HEAD")

    receipt_path = COMMAND_GATE_RECEIPT_PATHS[gate_id]
    log_directory = f"release/receipts/logs/{gate_id}"
    for relative in (receipt_path, log_directory):
        _assert_no_symlink_prefix(root, relative)
        target = root / relative
        if target.exists() or target.is_symlink():
            raise GateRunError(f"command-gate output already exists: {relative}")

    if _git_text(root, "cat-file", "-t", G1_FREEZE_TAG) != "tag":
        raise GateRunError("G1 freeze must be an annotated tag object")
    freeze_tag_object = _git_text(root, "rev-parse", f"{G1_FREEZE_TAG}^{{tag}}")
    if freeze_tag_object != G1_FREEZE_TAG_OBJECT:
        raise GateRunError("G1 annotated tag object identity differs")
    frozen_commit = _git_text(root, "rev-parse", f"{G1_FREEZE_TAG}^{{commit}}")
    if frozen_commit != G1_FREEZE_COMMIT:
        raise GateRunError(
            "G1 freeze tag peeled commit differs from the frozen contract"
        )
    integration_commit = _git_text(root, "rev-parse", "HEAD^{commit}")
    _git(
        root,
        "merge-base",
        "--is-ancestor",
        frozen_commit,
        integration_commit,
    )
    identities = _identity_rows(root, gate_id)
    return frozen_commit, freeze_tag_object, integration_commit, identities


def _runtime_versions(
    gate_id: str,
    *,
    repository_root: Path,
    temporary_root: Path,
    environment: dict[str, str],
    canaries: Sequence[bytes],
    executor: Executor,
) -> tuple[dict[str, str], dict[str, tuple[dict[str, object], ...]]]:
    versions: dict[str, str] = {}
    executable_chains: dict[str, tuple[dict[str, object], ...]] = {}
    working_directories = {
        working_directory: _contract_working_directory(
            repository_root,
            working_directory,
        )
        for _runtime, working_directory, _argv in (COMMAND_GATE_RUNTIME_PROBES[gate_id])
    }
    for runtime, working_directory, argv in COMMAND_GATE_RUNTIME_PROBES[gate_id]:
        cwd = _contract_working_directory(repository_root, working_directory)
        if cwd != working_directories[working_directory]:
            raise GateRunError(
                f"{gate_id} runtime working directory changed before execution"
            )
        executable_chain, resolved_executable = _bind_executable_invocation(
            argv,
            cwd=cwd,
            environment=environment,
        )
        _assert_executable_chain(
            argv,
            cwd=cwd,
            environment=environment,
            expected=executable_chain,
        )
        try:
            result = executor(
                argv,
                cwd=cwd,
                env=environment,
                timeout=COMMAND_GATE_RUNTIME_TIMEOUT_SECONDS,
                resolved_executable=resolved_executable,
            )
        except subprocess.TimeoutExpired as exc:
            raise GateRunError(f"{gate_id} {runtime} runtime probe timed out") from exc
        except OSError as exc:
            raise GateRunError(f"{gate_id} {runtime} runtime probe failed") from exc
        finally:
            _assert_executable_chain(
                argv,
                cwd=cwd,
                environment=environment,
                expected=executable_chain,
            )
        if result.returncode != 0:
            raise GateRunError(f"{gate_id} {runtime} runtime probe returned an error")
        stdout = _normalize_log(
            result.stdout,
            repository_root=repository_root,
            temporary_root=temporary_root,
            canaries=canaries,
            label=f"{gate_id} {runtime} runtime stdout",
        )
        stderr = _normalize_log(
            result.stderr,
            repository_root=repository_root,
            temporary_root=temporary_root,
            canaries=canaries,
            label=f"{gate_id} {runtime} runtime stderr",
        )
        version = "\n".join(
            part for part in (stdout.decode().strip(), stderr.decode().strip()) if part
        )
        if (
            not version
            or len(version.encode("utf-8")) > 4096
            or any(
                character != "\n" and not character.isprintable()
                for character in version
            )
        ):
            raise GateRunError(f"{gate_id} {runtime} runtime version is malformed")
        _validate_runtime_version(runtime, version)
        versions[runtime] = version
        executable_chains[runtime] = executable_chain
    if tuple(versions) != COMMAND_GATE_REQUIRED_RUNTIMES[gate_id]:
        raise GateRunError(f"{gate_id} runtime inventory differs from the contract")
    return versions, executable_chains


def _validate_runtime_version(runtime: str, observed: str) -> None:
    expected = COMMAND_GATE_EXPECTED_RUNTIME_VERSIONS.get(runtime)
    if expected is None:
        raise GateRunError(f"unknown command-gate runtime: {runtime}")
    if observed != expected:
        raise GateRunError(
            f"{runtime} runtime version differs from the frozen contract"
        )


def _capture_commands(
    gate_id: str,
    *,
    repository_root: Path,
    temporary_root: Path,
    environment: dict[str, str],
    canaries: Sequence[bytes],
    executor: Executor,
) -> list[_CapturedCommand]:
    captured: list[_CapturedCommand] = []
    commands = COMMAND_GATE_COMMANDS[gate_id]
    timeouts = COMMAND_GATE_TIMEOUT_SECONDS[gate_id]
    working_directories = {
        working_directory: _contract_working_directory(
            repository_root,
            working_directory,
        )
        for _command_id, working_directory, _argv in commands
    }
    for (command_id, working_directory, argv), timeout in zip(
        commands, timeouts, strict=True
    ):
        cwd = _contract_working_directory(repository_root, working_directory)
        if cwd != working_directories[working_directory]:
            raise GateRunError(
                f"{gate_id} command working directory changed before execution"
            )
        executable_chain, resolved_executable = _bind_executable_invocation(
            argv,
            cwd=cwd,
            environment=environment,
        )
        _assert_executable_chain(
            argv,
            cwd=cwd,
            environment=environment,
            expected=executable_chain,
        )
        command_started = _utc_now()
        try:
            result = executor(
                argv,
                cwd=cwd,
                env=environment,
                timeout=timeout,
                resolved_executable=resolved_executable,
            )
        except subprocess.TimeoutExpired as exc:
            raise GateRunError(f"{gate_id} {command_id} timed out") from exc
        except OSError as exc:
            raise GateRunError(f"{gate_id} {command_id} failed to execute") from exc
        finally:
            _assert_executable_chain(
                argv,
                cwd=cwd,
                environment=environment,
                expected=executable_chain,
            )
        command_ended = _utc_now()
        if result.returncode != 0:
            raise GateRunError(
                f"{gate_id} {command_id} returned exit code {result.returncode}"
            )
        stdout = _normalize_log(
            result.stdout,
            repository_root=repository_root,
            temporary_root=temporary_root,
            canaries=canaries,
            label=f"{gate_id} {command_id} stdout",
        )
        stderr = _normalize_log(
            result.stderr,
            repository_root=repository_root,
            temporary_root=temporary_root,
            canaries=canaries,
            label=f"{gate_id} {command_id} stderr",
        )
        captured.append(
            _CapturedCommand(
                command_id=command_id,
                working_directory=working_directory,
                argv=argv,
                started_at=command_started,
                ended_at=command_ended,
                stdout=stdout,
                stderr=stderr,
                executable_chain=executable_chain,
            )
        )
    return captured


def _artifact_rows_for_paths(
    repository_root: Path, paths: Sequence[str]
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for relative in paths:
        raw = _read_regular_file(
            repository_root,
            relative,
            limit=_MAX_ARTIFACT_BYTES,
        )
        rows.append({"path": relative, "sha256": hashlib.sha256(raw).hexdigest()})
    return rows


def _artifact_rows(repository_root: Path, gate_id: str) -> list[dict[str, str]]:
    return _artifact_rows_for_paths(
        repository_root, COMMAND_GATE_PRODUCED_ARTIFACT_PATHS[gate_id]
    )


def _empty_directory_descriptor(descriptor: int) -> None:
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    with os.scandir(descriptor) as entries:
        names = [entry.name for entry in entries]
    for name in names:
        metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode):
            raise GateRunError("fresh output tree contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            child = os.open(name, directory_flags, dir_fd=descriptor)
            try:
                _empty_directory_descriptor(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=descriptor)
        elif stat.S_ISREG(metadata.st_mode):
            os.unlink(name, dir_fd=descriptor)
        else:
            raise GateRunError("fresh output tree contains a non-regular entry")


def _remove_repository_tree(repository_root: Path, relative: str) -> None:
    parts = _validate_relative_path(relative)
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(repository_root, directory_flags)
    try:
        for part in parts[:-1]:
            next_descriptor = os.open(part, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        try:
            target = os.open(parts[-1], directory_flags, dir_fd=descriptor)
        except FileNotFoundError:
            return
        try:
            _empty_directory_descriptor(target)
        finally:
            os.close(target)
        os.rmdir(parts[-1], dir_fd=descriptor)
    except GateRunError:
        raise
    except OSError as exc:
        raise GateRunError(
            f"fresh output cannot be safely cleared: {relative}"
        ) from exc
    finally:
        os.close(descriptor)


def _prepare_fresh_outputs(repository_root: Path, gate_id: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for relative in COMMAND_GATE_FRESH_OUTPUT_PATHS[gate_id]:
        _remove_repository_tree(repository_root, relative)
        rows.append({"path": relative, "state_before": "removed_or_absent"})
    return rows


def _create_directory_chain(repository_root: Path, relative: str) -> list[Path]:
    created: list[Path] = []
    current = repository_root
    for part in _validate_relative_path(relative):
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o755)
            created.append(current)
            continue
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise GateRunError("release receipt directory is not safe")
    return created


def _write_staged_file(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o644)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_batch(
    repository_root: Path,
    gate_id: str,
    *,
    receipt_raw: bytes,
    logs: Mapping[str, bytes],
    before_commit: Callable[[frozenset[str]], None],
) -> None:
    receipt_relative = COMMAND_GATE_RECEIPT_PATHS[gate_id]
    receipt_path = repository_root / receipt_relative
    receipts_root = repository_root / "release/receipts"
    logs_root = receipts_root / "logs"
    gate_logs = logs_root / gate_id
    created_directories: list[Path] = []
    staging: Path | None = None
    linked: list[Path] = []
    committed = False
    try:
        created_directories.extend(
            _create_directory_chain(repository_root, "release/receipts/logs")
        )
        if receipt_path.exists() or receipt_path.is_symlink():
            raise GateRunError("refusing to overwrite an existing gate receipt")
        if gate_logs.exists() or gate_logs.is_symlink():
            raise GateRunError("refusing to overwrite an existing gate log batch")

        staging = receipts_root / (
            f".{gate_id}.gate-batch.{os.getpid()}.{secrets.token_hex(8)}"
        )
        staging.mkdir(mode=0o700)
        staged_logs = staging / "logs"
        staged_logs.mkdir(mode=0o700)
        for name, raw in logs.items():
            _write_staged_file(staged_logs / name, raw)
        staged_receipt = staging / "receipt.json"
        _write_staged_file(staged_receipt, receipt_raw)
        _fsync_directory(staged_logs)
        _fsync_directory(staging)

        gate_logs.mkdir(mode=0o755)
        created_directories.append(gate_logs)
        for name in logs:
            destination = gate_logs / name
            os.link(staged_logs / name, destination, follow_symlinks=False)
            linked.append(destination)
        _fsync_directory(gate_logs)
        _fsync_directory(logs_root)
        _fsync_directory(receipts_root)
        allowed_untracked = {
            path.relative_to(repository_root).as_posix() for path in linked
        }
        allowed_untracked.update(
            {
                (staged_logs / name).relative_to(repository_root).as_posix()
                for name in logs
            }
        )
        allowed_untracked.add(staged_receipt.relative_to(repository_root).as_posix())
        before_commit(frozenset(allowed_untracked))
        _assert_published_logs(repository_root, gate_id, logs)
        os.link(staged_receipt, receipt_path, follow_symlinks=False)
        linked.append(receipt_path)
        _fsync_directory(receipts_root)
        post_link_untracked = set(allowed_untracked)
        post_link_untracked.add(receipt_relative)
        before_commit(frozenset(post_link_untracked))
        _assert_published_logs(repository_root, gate_id, logs)
        _assert_published_receipt(repository_root, gate_id, receipt_raw)
        _fsync_directory(gate_logs)
        _fsync_directory(logs_root)
        _fsync_directory(receipts_root)
        committed = True
    except GateRunError:
        raise
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            raise GateRunError("refusing to overwrite command-gate output") from exc
        raise GateRunError("command-gate batch publication failed") from exc
    finally:
        if not committed:
            for path in reversed(linked):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            for path in (gate_logs, logs_root, receipts_root):
                try:
                    if path.is_dir() and not path.is_symlink():
                        _fsync_directory(path)
                except OSError:
                    pass
            for path in reversed(created_directories):
                try:
                    path.rmdir()
                    if path.parent.is_dir():
                        _fsync_directory(path.parent)
                except OSError:
                    pass
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
            try:
                if receipts_root.is_dir():
                    _fsync_directory(receipts_root)
            except OSError:
                pass


def _assert_published_logs(
    repository_root: Path,
    gate_id: str,
    logs: Mapping[str, bytes],
) -> None:
    gate_logs = repository_root / f"release/receipts/logs/{gate_id}"
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(gate_logs, directory_flags)
    except OSError as exc:
        raise GateRunError("published command log directory is unavailable") from exc
    try:
        with os.scandir(descriptor) as entries:
            names = {entry.name for entry in entries}
        if names != set(logs):
            raise GateRunError("published command log inventory differs")
        for name, expected in logs.items():
            observed = _read_descriptor_file(
                gate_logs,
                (name,),
                limit=_MAX_LOG_BYTES,
                label=f"published command log {gate_id}/{name}",
            )
            if observed != expected:
                raise GateRunError("published command log digest differs")
    finally:
        os.close(descriptor)


def _assert_published_receipt(
    repository_root: Path,
    gate_id: str,
    expected: bytes,
) -> None:
    relative = COMMAND_GATE_RECEIPT_PATHS[gate_id]
    observed = _read_descriptor_file(
        repository_root,
        tuple(PurePosixPath(relative).parts),
        limit=_MAX_ARTIFACT_BYTES,
        label=f"published command-gate receipt {gate_id}",
    )
    if observed != expected:
        raise GateRunError("published command-gate receipt digest differs")


def _assert_final_repository_identity(
    repository_root: Path,
    gate_id: str,
    *,
    freeze_tag_object: str,
    integration_commit: str,
    identities: list[dict[str, str]],
    produced_artifacts: list[dict[str, str]],
    input_artifacts: list[dict[str, str]],
    captured_commands: Sequence[_CapturedCommand],
    runtime_executable_chains: Mapping[
        str,
        Sequence[Mapping[str, object]],
    ],
    bound_launcher_identity: Mapping[str, object],
    environment: Mapping[str, str],
    allowed_untracked: frozenset[str],
) -> None:
    if dict(bound_process_launcher_identity()) != dict(bound_launcher_identity):
        raise GateRunError("bound process launcher identity changed during execution")
    if _git_text(repository_root, "rev-parse", "HEAD^{commit}") != integration_commit:
        raise GateRunError("command gate changed the integration commit")
    if (
        _git_text(repository_root, "cat-file", "-t", G1_FREEZE_TAG) != "tag"
        or _git_text(repository_root, "rev-parse", f"{G1_FREEZE_TAG}^{{tag}}")
        != G1_FREEZE_TAG_OBJECT
        or freeze_tag_object != G1_FREEZE_TAG_OBJECT
        or _git_text(repository_root, "rev-parse", f"{G1_FREEZE_TAG}^{{commit}}")
        != G1_FREEZE_COMMIT
    ):
        raise GateRunError("G1 freeze tag identity changed during execution")
    if _identity_rows(repository_root, gate_id) != identities:
        raise GateRunError(
            "command-gate implementation identity changed during execution"
        )
    if _artifact_rows(repository_root, gate_id) != produced_artifacts:
        raise GateRunError("produced artifact identity changed before receipt commit")
    if (
        _artifact_rows_for_paths(
            repository_root, COMMAND_GATE_INPUT_ARTIFACT_PATHS[gate_id]
        )
        != input_artifacts
    ):
        raise GateRunError("input artifact identity changed before receipt commit")
    for command in captured_commands:
        cwd = _contract_working_directory(
            repository_root,
            command.working_directory,
        )
        _assert_executable_chain(
            command.argv,
            cwd=cwd,
            environment=environment,
            expected=command.executable_chain,
        )
    for runtime, working_directory, argv in COMMAND_GATE_RUNTIME_PROBES[gate_id]:
        cwd = _contract_working_directory(
            repository_root,
            working_directory,
        )
        _assert_executable_chain(
            argv,
            cwd=cwd,
            environment=environment,
            expected=runtime_executable_chains[runtime],
        )

    status = _git(
        repository_root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
    )
    observed_untracked: set[str] = set()
    for raw_entry in status.split(b"\0"):
        if not raw_entry:
            continue
        if not raw_entry.startswith(b"?? "):
            raise GateRunError("tracked worktree changed before receipt commit")
        try:
            relative = raw_entry[3:].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise GateRunError("worktree status path is not UTF-8") from exc
        observed_untracked.add(relative)
    if observed_untracked != set(allowed_untracked):
        raise GateRunError("untracked worktree state changed before receipt commit")


def _repository_gate_lock(root: Path) -> int:
    """Acquire the same repository-wide lock used by manifest publication."""

    common_raw = _git_text(root, "rev-parse", "--git-common-dir").strip()
    common = Path(common_raw)
    if not common.is_absolute():
        common = root / common
    try:
        common = common.resolve(strict=True)
    except OSError as exc:
        raise GateRunError("Git common directory is unavailable") from exc
    lock_path = common / "concordia-release-manifest.lock"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            lock_path,
            os.O_RDWR
            | os.O_CREAT
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
        ):
            raise GateRunError("repository release lock is unsafe")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise GateRunError(
                "another release operation holds the repository lock"
            ) from exc
        return descriptor
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise


def _run_gate_locked(
    gate_id: str,
    *,
    repository_root: str | Path,
    executor: Executor = _execute_command,
) -> GateRunResult:
    """Run one fixed gate and publish its exact receipt batch only on success."""

    if gate_id not in COMMAND_GATE_COMMANDS:
        raise GateRunError(f"unknown command gate: {gate_id}")
    root = Path(repository_root)
    frozen_commit, freeze_tag_object, integration_commit, identity_rows = (
        _preflight_repository(root, gate_id)
    )
    root = root.resolve()
    bound_launcher_identity = dict(bound_process_launcher_identity())
    for _command_id, working_directory, _argv in COMMAND_GATE_COMMANDS[gate_id]:
        _contract_working_directory(root, working_directory)
    for _runtime, working_directory, _argv in COMMAND_GATE_RUNTIME_PROBES[gate_id]:
        _contract_working_directory(root, working_directory)
    caller_environment = dict(os.environ)
    canaries = _load_canaries(
        caller_environment,
        repository_root=root,
        secret_directories=_APPROVED_SECRET_DIRECTORIES,
    )
    fresh_outputs = _prepare_fresh_outputs(root, gate_id)

    with tempfile.TemporaryDirectory(prefix=f"concordia-{gate_id.lower()}-") as name:
        temporary_root = Path(name).resolve()
        environment = _sanitized_environment(
            temporary_root,
            gate_id=gate_id,
            caller_environment=caller_environment,
        )
        started_at = _utc_now()
        captured = _capture_commands(
            gate_id,
            repository_root=root,
            temporary_root=temporary_root,
            environment=environment,
            canaries=canaries,
            executor=executor,
        )
        runtime_versions, runtime_executable_chains = _runtime_versions(
            gate_id,
            repository_root=root,
            temporary_root=temporary_root,
            environment=environment,
            canaries=canaries,
            executor=executor,
        )
        ended_at = _utc_now()

    if _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all"):
        raise GateRunError("command gate changed the clean Git worktree")
    if _git_text(root, "rev-parse", "HEAD^{commit}") != integration_commit:
        raise GateRunError("command gate changed the integration commit")

    if _identity_rows(root, gate_id) != identity_rows:
        raise GateRunError(
            "command-gate implementation identity changed during execution"
        )
    if dict(bound_process_launcher_identity()) != bound_launcher_identity:
        raise GateRunError("bound process launcher identity changed during execution")

    logs: dict[str, bytes] = {}
    command_rows: list[dict[str, object]] = []
    for command in captured:
        stream_rows: dict[str, dict[str, str]] = {}
        for stream in ("stdout", "stderr"):
            raw = getattr(command, stream)
            name = f"{command.command_id}.{stream}"
            relative = f"release/receipts/logs/{gate_id}/{name}"
            logs[name] = raw
            stream_rows[stream] = {
                "path": relative,
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        command_rows.append(
            {
                "command_id": command.command_id,
                "working_directory": command.working_directory,
                "argv": list(command.argv),
                "started_at": command.started_at,
                "ended_at": command.ended_at,
                "exit_code": 0,
                **stream_rows,
                "executable_chain": command.executable_chain,
            }
        )

    produced_artifacts = _artifact_rows(root, gate_id)
    input_artifacts = _artifact_rows_for_paths(
        root, COMMAND_GATE_INPUT_ARTIFACT_PATHS[gate_id]
    )
    receipt = {
        "schema_version": COMMAND_GATE_RECEIPT_SCHEMA_VERSION,
        "gate_id": gate_id,
        "frozen_commit": frozen_commit,
        "freeze_tag": {
            "name": G1_FREEZE_TAG,
            "object": freeze_tag_object,
            "peeled_commit": frozen_commit,
        },
        "integration_commit": integration_commit,
        "clean_tree_sha256": hashlib.sha256(b"").hexdigest(),
        "normalization": dict(COMMAND_GATE_NORMALIZATION),
        "executable_chain_schema_version": (
            COMMAND_GATE_EXECUTABLE_CHAIN_SCHEMA_VERSION
        ),
        "runner": identity_rows,
        "bound_process_launcher": bound_launcher_identity,
        "runtime_versions": runtime_versions,
        "runtime_executable_chains": runtime_executable_chains,
        "public_build_profile": _command_gate_public_build_profile(
            gate_id,
            environment,
        ),
        "started_at": started_at,
        "ended_at": ended_at,
        "commands": command_rows,
        "produced_artifacts": produced_artifacts,
        "input_artifacts": input_artifacts,
        "fresh_outputs": fresh_outputs,
    }
    receipt_raw = _canonical_json(receipt)
    _assert_safe_bytes(receipt_raw, canaries, f"{gate_id} receipt")
    for name, raw in logs.items():
        _assert_safe_bytes(raw, canaries, f"{gate_id} {name}")
    _publish_batch(
        root,
        gate_id,
        receipt_raw=receipt_raw,
        logs=logs,
        before_commit=lambda allowed_untracked: _assert_final_repository_identity(
            root,
            gate_id,
            freeze_tag_object=freeze_tag_object,
            integration_commit=integration_commit,
            identities=identity_rows,
            produced_artifacts=produced_artifacts,
            input_artifacts=input_artifacts,
            captured_commands=captured,
            runtime_executable_chains=runtime_executable_chains,
            bound_launcher_identity=bound_launcher_identity,
            environment=environment,
            allowed_untracked=allowed_untracked,
        ),
    )
    return GateRunResult(
        gate_id=gate_id,
        receipt_path=COMMAND_GATE_RECEIPT_PATHS[gate_id],
        receipt_sha256=hashlib.sha256(receipt_raw).hexdigest(),
    )


def run_gate(
    gate_id: str,
    *,
    repository_root: str | Path,
    executor: Executor = _execute_command,
) -> GateRunResult:
    """Serialize a fixed gate with every manifest/capture operation."""

    root = Path(repository_root).absolute()
    lock_descriptor = _repository_gate_lock(root)
    try:
        return _run_gate_locked(
            gate_id,
            repository_root=root,
            executor=executor,
        )
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)
