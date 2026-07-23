"""Contract-bound, fail-closed command execution for release collectors."""

from __future__ import annotations

import ctypes
import fcntl
import hashlib
import json
import os
import plistlib
import re
import secrets
import select
import shlex
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from shared.release_gate_contract import (
    BOUND_HOST_AUTHORITY_DESCENDANT_PATHS,
    BOUND_HOST_AUTHORITY_DESCENDANT_PREFIXES,
    BOUND_HOST_ID_DOMAIN,
    BOUND_HOST_ID_POLICY,
    BOUND_HOST_TOOLCHAIN_RECEIPT_PATH,
    BOUND_HOST_TOOLCHAIN_RECEIPT_SCHEMA_VERSION,
    BOUND_HOST_TOOLCHAIN_RUNNER_PATH,
    BOUND_GIT_CONFIG_OVERRIDES,
    BOUND_TOOL_IDENTITY_SCHEMA_VERSION,
    BOUND_TOOL_POLICY,
    BOUND_TOOL_SPECS,
)


class BoundCommandError(RuntimeError):
    """A fixed release command could not be executed safely."""


@dataclass(frozen=True)
class ToolSpec:
    """One immutable logical tool definition."""

    tool_id: str
    absolute_candidates: tuple[str, ...]
    use_sys_executable: bool
    manifest_required_when_mutable: bool
    launcher_tool_id: str | None
    version_argv: tuple[str, ...]
    exact_version: str | None
    script_policy: str


@dataclass(frozen=True)
class SafeToolIdentity:
    """Path-redacted identity suitable for a receipt or canonical projection."""

    tool_id: str
    resolution: str
    resolved_path_sha256: str
    symlink_chain_sha256: str
    source_sha256: str
    source_size: int
    source_mode: int
    source_owner_uid: int
    version: str
    dependencies: Mapping[str, Mapping[str, object]]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": BOUND_TOOL_IDENTITY_SCHEMA_VERSION,
            "tool_id": self.tool_id,
            "resolution": self.resolution,
            "resolved_path_sha256": self.resolved_path_sha256,
            "symlink_chain_sha256": self.symlink_chain_sha256,
            "source_sha256": self.source_sha256,
            "source_size": self.source_size,
            "source_mode": self.source_mode,
            "source_owner_uid": self.source_owner_uid,
            "version": self.version,
            "dependencies": {
                key: dict(value) for key, value in self.dependencies.items()
            },
        }


@dataclass(frozen=True)
class BoundCommandResult:
    """Binary command result plus its path-redacted tool identity."""

    returncode: int
    stdout: bytes
    stderr: bytes
    tool_identity: Mapping[str, object]
    command_assets: tuple[Mapping[str, object], ...] = ()
    private_outputs: tuple[PrivateOutput, ...] = ()


@dataclass(frozen=True)
class PrivateOutputSpec:
    """One exact private output argument owned by the bound runner."""

    argument_index: int
    name: str
    size_limit: int


@dataclass(frozen=True)
class PrivateOutput:
    """Path-redacted immutable bytes recovered from a descriptor-bound output."""

    name: str
    raw: bytes
    sha256: str
    size: int


@dataclass(frozen=True)
class HostToolchainAuthority:
    """Committed host-toolchain authority, revalidated at every command call."""

    repository_root: Path
    source_commit: str
    receipt_raw: bytes


@dataclass(frozen=True)
class _SourceBinding:
    tool_id: str
    invoked: Path
    resolved: Path
    raw: bytes
    stat_identity: tuple[int, ...]
    safe_base: Mapping[str, object]
    immutable_system: bool
    shebang_interpreter: Path | None


@dataclass(frozen=True)
class _StagedSource:
    source: _SourceBinding
    path: Path
    stat_identity: tuple[int, ...]
    sha256: str


@dataclass(frozen=True)
class _TreeBinding:
    root: Path
    directories: tuple[str, ...]
    files: Mapping[str, bytes]
    links: Mapping[str, str]
    safe_identity: Mapping[str, object]
    state_sha256: str
    immutable_system: bool


@dataclass(frozen=True)
class _StagedTree:
    source: _TreeBinding
    root: Path


@dataclass(frozen=True)
class _DataBinding:
    path: Path
    raw: bytes
    stat_identity: tuple[int, ...]
    safe_identity: Mapping[str, object]


@dataclass(frozen=True)
class _StagedData:
    source: _DataBinding
    path: Path
    stat_identity: tuple[int, ...]


@dataclass(frozen=True)
class _StagedPrivateOutput:
    spec: PrivateOutputSpec
    path: Path
    descriptor: int
    device: int
    inode: int


_BOUND_PROCESS_NONCE_ENV = "CONCORDIA_INTERNAL_BOUND_PROCESS_NONCE"
_MAX_TRACKED_DESCENDANTS = 4096


def _spec_from_contract(tool_id: str, value: Mapping[str, object]) -> ToolSpec:
    try:
        candidates = tuple(str(path) for path in value["absolute_candidates"])
        version_argv = tuple(str(part) for part in value["version_argv"])
        launcher = value["launcher_tool_id"]
        exact_version = value["exact_version"]
        spec = ToolSpec(
            tool_id=tool_id,
            absolute_candidates=candidates,
            use_sys_executable=value["use_sys_executable"] is True,
            manifest_required_when_mutable=(
                value["manifest_required_when_mutable"] is True
            ),
            launcher_tool_id=None if launcher is None else str(launcher),
            version_argv=version_argv,
            exact_version=None if exact_version is None else str(exact_version),
            script_policy=str(value["script_policy"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("bound tool contract is malformed") from exc
    if (
        not spec.tool_id
        or not spec.version_argv
        or spec.version_argv[0] != spec.tool_id
        or spec.script_policy not in {"binary", "node_launcher"}
        or spec.use_sys_executable
        and spec.absolute_candidates
        or not spec.use_sys_executable
        and not spec.absolute_candidates
    ):
        raise RuntimeError("bound tool contract is internally inconsistent")
    return spec


_TOOL_SPECS: Mapping[str, ToolSpec] = MappingProxyType(
    {
        tool_id: _spec_from_contract(tool_id, value)
        for tool_id, value in BOUND_TOOL_SPECS.items()
    }
)


def tool_spec(tool_id: str) -> ToolSpec:
    """Return one immutable logical-tool definition."""

    try:
        return _TOOL_SPECS[tool_id]
    except KeyError as exc:
        raise BoundCommandError("unknown fixed release tool") from exc


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise BoundCommandError("tool identity is not canonical") from exc


def _path_hash(path: Path) -> str:
    return hashlib.sha256(os.fsencode(path.absolute())).hexdigest()


def _stat_tuple(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_working_directory(cwd: Path) -> Path:
    if not cwd.is_absolute():
        raise BoundCommandError("bound command working directory must be absolute")
    current = Path(cwd.anchor)
    try:
        root_metadata = current.lstat()
    except OSError as exc:
        raise BoundCommandError(
            "bound command working directory is unavailable"
        ) from exc
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise BoundCommandError("bound command working directory is invalid")
    for part in cwd.parts[1:]:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise BoundCommandError(
                "bound command working directory is unavailable"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise BoundCommandError(
                "bound command working directory contains a symlink"
            )
        if not stat.S_ISDIR(metadata.st_mode):
            raise BoundCommandError(
                "bound command working directory contains a non-directory"
            )
    try:
        resolved = cwd.resolve(strict=True)
    except OSError as exc:
        raise BoundCommandError(
            "bound command working directory is unavailable"
        ) from exc
    if resolved != cwd:
        raise BoundCommandError("bound command working directory changed")
    return resolved


def _validate_exact_regular_file(path: Path, *, label: str) -> Path:
    if not path.is_absolute():
        raise BoundCommandError(f"{label} must be an absolute path")
    normalized = Path(os.path.normpath(path.as_posix()))
    if normalized != path:
        raise BoundCommandError(f"{label} is not normalized")
    parent = _validate_working_directory(path.parent)
    exact = parent / path.name
    try:
        metadata = exact.lstat()
        resolved = exact.resolve(strict=True)
    except OSError as exc:
        raise BoundCommandError(f"{label} is unavailable") from exc
    if (
        exact != path
        or resolved != exact
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise BoundCommandError(f"{label} is not an exact regular file")
    return exact


def _candidate_path(spec: ToolSpec) -> Path:
    if spec.use_sys_executable:
        candidate = Path(sys.executable)
        if not candidate.is_absolute():
            raise BoundCommandError("fixed Python executable is not absolute")
        try:
            return candidate.resolve(strict=True)
        except OSError as exc:
            raise BoundCommandError("fixed Python executable is unavailable") from exc
    for value in spec.absolute_candidates:
        candidate = Path(value)
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise BoundCommandError("fixed release tool is unavailable") from exc
        return candidate
    raise BoundCommandError("fixed release tool is unavailable")


def _symlink_chain(candidate: Path) -> tuple[Path, tuple[dict[str, object], ...]]:
    rows: list[dict[str, object]] = []
    seen: set[tuple[int, int]] = set()
    maximum = int(BOUND_TOOL_POLICY["symlink_chain_max_depth"])
    pending = Path(os.path.normpath(candidate.absolute().as_posix()))
    symlink_count = 0
    while True:
        current = Path(pending.anchor)
        parts = pending.parts[1:]
        restarted = False
        for index, part in enumerate(parts):
            current = current / part
            try:
                metadata = current.lstat()
            except OSError as exc:
                raise BoundCommandError("fixed release tool is unavailable") from exc
            is_last = index == len(parts) - 1
            kind = (
                "symlink"
                if stat.S_ISLNK(metadata.st_mode)
                else "target"
                if is_last
                else "directory"
            )
            row: dict[str, object] = {
                "path_sha256": _path_hash(current),
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "mode": metadata.st_mode & 0o7777,
                "owner_uid": metadata.st_uid,
                "size": metadata.st_size,
                "mtime_ns": metadata.st_mtime_ns,
                "ctime_ns": metadata.st_ctime_ns,
                "kind": kind,
            }
            if not stat.S_ISLNK(metadata.st_mode):
                if not is_last and not stat.S_ISDIR(metadata.st_mode):
                    raise BoundCommandError(
                        "fixed release tool has a non-directory ancestor"
                    )
                if is_last:
                    rows.append(row)
                continue
            key = (metadata.st_dev, metadata.st_ino)
            if key in seen or symlink_count >= maximum:
                raise BoundCommandError(
                    "fixed release tool symlink loop or depth violation"
                )
            seen.add(key)
            symlink_count += 1
            try:
                target = os.readlink(current)
            except OSError as exc:
                raise BoundCommandError(
                    "fixed release tool symlink is unreadable"
                ) from exc
            row["link_target_sha256"] = hashlib.sha256(os.fsencode(target)).hexdigest()
            rows.append(row)
            target_path = Path(target)
            replacement = (
                target_path
                if target_path.is_absolute()
                else current.parent / target_path
            )
            pending = Path(
                os.path.normpath(replacement.joinpath(*parts[index + 1 :]).as_posix())
            )
            restarted = True
            break
        if not restarted:
            return current, tuple(rows)


def _read_source(path: Path) -> tuple[bytes, os.stat_result]:
    maximum = int(BOUND_TOOL_POLICY["maximum_source_bytes"])
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BoundCommandError("fixed release tool cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > maximum
            or before.st_mode & 0o022
            or not before.st_mode & 0o111
        ):
            raise BoundCommandError(
                "fixed release tool is not a bounded non-writable executable"
            )
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(raw) != before.st_size
            or len(raw) > maximum
            or _stat_tuple(before) != _stat_tuple(after)
        ):
            raise BoundCommandError("fixed release tool changed while read")
        return raw, before
    finally:
        os.close(descriptor)


def _read_tree_file(path: Path) -> tuple[bytes, os.stat_result]:
    maximum = int(BOUND_TOOL_POLICY["maximum_source_bytes"])
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BoundCommandError("tool runtime file cannot be opened safely") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise BoundCommandError("tool runtime contains an invalid file")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(raw) != before.st_size
            or len(raw) > maximum
            or _stat_tuple(before) != _stat_tuple(after)
        ):
            raise BoundCommandError("tool runtime file changed while read")
        return raw, before
    finally:
        os.close(descriptor)


def _tree_binding(root: Path, *, label: str) -> _TreeBinding:
    try:
        root = root.resolve(strict=True)
        root_metadata = root.lstat()
    except OSError as exc:
        raise BoundCommandError(f"{label} runtime tree is unavailable") from exc
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise BoundCommandError(f"{label} runtime root is not an exact directory")
    directories: list[str] = []
    files: dict[str, bytes] = {}
    links: dict[str, str] = {}
    safe_rows: list[dict[str, object]] = []
    state_rows: list[dict[str, object]] = [
        {"path": ".", "stat": _stat_tuple(root_metadata)}
    ]
    total = 0
    immutable_system = root_metadata.st_uid == 0 and root_metadata.st_mode & 0o022 == 0
    maximum = int(BOUND_TOOL_POLICY["maximum_source_bytes"])

    def walk(directory: Path, relative: Path) -> None:
        nonlocal immutable_system, total
        try:
            with os.scandir(directory) as entries:
                rows = sorted(entries, key=lambda entry: entry.name)
        except OSError as exc:
            raise BoundCommandError(f"{label} runtime tree is unreadable") from exc
        for entry in rows:
            if entry.name in {"", ".", ".."} or "/" in entry.name:
                raise BoundCommandError(f"{label} runtime entry is unsafe")
            child_relative = relative / entry.name
            relative_text = child_relative.as_posix()
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise BoundCommandError(
                    f"{label} runtime entry is unavailable"
                ) from exc
            state_rows.append({"path": relative_text, "stat": _stat_tuple(metadata)})
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                immutable_system = False
            if stat.S_ISDIR(metadata.st_mode):
                directories.append(relative_text)
                safe_rows.append(
                    {
                        "path": relative_text,
                        "kind": "directory",
                        "mode": metadata.st_mode & 0o7777,
                    }
                )
                walk(Path(entry.path), child_relative)
                continue
            if stat.S_ISREG(metadata.st_mode):
                raw, verified_metadata = _read_tree_file(Path(entry.path))
                if _stat_tuple(metadata) != _stat_tuple(verified_metadata):
                    raise BoundCommandError(
                        f"{label} runtime entry changed during scan"
                    )
                total += len(raw)
                if total > maximum:
                    raise BoundCommandError(f"{label} runtime tree is too large")
                files[relative_text] = raw
                safe_rows.append(
                    {
                        "path": relative_text,
                        "kind": "file",
                        "mode": metadata.st_mode & 0o7777,
                        "size": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    }
                )
                continue
            if stat.S_ISLNK(metadata.st_mode):
                try:
                    target = os.readlink(entry.path)
                except OSError as exc:
                    raise BoundCommandError(
                        f"{label} runtime symlink is unreadable"
                    ) from exc
                target_path = Path(target)
                if target_path.is_absolute():
                    raise BoundCommandError(
                        f"{label} runtime contains an absolute symlink"
                    )
                normalized = Path(
                    os.path.normpath(
                        (root / child_relative.parent / target_path).as_posix()
                    )
                )
                try:
                    normalized.relative_to(root)
                except ValueError as exc:
                    raise BoundCommandError(
                        f"{label} runtime symlink escapes its tree"
                    ) from exc
                links[relative_text] = target
                safe_rows.append(
                    {
                        "path": relative_text,
                        "kind": "symlink",
                        "target_sha256": hashlib.sha256(
                            os.fsencode(target)
                        ).hexdigest(),
                    }
                )
                continue
            raise BoundCommandError(f"{label} runtime contains a special file")

    walk(root, Path())
    try:
        root_after = root.lstat()
    except OSError as exc:
        raise BoundCommandError(f"{label} runtime root changed") from exc
    if _stat_tuple(root_metadata) != _stat_tuple(root_after):
        raise BoundCommandError(f"{label} runtime root changed during scan")
    safe_identity = {
        "schema_version": "concordia.bound_tool_tree.v1",
        "tree_sha256": hashlib.sha256(_canonical_json(safe_rows)).hexdigest(),
        "entry_count": len(safe_rows),
        "file_count": len(files),
        "total_file_bytes": total,
        "immutable_system": immutable_system,
    }
    return _TreeBinding(
        root=root,
        directories=tuple(directories),
        files=MappingProxyType(files),
        links=MappingProxyType(links),
        safe_identity=MappingProxyType(safe_identity),
        state_sha256=hashlib.sha256(_canonical_json(state_rows)).hexdigest(),
        immutable_system=immutable_system,
    )


def _revalidate_tree(binding: _TreeBinding, *, label: str) -> None:
    observed = _tree_binding(binding.root, label=label)
    if (
        observed.directories != binding.directories
        or dict(observed.files) != dict(binding.files)
        or dict(observed.links) != dict(binding.links)
        or dict(observed.safe_identity) != dict(binding.safe_identity)
        or observed.state_sha256 != binding.state_sha256
        or observed.immutable_system != binding.immutable_system
    ):
        raise BoundCommandError(f"{label} runtime tree changed")


def _stage_tree(
    directory: Path,
    binding: _TreeBinding,
    *,
    name: str,
) -> _StagedTree:
    root = directory / name
    root.mkdir(mode=0o700)
    for relative in binding.directories:
        (root / relative).mkdir(mode=0o700)
    for relative, raw in binding.files.items():
        target = root / relative
        executable = (binding.root / relative).lstat().st_mode & 0o111
        mode = 0o500 if executable else 0o400
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags, mode)
        try:
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, raw[offset:])
                if written <= 0:
                    raise BoundCommandError("tool runtime snapshot write failed")
                offset += written
            os.fsync(descriptor)
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    for relative, target in binding.links.items():
        os.symlink(target, root / relative)
    for relative in reversed(binding.directories):
        os.chmod(root / relative, 0o500)
    os.chmod(root, 0o500)
    _revalidate_staged_tree(_StagedTree(source=binding, root=root))
    return _StagedTree(source=binding, root=root)


def _revalidate_staged_tree(staged: _StagedTree) -> None:
    expected_inventory = {
        **{relative: "directory" for relative in staged.source.directories},
        **{relative: "file" for relative in staged.source.files},
        **{relative: "symlink" for relative in staged.source.links},
    }
    observed_inventory: dict[str, str] = {}
    for path in staged.root.rglob("*"):
        relative = path.relative_to(staged.root).as_posix()
        metadata = path.lstat()
        kind = (
            "symlink"
            if stat.S_ISLNK(metadata.st_mode)
            else "directory"
            if stat.S_ISDIR(metadata.st_mode)
            else "file"
            if stat.S_ISREG(metadata.st_mode)
            else "special"
        )
        observed_inventory[relative] = kind
    if observed_inventory != expected_inventory:
        raise BoundCommandError("private tool runtime snapshot inventory differs")
    for relative, expected in staged.source.files.items():
        observed, metadata = _read_tree_file(staged.root / relative)
        expected_mode = (
            0o500 if (staged.source.root / relative).stat().st_mode & 0o111 else 0o400
        )
        if (
            observed != expected
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o777 != expected_mode
        ):
            raise BoundCommandError("private tool runtime snapshot file differs")
    for relative, expected in staged.source.links.items():
        if os.readlink(staged.root / relative) != expected:
            raise BoundCommandError("private tool runtime snapshot symlink differs")


def _system_immutable(path: Path, metadata: os.stat_result) -> bool:
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        return False
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current = current / part
        try:
            parent = current.lstat()
        except OSError:
            return False
        if (
            stat.S_ISLNK(parent.st_mode)
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != 0
            or parent.st_mode & 0o022
        ):
            return False
    return True


def _validate_script_policy(
    spec: ToolSpec,
    raw: bytes,
) -> Path | None:
    first_line = raw.splitlines()[0] if raw else b""
    if spec.script_policy == "node_launcher":
        if first_line not in {b"#!/usr/bin/env node", b"#!/usr/bin/node"}:
            raise BoundCommandError("fixed npm script has an unsupported shebang")
        return None
    if not first_line.startswith(b"#!"):
        return None
    try:
        shebang = first_line[2:].decode("utf-8", errors="strict").strip()
        arguments = shlex.split(shebang, posix=True)
    except (UnicodeDecodeError, ValueError) as exc:
        raise BoundCommandError("fixed release tool shebang is malformed") from exc
    if len(arguments) != 1 or not Path(arguments[0]).is_absolute():
        raise BoundCommandError("fixed release tool shebang interpreter is not exact")
    interpreter = Path(arguments[0])
    resolved, _rows = _symlink_chain(interpreter)
    _raw, metadata = _read_source(resolved)
    if not _system_immutable(resolved, metadata):
        raise BoundCommandError(
            "fixed release tool shebang interpreter is not immutable"
        )
    return resolved


def _source_binding(spec: ToolSpec) -> _SourceBinding:
    invoked = _candidate_path(spec)
    resolved, chain = _symlink_chain(invoked)
    raw, metadata = _read_source(resolved)
    shebang_interpreter = _validate_script_policy(spec, raw)
    safe_base = {
        "schema_version": BOUND_TOOL_IDENTITY_SCHEMA_VERSION,
        "tool_id": spec.tool_id,
        "resolution": (
            "sys_executable" if spec.use_sys_executable else "absolute_candidate"
        ),
        "resolved_path_sha256": _path_hash(resolved),
        "symlink_chain_sha256": hashlib.sha256(_canonical_json(chain)).hexdigest(),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "source_size": len(raw),
        "source_mode": metadata.st_mode & 0o7777,
        "source_owner_uid": metadata.st_uid,
    }
    return _SourceBinding(
        tool_id=spec.tool_id,
        invoked=invoked,
        resolved=resolved,
        raw=raw,
        stat_identity=_stat_tuple(metadata),
        safe_base=MappingProxyType(safe_base),
        immutable_system=_system_immutable(resolved, metadata),
        shebang_interpreter=shebang_interpreter,
    )


def _revalidate_source(
    binding: _SourceBinding,
    *,
    exact_spec: ToolSpec | None = None,
) -> None:
    spec = exact_spec if exact_spec is not None else tool_spec(binding.tool_id)
    observed = _source_binding(spec)
    if (
        observed.invoked != binding.invoked
        or observed.resolved != binding.resolved
        or observed.stat_identity != binding.stat_identity
        or dict(observed.safe_base) != dict(binding.safe_base)
        or observed.raw != binding.raw
    ):
        raise BoundCommandError("fixed release tool identity changed")


def _write_snapshot(
    directory: Path,
    binding: _SourceBinding,
    *,
    suffix: str = "",
) -> _StagedSource:
    name = f"{binding.tool_id}{suffix}"
    target = directory / name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags, 0o400)
    except OSError as exc:
        raise BoundCommandError("private tool snapshot could not be created") from exc
    try:
        offset = 0
        while offset < len(binding.raw):
            written = os.write(descriptor, binding.raw[offset:])
            if written <= 0:
                raise BoundCommandError("private tool snapshot write failed")
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, int(BOUND_TOOL_POLICY["private_executable_mode"]))
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    directory_descriptor = os.open(
        directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    observed, observed_metadata = _read_source(target)
    digest = hashlib.sha256(observed).hexdigest()
    if observed != binding.raw or _stat_tuple(observed_metadata) != _stat_tuple(
        metadata
    ):
        raise BoundCommandError("private tool snapshot identity differs")
    return _StagedSource(
        source=binding,
        path=target,
        stat_identity=_stat_tuple(metadata),
        sha256=digest,
    )


def _revalidate_snapshot(snapshot: _StagedSource) -> None:
    raw, metadata = _read_source(snapshot.path)
    if (
        raw != snapshot.source.raw
        or hashlib.sha256(raw).hexdigest() != snapshot.sha256
        or _stat_tuple(metadata) != snapshot.stat_identity
    ):
        raise BoundCommandError("private tool snapshot changed")


class _NonReapingExitObserver:
    """Observe one child exit without releasing its PID for reuse."""

    def __init__(self, pid: int) -> None:
        if type(pid) is not int or pid <= 0:
            raise BoundCommandError("bound process identity is invalid")
        self._pid = pid
        self._exited = False
        self._kind = ""
        self._kqueue: select.kqueue | None = None
        self._pidfd: int | None = None
        self._poller: select.poll | None = None

        if sys.platform == "darwin":
            if not all(
                hasattr(select, name)
                for name in (
                    "kqueue",
                    "kevent",
                    "KQ_FILTER_PROC",
                    "KQ_EV_ADD",
                    "KQ_EV_ENABLE",
                    "KQ_EV_CLEAR",
                    "KQ_NOTE_EXIT",
                )
            ):
                raise BoundCommandError(
                    "non-reaping process observation is unavailable"
                )
            queue = select.kqueue()
            try:
                event = select.kevent(
                    pid,
                    filter=select.KQ_FILTER_PROC,
                    flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
                    fflags=select.KQ_NOTE_EXIT,
                )
                queue.control((event,), 0, 0)
            except ProcessLookupError:
                # Popen still owns the unreaped child. ESRCH while registering
                # EVFILT_PROC therefore means it exited before registration;
                # its PID remains allocated until the explicit wait below.
                queue.close()
                self._kind = "already_exited"
                self._exited = True
                return
            except (OSError, ValueError) as exc:
                queue.close()
                raise BoundCommandError(
                    "non-reaping process observation could not start"
                ) from exc
            self._kind = "darwin_kqueue"
            self._kqueue = queue
            return

        if sys.platform.startswith("linux"):
            waitid = getattr(os, "waitid", None)
            if callable(waitid) and all(
                hasattr(os, name) for name in ("P_PID", "WEXITED", "WNOHANG", "WNOWAIT")
            ):
                self._kind = "linux_waitid"
                return
            pidfd_open = getattr(os, "pidfd_open", None)
            if callable(pidfd_open) and hasattr(select, "poll"):
                try:
                    descriptor = pidfd_open(pid, 0)
                except ProcessLookupError:
                    self._kind = "already_exited"
                    self._exited = True
                    return
                except OSError as exc:
                    raise BoundCommandError(
                        "non-reaping process observation could not start"
                    ) from exc
                poller = select.poll()
                poller.register(
                    descriptor,
                    select.POLLIN | select.POLLHUP | select.POLLERR,
                )
                self._kind = "linux_pidfd"
                self._pidfd = descriptor
                self._poller = poller
                return

        raise BoundCommandError("non-reaping process observation is unsupported")

    def exited(self) -> bool:
        if self._exited:
            return True
        if self._kind == "darwin_kqueue":
            if self._kqueue is None:
                raise BoundCommandError("non-reaping process observer is invalid")
            try:
                events = self._kqueue.control(None, 1, 0)
            except (OSError, ValueError) as exc:
                raise BoundCommandError(
                    "non-reaping process observation failed"
                ) from exc
            if not events:
                return False
            event = events[0]
            if (
                event.ident != self._pid
                or not event.fflags & select.KQ_NOTE_EXIT
                or event.flags & getattr(select, "KQ_EV_ERROR", 0)
            ):
                raise BoundCommandError(
                    "non-reaping process observation was inconsistent"
                )
            self._exited = True
            return True
        if self._kind == "linux_waitid":
            try:
                observation = os.waitid(
                    os.P_PID,
                    self._pid,
                    os.WEXITED | os.WNOHANG | os.WNOWAIT,
                )
            except (ChildProcessError, OSError) as exc:
                raise BoundCommandError(
                    "non-reaping process observation failed"
                ) from exc
            self._exited = observation is not None and observation.si_pid == self._pid
            return self._exited
        if self._kind == "linux_pidfd":
            if self._poller is None:
                raise BoundCommandError("non-reaping process observer is invalid")
            try:
                events = self._poller.poll(0)
            except OSError as exc:
                raise BoundCommandError(
                    "non-reaping process observation failed"
                ) from exc
            if not events:
                return False
            if len(events) != 1 or events[0][0] != self._pidfd:
                raise BoundCommandError(
                    "non-reaping process observation was inconsistent"
                )
            if events[0][1] & (select.POLLERR | getattr(select, "POLLNVAL", 0)):
                raise BoundCommandError(
                    "non-reaping process observation was inconsistent"
                )
            self._exited = bool(events[0][1] & (select.POLLIN | select.POLLHUP))
            return self._exited
        if self._kind == "already_exited":
            return True
        raise BoundCommandError("non-reaping process observer is invalid")

    def close(self) -> None:
        if self._kqueue is not None:
            self._kqueue.close()
            self._kqueue = None
        if self._pidfd is not None:
            os.close(self._pidfd)
            self._pidfd = None


def _signal_process_group(
    process: subprocess.Popen[bytes],
    *,
    leader_exited: bool,
) -> None:
    """Signal the dedicated group while its unreaped leader still owns the PGID."""

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except PermissionError as group_error:
        # Darwin reports EPERM for a process group containing only its zombie
        # leader. Because the unreaped leader prevents PGID reuse, and a live
        # same-session child would make killpg succeed, this completed-leader
        # case has no signalable group member left.
        if leader_exited and sys.platform == "darwin":
            return
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except (PermissionError, OSError) as exc:
            raise BoundCommandError("bound process group could not be killed") from exc
        raise BoundCommandError(
            "bound process group could not be killed"
        ) from group_error
    except (PermissionError, OSError) as group_error:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except (PermissionError, OSError) as exc:
            raise BoundCommandError("bound process group could not be killed") from exc
        raise BoundCommandError(
            "bound process group could not be killed"
        ) from group_error


def _contain_and_reap_process(
    process: subprocess.Popen[bytes],
    tracker: _DescendantTracker,
    *,
    leader_exited: bool,
) -> int:
    """Contain the complete tree, then perform the only reap of its leader."""

    failure: BaseException | None = None
    try:
        _signal_process_group(process, leader_exited=leader_exited)
    except BaseException as exc:
        failure = exc
    try:
        tracker.contain()
    except BaseException as exc:
        if failure is None:
            failure = exc
    try:
        returncode = process.wait()
    except BaseException as exc:
        if failure is None:
            failure = exc
        returncode = 1
    if failure is not None:
        if isinstance(failure, BoundCommandError):
            raise failure
        raise BoundCommandError("bound process containment failed") from failure
    return returncode


def _darwin_child_pids(parent_pid: int) -> tuple[int, ...]:
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        function = library.proc_listchildpids
        function.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
        function.restype = ctypes.c_int
        values = (ctypes.c_int * _MAX_TRACKED_DESCENDANTS)()
        count = function(parent_pid, values, ctypes.sizeof(values))
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise BoundCommandError(
            "detached descendant enumeration is unavailable"
        ) from exc
    if count < 0:
        error = ctypes.get_errno()
        if error in {0, 3}:
            return ()
        raise BoundCommandError("detached descendant enumeration failed")
    if count >= _MAX_TRACKED_DESCENDANTS:
        raise BoundCommandError("detached descendant set is too large")
    children = tuple(int(values[index]) for index in range(count))
    if any(pid <= 0 for pid in children) or len(children) != len(set(children)):
        raise BoundCommandError("detached descendant enumeration is malformed")
    return children


def _linux_child_pids(parent_pid: int) -> tuple[int, ...]:
    task_root = Path(f"/proc/{parent_pid}/task")
    try:
        task_paths = tuple(task_root.iterdir())
    except FileNotFoundError:
        return ()
    except OSError as exc:
        raise BoundCommandError("detached descendant enumeration failed") from exc
    children: set[int] = set()
    for task_path in task_paths:
        if not task_path.name.isdecimal():
            raise BoundCommandError("detached descendant task identity is malformed")
        try:
            raw = (task_path / "children").read_bytes()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise BoundCommandError("detached descendant enumeration failed") from exc
        if len(raw) > 1024 * 1024:
            raise BoundCommandError("detached descendant set is too large")
        try:
            values = raw.decode("ascii", errors="strict").split()
        except UnicodeDecodeError as exc:
            raise BoundCommandError(
                "detached descendant enumeration is malformed"
            ) from exc
        for value in values:
            if not value.isdecimal() or int(value) <= 0:
                raise BoundCommandError("detached descendant enumeration is malformed")
            children.add(int(value))
            if len(children) >= _MAX_TRACKED_DESCENDANTS:
                raise BoundCommandError("detached descendant set is too large")
    return tuple(sorted(children))


def _direct_child_pids(parent_pid: int) -> tuple[int, ...]:
    if sys.platform == "darwin":
        return _darwin_child_pids(parent_pid)
    if sys.platform.startswith("linux"):
        return _linux_child_pids(parent_pid)
    raise BoundCommandError("detached descendant containment is unsupported")


def _linux_nonce_pids(nonce: str) -> tuple[int, ...]:
    if not sys.platform.startswith("linux"):
        return ()
    needle = f"{_BOUND_PROCESS_NONCE_ENV}={nonce}".encode("ascii")
    matches: set[int] = set()
    try:
        entries = tuple(Path("/proc").iterdir())
    except OSError as exc:
        raise BoundCommandError("detached descendant nonce scan failed") from exc
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        try:
            raw = (entry / "environ").read_bytes()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        except OSError as exc:
            raise BoundCommandError("detached descendant nonce scan failed") from exc
        if len(raw) > 16 * 1024 * 1024:
            raise BoundCommandError(
                "detached descendant environment is unexpectedly large"
            )
        if needle in raw.split(b"\0"):
            matches.add(int(entry.name))
            if len(matches) >= _MAX_TRACKED_DESCENDANTS:
                raise BoundCommandError("detached descendant set is too large")
    return tuple(sorted(matches))


def _darwin_descriptor_holder_pids(marker_path: Path) -> tuple[int, ...]:
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        list_all = library.proc_listallpids
        list_all.argtypes = (ctypes.c_void_p, ctypes.c_int)
        list_all.restype = ctypes.c_int
        pid_info = library.proc_pidinfo
        pid_info.argtypes = (
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_int,
        )
        pid_info.restype = ctypes.c_int
        fd_info = library.proc_pidfdinfo
        fd_info.argtypes = (
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_int,
        )
        fd_info.restype = ctypes.c_int
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise BoundCommandError(
            "detached descendant descriptor scan is unavailable"
        ) from exc

    pids = (ctypes.c_int * 32768)()
    count = list_all(pids, ctypes.sizeof(pids))
    if count < 0 or count >= len(pids):
        raise BoundCommandError("detached descendant process list is invalid")
    needle = os.fsencode(marker_path) + b"\0"
    matches: set[int] = set()
    fd_rows = ctypes.create_string_buffer(8 * 4096)
    vnode = ctypes.create_string_buffer(4096)
    for pid in pids[:count]:
        if pid <= 0 or pid == os.getpid():
            continue
        byte_count = pid_info(pid, 1, 0, fd_rows, len(fd_rows))
        if byte_count <= 0:
            continue
        if byte_count >= len(fd_rows) or byte_count % 8:
            raise BoundCommandError("detached descendant descriptor list is malformed")
        for offset in range(0, byte_count, 8):
            descriptor, descriptor_type = struct.unpack_from("iI", fd_rows.raw, offset)
            if descriptor < 0 or descriptor_type != 1:
                continue
            vnode_count = fd_info(pid, descriptor, 2, vnode, len(vnode))
            if vnode_count <= 0:
                continue
            if vnode_count > len(vnode):
                raise BoundCommandError(
                    "detached descendant descriptor record is malformed"
                )
            if needle in vnode.raw[:vnode_count]:
                matches.add(pid)
                if len(matches) >= _MAX_TRACKED_DESCENDANTS:
                    raise BoundCommandError("detached descendant set is too large")
                break
    return tuple(sorted(matches))


def _linux_descriptor_holder_pids(marker_path: Path) -> tuple[int, ...]:
    try:
        marker_metadata = marker_path.stat()
        entries = tuple(Path("/proc").iterdir())
    except OSError as exc:
        raise BoundCommandError("detached descendant descriptor scan failed") from exc
    matches: set[int] = set()
    for entry in entries:
        if not entry.name.isdecimal() or int(entry.name) == os.getpid():
            continue
        try:
            descriptors = tuple((entry / "fd").iterdir())
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        except OSError as exc:
            raise BoundCommandError(
                "detached descendant descriptor scan failed"
            ) from exc
        for descriptor in descriptors:
            try:
                metadata = descriptor.stat()
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            except OSError as exc:
                raise BoundCommandError(
                    "detached descendant descriptor scan failed"
                ) from exc
            if (
                metadata.st_dev == marker_metadata.st_dev
                and metadata.st_ino == marker_metadata.st_ino
            ):
                matches.add(int(entry.name))
                if len(matches) >= _MAX_TRACKED_DESCENDANTS:
                    raise BoundCommandError("detached descendant set is too large")
                break
    return tuple(sorted(matches))


def _descriptor_holder_pids(marker_path: Path) -> tuple[int, ...]:
    if sys.platform == "darwin":
        return _darwin_descriptor_holder_pids(marker_path)
    if sys.platform.startswith("linux"):
        return _linux_descriptor_holder_pids(marker_path)
    raise BoundCommandError("detached descendant containment is unsupported")


def _process_identity(pid: int) -> tuple[int, int, int] | None:
    if pid <= 0:
        raise BoundCommandError("detached descendant process identity is malformed")
    if sys.platform == "darwin":
        try:
            library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            function = library.proc_pidinfo
            function.argtypes = (
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_uint64,
                ctypes.c_void_p,
                ctypes.c_int,
            )
            function.restype = ctypes.c_int
            raw = ctypes.create_string_buffer(136)
            count = function(pid, 3, 0, raw, len(raw))
        except (AttributeError, OSError, TypeError, ValueError) as exc:
            raise BoundCommandError(
                "detached descendant process identity is unavailable"
            ) from exc
        if count == 0:
            return None
        if count != 136:
            raise BoundCommandError("detached descendant process identity is malformed")
        observed_pid = struct.unpack_from("=I", raw.raw, 12)[0]
        start_seconds = struct.unpack_from("=Q", raw.raw, 120)[0]
        start_microseconds = struct.unpack_from("=Q", raw.raw, 128)[0]
        if observed_pid != pid or start_seconds == 0 or start_microseconds >= 1_000_000:
            raise BoundCommandError("detached descendant process identity is malformed")
        return pid, start_seconds, start_microseconds

    if sys.platform.startswith("linux"):
        try:
            raw = Path(f"/proc/{pid}/stat").read_bytes()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise BoundCommandError(
                "detached descendant process identity is unavailable"
            ) from exc
        if len(raw) > 1024 * 1024:
            raise BoundCommandError("detached descendant process identity is malformed")
        closing = raw.rfind(b")")
        if closing < 0:
            raise BoundCommandError("detached descendant process identity is malformed")
        try:
            observed_pid = int(raw[: raw.index(b" ")])
            fields = raw[closing + 2 :].decode("ascii", errors="strict").split()
            start_ticks = int(fields[19])
        except (UnicodeDecodeError, ValueError, IndexError) as exc:
            raise BoundCommandError(
                "detached descendant process identity is malformed"
            ) from exc
        if observed_pid != pid or start_ticks <= 0:
            raise BoundCommandError("detached descendant process identity is malformed")
        return pid, start_ticks, 0

    raise BoundCommandError("detached descendant containment is unsupported")


class _DescendantTracker:
    """Track trusted descendants while ancestry is visible, then kill survivors."""

    def __init__(self, nonce: str, marker_path: Path) -> None:
        self._nonce = nonce
        self._marker_path = marker_path
        self._root_pid: int | None = None
        self._root_identity: tuple[int, int, int] | None = None
        self._seen: dict[int, tuple[int, int, int]] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._failure: BaseException | None = None
        self._thread: threading.Thread | None = None
        self._contained = False

    def start(self, root_pid: int) -> None:
        if self._root_pid is not None or root_pid <= 0:
            raise BoundCommandError("detached descendant tracker state is invalid")
        root_identity = _process_identity(root_pid)
        if root_identity is None:
            raise BoundCommandError("bound process disappeared before containment")
        self._root_pid = root_pid
        self._root_identity = root_identity
        self._sample()
        self._thread = threading.Thread(
            target=self._monitor,
            name="concordia-bound-descendant-monitor",
            daemon=True,
        )
        self._thread.start()

    def _sample(self) -> None:
        root = self._root_pid
        if root is None:
            return
        with self._lock:
            observed = {
                pid: identity
                for pid, identity in self._seen.items()
                if _process_identity(pid) == identity
            }
            queue = (
                [root, *sorted(observed)]
                if _process_identity(root) == self._root_identity
                else sorted(observed)
            )
        index = 0
        while index < len(queue):
            parent_pid = queue[index]
            index += 1
            expected_identity = (
                self._root_identity if parent_pid == root else observed.get(parent_pid)
            )
            if _process_identity(parent_pid) != expected_identity:
                continue
            for child_pid in _direct_child_pids(parent_pid):
                if child_pid == os.getpid():
                    raise BoundCommandError(
                        "detached descendant enumeration included the runner"
                    )
                identity = _process_identity(child_pid)
                if identity is None:
                    continue
                if observed.get(child_pid) != identity:
                    observed[child_pid] = identity
                    queue.append(child_pid)
                if len(observed) >= _MAX_TRACKED_DESCENDANTS:
                    raise BoundCommandError("detached descendant set is too large")
        with self._lock:
            self._seen = observed

    def _monitor(self) -> None:
        try:
            while not self._stop.wait(0.001):
                self._sample()
        except BaseException as exc:  # pragma: no cover - surfaced by contain()
            self._failure = exc
            self._stop.set()

    def contain(self) -> None:
        if self._contained:
            return
        if self._root_pid is None:
            self._contained = True
            return
        try:
            self._sample()
        except BaseException as exc:
            self._failure = exc
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            if self._thread.is_alive():
                raise BoundCommandError("detached descendant monitor did not stop")
        if self._failure is not None:
            if isinstance(self._failure, BoundCommandError):
                raise self._failure
            raise BoundCommandError(
                "detached descendant containment failed"
            ) from self._failure

        for _attempt in range(100):
            self._sample()
            with self._lock:
                for pid in (
                    *_linux_nonce_pids(self._nonce),
                    *_descriptor_holder_pids(self._marker_path),
                ):
                    identity = _process_identity(pid)
                    if identity is not None:
                        self._seen[pid] = identity
                candidates = tuple(sorted(self._seen.items()))
            if not candidates:
                self._contained = True
                return
            survivors: dict[int, tuple[int, int, int]] = {}
            for pid, identity in candidates:
                if pid == os.getpid() or _process_identity(pid) != identity:
                    continue
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    continue
                except (PermissionError, OSError) as exc:
                    raise BoundCommandError(
                        "detached descendant could not be killed"
                    ) from exc
                survivors[pid] = identity
            with self._lock:
                self._seen = survivors
            time.sleep(0.01)
        raise BoundCommandError("detached descendant survived containment")


def _run_bounded_process_once(
    *,
    cwd: Path,
    argv: Sequence[str],
    executable: Path,
    env: Mapping[str, str],
    stdout_limit: int,
    stderr_limit: int,
    timeout_s: int,
    tracker: _DescendantTracker,
    inherited_descriptor: int,
    inherited_private_descriptor: int | None = None,
) -> subprocess.CompletedProcess[bytes]:
    with tempfile.TemporaryFile(mode="w+b") as stdout_file:
        with tempfile.TemporaryFile(mode="w+b") as stderr_file:
            try:
                process = subprocess.Popen(
                    list(argv),
                    executable=executable.as_posix(),
                    cwd=cwd,
                    env=dict(env),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    start_new_session=True,
                    pass_fds=(
                        (inherited_descriptor,)
                        if inherited_private_descriptor is None
                        else (inherited_descriptor, inherited_private_descriptor)
                    ),
                )
            except OSError as exc:
                raise BoundCommandError("bound command could not start") from exc
            observer: _NonReapingExitObserver | None = None
            leader_exited = False
            try:
                tracker.start(process.pid)
                observer = _NonReapingExitObserver(process.pid)
                deadline = time.monotonic() + timeout_s
                while True:
                    stdout_size = os.fstat(stdout_file.fileno()).st_size
                    stderr_size = os.fstat(stderr_file.fileno()).st_size
                    if stdout_size > stdout_limit or stderr_size > stderr_limit:
                        raise BoundCommandError(
                            "bound command exceeded its output limit"
                        )
                    if observer.exited():
                        leader_exited = True
                        break
                    if time.monotonic() >= deadline:
                        raise BoundCommandError("bound command timed out")
                    time.sleep(0.002)
            finally:
                try:
                    # Keep the leader unreaped until both its process group and
                    # any detached, identity-bound descendants are contained.
                    returncode = _contain_and_reap_process(
                        process,
                        tracker,
                        leader_exited=leader_exited,
                    )
                finally:
                    if observer is not None:
                        observer.close()
            stdout_size = os.fstat(stdout_file.fileno()).st_size
            stderr_size = os.fstat(stderr_file.fileno()).st_size
            if stdout_size > stdout_limit or stderr_size > stderr_limit:
                raise BoundCommandError("bound command exceeded its output limit")
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read(stdout_limit + 1)
            stderr = stderr_file.read(stderr_limit + 1)
            if (
                len(stdout) != stdout_size
                or len(stderr) != stderr_size
                or len(stdout) > stdout_limit
                or len(stderr) > stderr_limit
            ):
                raise BoundCommandError("bound command capture changed")
    return subprocess.CompletedProcess(tuple(argv), returncode, stdout, stderr)


def run_bounded_process(
    *,
    cwd: Path,
    argv: Sequence[str],
    executable: Path,
    env: Mapping[str, str],
    stdout_limit: int,
    stderr_limit: int,
    timeout_s: int,
    inherited_private_descriptor: int | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Capture live-capped output and contain inherited trusted descendants."""

    if (
        not argv
        or not executable.is_absolute()
        or stdout_limit < 0
        or stderr_limit < 0
        or timeout_s <= 0
        or _BOUND_PROCESS_NONCE_ENV in env
    ):
        raise BoundCommandError("bounded command parameters are invalid")
    if inherited_private_descriptor is not None:
        if (
            type(inherited_private_descriptor) is not int
            or inherited_private_descriptor <= 2
        ):
            raise BoundCommandError("private inherited descriptor is invalid")
        try:
            descriptor_status = os.fstat(inherited_private_descriptor)
            descriptor_flags = fcntl.fcntl(
                inherited_private_descriptor,
                fcntl.F_GETFL,
            )
            descriptor_fd_flags = fcntl.fcntl(
                inherited_private_descriptor,
                fcntl.F_GETFD,
            )
        except OSError as exc:
            raise BoundCommandError(
                "private inherited descriptor is unavailable"
            ) from exc
        if (
            not stat.S_ISFIFO(descriptor_status.st_mode)
            or descriptor_flags & os.O_ACCMODE != os.O_RDONLY
            or descriptor_fd_flags & fcntl.FD_CLOEXEC == 0
        ):
            raise BoundCommandError(
                "private inherited descriptor is not a read-only CLOEXEC FIFO"
            )
    maximum_stream = int(BOUND_TOOL_POLICY["maximum_stream_bytes"])
    if stdout_limit > maximum_stream or stderr_limit > maximum_stream:
        raise BoundCommandError("bounded command output limit is invalid")
    nonce = secrets.token_hex(32)
    execution_env = dict(env)
    execution_env[_BOUND_PROCESS_NONCE_ENV] = nonce
    marker = tempfile.NamedTemporaryFile(
        prefix="concordia-bound-descendant-",
        delete=False,
    )
    marker_path = Path(marker.name)
    os.fchmod(marker.fileno(), 0o600)
    tracker = _DescendantTracker(nonce, marker_path)
    try:
        try:
            return _run_bounded_process_once(
                cwd=cwd,
                argv=argv,
                executable=executable,
                env=execution_env,
                stdout_limit=stdout_limit,
                stderr_limit=stderr_limit,
                timeout_s=timeout_s,
                tracker=tracker,
                inherited_descriptor=marker.fileno(),
                inherited_private_descriptor=inherited_private_descriptor,
            )
        finally:
            marker.close()
            tracker.contain()
    finally:
        try:
            marker_path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise BoundCommandError(
                "detached descendant marker could not be removed"
            ) from exc


def _sanitize_environment(
    environment: Mapping[str, str],
    *,
    private_path: Path | None,
) -> dict[str, str]:
    allowed = set(BOUND_TOOL_POLICY["allowed_environment_keys"])
    result: dict[str, str] = {}
    for key, value in environment.items():
        if key == "PATH":
            continue
        if (
            key not in allowed
            or type(value) is not str
            or "\0" in value
            or "\n" in key
            or "=" in key
        ):
            raise BoundCommandError("bound command environment is not sanitized")
        result[key] = value
    result["PATH"] = str(BOUND_TOOL_POLICY["fixed_path"])
    if private_path is not None:
        result["PATH"] = private_path.as_posix() + os.pathsep + result["PATH"]
    result.setdefault("LANG", "C.UTF-8")
    result.setdefault("LC_ALL", "C.UTF-8")
    result.setdefault("NO_COLOR", "1")
    return result


def _normalize_version(result: subprocess.CompletedProcess[bytes]) -> str:
    try:
        values = [
            raw.decode("utf-8", errors="strict")
            .replace("\r\n", "\n")
            .replace("\r", "\n")
            .strip()
            for raw in (result.stdout, result.stderr)
            if raw
        ]
    except UnicodeDecodeError as exc:
        raise BoundCommandError("fixed tool version is not UTF-8") from exc
    version = "\n".join(value for value in values if value)
    if (
        not version
        or len(version.encode("utf-8")) > 1024 * 1024
        or any(
            character != "\n" and not character.isprintable() for character in version
        )
    ):
        raise BoundCommandError("fixed tool version is malformed")
    return version


def _identity(
    primary: _SourceBinding,
    *,
    version: str,
    dependencies: Mapping[str, SafeToolIdentity | Mapping[str, object]],
) -> SafeToolIdentity:
    dependency_rows: dict[str, Mapping[str, object]] = {}
    for key, value in dependencies.items():
        dependency_rows[key] = (
            value.to_dict() if isinstance(value, SafeToolIdentity) else dict(value)
        )
    return SafeToolIdentity(
        tool_id=primary.tool_id,
        resolution=str(primary.safe_base["resolution"]),
        resolved_path_sha256=str(primary.safe_base["resolved_path_sha256"]),
        symlink_chain_sha256=str(primary.safe_base["symlink_chain_sha256"]),
        source_sha256=str(primary.safe_base["source_sha256"]),
        source_size=int(primary.safe_base["source_size"]),
        source_mode=int(primary.safe_base["source_mode"]),
        source_owner_uid=int(primary.safe_base["source_owner_uid"]),
        version=version,
        dependencies=MappingProxyType(dependency_rows),
    )


def _accepted_identity_matches(
    expected: Mapping[str, object],
    observed: SafeToolIdentity,
) -> bool:
    allowed_fields = tuple(BOUND_TOOL_POLICY["accepted_identity_fields"])
    if set(expected) != set(allowed_fields):
        return False
    return dict(expected) == observed.to_dict()


def _stage_if_needed(
    directory: Path,
    binding: _SourceBinding,
    *,
    suffix: str = "",
) -> tuple[Path, _StagedSource | None]:
    if binding.immutable_system:
        return binding.resolved, None
    snapshot = _write_snapshot(directory, binding, suffix=suffix)
    return snapshot.path, snapshot


def _runtime_tree(
    spec: ToolSpec,
    primary: _SourceBinding,
) -> tuple[str, _TreeBinding, Path] | None:
    if spec.script_policy == "node_launcher":
        root = primary.resolved.parents[1]
        relative = primary.resolved.relative_to(root)
        return "npm_package", _tree_binding(root, label="npm"), relative
    if spec.use_sys_executable:
        root = primary.resolved.parents[1]
        relative = primary.resolved.relative_to(root)
        return "python_runtime", _tree_binding(root, label="Python"), relative
    return None


def _run_version(
    spec: ToolSpec,
    *,
    cwd: Path,
    environment: Mapping[str, str],
    primary_path: Path,
    launcher_path: Path | None,
) -> str:
    if launcher_path is None:
        executable = primary_path
        argv = spec.version_argv
    else:
        executable = launcher_path
        argv = (spec.version_argv[0], primary_path.as_posix(), *spec.version_argv[1:])
    result = run_bounded_process(
        cwd=cwd,
        argv=argv,
        executable=executable,
        env=environment,
        stdout_limit=1024 * 1024,
        stderr_limit=1024 * 1024,
        timeout_s=10,
    )
    if result.returncode != 0:
        raise BoundCommandError("fixed tool version probe returned an error")
    version = _normalize_version(result)
    if spec.exact_version is not None and version != spec.exact_version:
        raise BoundCommandError("fixed tool version differs from the contract")
    return version


def _inspect_with_staging(
    spec: ToolSpec,
    *,
    cwd: Path,
) -> SafeToolIdentity:
    primary = _source_binding(spec)
    dependencies: dict[str, SafeToolIdentity | Mapping[str, object]] = {}
    launcher: _SourceBinding | None = None
    if spec.launcher_tool_id is not None:
        launcher_spec = tool_spec(spec.launcher_tool_id)
        launcher = _source_binding(launcher_spec)
    runtime_tree = _runtime_tree(spec, primary)
    with tempfile.TemporaryDirectory(prefix="concordia-bound-inspect-") as name:
        directory = Path(name)
        os.chmod(directory, int(BOUND_TOOL_POLICY["private_directory_mode"]))
        staged_tree: _StagedTree | None = None
        if runtime_tree is None:
            primary_path, primary_snapshot = _stage_if_needed(
                directory, primary, suffix=".source"
            )
        else:
            tree_name, tree_binding, relative = runtime_tree
            staged_tree = _stage_tree(directory, tree_binding, name=tree_name)
            primary_path = staged_tree.root / relative
            primary_snapshot = None
            dependencies[tree_name] = tree_binding.safe_identity
        launcher_path: Path | None = None
        launcher_snapshot: _StagedSource | None = None
        environment = _sanitize_environment({}, private_path=directory)
        try:
            if launcher is not None:
                launcher_path, launcher_snapshot = _stage_if_needed(
                    directory, launcher, suffix=".launcher"
                )
                launcher_spec = tool_spec(launcher.tool_id)
                launcher_version = _run_version(
                    launcher_spec,
                    cwd=cwd,
                    environment=environment,
                    primary_path=launcher_path,
                    launcher_path=None,
                )
                dependencies[launcher.tool_id] = _identity(
                    launcher,
                    version=launcher_version,
                    dependencies={},
                )
            version = _run_version(
                spec,
                cwd=cwd,
                environment=environment,
                primary_path=primary_path,
                launcher_path=launcher_path,
            )
        finally:
            if primary_snapshot is not None:
                _revalidate_snapshot(primary_snapshot)
            if launcher_snapshot is not None:
                _revalidate_snapshot(launcher_snapshot)
            if staged_tree is not None:
                _revalidate_staged_tree(staged_tree)
            _revalidate_source(primary)
            if runtime_tree is not None:
                _tree_name, tree_binding, _relative = runtime_tree
                _revalidate_tree(tree_binding, label=spec.tool_id)
            if launcher is not None:
                _revalidate_source(launcher)
    return _identity(primary, version=version, dependencies=dependencies)


def inspect_bound_tool(tool_id: str) -> SafeToolIdentity:
    """Create an enrollment candidate; never self-approve it in the same run."""

    spec = tool_spec(tool_id)
    cwd = _validate_working_directory(Path.cwd().resolve())
    return _inspect_with_staging(spec, cwd=cwd)


def _host_identity_material() -> tuple[str, bytes]:
    if sys.platform == "darwin":
        source = Path(str(BOUND_HOST_ID_POLICY["darwin_source"]))
        argv = tuple(str(part) for part in BOUND_HOST_ID_POLICY["darwin_argv"])
        spec = ToolSpec(
            tool_id="host-identity-ioreg",
            absolute_candidates=(source.as_posix(),),
            use_sys_executable=False,
            manifest_required_when_mutable=False,
            launcher_tool_id=None,
            version_argv=("host-identity-ioreg", "--version"),
            exact_version=None,
            script_policy="binary",
        )
        binding = _source_binding(spec)
        if not binding.immutable_system:
            raise BoundCommandError("host identity source is not immutable")
        try:
            result = run_bounded_process(
                cwd=Path("/"),
                argv=argv,
                executable=binding.resolved,
                env=_sanitize_environment({}, private_path=None),
                stdout_limit=1024 * 1024,
                stderr_limit=64 * 1024,
                timeout_s=5,
            )
        finally:
            _revalidate_source(binding, exact_spec=spec)
        if result.returncode != 0:
            raise BoundCommandError("host identity probe returned an error")
        try:
            document = plistlib.loads(result.stdout)
        except (plistlib.InvalidFileException, ValueError, TypeError) as exc:
            raise BoundCommandError("host identity probe is malformed") from exc
        values = (
            {
                value
                for row in document
                if type(row) is dict
                for key, value in row.items()
                if key == "IOPlatformUUID" and type(value) is str
            }
            if type(document) is list
            else set()
        )
        if len(values) != 1:
            raise BoundCommandError("host identity probe is ambiguous")
        value = next(iter(values))
        if (
            re.fullmatch(
                r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
                r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}",
                value,
            )
            is None
        ):
            raise BoundCommandError("host identity probe value is malformed")
        return "darwin_ioplatformuuid", value.lower().encode("ascii")

    if sys.platform.startswith("linux"):
        for value in BOUND_HOST_ID_POLICY["linux_sources"]:
            path = Path(str(value))
            try:
                exact = _validate_exact_regular_file(
                    path,
                    label="host identity source",
                )
            except BoundCommandError:
                continue
            raw, metadata = _read_tree_file(exact)
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                continue
            try:
                text = raw.decode("ascii", errors="strict")
            except UnicodeDecodeError:
                continue
            if text.endswith("\n"):
                text = text[:-1]
            if re.fullmatch(r"[0-9a-f]{32}", text) is None:
                continue
            verified, verified_metadata = _read_tree_file(exact)
            if raw != verified or _stat_tuple(metadata) != _stat_tuple(
                verified_metadata
            ):
                raise BoundCommandError("host identity source changed")
            return "linux_machine_id", text.encode("ascii")
        raise BoundCommandError("no canonical host identity source is available")

    raise BoundCommandError("host identity is unsupported on this platform")


def derive_bound_host_id() -> str:
    """Derive a stable, path-redacted ID from root-controlled host identity."""

    kind, material = _host_identity_material()
    payload = (
        BOUND_HOST_ID_DOMAIN.encode("ascii") + kind.encode("ascii") + b"\0" + material
    )
    return hashlib.sha256(payload).hexdigest()


def _validate_host_receipt_bindings(
    *,
    source_commit: str,
    runner_sha256: str,
    host_id: str,
) -> None:
    lowercase_hex = set("0123456789abcdef")
    if (
        type(source_commit) is not str
        or len(source_commit) not in {40, 64}
        or set(source_commit) - lowercase_hex
        or type(runner_sha256) is not str
        or len(runner_sha256) != 64
        or set(runner_sha256) - lowercase_hex
        or type(host_id) is not str
        or len(host_id) != 64
        or set(host_id) - lowercase_hex
    ):
        raise BoundCommandError("host-toolchain receipt binding is malformed")


def _validated_host_receipt_tools(
    receipt: Mapping[str, object],
    *,
    repository_root: Path,
    source_commit: str,
) -> Mapping[str, Mapping[str, object]]:
    runner_sha256 = derive_accepted_runner_sha256(
        repository_root,
        source_commit=source_commit,
        receipt=receipt,
    )
    host_id = derive_bound_host_id()
    _validate_host_receipt_bindings(
        source_commit=source_commit,
        runner_sha256=runner_sha256,
        host_id=host_id,
    )
    expected_receipt_fields = {
        "schema_version",
        "source_commit",
        "runner_sha256",
        "host_id",
        "tools",
    }
    if (
        set(receipt) != expected_receipt_fields
        or receipt.get("schema_version") != BOUND_HOST_TOOLCHAIN_RECEIPT_SCHEMA_VERSION
        or receipt.get("source_commit") != source_commit
        or receipt.get("runner_sha256") != runner_sha256
        or receipt.get("host_id") != host_id
    ):
        raise BoundCommandError("accepted host-toolchain receipt binding differs")
    tools = receipt.get("tools")
    if type(tools) is not dict or set(tools) != set(_TOOL_SPECS):
        raise BoundCommandError("accepted host-toolchain receipt tool set differs")
    validated: dict[str, Mapping[str, object]] = {}
    for expected_tool_id, value in tools.items():
        if (
            type(value) is not dict
            or set(value) != set(BOUND_TOOL_POLICY["accepted_identity_fields"])
            or value.get("tool_id") != expected_tool_id
        ):
            raise BoundCommandError("accepted host-toolchain identity schema differs")
        validated[expected_tool_id] = MappingProxyType(value.copy())
    return MappingProxyType(validated)


def _strict_host_receipt(raw: bytes) -> Mapping[str, object]:
    if len(raw) > 16 * 1024 * 1024:
        raise BoundCommandError("accepted host-toolchain receipt is oversized")

    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise BoundCommandError(
                    "accepted host-toolchain receipt has duplicate keys"
                )
            result[key] = value
        return result

    def reject_constant(_value: str) -> object:
        raise BoundCommandError("accepted host-toolchain receipt is non-finite")

    try:
        value = json.loads(
            raw,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise BoundCommandError(
            "accepted host-toolchain receipt is invalid JSON"
        ) from exc
    if type(value) is not dict or _canonical_json(value) + b"\n" != raw:
        raise BoundCommandError("accepted host-toolchain receipt is not canonical")
    return value


def accepted_tool_authority_from_receipt(
    receipt: Mapping[str, object],
    *,
    repository_root: Path,
    source_commit: str,
) -> HostToolchainAuthority:
    """Create a committed authority that will still be revalidated per command."""

    if type(receipt) is not dict:
        raise BoundCommandError("accepted host-toolchain receipt must be a JSON object")
    receipt_raw = _canonical_json(receipt) + b"\n"
    strict_receipt = _strict_host_receipt(receipt_raw)
    _validated_host_receipt_tools(
        strict_receipt,
        repository_root=repository_root,
        source_commit=source_commit,
    )
    return HostToolchainAuthority(
        repository_root=repository_root,
        source_commit=source_commit,
        receipt_raw=receipt_raw,
    )


def _identity_from_authority(
    authority: HostToolchainAuthority,
    *,
    tool_id: str,
) -> Mapping[str, object]:
    if (
        type(authority) is not HostToolchainAuthority
        or not isinstance(authority.repository_root, Path)
        or type(authority.source_commit) is not str
        or type(authority.receipt_raw) is not bytes
    ):
        raise BoundCommandError(
            "accepted host-toolchain authority provenance is invalid"
        )
    receipt = _strict_host_receipt(authority.receipt_raw)
    tools = _validated_host_receipt_tools(
        receipt,
        repository_root=authority.repository_root,
        source_commit=authority.source_commit,
    )
    try:
        return tools[tool_id]
    except KeyError as exc:
        raise BoundCommandError(
            "accepted host-toolchain authority has no tool identity"
        ) from exc


def build_host_toolchain_receipt_candidate(
    *,
    repository_root: Path,
    source_commit: str,
) -> Mapping[str, object]:
    """Build a review candidate; it must be committed before it is authority."""

    runner_sha256 = derive_candidate_runner_sha256(
        repository_root,
        source_commit=source_commit,
    )
    host_id = derive_bound_host_id()
    _validate_host_receipt_bindings(
        source_commit=source_commit,
        runner_sha256=runner_sha256,
        host_id=host_id,
    )
    validated_root = _validate_working_directory(repository_root)
    tools = {
        tool_id: _inspect_with_staging(
            tool_spec(tool_id),
            cwd=validated_root,
        ).to_dict()
        for tool_id in sorted(_TOOL_SPECS)
    }
    return {
        "schema_version": BOUND_HOST_TOOLCHAIN_RECEIPT_SCHEMA_VERSION,
        "source_commit": source_commit,
        "runner_sha256": runner_sha256,
        "host_id": host_id,
        "tools": tools,
    }


def _bind_command_package(
    *,
    asset_root: Path,
    entrypoint_argument: str,
    tool_id: str,
) -> tuple[_TreeBinding, Path, Mapping[str, object]]:
    if tool_id not in {"node", "python"}:
        raise BoundCommandError("command package tool is outside its contract")
    label = f"{tool_id} package"
    root = _validate_working_directory(asset_root)
    entrypoint = _validate_exact_regular_file(
        Path(entrypoint_argument),
        label=f"{label} entrypoint",
    )
    try:
        relative = entrypoint.relative_to(root)
    except ValueError as exc:
        raise BoundCommandError(f"{label} entrypoint escapes its package") from exc
    tree = _tree_binding(root, label=label)
    relative_text = relative.as_posix()
    if relative_text not in tree.files:
        raise BoundCommandError(f"{label} entrypoint is not a bound regular file")
    raw = tree.files[relative_text]
    identity = {
        "kind": f"{tool_id}_package",
        **dict(tree.safe_identity),
        "entrypoint_relative_sha256": hashlib.sha256(
            relative_text.encode("utf-8")
        ).hexdigest(),
        "entrypoint_sha256": hashlib.sha256(raw).hexdigest(),
        "entrypoint_size": len(raw),
    }
    return tree, relative, MappingProxyType(identity)


def _bind_data(path: Path) -> _DataBinding:
    exact = _validate_exact_regular_file(path, label="bound data input")
    raw, metadata = _read_tree_file(exact)
    identity = {
        "kind": "data",
        "path_sha256": _path_hash(exact),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    }
    return _DataBinding(
        path=exact,
        raw=raw,
        stat_identity=_stat_tuple(metadata),
        safe_identity=MappingProxyType(identity),
    )


def _write_data_snapshot(
    directory: Path,
    binding: _DataBinding,
    *,
    index: int,
) -> _StagedData:
    target = directory / f"bound-data-{index}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags, 0o400)
    except OSError as exc:
        raise BoundCommandError("private data snapshot could not be created") from exc
    try:
        offset = 0
        while offset < len(binding.raw):
            written = os.write(descriptor, binding.raw[offset:])
            if written <= 0:
                raise BoundCommandError("private data snapshot write failed")
            offset += written
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    directory_descriptor = os.open(
        directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    staged = _StagedData(
        source=binding,
        path=target,
        stat_identity=_stat_tuple(metadata),
    )
    _revalidate_staged_data(staged)
    return staged


def _revalidate_data(binding: _DataBinding) -> None:
    raw, metadata = _read_tree_file(binding.path)
    if raw != binding.raw or _stat_tuple(metadata) != binding.stat_identity:
        raise BoundCommandError("bound data input changed")


def _revalidate_staged_data(staged: _StagedData) -> None:
    raw, metadata = _read_tree_file(staged.path)
    if (
        raw != staged.source.raw
        or _stat_tuple(metadata) != staged.stat_identity
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o777 != 0o400
    ):
        raise BoundCommandError("private data snapshot differs")


def _validate_private_output_specs(
    specs: Sequence[PrivateOutputSpec],
    *,
    argv: Sequence[str],
    command_script: bool,
    bound_data_argument_indexes: set[int],
) -> tuple[PrivateOutputSpec, ...]:
    validated: list[PrivateOutputSpec] = []
    seen_indexes: set[int] = set()
    seen_names: set[str] = set()
    for spec in specs:
        if type(spec) is not PrivateOutputSpec:
            raise BoundCommandError("private output specification is invalid")
        argument_index = spec.argument_index
        name = spec.name
        size_limit = spec.size_limit
        if (
            type(argument_index) is not int
            or argument_index <= 0
            or argument_index >= len(argv)
            or argument_index in seen_indexes
            or argument_index in bound_data_argument_indexes
            or command_script
            and argument_index == 1
        ):
            raise BoundCommandError("private output argument is outside its contract")
        if (
            type(name) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name) is None
            or name in {".", ".."}
            or name in seen_names
        ):
            raise BoundCommandError("private output name is outside its contract")
        if argv[argument_index] != name:
            raise BoundCommandError(
                "private output must match one exact command argument"
            )
        if (
            type(size_limit) is not int
            or size_limit <= 0
            or size_limit > 1024 * 1024 * 1024
        ):
            raise BoundCommandError("private output size limit is outside its contract")
        seen_indexes.add(argument_index)
        seen_names.add(name)
        validated.append(spec)
    return tuple(validated)


def _open_private_output_directory(directory: Path) -> tuple[Path, int]:
    output_directory = directory / "private-outputs"
    try:
        os.mkdir(output_directory, 0o700)
        descriptor = os.open(
            output_directory,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise BoundCommandError("private output directory could not be created") from exc
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o777 != 0o700
    ):
        os.close(descriptor)
        raise BoundCommandError("private output directory identity differs")
    return output_directory, descriptor


def _stage_private_output(
    output_directory: Path,
    directory_descriptor: int,
    spec: PrivateOutputSpec,
) -> _StagedPrivateOutput:
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(
            spec.name,
            flags,
            0o600,
            dir_fd=directory_descriptor,
        )
    except OSError as exc:
        raise BoundCommandError("private output could not be created") from exc
    try:
        os.set_inheritable(descriptor, False)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        os.fsync(directory_descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o777 != 0o600
            or metadata.st_nlink != 1
        ):
            raise BoundCommandError("private output identity differs")
        return _StagedPrivateOutput(
            spec=spec,
            path=output_directory / spec.name,
            descriptor=descriptor,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
    except BaseException:
        os.close(descriptor)
        raise


def _revalidate_private_output(
    staged: _StagedPrivateOutput,
    *,
    directory_descriptor: int,
    include_bytes: bool,
) -> PrivateOutput | None:
    try:
        descriptor_metadata = os.fstat(staged.descriptor)
        path_metadata = os.stat(
            staged.spec.name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        path_descriptor = os.open(
            staged.spec.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
    except OSError as exc:
        raise BoundCommandError("private output path was substituted") from exc
    try:
        opened_metadata = os.fstat(path_descriptor)
        identities = (
            descriptor_metadata,
            path_metadata,
            opened_metadata,
        )
        if any(
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_dev != staged.device
            or metadata.st_ino != staged.inode
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o777 != 0o600
            or metadata.st_nlink != 1
            for metadata in identities
        ):
            raise BoundCommandError("private output path changed")
        if descriptor_metadata.st_size > staged.spec.size_limit:
            raise BoundCommandError("private output is oversized")
        if not include_bytes:
            return None
        os.fsync(staged.descriptor)
        os.lseek(staged.descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = descriptor_metadata.st_size
        while remaining:
            chunk = os.read(staged.descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise BoundCommandError("private output read was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != descriptor_metadata.st_size:
            raise BoundCommandError("private output read was truncated")
        return PrivateOutput(
            name=staged.spec.name,
            raw=raw,
            sha256=hashlib.sha256(raw).hexdigest(),
            size=len(raw),
        )
    finally:
        os.close(path_descriptor)


def run_bound_command(
    *,
    cwd: Path,
    tool_id: str,
    argv: Sequence[str],
    env: Mapping[str, str],
    stdout_limit: int,
    stderr_limit: int,
    timeout_s: int,
    check: bool = True,
    accepted_authority: HostToolchainAuthority | None = None,
    command_asset_root: Path | None = None,
    bound_data_inputs: Sequence[Path] = (),
    private_output_specs: Sequence[PrivateOutputSpec] = (),
    inherited_private_descriptor: int | None = None,
) -> BoundCommandResult:
    """Run one exact logical tool without shell or caller-controlled resolution."""

    spec = tool_spec(tool_id)
    if (
        not argv
        or argv[0] != tool_id
        or any(type(part) is not str or "\0" in part for part in argv)
        or timeout_s < int(BOUND_TOOL_POLICY["minimum_timeout_seconds"])
        or timeout_s > int(BOUND_TOOL_POLICY["maximum_timeout_seconds"])
    ):
        raise BoundCommandError("bound command invocation is outside its contract")
    validated_cwd = _validate_working_directory(cwd)
    command_script = (
        tool_id in {"node", "python"} and len(argv) > 1 and not argv[1].startswith("-")
    )
    if command_script != (command_asset_root is not None):
        raise BoundCommandError("command package binding is outside its contract")
    command_package: tuple[_TreeBinding, Path, Mapping[str, object]] | None = None
    if command_script:
        assert command_asset_root is not None
        command_package = _bind_command_package(
            asset_root=command_asset_root,
            entrypoint_argument=argv[1],
            tool_id=tool_id,
        )

    data_bindings: list[tuple[int, _DataBinding]] = []
    seen_data_paths: set[Path] = set()
    for requested_path in bound_data_inputs:
        if not isinstance(requested_path, Path):
            raise BoundCommandError("bound data input is outside its contract")
        binding = _bind_data(requested_path)
        if binding.path in seen_data_paths:
            raise BoundCommandError("bound data input is duplicated")
        matches = [
            index
            for index, argument in enumerate(argv)
            if argument == binding.path.as_posix()
        ]
        if len(matches) != 1 or matches[0] == 0:
            raise BoundCommandError(
                "bound data input must match one exact command argument"
            )
        if command_script and matches[0] == 1:
            raise BoundCommandError("command entrypoint cannot be a bound data input")
        seen_data_paths.add(binding.path)
        data_bindings.append((matches[0], binding))
    validated_private_output_specs = _validate_private_output_specs(
        private_output_specs,
        argv=argv,
        command_script=command_script,
        bound_data_argument_indexes={
            argument_index for argument_index, _binding in data_bindings
        },
    )

    primary = _source_binding(spec)
    launcher: _SourceBinding | None = None
    if spec.launcher_tool_id is not None:
        launcher = _source_binding(tool_spec(spec.launcher_tool_id))
    runtime_tree = _runtime_tree(spec, primary)
    mutable = not primary.immutable_system or (
        launcher is not None and not launcher.immutable_system
    )
    if runtime_tree is not None and not runtime_tree[1].immutable_system:
        mutable = True
    accepted_tool_identity: Mapping[str, object] | None = None
    if accepted_authority is not None:
        accepted_tool_identity = _identity_from_authority(
            accepted_authority,
            tool_id=tool_id,
        )
    if mutable and spec.manifest_required_when_mutable and accepted_authority is None:
        raise BoundCommandError("accepted host-toolchain authority is required")

    snapshots: list[_StagedSource] = []
    staged_trees: list[_StagedTree] = []
    staged_data: list[_StagedData] = []
    staged_private_outputs: list[_StagedPrivateOutput] = []
    private_output_directory_descriptor: int | None = None
    command_assets: list[Mapping[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="concordia-bound-command-") as name:
        directory = Path(name)
        os.chmod(directory, int(BOUND_TOOL_POLICY["private_directory_mode"]))
        tree_dependencies: dict[str, Mapping[str, object]] = {}
        if runtime_tree is None:
            primary_path, primary_snapshot = _stage_if_needed(
                directory, primary, suffix=".source"
            )
        else:
            tree_name, tree_binding, relative = runtime_tree
            runtime_snapshot = _stage_tree(directory, tree_binding, name=tree_name)
            staged_trees.append(runtime_snapshot)
            primary_path = runtime_snapshot.root / relative
            primary_snapshot = None
            tree_dependencies[tree_name] = tree_binding.safe_identity
        if primary_snapshot is not None:
            snapshots.append(primary_snapshot)
        launcher_path: Path | None = None
        if launcher is not None:
            launcher_path, launcher_snapshot = _stage_if_needed(
                directory, launcher, suffix=".launcher"
            )
            if launcher_snapshot is not None:
                snapshots.append(launcher_snapshot)
        environment = _sanitize_environment(env, private_path=directory)
        execution_parts = list(argv)
        if command_package is not None:
            package_tree, entrypoint_relative, package_identity = command_package
            package_snapshot = _stage_tree(
                directory,
                package_tree,
                name=f"{tool_id}-command-package",
            )
            staged_trees.append(package_snapshot)
            execution_parts[1] = (
                package_snapshot.root / entrypoint_relative
            ).as_posix()
            command_assets.append(package_identity)
        for index, (argument_index, binding) in enumerate(data_bindings):
            snapshot = _write_data_snapshot(directory, binding, index=index)
            staged_data.append(snapshot)
            execution_parts[argument_index] = snapshot.path.as_posix()
            command_assets.append(binding.safe_identity)
        if validated_private_output_specs:
            (
                private_output_directory,
                private_output_directory_descriptor,
            ) = _open_private_output_directory(directory)
            try:
                for output_spec in validated_private_output_specs:
                    staged_output = _stage_private_output(
                        private_output_directory,
                        private_output_directory_descriptor,
                        output_spec,
                    )
                    staged_private_outputs.append(staged_output)
                    execution_parts[output_spec.argument_index] = (
                        staged_output.path.as_posix()
                    )
            except BaseException:
                for staged_output in staged_private_outputs:
                    os.close(staged_output.descriptor)
                os.close(private_output_directory_descriptor)
                private_output_directory_descriptor = None
                raise

        execution_argv = tuple(execution_parts)
        executable = primary_path
        if launcher_path is not None:
            executable = launcher_path
            execution_argv = (
                execution_parts[0],
                primary_path.as_posix(),
                *execution_parts[1:],
            )

        try:
            dependencies: dict[str, SafeToolIdentity | Mapping[str, object]] = dict(
                tree_dependencies
            )
            if launcher is not None:
                launcher_spec = tool_spec(launcher.tool_id)
                launcher_version = _run_version(
                    launcher_spec,
                    cwd=validated_cwd,
                    environment=environment,
                    primary_path=launcher_path,
                    launcher_path=None,
                )
                dependencies[launcher.tool_id] = _identity(
                    launcher,
                    version=launcher_version,
                    dependencies={},
                )
            version = _run_version(
                spec,
                cwd=validated_cwd,
                environment=environment,
                primary_path=primary_path,
                launcher_path=launcher_path,
            )
            identity = _identity(
                primary,
                version=version,
                dependencies=dependencies,
            )
            if accepted_tool_identity is not None and not _accepted_identity_matches(
                accepted_tool_identity, identity
            ):
                raise BoundCommandError("accepted host tool identity differs")
            process_result = run_bounded_process(
                cwd=validated_cwd,
                argv=execution_argv,
                executable=executable,
                env=environment,
                stdout_limit=stdout_limit,
                stderr_limit=stderr_limit,
                timeout_s=timeout_s,
                inherited_private_descriptor=inherited_private_descriptor,
            )
            if check and process_result.returncode != 0:
                raise BoundCommandError("bound command returned a nonzero status")
            if private_output_directory_descriptor is None:
                private_output_records: tuple[PrivateOutput, ...] = ()
            else:
                private_output_records = tuple(
                    output
                    for staged_output in staged_private_outputs
                    if (
                        output := _revalidate_private_output(
                            staged_output,
                            directory_descriptor=private_output_directory_descriptor,
                            include_bytes=True,
                        )
                    )
                    is not None
                )
            return BoundCommandResult(
                returncode=process_result.returncode,
                stdout=process_result.stdout,
                stderr=process_result.stderr,
                tool_identity=MappingProxyType(identity.to_dict()),
                command_assets=tuple(command_assets),
                private_outputs=private_output_records,
            )
        finally:
            private_output_error: BaseException | None = None
            if private_output_directory_descriptor is not None:
                try:
                    for staged_output in staged_private_outputs:
                        _revalidate_private_output(
                            staged_output,
                            directory_descriptor=private_output_directory_descriptor,
                            include_bytes=False,
                        )
                except BaseException as exc:
                    private_output_error = exc
                finally:
                    for staged_output in staged_private_outputs:
                        os.close(staged_output.descriptor)
                    os.close(private_output_directory_descriptor)
            for snapshot in snapshots:
                _revalidate_snapshot(snapshot)
            for tree in staged_trees:
                _revalidate_staged_tree(tree)
            for snapshot in staged_data:
                _revalidate_staged_data(snapshot)
            _revalidate_source(primary)
            if runtime_tree is not None:
                _tree_name, tree_binding, _relative = runtime_tree
                _revalidate_tree(tree_binding, label=tool_id)
            if command_package is not None:
                package_tree, _entrypoint_relative, _package_identity = command_package
                _revalidate_tree(package_tree, label=f"{tool_id} package")
            for _argument_index, binding in data_bindings:
                _revalidate_data(binding)
            if launcher is not None:
                _revalidate_source(launcher)
            if private_output_error is not None:
                raise private_output_error


def _run_bound_git(
    repository_root: Path,
    arguments: Sequence[str],
    *,
    check: bool = True,
    stdout_limit: int = 4 * 1024 * 1024,
) -> BoundCommandResult:
    return run_bound_command(
        cwd=repository_root,
        tool_id="git",
        argv=(
            "git",
            "--no-replace-objects",
            *BOUND_GIT_CONFIG_OVERRIDES,
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
        stdout_limit=stdout_limit,
        stderr_limit=1024 * 1024,
        timeout_s=30,
        check=check,
    )


def _one_git_line(raw: bytes, *, label: str) -> str:
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise BoundCommandError(f"{label} is not canonical ASCII") from exc
    if not text.endswith("\n") or "\n" in text[:-1] or "\r" in text:
        raise BoundCommandError(f"{label} is not one canonical line")
    return text[:-1]


def _require_clean_repository(repository_root: Path) -> None:
    status = _run_bound_git(
        repository_root,
        ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
    )
    if status.stdout:
        raise BoundCommandError("host-toolchain authority requires a clean repository")


def _head_commit(repository_root: Path) -> str:
    result = _run_bound_git(
        repository_root,
        ("rev-parse", "--verify", "HEAD^{commit}"),
    )
    value = _one_git_line(result.stdout, label="repository HEAD")
    lowercase_hex = set("0123456789abcdef")
    if len(value) not in {40, 64} or set(value) - lowercase_hex:
        raise BoundCommandError("repository HEAD is malformed")
    return value


def _verify_repository_root(repository_root: Path) -> Path:
    root = _validate_working_directory(repository_root)
    result = _run_bound_git(root, ("rev-parse", "--show-toplevel"))
    try:
        reported = Path(_one_git_line(result.stdout, label="repository root")).resolve(
            strict=True
        )
    except OSError as exc:
        raise BoundCommandError("repository root is unavailable") from exc
    if reported != root:
        raise BoundCommandError("bound runner repository root differs")
    return root


def _read_exact_repository_file(
    repository_root: Path,
    relative_path: str,
    *,
    label: str,
) -> tuple[bytes, tuple[int, ...]]:
    path = _validate_exact_regular_file(
        repository_root.joinpath(*relative_path.split("/")),
        label=label,
    )
    raw, metadata = _read_tree_file(path)
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o022:
        raise BoundCommandError(f"{label} ownership or mode is unsafe")
    return raw, _stat_tuple(metadata)


def _git_blob(
    repository_root: Path,
    revision: str,
    relative_path: str,
) -> bytes:
    result = _run_bound_git(
        repository_root,
        ("show", f"{revision}:{relative_path}"),
        stdout_limit=min(
            int(BOUND_TOOL_POLICY["maximum_source_bytes"]),
            int(BOUND_TOOL_POLICY["maximum_stream_bytes"]),
        ),
    )
    return result.stdout


def _runner_digest_at_source_commit(
    repository_root: Path,
    source_commit: str,
) -> str:
    raw, state = _read_exact_repository_file(
        repository_root,
        BOUND_HOST_TOOLCHAIN_RUNNER_PATH,
        label="bound release runner",
    )
    committed = _git_blob(
        repository_root,
        source_commit,
        BOUND_HOST_TOOLCHAIN_RUNNER_PATH,
    )
    verified, verified_state = _read_exact_repository_file(
        repository_root,
        BOUND_HOST_TOOLCHAIN_RUNNER_PATH,
        label="bound release runner",
    )
    if raw != committed or verified != raw or verified_state != state:
        raise BoundCommandError("bound release runner differs from source commit")
    return hashlib.sha256(raw).hexdigest()


def derive_candidate_runner_sha256(
    repository_root: Path,
    *,
    source_commit: str,
) -> str:
    """Bind a clean source commit A before its authority receipt is created."""

    _validate_host_receipt_bindings(
        source_commit=source_commit,
        runner_sha256="0" * 64,
        host_id="0" * 64,
    )
    root = _verify_repository_root(repository_root)
    _require_clean_repository(root)
    if _head_commit(root) != source_commit:
        raise BoundCommandError("candidate source commit is not exact HEAD")
    receipt_path = root.joinpath(*BOUND_HOST_TOOLCHAIN_RECEIPT_PATH.split("/"))
    if os.path.lexists(receipt_path):
        raise BoundCommandError("candidate authority receipt already exists")
    tracked = _run_bound_git(
        root,
        ("cat-file", "-e", f"{source_commit}:{BOUND_HOST_TOOLCHAIN_RECEIPT_PATH}"),
        check=False,
    )
    if tracked.returncode == 0:
        raise BoundCommandError("candidate authority receipt is already tracked")
    return _runner_digest_at_source_commit(root, source_commit)


def _authority_descendant_path_allowed(path: str) -> bool:
    return path in BOUND_HOST_AUTHORITY_DESCENDANT_PATHS or any(
        path.startswith(prefix) for prefix in BOUND_HOST_AUTHORITY_DESCENDANT_PREFIXES
    )


def _nul_terminated_git_paths(raw: bytes, *, label: str) -> tuple[str, ...]:
    if raw and not raw.endswith(b"\0"):
        raise BoundCommandError(f"{label} paths are not canonical")
    try:
        paths = tuple(
            part.decode("utf-8", errors="strict") for part in raw.split(b"\0") if part
        )
    except UnicodeDecodeError as exc:
        raise BoundCommandError(f"{label} path is malformed") from exc
    if len(paths) != len(set(paths)) or any(
        path in {"", ".", ".."}
        or path.startswith("/")
        or "\0" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
        for path in paths
    ):
        raise BoundCommandError(f"{label} paths are duplicated or unsafe")
    return paths


def _strict_release_descendant_history(
    repository_root: Path,
    *,
    authority_commit: str,
    head: str,
) -> None:
    raw_commits = _run_bound_git(
        repository_root,
        ("rev-list", "--reverse", f"{authority_commit}..{head}"),
    ).stdout
    try:
        text = raw_commits.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise BoundCommandError(
            "host-toolchain descendant history is malformed"
        ) from exc
    if text and not text.endswith("\n") or "\r" in text:
        raise BoundCommandError("host-toolchain descendant history is not canonical")
    commits = tuple(line for line in text.splitlines() if line)
    lowercase_hex = set("0123456789abcdef")
    if any(
        len(commit) not in {40, 64} or set(commit) - lowercase_hex for commit in commits
    ):
        raise BoundCommandError("host-toolchain descendant commit is malformed")

    expected_parent = authority_commit
    for commit in commits:
        lineage = _one_git_line(
            _run_bound_git(
                repository_root,
                ("rev-list", "--parents", "-n", "1", commit),
            ).stdout,
            label="host-toolchain descendant lineage",
        ).split(" ")
        if lineage != [commit, expected_parent]:
            raise BoundCommandError(
                "host-toolchain descendant history is not strictly linear"
            )
        changed_paths = _nul_terminated_git_paths(
            _run_bound_git(
                repository_root,
                (
                    "diff-tree",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-commit-id",
                    "--name-only",
                    "-z",
                    "-r",
                    commit,
                ),
            ).stdout,
            label="host-toolchain descendant",
        )
        if any(not _authority_descendant_path_allowed(path) for path in changed_paths):
            raise BoundCommandError("host-toolchain descendant changed source code")
        expected_parent = commit
    if expected_parent != head:
        raise BoundCommandError("host-toolchain descendant history differs from HEAD")


def derive_accepted_runner_sha256(
    repository_root: Path,
    *,
    source_commit: str,
    receipt: Mapping[str, object],
) -> str:
    """Validate the A->B authority commit and closed release-only descendants."""

    _validate_host_receipt_bindings(
        source_commit=source_commit,
        runner_sha256="0" * 64,
        host_id="0" * 64,
    )
    root = _verify_repository_root(repository_root)
    _require_clean_repository(root)
    head = _head_commit(root)
    latest = _run_bound_git(
        root,
        (
            "log",
            "-1",
            "--format=%H",
            "--",
            BOUND_HOST_TOOLCHAIN_RECEIPT_PATH,
        ),
    )
    authority_commit = _one_git_line(
        latest.stdout,
        label="host-toolchain authority commit",
    )
    parents = _one_git_line(
        _run_bound_git(
            root,
            ("rev-list", "--parents", "-n", "1", authority_commit),
        ).stdout,
        label="host-toolchain authority lineage",
    ).split(" ")
    if (
        len(parents) != 2
        or parents[0] != authority_commit
        or parents[1] != source_commit
    ):
        raise BoundCommandError("host-toolchain authority lineage differs")
    authority_diff = _run_bound_git(
        root,
        (
            "diff-tree",
            "--no-ext-diff",
            "--no-textconv",
            "--no-commit-id",
            "--name-status",
            "-r",
            authority_commit,
        ),
    )
    expected_diff = f"A\t{BOUND_HOST_TOOLCHAIN_RECEIPT_PATH}\n".encode("ascii")
    if authority_diff.stdout != expected_diff:
        raise BoundCommandError("host-toolchain authority commit is not receipt-only")
    ancestor = _run_bound_git(
        root,
        ("merge-base", "--is-ancestor", authority_commit, head),
        check=False,
    )
    if ancestor.returncode != 0:
        raise BoundCommandError("host-toolchain authority is not an ancestor")
    _strict_release_descendant_history(
        root,
        authority_commit=authority_commit,
        head=head,
    )

    expected_receipt = _canonical_json(receipt) + b"\n"
    working_receipt, receipt_state = _read_exact_repository_file(
        root,
        BOUND_HOST_TOOLCHAIN_RECEIPT_PATH,
        label="host-toolchain authority receipt",
    )
    committed_receipt = _git_blob(
        root,
        authority_commit,
        BOUND_HOST_TOOLCHAIN_RECEIPT_PATH,
    )
    verified_receipt, verified_receipt_state = _read_exact_repository_file(
        root,
        BOUND_HOST_TOOLCHAIN_RECEIPT_PATH,
        label="host-toolchain authority receipt",
    )
    if (
        working_receipt != expected_receipt
        or committed_receipt != expected_receipt
        or verified_receipt != working_receipt
        or verified_receipt_state != receipt_state
    ):
        raise BoundCommandError("host-toolchain authority receipt bytes differ")
    return _runner_digest_at_source_commit(root, source_commit)


__all__ = [
    "BoundCommandError",
    "BoundCommandResult",
    "HostToolchainAuthority",
    "SafeToolIdentity",
    "ToolSpec",
    "accepted_tool_authority_from_receipt",
    "build_host_toolchain_receipt_candidate",
    "derive_accepted_runner_sha256",
    "derive_bound_host_id",
    "derive_candidate_runner_sha256",
    "inspect_bound_tool",
    "run_bound_command",
    "run_bounded_process",
    "tool_spec",
]
