#!/usr/bin/env python3
"""Build one exact NativeTransferV1 input from verified offline artifacts.

The command performs no network I/O, signing, or submission.  It reads each
source once through a no-follow descriptor and publishes two private files as
one create-once directory.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import secrets
import stat
import sys
from collections.abc import Sequence
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared.native_transfer_input_v3 import (
    NativeTransferInputError,
    build_native_transfer_input,
    render_json_bytes,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
LIVE_ARTIFACT_ROOT = (REPOSITORY_ROOT / "artifacts" / "live").resolve()
MAX_SOURCE_BYTES = 32 * 1024 * 1024

_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_READ_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_WRITE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


class NativeTransferInputCliError(RuntimeError):
    """The offline input build could not be completed safely."""


def _validate_absolute_path(path: Path, label: str) -> Path:
    candidate = Path(path)
    if (
        not candidate.is_absolute()
        or candidate.name in {"", ".", ".."}
        or any(component in {"", ".", ".."} for component in candidate.parts[1:])
    ):
        raise NativeTransferInputCliError(f"{label} must be an absolute safe path")
    return candidate


def _open_parent(path: Path, label: str) -> tuple[int, str]:
    candidate = _validate_absolute_path(path, label)
    descriptor = os.open(candidate.anchor, _DIRECTORY_FLAGS)
    try:
        for component in candidate.parts[1:-1]:
            next_descriptor = os.open(
                component,
                _DIRECTORY_FLAGS,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, candidate.name
    except BaseException:
        os.close(descriptor)
        raise


def _stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_source_once(path: Path, label: str) -> bytes:
    """Read one bounded regular file without following path components."""

    parent_fd: int | None = None
    file_fd: int | None = None
    try:
        parent_fd, name = _open_parent(path, label)
        file_fd = os.open(name, _FILE_READ_FLAGS, dir_fd=parent_fd)
        before = os.fstat(file_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink < 1
            or not 0 < before.st_size <= MAX_SOURCE_BYTES
        ):
            raise NativeTransferInputCliError(
                f"{label} must be one bounded regular file"
            )
        remaining = before.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(file_fd, min(remaining, 1024 * 1024))
            if not chunk:
                raise NativeTransferInputCliError(f"{label} changed while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(file_fd, 1):
            raise NativeTransferInputCliError(f"{label} changed while reading")
        after = os.fstat(file_fd)
        if _stable_identity(before) != _stable_identity(after):
            raise NativeTransferInputCliError(f"{label} changed while reading")
        return b"".join(chunks)
    except NativeTransferInputCliError:
        raise
    except OSError as exc:
        raise NativeTransferInputCliError(
            f"{label} could not be opened as a stable no-follow file"
        ) from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if parent_fd is not None:
            os.close(parent_fd)


def _write_private_file(directory_fd: int, name: str, payload: bytes) -> None:
    if type(payload) is not bytes or not payload:
        raise NativeTransferInputCliError("derived output bytes are unavailable")
    descriptor = os.open(name, _FILE_WRITE_FLAGS, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(descriptor, 0o600)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("derived output write stalled")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_directory_noreplace(
    parent_fd: int,
    temporary_name: str,
    target_name: str,
) -> None:
    """Atomically publish a directory, refusing any pre-existing target."""

    libc = ctypes.CDLL(None, use_errno=True)
    source = os.fsencode(temporary_name)
    target = os.fsencode(target_name)
    if sys.platform == "darwin":
        operation = getattr(libc, "renameatx_np", None)
        if operation is None:
            raise NativeTransferInputCliError(
                "atomic create-once directory rename is unavailable"
            )
        operation.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        operation.restype = ctypes.c_int
        result = operation(parent_fd, source, parent_fd, target, 0x00000004)
    elif sys.platform.startswith("linux"):
        operation = getattr(libc, "renameat2", None)
        if operation is None:
            raise NativeTransferInputCliError(
                "atomic create-once directory rename is unavailable"
            )
        operation.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        operation.restype = ctypes.c_int
        result = operation(parent_fd, source, parent_fd, target, 0x00000001)
    else:
        raise NativeTransferInputCliError(
            "atomic create-once directory rename is unsupported"
        )
    if result != 0:
        code = ctypes.get_errno()
        if code in {errno.EEXIST, errno.ENOTEMPTY}:
            raise NativeTransferInputCliError(
                "refusing to overwrite existing output directory"
            )
        raise OSError(code, os.strerror(code))


def _is_live_artifact_path(output: Path) -> bool:
    parent = output.parent.resolve(strict=True)
    canonical = parent / output.name
    return canonical == LIVE_ARTIFACT_ROOT or LIVE_ARTIFACT_ROOT in canonical.parents


def _remove_temporary_directory(
    parent_fd: int,
    temporary_name: str | None,
) -> None:
    if temporary_name is None:
        return
    directory_fd: int | None = None
    try:
        directory_fd = os.open(
            temporary_name,
            _DIRECTORY_FLAGS,
            dir_fd=parent_fd,
        )
        for name in ("typed-input.json", "derivation-manifest.json"):
            try:
                os.unlink(name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)
        directory_fd = None
        os.rmdir(temporary_name, dir_fd=parent_fd)
    except FileNotFoundError:
        pass
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def _publish_output_directory(
    output: Path,
    *,
    typed_input_bytes: bytes,
    derivation_manifest_bytes: bytes,
) -> None:
    candidate = _validate_absolute_path(output, "output directory")
    parent_fd: int | None = None
    temporary_fd: int | None = None
    temporary_name: str | None = None
    try:
        if _is_live_artifact_path(candidate):
            raise NativeTransferInputCliError(
                "builder output may not be written under artifacts/live"
            )
        parent_fd, target_name = _open_parent(candidate, "output directory")
        try:
            os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise NativeTransferInputCliError(
                "refusing to overwrite existing output directory"
            )
        temporary_name = f".{target_name}.{secrets.token_hex(16)}.tmp"
        os.mkdir(temporary_name, 0o700, dir_fd=parent_fd)
        temporary_fd = os.open(
            temporary_name,
            _DIRECTORY_FLAGS,
            dir_fd=parent_fd,
        )
        os.fchmod(temporary_fd, 0o700)
        _write_private_file(temporary_fd, "typed-input.json", typed_input_bytes)
        _write_private_file(
            temporary_fd,
            "derivation-manifest.json",
            derivation_manifest_bytes,
        )
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None
        _rename_directory_noreplace(
            parent_fd,
            temporary_name,
            target_name,
        )
        temporary_name = None
        os.fsync(parent_fd)
    except NativeTransferInputCliError:
        raise
    except OSError as exc:
        raise NativeTransferInputCliError(
            "derived output directory could not be published atomically"
        ) from exc
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        if parent_fd is not None:
            _remove_temporary_directory(parent_fd, temporary_name)
            os.close(parent_fd)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build an exact NativeTransferV1 typed input from verified offline "
            "release artifacts; performs no network, signing, or submission."
        )
    )
    parser.add_argument("--historical-receipt", required=True, type=Path)
    parser.add_argument("--historical-inventory", required=True, type=Path)
    parser.add_argument("--canonical-receipt", required=True, type=Path)
    parser.add_argument("--deployment-manifest", required=True, type=Path)
    parser.add_argument("--treasury-snapshot", required=True, type=Path)
    parser.add_argument("--intent", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        output = _validate_absolute_path(arguments.out_dir, "output directory")
        if _is_live_artifact_path(output):
            raise NativeTransferInputCliError(
                "builder output may not be written under artifacts/live"
            )
        historical_receipt = _read_source_once(
            arguments.historical_receipt,
            "historical receipt",
        )
        historical_inventory = _read_source_once(
            arguments.historical_inventory,
            "historical inventory",
        )
        canonical_receipt = _read_source_once(
            arguments.canonical_receipt,
            "canonical receipt",
        )
        deployment_manifest = _read_source_once(
            arguments.deployment_manifest,
            "deployment manifest",
        )
        treasury_snapshot = _read_source_once(
            arguments.treasury_snapshot,
            "treasury snapshot",
        )
        intent = _read_source_once(arguments.intent, "native transfer intent")
        built = build_native_transfer_input(
            historical_receipt_bytes=historical_receipt,
            historical_inventory_bytes=historical_inventory,
            canonical_receipt_bytes=canonical_receipt,
            deployment_manifest_bytes=deployment_manifest,
            treasury_snapshot_bytes=treasury_snapshot,
            intent_bytes=intent,
        )
        _publish_output_directory(
            output,
            typed_input_bytes=render_json_bytes(built.typed_input),
            derivation_manifest_bytes=render_json_bytes(built.derivation_manifest),
        )
    except (NativeTransferInputCliError, NativeTransferInputError) as exc:
        parser.error(str(exc))
    except OSError:
        parser.error("offline artifact path could not be accessed safely")
    summary = {
        "derivation_manifest": str(output / "derivation-manifest.json"),
        "output_directory": str(output),
        "typed_input": str(output / "typed-input.json"),
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
