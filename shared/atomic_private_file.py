"""Race-resistant create-once writes for private release artifacts."""

from __future__ import annotations

import errno
import hmac
import os
import secrets
import stat
from pathlib import Path


class AtomicPrivateFileError(RuntimeError):
    """A private artifact could not be created without replacement or traversal."""


def _open_parent(path: Path) -> tuple[int, str]:
    candidate = Path(path)
    if (
        not candidate.is_absolute()
        or candidate.name in {"", ".", ".."}
        or any(part in {"", ".", ".."} for part in candidate.parts[1:])
    ):
        raise OSError("unsafe artifact path")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(candidate.anchor, flags)
    try:
        for component in candidate.parts[1:-1]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, candidate.name
    except BaseException:
        os.close(descriptor)
        raise


def _existing_private_file_matches(
    directory_fd: int,
    target_name: str,
    payload: bytes,
) -> bool:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(target_name, flags, dir_fd=directory_fd)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or before.st_size != len(payload)
        ):
            return False
        chunks: list[bytes] = []
        remaining = len(payload)
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                return False
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            return False
        after = os.fstat(descriptor)
        stable = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) == (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        return stable and hmac.compare_digest(b"".join(chunks), payload)
    finally:
        os.close(descriptor)


def write_private_file_once(
    path: Path,
    payload: bytes,
    *,
    allow_identical: bool = False,
) -> None:
    """Durably create an owner-private file without following or replacing names."""

    directory_fd: int | None = None
    file_fd: int | None = None
    temporary_name: str | None = None
    try:
        if type(payload) is not bytes or not payload or len(payload) > 64 * 1024 * 1024:
            raise OSError("invalid private artifact payload")
        directory_fd, target_name = _open_parent(Path(path))
        temporary_name = f".{target_name}.{secrets.token_hex(16)}.tmp"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        file_fd = os.open(temporary_name, flags, 0o600, dir_fd=directory_fd)
        os.fchmod(file_fd, 0o600)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(file_fd, remaining)
            if written <= 0:
                raise OSError("private artifact write stalled")
            remaining = remaining[written:]
        os.fsync(file_fd)
        os.close(file_fd)
        file_fd = None
        try:
            os.link(
                temporary_name,
                target_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                if allow_identical:
                    try:
                        if _existing_private_file_matches(
                            directory_fd,
                            target_name,
                            payload,
                        ):
                            return
                    except OSError:
                        pass
                raise AtomicPrivateFileError(
                    "private artifact target already exists with different bytes "
                    "or unsafe metadata"
                ) from None
            raise
        os.fsync(directory_fd)
    except AtomicPrivateFileError:
        raise
    except (OSError, TypeError, ValueError, OverflowError):
        raise AtomicPrivateFileError(
            "private artifact could not be created safely"
        ) from None
    finally:
        if file_fd is not None:
            try:
                os.close(file_fd)
            except OSError:
                pass
        if directory_fd is not None:
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name, dir_fd=directory_fd)
                except OSError:
                    pass
            try:
                os.close(directory_fd)
            except OSError:
                pass


__all__ = ["AtomicPrivateFileError", "write_private_file_once"]
