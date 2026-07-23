"""Race-resistant local secret-file reads for release operators.

The caller supplies an absolute path, but this module never resolves it with a
string-level realpath.  Every parent directory is opened relative to the
previous directory descriptor with ``O_NOFOLLOW`` and the final regular file
is then read through that pinned directory.  Errors deliberately disclose
neither path nor contents.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path


class SecureSecretFileError(RuntimeError):
    """A secret file failed custody or stability validation."""


def _stable_identity(metadata: object) -> tuple[int, ...]:
    return (
        int(getattr(metadata, "st_dev")),
        int(getattr(metadata, "st_ino")),
        int(getattr(metadata, "st_mode")),
        int(getattr(metadata, "st_uid")),
        int(getattr(metadata, "st_size")),
        int(getattr(metadata, "st_mtime_ns")),
        int(getattr(metadata, "st_ctime_ns")),
    )


def read_secure_secret_file(path: Path, *, max_bytes: int) -> bytes:
    """Return bytes from one owner-private, stable, non-symlink regular file."""

    directory_fd: int | None = None
    descriptor: int | None = None
    try:
        candidate = Path(path)
        if (
            not candidate.is_absolute()
            or type(max_bytes) is not int
            or not 1 <= max_bytes <= 32 * 1024 * 1024
            or candidate.name in {"", ".", ".."}
            or any(part in {"", ".", ".."} for part in candidate.parts[1:])
        ):
            raise OSError("unsafe secret path")

        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        directory_fd = os.open(candidate.anchor, directory_flags)
        for component in candidate.parts[1:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd

        file_flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(candidate.name, file_flags, dir_fd=directory_fd)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
            or not 0 < before.st_size <= max_bytes
        ):
            raise OSError("unsafe secret file")

        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(raw) != before.st_size
            or len(raw) > max_bytes
            or _stable_identity(before) != _stable_identity(after)
        ):
            raise OSError("secret file changed during read")
        return raw
    except (OSError, TypeError, ValueError, OverflowError):
        raise SecureSecretFileError("secret file could not be loaded safely") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if directory_fd is not None:
            try:
                os.close(directory_fd)
            except OSError:
                pass


__all__ = ["SecureSecretFileError", "read_secure_secret_file"]
