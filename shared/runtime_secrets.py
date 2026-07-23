"""Runtime secret helpers for env-var and Docker-secret deployments."""

from __future__ import annotations

import os
import stat
from pathlib import Path


_MAX_RUNTIME_SECRET_BYTES = 64 * 1024


def _read_file_secret(path: str) -> str:
    """Read one bounded non-symlink secret without falling back on failure."""

    directory_fd: int | None = None
    descriptor: int | None = None
    try:
        candidate = Path(path)
        if (
            not candidate.is_absolute()
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
        descriptor = os.open(
            candidate.name,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_mode & 0o022
            or not 0 < before.st_size <= _MAX_RUNTIME_SECRET_BYTES
        ):
            raise OSError("unsafe secret file")
        raw = os.read(descriptor, _MAX_RUNTIME_SECRET_BYTES + 1)
        after = os.fstat(descriptor)

        def identity(value: os.stat_result) -> tuple[int, ...]:
            return (
                value.st_dev,
                value.st_ino,
                value.st_mode,
                value.st_uid,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )

        if (
            len(raw) != before.st_size
            or len(raw) > _MAX_RUNTIME_SECRET_BYTES
            or identity(before) != identity(after)
        ):
            raise OSError("unstable secret file")
        return raw.decode("utf-8").strip()
    except (OSError, UnicodeDecodeError, ValueError, TypeError):
        return ""
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


def read_secret(name: str, *, allow_env: bool = True) -> str:
    """Return a secret from NAME or NAME_FILE, trimming surrounding whitespace."""

    file_path = os.getenv(f"{name}_FILE", "").strip()
    if file_path:
        return _read_file_secret(file_path)
    return os.getenv(name, "").strip() if allow_env else ""
