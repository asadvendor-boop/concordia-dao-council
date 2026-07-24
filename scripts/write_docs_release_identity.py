#!/usr/bin/env python3
"""Write the public GitHub Pages release identity exactly once."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from pathlib import Path
from typing import Sequence


_SHA40 = re.compile(r"[0-9a-f]{40}")
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


def release_identity(github_sha: str, run_id_text: str) -> dict[str, object]:
    if _SHA40.fullmatch(github_sha) is None:
        raise ValueError("GITHUB_SHA must be 40 lowercase hex characters")
    if not run_id_text.isdigit() or int(run_id_text) < 1:
        raise ValueError("GITHUB_RUN_ID must be a positive integer")
    return {"GITHUB_SHA": github_sha, "run_id": int(run_id_text)}


def _canonical_bytes(identity: dict[str, object]) -> bytes:
    return (
        json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("ascii")


def _open_parent_directory(output: Path) -> tuple[int, str]:
    if output.name in {"", ".", ".."}:
        raise ValueError("output must name a file")

    if output.is_absolute():
        descriptor = os.open("/", _DIRECTORY_FLAGS)
        parts = output.parent.parts[1:]
    else:
        descriptor = os.open(".", _DIRECTORY_FLAGS)
        parts = output.parent.parts

    try:
        for part in parts:
            if part in {"", "."}:
                continue
            if part == "..":
                raise ValueError("output parent may not contain '..'")
            next_descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        parent_stat = os.fstat(descriptor)
        if not stat.S_ISDIR(parent_stat.st_mode):
            raise ValueError("output parent must be a directory")
        return descriptor, output.name
    except BaseException:
        os.close(descriptor)
        raise


def write_release_identity_once(output: Path, payload: bytes) -> None:
    parent_descriptor, filename = _open_parent_directory(output)
    file_descriptor: int | None = None
    created = False
    try:
        file_descriptor = os.open(
            filename,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o644,
            dir_fd=parent_descriptor,
        )
        created = True
        view = memoryview(payload)
        while view:
            written = os.write(file_descriptor, view)
            if written < 1:
                raise OSError("short write while creating release identity")
            view = view[written:]
        os.fsync(file_descriptor)
        os.close(file_descriptor)
        file_descriptor = None
        os.fsync(parent_descriptor)
    except BaseException:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if created:
            try:
                os.unlink(filename, dir_fd=parent_descriptor)
            except OSError:
                pass
        raise
    finally:
        os.close(parent_descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    identity = release_identity(
        os.environ.get("GITHUB_SHA", ""),
        os.environ.get("GITHUB_RUN_ID", ""),
    )
    write_release_identity_once(args.output, _canonical_bytes(identity))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
