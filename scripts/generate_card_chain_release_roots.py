#!/usr/bin/env python3
"""Derive the public card-chain cutoff from a verified historical receipt.

The release root is never an operator assertion.  This tool first runs the
strict historical Odra verifier, then emits exactly the proposal/root pair it
derived from the signed receipt and exact card preimages.
"""

from __future__ import annotations

import argparse
import errno
import hmac
import json
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Sequence

from shared.historical_odra_artifact import (
    HistoricalOdraArtifactError,
    HistoricalOdraArtifactUnavailable,
    PACKAGED_INVENTORY_PATH,
    verify_historical_odra_artifact,
)


MAX_HISTORICAL_ARTIFACT_BYTES = 32 * 1024 * 1024
MAX_RELEASE_ROOTS_BYTES = 64 * 1024


class ReleaseRootsError(RuntimeError):
    """A verified receipt-derived release-root file cannot be produced."""


def derive_card_chain_release_roots(
    historical_artifact: bytes,
    *,
    inventory_bytes: bytes | None = None,
) -> bytes:
    """Return canonical release-root bytes derived by the strict verifier."""

    if (
        type(historical_artifact) is not bytes
        or not historical_artifact
        or len(historical_artifact) > MAX_HISTORICAL_ARTIFACT_BYTES
    ):
        raise ReleaseRootsError("historical artifact is unavailable or oversized")
    try:
        facts = verify_historical_odra_artifact(
            historical_artifact,
            inventory_bytes=inventory_bytes,
        )
    except (HistoricalOdraArtifactError, HistoricalOdraArtifactUnavailable) as exc:
        raise ReleaseRootsError("historical artifact did not verify") from exc
    proposal_id = facts.get("proposalId")
    generation = facts.get("generation")
    final_card_hash = facts.get("finalCardHash")
    if (
        generation != "v1"
        or type(proposal_id) is not str
        or not proposal_id
        or type(final_card_hash) is not str
        or len(final_card_hash) != 64
    ):
        raise ReleaseRootsError("historical artifact has no publishable v1 root")
    document = {
        "schema_version": "concordia.card_chain_roots.v1",
        "roots": {proposal_id: final_card_hash},
    }
    try:
        payload = (
            json.dumps(
                document,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:  # pragma: no cover
        raise ReleaseRootsError("verified release root is not canonical JSON") from exc
    if len(payload) > MAX_RELEASE_ROOTS_BYTES:
        raise ReleaseRootsError("verified release root exceeds size limit")
    return payload


def _read_regular_file(path: Path, *, limit: int, label: str) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseRootsError(f"{label} is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ReleaseRootsError(f"{label} is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except OSError as exc:
        raise ReleaseRootsError(f"{label} is unreadable") from exc
    finally:
        os.close(descriptor)
    if not raw or len(raw) > limit:
        raise ReleaseRootsError(f"{label} exceeds its size limit")
    return raw


def verify_existing_release_roots(path: Path, expected: bytes) -> None:
    """Require an existing regular root file to equal verifier-derived bytes."""

    actual = _read_regular_file(
        Path(path),
        limit=MAX_RELEASE_ROOTS_BYTES,
        label="card-chain release roots",
    )
    if not hmac.compare_digest(actual, expected):
        raise ReleaseRootsError(
            "card-chain release roots does not equal verified historical receipt"
        )


def write_release_roots_once(path: Path, payload: bytes) -> None:
    """Create one release-root file atomically; never replace any path."""

    if type(payload) is not bytes or not payload or len(payload) > MAX_RELEASE_ROOTS_BYTES:
        raise ReleaseRootsError("release-root payload is invalid")
    target = Path(path)
    parent = target.parent
    try:
        parent_stat = parent.stat()
        if not stat.S_ISDIR(parent_stat.st_mode) or parent.is_symlink():
            raise ReleaseRootsError("release-root parent is not a regular directory")
    except OSError as exc:
        raise ReleaseRootsError("release-root parent is unavailable") from exc
    temporary = parent / f".{target.name}.{secrets.token_hex(12)}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o644,
        )
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ReleaseRootsError("release-root write failed")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(temporary, target, follow_symlinks=False)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                raise ReleaseRootsError("release-root output already exists") from exc
            raise ReleaseRootsError("release-root output could not be committed") from exc
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except ReleaseRootsError:
        raise
    except OSError as exc:
        raise ReleaseRootsError("release-root write failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--historical-artifact", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, default=PACKAGED_INVENTORY_PATH)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args(argv)
    try:
        historical = _read_regular_file(
            args.historical_artifact,
            limit=MAX_HISTORICAL_ARTIFACT_BYTES,
            label="historical artifact",
        )
        inventory = _read_regular_file(
            args.inventory,
            limit=256 * 1024,
            label="historical inventory",
        )
        payload = derive_card_chain_release_roots(
            historical,
            inventory_bytes=inventory,
        )
        if args.verify_existing:
            verify_existing_release_roots(args.output, payload)
        else:
            write_release_roots_once(args.output, payload)
    except ReleaseRootsError as exc:
        print(f"release-root generation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - operator CLI
    raise SystemExit(main())
