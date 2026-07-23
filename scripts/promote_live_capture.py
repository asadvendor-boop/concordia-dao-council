#!/usr/bin/env python3
"""Fail-closed promotion of immutable live collector captures.

The destination commit does not exist when its bytes are created, so a single
invocation cannot honestly put that commit in a receipt.  Promotion is
therefore deliberately a two-commit sequence:

1. ``prepare`` validates one immutable collector batch and atomically creates
   the fixed live artifact. Commit *only* that destination.
2. ``seal`` revalidates the batch and the destination first-add, then atomically
   creates the fixed promotion receipt. Commit *only* that receipt.
3. ``verify`` performs no writes and proves both immutable first-add bindings.

There are no caller-selectable source, destination, or receipt paths.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

from shared.bound_command import BoundCommandError, _run_bound_git
from shared.release_manifest import ARTIFACT_PATHS


MAX_BYTES = 64 * 1024 * 1024
PROMOTION_SCHEMA_VERSION = "concordia.live_capture_promotion.v1"
CAPTURE_PATHS = {
    "safepay_v2": {
        "receipt": "release/captures/payment-safepay-v2/collector-receipt.json",
        "raw": "release/captures/payment-safepay-v2/raw-bundle.json",
        "candidate": "release/captures/payment-safepay-v2/artifact-candidate.json",
    },
    "official_x402_settlement_v1": {
        "receipt": "release/captures/payment-official-x402/collector-receipt.json",
        "raw": "release/captures/payment-official-x402/raw-bundle.json",
        "candidate": "release/captures/payment-official-x402/artifact-candidate.json",
    },
}
PROMOTION_PATHS = {
    proof_id: {
        "destination": ARTIFACT_PATHS[proof_id],
        "receipt": f"release/promotions/{proof_id}.json",
    }
    for proof_id in CAPTURE_PATHS
}
_HISTORICAL_CANONICAL_ARTIFACTS = frozenset(
    path for proof_id, path in ARTIFACT_PATHS.items() if proof_id not in CAPTURE_PATHS
)
_GIT40 = __import__("re").compile(r"^[0-9a-f]{40}$")
_IGNORED_OUTPUT_PREFIXES = (
    ".pytest_cache/",
    ".ruff_cache/",
    ".venv/",
    "node_modules/",
    "dashboard/.next/",
    "dashboard/node_modules/",
    "dashboard/playwright-report/",
    "dashboard/test-results/",
    "packages/verify/node_modules/",
    "packages/verify/dist/",
    "services/x402-official/node_modules/",
    "services/x402-official/dist/",
    "contracts/odra-governance-receipt-v3/target/",
)

def _verify_live_collector_admission(**kwargs: object) -> dict[str, object]:
    """Load the existing admission validator only when a real promotion runs."""

    # This module's basic refusal paths must remain runnable without the
    # optional Casper verifier dependency; live admission still always uses the
    # established registry validator.
    from scripts.assemble_proof_registry import _verify_live_collector_admission as verify

    return verify(**kwargs)


class PromotionError(ValueError):
    """A live capture cannot be promoted without weakening its provenance."""


def _canonical(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise PromotionError("promotion receipt is not canonical") from exc


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PromotionError("JSON has duplicate keys")
        result[key] = value
    return result


def _read_json(path: Path, *, label: str) -> tuple[bytes, dict[str, Any]]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PromotionError(f"{label} is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES:
            raise PromotionError(f"{label} is not a bounded regular file")
        parts: list[bytes] = []
        remaining = MAX_BYTES + 1
        while remaining:
            piece = os.read(descriptor, min(1024 * 1024, remaining))
            if not piece:
                break
            parts.append(piece)
            remaining -= len(piece)
        raw = b"".join(parts)
        after = os.fstat(descriptor)
        if len(raw) > MAX_BYTES or len(raw) != before.st_size or (
            before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns
        ) != (
            after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns
        ):
            raise PromotionError(f"{label} changed while being read")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError, PromotionError) as exc:
        raise PromotionError(f"{label} is not strict JSON") from exc
    if type(value) is not dict or raw != _canonical(value):
        raise PromotionError(f"{label} is not canonical JSON")
    return raw, value


def _git(root: Path, *arguments: str, check: bool = True) -> bytes:
    try:
        result = _run_bound_git(
            root,
            tuple(arguments),
            check=check,
            stdout_limit=MAX_BYTES + 1,
        )
    except BoundCommandError as exc:
        raise PromotionError("Git provenance is unavailable") from exc
    return result.stdout


def _repository_root(root: str | Path) -> Path:
    candidate = Path(root).resolve()
    actual = _git(candidate, "rev-parse", "--show-toplevel").decode("utf-8").strip()
    if Path(actual).resolve() != candidate:
        raise PromotionError("repository root is not the Git top level")
    return candidate


def _path_commits(root: Path, relative: str, *, all_refs: bool = False) -> list[str]:
    arguments = ["log"]
    if all_refs:
        arguments.append("--all")
    arguments.extend(["--format=%H", "--", relative])
    try:
        commits = _git(root, *arguments).decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise PromotionError("Git history is malformed") from exc
    if any(_GIT40.fullmatch(commit) is None for commit in commits):
        raise PromotionError("Git history is malformed")
    return commits


def _first_add(root: Path, relative: str) -> str:
    try:
        commits = _git(
            root, "log", "--diff-filter=A", "--reverse", "--format=%H", "--", relative
        ).decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise PromotionError("Git first-add history is malformed") from exc
    if not commits or _GIT40.fullmatch(commits[0]) is None:
        raise PromotionError(f"{relative} has no committed first-add")
    return commits[0]


def _blob(root: Path, commit: str, relative: str) -> bytes:
    raw = _git(root, "show", f"{commit}:{relative}")
    if len(raw) > MAX_BYTES:
        raise PromotionError(f"{relative} committed bytes exceed the limit")
    return raw


def _head(root: Path) -> str:
    value = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    if _GIT40.fullmatch(value) is None:
        raise PromotionError("Git HEAD is malformed")
    return value


def _is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    try:
        result = _run_bound_git(
            root,
            ("merge-base", "--is-ancestor", ancestor, descendant),
            check=False,
            stdout_limit=1024,
        )
    except BoundCommandError as exc:
        raise PromotionError("Git ancestry check failed") from exc
    if result.returncode not in {0, 1}:
        raise PromotionError("Git ancestry check failed")
    return result.returncode == 0


def _immutable_path(root: Path, relative: str, *, label: str) -> tuple[bytes, str]:
    raw, _document = _read_json(root / relative, label=label)
    first = _first_add(root, relative)
    commits = _path_commits(root, relative)
    if commits != [first] or not _is_ancestor(root, first, _head(root)):
        raise PromotionError(f"{label} is not an immutable first-add artifact")
    if _blob(root, first, relative) != raw:
        raise PromotionError(f"{label} differs from its immutable first-add bytes")
    return raw, first


def _validate_source(root: Path, proof_id: str) -> dict[str, object]:
    try:
        capture = CAPTURE_PATHS[proof_id]
    except KeyError as exc:
        raise PromotionError("proof ID is unsupported") from exc
    receipt_raw, receipt_commit = _immutable_path(
        root, capture["receipt"], label="collector receipt"
    )
    raw_bundle, raw_commit = _immutable_path(
        root, capture["raw"], label="collector raw bundle"
    )
    candidate_raw, candidate_commit = _immutable_path(
        root, capture["candidate"], label="collector artifact candidate"
    )
    if len({receipt_commit, raw_commit, candidate_commit}) != 1:
        raise PromotionError("candidate, receipt, and raw bundle were not first-added in one immutable commit")
    _receipt_raw, candidate_document = _read_json(
        root / capture["candidate"], label="collector artifact candidate"
    )
    artifact = SimpleNamespace(
        path=root / capture["candidate"],
        relative_path=capture["candidate"],
        raw=candidate_raw,
        document=candidate_document,
        sha256=hashlib.sha256(candidate_raw).hexdigest(),
        stat_identity=(0, 0, 0, 0, 0),
    )
    try:
        projection = _verify_live_collector_admission(
            repository_root=root,
            proof_id=proof_id,
            artifact=artifact,
            receipt_path=root / capture["receipt"],
            raw_bundle_path=root / capture["raw"],
            release=True,
        )
    except (ValueError, OSError, RuntimeError) as exc:
        raise PromotionError(f"collector provenance is inconsistent: {exc}") from exc
    if projection.get("artifact_sha256") != artifact.sha256:
        raise PromotionError("collector provenance artifact digest differs")
    # Retain local bindings so an invocation cannot silently swap files after
    # the validator has read them.
    if receipt_raw != _blob(root, receipt_commit, capture["receipt"]) or raw_bundle != _blob(
        root, raw_commit, capture["raw"]
    ):
        raise PromotionError("collector batch changed during validation")
    return {
        "candidate_raw": candidate_raw,
        "candidate_path": capture["candidate"],
        "candidate_commit": candidate_commit,
        "candidate_sha256": artifact.sha256,
    }


def _assert_destination_absent(root: Path, relative: str) -> None:
    if relative in _HISTORICAL_CANONICAL_ARTIFACTS:
        raise PromotionError("historical canonical artifacts are never promotion targets")
    if (root / relative).exists() or _path_commits(root, relative, all_refs=True):
        raise PromotionError("destination already exists or has prior history")


def _atomic_create(root: Path, relative: str, raw: bytes) -> None:
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise PromotionError("destination already exists")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".promotion-", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, destination, follow_symlinks=False)
        except FileExistsError as exc:
            raise PromotionError("destination already exists") from exc
        parent_descriptor = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except OSError as exc:
        raise PromotionError("atomic destination creation failed") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _require_promotion_clean_worktree(root: Path) -> None:
    try:
        rows = _git(
            root,
            "status",
            "--ignored=matching",
            "--porcelain=v1",
            "--untracked-files=all",
        ).decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise PromotionError("promotion worktree status is malformed") from exc
    for row in rows:
        if not row.startswith("!! "):
            raise PromotionError("promotion worktree is not clean")
        relative = row[3:]
        if not any(
            relative == prefix.rstrip("/") or relative.startswith(prefix)
            for prefix in _IGNORED_OUTPUT_PREFIXES
        ):
            raise PromotionError(
                f"promotion worktree has non-allowlisted ignored output: {relative}"
            )


def _promotion_release_lock(root: Path) -> int:
    try:
        common_raw = _git(root, "rev-parse", "--git-common-dir").decode(
            "utf-8", errors="strict"
        ).strip()
    except UnicodeDecodeError as exc:
        raise PromotionError("Git common directory is malformed") from exc
    common = Path(common_raw)
    if not common.is_absolute():
        common = root / common
    try:
        common = common.resolve(strict=True)
    except OSError as exc:
        raise PromotionError("Git common directory is unavailable") from exc
    lock_path = common / "concordia-release-manifest.lock"
    try:
        descriptor = os.open(
            lock_path,
            os.O_RDWR
            | os.O_CREAT
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError as exc:
        raise PromotionError("promotion release lock is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
        ):
            raise PromotionError("promotion release lock is unsafe")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise PromotionError(
                "another release operation holds the repository lock"
            ) from exc
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def _promotion_mutation_guard(root: Path):
    from shared.release_manifest import (
        ReleaseManifestError,
        _recover_capture_publication,
    )

    descriptor: int | None = None
    try:
        descriptor = _promotion_release_lock(root)
        if _recover_capture_publication(root) != "none":
            raise PromotionError(
                "promotion recovery completed; rerun from the reconciled tree"
            )
        _require_promotion_clean_worktree(root)
        yield
    except ReleaseManifestError as exc:
        raise PromotionError("promotion release preflight failed closed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _receipt_document(proof_id: str, source: Mapping[str, object], destination_commit: str) -> dict[str, object]:
    paths = PROMOTION_PATHS[proof_id]
    raw = source["candidate_raw"]
    assert isinstance(raw, bytes)
    return {
        "schema_version": PROMOTION_SCHEMA_VERSION,
        "proof_id": proof_id,
        "source": {
            "candidate_path": source["candidate_path"],
            "candidate_first_add_commit": source["candidate_commit"],
            "candidate_sha256": source["candidate_sha256"],
        },
        "destination": {
            "path": paths["destination"],
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
            "first_add_commit": destination_commit,
        },
    }


def prepare(repository_root: str | Path, proof_id: str) -> dict[str, object]:
    """Atomically create the fixed destination after source admission."""

    root = _repository_root(repository_root)
    with _promotion_mutation_guard(root):
        source = _validate_source(root, proof_id)
        destination = PROMOTION_PATHS[proof_id]["destination"]
        _assert_destination_absent(root, destination)
        raw = source["candidate_raw"]
        assert isinstance(raw, bytes)
        _atomic_create(root, destination, raw)
    return {
        "proof_id": proof_id,
        "source_candidate_sha256": source["candidate_sha256"],
        "destination_path": destination,
    }


def seal(repository_root: str | Path, proof_id: str) -> dict[str, object]:
    """Create the fixed receipt only after the destination is immutable."""

    root = _repository_root(repository_root)
    with _promotion_mutation_guard(root):
        source = _validate_source(root, proof_id)
        paths = PROMOTION_PATHS[proof_id]
        destination_raw, destination_commit = _immutable_path(
            root, paths["destination"], label="promotion destination"
        )
        candidate_raw = source["candidate_raw"]
        assert isinstance(candidate_raw, bytes)
        if destination_raw != candidate_raw:
            raise PromotionError("destination bytes differ from the admitted candidate")
        _assert_destination_absent(root, paths["receipt"])
        receipt = _receipt_document(proof_id, source, destination_commit)
        _atomic_create(root, paths["receipt"], _canonical(receipt))
    return {
        "proof_id": proof_id,
        "destination_first_add_commit": destination_commit,
        "promotion_receipt_path": paths["receipt"],
    }


def verify(repository_root: str | Path, proof_id: str) -> dict[str, object]:
    """Verify the sealed promotion without writing any repository file."""

    root = _repository_root(repository_root)
    source = _validate_source(root, proof_id)
    paths = PROMOTION_PATHS[proof_id]
    destination_raw, destination_commit = _immutable_path(
        root, paths["destination"], label="promotion destination"
    )
    candidate_raw = source["candidate_raw"]
    assert isinstance(candidate_raw, bytes)
    if destination_raw != candidate_raw:
        raise PromotionError("destination bytes differ from the admitted candidate")
    receipt_raw, receipt = _read_json(root / paths["receipt"], label="promotion receipt")
    receipt_first = _first_add(root, paths["receipt"])
    if _path_commits(root, paths["receipt"]) != [receipt_first] or not _is_ancestor(
        root, receipt_first, _head(root)
    ) or _blob(root, receipt_first, paths["receipt"]) != receipt_raw:
        raise PromotionError("promotion receipt is not an immutable first-add artifact")
    expected = _receipt_document(proof_id, source, destination_commit)
    if receipt != expected:
        raise PromotionError("promotion receipt binding differs")
    return {
        "proof_id": proof_id,
        "source_candidate_sha256": source["candidate_sha256"],
        "destination_first_add_commit": destination_commit,
        "promotion_receipt_commit": receipt_first,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "seal", "verify"))
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--proof-id", required=True, choices=tuple(CAPTURE_PATHS))
    arguments = parser.parse_args(argv)
    try:
        result = {"prepare": prepare, "seal": seal, "verify": verify}[arguments.action](
            arguments.repository_root, arguments.proof_id
        )
    except PromotionError as exc:
        parser.error(str(exc))
    print(_canonical(result).decode("ascii"), end="")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
