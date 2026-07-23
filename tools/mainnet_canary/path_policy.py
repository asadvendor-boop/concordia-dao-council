"""Centralized output-path confinement for every canary write.

Every command that produces an output (plan, intents, journal, signed bytes,
receipts, raw observations, proof bundle, release manifest) must resolve its
target through one :class:`CanaryPathPolicy`.  The policy refuses:

- any path below the protected canonical/live namespaces or the repository's
  secret locations;
- absolute targets outside the authorized output root;
- ``..`` traversal and non-normalized components;
- symlink escapes (any existing ancestor of the target that is a symlink);
- overwriting: every write is an exclusive creation (``O_EXCL`` +
  hard-link publish), fsynced at both the file and its directory.

Until Codex explicitly authorizes live capture, the output root itself must
live OUTSIDE the repository (temporary directories in tests); the supplemental
``artifacts/mainnet-canary/<canary_id>/`` namespace is only reachable with
``live_capture_authorized=True``, which nothing in the preparation lane sets.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from tools.mainnet_canary.constants import (
    CANARY_OUTPUT_NAMESPACE,
    PROTECTED_CANONICAL_PREFIXES,
)
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode

_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-]{0,200}\Z")
_CANARY_ID = re.compile(r"[a-z0-9][a-z0-9\-]{3,63}\Z")

# Repository locations that canary outputs must never touch, beyond the
# canonical prefixes shared with the artifact-lineage constants.
_FORBIDDEN_REPO_PREFIXES = PROTECTED_CANONICAL_PREFIXES + (
    ".git/",
    "secrets/",
    "deploy/secrets/",
)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _refuse(code: str, detail: str) -> CanaryRefusal:
    return CanaryRefusal(code, detail)


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class CanaryPathPolicy:
    """One policy instance confines every output of one canary run."""

    def __init__(
        self,
        repo_root: Path,
        output_root: Path,
        *,
        canary_id: str,
        live_capture_authorized: bool = False,
    ):
        if _CANARY_ID.match(canary_id) is None:
            raise _refuse(
                RefusalCode.PLAN_INPUT_INVALID,
                "canary_id must be 4-64 chars of [a-z0-9-]",
            )
        self.repo_root = repo_root.resolve()
        self.canary_id = canary_id
        resolved = output_root.resolve()

        if _is_relative_to(resolved, self.repo_root):
            relative = str(resolved.relative_to(self.repo_root)) + "/"
            for prefix in _FORBIDDEN_REPO_PREFIXES:
                if relative.startswith(prefix):
                    raise _refuse(
                        RefusalCode.CANONICAL_NAMESPACE_PROTECTED,
                        f"output root is below protected namespace {prefix}",
                    )
            expected = f"{CANARY_OUTPUT_NAMESPACE}{canary_id}/"
            if not relative.startswith(expected):
                raise _refuse(
                    RefusalCode.LIVE_ARTIFACTS_UNAVAILABLE_IN_PREP,
                    "an in-repo output root must be exactly the supplemental "
                    f"namespace {expected}",
                )
            if not live_capture_authorized:
                raise _refuse(
                    RefusalCode.LIVE_ARTIFACTS_UNAVAILABLE_IN_PREP,
                    "live capture into the repository is not authorized; use "
                    "a temporary directory outside the repo",
                )
        self.output_root = resolved
        # The policy owns its (validated) root; creating it here keeps the
        # symlink-escape probe from ever walking above the root.
        self.output_root.mkdir(parents=True, exist_ok=True)

    # -- resolution ----------------------------------------------------------

    def resolve(self, relpath: str) -> Path:
        """Resolve one confined output path; refuse traversal and escapes."""

        if not isinstance(relpath, str) or not relpath:
            raise _refuse(RefusalCode.PLAN_INPUT_INVALID, "output path empty")
        candidate = Path(relpath)
        if candidate.is_absolute():
            raise _refuse(
                RefusalCode.CANONICAL_NAMESPACE_PROTECTED,
                "output paths must be relative to the authorized output root",
            )
        for component in candidate.parts:
            if _COMPONENT.match(component) is None:
                raise _refuse(
                    RefusalCode.CANONICAL_NAMESPACE_PROTECTED,
                    f"output path component {component!r} is not permitted",
                )
        target = self.output_root / candidate
        # Symlink-escape guard: the nearest existing ancestor chain must be
        # real directories inside the output root once fully resolved.
        probe = target.parent
        while not probe.exists():
            probe = probe.parent
        resolved_probe = probe.resolve()
        if not (
            resolved_probe == self.output_root
            or _is_relative_to(resolved_probe, self.output_root)
        ):
            raise _refuse(
                RefusalCode.CANONICAL_NAMESPACE_PROTECTED,
                "output path escapes the authorized root via a symlinked "
                "ancestor",
            )
        if probe.is_symlink():
            raise _refuse(
                RefusalCode.CANONICAL_NAMESPACE_PROTECTED,
                "output ancestors may not be symlinks",
            )
        return target

    # -- exclusive, durable writes ------------------------------------------

    def exclusive_write_bytes(self, relpath: str, data: bytes) -> Path:
        """Exclusively create ``relpath`` with fsynced content; never overwrite."""

        target = self.resolve(relpath)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.parent.is_symlink():
            raise _refuse(
                RefusalCode.CANONICAL_NAMESPACE_PROTECTED,
                "output directory may not be a symlink",
            )
        if target.is_symlink():
            raise _refuse(
                RefusalCode.CANONICAL_NAMESPACE_PROTECTED,
                f"evidence output {relpath} may not be a symlink",
            )
        if target.exists():
            # Content-addressed idempotency: re-publishing identical bytes is
            # a no-op; ANY difference refuses — evidence is never replaced.
            if target.is_file() and target.read_bytes() == data:
                return target
            raise _refuse(
                RefusalCode.JOURNAL_CONFLICT,
                f"refusing to overwrite existing evidence output {relpath}",
            )
        staging = target.parent / f".staging-{os.getpid()}-{target.name}"
        fd = os.open(
            staging,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            # Hard-link publish: unlike rename, link() fails if the final
            # name appears concurrently, so an existing bundle is never
            # silently replaced.
            try:
                os.link(staging, target)
            except FileExistsError as exc:
                raise _refuse(
                    RefusalCode.JOURNAL_CONFLICT,
                    f"evidence output {relpath} appeared concurrently; "
                    "refusing to overwrite",
                ) from exc
            _fsync_dir(target.parent)
        finally:
            try:
                os.unlink(staging)
            except FileNotFoundError:
                pass
        return target

    def exclusive_write_json(self, relpath: str, document: dict[str, object]) -> Path:
        payload = json.dumps(document, sort_keys=True, separators=(",", ":"))
        return self.exclusive_write_bytes(relpath, payload.encode("utf-8"))
