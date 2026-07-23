"""Reproducible artifact attestation (RC gate v2).

Every network Wasm artifact the canary relies on must be rebuilt from a
Codex-published ANNOTATED tag, twice, from independently exported clean
trees, through the accepted release command, and hash byte-identically.
Declared hashes are never trusted: the attested hash is recomputed from the
actual built artifact.  The only permitted build-input difference between the
Testnet and Mainnet-native artifacts is the allowlisted profile environment
variable ``CONCORDIA_V3_NETWORK_PROFILE`` (cargo-odra 0.1.7 forwards no
cargo flags, so the network profile rides build.rs — see the interface
manifest for the deviation record).

The ``build_runner`` is injected: tests use deterministic fakes; the real
runner invokes the pinned absolute cargo-odra pipeline with a sanitized
environment and timeout.  Nothing in this module signs, broadcasts, or
touches live artifacts.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tarfile
import io
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode

RC_ATTESTATION_SCHEMA_ID = "concordia.mainnet-canary.rc-attestation.v1"

# The single allowlisted build-input delta between network artifacts.
ALLOWED_BUILD_ENV_KEY = "CONCORDIA_V3_NETWORK_PROFILE"
ALLOWED_PROFILES = ("testnet", "mainnet-native")

_REQUIRED_TOOLCHAIN_FIELDS = (
    "rustc_version",
    "cargo_odra_version",
    "cargo_lock_sha256",
)

BuildRunner = Callable[[Path, dict[str, str]], Path]
ToolchainProbe = Callable[[], dict[str, str]]


@dataclass(frozen=True)
class TagResolution:
    """An annotated tag pinned to both its tag object and peeled commit."""

    tag: str
    tag_object_sha: str
    peeled_commit_sha: str


def _git(repo_root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True,
        check=False,
    )


def _git_text(repo_root: Path, *args: str) -> str | None:
    result = _git(repo_root, *args)
    if result.returncode != 0:
        return None
    return result.stdout.decode("utf-8", errors="replace").strip()


def resolve_annotated_tag(
    repo_root: Path, tag: str, *, expected_peeled_commit_sha: str | None = None
) -> TagResolution:
    """Resolve ``tag`` to (tag object, peeled commit); fail closed.

    Missing tags, lightweight tags, and tags that no longer peel to the
    expected commit (a moved tag) all refuse.  Ref listing never uses
    ``--all``/newest-ref heuristics — only the exact requested tag ref.
    """

    tag_object = _git_text(repo_root, "rev-parse", "--verify", f"refs/tags/{tag}")
    if tag_object is None:
        raise CanaryRefusal(
            RefusalCode.TAG_MISSING, f"tag {tag!r} does not exist in this repository"
        )
    object_type = _git_text(repo_root, "cat-file", "-t", tag_object)
    if object_type != "tag":
        raise CanaryRefusal(
            RefusalCode.TAG_NOT_ANNOTATED,
            f"tag {tag!r} is not an annotated tag object "
            f"(found {object_type!r}); lightweight tags carry no authorship "
            "and are refused",
        )
    peeled = _git_text(repo_root, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
    if peeled is None:
        raise CanaryRefusal(
            RefusalCode.TAG_MISSING, f"tag {tag!r} does not peel to a commit"
        )
    if (
        expected_peeled_commit_sha is not None
        and peeled != expected_peeled_commit_sha
    ):
        raise CanaryRefusal(
            RefusalCode.TAG_MOVED,
            f"tag {tag!r} peels to a different commit than the pinned "
            "declaration; a moved tag is never trusted",
        )
    return TagResolution(tag=tag, tag_object_sha=tag_object, peeled_commit_sha=peeled)


def require_pristine_worktree(repo_root: Path) -> None:
    """Refuse tracked, staged, unstaged, AND untracked drift."""

    status = _git_text(repo_root, "status", "--porcelain", "--untracked-files=all")
    if status is None:
        raise CanaryRefusal(
            RefusalCode.SOURCE_TREE_DIRTY, "git status failed; tree state unprovable"
        )
    if status:
        raise CanaryRefusal(
            RefusalCode.SOURCE_TREE_DIRTY,
            "worktree carries tracked/staged/unstaged/untracked drift; the "
            "attestation builds only from a pristine exported tag tree",
        )


def export_commit_tree(repo_root: Path, peeled_commit_sha: str, dest: Path) -> Path:
    """Export the exact commit into a fresh private directory (no reuse)."""

    if dest.exists():
        raise CanaryRefusal(
            RefusalCode.BUILD_COMMAND_INVALID,
            "export destination already exists; each build uses a fresh tree",
        )
    dest.mkdir(parents=True, mode=0o700)
    archive = _git(repo_root, "archive", "--format=tar", peeled_commit_sha)
    if archive.returncode != 0:
        raise CanaryRefusal(
            RefusalCode.BUILD_FAILED, "git archive of the peeled commit failed"
        )
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:
        tar.extractall(dest, filter="data")
    return dest


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            digest.update(str(path.relative_to(root)).encode())
            digest.update(b"\x00")
            digest.update(path.read_bytes())
            digest.update(b"\x01")
    return digest.hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def attest_network_build(
    repo_root: Path,
    *,
    tag: str,
    expected_peeled_commit_sha: str,
    profile: str,
    build_runner: BuildRunner,
    scratch_dir: Path,
    toolchain_probe: ToolchainProbe,
) -> dict[str, object]:
    """Double-build one network artifact from independent clean trees."""

    if profile not in ALLOWED_PROFILES:
        raise CanaryRefusal(
            RefusalCode.BUILD_COMMAND_INVALID,
            f"profile must be one of {ALLOWED_PROFILES}; caller-supplied "
            "chain values are forbidden",
        )
    resolution = resolve_annotated_tag(
        repo_root, tag, expected_peeled_commit_sha=expected_peeled_commit_sha
    )
    require_pristine_worktree(repo_root)

    toolchain = toolchain_probe()
    missing = [
        field
        for field in _REQUIRED_TOOLCHAIN_FIELDS
        if not isinstance(toolchain.get(field), str) or not toolchain.get(field)
    ]
    if missing:
        raise CanaryRefusal(
            RefusalCode.TOOLCHAIN_UNPINNED,
            f"toolchain identity is incomplete (missing {missing}); an "
            "attestation without pinned toolchain facts is not reproducible",
        )

    env_delta = {ALLOWED_BUILD_ENV_KEY: profile}
    artifacts: list[bytes] = []
    artifact_relpath: str | None = None
    try:
        for build_index in (1, 2):
            tree = export_commit_tree(
                repo_root,
                resolution.peeled_commit_sha,
                scratch_dir / f"build-{build_index}",
            )
            if build_index == 1:
                first_tree_digest = _tree_digest(tree)
            elif _tree_digest(tree) != first_tree_digest:
                raise CanaryRefusal(
                    RefusalCode.SOURCE_DELTA_NOT_ALLOWLISTED,
                    "independently exported trees of the same peeled commit "
                    "differ; refusing to attest",
                )
            try:
                artifact_path = build_runner(tree, dict(env_delta))
            except CanaryRefusal:
                raise
            except Exception as exc:
                raise CanaryRefusal(
                    RefusalCode.BUILD_FAILED,
                    f"build {build_index} failed under the accepted release "
                    "command",
                ) from exc
            if not isinstance(artifact_path, Path) or not artifact_path.is_file():
                raise CanaryRefusal(
                    RefusalCode.BUILD_FAILED,
                    f"build {build_index} produced no artifact file",
                )
            artifacts.append(artifact_path.read_bytes())
            artifact_relpath = str(artifact_path.relative_to(tree))
    finally:
        shutil.rmtree(scratch_dir, ignore_errors=True)

    if artifacts[0] != artifacts[1]:
        raise CanaryRefusal(
            RefusalCode.BUILD_NOT_REPRODUCIBLE,
            "two independent clean-tree builds are not byte-identical; the "
            "artifact hash cannot be attested",
        )
    wasm_sha256 = hashlib.sha256(artifacts[0]).hexdigest()
    return {
        "schema_id": RC_ATTESTATION_SCHEMA_ID,
        "tag": resolution.tag,
        "tag_object_sha": resolution.tag_object_sha,
        "peeled_commit_sha": resolution.peeled_commit_sha,
        "profile": profile,
        "build_env_delta": env_delta,
        "builds": 2,
        "artifact_relpath": artifact_relpath,
        "wasm_sha256": wasm_sha256,
        "wasm_size_bytes": len(artifacts[0]),
        "toolchain": {
            field: toolchain[field] for field in _REQUIRED_TOOLCHAIN_FIELDS
        },
    }


def require_disjoint_network_artifacts(
    testnet_attestation: dict[str, object], mainnet_attestation: dict[str, object]
) -> None:
    """Testnet and Mainnet-native artifacts must differ byte-for-byte."""

    if (
        testnet_attestation["peeled_commit_sha"]
        != mainnet_attestation["peeled_commit_sha"]
    ):
        raise CanaryRefusal(
            RefusalCode.RC_COMMIT_MISMATCH,
            "network attestations were built from different peeled commits",
        )
    if testnet_attestation["wasm_sha256"] == mainnet_attestation["wasm_sha256"]:
        raise CanaryRefusal(
            RefusalCode.RC_MAINNET_WASM_UNATTESTED,
            "the Mainnet-native artifact is byte-identical to the Testnet "
            "artifact; a Testnet-chained Wasm cannot initialise on Mainnet",
        )


def verify_declared_artifact_hash(
    attestation: dict[str, object], declared_sha256: str
) -> None:
    """Declared hashes are never trusted — only the recomputed one counts."""

    if declared_sha256 != attestation["wasm_sha256"]:
        raise CanaryRefusal(
            RefusalCode.ARTIFACT_HASH_UNBACKED,
            "a declared artifact hash is not backed by the actual double-"
            "built artifact",
        )
