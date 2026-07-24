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


ATTESTATION_DOCUMENT_SCHEMA_ID = (
    "concordia.mainnet-canary.build-attestation-document.v2"
)
ATTESTATION_DIGEST_DOMAIN = b"CONCORDIA_MAINNET_CANARY_ATTESTATION_V2\x00"

# Exact field set of one per-profile attestation entry.  A summary carrying
# fewer, extra, or renamed fields is caller-authored and refuses.
_ENTRY_FIELDS = frozenset(
    {
        "schema_id",
        "tag",
        "tag_object_sha",
        "peeled_commit_sha",
        "profile",
        "build_env_delta",
        "builds",
        "artifact_relpath",
        "wasm_sha256",
        "wasm_size_bytes",
        "toolchain",
    }
)

# Pinned contract-crate paths inside the exported tag tree.
CONTRACT_CRATE_RELPATH = "contracts/odra-governance-receipt-v3"
CARGO_LOCK_RELPATH = f"{CONTRACT_CRATE_RELPATH}/Cargo.lock"
COMMITTED_TESTNET_WASM_RELPATH = (
    f"{CONTRACT_CRATE_RELPATH}/wasm/GovernanceReceiptV3.wasm"
)

# Accepted release build command, pinned absolutely (no PATH lookup, no
# caller-supplied program).  The runner refuses to start without it.
CARGO_ODRA_BUILD_ARGS = ("odra", "build", "-b", "casper")
BUILD_TIMEOUT_SECONDS = 1800


def production_build_runner(cargo_path: str) -> BuildRunner:
    """The real pinned cargo-odra pipeline as an injectable build runner.

    ``cargo_path`` must be an absolute path to the cargo binary; the child
    environment is sanitized to exactly the profile delta plus the minimal
    PATH/HOME the toolchain needs.  The runner returns the built Wasm path
    inside the exported tree and never touches the repository worktree.
    """

    if not isinstance(cargo_path, str) or not cargo_path.startswith("/"):
        raise CanaryRefusal(
            RefusalCode.BUILD_COMMAND_INVALID,
            "cargo path must be absolute; PATH lookups are not part of the "
            "accepted release command",
        )

    def _run(tree: Path, env_delta: dict[str, str]) -> Path:
        crate = tree / CONTRACT_CRATE_RELPATH
        if not crate.is_dir():
            raise CanaryRefusal(
                RefusalCode.BUILD_FAILED,
                "exported tree carries no contract crate at the pinned path",
            )
        home = str(Path.home())
        env = {
            "PATH": "/usr/bin:/bin:" + str(Path(cargo_path).parent),
            "HOME": home,
            "CARGO_HOME": home + "/.cargo",
            "RUSTUP_HOME": home + "/.rustup",
            **env_delta,
        }
        result = subprocess.run(
            [cargo_path, *CARGO_ODRA_BUILD_ARGS],
            cwd=crate,
            env=env,
            capture_output=True,
            timeout=BUILD_TIMEOUT_SECONDS,
            check=False,
        )
        if result.returncode != 0:
            raise CanaryRefusal(
                RefusalCode.BUILD_FAILED,
                "pinned cargo-odra release build exited non-zero",
            )
        artifact = crate / "wasm" / "GovernanceReceiptV3.wasm"
        if not artifact.is_file():
            raise CanaryRefusal(
                RefusalCode.BUILD_FAILED,
                "pinned build produced no Wasm at the expected crate path",
            )
        return artifact

    return _run


def attestation_entry_digest(entry: dict[str, object]) -> str:
    """Canonical digest of one double-build result, domain-separated."""

    import json as _json

    body = {key: entry[key] for key in sorted(_ENTRY_FIELDS) if key in entry}
    payload = _json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(
        ATTESTATION_DIGEST_DOMAIN + payload.encode("utf-8")
    ).hexdigest()


def _git_blob_sha256(repo_root: Path, commit_sha: str, relpath: str) -> str | None:
    result = _git(repo_root, "show", f"{commit_sha}:{relpath}")
    if result.returncode != 0:
        return None
    return hashlib.sha256(result.stdout).hexdigest()


def _commit_tree_has_path(repo_root: Path, commit_sha: str, relpath: str) -> bool:
    result = _git(repo_root, "cat-file", "-e", f"{commit_sha}:{relpath}")
    return result.returncode == 0


def verify_attestation_entry(
    repo_root: Path,
    entry: object,
    *,
    profile: str,
    expected_tag: str,
    expected_peeled_commit_sha: str,
) -> dict[str, object]:
    """Recompute one attestation entry against the repository itself.

    A caller-authored summary containing plausible counters and hashes is
    NOT acceptable: the tag object, the peeled commit, the pinned Cargo.lock
    digest, the artifact path inside the exported tree, and (for the Testnet
    profile) the committed Wasm bytes are all independently recomputed here.
    Any recompute mismatch refuses with a stable code.
    """

    if not isinstance(entry, dict) or set(entry) != _ENTRY_FIELDS:
        raise CanaryRefusal(
            RefusalCode.ATTESTATION_NOT_EXECUTED,
            f"{profile}: attestation entry must contain exactly "
            f"{sorted(_ENTRY_FIELDS)}; a summary with a different shape is "
            "caller-authored",
        )
    if entry["schema_id"] != RC_ATTESTATION_SCHEMA_ID:
        raise CanaryRefusal(
            RefusalCode.ATTESTATION_NOT_EXECUTED,
            f"{profile}: attestation schema mismatch",
        )
    if entry["profile"] != profile or profile not in ALLOWED_PROFILES:
        raise CanaryRefusal(
            RefusalCode.ATTESTATION_NOT_EXECUTED,
            f"attestation entry does not carry profile {profile!r}",
        )
    if entry["build_env_delta"] != {ALLOWED_BUILD_ENV_KEY: profile}:
        raise CanaryRefusal(
            RefusalCode.SOURCE_DELTA_NOT_ALLOWLISTED,
            f"{profile}: build env delta is not exactly the allowlisted "
            "profile variable",
        )
    if entry["builds"] != 2:
        raise CanaryRefusal(
            RefusalCode.ATTESTATION_NOT_EXECUTED,
            f"{profile}: attestation does not record two independent builds",
        )
    if entry["tag"] != expected_tag:
        raise CanaryRefusal(
            RefusalCode.ATTESTATION_NOT_EXECUTED,
            f"{profile}: attestation tag does not equal the RC declaration's",
        )

    # The tag must exist, be annotated, and peel to the pinned commit — and
    # the recorded tag OBJECT sha must be the repository's actual tag object.
    resolution = resolve_annotated_tag(
        repo_root,
        expected_tag,
        expected_peeled_commit_sha=expected_peeled_commit_sha,
    )
    if (
        entry["tag_object_sha"] != resolution.tag_object_sha
        or entry["peeled_commit_sha"] != resolution.peeled_commit_sha
    ):
        raise CanaryRefusal(
            RefusalCode.ATTESTATION_NOT_EXECUTED,
            f"{profile}: recorded tag object/peeled commit do not recompute "
            "from the repository tag",
        )

    toolchain = entry["toolchain"]
    if not isinstance(toolchain, dict) or set(toolchain) != set(
        _REQUIRED_TOOLCHAIN_FIELDS
    ):
        raise CanaryRefusal(
            RefusalCode.TOOLCHAIN_UNPINNED,
            f"{profile}: toolchain facts must contain exactly "
            f"{sorted(_REQUIRED_TOOLCHAIN_FIELDS)}",
        )
    for field in _REQUIRED_TOOLCHAIN_FIELDS:
        if not isinstance(toolchain[field], str) or not toolchain[field]:
            raise CanaryRefusal(
                RefusalCode.TOOLCHAIN_UNPINNED,
                f"{profile}: toolchain field {field} is empty",
            )
    lock_sha = _git_blob_sha256(
        repo_root, resolution.peeled_commit_sha, CARGO_LOCK_RELPATH
    )
    if lock_sha is None or toolchain["cargo_lock_sha256"] != lock_sha:
        raise CanaryRefusal(
            RefusalCode.TOOLCHAIN_UNPINNED,
            f"{profile}: recorded Cargo.lock digest does not recompute from "
            "the peeled commit",
        )

    relpath = entry["artifact_relpath"]
    if relpath != f"{CONTRACT_CRATE_RELPATH}/wasm/GovernanceReceiptV3.wasm":
        raise CanaryRefusal(
            RefusalCode.ATTESTATION_NOT_EXECUTED,
            f"{profile}: artifact path is not the pinned crate Wasm path",
        )
    if not _commit_tree_has_path(
        repo_root, resolution.peeled_commit_sha, CONTRACT_CRATE_RELPATH
    ):
        raise CanaryRefusal(
            RefusalCode.ATTESTATION_NOT_EXECUTED,
            f"{profile}: the peeled commit carries no contract crate",
        )

    wasm_sha = entry["wasm_sha256"]
    size = entry["wasm_size_bytes"]
    if (
        not isinstance(wasm_sha, str)
        or len(wasm_sha) != 64
        or not isinstance(size, int)
        or size <= 0
    ):
        raise CanaryRefusal(
            RefusalCode.ARTIFACT_HASH_UNBACKED,
            f"{profile}: artifact hash/size malformed",
        )
    if profile == "testnet":
        committed = _git_blob_sha256(
            repo_root,
            resolution.peeled_commit_sha,
            COMMITTED_TESTNET_WASM_RELPATH,
        )
        if committed is None or wasm_sha != committed:
            raise CanaryRefusal(
                RefusalCode.ARTIFACT_HASH_UNBACKED,
                "testnet attestation hash does not equal the committed RC "
                "Wasm bytes at the peeled commit; the recorded double-build "
                "did not reproduce the judged artifact",
            )
    return entry


def verify_attestation_document(
    repo_root: Path,
    document: object,
    *,
    rc_tag: str,
    rc_peeled_commit_sha: str,
    rc_mainnet_wasm_sha256: str,
) -> dict[str, object]:
    """Full correction-round attestation verification (blocker 1).

    The document must be the executed double-build result: exact schema,
    both profiles, per-entry canonical digests that recompute, and every
    repository-recomputable fact (tag object, peeled commit, Cargo.lock,
    committed Testnet Wasm) independently re-derived here.
    """

    if (
        not isinstance(document, dict)
        or document.get("schema_id") != ATTESTATION_DOCUMENT_SCHEMA_ID
        or set(document)
        != {"schema_id", "network_artifacts", "entry_digests"}
    ):
        raise CanaryRefusal(
            RefusalCode.ATTESTATION_NOT_EXECUTED,
            "attestation document must be the executed "
            f"{ATTESTATION_DOCUMENT_SCHEMA_ID} result "
            "(schema_id, network_artifacts, entry_digests)",
        )
    pair = document["network_artifacts"]
    if not isinstance(pair, dict) or set(pair) != set(ALLOWED_PROFILES):
        raise CanaryRefusal(
            RefusalCode.ATTESTATION_NOT_EXECUTED,
            f"attestation must carry exactly the profiles {ALLOWED_PROFILES}",
        )
    digests = document["entry_digests"]
    if not isinstance(digests, dict) or set(digests) != set(ALLOWED_PROFILES):
        raise CanaryRefusal(
            RefusalCode.ATTESTATION_NOT_EXECUTED,
            "attestation entry digests must cover exactly both profiles",
        )
    entries: dict[str, dict[str, object]] = {}
    for profile in ALLOWED_PROFILES:
        entry = verify_attestation_entry(
            repo_root,
            pair[profile],
            profile=profile,
            expected_tag=rc_tag,
            expected_peeled_commit_sha=rc_peeled_commit_sha,
        )
        if digests[profile] != attestation_entry_digest(entry):
            raise CanaryRefusal(
                RefusalCode.ATTESTATION_NOT_EXECUTED,
                f"{profile}: entry digest does not recompute; the document "
                "was edited after the build executed",
            )
        entries[profile] = entry
    require_disjoint_network_artifacts(
        entries["testnet"], entries["mainnet-native"]
    )
    verify_declared_artifact_hash(
        entries["mainnet-native"], rc_mainnet_wasm_sha256
    )
    return document


def build_attestation_document(
    repo_root: Path,
    *,
    tag: str,
    expected_peeled_commit_sha: str,
    build_runner: BuildRunner,
    scratch_dir: Path,
    toolchain_probe: ToolchainProbe,
) -> dict[str, object]:
    """Execute the double builds for BOTH profiles and bind the result."""

    entries: dict[str, dict[str, object]] = {}
    for profile in ALLOWED_PROFILES:
        entries[profile] = attest_network_build(
            repo_root,
            tag=tag,
            expected_peeled_commit_sha=expected_peeled_commit_sha,
            profile=profile,
            build_runner=build_runner,
            scratch_dir=scratch_dir / profile,
            toolchain_probe=toolchain_probe,
        )
    require_disjoint_network_artifacts(
        entries["testnet"], entries["mainnet-native"]
    )
    return {
        "schema_id": ATTESTATION_DOCUMENT_SCHEMA_ID,
        "network_artifacts": entries,
        "entry_digests": {
            profile: attestation_entry_digest(entry)
            for profile, entry in entries.items()
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
