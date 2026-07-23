"""Assemble Concordia's post-hoc, commit-bound finals release manifest.

The manifest is deliberately generated *after* every evidence artifact and
staged deployment identity has been committed.  It never contains the commit
that will later contain the manifest itself.  Git therefore provides that last
edge without a circular self-reference.
"""

from __future__ import annotations

import base64
import binascii
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit


SCHEMA_VERSION = "concordia.release_manifest.v1"
COMPOSE_INVENTORY_PATH = "release/RENDERED_COMPOSE_INVENTORY.json"
RELEASE_INPUTS_PATH = "release/STAGED_RELEASE_INPUTS.json"
RELEASE_MANIFEST_PATH = "release/RELEASE_MANIFEST.json"
TREASURY_CHILD_PATH = "release/children/treasury-execution-v3.json"

ARTIFACT_PATHS: dict[str, str] = {
    "card_chain_roots_v1": "artifacts/live/card-chain-roots-v1.json",
    "exact_envelope_v3": "artifacts/live/odra-governance-receipt-v3-exact-envelope-proof.json",
    "historical_odra_receipt_v1": "artifacts/live/historical-odra-receipt-v2.json",
    "native_treasury_execution_v1": "artifacts/live/treasury-execution-v3.json",
    "official_x402_settlement_v1": "artifacts/live/official-x402-settlement-v1.json",
    "proof_registry_v1": "artifacts/live/proof-registry/registry.json",
    "safepay_v2": "artifacts/live/safepay-lite-replaysafe-v2.json",
}

PUBLIC_URLS: dict[str, str] = {
    "custom_apex": "https://concordiadao.xyz/",
    "custom_docs": "https://docs.concordiadao.xyz/",
    "custom_www": "https://www.concordiadao.xyz/",
    "custom_x402": "https://x402.concordiadao.xyz/",
    "sslip_app": "https://concordia.47.84.232.193.sslip.io/",
    "sslip_provider": "https://x402-provider.47.84.232.193.sslip.io/",
}

RPC_PROVIDERS: dict[str, dict[str, str]] = {
    "casper_association": {
        "operator_id": "casper_association",
        "endpoint": "https://node.testnet.casper.network/rpc",
        "authentication": "none",
    },
    "cspr_cloud": {
        "operator_id": "cspr_cloud",
        "endpoint": "https://node.testnet.cspr.cloud/rpc",
        "authentication": "raw_authorization_file",
    },
}

_ARTIFACT_LIMIT = 64 * 1024 * 1024
_CONTROL_LIMIT = 2 * 1024 * 1024
_GIT_OUTPUT_LIMIT = 70 * 1024 * 1024
_GIT40 = re.compile(r"^[0-9a-f]{40}$")
_HEX32 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SERVICE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_SHA512_INTEGRITY = re.compile(r"^sha512-[A-Za-z0-9+/]+={0,2}$")
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$"
)
_FORBIDDEN_STATUS = frozenset(
    {
        "blocked",
        "blocked_fail_closed",
        "error",
        "failed",
        "invalid",
        "not_attempted",
        "pending",
        "stale",
        "unavailable",
        "unknown",
    }
)
_SECRET_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization_header",
        "bearer_token",
        "client_secret",
        "github_token",
        "npm_token",
        "password",
        "private_key",
        "secret",
        "secret_key",
    }
)
_SECRET_TEXT = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|github_pat|npm)_[A-Za-z0-9_]{12,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
)

_HISTORICAL_KEYS = frozenset(
    {
        "schema_version",
        "proposal_id",
        "generation",
        "captured_at",
        "source_commit",
        "deployment_commit",
        "source_url",
        "network",
        "lineage_inventory",
        "contract_identity",
        "card_chain",
        "raw_rpc",
    }
)
_ROOT_KEYS = frozenset({"schema_version", "roots"})
_EXACT_KEYS = frozenset(
    {"schema_id", "deployment", "input", "prepared", "run", "readback"}
)
_TREASURY_KEYS = frozenset(
    {
        "schema_version",
        "captured_at",
        "source_commit",
        "deployment_commit",
        "release_identity",
        "authorization",
        "executor_journal",
        "finality",
        "balance_evidence",
        "bounded_transfer_scan",
        "artifact_sha256_scope",
    }
)
_SAFEPAY_KEYS = frozenset(
    {
        "schema_version",
        "captured_at",
        "source_commit",
        "deployment_commit",
        "quote",
        "consumption",
        "redemption_observations",
        "verification",
    }
)
_OFFICIAL_X402_KEYS = frozenset(
    {
        "schema_version",
        "captured_at",
        "source_commit",
        "deployment_commit",
        "status",
        "governance_binding",
        "payment_requirements",
        "signed_payment_payload",
        "facilitator_verification",
        "settlement",
        "finality",
        "protected_report",
        "fulfillment",
    }
)
_REGISTRY_KEYS = frozenset(
    {"schema_version", "public_items", "internal_records", "card_chain_roots"}
)
_RELEASE_INPUT_KEYS = frozenset(
    {
        "schema_version",
        "captured_at",
        "source_commit",
        "deployment_commit",
        "rendered_compose_inventory_path",
        "rendered_compose_inventory_sha256",
        "compose_semantic_sha256",
        "caddy_semantic_sha256",
        "services",
        "public_urls",
        "docs_pages",
        "npm_package",
        "rpc_providers",
    }
)
_COMPOSE_INVENTORY_KEYS = frozenset(
    {
        "schema_version",
        "captured_at",
        "source_commit",
        "deployment_commit",
        "compose_project",
        "compose_semantic_sha256",
        "services",
    }
)
_INVENTORY_SERVICE_KEYS = frozenset({"service_id", "image_reference", "image_digest"})
_SERVICE_KEYS = frozenset(
    {
        "service_id",
        "image_reference",
        "image_digest",
        "deployment_commit",
        "status",
        "staged_at",
    }
)
_URL_KEYS = frozenset({"url_id", "url", "deployment_commit", "status", "observed_at"})
_DOCS_PAGES_KEYS = frozenset({"status", "deployment_commit", "url", "observed_at"})
_NPM_PACKAGE_KEYS = frozenset(
    {
        "status",
        "name",
        "version",
        "tarball_sha256",
        "integrity",
        "deployment_commit",
        "observed_at",
    }
)
_RPC_PROVIDER_KEYS = frozenset(
    {
        "provider_id",
        "operator_id",
        "endpoint",
        "authentication",
        "status",
        "reviewed_at",
    }
)
_TREASURY_CHILD_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "captured_at",
        "source_commit",
        "deployment_commit",
        "artifact_path",
        "artifact_sha256",
    }
)
_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "generated_at",
        "compose_inventory",
        "release_inputs",
        "artifacts",
        "contract_identity",
        "deployment_surfaces",
        "services",
        "public_urls",
        "treasury_child",
    }
)


class ReleaseManifestError(ValueError):
    """The release cannot be represented as one complete, immutable identity."""


@dataclass(frozen=True)
class _RepositoryRead:
    raw: bytes
    fingerprint: tuple[int, int, int, int]


@dataclass(frozen=True)
class _BoundDocument:
    path: str
    raw: bytes
    document: dict[str, Any]
    canonical: bytes
    sha256: str
    canonical_sha256: str
    artifact_commit: str
    fingerprint: tuple[int, int, int, int]


@dataclass(frozen=True)
class _ArtifactMetadata:
    schema_version: str
    captured_at: str
    source_commit: str
    deployment_commit: str


def _canonical_json(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ReleaseManifestError("document is not canonical JSON") from exc


def _reject_constant(value: str) -> None:
    raise ReleaseManifestError(f"non-finite JSON value {value!r} is forbidden")


def _object_pairs(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseManifestError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strict_json(raw: bytes, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseManifestError(f"{label} is not UTF-8 JSON") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
    except ReleaseManifestError:
        raise
    except json.JSONDecodeError as exc:
        raise ReleaseManifestError(f"{label} is invalid JSON") from exc
    if type(value) is not dict:
        raise ReleaseManifestError(f"{label} must be a JSON object")
    canonical = _canonical_json(value)
    return value, canonical


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        unknown = sorted(actual - expected)
        missing = sorted(expected - actual)
        detail = []
        if unknown:
            detail.append(f"unknown fields {unknown}")
        if missing:
            detail.append(f"missing fields {missing}")
        raise ReleaseManifestError(f"{label} has " + " and ".join(detail))


def _mapping(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ReleaseManifestError(f"{label} must be an object")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise ReleaseManifestError(f"{label} must be a non-empty string")
    return value


def _commit(value: object, label: str) -> str:
    value = _text(value, label)
    if _GIT40.fullmatch(value) is None:
        raise ReleaseManifestError(f"{label} must be lowercase git40")
    return value


def _hash32(value: object, label: str) -> str:
    value = _text(value, label)
    if _HEX32.fullmatch(value) is None:
        raise ReleaseManifestError(f"{label} must be lowercase hex32")
    return value


def _timestamp(value: object, label: str) -> tuple[str, datetime]:
    value = _text(value, label)
    if _TIMESTAMP.fullmatch(value) is None:
        raise ReleaseManifestError(
            f"{label} must be a canonical RFC3339 UTC-Z timestamp"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ReleaseManifestError(f"{label} is not a valid RFC3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ReleaseManifestError(f"{label} must be UTC")
    return value, parsed


def _assert_not_after(value: str, upper: datetime, label: str) -> None:
    _, parsed = _timestamp(value, label)
    if parsed > upper:
        raise ReleaseManifestError(f"{label} is later than manifest generation")


def _assert_no_secret_material(value: object, label: str = "release input") -> None:
    if type(value) is dict:
        for key, nested in value.items():
            lowered = key.lower()
            if lowered in _SECRET_KEYS and nested not in (None, "", [], {}):
                raise ReleaseManifestError(f"{label} contains secret material in {key}")
            if (
                lowered == "authorization"
                and not isinstance(nested, (dict, list))
                and nested
            ):
                raise ReleaseManifestError(f"{label} contains an authorization secret")
            _assert_no_secret_material(nested, f"{label}.{key}")
    elif type(value) is list:
        for index, nested in enumerate(value):
            _assert_no_secret_material(nested, f"{label}[{index}]")
    elif type(value) is str:
        if any(pattern.search(value) for pattern in _SECRET_TEXT):
            raise ReleaseManifestError(f"{label} contains secret material")
        parsed = urlsplit(value)
        if parsed.scheme in {"http", "https"} and (parsed.username or parsed.password):
            raise ReleaseManifestError(
                f"{label} contains credential-bearing URL material"
            )


def _assert_no_unavailable_status(value: object, label: str = "release input") -> None:
    if type(value) is dict:
        for key, nested in value.items():
            if key in {
                "status",
                "verification_status",
                "observation_mode",
                "availability",
            }:
                if type(nested) is str and nested.lower() in _FORBIDDEN_STATUS:
                    raise ReleaseManifestError(
                        f"{label}.{key} has unavailable status {nested!r}"
                    )
            _assert_no_unavailable_status(nested, f"{label}.{key}")
    elif type(value) is list:
        for index, nested in enumerate(value):
            _assert_no_unavailable_status(nested, f"{label}[{index}]")


def _validate_relative_path(relative: str) -> tuple[str, ...]:
    path = PurePosixPath(relative)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or str(path) != relative
    ):
        raise ReleaseManifestError(
            "release path is not a frozen repository-relative path"
        )
    return path.parts


def _root_fd(root: Path) -> int:
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise ReleaseManifestError("repository root is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseManifestError("repository root cannot be a symlink")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(root, flags)
    except OSError as exc:
        raise ReleaseManifestError("repository root cannot be opened safely") from exc


def _read_bounded_repository_file(
    root: Path, relative: str, limit: int
) -> _RepositoryRead:
    parts = _validate_relative_path(relative)
    descriptor = _root_fd(root)
    try:
        for part in parts[:-1]:
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        file_descriptor = os.open(parts[-1], file_flags, dir_fd=descriptor)
        try:
            before = os.fstat(file_descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ReleaseManifestError(
                    f"{relative} must be a regular non-symlink file"
                )
            if before.st_size > limit:
                raise ReleaseManifestError(f"{relative} exceeds its size bound")
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining:
                chunk = os.read(file_descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > limit:
                raise ReleaseManifestError(f"{relative} exceeds its size bound")
            after = os.fstat(file_descriptor)
            fingerprint = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            if fingerprint != (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ):
                raise ReleaseManifestError(f"{relative} changed during assembly")
            return _RepositoryRead(raw=raw, fingerprint=fingerprint)
        finally:
            os.close(file_descriptor)
    except FileNotFoundError as exc:
        raise ReleaseManifestError(
            f"required artifact {relative} is unavailable"
        ) from exc
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ReleaseManifestError(f"{relative} contains or is a symlink") from exc
        raise ReleaseManifestError(f"{relative} cannot be read safely") from exc
    finally:
        os.close(descriptor)


def _repository_file_exists(root: Path, relative: str) -> bool:
    try:
        _read_bounded_repository_file(root, relative, _CONTROL_LIMIT)
    except ReleaseManifestError as exc:
        if "required artifact" in str(exc) and "unavailable" in str(exc):
            return False
        raise
    return True


def _git(
    root: Path,
    arguments: Sequence[str],
    *,
    check: bool = True,
    limit: int = _GIT_OUTPUT_LIMIT,
) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseManifestError("Git provenance check failed") from exc
    if len(completed.stdout) > limit or len(completed.stderr) > _CONTROL_LIMIT:
        raise ReleaseManifestError("Git provenance output exceeded its bound")
    if check and completed.returncode != 0:
        raise ReleaseManifestError("Git provenance check failed")
    return completed


def _require_repository(root: Path) -> None:
    top = _git(root, ["rev-parse", "--show-toplevel"], limit=_CONTROL_LIMIT).stdout
    try:
        top_path = Path(top.decode("utf-8").strip())
    except UnicodeDecodeError as exc:
        raise ReleaseManifestError("Git repository path is not UTF-8") from exc
    if top_path != root.absolute():
        raise ReleaseManifestError(
            "repository root must be the exact Git worktree root"
        )


def _require_clean_worktree(root: Path) -> None:
    status = _git(
        root,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        limit=_CONTROL_LIMIT,
    ).stdout
    if status:
        raise ReleaseManifestError(
            "Git worktree is not clean; untracked bytes are forbidden"
        )


def _latest_path_commit(root: Path, relative: str) -> str:
    output = (
        _git(
            root,
            ["log", "-1", "--format=%H", "HEAD", "--", relative],
            limit=_CONTROL_LIMIT,
        )
        .stdout.decode("ascii", errors="strict")
        .strip()
    )
    if _GIT40.fullmatch(output) is None:
        raise ReleaseManifestError(f"{relative} has no immutable artifact commit")
    return output


def _git_blob(root: Path, commit: str, relative: str, limit: int) -> bytes:
    tree = _git(
        root,
        ["ls-tree", "-z", "--full-tree", commit, "--", relative],
        limit=_CONTROL_LIMIT,
    ).stdout
    entries = [entry for entry in tree.split(b"\0") if entry]
    if len(entries) != 1:
        raise ReleaseManifestError(
            f"{relative} is not uniquely tracked at artifact commit"
        )
    try:
        metadata, encoded_path = entries[0].split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split(" ")
        tracked_path = encoded_path.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ReleaseManifestError("Git tree entry is malformed") from exc
    if (
        tracked_path != relative
        or object_type != "blob"
        or mode not in {"100644", "100755"}
        or _GIT40.fullmatch(object_id) is None
    ):
        raise ReleaseManifestError(f"{relative} is not a regular tracked artifact")
    size_raw = _git(root, ["cat-file", "-s", object_id], limit=_CONTROL_LIMIT).stdout
    try:
        size = int(size_raw.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError) as exc:
        raise ReleaseManifestError("Git artifact size is malformed") from exc
    if size < 0 or size > limit:
        raise ReleaseManifestError(f"{relative} committed blob exceeds its size bound")
    raw = _git(root, ["cat-file", "blob", object_id], limit=limit + 1).stdout
    if len(raw) != size:
        raise ReleaseManifestError(f"{relative} committed blob size changed")
    return raw


def _is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    result = _git(
        root,
        ["merge-base", "--is-ancestor", ancestor, descendant],
        check=False,
        limit=_CONTROL_LIMIT,
    )
    if result.returncode not in {0, 1}:
        raise ReleaseManifestError("Git ancestry check failed")
    return result.returncode == 0


def _require_ancestry(root: Path, source: str, deployment: str, artifact: str) -> None:
    if not _is_ancestor(root, source, artifact):
        raise ReleaseManifestError(
            "source_commit is not an ancestor of artifact_commit"
        )
    if not _is_ancestor(root, deployment, artifact):
        raise ReleaseManifestError(
            "deployment_commit is not an ancestor of artifact_commit"
        )
    if not _is_ancestor(root, artifact, "HEAD"):
        raise ReleaseManifestError("artifact_commit is not an ancestor of release HEAD")


def _load_bound_document(
    root: Path,
    relative: str,
    *,
    label: str,
    limit: int,
    canonical_source_required: bool = False,
) -> _BoundDocument:
    read = _read_bounded_repository_file(root, relative, limit)
    document, canonical = _strict_json(read.raw, label)
    if canonical_source_required and read.raw != canonical:
        raise ReleaseManifestError(
            f"{label} must use canonical JSON with one terminal LF"
        )
    _assert_no_secret_material(document, label)
    artifact_commit = _latest_path_commit(root, relative)
    committed = _git_blob(root, artifact_commit, relative, limit)
    if committed != read.raw:
        raise ReleaseManifestError(
            f"{relative} committed bytes differ from worktree bytes"
        )
    return _BoundDocument(
        path=relative,
        raw=read.raw,
        document=document,
        canonical=canonical,
        sha256=hashlib.sha256(read.raw).hexdigest(),
        canonical_sha256=hashlib.sha256(canonical).hexdigest(),
        artifact_commit=artifact_commit,
        fingerprint=read.fingerprint,
    )


def _common_metadata(
    document: Mapping[str, Any],
    *,
    expected_schema: str,
    schema_field: str = "schema_version",
) -> _ArtifactMetadata:
    if document.get(schema_field) != expected_schema:
        raise ReleaseManifestError(f"artifact schema must be {expected_schema}")
    captured_at, _ = _timestamp(document.get("captured_at"), "artifact captured_at")
    return _ArtifactMetadata(
        schema_version=expected_schema,
        captured_at=captured_at,
        source_commit=_commit(document.get("source_commit"), "artifact source_commit"),
        deployment_commit=_commit(
            document.get("deployment_commit"), "artifact deployment_commit"
        ),
    )


def _historical_metadata(document: Mapping[str, Any]) -> _ArtifactMetadata:
    _exact_keys(document, _HISTORICAL_KEYS, "historical Odra artifact")
    if document.get("generation") != "v1" or document.get("network") != "casper-test":
        raise ReleaseManifestError(
            "historical Odra artifact is not the frozen v1 Testnet proof"
        )
    return _common_metadata(
        document, expected_schema="concordia.historical_odra_receipt.v1"
    )


def _roots_metadata(
    document: Mapping[str, Any], historical: _ArtifactMetadata
) -> _ArtifactMetadata:
    _exact_keys(document, _ROOT_KEYS, "card-chain roots")
    if document.get("schema_version") != "concordia.card_chain_roots.v1":
        raise ReleaseManifestError("card-chain roots schema is invalid")
    roots = _mapping(document.get("roots"), "card-chain roots.roots")
    if not roots or any(
        type(key) is not str or _HEX32.fullmatch(str(value)) is None
        for key, value in roots.items()
    ):
        raise ReleaseManifestError("card-chain roots contain an invalid identity")
    return _ArtifactMetadata(
        schema_version="concordia.card_chain_roots.v1",
        captured_at=historical.captured_at,
        source_commit=historical.source_commit,
        deployment_commit=historical.deployment_commit,
    )


def _exact_v3_metadata(
    document: Mapping[str, Any],
) -> tuple[_ArtifactMetadata, dict[str, Any]]:
    _exact_keys(document, _EXACT_KEYS, "exact-envelope v3 artifact")
    if document.get("schema_id") != "concordia.v3-proof.v1":
        raise ReleaseManifestError("exact-envelope v3 artifact schema is invalid")
    deployment = _mapping(document.get("deployment"), "v3 deployment")
    run = _mapping(document.get("run"), "v3 run")
    if (
        deployment.get("status") != "finalized"
        or run.get("status") != "contract_sequence_verified"
    ):
        raise ReleaseManifestError("v3 deployment and choreography must be finalized")
    if run.get("network") not in (None, "casper-test"):
        raise ReleaseManifestError("v3 proof network is not casper-test")
    steps = run.get("steps")
    if type(steps) is not list:
        raise ReleaseManifestError("v3 run steps are missing")
    observed: list[tuple[datetime, str]] = []
    finalize_count = 0
    for step in steps:
        if type(step) is not dict:
            raise ReleaseManifestError("v3 run step is invalid")
        if step.get("name") == "finalize_exact":
            finalize_count += 1
        evidence = step.get("finality_block_evidence")
        if type(evidence) is dict and "observed_at" in evidence:
            timestamp, parsed = _timestamp(evidence["observed_at"], "v3 observation")
            observed.append((parsed, timestamp))
    if finalize_count != 1 or not observed:
        raise ReleaseManifestError("v3 proof lacks one observed exact finalization")
    captured_at = max(observed)[1]
    source_commit = _commit(deployment.get("source_commit"), "v3 source_commit")
    deployment_commit = _commit(
        deployment.get("deployment_commit"), "v3 deployment_commit"
    )
    contract_identity = {
        "network": "casper-test",
        "package_hash": _hash32(deployment.get("package_hash"), "v3 package_hash"),
        "identity_kind": "contract_hash",
        "entity_or_contract_hash": _hash32(
            deployment.get("contract_hash"), "v3 contract_hash"
        ),
        "contract_version": deployment.get("contract_version"),
        "install_deploy_hash": _hash32(
            deployment.get("install_deploy_hash"), "v3 install_deploy_hash"
        ),
        "install_block_hash": _hash32(
            deployment.get("install_block_hash"), "v3 install_block_hash"
        ),
        "install_block_height": deployment.get("install_block_height"),
    }
    if (
        type(contract_identity["contract_version"]) is not int
        or contract_identity["contract_version"] < 1
        or type(contract_identity["install_block_height"]) is not int
        or contract_identity["install_block_height"] < 1
    ):
        raise ReleaseManifestError("v3 contract version or install block is invalid")
    return (
        _ArtifactMetadata(
            schema_version="concordia.v3-proof.v1",
            captured_at=captured_at,
            source_commit=source_commit,
            deployment_commit=deployment_commit,
        ),
        contract_identity,
    )


def _registry_metadata(
    document: Mapping[str, Any],
    *,
    release_source_commit: str,
    release_deployment_commit: str,
    roots_sha256: str,
    artifact_bindings: Mapping[str, tuple[str, str, str]],
) -> _ArtifactMetadata:
    _exact_keys(document, _REGISTRY_KEYS, "proof registry")
    if document.get("schema_version") != 1:
        raise ReleaseManifestError("proof registry schema is invalid")
    roots = _mapping(document.get("card_chain_roots"), "registry card-chain roots")
    if set(roots) != {"artifact_path", "artifact_sha256"}:
        raise ReleaseManifestError("registry card-chain roots fields are invalid")
    if (
        roots.get("artifact_path") != ARTIFACT_PATHS["card_chain_roots_v1"]
        or roots.get("artifact_sha256") != roots_sha256
    ):
        raise ReleaseManifestError(
            "proof registry is not bound to canonical card-chain roots"
        )
    public_items = document.get("public_items")
    if type(public_items) is not list:
        raise ReleaseManifestError("proof registry public_items are invalid")
    required = {
        "historical_odra_receipt_v2",
        "exact_envelope_v3",
        "native_treasury_execution_v1",
        "safepay_v2",
        "official_x402_settlement_v1",
    }
    seen: set[str] = set()
    captures: list[tuple[datetime, str]] = []
    for item in public_items:
        item = _mapping(item, "proof registry item")
        proof_type = _text(item.get("proof_type"), "proof registry proof_type")
        if proof_type in seen:
            raise ReleaseManifestError(
                "proof registry contains duplicate proof identity"
            )
        seen.add(proof_type)
        if item.get("verification_status") != "verified":
            raise ReleaseManifestError(
                "proof registry contains an unavailable proof status"
            )
        if item.get("observation_mode") not in {"live", "snapshot"}:
            raise ReleaseManifestError(
                "proof registry contains an unavailable observation"
            )
        expected_binding = artifact_bindings.get(proof_type)
        if (
            expected_binding is None
            or (
                item.get("artifact_path"),
                item.get("artifact_sha256"),
                item.get("schema_version"),
            )
            != expected_binding
        ):
            raise ReleaseManifestError(
                "proof registry artifact binding differs from fixed release artifact"
            )
        captured, parsed = _timestamp(item.get("captured_at"), "proof item captured_at")
        captures.append((parsed, captured))
        _commit(item.get("source_commit"), "proof item source_commit")
        _commit(item.get("deployment_commit"), "proof item deployment_commit")
    if seen != required:
        raise ReleaseManifestError(
            "proof registry does not contain the exact required release proofs"
        )
    if not captures:
        raise ReleaseManifestError("proof registry contains no captured proof")
    return _ArtifactMetadata(
        schema_version="concordia.proof_registry.v1",
        captured_at=max(captures)[1],
        source_commit=release_source_commit,
        deployment_commit=release_deployment_commit,
    )


def _image_identity(value: Mapping[str, Any], label: str) -> tuple[str, str, str]:
    service_id = _text(value.get("service_id"), f"{label} service_id")
    if _SERVICE_ID.fullmatch(service_id) is None:
        raise ReleaseManifestError(f"{label} service_id is invalid")
    image_reference = _text(value.get("image_reference"), f"{label} image_reference")
    if "@" in image_reference or any(char.isspace() for char in image_reference):
        raise ReleaseManifestError(
            f"{label} image_reference must not embed a digest or whitespace"
        )
    digest = _text(value.get("image_digest"), f"{label} image_digest")
    if _IMAGE_DIGEST.fullmatch(digest) is None:
        raise ReleaseManifestError(f"{label} image_digest must be sha256:hex32")
    return service_id, image_reference, digest


def _validate_compose_inventory(
    document: Mapping[str, Any], generated_time: datetime
) -> tuple[_ArtifactMetadata, list[dict[str, Any]], str]:
    _exact_keys(document, _COMPOSE_INVENTORY_KEYS, "rendered Compose inventory")
    metadata = _common_metadata(
        document, expected_schema="concordia.rendered_compose_inventory.v1"
    )
    _assert_not_after(
        metadata.captured_at, generated_time, "rendered Compose inventory captured_at"
    )
    if document.get("compose_project") != "concordia":
        raise ReleaseManifestError(
            "rendered Compose inventory is not project concordia"
        )
    semantic_sha256 = _hash32(
        document.get("compose_semantic_sha256"), "Compose semantic SHA-256"
    )
    services = document.get("services")
    if type(services) is not list or not services:
        raise ReleaseManifestError("rendered Compose inventory has no services")
    normalized: list[dict[str, Any]] = []
    identities: set[str] = set()
    for service in services:
        service = _mapping(service, "rendered Compose service")
        _exact_keys(service, _INVENTORY_SERVICE_KEYS, "rendered Compose service")
        service_id, _, _ = _image_identity(service, "rendered Compose service")
        if service_id in identities:
            raise ReleaseManifestError("duplicate rendered Compose service identity")
        identities.add(service_id)
        normalized.append(dict(service))
    return (
        metadata,
        sorted(normalized, key=lambda item: item["service_id"]),
        semantic_sha256,
    )


def _validate_release_inputs(
    document: Mapping[str, Any],
    generated_time: datetime,
    *,
    compose_inventory: _BoundDocument,
    inventory_services: Sequence[Mapping[str, Any]],
    inventory_semantic_sha256: str,
) -> tuple[
    _ArtifactMetadata,
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any],
]:
    _exact_keys(document, _RELEASE_INPUT_KEYS, "staged release inputs")
    metadata = _common_metadata(
        document, expected_schema="concordia.staged_release_inputs.v1"
    )
    _assert_not_after(metadata.captured_at, generated_time, "release input captured_at")
    if document.get("rendered_compose_inventory_path") != COMPOSE_INVENTORY_PATH:
        raise ReleaseManifestError("rendered Compose inventory path is not frozen")
    if document.get("rendered_compose_inventory_sha256") != compose_inventory.sha256:
        raise ReleaseManifestError("rendered Compose inventory SHA-256 differs")
    compose_semantic_sha256 = _hash32(
        document.get("compose_semantic_sha256"), "Compose semantic SHA-256"
    )
    if compose_semantic_sha256 != inventory_semantic_sha256:
        raise ReleaseManifestError(
            "Compose semantic SHA-256 differs from rendered inventory"
        )
    caddy_semantic_sha256 = _hash32(
        document.get("caddy_semantic_sha256"), "Caddy semantic SHA-256"
    )
    services = document.get("services")
    if type(services) is not list:
        raise ReleaseManifestError("staged services must be a list")
    normalized_services: list[dict[str, Any]] = []
    seen_services: set[str] = set()
    for service in services:
        service = _mapping(service, "staged service")
        _exact_keys(service, _SERVICE_KEYS, "staged service")
        service_id, _, _ = _image_identity(service, "staged service")
        if service_id in seen_services:
            raise ReleaseManifestError("duplicate service identity")
        seen_services.add(service_id)
        if service.get("status") != "staged":
            raise ReleaseManifestError(f"service {service_id} is not staged")
        if service.get("deployment_commit") != metadata.deployment_commit:
            raise ReleaseManifestError("service deployment_commit differs from release")
        staged_at, _ = _timestamp(service.get("staged_at"), "service staged_at")
        _assert_not_after(staged_at, generated_time, "service staged_at")
        normalized_services.append(dict(service))
    expected_services = {
        (
            str(service["service_id"]),
            str(service["image_reference"]),
            str(service["image_digest"]),
        )
        for service in inventory_services
    }
    staged_services = {
        (
            str(service["service_id"]),
            str(service["image_reference"]),
            str(service["image_digest"]),
        )
        for service in normalized_services
    }
    if staged_services != expected_services:
        raise ReleaseManifestError(
            "staged services differ from the fixed committed rendered Compose inventory"
        )

    urls = document.get("public_urls")
    if type(urls) is not list:
        raise ReleaseManifestError("public URLs must be a list")
    normalized_urls: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    for item in urls:
        item = _mapping(item, "public URL")
        _exact_keys(item, _URL_KEYS, "public URL")
        url_id = _text(item.get("url_id"), "url_id")
        if url_id in seen_urls:
            raise ReleaseManifestError("duplicate public URL identity")
        seen_urls.add(url_id)
        if item.get("status") != "available":
            raise ReleaseManifestError(f"public URL {url_id} is unavailable")
        if item.get("deployment_commit") != metadata.deployment_commit:
            raise ReleaseManifestError(
                "public URL deployment_commit differs from release"
            )
        if PUBLIC_URLS.get(url_id) != item.get("url"):
            raise ReleaseManifestError(
                "public URL identity differs from the frozen allowlist"
            )
        observed_at, _ = _timestamp(item.get("observed_at"), "public URL observed_at")
        _assert_not_after(observed_at, generated_time, "public URL observed_at")
        normalized_urls.append(dict(item))
    if seen_urls != set(PUBLIC_URLS):
        raise ReleaseManifestError(
            "public URL identities do not match the frozen allowlist"
        )

    docs_pages = _mapping(document.get("docs_pages"), "Pages/docs deployment")
    _exact_keys(docs_pages, _DOCS_PAGES_KEYS, "Pages/docs deployment")
    if (
        docs_pages.get("status") != "deployed"
        or docs_pages.get("url") != PUBLIC_URLS["custom_docs"]
    ):
        raise ReleaseManifestError("Pages/docs deployment is unavailable")
    docs_commit = _commit(
        docs_pages.get("deployment_commit"), "Pages/docs deployment_commit"
    )
    if docs_commit != metadata.deployment_commit:
        raise ReleaseManifestError("Pages/docs deployment_commit differs from release")
    docs_observed, _ = _timestamp(
        docs_pages.get("observed_at"), "Pages/docs observed_at"
    )
    _assert_not_after(docs_observed, generated_time, "Pages/docs observed_at")

    npm_package = _mapping(document.get("npm_package"), "npm package")
    _exact_keys(npm_package, _NPM_PACKAGE_KEYS, "npm package")
    if (
        npm_package.get("status") != "published"
        or npm_package.get("name") != "@concordia-dao/verify"
    ):
        raise ReleaseManifestError("npm package identity is unavailable or incorrect")
    version = _text(npm_package.get("version"), "npm package version")
    if _SEMVER.fullmatch(version) is None:
        raise ReleaseManifestError("npm package version is not exact SemVer")
    _hash32(npm_package.get("tarball_sha256"), "npm package tarball SHA-256")
    integrity = _text(npm_package.get("integrity"), "npm package integrity")
    if _SHA512_INTEGRITY.fullmatch(integrity) is None:
        raise ReleaseManifestError("npm package integrity is not sha512 SRI")
    try:
        integrity_bytes = base64.b64decode(
            integrity.removeprefix("sha512-"), validate=True
        )
    except (binascii.Error, ValueError) as exc:
        raise ReleaseManifestError("npm package integrity is invalid base64") from exc
    if len(integrity_bytes) != 64:
        raise ReleaseManifestError("npm package integrity is not a SHA-512 digest")
    npm_commit = _commit(
        npm_package.get("deployment_commit"), "npm package deployment_commit"
    )
    if npm_commit != metadata.deployment_commit:
        raise ReleaseManifestError("npm package deployment_commit differs from release")
    npm_observed, _ = _timestamp(
        npm_package.get("observed_at"), "npm package observed_at"
    )
    _assert_not_after(npm_observed, generated_time, "npm package observed_at")

    providers = document.get("rpc_providers")
    if type(providers) is not list:
        raise ReleaseManifestError("RPC providers must be a list")
    normalized_providers: list[dict[str, Any]] = []
    seen_providers: set[str] = set()
    seen_operators: set[str] = set()
    for provider in providers:
        provider = _mapping(provider, "RPC provider")
        _exact_keys(provider, _RPC_PROVIDER_KEYS, "RPC provider")
        provider_id = _text(provider.get("provider_id"), "RPC provider_id")
        operator_id = _text(provider.get("operator_id"), "RPC operator_id")
        if provider_id in seen_providers:
            raise ReleaseManifestError("duplicate RPC provider identity")
        if operator_id in seen_operators:
            raise ReleaseManifestError("RPC provider operators are not independent")
        seen_providers.add(provider_id)
        seen_operators.add(operator_id)
        frozen = RPC_PROVIDERS.get(provider_id)
        if (
            frozen is None
            or provider.get("operator_id") != frozen["operator_id"]
            or provider.get("endpoint") != frozen["endpoint"]
            or provider.get("authentication") != frozen["authentication"]
            or provider.get("status") != "reviewed"
        ):
            raise ReleaseManifestError("RPC provider identity is not the reviewed pair")
        reviewed_at, _ = _timestamp(provider.get("reviewed_at"), "RPC reviewed_at")
        _assert_not_after(reviewed_at, generated_time, "RPC reviewed_at")
        normalized_providers.append(dict(provider))
    if seen_providers != set(RPC_PROVIDERS) or len(seen_operators) != len(
        RPC_PROVIDERS
    ):
        raise ReleaseManifestError(
            "RPC provider identities do not prove operator separation"
        )

    deployment_surfaces = {
        "compose_semantic_sha256": compose_semantic_sha256,
        "caddy_semantic_sha256": caddy_semantic_sha256,
        "docs_pages": dict(docs_pages),
        "npm_package": dict(npm_package),
        "rpc_providers": sorted(
            normalized_providers, key=lambda value: value["provider_id"]
        ),
    }
    return (
        metadata,
        sorted(normalized_services, key=lambda value: value["service_id"]),
        sorted(normalized_urls, key=lambda value: value["url_id"]),
        deployment_surfaces,
    )


def _entry(
    artifact_id: str, bound: _BoundDocument, metadata: _ArtifactMetadata
) -> dict[str, Any]:
    return {
        "artifact_id": artifact_id,
        "path": bound.path,
        "sha256": bound.sha256,
        "canonical_sha256": bound.canonical_sha256,
        "schema_version": metadata.schema_version,
        "captured_at": metadata.captured_at,
        "source_commit": metadata.source_commit,
        "deployment_commit": metadata.deployment_commit,
        "artifact_commit": bound.artifact_commit,
    }


def _load_treasury_child(
    root: Path,
    *,
    generated_time: datetime,
    treasury: _BoundDocument,
) -> tuple[dict[str, Any] | None, _BoundDocument | None]:
    if not _repository_file_exists(root, TREASURY_CHILD_PATH):
        return None, None
    child = _load_bound_document(
        root,
        TREASURY_CHILD_PATH,
        label="treasury child manifest",
        limit=_CONTROL_LIMIT,
        canonical_source_required=True,
    )
    document = child.document
    _exact_keys(document, _TREASURY_CHILD_KEYS, "treasury child manifest")
    if document.get("schema_version") != "concordia.treasury_release_child.v1":
        raise ReleaseManifestError("treasury child manifest schema is invalid")
    if document.get("status") != "ready":
        raise ReleaseManifestError("treasury child manifest is not ready")
    captured_at, _ = _timestamp(
        document.get("captured_at"), "treasury child captured_at"
    )
    _assert_not_after(captured_at, generated_time, "treasury child captured_at")
    source_commit = _commit(
        document.get("source_commit"), "treasury child source_commit"
    )
    deployment_commit = _commit(
        document.get("deployment_commit"), "treasury child deployment_commit"
    )
    if document.get("artifact_path") != ARTIFACT_PATHS["native_treasury_execution_v1"]:
        raise ReleaseManifestError("treasury child artifact path is not frozen")
    if document.get("artifact_sha256") != treasury.sha256:
        raise ReleaseManifestError("treasury child artifact SHA-256 does not match")
    _require_ancestry(root, source_commit, deployment_commit, child.artifact_commit)
    return (
        {
            "path": child.path,
            "sha256": child.sha256,
            "schema_version": "concordia.treasury_release_child.v1",
            "status": "ready",
            "captured_at": captured_at,
            "source_commit": source_commit,
            "deployment_commit": deployment_commit,
            "artifact_commit": child.artifact_commit,
            "artifact_path": document["artifact_path"],
            "artifact_sha256": document["artifact_sha256"],
        },
        child,
    )


def _assert_unchanged(root: Path, bound: _BoundDocument, limit: int) -> None:
    latest = _read_bounded_repository_file(root, bound.path, limit)
    if latest.fingerprint != bound.fingerprint or latest.raw != bound.raw:
        raise ReleaseManifestError(f"{bound.path} changed during assembly")


def build_release_manifest(repository_root: str | Path, *, generated_at: str) -> bytes:
    """Return one canonical ready manifest from fixed, already-committed inputs."""

    root = Path(repository_root).absolute()
    _require_repository(root)
    _require_clean_worktree(root)
    generated_at, generated_time = _timestamp(generated_at, "generated_at")
    if generated_time > datetime.now(UTC):
        raise ReleaseManifestError("generated_at cannot be in the future")

    compose_inventory = _load_bound_document(
        root,
        COMPOSE_INVENTORY_PATH,
        label="rendered Compose inventory",
        limit=_CONTROL_LIMIT,
        canonical_source_required=True,
    )
    inventory_metadata, inventory_services, inventory_semantic_sha256 = (
        _validate_compose_inventory(compose_inventory.document, generated_time)
    )
    _require_ancestry(
        root,
        inventory_metadata.source_commit,
        inventory_metadata.deployment_commit,
        compose_inventory.artifact_commit,
    )
    release_inputs = _load_bound_document(
        root,
        RELEASE_INPUTS_PATH,
        label="staged release inputs",
        limit=_CONTROL_LIMIT,
        canonical_source_required=True,
    )
    release_metadata, services, public_urls, deployment_surfaces = (
        _validate_release_inputs(
            release_inputs.document,
            generated_time,
            compose_inventory=compose_inventory,
            inventory_services=inventory_services,
            inventory_semantic_sha256=inventory_semantic_sha256,
        )
    )
    if (
        inventory_metadata.source_commit != release_metadata.source_commit
        or inventory_metadata.deployment_commit != release_metadata.deployment_commit
    ):
        raise ReleaseManifestError(
            "rendered Compose inventory and staged inputs do not bind the same ancestor commits"
        )
    _require_ancestry(
        root,
        release_metadata.source_commit,
        release_metadata.deployment_commit,
        release_inputs.artifact_commit,
    )

    bound: dict[str, _BoundDocument] = {}
    for artifact_id, path in ARTIFACT_PATHS.items():
        bound[artifact_id] = _load_bound_document(
            root,
            path,
            label=artifact_id,
            limit=_ARTIFACT_LIMIT,
        )

    metadata: dict[str, _ArtifactMetadata] = {}
    metadata["historical_odra_receipt_v1"] = _historical_metadata(
        bound["historical_odra_receipt_v1"].document
    )
    metadata["card_chain_roots_v1"] = _roots_metadata(
        bound["card_chain_roots_v1"].document,
        metadata["historical_odra_receipt_v1"],
    )
    metadata["exact_envelope_v3"], contract_identity = _exact_v3_metadata(
        bound["exact_envelope_v3"].document
    )
    treasury_document = bound["native_treasury_execution_v1"].document
    _exact_keys(treasury_document, _TREASURY_KEYS, "native treasury artifact")
    metadata["native_treasury_execution_v1"] = _common_metadata(
        treasury_document,
        expected_schema="concordia.native_treasury_execution.v1",
    )
    safepay_document = bound["safepay_v2"].document
    _exact_keys(safepay_document, _SAFEPAY_KEYS, "SafePay v2 artifact")
    metadata["safepay_v2"] = _common_metadata(
        safepay_document, expected_schema="safepay-v2"
    )
    official_document = bound["official_x402_settlement_v1"].document
    _exact_keys(
        official_document, _OFFICIAL_X402_KEYS, "official x402 settlement artifact"
    )
    if official_document.get("status") != "verified":
        raise ReleaseManifestError("official x402 settlement artifact is not verified")
    metadata["official_x402_settlement_v1"] = _common_metadata(
        official_document,
        expected_schema="concordia.official_x402_settlement.v1",
    )
    metadata["proof_registry_v1"] = _registry_metadata(
        bound["proof_registry_v1"].document,
        release_source_commit=release_metadata.source_commit,
        release_deployment_commit=release_metadata.deployment_commit,
        roots_sha256=bound["card_chain_roots_v1"].sha256,
        artifact_bindings={
            "historical_odra_receipt_v2": (
                ARTIFACT_PATHS["historical_odra_receipt_v1"],
                bound["historical_odra_receipt_v1"].sha256,
                "concordia.historical_odra_receipt.v1",
            ),
            "exact_envelope_v3": (
                ARTIFACT_PATHS["exact_envelope_v3"],
                bound["exact_envelope_v3"].sha256,
                "concordia.v3-proof.v1",
            ),
            "native_treasury_execution_v1": (
                ARTIFACT_PATHS["native_treasury_execution_v1"],
                bound["native_treasury_execution_v1"].sha256,
                "concordia.native_treasury_execution.v1",
            ),
            "safepay_v2": (
                ARTIFACT_PATHS["safepay_v2"],
                bound["safepay_v2"].sha256,
                "safepay-v2",
            ),
            "official_x402_settlement_v1": (
                ARTIFACT_PATHS["official_x402_settlement_v1"],
                bound["official_x402_settlement_v1"].sha256,
                "concordia.official_x402_settlement.v1",
            ),
        },
    )

    artifacts: list[dict[str, Any]] = []
    artifact_hashes: set[str] = set()
    for artifact_id in sorted(ARTIFACT_PATHS):
        item = _entry(artifact_id, bound[artifact_id], metadata[artifact_id])
        _assert_not_after(
            item["captured_at"], generated_time, f"{artifact_id} captured_at"
        )
        _require_ancestry(
            root,
            item["source_commit"],
            item["deployment_commit"],
            item["artifact_commit"],
        )
        if item["sha256"] in artifact_hashes:
            raise ReleaseManifestError("duplicate artifact identity")
        artifact_hashes.add(item["sha256"])
        artifacts.append(item)

    treasury_child, child_bound = _load_treasury_child(
        root,
        generated_time=generated_time,
        treasury=bound["native_treasury_execution_v1"],
    )
    release_input_entry = {
        "path": release_inputs.path,
        "sha256": release_inputs.sha256,
        "schema_version": release_metadata.schema_version,
        "captured_at": release_metadata.captured_at,
        "source_commit": release_metadata.source_commit,
        "deployment_commit": release_metadata.deployment_commit,
        "artifact_commit": release_inputs.artifact_commit,
    }
    compose_inventory_entry = {
        "path": compose_inventory.path,
        "sha256": compose_inventory.sha256,
        "canonical_sha256": compose_inventory.canonical_sha256,
        "schema_version": inventory_metadata.schema_version,
        "captured_at": inventory_metadata.captured_at,
        "source_commit": inventory_metadata.source_commit,
        "deployment_commit": inventory_metadata.deployment_commit,
        "artifact_commit": compose_inventory.artifact_commit,
        "compose_project": "concordia",
        "compose_semantic_sha256": inventory_semantic_sha256,
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "status": "ready",
        "generated_at": generated_at,
        "compose_inventory": compose_inventory_entry,
        "release_inputs": release_input_entry,
        "artifacts": artifacts,
        "contract_identity": contract_identity,
        "deployment_surfaces": deployment_surfaces,
        "services": services,
        "public_urls": public_urls,
        "treasury_child": treasury_child,
    }
    _assert_no_secret_material(manifest, "release manifest")
    _assert_no_unavailable_status(manifest, "release manifest")

    _assert_unchanged(root, compose_inventory, _CONTROL_LIMIT)
    _assert_unchanged(root, release_inputs, _CONTROL_LIMIT)
    for item in bound.values():
        _assert_unchanged(root, item, _ARTIFACT_LIMIT)
    if child_bound is not None:
        _assert_unchanged(root, child_bound, _CONTROL_LIMIT)
    _require_clean_worktree(root)
    return _canonical_json(manifest)


def _validate_ready_manifest_payload(payload: bytes) -> None:
    document, canonical = _strict_json(payload, "release manifest")
    if payload != canonical:
        raise ReleaseManifestError("release manifest payload is not canonical JSON")
    _exact_keys(document, _MANIFEST_KEYS, "release manifest")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise ReleaseManifestError("release manifest schema is invalid")
    if document.get("status") != "ready":
        raise ReleaseManifestError("release manifest status must be ready")
    if "manifest_commit" in document:
        raise ReleaseManifestError(
            "release manifest cannot self-reference a future commit"
        )
    _assert_no_secret_material(document, "release manifest")
    _assert_no_unavailable_status(document, "release manifest")


def write_release_manifest_once(repository_root: str | Path, payload: bytes) -> Path:
    """Atomically create the fixed release path once, mode 0600, with fsync."""

    _validate_ready_manifest_payload(payload)
    root = Path(repository_root).absolute()
    _require_repository(root)
    release_parts = _validate_relative_path(RELEASE_MANIFEST_PATH)
    if len(release_parts) != 2:
        raise ReleaseManifestError("release manifest path is not frozen")
    root_descriptor = _root_fd(root)
    directory_descriptor: int | None = None
    temporary_name: str | None = None
    try:
        directory_descriptor = os.open(
            release_parts[0],
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_descriptor,
        )
        temporary_name = f".{release_parts[1]}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise ReleaseManifestError(
                        "release manifest write made no progress"
                    )
                view = view[written:]
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.link(
                temporary_name,
                release_parts[1],
                src_dir_fd=directory_descriptor,
                dst_dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise ReleaseManifestError("release manifest already exists") from exc
        os.fsync(directory_descriptor)
    except ReleaseManifestError:
        raise
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ReleaseManifestError(
                "release manifest path contains a symlink"
            ) from exc
        raise ReleaseManifestError("release manifest atomic write failed") from exc
    finally:
        if directory_descriptor is not None and temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
            except FileNotFoundError:
                pass
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        os.close(root_descriptor)
    return root / RELEASE_MANIFEST_PATH


__all__ = [
    "ARTIFACT_PATHS",
    "COMPOSE_INVENTORY_PATH",
    "PUBLIC_URLS",
    "RPC_PROVIDERS",
    "RELEASE_INPUTS_PATH",
    "RELEASE_MANIFEST_PATH",
    "SCHEMA_VERSION",
    "TREASURY_CHILD_PATH",
    "ReleaseManifestError",
    "build_release_manifest",
    "write_release_manifest_once",
]
