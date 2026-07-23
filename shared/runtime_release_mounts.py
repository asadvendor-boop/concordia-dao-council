"""Fail-closed validation for release-scoped runtime proof mounts.

The Python image deliberately contains no ``artifacts/`` bytes.  Production
must provide one immutable release artifact tree plus exactly one selected
proof-registry directory.  The latter is a separate nested bind so the
official-x402 pre-settlement registry can be selected without ever loading it
beside the final registry.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from shared.card_chain_artifact import (
    CardChainRootsError,
    load_card_chain_release_roots,
)
from shared.proof_registry import validate_registry_document


MAX_REGISTRY_BYTES = 8 * 1024 * 1024
MAX_RELEASE_ARTIFACT_BYTES = 64 * 1024 * 1024
REQUIRED_RUNTIME_ARTIFACTS = (
    "live/card-chain-roots-v1.json",
    "live/casper-final-receipt-cspr-live.json",
    "live/odra-quorum-exercise-plan.json",
    "live/odra-topology-genesis-proof.json",
    "rwa/sample-invoice-pool-DAO-PROP-RWA-001.json",
)


class RuntimeReleaseMountError(ValueError):
    """The mounted release view is absent, ambiguous, or inconsistent."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeReleaseMountError("mounted JSON contains a duplicate field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise RuntimeReleaseMountError(
        f"mounted JSON contains a non-standard constant: {value}"
    )


def _require_directory(path: Path, label: str) -> None:
    if not path.is_absolute():
        raise RuntimeReleaseMountError(f"{label} path must be absolute")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RuntimeReleaseMountError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RuntimeReleaseMountError(
            f"{label} must be a non-symlink directory"
        )


def _read_regular_file(path: Path, *, label: str, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeReleaseMountError(
            f"{label} must be a readable non-symlink file"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeReleaseMountError(f"{label} must be a regular file")
        if metadata.st_size > limit:
            raise RuntimeReleaseMountError(f"{label} exceeds its size limit")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError as exc:
        raise RuntimeReleaseMountError(f"{label} is unreadable") from exc
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    if len(raw) > limit:
        raise RuntimeReleaseMountError(f"{label} exceeds its size limit")
    return raw


def _strict_json(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except RuntimeReleaseMountError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeReleaseMountError(f"{label} is not strict JSON") from exc
    if type(value) is not dict:
        raise RuntimeReleaseMountError(f"{label} must contain one JSON object")
    return value


def _artifact_file(artifacts_dir: Path, relative: str) -> Path:
    parsed = PurePosixPath(relative)
    if (
        parsed.is_absolute()
        or not parsed.parts
        or any(part in {"", ".", ".."} for part in parsed.parts)
    ):
        raise RuntimeReleaseMountError("registry artifact path is unsafe")
    path = artifacts_dir.joinpath(*parsed.parts)
    parent = artifacts_dir
    for part in parsed.parts[:-1]:
        parent = parent / part
        _require_directory(parent, "mounted artifact directory")
    return path


def _verify_registry_artifact_binding(
    *,
    artifacts_dir: Path,
    artifact_path: object,
    artifact_sha256: object,
    label: str,
) -> None:
    if (
        type(artifact_path) is not str
        or not artifact_path.startswith("artifacts/")
        or type(artifact_sha256) is not str
        or len(artifact_sha256) != 64
        or any(character not in "0123456789abcdef" for character in artifact_sha256)
    ):
        raise RuntimeReleaseMountError(f"{label} binding is malformed")
    relative = artifact_path.removeprefix("artifacts/")
    raw = _read_regular_file(
        _artifact_file(artifacts_dir, relative),
        label=label,
        limit=MAX_RELEASE_ARTIFACT_BYTES,
    )
    if not hashlib.sha256(raw).hexdigest() == artifact_sha256:
        raise RuntimeReleaseMountError(f"{label} digest differs")


def validate_runtime_release_mounts(
    *,
    artifacts_dir: Path,
    proof_registry_dir: Path,
    card_chain_roots_file: Path,
) -> dict[str, object]:
    """Validate one immutable artifact tree and one selected registry."""

    artifacts_dir = Path(artifacts_dir)
    proof_registry_dir = Path(proof_registry_dir)
    card_chain_roots_file = Path(card_chain_roots_file)
    _require_directory(artifacts_dir, "release artifact root")
    _require_directory(proof_registry_dir, "selected proof registry")
    if artifacts_dir == proof_registry_dir:
        raise RuntimeReleaseMountError(
            "release artifact root and selected registry must be separate mounts"
        )

    for relative in REQUIRED_RUNTIME_ARTIFACTS:
        _read_regular_file(
            _artifact_file(artifacts_dir, relative),
            label=f"required runtime artifact {relative}",
            limit=MAX_RELEASE_ARTIFACT_BYTES,
        )

    expected_roots_file = artifacts_dir / "live/card-chain-roots-v1.json"
    if card_chain_roots_file != expected_roots_file:
        raise RuntimeReleaseMountError(
            "card-chain roots file is outside the release artifact mount"
        )
    try:
        load_card_chain_release_roots(str(card_chain_roots_file))
    except CardChainRootsError as exc:
        raise RuntimeReleaseMountError(
            "mounted card-chain roots file is invalid"
        ) from exc

    try:
        registry_names = sorted(path.name for path in proof_registry_dir.iterdir())
    except OSError as exc:
        raise RuntimeReleaseMountError("selected proof registry is unreadable") from exc
    if registry_names != ["registry.json"]:
        raise RuntimeReleaseMountError(
            "selected proof registry must contain exactly registry.json"
        )
    registry_raw = _read_regular_file(
        proof_registry_dir / "registry.json",
        label="selected proof registry",
        limit=MAX_REGISTRY_BYTES,
    )
    registry = _strict_json(registry_raw, label="selected proof registry")
    try:
        validated = validate_registry_document(registry)
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeReleaseMountError(
            "selected proof registry failed strict validation"
        ) from exc
    if validated != registry:
        raise RuntimeReleaseMountError(
            "selected proof registry changed during validation"
        )

    roots_binding = registry.get("card_chain_roots")
    if type(roots_binding) is not dict:
        raise RuntimeReleaseMountError(
            "selected proof registry lacks the card-chain roots binding"
        )
    _verify_registry_artifact_binding(
        artifacts_dir=artifacts_dir,
        artifact_path=roots_binding.get("artifact_path"),
        artifact_sha256=roots_binding.get("artifact_sha256"),
        label="card-chain roots",
    )
    for index, item in enumerate(registry["public_items"]):
        if type(item) is not dict:
            raise RuntimeReleaseMountError("registry public proof item is malformed")
        _verify_registry_artifact_binding(
            artifacts_dir=artifacts_dir,
            artifact_path=item.get("artifact_path"),
            artifact_sha256=item.get("artifact_sha256"),
            label=f"public proof item {index}",
        )

    return {
        "artifact_root": "/app/artifacts",
        "proof_registry": "/run/config/proof-registry",
        "registry_documents": 1,
        "status": "ready",
    }


def main() -> int:
    artifacts = os.getenv("CONCORDIA_RELEASE_ARTIFACTS_DIR", "")
    registry = os.getenv("CONCORDIA_PROOF_REGISTRY_DIR", "")
    roots = os.getenv("CONCORDIA_CARD_CHAIN_ROOTS_FILE", "")
    if not artifacts or not registry or not roots:
        print(
            '{"error":"runtime release mount configuration is incomplete",'
            '"status":"blocked"}',
            file=sys.stderr,
        )
        return 78
    try:
        result = validate_runtime_release_mounts(
            artifacts_dir=Path(artifacts),
            proof_registry_dir=Path(registry),
            card_chain_roots_file=Path(roots),
        )
    except RuntimeReleaseMountError as exc:
        print(
            json.dumps(
                {"error": str(exc), "status": "blocked"},
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 78
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
