#!/usr/bin/env python3
"""Fail-closed cleanliness and coherent-runtime audit for the V1 baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path


RUNTIME_HASHES = {
    "Dockerfile": "b19a3d611e13addd7dc03de328c1949d22a54ab7fed001521a0bab3799268366",
    "dashboard/Dockerfile": "1e5ab0e9bb790ba9fc57acf4574bb1b0c88e0adb1715fc83e399f46d2c2f3709",
    "deploy/shared-host/compose.prod.yml": "0a5e8a17773d9d3f856e6a14de818d94af0fd241b172184787e98847e791606d",
}
REQUIRED_RELEASE_FILES = {
    ".github/SECURITY.md",
    ".github/workflows/ci.yml",
    ".github/workflows/docs-pages.yml",
    ".github/workflows/publish-verifier.yml",
    ".github/workflows/verify-published-release.yml",
    "docs/requirements-docs.txt",
    "scripts/write_docs_release_identity.py",
}
FORBIDDEN_DIR_NAMES = {
    ".cache",
    ".mypy_cache",
    ".next",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".turbo",
    ".venv",
    "__pycache__",
    "dist",
    "node_modules",
    "target",
    "venv",
}
FORBIDDEN_SERVICE_NAMES = {
    "caddy",
    "governance-v3",
    "mainnet",
    "x402-official",
}
SECRET_FILENAMES = {
    ".npmrc",
    ".pypirc",
    "credentials",
    "credentials.json",
    "id_ed25519",
    "id_rsa",
    "secrets.json",
}
SECRET_PATTERNS = {
    "private-key": re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    "aws-access-key": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "github-token": re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "openai-token": re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
    "slack-token": re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "credential-url": re.compile(
        rb"\b(?:https?|postgres(?:ql)?|mysql|redis)://[^/\s:@]+:[^/\s@]+@[^/\s:]+"
    ),
}
V2_COMPONENT = re.compile(r"(?:^|[-_.])v2(?:$|[-_.])", re.IGNORECASE)
RESERVED_TEST_CREDENTIAL_HOST = re.compile(
    rb"@[A-Za-z0-9.-]+\.example\.(?:com|invalid)$"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compose_services(path: Path) -> set[str]:
    services: set[str] = set()
    in_services = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if re.fullmatch(r"services:\s*(?:#.*)?", line):
            in_services = True
            continue
        if in_services and line and not line.startswith((" ", "#")):
            break
        if in_services:
            match = re.fullmatch(r"  ([A-Za-z0-9_.-]+):\s*(?:#.*)?", line)
            if match:
                services.add(match.group(1))
    return services


def audit(root: Path) -> dict[str, object]:
    root = root.resolve()
    violations: list[dict[str, str]] = []
    large_files: list[dict[str, object]] = []
    scanned_files = 0
    runtime_actual: dict[str, str] = {}

    for current, dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        kept_dirs: list[str] = []
        for dirname in sorted(dirnames):
            path = current_path / dirname
            rel = path.relative_to(root).as_posix()
            if rel == ".git":
                continue
            if path.is_symlink():
                violations.append({"kind": "symlink", "path": rel})
                continue
            if dirname == ".git":
                violations.append({"kind": "nested-git", "path": rel})
                continue
            if dirname in FORBIDDEN_DIR_NAMES:
                violations.append({"kind": "generated-or-cache-directory", "path": rel})
                continue
            if rel == "private" or rel.startswith("artifacts/private"):
                violations.append({"kind": "private-directory", "path": rel})
                continue
            if V2_COMPONENT.search(dirname):
                violations.append({"kind": "v2-residue-path", "path": rel})
                continue
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs

        for filename in sorted(filenames):
            path = current_path / filename
            rel = path.relative_to(root).as_posix()
            scanned_files += 1
            lower = filename.lower()
            if path.is_symlink():
                violations.append({"kind": "symlink", "path": rel})
                continue
            if filename == ".DS_Store":
                violations.append({"kind": "macos-metadata", "path": rel})
            if lower.endswith(".zip"):
                violations.append({"kind": "zip", "path": rel})
            if lower == ".env" or lower.startswith(".env."):
                violations.append({"kind": "environment-secret-file", "path": rel})
            if lower in SECRET_FILENAMES or lower.endswith((".pem", ".key")):
                violations.append({"kind": "secret-looking-filename", "path": rel})
            if lower.endswith((".db", ".db-wal", ".db-shm")):
                violations.append({"kind": "database-file", "path": rel})
            if lower.endswith(".log"):
                violations.append({"kind": "log-file", "path": rel})
            if V2_COMPONENT.search(filename):
                violations.append({"kind": "v2-residue-path", "path": rel})

            size = path.stat().st_size
            if size >= 5 * 1024 * 1024:
                large_files.append({"path": rel, "size": size, "sha256": sha256(path)})
            if size <= 10 * 1024 * 1024:
                raw = path.read_bytes()
                if b"\x00" not in raw[:8192]:
                    for name, pattern in SECRET_PATTERNS.items():
                        matches = list(pattern.finditer(raw))
                        if (
                            name == "credential-url"
                            and rel.startswith("packages/verify/test/")
                            and matches
                            and all(RESERVED_TEST_CREDENTIAL_HOST.search(match.group()) for match in matches)
                        ):
                            continue
                        if matches:
                            violations.append({"kind": f"secret-pattern:{name}", "path": rel})

    for rel in sorted(REQUIRED_RELEASE_FILES):
        if not (root / rel).is_file():
            violations.append({"kind": "missing-required-release-file", "path": rel})

    for rel in (".github/workflows/codeql.yml", ".github/dependabot.yml"):
        if (root / rel).exists():
            violations.append({"kind": "forbidden-default-setup-file", "path": rel})

    for rel, expected in RUNTIME_HASHES.items():
        path = root / rel
        if not path.is_file():
            violations.append({"kind": "missing-runtime-build-layer-file", "path": rel})
            continue
        actual = sha256(path)
        runtime_actual[rel] = actual
        if actual != expected:
            violations.append(
                {
                    "kind": "runtime-build-layer-hash-mismatch",
                    "path": rel,
                    "expected": expected,
                    "actual": actual,
                }
            )

    compose_path = root / "deploy/shared-host/compose.prod.yml"
    services = compose_services(compose_path) if compose_path.is_file() else set()
    for service in sorted(services & FORBIDDEN_SERVICE_NAMES):
        violations.append({"kind": "forbidden-compose-service", "path": service})

    return {
        "schema_version": 1,
        "root": str(root),
        "status": "pass" if not violations else "fail",
        "scanned_files": scanned_files,
        "violations": violations,
        "large_files": sorted(large_files, key=lambda item: str(item["path"])),
        "runtime_build_layer": {
            "source": "approved VM V1 source archive",
            "expected_sha256": RUNTIME_HASHES,
            "actual_sha256": runtime_actual,
            "compose_services": sorted(services),
            "forbidden_services": sorted(FORBIDDEN_SERVICE_NAMES),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    result = audit(args.root)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
