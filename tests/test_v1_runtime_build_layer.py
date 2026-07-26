from __future__ import annotations

import hashlib
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "Dockerfile": "b19a3d611e13addd7dc03de328c1949d22a54ab7fed001521a0bab3799268366",
    "dashboard/Dockerfile": "1e5ab0e9bb790ba9fc57acf4574bb1b0c88e0adb1715fc83e399f46d2c2f3709",
    "deploy/shared-host/compose.prod.yml": "0a5e8a17773d9d3f856e6a14de818d94af0fd241b172184787e98847e791606d",
}
FORBIDDEN_SERVICES = {"caddy", "governance-v3", "mainnet", "x402-official"}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _services(path: Path) -> set[str]:
    found: set[str] = set()
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
                found.add(match.group(1))
    return found


def test_runtime_build_layer_is_one_unchanged_archive_set() -> None:
    actual = {rel: _sha256(ROOT / rel) for rel in EXPECTED}
    assert actual == EXPECTED


def test_runtime_compose_excludes_unapproved_services() -> None:
    services = _services(ROOT / "deploy/shared-host/compose.prod.yml")
    assert not services.intersection(FORBIDDEN_SERVICES)
