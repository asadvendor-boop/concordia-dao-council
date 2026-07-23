"""Release collectors must declare every parser they execute."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_real_pdf_parser_is_exactly_pinned_in_project_and_lockfile() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))

    assert "pypdf==6.14.2" in project["project"]["dependencies"]
    packages = [
        package
        for package in lock["package"]
        if package.get("name") == "pypdf" and package.get("version") == "6.14.2"
    ]
    assert len(packages) == 1


def test_release_locks_pin_the_dependabot_security_floors() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    integration = ROOT / "integrations" / "casper-sdk-v5"
    package = json.loads((integration / "package.json").read_text(encoding="utf-8"))
    package_lock = json.loads(
        (integration / "package-lock.json").read_text(encoding="utf-8")
    )
    dashboard = ROOT / "dashboard"
    dashboard_package = json.loads(
        (dashboard / "package.json").read_text(encoding="utf-8")
    )
    dashboard_lock = json.loads(
        (dashboard / "package-lock.json").read_text(encoding="utf-8")
    )

    assert "pillow==12.3.0" in project["tool"]["uv"]["constraint-dependencies"]
    assert "click==8.3.3" in project["tool"]["uv"]["constraint-dependencies"]
    pillows = [
        item
        for item in lock["package"]
        if item.get("name") == "pillow"
    ]
    assert [item.get("version") for item in pillows] == ["12.3.0"]
    clicks = [
        item
        for item in lock["package"]
        if item.get("name") == "click"
    ]
    assert [item.get("version") for item in clicks] == ["8.3.3"]

    assert package["overrides"]["brace-expansion"] == "1.1.16"
    brace = package_lock["packages"]["node_modules/brace-expansion"]
    assert brace["version"] == "1.1.16"

    assert dashboard_package["dependencies"]["next"] == "16.2.11"
    assert dashboard_package["overrides"]["sharp"] == "0.35.3"
    assert dashboard_lock["packages"]["node_modules/next"]["version"] == "16.2.11"
    assert dashboard_lock["packages"]["node_modules/sharp"]["version"] == "0.35.3"
    assert (
        dashboard_lock["packages"]["node_modules/brace-expansion"]["version"]
        == "1.1.16"
    )


def test_security_register_records_current_python_dependency_posture() -> None:
    policy = (ROOT / ".github" / "SECURITY.md").read_text(encoding="utf-8")

    assert "GHSA-47fr-3ffg-hgmw" in policy
    assert "CVE-2026-7246" in policy
    assert "GHSA-9f5j-8jwj-x28g" in policy
    assert "GHSA-79v4-65xg-pq4g" in policy
    assert "GHSA-h4gh-qq45-vh27" in policy
    assert "GHSA-m959-cc7f-wv43" in policy
    assert "No mainnet funds are at risk" not in policy
    assert "Testnet-only deployment; no mainnet keys or funds" not in policy
