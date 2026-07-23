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

    assert "pillow==12.3.0" in project["tool"]["uv"]["constraint-dependencies"]
    pillows = [
        item
        for item in lock["package"]
        if item.get("name") == "pillow"
    ]
    assert [item.get("version") for item in pillows] == ["12.3.0"]

    assert package["overrides"]["brace-expansion"] == "1.1.16"
    brace = package_lock["packages"]["node_modules/brace-expansion"]
    assert brace["version"] == "1.1.16"
