"""Release collectors must declare every parser they execute."""

from __future__ import annotations

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
