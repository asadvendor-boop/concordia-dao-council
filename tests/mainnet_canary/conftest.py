"""Fixtures for the Mainnet canary preparation tests.

The builders live in ``mc_support`` (a uniquely named helper module so it can
never collide with the repository root ``conftest``).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import mc_support  # noqa: E402


@pytest.fixture()
def hermetic_repo(tmp_path: Path) -> Path:
    return mc_support.build_hermetic_repo(tmp_path)


@pytest.fixture()
def plan_inputs(hermetic_repo: Path, tmp_path: Path) -> dict[str, Path]:
    return mc_support.build_plan_inputs(hermetic_repo, tmp_path)
