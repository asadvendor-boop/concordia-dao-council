from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
MAKEFILE = ROOT / "Makefile"
CONTRIBUTING = ROOT / ".github" / "CONTRIBUTING.md"
PULL_REQUEST_TEMPLATE = ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md"


def test_ci_checks_out_complete_history_with_immutable_actions() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    action_uses = re.findall(r"(?m)^\s*uses:\s*([^#\s]+)", source)

    assert action_uses
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", item) for item in action_uses)
    assert "fetch-depth: 0" in source
    assert "fetch-tags: true" in source
    assert "persist-credentials: false" in source


def test_ci_pins_release_runtimes_and_builds_verifier_before_pytest() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")

    assert "timeout-minutes:" in source
    assert "node-version: 22.12.0" in source
    assert "version: 0.10.12" in source
    assert "id: setup-uv" in source
    assert "uv python install 3.12.11" in source
    assert "npm ci" in source
    assert "npm run build" in source
    assert "working-directory: packages/verify" in source
    assert "working-directory: scripts/g13-browser-runtime" in source
    assert "npm ci --ignore-scripts --no-audit --no-fund" in source
    assert "PLAYWRIGHT_BROWSERS_PATH=0" in source
    assert (
        "node node_modules/playwright/cli.js install --with-deps chromium"
        in source
    )
    assert source.index("npm run build") < source.index("python -m pytest -q")
    assert source.index("install --with-deps chromium") < source.index(
        "python -m pytest -q"
    )
    assert "working-directory: dashboard" in source
    assert "npm run test:unit" in source
    assert source.index("npm run test:unit") < source.index(
        "python -m pytest -q"
    )


def test_ci_does_not_shadow_pinned_runtime_entrypoints_with_detached_copies() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")

    assert '"$HOME/.local/bin/uv"' not in source
    assert '"$HOME/.local/bin/node"' not in source
    assert '"$HOME/.local/bin/npm"' not in source
    assert "readlink -f" not in source
    assert re.search(
        r"uv run --frozen --isolated --python 3\.12\.11\s+"
        r"python -m pytest -q",
        source,
    )


def test_local_release_entrypoints_pin_the_same_frozen_python_runtime() -> None:
    makefile = MAKEFILE.read_text(encoding="utf-8")
    contributing = CONTRIBUTING.read_text(encoding="utf-8")
    pull_request = PULL_REQUEST_TEMPLATE.read_text(encoding="utf-8")
    command = "uv run --frozen --isolated --python 3.12.11"

    assert "UV ?= uv" in makefile
    assert "UV_RUN ?= $(UV) run --frozen --isolated --python 3.12.11" in makefile
    assert "PYTHON ?= $(UV_RUN) python" in makefile
    assert "runtime-preflight:" in makefile
    assert 'sys.version_info[:3] == (3, 12, 11)' in makefile
    assert "test: runtime-preflight smoke" in makefile
    assert f"{command} python -m pytest -q" in contributing
    assert f"`{command} python -m pytest -q`" in pull_request
