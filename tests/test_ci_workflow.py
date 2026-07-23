from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


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


def test_ci_does_not_shadow_pinned_runtime_entrypoints_with_detached_copies() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")

    assert '"$HOME/.local/bin/uv"' not in source
    assert '"$HOME/.local/bin/node"' not in source
    assert '"$HOME/.local/bin/npm"' not in source
    assert "readlink -f" not in source
    assert re.search(
        r"uv run --frozen --isolated --python python3\.12\s+"
        r"python -m pytest -q",
        source,
    )
