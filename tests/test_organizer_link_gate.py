from __future__ import annotations

import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).parents[1]
RUNNER = ROOT / "scripts/run_organizer_link_gate.mjs"
CORE = ROOT / "scripts/organizer-link-gate-core.mjs"
REQUEST = ROOT / "handoff/ORGANIZER_LINK_GATE_REQUEST.json"
DOCUMENTATION = ROOT / "docs/PRE_SUBMISSION_VERIFICATION.md"
NODE_TEST = ROOT / "tests/js/organizer_link_gate.test.mjs"


def test_failure_first_node_contract_suite_passes() -> None:
    completed = subprocess.run(
        ["node", "--test", str(NODE_TEST)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "# pass 13" in completed.stdout
    assert "# fail 0" in completed.stdout


def test_collector_is_read_only_and_uses_the_locked_browser_runtime() -> None:
    runner = RUNNER.read_text()
    runtime = json.loads((ROOT / "scripts/g13-browser-runtime/package.json").read_text())

    assert runtime["dependencies"] == {"playwright": "1.58.2"}
    assert '"GET", "HEAD", "OPTIONS"' in runner
    assert 'page.route("**/*"' in runner
    assert "blockedbyclient" in runner
    assert "createRequire(runtimePackage)" in runner
    assert "storage_state" not in runner
    assert ".screenshot(" not in runner
    assert "writeFile(" not in runner
    assert "mkdir(" not in runner


def test_frozen_request_and_core_cover_the_organizer_census() -> None:
    request = json.loads(REQUEST.read_text())
    core = CORE.read_text()

    assert request["schema_version"] == "concordia.organizer_rendered_link_request.v2"
    assert len(request["known_links"]) == 17
    assert "docs_judge_quickstart_anchor" in {
        row["link_id"] for row in request["known_links"]
    }
    assert "DOUBLED_BASE_PATH" in core
    assert "MISSING_DOC_ANCHOR" in core
    assert "FIRST_PARTY_REQUEST_FAILED" in core
    assert "PROOF_TAB_NOT_ACTIVE" in core


def test_organizer_gate_is_invoked_before_both_g12_and_g13() -> None:
    notes = DOCUMENTATION.read_text()

    assert (
        "python scripts/build_release_manifest.py capture-organizer-g12"
        in notes
    )
    assert (
        "python scripts/build_release_manifest.py capture-organizer-g13"
        in notes
    )
    assert "release/organizer/G12_RENDERED_LINK_AUDIT.json" in notes
    assert "release/g13/ORGANIZER_RENDERED_LINK_AUDIT.json" in notes
    assert "no-fixture invocation receipt" in notes
    assert "shell redirection into either release path" in notes
    assert "before G12" in notes
    assert "before G13" in notes
    assert "does not replace or weaken G12 or G13" in notes
    assert "--fixture tests/fixtures/organizer-link-gate-pass.json" in notes
    assert "never release evidence" in notes
