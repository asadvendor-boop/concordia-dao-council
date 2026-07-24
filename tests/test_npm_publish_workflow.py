from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "publish-verifier.yml"


def test_verifier_publish_workflow_is_manual_exact_commit_and_provenance_bound() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in source
    assert re.search(r"(?m)^\s*(push|pull_request|release):", source) is None
    assert "id-token: write" in source
    assert "contents: read" in source
    assert "runs-on: ubuntu-latest" in source
    assert "ref: ${{ inputs.commit_sha }}" in source
    assert "fetch-depth: 0" in source
    assert "COMMIT_SHA: ${{ inputs.commit_sha }}" in source
    assert "PACKAGE_VERSION: ${{ inputs.version }}" in source
    assert "expected_commit='${{ inputs.commit_sha }}'" not in source
    assert "expected_version='${{ inputs.version }}'" not in source
    assert "npm publish" in source
    assert "npm publish '${{ steps.pack.outputs.tarball }}'" not in source
    assert "--provenance" in source
    assert "--access public" in source
    assert "NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}" in source
    assert "npm audit signatures" in source


def test_verifier_publish_workflow_pins_actions_and_disables_release_cache() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    action_uses = re.findall(r"(?m)^\s*uses:\s*([^#\s]+)", source)

    assert action_uses
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", item) for item in action_uses)
    assert "package-manager-cache: false" in source


def test_verifier_publish_workflow_preflights_the_exact_public_contract() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")

    build = source.index("- name: Build the exact publication tarball")
    preflight = source.index(
        "- name: Verify exact tarball in a clean consumer before publication"
    )
    publish = source.index("- name: Publish exact tarball with registry provenance")

    assert build < preflight < publish
    assert source.count("typeof m.verifyProofRegistry!=='function'") == 2
    assert "typeof m.verifyRegistry" not in source
    assert source.count("./node_modules/.bin/concordia-verify --help") == 2
    assert 'npm install --ignore-scripts "$tarball"' in source
