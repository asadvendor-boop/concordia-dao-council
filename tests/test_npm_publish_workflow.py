from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "publish-verifier.yml"


def _shared_verifier() -> str:
    return (WORKFLOW.parent.parent.parent / "scripts/verify_published_release.mjs").read_text(
        encoding="utf-8"
    )


def test_verifier_publish_workflow_is_manual_exact_commit_and_provenance_bound() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    verifier = _shared_verifier()

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
    assert "NODE_AUTH_TOKEN" not in source
    assert "npm audit signatures" in verifier
    assert "default: 0.1.1" in source
    assert "dist?.attestations" in verifier
    assert "https://slsa.dev/provenance/v1" in verifier
    assert "https://in-toto.io/Statement/v1" in verifier
    assert ".github/workflows/publish-verifier.yml" in verifier
    # gitHead is deliberately absent: npm does not populate it for tarball
    # publication, so the source commit is bound through SLSA provenance.
    assert (
        'execFileSync("npm", ["view", spec, "name", "version", "dist", '
        '"repository", "--json"]'
        in verifier
    )
    assert "node-version: 22.22.0" in source
    assert "npm install --global npm@11.18.0" in source
    assert 'test "$(npm --version)" = "11.18.0"' in source


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
    # Once pre-publication in the workflow; post-publication is in the shared script.
    assert source.count("typeof m.verifyProofRegistry!=='function'") == 1
    assert "typeof m.verifyProofRegistry!=='function'" in _shared_verifier()
    assert "typeof m.verifyRegistry" not in source
    assert source.count("./node_modules/.bin/concordia-verify --help") == 1
    assert "node_modules/.bin/concordia-verify" in _shared_verifier()
    assert 'npm install --ignore-scripts "$tarball"' in source


def test_verifier_publish_workflow_installs_python_fixture_runtime_before_tests() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")

    setup_uv = source.index("- name: Install pinned uv")
    package_tests = source.index(
        "- name: Install, test, lint, audit, and inspect package"
    )

    assert setup_uv < package_tests
    assert (
        "uses: astral-sh/setup-uv@d4b2f3b6ecc6e67c4457f6d3e41ec42d3d0fcb86"
        in source
    )
    assert "version: 0.10.12" in source
    assert "uv python install 3.12.11" in source


def test_verifier_publish_workflow_primes_exact_offline_runtime_dependency() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")

    cache_prime = source.index("npm cache add '@noble/hashes@1.8.0'")
    package_tests = source.index("npm test")

    assert cache_prime < package_tests


def test_shared_verifier_parses_json_without_require() -> None:
    """The extensionless-mktemp/require() bug is structurally impossible now.

    The shared verifier parses JSON explicitly instead of loading temp files
    through node require(), which previously failed with
    `SyntaxError: Unexpected token ':'` AFTER a successful publish.
    """

    script = (WORKFLOW.parent.parent.parent / "scripts/verify_published_release.mjs").read_text(
        encoding="utf-8"
    )
    assert "JSON.parse" in script
    assert "require(process.argv" not in script


def test_verification_does_not_trust_registry_git_head() -> None:
    """npm does not populate gitHead for tarball publication.

    `npm view @concordia-dao/verify@0.1.1 gitHead` returns nothing, so asserting
    metadata.gitHead == COMMIT_SHA can never pass and left publish run
    30153047625 red after a genuinely successful publish. The authoritative
    source binding is the SLSA provenance, which the same step already checks.
    """

    source = WORKFLOW.read_text(encoding="utf-8")

    assert "x.gitHead" not in source, "registry gitHead must not be asserted"
    assert "gitHead --json" not in source, "gitHead must not be requested"


def test_source_commit_is_bound_through_slsa_provenance() -> None:
    """The commit must still be verified — from provenance, not the registry."""

    script = (WORKFLOW.parent.parent.parent / "scripts/verify_published_release.mjs").read_text(
        encoding="utf-8"
    )

    assert "resolvedDependencies" in script
    assert "sourceDependencies.length === 1" in script
    assert "sourceDependencies[0]?.digest?.gitCommit === commit" in script
    assert (
        "git+https://github.com/asadvendor-boop/"
        "concordia-dao-council@refs/heads/main"
    ) in script
    for binding in ("workflow?.repository", "workflow?.path", "workflow?.ref",
                    "builder?.id", "sha512"):
        assert binding in script
    assert "subject[0]?.digest?.sha512 === expectedDigest" in script


VERIFY_ONLY = WORKFLOW.parent / "verify-published-release.yml"


def test_single_shared_verifier_implementation() -> None:
    """Publication and re-verification must not drift apart.

    Two independently maintained provenance checks would eventually disagree,
    and the weaker one would be the one that passes.
    """

    publish = WORKFLOW.read_text(encoding="utf-8")
    verify = VERIFY_ONLY.read_text(encoding="utf-8")
    script = "scripts/verify_published_release.mjs"

    assert script in publish, "publish step must call the shared verifier"
    assert script in verify, "verify-only workflow must call the shared verifier"
    # the inline duplicate must be gone
    assert "in-toto.io/Statement/v1" not in publish, "inline provenance logic must not remain"


def test_verify_only_workflow_is_read_only_and_cannot_publish() -> None:
    verify = VERIFY_ONLY.read_text(encoding="utf-8")

    assert "permissions:\n  contents: read" in verify
    assert "id-token: write" not in verify
    assert "packages: write" not in verify
    assert "${{ secrets.NPM_TOKEN }}" not in verify
    assert "NODE_AUTH_TOKEN:" not in verify
    body = "\n".join(
        line for line in verify.splitlines() if not line.strip().startswith("#")
    )
    for forbidden in ("npm publish", "npm deprecate", "npm unpublish"):
        assert forbidden not in body, f"verify-only workflow must not {forbidden}"


def test_verify_only_workflow_requires_exact_version_and_commit() -> None:
    verify = VERIFY_ONLY.read_text(encoding="utf-8")

    assert "commit_sha" in verify and "required: true" in verify
    assert "[0-9a-f]{40}" in verify, "commit must be validated as 40-hex"
    assert "[0-9]+\\.[0-9]+\\.[0-9]+" in verify, "version must be validated"


def test_shared_verifier_binds_commit_and_refuses_bad_provenance() -> None:
    script = (WORKFLOW.parent.parent.parent / "scripts/verify_published_release.mjs").read_text(
        encoding="utf-8"
    )

    assert "resolvedDependencies" in script
    assert "sourceDependencies.length === 1" in script
    assert "sourceDependencies[0]?.digest?.gitCommit === commit" in script
    assert "gitHead" not in script.split('"""')[0] or "npm does not populate gitHead" in script
    # every binding must remain enforced
    for binding in ("in-toto.io/Statement/v1", "sha512", "workflow?.repository",
                    "workflow?.path", "workflow?.ref", "builder?.id", "invocationId"):
        assert binding in script, f"shared verifier must bind {binding}"
    # and it must exit non-zero when a check fails
    assert "if (failed.length) process.exit(1)" in script
