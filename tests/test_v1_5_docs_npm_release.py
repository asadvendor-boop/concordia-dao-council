from __future__ import annotations

import json
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CANONICAL_PROPOSAL = "DAO-PROP-6CB25C"
CANONICAL_RECEIPT = (
    "e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852"
)
QUORUM_ACCEPTANCE = (
    "9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928"
)
SAFEPAY_PAYMENT = (
    "dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c"
)


def _workflow(name: str) -> dict[str, object]:
    source = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
    return yaml.load(source, Loader=yaml.BaseLoader)


def test_candidate_pages_dispatch_builds_but_only_main_can_deploy() -> None:
    workflow = _workflow("docs-pages.yml")
    assert set(workflow["on"]) == {"workflow_dispatch", "push"}

    jobs = workflow["jobs"]
    assert set(jobs) == {"build", "deploy"}
    assert "if" not in jobs["build"]
    assert jobs["deploy"]["needs"] == "build"
    assert jobs["deploy"]["if"] == "github.ref == 'refs/heads/main'"
    assert jobs["deploy"]["environment"]["name"] == "github-pages"
    assert jobs["deploy"]["permissions"] == {
        "pages": "write",
        "id-token": "write",
    }

    build_commands = "\n".join(
        step.get("run", "") for step in jobs["build"]["steps"] if "run" in step
    )
    assert "python scripts/check_public_docs_links.py" in build_commands
    assert "mkdocs build --strict" in build_commands


def test_npm_publish_is_manual_oidc_exact_main_tip_and_shared_verification() -> None:
    workflow = _workflow("publish-verifier.yml")
    assert set(workflow["on"]) == {"workflow_dispatch"}
    dispatch = workflow["on"]["workflow_dispatch"]["inputs"]
    assert dispatch["version"]["default"] == "0.1.4"

    publish = workflow["jobs"]["publish"]
    assert publish["environment"] == "npm-production"
    assert publish["permissions"] == {"contents": "read", "id-token": "write"}

    steps = publish["steps"]
    bind = next(step for step in steps if step["name"] == "Bind release inputs to main and package metadata")
    command = bind["run"]
    assert "refs/heads/main:refs/remotes/origin/main" in command
    assert 'test "$(git rev-parse origin/main)" = "$expected_commit"' in command
    assert "merge-base --is-ancestor" not in command

    publish_step = next(step for step in steps if step["name"] == "Publish exact tarball with registry provenance")
    assert "npm publish" in publish_step["run"]
    assert "--provenance" in publish_step["run"]

    pack_step = next(step for step in steps if step["name"] == "Build the exact publication tarball")
    assert 'npm pkg set "gitHead=${GITHUB_SHA}"' in pack_step["run"]

    consumer_step = next(
        step
        for step in steps
        if step["name"] == "Verify exact tarball in a clean consumer before publication"
    )
    assert "scripts/verify_verifier_consumer.mjs" in consumer_step["run"]

    verify_step = next(step for step in steps if step["name"].startswith("Verify registry copy"))
    assert 'node scripts/verify_published_release.mjs "$PACKAGE_VERSION" "$COMMIT_SHA"' in verify_step["run"]
    assert "verify_verifier_consumer.mjs" in (
        ROOT / "scripts" / "verify_published_release.mjs"
    ).read_text(encoding="utf-8")

    read_only = _workflow("verify-published-release.yml")
    assert (
        read_only["on"]["workflow_dispatch"]["inputs"]["version"]["default"]
        == "0.1.4"
    )
    assert read_only["jobs"]["verify"]["permissions"] == {"contents": "read"}
    assert "id-token" not in read_only["jobs"]["verify"]["permissions"]
    verifier_source = (ROOT / "scripts" / "verify_published_release.mjs").read_text(
        encoding="utf-8"
    )
    assert '"registry gitHead"' in verifier_source
    assert "metadata.gitHead === commit" in verifier_source


def test_public_release_copy_is_v1_first_and_explicit_about_exclusions() -> None:
    required_files = [
        ROOT / "README.md",
        ROOT / "buidl-page-FINALS-STABLE.md",
        ROOT / "docs-site" / "index.md",
        ROOT / "docs-site" / "release-scope.md",
        ROOT / "docs-site" / "governance-receipts.md",
        ROOT / "docs-site" / "safepay-lite.md",
        ROOT / "docs-site" / "proof-verification.md",
    ]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in required_files)
    lowered = combined.lower()

    assert CANONICAL_PROPOSAL in combined
    assert CANONICAL_RECEIPT in combined
    assert QUORUM_ACCEPTANCE in combined
    assert SAFEPAY_PAYMENT in combined
    corrected_copy = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            ROOT / "README.md",
            ROOT / "docs-site" / "index.md",
            ROOT / "docs-site" / "release-scope.md",
            ROOT / "docs-site" / "safepay-lite.md",
            ROOT / "docs-site" / "proof-verification.md",
        )
    ).lower()
    assert "casper-native x402 v2" in corrected_copy
    assert "http 402" in corrected_copy
    assert "payment intent" in corrected_copy
    assert "native-transfer verification" in corrected_copy
    assert "official facilitator service" in corrected_copy
    assert "successful external-provider settlement" in corrected_copy
    assert "recorded native-cspr" in corrected_copy
    assert "official x402 is not shipped" not in corrected_copy
    assert "mainnet has not been executed" in lowered
    assert "governance v3 is excluded" in lowered
    assert "recorded native-cspr" in lowered
    assert "casper testnet" in lowered

    for path in (
        ROOT / "docs-site" / "official-x402.md",
        ROOT / "docs-site" / "v3-envelope.md",
        ROOT / "docs-site" / "treasury-execution.md",
    ):
        assert not path.exists()

    public_copy = "\n".join(
        [ROOT.joinpath("README.md").read_text(encoding="utf-8")]
        + [
            path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "docs-site").glob("*.md"))
        ]
        + [
            path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "docs").glob("*.md"))
        ]
        + [ROOT.joinpath("buidl-page-FINALS-STABLE.md").read_text(encoding="utf-8")]
    )
    assert "sslip.io" not in public_copy
    assert "x402.concordiadao.xyz" not in public_copy
    assert "safepay.concordiadao.xyz" not in public_copy
    assert "x402-provider." not in public_copy
    assert "/verify/v/0.1.1" not in public_copy
    assert "safepay lite conditional paid specialist-report settlement" not in public_copy.lower()
    assert "demonstrates conditional paid specialist-report settlement" not in public_copy.lower()
    assert "safepay lite is the first monetization primitive" not in public_copy.lower()


def test_public_introduction_uses_approved_implicit_positioning_and_no_stale_community_notes() -> None:
    approved_lead = "Agentic payments on Casper are arriving. The unsolved half is authorization"
    for path in (ROOT / "README.md", ROOT / "docs-site" / "index.md"):
        copy = path.read_text(encoding="utf-8")
        assert approved_lead in copy
        assert "A gateway can be routed around." in copy

    public_positioning = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            ROOT / "README.md",
            ROOT / "docs-site" / "index.md",
            ROOT / "dashboard" / "app" / "_components" / "LandingPage.js",
        )
    )
    for competitor in (
        "AiFinPay",
        "A2A Governance Gateway",
        "LASTRE",
        "Phoenix Zero",
        "Sluice",
        "AgentPay",
        "CasperGuard",
    ):
        assert competitor not in public_positioning

    social = (ROOT / "docs" / "SOCIAL_LAUNCH.md").read_text(encoding="utf-8")
    assets = (ROOT / "docs" / "SUBMISSION_ASSETS_STATUS.md").read_text(encoding="utf-8")
    assert "Community channel pending" not in social
    assert "Telegram/Discord/community URL | Optional / pending" not in assets
    for url in (
        "https://t.me/CSPRDevelopers",
        "https://discord.com/invite/caspernetwork",
    ):
        assert url in social
        assert url in assets


def test_mkdocs_navigation_is_v1_5_scoped_and_all_links_resolve() -> None:
    config = yaml.safe_load((ROOT / "mkdocs.yml").read_text(encoding="utf-8"))
    nav_text = json.dumps(config["nav"])
    assert "release-scope.md" in nav_text
    assert "official-x402.md" not in nav_text
    assert "v3-envelope.md" not in nav_text
    assert "treasury-execution.md" not in nav_text
    assert "site/" in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "site" in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()

    completed = subprocess.run(
        ["python", "scripts/check_public_docs_links.py"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_verifier_0_1_4_metadata_and_docs_are_v1_first_compatibility_superset() -> None:
    package_root = ROOT / "packages" / "verify"
    package = json.loads((package_root / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((package_root / "package-lock.json").read_text(encoding="utf-8"))
    readme = (package_root / "README.md").read_text(encoding="utf-8")

    assert package["version"] == "0.1.4"
    assert lock["version"] == "0.1.4"
    assert lock["packages"][""]["version"] == "0.1.4"
    assert package["description"].lower().startswith(
        "read-only, fail-closed verifier for concordia v1"
    )
    assert package["publishConfig"] == {"access": "public"}
    assert "publish" not in package["scripts"]

    assert CANONICAL_PROPOSAL in readme
    assert "DAO-PROP-EXAMPLE" not in readme
    assert "casper-native x402 v2 exposes a live http 402 challenge" in readme.lower()
    assert "external facilitator service" in readme.lower()
    assert "mainnet has not been executed" in readme.lower()
    assert "governance v3 is excluded" in readme.lower()
    for proof_type in (
        "historical_odra_receipt_v2",
        "exact_envelope_v3",
        "native_treasury_execution_v1",
        "safepay_v2",
        "official_x402_settlement_v1",
        "approval_boundary_v1",
        "demo_capability_v1",
        "room_identity_v1",
        "snapshot",
    ):
        assert proof_type in readme


def test_security_register_and_default_setup_contract_are_preserved() -> None:
    security = (ROOT / ".github" / "SECURITY.md").read_text(encoding="utf-8")
    for advisory in (
        "GHSA-rc23-xxgq-x27g",
        "GHSA-537c-gmf6-5ccf",
        "GHSA-r6ph-v2qm-q3c2",
        "GHSA-wj6h-64fc-37mp",
    ):
        assert advisory in security
    for unshipped_claim in ("WP3", "WP5", "official x402 service", "Mainnet canary"):
        assert unshipped_claim not in security

    assert not (ROOT / ".github" / "workflows" / "codeql.yml").exists()
    assert not (ROOT / ".github" / "dependabot.yml").exists()

    for template in ("bug_report.md", "feature_request.md"):
        frontmatter = (ROOT / ".github" / "ISSUE_TEMPLATE" / template).read_text(
            encoding="utf-8"
        )
        assert 'assignees: ""' in frontmatter
