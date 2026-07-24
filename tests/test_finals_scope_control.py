"""Durable finals scope must enumerate every non-cuttable gate and truth rule."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from scripts.check_repo_hygiene import BLOCKED


ROOT = Path(__file__).resolve().parents[1]
CONTROL = ROOT / "handoff/FINALS_SCOPE_CONTROL.json"
FREEZE = ROOT / "handoff/G1_FREEZE_MANIFEST.json"
LEDGER = ROOT / "handoff/EXECUTION_STATE.md"

FORMAL_GATES = [
    "G0",
    "G1",
    "G2",
    "G3",
    "G4",
    "G5",
    "G6",
    "G7a",
    "G7b",
    "G8",
    "G9",
    "G9n",
    "G9d",
    "G10",
    "G11",
    "G12",
    "G13",
]

HUMAN_PREREQUISITES = {
    "installer_funding",
    "proposer_identity_and_funding",
    "finalizer_identity_and_funding",
    "three_signer_custody_and_funding",
    "safepay_payer_funding",
    "dedicated_treasury_exact_balance",
    "native_transfer_recipient",
    "wcspr_payer_and_balance",
    "treasury_gas_and_rerun_reserve",
    "wcspr_payee",
    "facilitator_access",
    "namecheap_authority",
    "github_pages_authority",
    "npm_scope_login_2fa",
    "vm_caddy_authority",
    "youtube_authority",
    "dorahacks_authority_and_backup",
}

EXACT_GATE_DEPENDENCIES = {
    "G0": [],
    "G1": [],
    "G2": ["G1"],
    "G3": ["G2"],
    "G4": ["G2"],
    "G5": ["G4"],
    "G6": ["G4", "G5"],
    "G7a": ["G0", "G3", "G4", "G5"],
    "G7b": ["G0", "G3", "G4", "G5"],
    "G8": ["G6", "G7a", "G7b"],
    "G9": ["G8"],
    "G9n": ["G8"],
    "G9d": ["G8"],
    "G10": ["G9", "G9n", "G9d"],
    "G11": ["G10"],
    "G12": ["G11"],
    "G13": ["G12"],
}

REQUIRED_GATE_PHRASES = {
    "G0": [
        "installer-deployer holds 250 cspr",
        "proposer 25 cspr",
        "finalizer 40 cspr",
        "each of three signers 25 cspr",
        "safepay payer 20 cspr",
        "exactly 625.000000000 cspr",
        "60 cspr for swap source plus gas",
        "at least 25 wcspr plus enough native cspr for fees",
        "5 cspr gas allowance budgeted and recorded separately",
        "100 cspr remains as rerun reserve",
        "transfer_with_authorization abi",
        "four design references",
        "77 image digests",
        "historical contract and live-artifact sha-256 inventories",
        "fresh baseline",
        "provider tls",
    ],
    "G7a": [
        "thirteen-step",
        "quorumnotmet error 8",
        "envelopehashmismatch error 10",
        "alreadyfinalized error 12",
        "action_authorized true",
        "duplicate executor invocation creates no second transfer",
        "source account",
        "recipient account",
        "proposal-derived transfer id",
        "finality",
        "gas",
    ],
    "G7b": [
        "real unauthenticated resource request returning http 402",
        "isvalid true",
        "success true",
        "finalized on-chain transfer_with_authorization",
        "identical retried request",
        "without a second debit",
        "direct duplicate settlement attempt fails",
        "cross-resource reuse",
        "tampered authorization",
    ],
    "G9n": [
        "mutation tests",
        "rust-python-javascript golden vectors",
        "file allowlist",
        "secret scan",
        "clean-room install",
        "tampered-proof refusal",
        "unavailable-proof refusal",
        "npm view",
        "second independent registry download",
        "registry-visible provenance",
        "npm audit signatures",
    ],
    "G9d": [
        "hash-checked strict mkdocs build",
        "15 committed information-architecture sections",
        "custom 404",
        "internal-only or credential-bearing documents are excluded",
        "least-privilege permissions",
        "pages ownership is verified before the docs cname",
        "enforced https",
        "deployed content hash",
    ],
    "G10": [
        "non-concordia co-hosted judged application's submitted sslip alias",
        "concordia's retired sslip aliases remain rejected",
        "apex, www, docs, safepay, and x402",
    ],
}

KNOWN_GAPS = {
    "RELEASE_COLLECTOR_CORRECTION_GATE",
    "WP2_CORRECTION_GATE",
    "WP3_CORRECTION_GATE",
    "WP7_CORRECTION_GATE",
    "WP5_LIVE_TOOLING",
    "WP9_INFORMATION_ARCHITECTURE",
    "WP11_COPY_AND_VIDEO",
    "EXACT_FILE_MAP_DISPOSITION",
    "REPOSITORY_HYGIENE",
}


def _control() -> dict[str, object]:
    loaded = json.loads(CONTROL.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _joined(value: object) -> str:
    return json.dumps(value, sort_keys=True).lower().replace("-", " ")


def test_scope_control_contains_no_cross_project_identifiers() -> None:
    text = CONTROL.read_text(encoding="utf-8")

    assert [term for term in BLOCKED if term in text] == []


def test_scope_control_is_bound_to_the_g1_manifest_authority() -> None:
    control = _control()
    freeze = json.loads(FREEZE.read_text(encoding="utf-8"))

    assert control["schema"] == "concordia-finals-scope-control-v1"
    assert control["status"] == "active"
    authority = freeze["authority"]
    assert control["source_documents"] == [
        {
            "name": Path(authority["plan"]["path"]).name,
            "sha256": authority["plan"]["sha256"],
        },
        {
            "name": Path(authority["addendum"]["path"]).name,
            "sha256": authority["addendum"]["sha256"],
        },
    ]
    assert freeze["status"] == "ready"
    assert freeze["tag"] == "concordia-g1-freeze-v2.0-a"
    tag_type = subprocess.run(
        ["git", "cat-file", "-t", freeze["tag"]],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    peeled = subprocess.run(
        ["git", "rev-parse", f"{freeze['tag']}^{{}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert tag_type == "tag"
    assert peeled == "b24c0409023e6c4b56287d4fddc17bdb42d9b1ac"
    assert control["scope_policy"] == {
        "committed_items_are_non_cuttable": True,
        "rollback_is_availability_only": True,
        "rollback_never_completes_a_gate": True,
        "missing_authority_blocks_instead_of_reducing_scope": True,
        "only_tail_items": ["MIT_TO_AGPL_DECISION", "EXTRA_TUTORIAL_SCREENCASTS"],
    }


def test_every_formal_release_gate_is_explicit_dependency_ordered_and_fail_closed() -> (
    None
):
    control = _control()
    gates = control["gates"]
    assert isinstance(gates, list)
    assert [gate["id"] for gate in gates] == FORMAL_GATES

    allowed_statuses = {"pending", "in_progress", "blocked", "pass"}
    by_id = {gate["id"]: gate for gate in gates}
    seen: set[str] = set()
    for gate in gates:
        assert gate["status"] in allowed_statuses
        assert isinstance(gate["depends_on"], list)
        assert gate["depends_on"] == EXACT_GATE_DEPENDENCIES[gate["id"]]
        assert set(gate["depends_on"]).issubset(seen)
        assert isinstance(gate["acceptance"], list) and gate["acceptance"]
        assert isinstance(gate["evidence"], list)
        assert isinstance(gate["next_action"], str) and gate["next_action"]
        if gate["status"] == "pass":
            assert gate["evidence"]
            assert all(
                by_id[dependency]["status"] == "pass"
                for dependency in gate["depends_on"]
            )
        seen.add(gate["id"])

    assert by_id["G1"]["status"] == "pass"
    assert by_id["G7b"]["status"] == "blocked"
    assert by_id["G8"]["depends_on"] == ["G6", "G7a", "G7b"]
    assert by_id["G10"]["depends_on"] == ["G9", "G9n", "G9d"]


def test_high_risk_gate_acceptance_contains_every_approved_live_predicate() -> None:
    by_id = {gate["id"]: gate for gate in _control()["gates"]}

    for gate_id, phrases in REQUIRED_GATE_PHRASES.items():
        acceptance = _joined(by_id[gate_id]["acceptance"])
        for phrase in phrases:
            normalized = phrase.lower().replace("-", " ")
            assert normalized in acceptance, (
                f"{gate_id} omits required predicate: {phrase}"
            )


def test_every_human_prerequisite_has_owner_status_evidence_and_action() -> None:
    prerequisites = _control()["human_prerequisites"]
    assert isinstance(prerequisites, list)
    assert {item["id"] for item in prerequisites} == HUMAN_PREREQUISITES

    for item in prerequisites:
        assert item["owner"] in {"Asad", "Asad+Codex"}
        assert item["status"] in {"pass", "partial", "blocked", "pending_verification"}
        assert isinstance(item["required"], str) and item["required"]
        assert isinstance(item["evidence"], list) and item["evidence"]
        assert isinstance(item["next_action"], str) and item["next_action"]

    by_id = {item["id"]: item for item in prerequisites}
    assert by_id["dedicated_treasury_exact_balance"]["required"] == (
        "625.000000000 CSPR exactly before the evidenced snapshot"
    )
    assert by_id["wcspr_payer_and_balance"]["required"] == (
        "60 CSPR as swap source plus gas, converted to at least 25 WCSPR while preserving enough native CSPR for fees"
    )
    assert by_id["treasury_gas_and_rerun_reserve"]["required"] == (
        "5 CSPR treasury gas planning allowance and 100 CSPR rerun reserve remain allocated outside the evidenced 625-CSPR baseline until live execution"
    )
    assert by_id["npm_scope_login_2fa"]["required"] == (
        "concordia-dao ownership, login, publishing 2FA, and first-release provenance"
    )


def test_a2_through_a5_are_normative_and_cannot_be_upgraded_by_marketing() -> None:
    truth = _control()["truth_contract"]
    assert list(truth) == ["A2", "A3", "A4", "A5"]

    a2 = truth["A2"]
    assert a2["deliberative_agents"] == ["Rowan", "Mercer", "Verity", "Alden"]
    assert a2["locke_role"] == "authorization-bound execution signer"
    assert a2["core_role"] == "deterministic evidence core"
    assert a2["wells_role"] == "non-reasoning presentation and archival persona"
    assert a2["future_archive_builder"] == "Core"
    assert a2["future_archive_sealer"] == "Locke"
    assert a2["historical_sealed_attribution_is_rewritten"] is False
    forbidden = _joined(a2["forbidden_claims"])
    for false_claim in [
        "six reasoning agents deliberate",
        "wells independently reasons",
        "wells deterministically produces the archive",
    ]:
        assert false_claim in forbidden

    a3 = truth["A3"]
    assert a3["historical_v2_claim"].startswith("The historical v2 contract")
    assert a3["v3_claim"] == (
        "Casper quorum and exact approved-envelope binding are both enforced on-chain by Concordia v3."
    )
    assert a3["native_transfer_claim"] == (
        "authorized by on-chain quorum, bound to the approved envelope hash, executed as a native transfer"
    )
    assert a3["contract_custodies_or_disburses_treasury"] is False

    a4 = truth["A4"]
    assert a4["council_chamber_is_auth_boundary"] is False
    assert a4["human_approval_uses_separate_trusted_path"] is True
    assert a4["agent_identity_is_derived_from_authenticated_key"] is True
    required_boundary_topics = {
        "public and internal endpoints",
        "credential and key custody",
        "Caddy and provider trust",
        "proof lineage",
        "human approval",
        "operator capabilities and tokens",
    }
    assert set(a4["must_document"]) == required_boundary_topics

    a5 = truth["A5"]
    assert a5["policy_categories"] == [
        "Enforced",
        "Evidenced",
        "Presentation",
        "Roadmap",
    ]
    assert a5["classification_source"] == "predicates and tests"
    assert a5["marketing_interpretation_can_upgrade_category"] is False


def test_financial_claims_and_first_publish_cannot_fail_open() -> None:
    control = _control()
    claims = control["financial_claims"]

    assert claims["safepay_lite"]["asset"] == "native CSPR"
    assert claims["safepay_lite"]["public_semantic"] == (
        "replay-safe and no double consumption; exact same-resource retries are idempotent"
    )
    assert claims["official_x402"]["asset"] == "WCSPR"
    assert claims["official_x402"]["may_claim_governed_only_after"] == (
        "a finalized v3 authorization followed by success:true settlement and finalized on-chain verification"
    )
    assert claims["official_x402"]["may_be_called_native_cspr"] is False

    release = control["npm_release"]
    assert release["first_release_requires_registry_visible_provenance"] is True
    assert release["provenance_free_bootstrap_allowed"] is False
    assert release["required_postpublish_check"] == "npm audit signatures"
    for binding in [
        "registry gitHead",
        "exact tarball SHA-512 and SHA-256",
        "provenance subject digest",
        "provenance source repository and commit",
    ]:
        assert binding in release["required_binding"]


def test_every_known_scope_gap_remains_explicitly_blocking() -> None:
    gaps = _control()["known_scope_gaps"]
    assert {gap["id"] for gap in gaps} == KNOWN_GAPS
    assert all(gap["status"] == "blocking" for gap in gaps)
    assert all(gap["required"] for gap in gaps)

    joined = _joined(gaps)
    for required in [
        "pypdf",
        "strict typed request and response schemas",
        "never retry 409",
        "short-lived scenario-scoped",
        "derive room sender identity",
        "stale cross-proposal state",
        "fe-01 through fe-20",
        "scripts/run_x402_live_proof.py",
        "eleven-beat video script",
        ".playwright-cli",
        "second independent adversarial review",
        "deep route-specific response predicates",
        "pages deployment status",
        "offline self-test",
        "partial or fallback argument sets are forbidden",
        "pending finality as pending",
        "persisted exact transaction hash",
        "reject runtime origin overrides",
        "without rerunning expired or live governance gates",
        "artifact transcript consistency",
        "remove all overclaims",
    ]:
        normalized = required.lower().replace("-", " ")
        assert normalized in joined

    by_id = {gap["id"]: gap for gap in gaps}
    assert len(by_id["WP9_INFORMATION_ARCHITECTURE"]["required"]) == 15
    assert by_id["WP9_INFORMATION_ARCHITECTURE"]["required"] == [
        "Product overview",
        "Judge quickstart",
        "Architecture and trust boundaries",
        "Agent and role taxonomy",
        "v1 v2 v3 lineage",
        "v3 envelope specification",
        "SafePay Lite",
        "Official x402",
        "Treasury execution",
        "Proof provenance",
        "Verifier SDK and CLI",
        "Policy matrix",
        "Deployment and security",
        "Public receipts",
        "Launch roadmap",
    ]


def test_scope_control_contains_no_credential_material() -> None:
    serialized = CONTROL.read_text(encoding="utf-8")
    forbidden_patterns = [
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"ghp_[A-Za-z0-9]{20,}",
        r"github_pat_[A-Za-z0-9_]{20,}",
        r"npm_[A-Za-z0-9]{20,}",
        r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{12,}",
        r"(?i)authorization\s*[:=]\s*[A-Za-z0-9._~+/=-]{12,}",
    ]
    for pattern in forbidden_patterns:
        assert re.search(pattern, serialized) is None


def test_execution_ledger_statuses_match_scope_control_and_history_is_nonoperative() -> (
    None
):
    ledger = LEDGER.read_text(encoding="utf-8")
    control = _control()

    assert "handoff/FINALS_SCOPE_CONTROL.json" in ledger
    assert "every G0-G13 gate" in ledger
    assert "## Current operational checkpoint" in ledger
    assert "## Formal release-gate index" in ledger
    assert "## Human-prerequisite index" in ledger
    assert "3d51406873ec89e73aabe22a6fc1bfa842422c30" in ledger
    assert "7a8b9e1" in ledger
    assert "8956f97" in ledger
    assert "first release deliberately makes no provenance claim" not in ledger
    assert "## Latest checkpoint" not in ledger

    table = re.findall(r"^\| (G(?:\d+[a-z]?)) \| ([A-Z_]+) \|", ledger, re.MULTILINE)
    ledger_statuses = {gate_id: status.lower() for gate_id, status in table}
    control_statuses = {gate["id"]: gate["status"] for gate in control["gates"]}
    assert ledger_statuses == control_statuses

    historical_heading = "## Historical checkpoint narrative (non-operative)"
    assert ledger.count(historical_heading) == 1
    historical_index = ledger.index(historical_heading)
    history = ledger[historical_index:]
    assert "must not be used to decide the next action" in history
    assert "## Current operational checkpoint" not in history
    assert "## Formal release-gate index" not in history
    assert "## Human-prerequisite index" not in history
    assert not any(line.startswith("## ") for line in history.splitlines()[1:]), (
        "No level-two section may regain operational authority after the historical boundary"
    )
