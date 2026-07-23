"""Artifact-lineage protection and end-to-end CLI mode behaviour."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import mc_support

from mc_support import build_valid_plan, make_observation
from tools.mainnet_canary.cli import main
from tools.mainnet_canary.constants import (
    BLOCKED_PENDING_LIVE_PROOF,
    MAINNET_ARTIFACT_NAMESPACE,
    MAINNET_SUPPLEMENTAL_PROVENANCE,
    PROTECTED_CANONICAL_PREFIXES,
)
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.stage import refuse_artifact_namespace_write, run_stage

REAL_REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_cli(capsys, argv: list[str]) -> tuple[int, dict[str, object]]:
    exit_code = main(argv)
    return exit_code, json.loads(capsys.readouterr().out)


# --- lineage ----------------------------------------------------------------


def test_live_artifact_namespace_is_unavailable_in_preparation(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    plan = build_valid_plan(plan_inputs)
    repo = plan_inputs["repo"]
    with pytest.raises(CanaryRefusal) as refusal:
        run_stage(
            repo,
            plan_document=plan,
            rc_declaration_path=plan_inputs["rc"],
            snapshot_path=plan_inputs["snapshot"],
            status_path=plan_inputs["status"],
            ceiling_path=plan_inputs["ceiling"],
            measured_costs_path=plan_inputs["measured"],
            journal_path=tmp_path / "journal.jsonl",
            output_dir=repo / "artifacts" / "mainnet-canary" / "v3" / "x",
            **mc_support.stage_gate_kwargs(plan_inputs, tmp_path),
        )
    assert refusal.value.code == RefusalCode.LIVE_ARTIFACTS_UNAVAILABLE_IN_PREP


def test_canonical_namespaces_are_protected_outright(
    hermetic_repo: Path,
) -> None:
    for prefix in PROTECTED_CANONICAL_PREFIXES:
        target = hermetic_repo / prefix / "anything"
        with pytest.raises(CanaryRefusal) as refusal:
            refuse_artifact_namespace_write(target, hermetic_repo)
        assert refusal.value.code == RefusalCode.CANONICAL_NAMESPACE_PROTECTED


def test_mainnet_supplemental_can_never_alias_canonical_namespaces() -> None:
    assert MAINNET_ARTIFACT_NAMESPACE.startswith("artifacts/mainnet-canary/")
    for prefix in PROTECTED_CANONICAL_PREFIXES:
        assert not MAINNET_ARTIFACT_NAMESPACE.startswith(prefix)
    assert MAINNET_SUPPLEMENTAL_PROVENANCE == "mainnet_supplemental"


def test_schema_only_fixtures_contain_no_invented_evidence() -> None:
    fixtures = (
        REAL_REPO_ROOT / "tests" / "mainnet_canary" / "fixtures" / "schema-only"
    )
    hex_like = set("0123456789abcdef")
    for path in sorted(fixtures.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))

        def walk(node: object) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    assert key != "verified", f"{path.name} asserts verification"
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)
            elif isinstance(node, str):
                stripped = node.lower()
                is_long_hex = len(stripped) >= 40 and set(stripped) <= hex_like
                assert not is_long_hex, f"{path.name} contains an invented hash"
            elif isinstance(node, (int, float)):
                assert node in (
                    0,
                    1,
                ), f"{path.name} contains an invented numeric value: {node}"

        walk(document)
        assert document.get("status", BLOCKED_PENDING_LIVE_PROOF) == (
            BLOCKED_PENDING_LIVE_PROOF
        )


def test_proof_pack_schema_is_supplemental_and_blocked() -> None:
    fixture = (
        REAL_REPO_ROOT
        / "tests"
        / "mainnet_canary"
        / "fixtures"
        / "schema-only"
        / "mainnet-proof-pack.schema-only.json"
    )
    document = json.loads(fixture.read_text(encoding="utf-8"))
    assert document["provenance"] == "mainnet_supplemental"
    assert document["lineage"] == "supplemental"
    assert document["status"] == BLOCKED_PENDING_LIVE_PROOF
    assert document["self_attested_green_status_present"] is False
    for field in (
        "wasm_sha256",
        "transaction_deploy_hashes",
        "before_quorum_refusal",
        "after_quorum_acceptance",
        "transfer_receipt",
    ):
        assert document[field] is None


# --- CLI modes ---------------------------------------------------------------


def test_cli_inventory_reports_missing_prerequisites(
    tmp_path: Path, capsys
) -> None:
    exit_code, output = _run_cli(
        capsys,
        [
            "inventory",
            "--key-inventory",
            str(tmp_path / "absent-inventory.json"),
            "--rc-declaration",
            str(tmp_path / "absent-rc.json"),
        ],
    )
    assert exit_code == 0
    assert output["mainnet_deployment_status"] == BLOCKED_PENDING_LIVE_PROOF
    assert output["network"]["chain_name"] == "casper"
    assert output["network"]["rpc_url"].startswith("https://node.mainnet")
    missing = "\n".join(output["missing_prerequisites"])
    assert "Testnet-RC declaration" in missing
    assert "live authorization" in missing
    assert "spending ceiling" in missing
    assert "UNKNOWN" in missing


def test_cli_inventory_prints_public_identities_only(
    plan_inputs: dict[str, Path], capsys
) -> None:
    exit_code, output = _run_cli(
        capsys,
        [
            "inventory",
            "--key-inventory",
            str(plan_inputs["inventory"]),
            "--rc-declaration",
            str(plan_inputs["rc"]),
        ],
    )
    assert exit_code == 0
    assert output["threshold"] == 2
    proposer = output["roles"]["proposer"]
    assert set(proposer) == {
        "public_key_hex",
        "account_hash_hex",
        "key_file_mount_path",
        "balance_motes",
    }
    assert proposer["balance_motes"] == "UNKNOWN_NOT_OBSERVED"
    assert output["rc_declaration"]["status"] == "PRESENT_UNVALIDATED"


def test_cli_estimate_refuses_at_the_preparation_base(capsys) -> None:
    exit_code, output = _run_cli(
        capsys, ["--repo-root", str(REAL_REPO_ROOT), "estimate"]
    )
    assert exit_code == 2
    assert output["refusal"]["code"] in (
        RefusalCode.COST_LINE_UNKNOWN,
        RefusalCode.COST_CEILING_ABSENT,
    )


def test_cli_plan_and_stage_round_trip(
    plan_inputs: dict[str, Path], tmp_path: Path, capsys
) -> None:
    plan_path = tmp_path / "plan.json"
    exit_code, output = _run_cli(
        capsys,
        [
            "--repo-root",
            str(plan_inputs["repo"]),
            "plan",
            "--rc-declaration",
            str(plan_inputs["rc"]),
            "--key-inventory",
            str(plan_inputs["inventory"]),
            "--parameters",
            str(plan_inputs["parameters"]),
            "--snapshot",
            str(plan_inputs["snapshot"]),
            "--status",
            str(plan_inputs["status"]),
            "--out",
            str(plan_path),
        ],
    )
    assert exit_code == 0
    assert output["live_proof_status"] == BLOCKED_PENDING_LIVE_PROOF
    assert plan_path.is_file()

    gates = mc_support.stage_gate_kwargs(plan_inputs, tmp_path)
    exit_code, staged = _run_cli(
        capsys,
        [
            "--repo-root",
            str(plan_inputs["repo"]),
            "stage",
            "--plan",
            str(plan_path),
            "--rc-declaration",
            str(plan_inputs["rc"]),
            "--snapshot",
            str(plan_inputs["snapshot"]),
            "--status",
            str(plan_inputs["status"]),
            "--ceiling",
            str(plan_inputs["ceiling"]),
            "--measured-costs",
            str(plan_inputs["measured"]),
            "--journal",
            str(tmp_path / "journal.jsonl"),
            "--out-dir",
            str(tmp_path / "staged"),
            # The CLI itself now requires the hardening gates.
            "--attestation",
            str(gates["attestation_path"]),
            "--calibration",
            str(gates["calibration_path"]),
            "--authorization",
            str(gates["authorization_path"]),
            "--snapshot-corroboration",
            str(gates["snapshot_corroboration_path"]),
            "--authorizer-key",
            mc_support.test_authorizer_public_key_hex(),
            "--clock-unix",
            str(gates["clock_unix"]),
        ],
    )
    assert exit_code == 0
    assert staged["broadcast_enabled"] is False
    assert len(staged["staged_steps"]) >= 6
    # The wired modules must show up in the CLI's own output, proving they
    # ran on this path rather than merely existing beside it.
    assert staged["build_attestation"]["double_built"] is True
    assert staged["economic_manifest"]["max_total_outlay_motes"]
    assert staged["human_authorization_nonce"]


def test_cli_stage_refuses_without_the_build_attestation(
    plan_inputs: dict[str, Path], tmp_path: Path, capsys
) -> None:
    """The attestation gate is on the CLI path, not just in a unit test."""

    plan_path = tmp_path / "plan.json"
    plan_path.write_text(
        json.dumps(build_valid_plan(plan_inputs), sort_keys=True), encoding="utf-8"
    )
    gates = mc_support.stage_gate_kwargs(plan_inputs, tmp_path)
    exit_code, output = _run_cli(
        capsys,
        [
            "--repo-root",
            str(plan_inputs["repo"]),
            "stage",
            "--plan",
            str(plan_path),
            "--rc-declaration",
            str(plan_inputs["rc"]),
            "--snapshot",
            str(plan_inputs["snapshot"]),
            "--status",
            str(plan_inputs["status"]),
            "--ceiling",
            str(plan_inputs["ceiling"]),
            "--measured-costs",
            str(plan_inputs["measured"]),
            "--journal",
            str(tmp_path / "journal2.jsonl"),
            "--out-dir",
            str(tmp_path / "staged2"),
            "--attestation",
            str(tmp_path / "no-such-attestation.json"),
            "--calibration",
            str(gates["calibration_path"]),
            "--authorization",
            str(gates["authorization_path"]),
            "--snapshot-corroboration",
            str(gates["snapshot_corroboration_path"]),
            "--authorizer-key",
            mc_support.test_authorizer_public_key_hex(),
            "--clock-unix",
            str(gates["clock_unix"]),
        ],
    )
    assert exit_code == 2
    assert output["refusal"]["code"] == RefusalCode.ARTIFACT_HASH_UNBACKED


def test_cli_stage_refuses_an_expired_human_authorization(
    plan_inputs: dict[str, Path], tmp_path: Path, capsys
) -> None:
    plan = build_valid_plan(plan_inputs)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
    gates = mc_support.stage_gate_kwargs(plan_inputs, tmp_path)
    exit_code, output = _run_cli(
        capsys,
        [
            "--repo-root",
            str(plan_inputs["repo"]),
            "stage",
            "--plan",
            str(plan_path),
            "--rc-declaration",
            str(plan_inputs["rc"]),
            "--snapshot",
            str(plan_inputs["snapshot"]),
            "--status",
            str(plan_inputs["status"]),
            "--ceiling",
            str(plan_inputs["ceiling"]),
            "--measured-costs",
            str(plan_inputs["measured"]),
            "--journal",
            str(tmp_path / "journal3.jsonl"),
            "--out-dir",
            str(tmp_path / "staged3"),
            "--attestation",
            str(gates["attestation_path"]),
            "--calibration",
            str(gates["calibration_path"]),
            "--authorization",
            str(gates["authorization_path"]),
            # Clock advanced well past the authorization's expiry.
            "--snapshot-corroboration",
            str(gates["snapshot_corroboration_path"]),
            "--authorizer-key",
            mc_support.test_authorizer_public_key_hex(),
            "--clock-unix",
            str(int(gates["clock_unix"]) + 999_999),
        ],
    )
    assert exit_code == 2
    assert output["refusal"]["code"] == RefusalCode.AUTHORIZATION_EXPIRED


def test_cli_verify_refuses_without_observations(
    plan_inputs: dict[str, Path], tmp_path: Path, capsys
) -> None:
    plan = build_valid_plan(plan_inputs)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
    exit_code, output = _run_cli(
        capsys,
        [
            "verify",
            "--plan",
            str(plan_path),
            "--observations",
            str(tmp_path / "absent-observations.json"),
        ],
    )
    assert exit_code == 2
    assert output["refusal"]["code"] == RefusalCode.OBSERVATION_ABSENT


def test_cli_verify_refuses_prequorum_success_end_to_end(
    plan_inputs: dict[str, Path], tmp_path: Path, capsys
) -> None:
    plan = build_valid_plan(plan_inputs)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")

    package = "8b" * 32
    contract = "9c" * 32

    def observed(step: dict[str, object], **overrides: object) -> dict[str, object]:
        return make_observation(
            str(step["step_id"]),
            target={
                "package_hash": package,
                "contract_hash": contract,
                "entry_point": step["entry_point"],
                "typed_args": {
                    str(arg["name"]): arg["value"] for arg in step["typed_args"]
                },
                "transfer": None,
            },
            **overrides,
        )

    bundle = []
    for step in plan["steps"]:
        if not step["economic"]:
            continue
        # Adversarial: the pre-quorum step "succeeds" on chain.
        # Emitted as a disjoint provider PAIR — verify refuses single-source.
        base = observed(step)
        for provider_id, host in (("provider-a", "node-a.example"),
                                  ("provider-b", "node-b.example")):
            doc = json.loads(json.dumps(base))
            doc["schema_id"] = "concordia.mainnet-canary.step-observation.v2"
            doc["provider"] = {
                "provider_id": provider_id, "endpoint_host": host,
                "method": "info_get_deploy", "request_sha256": "11" * 32,
                "response_sha256": "22" * 32,
                "retrieved_at_unix": mc_support.CLOCK_UNIX,
                "api_version": "2.0.0", "chainspec_name": "casper",
                "chain_tip_height": 128,
            }
            doc.setdefault("state_readback", None)
            bundle.append(doc)
    (tmp_path / "observations.json").write_text(
        json.dumps(bundle), encoding="utf-8"
    )

    exit_code, output = _run_cli(
        capsys,
        [
            "verify",
            "--plan",
            str(plan_path),
            "--observations",
            str(tmp_path / "observations.json"),
        ],
    )
    assert exit_code == 2
    assert output["refusal"]["code"] == RefusalCode.PREQUORUM_UNEXPECTED_SUCCESS


def test_cli_verify_never_claims_mainnet_verified(
    plan_inputs: dict[str, Path], tmp_path: Path, capsys
) -> None:
    plan = build_valid_plan(plan_inputs)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")

    package = "8b" * 32
    contract = "9c" * 32
    bundle = []
    for step in plan["steps"]:
        if not step["economic"]:
            continue
        step_id = str(step["step_id"])
        expected = step["expected_outcome"]
        overrides: dict[str, object] = {}
        transfer = None
        if expected.get("execution") == "failure":
            # E pre-quorum, F9 wrong-envelope, and H duplicate-finalize are
            # all finalized refusal proofs with exact error renderings.
            overrides["execution"] = {
                "success": False,
                "error_message": expected["exact_error_message"],
                "cost_motes": "100000000",
            }
        if step["kind"] == "native_transfer":
            transfer = {
                "source_account": expected["source_account"],
                "recipient_account": expected["recipient_account"],
                "amount_motes": expected["amount_motes"],
                "transfer_id": expected["transfer_id"],
            }
        bundle.extend(
            mc_support.make_v2_pair(
                step_id,
                target={
                    "package_hash": package,
                    "contract_hash": contract,
                    "entry_point": step["entry_point"],
                    "typed_args": {
                        str(arg["name"]): arg["value"] for arg in step["typed_args"]
                    },
                    "transfer": transfer,
                },
                **overrides,
            )
        )
    (tmp_path / "observations.json").write_text(
        json.dumps(bundle), encoding="utf-8"
    )
    exit_code, output = _run_cli(
        capsys,
        [
            "verify",
            "--plan",
            str(plan_path),
            "--observations",
            str(tmp_path / "observations.json"),
        ],
    )
    assert exit_code == 0
    assert output["canary_release_claim"] == BLOCKED_PENDING_LIVE_PROOF
    statuses = {step["status"] for step in output["steps"]}
    assert statuses == {"observation_consistent"}


# --- the hardening modules are ON the CLI path, not merely beside it ---------
#
# The audit finding these cover: attestation, finality_v2, economic_manifest
# and proof_bundle were unit-tested in isolation while the CLI never imported
# them, so they enforced nothing at runtime. Each test below drives the CLI
# itself and asserts the refusal that only the wired module can produce.


def test_cli_verify_refuses_single_source_observations(
    plan_inputs: dict[str, Path], tmp_path: Path, capsys
) -> None:
    """finality_v2 on the path: one provider is never sufficient evidence."""

    plan = build_valid_plan(plan_inputs)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
    single = [
        mc_support.make_v2_pair(str(step["step_id"]))[0]
        for step in plan["steps"]
        if step["economic"]
    ]
    (tmp_path / "single.json").write_text(json.dumps(single), encoding="utf-8")
    exit_code, output = _run_cli(
        capsys,
        ["verify", "--plan", str(plan_path), "--observations", str(tmp_path / "single.json")],
    )
    assert exit_code == 2
    assert output["refusal"]["code"] == RefusalCode.NODE_SET_INVALID


def test_cli_verify_refuses_a_v1_observation_bundle(
    plan_inputs: dict[str, Path], tmp_path: Path, capsys
) -> None:
    """Bundles without raw provider evidence can no longer be verified."""

    plan = build_valid_plan(plan_inputs)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
    legacy = [
        make_observation(str(step["step_id"]))
        for step in plan["steps"]
        if step["economic"]
        for _ in (0, 1)
    ]
    (tmp_path / "legacy.json").write_text(json.dumps(legacy), encoding="utf-8")
    exit_code, output = _run_cli(
        capsys,
        ["verify", "--plan", str(plan_path), "--observations", str(tmp_path / "legacy.json")],
    )
    assert exit_code == 2
    assert output["refusal"]["code"] in (
        RefusalCode.OBSERVATION_MALFORMED,
        RefusalCode.NODE_SET_INVALID,
    )


def test_cli_funding_reports_the_exact_maximum_only(
    plan_inputs: dict[str, Path], tmp_path: Path, capsys
) -> None:
    """economic_manifest on the path: one number, and no acquisition step."""

    plan = build_valid_plan(plan_inputs)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
    gates = mc_support.stage_gate_kwargs(plan_inputs, tmp_path)
    exit_code, output = _run_cli(
        capsys,
        [
            "funding",
            "--plan",
            str(plan_path),
            "--calibration",
            str(gates["calibration_path"]),
        ],
    )
    assert exit_code == 0
    total = int(output["required_funding_motes"])
    assert total == int(output["transfer_principal_motes"]) + int(
        output["max_fees_motes"]
    )
    assert "never purchases" in output["acquisition"]


def test_cli_funding_refuses_without_calibration(
    plan_inputs: dict[str, Path], tmp_path: Path, capsys
) -> None:
    plan = build_valid_plan(plan_inputs)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
    empty = tmp_path / "empty-calibration.json"
    empty.write_text(
        json.dumps(
            {"schema_id": "concordia.mainnet-canary.testnet-calibration.v1", "lines": {}}
        ),
        encoding="utf-8",
    )
    exit_code, output = _run_cli(
        capsys,
        ["funding", "--plan", str(plan_path), "--calibration", str(empty)],
    )
    assert exit_code == 2
    assert output["refusal"]["code"] == RefusalCode.CALIBRATION_RECEIPT_ABSENT


def _journal_bound_to(plan: dict[str, object], path: Path) -> Path:
    """A real journal whose genesis binds this plan — the bundle reads its
    head rather than trusting an operator-supplied value."""

    from tools.mainnet_canary.journal import CanaryJournal

    journal = CanaryJournal.create(
        path, plan_hash=str(plan["canary_plan_sha256"]), rc_tag="rc"
    )
    journal.close()
    return path


def test_cli_bundle_emits_lineage_and_required_statement(
    plan_inputs: dict[str, Path], tmp_path: Path, capsys
) -> None:
    """proof_bundle on the path: lineage, verbatim statement, confined write."""

    from tools.mainnet_canary.economic_manifest import build_economic_manifest
    from tools.mainnet_canary.proof_bundle import BUNDLE_LINEAGE, REQUIRED_STATEMENT

    plan = build_valid_plan(plan_inputs)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
    gates = mc_support.stage_gate_kwargs(plan_inputs, tmp_path)
    manifest = build_economic_manifest(
        plan,
        calibration=mc_support.make_calibration(plan),
        operator_ceilings={},
    )
    manifest_path = mc_support.write_json(tmp_path / "manifest.json", manifest)
    verification_path = mc_support.write_json(
        tmp_path / "verification.json",
        {
            "mode": "verify",
            "plan_hash": plan["canary_plan_sha256"],
            "steps": [{"step_id": "G-finalize-exact-envelope"}],
        },
    )
    journal_for_bundle = _journal_bound_to(plan, tmp_path / "bundle-journal.jsonl")
    exit_code, output = _run_cli(
        capsys,
        [
            "--repo-root",
            str(plan_inputs["repo"]),
            "bundle",
            "--plan",
            str(plan_path),
            "--verification",
            str(verification_path),
            "--economic-manifest",
            str(manifest_path),
            "--attestation",
            str(gates["attestation_path"]),
            "--journal",
            str(journal_for_bundle),
            "--out-dir",
            str(tmp_path / "bundle-out"),
        ],
    )
    assert exit_code == 0
    assert output["lineage"] == BUNDLE_LINEAGE == "concordia-mainnet-canary-v1"
    assert output["required_statement"] == REQUIRED_STATEMENT
    assert Path(output["bundle_path"]).is_file()


def test_cli_bundle_refuses_to_write_into_a_protected_namespace(
    plan_inputs: dict[str, Path], tmp_path: Path, capsys
) -> None:
    """path_policy still fences the bundle writer."""

    from tools.mainnet_canary.economic_manifest import build_economic_manifest

    plan = build_valid_plan(plan_inputs)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")
    gates = mc_support.stage_gate_kwargs(plan_inputs, tmp_path)
    manifest_path = mc_support.write_json(
        tmp_path / "manifest2.json",
        build_economic_manifest(
            plan, calibration=mc_support.make_calibration(plan), operator_ceilings={}
        ),
    )
    verification_path = mc_support.write_json(
        tmp_path / "verification2.json",
        {"mode": "verify", "plan_hash": plan["canary_plan_sha256"], "steps": []},
    )
    journal_for_bundle = _journal_bound_to(plan, tmp_path / "bundle-journal2.jsonl")
    exit_code, output = _run_cli(
        capsys,
        [
            "--repo-root",
            str(plan_inputs["repo"]),
            "bundle",
            "--plan",
            str(plan_path),
            "--verification",
            str(verification_path),
            "--economic-manifest",
            str(manifest_path),
            "--attestation",
            str(gates["attestation_path"]),
            "--journal",
            str(journal_for_bundle),
            "--out-dir",
            str(plan_inputs["repo"] / "artifacts" / "live" / "x"),
        ],
    )
    assert exit_code == 2
    assert output["refusal"]["code"] in (
        RefusalCode.CANONICAL_NAMESPACE_PROTECTED,
        RefusalCode.LIVE_ARTIFACTS_UNAVAILABLE_IN_PREP,
    )
