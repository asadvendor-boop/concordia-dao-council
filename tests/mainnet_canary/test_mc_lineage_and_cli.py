"""Artifact-lineage protection and end-to-end CLI mode behaviour."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

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
        ],
    )
    assert exit_code == 0
    assert staged["broadcast_enabled"] is False
    assert len(staged["staged_steps"]) >= 6


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
        bundle.append(observed(step))
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
        if step_id == "E-prequorum-finalize-refusal":
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
        bundle.append(
            make_observation(
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
