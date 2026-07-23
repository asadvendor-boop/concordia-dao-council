"""Failure-first tests for plan assembly and unsigned-payload staging."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import mc_support
from mc_support import (
    build_valid_plan,
    make_parameters,
    make_snapshot,
    make_status,
    write_json,
)
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.journal import CanaryJournal
from tools.mainnet_canary.plan import build_plan, plan_document_hash
from tools.mainnet_canary.stage import run_stage


def _plan_with(plan_inputs: dict[str, Path], **replacements: Path) -> object:
    arguments = dict(plan_inputs)
    arguments.update(replacements)
    return build_plan(
        arguments["repo"],
        rc_declaration_path=arguments["rc"],
        key_inventory_path=arguments["inventory"],
        parameters_path=arguments["parameters"],
        snapshot_path=arguments["snapshot"],
        status_path=arguments["status"],
    )


def test_valid_plan_builds_with_recomputed_identifiers(
    plan_inputs: dict[str, Path],
) -> None:
    plan = build_valid_plan(plan_inputs)
    assert plan["network"]["chain_name"] == "casper"
    derived = plan["envelope"]["derived"]
    assert plan["envelope"]["header"]["action_id"] == derived["action_id"]
    assert plan["envelope"]["body"]["transfer_id"] == derived["transfer_id"]
    assert plan["envelope"]["body"]["amount_motes"] == "50000000000"
    assert plan["canary_plan_sha256"] == plan_document_hash(plan)
    assert plan["live_proof_status"] == "BLOCKED_PENDING_LIVE_PROOF"
    step_ids = [step["step_id"] for step in plan["steps"]]
    assert step_ids[0] == "A-network-preflight"
    assert "E-prequorum-finalize-refusal" in step_ids
    assert "K-supplemental-proof-pack" in step_ids
    prequorum = [
        step
        for step in plan["steps"]
        if step["step_id"] == "E-prequorum-finalize-refusal"
    ][0]
    assert prequorum["expected_outcome"]["exact_error_message"] == "User error: 8"
    assert prequorum["expected_outcome"]["error_name"] == "QuorumNotMet"


def test_plan_is_deterministic(plan_inputs: dict[str, Path]) -> None:
    first = build_valid_plan(plan_inputs)
    second = build_valid_plan(plan_inputs)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_plan_without_rc_declaration_is_refused(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    with pytest.raises(CanaryRefusal) as refusal:
        _plan_with(plan_inputs, rc=tmp_path / "absent-rc.json")
    assert refusal.value.code == RefusalCode.RC_DECLARATION_ABSENT


def test_plan_without_inventory_is_refused(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    with pytest.raises(CanaryRefusal) as refusal:
        _plan_with(plan_inputs, inventory=tmp_path / "absent-inventory.json")
    assert refusal.value.code == RefusalCode.KEY_INVENTORY_ABSENT


def test_testnet_snapshot_is_refused(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    snapshot = write_json(
        tmp_path / "bad-snapshot.json", make_snapshot(chain_name="casper-test")
    )
    with pytest.raises(CanaryRefusal) as refusal:
        _plan_with(plan_inputs, snapshot=snapshot)
    assert refusal.value.code == RefusalCode.NETWORK_MISMATCH


def test_stale_snapshot_is_refused(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    status = write_json(
        tmp_path / "late-status.json",
        make_status(latest_block_height=200, latest_timestamp_unix=1_002_000),
    )
    with pytest.raises(CanaryRefusal) as refusal:
        _plan_with(plan_inputs, status=status)
    assert refusal.value.code == RefusalCode.STATE_ROOT_STALE


def test_snapshot_newer_than_head_is_refused(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    status = write_json(
        tmp_path / "old-status.json",
        make_status(latest_block_height=50, latest_timestamp_unix=999_000),
    )
    with pytest.raises(CanaryRefusal) as refusal:
        _plan_with(plan_inputs, status=status)
    assert refusal.value.code == RefusalCode.STATE_ROOT_STALE


def test_snapshot_for_wrong_account_is_refused(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    snapshot = write_json(
        tmp_path / "foreign-snapshot.json", make_snapshot(account_hash="9" * 64)
    )
    with pytest.raises(CanaryRefusal) as refusal:
        _plan_with(plan_inputs, snapshot=snapshot)
    assert refusal.value.code == RefusalCode.PLAN_INPUT_INVALID


def test_amount_above_tiny_cap_is_refused(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    parameters = write_json(
        tmp_path / "greedy-parameters.json",
        make_parameters(max_amount_motes="49999999999"),
    )
    with pytest.raises(CanaryRefusal) as refusal:
        _plan_with(plan_inputs, parameters=parameters)
    assert refusal.value.code == RefusalCode.AMOUNT_MISMATCH


def test_non_executable_decision_is_refused(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    parameters = write_json(
        tmp_path / "rejected-parameters.json", make_parameters(decision_code=0)
    )
    with pytest.raises(CanaryRefusal) as refusal:
        _plan_with(plan_inputs, parameters=parameters)
    assert refusal.value.code == RefusalCode.ENVELOPE_INVALID


def test_zero_action_nonce_parameter_is_refused(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    parameters = write_json(
        tmp_path / "zero-nonce-parameters.json",
        make_parameters(action_nonce="00" * 32),
    )
    with pytest.raises(CanaryRefusal) as refusal:
        _plan_with(plan_inputs, parameters=parameters)
    assert refusal.value.code == RefusalCode.ENVELOPE_INVALID


def _stage(
    plan_inputs: dict[str, Path],
    plan_document: dict[str, object],
    tmp_path: Path,
    **overrides: object,
) -> dict[str, object]:
    arguments: dict[str, object] = {
        "plan_document": plan_document,
        "rc_declaration_path": plan_inputs["rc"],
        "snapshot_path": plan_inputs["snapshot"],
        "status_path": plan_inputs["status"],
        "ceiling_path": plan_inputs["ceiling"],
        "measured_costs_path": plan_inputs["measured"],
        "journal_path": tmp_path / "journal.jsonl",
        "output_dir": tmp_path / "staged",
        # The hardening gates are REQUIRED arguments of run_stage: staging
        # cannot proceed on an unattested artifact, an ungrounded cost model,
        # or an unsigned/expired human authorization.
        **mc_support.stage_gate_kwargs(plan_inputs, tmp_path),
    }
    arguments.update(overrides)
    return run_stage(plan_inputs["repo"], **arguments)


def test_stage_produces_content_addressed_unsigned_intents(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    plan = build_valid_plan(plan_inputs)
    report = _stage(plan_inputs, plan, tmp_path)
    assert report["broadcast_enabled"] is False
    staged = report["staged_steps"]
    economic = [step for step in plan["steps"] if step["economic"]]
    assert len(staged) == len(economic)
    import hashlib

    for entry in staged:
        payload = Path(entry["unsigned_intent_path"]).read_bytes()
        assert entry["signed"] is False
        assert hashlib.sha256(payload).hexdigest() == entry["unsigned_intent_sha256"]
        assert payload.startswith(b"CONCORDIA_MAINNET_CANARY_UNSIGNED_INTENT_V1\x00")
    journal = CanaryJournal.load(tmp_path / "journal.jsonl")
    for entry in staged:
        status = journal.step_status(str(entry["step_id"]))
        assert status is not None and status.state == "STAGED"


def test_stage_without_cost_grounding_is_refused(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    plan = build_valid_plan(plan_inputs)
    with pytest.raises(CanaryRefusal) as refusal:
        _stage(plan_inputs, plan, tmp_path, measured_costs_path=None)
    assert refusal.value.code == RefusalCode.COST_LINE_UNKNOWN


def test_stage_without_ceiling_is_refused(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    plan = build_valid_plan(plan_inputs)
    with pytest.raises(CanaryRefusal) as refusal:
        _stage(plan_inputs, plan, tmp_path, ceiling_path=None)
    assert refusal.value.code == RefusalCode.COST_CEILING_ABSENT


def test_stage_refuses_tampered_plan(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    plan = build_valid_plan(plan_inputs)
    plan["envelope"]["body"]["amount_motes"] = "99999999999"
    with pytest.raises(CanaryRefusal) as refusal:
        _stage(plan_inputs, plan, tmp_path)
    assert refusal.value.code == RefusalCode.PLAN_HASH_MISMATCH


def test_stage_refuses_snapshot_drift(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    plan = build_valid_plan(plan_inputs)
    moved = write_json(
        tmp_path / "moved-snapshot.json",
        make_snapshot(block_hash="4e" * 32, block_height=105),
    )
    with pytest.raises(CanaryRefusal) as refusal:
        _stage(plan_inputs, plan, tmp_path, snapshot_path=moved)
    assert refusal.value.code == RefusalCode.STATE_ROOT_STALE


def test_stage_twice_is_idempotent_without_duplicates(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    plan = build_valid_plan(plan_inputs)
    first = _stage(plan_inputs, plan, tmp_path)
    second = _stage(plan_inputs, plan, tmp_path)
    assert [entry["unsigned_intent_sha256"] for entry in first["staged_steps"]] == [
        entry["unsigned_intent_sha256"] for entry in second["staged_steps"]
    ]


def test_stage_refuses_after_in_flight_restart(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    plan = build_valid_plan(plan_inputs)
    _stage(plan_inputs, plan, tmp_path)
    journal = CanaryJournal.load(tmp_path / "journal.jsonl")
    plan_hash = str(plan["canary_plan_sha256"])
    journal.transition(
        "B-install-rc-wasm", "AUTHORIZATION_VALIDATED", plan_hash=plan_hash
    )
    journal.transition(
        "B-install-rc-wasm",
        "SIGNED",
        plan_hash=plan_hash,
        deploy_hash="d0" * 32,
        signed_bytes_sha256="b1" * 32,
    )
    journal.close()
    with pytest.raises(CanaryRefusal) as refusal:
        _stage(plan_inputs, plan, tmp_path)
    assert refusal.value.code == RefusalCode.RECONCILIATION_REQUIRED
