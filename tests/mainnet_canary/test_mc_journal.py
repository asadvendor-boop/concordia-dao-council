"""Durable journal: tamper detection and reconcile-not-duplicate restarts."""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.journal import CanaryJournal

PLAN_HASH = "f" * 64
STEP = "I-executor-native-transfer"
DEPLOY = "d" * 64
SIGNED_BYTES = "c" * 64


def _fresh(tmp_path: Path) -> CanaryJournal:
    return CanaryJournal.create(
        tmp_path / "journal.jsonl", plan_hash=PLAN_HASH, rc_tag="rc-test"
    )


def test_create_refuses_to_overwrite_existing_journal(tmp_path: Path) -> None:
    _fresh(tmp_path)
    with pytest.raises(CanaryRefusal) as refusal:
        _fresh(tmp_path)
    assert refusal.value.code == RefusalCode.JOURNAL_CONFLICT


def test_missing_journal_is_a_stable_refusal(tmp_path: Path) -> None:
    with pytest.raises(CanaryRefusal) as refusal:
        CanaryJournal.load(tmp_path / "nope.jsonl")
    assert refusal.value.code == RefusalCode.JOURNAL_ABSENT


def test_happy_path_survives_restart(tmp_path: Path) -> None:
    journal = _fresh(tmp_path)
    journal.transition(STEP, "PLANNED", plan_hash=PLAN_HASH)
    journal.transition(STEP, "STAGED", plan_hash=PLAN_HASH)
    journal.close()
    reloaded = CanaryJournal.load(tmp_path / "journal.jsonl")
    status = reloaded.step_status(STEP)
    assert status is not None and status.state == "STAGED"
    assert reloaded.plan_hash == PLAN_HASH


def test_wrong_plan_hash_is_refused(tmp_path: Path) -> None:
    journal = _fresh(tmp_path)
    with pytest.raises(CanaryRefusal) as refusal:
        journal.transition(STEP, "PLANNED", plan_hash="0" * 64)
    assert refusal.value.code == RefusalCode.PLAN_HASH_MISMATCH


def test_illegal_transition_is_refused(tmp_path: Path) -> None:
    journal = _fresh(tmp_path)
    with pytest.raises(CanaryRefusal) as refusal:
        journal.transition(STEP, "SUBMITTED", plan_hash=PLAN_HASH)
    assert refusal.value.code == RefusalCode.JOURNAL_CONFLICT


def test_tampered_line_is_detected_on_load(tmp_path: Path) -> None:
    journal = _fresh(tmp_path)
    journal.transition(STEP, "PLANNED", plan_hash=PLAN_HASH)
    journal.close()
    path = tmp_path / "journal.jsonl"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("PLANNED", "STAGED!"), encoding="utf-8")
    with pytest.raises(CanaryRefusal) as refusal:
        CanaryJournal.load(path)
    assert refusal.value.code == RefusalCode.JOURNAL_TAMPERED


def test_deleted_record_breaks_the_chain(tmp_path: Path) -> None:
    journal = _fresh(tmp_path)
    journal.transition(STEP, "PLANNED", plan_hash=PLAN_HASH)
    journal.transition(STEP, "STAGED", plan_hash=PLAN_HASH)
    journal.close()
    path = tmp_path / "journal.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:1] + lines[2:]) + "\n", encoding="utf-8")
    with pytest.raises(CanaryRefusal) as refusal:
        CanaryJournal.load(path)
    assert refusal.value.code == RefusalCode.JOURNAL_TAMPERED


def _drive_to(journal: CanaryJournal, state: str) -> None:
    sequence = [
        "PLANNED",
        "STAGED",
        "AUTHORIZATION_VALIDATED",
        "SIGNED",
        "SUBMITTED",
        "SUBMISSION_UNKNOWN",
    ]
    for name in sequence[: sequence.index(state) + 1]:
        deploy = (
            DEPLOY
            if name in ("SIGNED", "SUBMITTED", "SUBMISSION_UNKNOWN")
            else None
        )
        signed_bytes = SIGNED_BYTES if name == "SIGNED" else None
        journal.transition(
            STEP,
            name,
            plan_hash=PLAN_HASH,
            deploy_hash=deploy,
            signed_bytes_sha256=signed_bytes,
        )


@pytest.mark.parametrize("in_flight", ["SIGNED", "SUBMITTED", "SUBMISSION_UNKNOWN"])
def test_restart_with_in_flight_step_cannot_emit_second_action(
    tmp_path: Path, in_flight: str
) -> None:
    journal = _fresh(tmp_path)
    _drive_to(journal, in_flight)
    journal.close()
    reloaded = CanaryJournal.load(tmp_path / "journal.jsonl")
    with pytest.raises(CanaryRefusal) as refusal:
        reloaded.transition(STEP, "STAGED", plan_hash=PLAN_HASH)
    assert refusal.value.code == RefusalCode.DUPLICATE_ECONOMIC_ACTION
    with pytest.raises(CanaryRefusal) as blocked:
        reloaded.require_no_in_flight(context="test")
    assert blocked.value.code == RefusalCode.RECONCILIATION_REQUIRED


def test_reconciliation_requires_the_original_deploy_hash(tmp_path: Path) -> None:
    journal = _fresh(tmp_path)
    _drive_to(journal, "SUBMISSION_UNKNOWN")
    journal.close()
    reloaded = CanaryJournal.load(tmp_path / "journal.jsonl")
    with pytest.raises(CanaryRefusal) as refusal:
        reloaded.transition(
            STEP,
            "RECONCILED_CONFIRMED",
            plan_hash=PLAN_HASH,
            deploy_hash="e" * 64,
        )
    assert refusal.value.code == RefusalCode.RECONCILIATION_REQUIRED
    reloaded.transition(
        STEP, "RECONCILED_CONFIRMED", plan_hash=PLAN_HASH, deploy_hash=DEPLOY
    )
    status = reloaded.step_status(STEP)
    assert status is not None and status.state == "RECONCILED_CONFIRMED"


def test_terminal_states_accept_no_further_transitions(tmp_path: Path) -> None:
    journal = _fresh(tmp_path)
    _drive_to(journal, "SUBMITTED")
    journal.transition(
        STEP, "CONFIRMED_FINALIZED", plan_hash=PLAN_HASH, deploy_hash=DEPLOY
    )
    with pytest.raises(CanaryRefusal) as refusal:
        journal.transition(
            STEP, "SUBMITTED", plan_hash=PLAN_HASH, deploy_hash=DEPLOY
        )
    assert refusal.value.code == RefusalCode.JOURNAL_CONFLICT


def test_submitted_requires_a_deploy_hash(tmp_path: Path) -> None:
    journal = _fresh(tmp_path)
    _drive_to(journal, "SIGNED")
    with pytest.raises(CanaryRefusal) as refusal:
        journal.transition(STEP, "SUBMITTED", plan_hash=PLAN_HASH)
    assert refusal.value.code == RefusalCode.JOURNAL_CONFLICT
