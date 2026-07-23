"""Key/role safety v2 + durable exactly-once executor v2 (failing-first).

Requirements under test:
- ALL seven canary roles pairwise distinct (the prototype allowed
  treasury_source to collide with a governance role);
- unique key-file mounts per role;
- journal SIGNED is impossible without the canonical signed-bytes digest
  AND the locally computed deploy hash;
- SUBMITTED must bind the exact deploy hash recorded at SIGNED;
- CONFIRMED/FAILED_FINALIZED must bind the original deploy hash;
- exclusive OS lock: a second process/handle on the same journal refuses;
- symlinked journal directories refuse;
- atomic exclusive creation (a partially existing journal file refuses).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import mc_support
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.journal import CanaryJournal
from tools.mainnet_canary.keys import load_key_inventory

PLAN_HASH = "5a" * 32
DEPLOY = "d0" * 32
SIGNED_BYTES_SHA = "b1" * 32
STEP = "I-executor-native-transfer"


def _fresh(tmp_path: Path) -> CanaryJournal:
    return CanaryJournal.create(
        tmp_path / "journal" / "journal.jsonl", plan_hash=PLAN_HASH, rc_tag="rc"
    )


def _sign(journal: CanaryJournal) -> None:
    journal.transition(STEP, "PLANNED", plan_hash=PLAN_HASH)
    journal.transition(STEP, "STAGED", plan_hash=PLAN_HASH)
    journal.transition(STEP, "AUTHORIZATION_VALIDATED", plan_hash=PLAN_HASH)
    journal.transition(
        STEP,
        "SIGNED",
        plan_hash=PLAN_HASH,
        deploy_hash=DEPLOY,
        signed_bytes_sha256=SIGNED_BYTES_SHA,
    )


class TestRoleSafety:
    def test_treasury_source_may_not_be_a_governance_role(self, tmp_path: Path) -> None:
        # Prototype bug: only governance-pairwise and treasury!=recipient were
        # enforced, so the treasury source could BE a signer.
        inventory = mc_support.make_key_inventory()
        signer_entry = dict(inventory["roles"]["signer_a"])
        signer_entry["key_file_mount_path"] = (
            "/run/secrets/mainnet_canary/treasury_source.ref"
        )
        inventory["roles"]["treasury_source"] = signer_entry
        path = mc_support.write_json(tmp_path / "inventory.json", inventory)
        with pytest.raises(CanaryRefusal) as refusal:
            load_key_inventory(path)
        assert refusal.value.code == RefusalCode.ROLE_SET_INVALID

    def test_recipient_may_not_be_a_governance_role(self, tmp_path: Path) -> None:
        inventory = mc_support.make_key_inventory()
        finalizer_entry = dict(inventory["roles"]["finalizer"])
        finalizer_entry["key_file_mount_path"] = (
            "/run/secrets/mainnet_canary/recipient.ref"
        )
        inventory["roles"]["recipient"] = finalizer_entry
        path = mc_support.write_json(tmp_path / "inventory.json", inventory)
        with pytest.raises(CanaryRefusal) as refusal:
            load_key_inventory(path)
        assert refusal.value.code == RefusalCode.ROLE_SET_INVALID

    def test_duplicate_key_file_mounts_refuse(self, tmp_path: Path) -> None:
        inventory = mc_support.make_key_inventory()
        inventory["roles"]["signer_b"]["key_file_mount_path"] = inventory["roles"][
            "signer_a"
        ]["key_file_mount_path"]
        path = mc_support.write_json(tmp_path / "inventory.json", inventory)
        with pytest.raises(CanaryRefusal) as refusal:
            load_key_inventory(path)
        assert refusal.value.code == RefusalCode.ROLE_SET_INVALID


class TestSignedEvidence:
    def test_signed_without_deploy_hash_is_impossible(self, tmp_path: Path) -> None:
        journal = _fresh(tmp_path)
        journal.transition(STEP, "PLANNED", plan_hash=PLAN_HASH)
        journal.transition(STEP, "STAGED", plan_hash=PLAN_HASH)
        journal.transition(STEP, "AUTHORIZATION_VALIDATED", plan_hash=PLAN_HASH)
        with pytest.raises(CanaryRefusal) as refusal:
            journal.transition(STEP, "SIGNED", plan_hash=PLAN_HASH)
        assert refusal.value.code == RefusalCode.JOURNAL_CONFLICT
        journal.close()

    def test_signed_without_signed_bytes_digest_is_impossible(
        self, tmp_path: Path
    ) -> None:
        journal = _fresh(tmp_path)
        journal.transition(STEP, "PLANNED", plan_hash=PLAN_HASH)
        journal.transition(STEP, "STAGED", plan_hash=PLAN_HASH)
        journal.transition(STEP, "AUTHORIZATION_VALIDATED", plan_hash=PLAN_HASH)
        with pytest.raises(CanaryRefusal) as refusal:
            journal.transition(
                STEP, "SIGNED", plan_hash=PLAN_HASH, deploy_hash=DEPLOY
            )
        assert refusal.value.code == RefusalCode.JOURNAL_CONFLICT
        journal.close()

    def test_submit_must_bind_the_signed_deploy_hash(self, tmp_path: Path) -> None:
        journal = _fresh(tmp_path)
        _sign(journal)
        with pytest.raises(CanaryRefusal) as refusal:
            journal.transition(
                STEP, "SUBMITTED", plan_hash=PLAN_HASH, deploy_hash="e" * 64
            )
        assert refusal.value.code == RefusalCode.DUPLICATE_ECONOMIC_ACTION
        journal.transition(
            STEP, "SUBMITTED", plan_hash=PLAN_HASH, deploy_hash=DEPLOY
        )
        journal.close()

    def test_finalization_must_bind_the_original_deploy_hash(
        self, tmp_path: Path
    ) -> None:
        journal = _fresh(tmp_path)
        _sign(journal)
        journal.transition(STEP, "SUBMITTED", plan_hash=PLAN_HASH, deploy_hash=DEPLOY)
        with pytest.raises(CanaryRefusal) as refusal:
            journal.transition(
                STEP,
                "CONFIRMED_FINALIZED",
                plan_hash=PLAN_HASH,
                deploy_hash="e" * 64,
            )
        assert refusal.value.code == RefusalCode.JOURNAL_CONFLICT
        journal.transition(
            STEP, "CONFIRMED_FINALIZED", plan_hash=PLAN_HASH, deploy_hash=DEPLOY
        )
        journal.close()

    def test_signed_evidence_survives_restart(self, tmp_path: Path) -> None:
        journal = _fresh(tmp_path)
        _sign(journal)
        journal.close()
        reloaded = CanaryJournal.load(tmp_path / "journal" / "journal.jsonl")
        status = reloaded.step_status(STEP)
        assert status is not None
        assert status.state == "SIGNED"
        assert status.deploy_hash == DEPLOY
        assert status.signed_bytes_sha256 == SIGNED_BYTES_SHA
        reloaded.close()


class TestExclusiveLock:
    def test_second_handle_on_live_journal_refuses(self, tmp_path: Path) -> None:
        journal = _fresh(tmp_path)
        with pytest.raises(CanaryRefusal) as refusal:
            CanaryJournal.load(tmp_path / "journal" / "journal.jsonl")
        assert refusal.value.code == RefusalCode.JOURNAL_LOCK_HELD
        journal.close()
        # After a clean close (or process death: flock dies with the fd) the
        # journal is loadable again — no stale-lock file can wedge recovery.
        reloaded = CanaryJournal.load(tmp_path / "journal" / "journal.jsonl")
        reloaded.close()

    def test_create_over_existing_file_refuses(self, tmp_path: Path) -> None:
        target = tmp_path / "journal" / "journal.jsonl"
        target.parent.mkdir(parents=True)
        target.write_text("partial", encoding="utf-8")
        with pytest.raises(CanaryRefusal) as refusal:
            CanaryJournal.create(target, plan_hash=PLAN_HASH, rc_tag="rc")
        assert refusal.value.code == RefusalCode.JOURNAL_CONFLICT

    def test_symlinked_journal_directory_refuses(self, tmp_path: Path) -> None:
        real = tmp_path / "real-dir"
        real.mkdir()
        link = tmp_path / "linked-dir"
        os.symlink(real, link)
        with pytest.raises(CanaryRefusal) as refusal:
            CanaryJournal.create(
                link / "journal.jsonl", plan_hash=PLAN_HASH, rc_tag="rc"
            )
        assert refusal.value.code == RefusalCode.JOURNAL_PATH_UNSAFE

    def test_a_symlinked_system_ancestor_does_not_block_a_real_journal(
        self, tmp_path: Path
    ) -> None:
        """Regression: the guard used to walk to the filesystem root.

        On macOS `/var -> private/var` and `/tmp -> private/tmp`, so every
        journal in a normal scratch location was refused JOURNAL_PATH_UNSAFE.
        The suite missed it because pytest's tmp_path is already resolved;
        the real CLI failed. Reproduced portably here: the journal's own
        directory is a REAL directory that merely happens to be reached
        THROUGH a symlinked ancestor — which must be accepted.
        """

        real = tmp_path / "real-root"
        (real / "nested").mkdir(parents=True)
        link = tmp_path / "linked-root"
        os.symlink(real, link)
        journal_path = link / "nested" / "journal.jsonl"
        assert link.is_symlink() and not journal_path.parent.is_symlink()

        journal = CanaryJournal.create(
            journal_path, plan_hash=PLAN_HASH, rc_tag="rc"
        )
        journal.transition(STEP, "PLANNED", plan_hash=PLAN_HASH)
        journal.close()
        reloaded = CanaryJournal.load(journal_path)
        status = reloaded.step_status(STEP)
        assert status is not None and status.state == "PLANNED"
        reloaded.close()

    def test_symlinked_journal_file_refuses_on_load(self, tmp_path: Path) -> None:
        journal = _fresh(tmp_path)
        journal.close()
        alias = tmp_path / "alias.jsonl"
        os.symlink(tmp_path / "journal" / "journal.jsonl", alias)
        with pytest.raises(CanaryRefusal) as refusal:
            CanaryJournal.load(alias)
        assert refusal.value.code == RefusalCode.JOURNAL_PATH_UNSAFE
