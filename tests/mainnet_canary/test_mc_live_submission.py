"""Blocker 3 failure-first suite: the exactly-once submission boundary.

Every economic-safety property is proven by attempting its violation:
a second broadcast after restart, different bytes under a persisted SIGNED
record, unsigned/mutated/foreign-chain deploys, transport failure mid-
broadcast, and reconciliation by anything other than the original hash.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pycspr import KeyAlgorithm, crypto as pycspr_crypto
from pycspr.factory.accounts import parse_private_key_bytes

from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.journal import CanaryJournal
from tools.mainnet_canary.submission import (
    load_signed_deploy_bytes,
    reconcile_step,
    submit_step_exactly_once,
    validate_signed_step_deploy,
)
from shared.native_transfer_deploy import build_signed_native_transfer_deploy

# Deterministic TEST key (fixture-only; signs nothing outside tmp_path).
SOURCE_KEY = parse_private_key_bytes(bytes(range(1, 33)), KeyAlgorithm.ED25519)
RECIPIENT = bytes.fromhex("2b" * 32)
AMOUNT = 2_500_000_000
TRANSFER_ID = 7
PAYMENT = 100_000_000
PLAN_HASH = "ab" * 32
STEP_ID = "I-executor-native-transfer"


def _step() -> dict[str, object]:
    return {
        "step_id": STEP_ID,
        "kind": "native_transfer",
        "signing_account_hash": pycspr_crypto.get_account_hash(SOURCE_KEY.account_key).hex(),
        "entry_point": None,
        "typed_args": None,
        "expected_outcome": {
            "recipient_account": RECIPIENT.hex(),
            "amount_motes": str(AMOUNT),
        },
    }


def _signed_bytes(chain: str = "casper") -> bytes:
    return build_signed_native_transfer_deploy(
        source_private_key=SOURCE_KEY,
        recipient_account_hash=RECIPIENT,
        amount_motes=AMOUNT,
        transfer_id=TRANSFER_ID,
        payment_amount_motes=PAYMENT,
        timestamp_seconds=1_700_000_000.0,
        chain_name=chain,
    )


class _Transport:
    """Counting fake: proves the RPC fires at most once, ever."""

    def __init__(self, *, fail: bool = False, report: str | None = None):
        self.submissions = 0
        self.fail = fail
        self.report = report
        self.finalized: dict[str, bool] = {}

    def submit_deploy(self, signed_bytes: bytes) -> str:
        self.submissions += 1
        if self.fail:
            raise ConnectionError("mid-broadcast network failure")
        if self.report is not None:
            return self.report
        facts = validate_signed_step_deploy(
            signed_bytes, step=_step(), max_payment_motes=PAYMENT
        )
        return str(facts["deploy_hash_hex"])

    def fetch_deploy_status(self, deploy_hash_hex: str) -> dict[str, object]:
        return {
            "finalized": self.finalized.get(deploy_hash_hex, True),
            "success": True,
        }


def _journal_at_authorized(tmp_path: Path) -> Path:
    path = tmp_path / "journal.jsonl"
    journal = CanaryJournal.create(path, plan_hash=PLAN_HASH, rc_tag="rc")
    try:
        journal.transition(STEP_ID, "PLANNED", plan_hash=PLAN_HASH)
        journal.transition(STEP_ID, "STAGED", plan_hash=PLAN_HASH)
        journal.transition(
            STEP_ID, "AUTHORIZATION_VALIDATED", plan_hash=PLAN_HASH
        )
    finally:
        journal.close()
    return path


def _submit_once(tmp_path: Path, transport: _Transport) -> dict[str, object]:
    raw = _signed_bytes()
    facts = validate_signed_step_deploy(
        raw, step=_step(), max_payment_motes=PAYMENT
    )
    return submit_step_exactly_once(
        journal_path=_journal_at_authorized(tmp_path),
        plan_hash=PLAN_HASH,
        step=_step(),
        signed_bytes=raw,
        facts=facts,
        transport=transport,
    )


class TestDeployImport:
    def test_valid_wallet_signed_bytes_recompute_the_hash(self) -> None:
        raw = _signed_bytes()
        facts = validate_signed_step_deploy(
            raw, step=_step(), max_payment_motes=PAYMENT
        )
        assert facts["signed_bytes_sha256"] == hashlib.sha256(raw).hexdigest()
        assert len(str(facts["deploy_hash_hex"])) == 64

    def test_wrong_chain_refuses(self) -> None:
        with pytest.raises(CanaryRefusal) as refusal:
            validate_signed_step_deploy(
                _signed_bytes(chain="casper-test"),
                step=_step(),
                max_payment_motes=PAYMENT,
            )
        assert refusal.value.code == RefusalCode.NETWORK_MISMATCH

    def test_mutated_bytes_refuse(self) -> None:
        raw = bytearray(_signed_bytes())
        raw[len(raw) // 2] ^= 0xFF
        with pytest.raises(CanaryRefusal) as refusal:
            validate_signed_step_deploy(
                bytes(raw), step=_step(), max_payment_motes=PAYMENT
            )
        assert refusal.value.code in (
            RefusalCode.SIGNED_BYTES_INVALID,
            RefusalCode.NETWORK_MISMATCH,
        )

    def test_payment_above_calibrated_maximum_refuses(self) -> None:
        with pytest.raises(CanaryRefusal) as refusal:
            validate_signed_step_deploy(
                _signed_bytes(), step=_step(), max_payment_motes=PAYMENT - 1
            )
        assert refusal.value.code == RefusalCode.COST_CEILING_EXCEEDED

    def test_wrong_recipient_refuses(self) -> None:
        step = _step()
        step["expected_outcome"]["recipient_account"] = "3c" * 32
        with pytest.raises(CanaryRefusal) as refusal:
            validate_signed_step_deploy(
                _signed_bytes(), step=step, max_payment_motes=PAYMENT
            )
        assert refusal.value.code == RefusalCode.SIGNED_BYTES_INVALID

    def test_secret_path_import_refuses(self, tmp_path: Path) -> None:
        with pytest.raises(CanaryRefusal) as refusal:
            load_signed_deploy_bytes(
                Path("/run/secrets/mainnet_canary/deploy.bin")
            )
        assert refusal.value.code == RefusalCode.SECRET_PATH_READ_REFUSED


class TestExactlyOnce:
    def test_happy_path_submits_exactly_once(self, tmp_path: Path) -> None:
        transport = _Transport()
        result = _submit_once(tmp_path, transport)
        assert transport.submissions == 1
        assert result["state"] == "SUBMITTED"
        # The deploy hash was persisted at SIGNED, before the broadcast.
        journal = CanaryJournal.load(tmp_path / "journal.jsonl")
        try:
            status = journal.step_status(STEP_ID)
        finally:
            journal.close()
        assert status.deploy_hash == result["deploy_hash"]

    def test_second_broadcast_is_impossible_across_restart(
        self, tmp_path: Path
    ) -> None:
        transport = _Transport()
        _submit_once(tmp_path, transport)
        # "Restart": a brand-new call against the same durable journal.
        raw = _signed_bytes()
        facts = validate_signed_step_deploy(
            raw, step=_step(), max_payment_motes=PAYMENT
        )
        with pytest.raises(CanaryRefusal) as refusal:
            submit_step_exactly_once(
                journal_path=tmp_path / "journal.jsonl",
                plan_hash=PLAN_HASH,
                step=_step(),
                signed_bytes=raw,
                facts=facts,
                transport=transport,
            )
        assert refusal.value.code == RefusalCode.DUPLICATE_ECONOMIC_ACTION
        assert transport.submissions == 1

    def test_broadcast_of_different_bytes_refuses(self, tmp_path: Path) -> None:
        journal_path = _journal_at_authorized(tmp_path)
        raw = _signed_bytes()
        facts = validate_signed_step_deploy(
            raw, step=_step(), max_payment_motes=PAYMENT
        )
        # Persist SIGNED for the original bytes, then crash before broadcast.
        journal = CanaryJournal.load(journal_path)
        try:
            journal.transition(
                STEP_ID,
                "SIGNED",
                plan_hash=PLAN_HASH,
                deploy_hash=str(facts["deploy_hash_hex"]),
                signed_bytes_sha256=str(facts["signed_bytes_sha256"]),
            )
        finally:
            journal.close()
        # Resume with DIFFERENT bytes (a different transfer id → different
        # deploy) — a second economic action in disguise.
        other = build_signed_native_transfer_deploy(
            source_private_key=SOURCE_KEY,
            recipient_account_hash=RECIPIENT,
            amount_motes=AMOUNT,
            transfer_id=TRANSFER_ID + 1,
            payment_amount_motes=PAYMENT,
            timestamp_seconds=1_700_000_000.0,
            chain_name="casper",
        )
        other_facts = validate_signed_step_deploy(
            other, step=_step(), max_payment_motes=PAYMENT
        )
        transport = _Transport()
        with pytest.raises(CanaryRefusal) as refusal:
            submit_step_exactly_once(
                journal_path=journal_path,
                plan_hash=PLAN_HASH,
                step=_step(),
                signed_bytes=other,
                facts=other_facts,
                transport=transport,
            )
        assert refusal.value.code == RefusalCode.SIGNED_BYTES_MISMATCH
        assert transport.submissions == 0

    def test_transport_failure_leaves_the_step_in_flight(
        self, tmp_path: Path
    ) -> None:
        transport = _Transport(fail=True)
        with pytest.raises(CanaryRefusal) as refusal:
            _submit_once(tmp_path, transport)
        assert refusal.value.code == RefusalCode.SUBMISSION_TRANSPORT_INVALID
        journal = CanaryJournal.load(tmp_path / "journal.jsonl")
        try:
            status = journal.step_status(STEP_ID)
        finally:
            journal.close()
        assert status.state == "SUBMISSION_UNKNOWN"

    def test_node_reported_hash_mismatch_goes_in_flight(
        self, tmp_path: Path
    ) -> None:
        transport = _Transport(report="ff" * 32)
        with pytest.raises(CanaryRefusal) as refusal:
            _submit_once(tmp_path, transport)
        assert refusal.value.code == RefusalCode.SUBMISSION_RESULT_MISMATCH


class TestReconciliation:
    def test_reconcile_finalizes_by_the_original_hash(
        self, tmp_path: Path
    ) -> None:
        transport = _Transport(fail=True)
        with pytest.raises(CanaryRefusal):
            _submit_once(tmp_path, transport)
        working = _Transport()
        result = reconcile_step(
            journal_path=tmp_path / "journal.jsonl",
            plan_hash=PLAN_HASH,
            step_id=STEP_ID,
            transport=working,
        )
        assert result["state"] == "RECONCILED_CONFIRMED"
        # After reconciliation the step is terminal: no further submission.
        raw = _signed_bytes()
        facts = validate_signed_step_deploy(
            raw, step=_step(), max_payment_motes=PAYMENT
        )
        with pytest.raises(CanaryRefusal) as refusal:
            submit_step_exactly_once(
                journal_path=tmp_path / "journal.jsonl",
                plan_hash=PLAN_HASH,
                step=_step(),
                signed_bytes=raw,
                facts=facts,
                transport=working,
            )
        assert refusal.value.code == RefusalCode.DUPLICATE_ECONOMIC_ACTION

    def test_unfinalized_deploy_keeps_the_step_in_flight(
        self, tmp_path: Path
    ) -> None:
        transport = _Transport(fail=True)
        with pytest.raises(CanaryRefusal):
            _submit_once(tmp_path, transport)
        pending = _Transport()
        journal = CanaryJournal.load(tmp_path / "journal.jsonl")
        try:
            original = journal.step_status(STEP_ID).deploy_hash
        finally:
            journal.close()
        pending.finalized[original] = False
        with pytest.raises(CanaryRefusal) as refusal:
            reconcile_step(
                journal_path=tmp_path / "journal.jsonl",
                plan_hash=PLAN_HASH,
                step_id=STEP_ID,
                transport=pending,
            )
        assert refusal.value.code == RefusalCode.PROOF_PENDING

    def test_reconcile_without_in_flight_state_refuses(
        self, tmp_path: Path
    ) -> None:
        _journal_at_authorized(tmp_path)
        with pytest.raises(CanaryRefusal) as refusal:
            reconcile_step(
                journal_path=tmp_path / "journal.jsonl",
                plan_hash=PLAN_HASH,
                step_id=STEP_ID,
                transport=_Transport(),
            )
        assert refusal.value.code == RefusalCode.RECONCILIATION_REQUIRED
