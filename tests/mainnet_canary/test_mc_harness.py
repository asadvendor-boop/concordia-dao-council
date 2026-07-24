"""Blocker 4 failure-first suite: the Testnet calibration harness.

prepare → validate/dry-run → explicit submit → reconcile by original hash →
dual-node depth≥8 observation → harness observation document — rehearsed
end-to-end with fakes (no live calls), plus the refusals: non-economic step,
argument-shape drift, missing transports, disagreeing providers.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pycspr import KeyAlgorithm, crypto as pycspr_crypto
from pycspr.factory.accounts import parse_private_key_bytes

import mc_support
from shared.native_transfer_deploy import build_signed_native_transfer_deploy
from tools.mainnet_canary.calibration import HARNESS_OBSERVATION_SCHEMA_ID
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.harness import (
    dry_run_harness_step,
    prepare_harness_step,
    run_harness_step,
)
from tools.mainnet_canary.journal import CanaryJournal
from tools.mainnet_canary.submission import validate_signed_step_deploy

SOURCE_KEY = parse_private_key_bytes(bytes(range(1, 33)), KeyAlgorithm.ED25519)
RECIPIENT = bytes.fromhex("2b" * 32)
PAYMENT = 100_000_000


@pytest.fixture()
def plan(tmp_path: Path) -> dict[str, object]:
    repo = mc_support.build_hermetic_repo(tmp_path)
    inputs = mc_support.build_plan_inputs(repo, tmp_path)
    return mc_support.build_valid_plan(inputs)


def _transfer_step_id(plan: dict[str, object]) -> str:
    for step in plan["steps"]:
        if step.get("kind") == "native_transfer":
            return str(step["step_id"])
    raise AssertionError("plan has no native transfer step")


def _testnet_step(plan: dict[str, object], step_id: str) -> dict[str, object]:
    """The Testnet-profile rendering of the plan step (same arg shape)."""

    for step in plan["steps"]:
        if str(step["step_id"]) == step_id:
            testnet = json.loads(json.dumps(step))
            testnet["signing_account_hash"] = pycspr_crypto.get_account_hash(
                SOURCE_KEY.account_key
            ).hex()
            amount = str(step["expected_outcome"]["amount_motes"])
            testnet["expected_outcome"] = {
                "recipient_account": RECIPIENT.hex(),
                "amount_motes": amount,
                "transfer_id": "1",
            }
            return testnet
    raise AssertionError(step_id)


def _signed_testnet_bytes(plan: dict[str, object], step_id: str, path: Path) -> Path:
    step = _testnet_step(plan, step_id)
    raw = build_signed_native_transfer_deploy(
        source_private_key=SOURCE_KEY,
        recipient_account_hash=RECIPIENT,
        amount_motes=int(step["expected_outcome"]["amount_motes"]),
        transfer_id=1,
        payment_amount_motes=PAYMENT,
        timestamp_seconds=1_700_000_000.0,
        chain_name="casper-test",
    )
    path.write_bytes(raw)
    return path


class _Transport:
    def __init__(self) -> None:
        self.submissions = 0

    def submit_deploy(self, signed_bytes: bytes) -> str:
        self.submissions += 1
        from pycspr import serializer
        from pycspr.types.node.rpc import Deploy

        _, deploy = serializer.from_bytes(signed_bytes, Deploy)
        return deploy.hash.hex()

    def fetch_deploy_status(self, deploy_hash_hex: str) -> dict[str, object]:
        return {"finalized": True, "success": True}


def _observation_calls(deploy_hash: str):
    provider = mc_support.make_raw_provider(
        "x",
        "x.example",
        deploy_hash=deploy_hash,
        block_hash="2e" * 32,
        block_height=100,
        success=True,
        chainspec_name="casper-test",
        chain_tip_height=140,
    )
    exchanges = provider["raw_exchanges"]

    def call(method: str, params: dict[str, object]) -> dict[str, object]:
        return json.loads(exchanges[method]["response_body"])

    return call


def test_prepare_refuses_a_non_economic_step(plan: dict[str, object]) -> None:
    with pytest.raises(CanaryRefusal) as refusal:
        prepare_harness_step(plan, step_id="not-a-step")
    assert refusal.value.code == RefusalCode.CALIBRATION_LINE_SET_MISMATCH


def test_dry_run_validates_without_submitting(
    plan: dict[str, object], tmp_path: Path
) -> None:
    step_id = _transfer_step_id(plan)
    signed = _signed_testnet_bytes(plan, step_id, tmp_path / "signed.bin")
    result = dry_run_harness_step(
        plan,
        step_id=step_id,
        signed_deploy_path=signed,
        testnet_step=_testnet_step(plan, step_id),
        max_payment_motes=PAYMENT,
    )
    assert result["facts"]["deploy_hash_hex"]


def test_argument_shape_drift_refuses(
    plan: dict[str, object], tmp_path: Path
) -> None:
    step_id = _transfer_step_id(plan)
    signed = _signed_testnet_bytes(plan, step_id, tmp_path / "signed.bin")
    testnet = _testnet_step(plan, step_id)
    testnet["typed_args"] = [{"name": "sneaky", "type": "U8", "value": 1}]
    with pytest.raises(CanaryRefusal) as refusal:
        dry_run_harness_step(
            plan,
            step_id=step_id,
            signed_deploy_path=signed,
            testnet_step=testnet,
            max_payment_motes=PAYMENT,
        )
    assert refusal.value.code == RefusalCode.CALIBRATION_BINDING_INVALID


def test_submit_without_transports_refuses(
    plan: dict[str, object], tmp_path: Path
) -> None:
    step_id = _transfer_step_id(plan)
    signed = _signed_testnet_bytes(plan, step_id, tmp_path / "signed.bin")
    with pytest.raises(CanaryRefusal) as refusal:
        run_harness_step(
            plan,
            step_id=step_id,
            signed_deploy_path=signed,
            testnet_step=_testnet_step(plan, step_id),
            max_payment_motes=PAYMENT,
            journal_path=tmp_path / "harness-journal.jsonl",
            submit=True,
        )
    assert refusal.value.code == RefusalCode.SUBMISSION_TRANSPORT_INVALID


def test_full_rehearsal_succeeds_and_submits_exactly_once(
    plan: dict[str, object], tmp_path: Path
) -> None:
    """The fully satisfied end-to-end rehearsal (required positive control):
    prepare → dry-run → submit → reconcile → dual-node observe → emit — and
    the emitted harness observation carries the v2 schema with raw-evidence
    providers, ready for calibration conversion."""

    step_id = _transfer_step_id(plan)
    signed = _signed_testnet_bytes(plan, step_id, tmp_path / "signed.bin")
    testnet = _testnet_step(plan, step_id)
    testnet["signer_public_key_hex"] = SOURCE_KEY.account_key.hex()
    testnet["wasm_sha256"] = None

    journal_path = tmp_path / "harness-journal.jsonl"
    journal = CanaryJournal.create(
        journal_path,
        plan_hash=str(plan["canary_plan_sha256"]),
        rc_tag=str(plan["rc"]["tag"]),
    )
    try:
        journal.transition(step_id, "PLANNED", plan_hash=str(plan["canary_plan_sha256"]))
        journal.transition(step_id, "STAGED", plan_hash=str(plan["canary_plan_sha256"]))
        journal.transition(
            step_id,
            "AUTHORIZATION_VALIDATED",
            plan_hash=str(plan["canary_plan_sha256"]),
        )
    finally:
        journal.close()

    facts = validate_signed_step_deploy(
        signed.read_bytes(),
        step=testnet,
        max_payment_motes=PAYMENT,
        expected_chain_name="casper-test",
    )
    deploy_hash = str(facts["deploy_hash_hex"])
    transport = _Transport()
    observation = run_harness_step(
        plan,
        step_id=step_id,
        signed_deploy_path=signed,
        testnet_step=testnet,
        max_payment_motes=PAYMENT,
        journal_path=journal_path,
        submit=True,
        transport=transport,
        observation_calls={
            "provider-a": _observation_calls(deploy_hash),
            "provider-b": _observation_calls(deploy_hash),
        },
        observation_hosts={
            "provider-a": "node-a.example",
            "provider-b": "node-b.example",
        },
        retrieved_at_unix=mc_support.CLOCK_UNIX,
    )
    assert transport.submissions == 1
    assert observation["schema_id"] == HARNESS_OBSERVATION_SCHEMA_ID
    assert observation["deploy_hash"] == deploy_hash
    assert len(observation["observations"]) == 2
    for provider in observation["observations"]:
        assert "raw_exchanges" in provider
    # The journal is terminal: a second submit attempt refuses.
    with pytest.raises(CanaryRefusal) as refusal:
        run_harness_step(
            plan,
            step_id=step_id,
            signed_deploy_path=signed,
            testnet_step=testnet,
            max_payment_motes=PAYMENT,
            journal_path=journal_path,
            submit=True,
            transport=transport,
            observation_calls={
                "provider-a": _observation_calls(deploy_hash),
                "provider-b": _observation_calls(deploy_hash),
            },
            observation_hosts={
                "provider-a": "node-a.example",
                "provider-b": "node-b.example",
            },
            retrieved_at_unix=mc_support.CLOCK_UNIX,
        )
    assert refusal.value.code == RefusalCode.DUPLICATE_ECONOMIC_ACTION
    assert transport.submissions == 1
