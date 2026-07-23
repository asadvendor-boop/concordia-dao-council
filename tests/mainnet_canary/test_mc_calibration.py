"""Calibration v2: plan-bound receipts, exact line-set, honest translation.

Requirements under test:

- the economic-step set is DERIVED from the plan (7 fixed steps + one vote
  per threshold signer), never hard-coded;
- the calibration line set must equal that set exactly — a missing line and
  an extra line both refuse (CALIBRATION_LINE_SET_MISMATCH);
- every line binds the Mainnet plan hash and the step's typed-args digest,
  recomputed from the plan itself (CALIBRATION_BINDING_INVALID);
- Testnet and Mainnet argument digests must DIFFER, and every differing
  field must belong to the reviewed translation set — no byte-identical
  claim, no unreviewed drift;
- refusal-probe steps calibrate their REFUSALS (exact finalized error);
- receipts require sufficient finality depth and two disjoint RPC
  observations;
- the converter derives the translated-field list by comparison, refuses
  shape drift, and its output re-validates.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import mc_support
from tools.mainnet_canary.calibration import (
    HARNESS_OBSERVATION_SCHEMA_ID,
    REVIEWED_TRANSLATION_FIELDS,
    build_calibration_from_harness,
    economic_step_ids,
    typed_args_sha256,
    validate_calibration_document,
)
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode


@pytest.fixture()
def plan(plan_inputs: dict[str, Path]) -> dict[str, object]:
    return mc_support.build_valid_plan(plan_inputs)


@pytest.fixture()
def calibration(plan: dict[str, object]) -> dict[str, object]:
    return mc_support.make_calibration(plan)


def _expect(code: str, plan: dict[str, object], calibration: dict[str, object]) -> None:
    with pytest.raises(CanaryRefusal) as refusal:
        validate_calibration_document(plan, calibration)
    assert refusal.value.code == code


class TestEconomicStepDerivation:
    def test_step_set_is_derived_seven_plus_threshold(
        self, plan: dict[str, object]
    ) -> None:
        ids = economic_step_ids(plan)
        # A..K has 7 fixed economic steps (install, propose, pre-quorum
        # refusal, wrong-envelope refusal, finalize, duplicate refusal,
        # native transfer) plus ONE vote per threshold signer.
        assert len(ids) == 7 + int(plan["threshold"])
        fixed = {
            "B-install-rc-wasm",
            "D-propose-envelope",
            "E-prequorum-finalize-refusal",
            "F9-wrong-envelope-refusal",
            "G-finalize-exact-envelope",
            "H-no-second-economic-action",
            "I-executor-native-transfer",
        }
        assert fixed <= set(ids)
        votes = {sid for sid in ids if sid.startswith("F-approve-")}
        assert len(votes) == int(plan["threshold"])

    def test_valid_calibration_passes_and_covers_every_step(
        self, plan: dict[str, object], calibration: dict[str, object]
    ) -> None:
        lines = validate_calibration_document(plan, calibration)
        assert sorted(lines) == sorted(economic_step_ids(plan))


class TestLineSetEquality:
    def test_missing_line_refuses(
        self, plan: dict[str, object], calibration: dict[str, object]
    ) -> None:
        del calibration["lines"]["I-executor-native-transfer"]
        _expect(RefusalCode.CALIBRATION_LINE_SET_MISMATCH, plan, calibration)

    def test_extra_line_refuses(
        self, plan: dict[str, object], calibration: dict[str, object]
    ) -> None:
        calibration["lines"]["Z-unknown-step"] = calibration["lines"][
            "D-propose-envelope"
        ]
        _expect(RefusalCode.CALIBRATION_LINE_SET_MISMATCH, plan, calibration)


class TestBindings:
    def test_wrong_plan_hash_refuses(
        self, plan: dict[str, object], calibration: dict[str, object]
    ) -> None:
        calibration["mainnet_plan_hash"] = "00" * 32
        _expect(RefusalCode.CALIBRATION_BINDING_INVALID, plan, calibration)

    def test_wrong_chain_refuses(
        self, plan: dict[str, object], calibration: dict[str, object]
    ) -> None:
        calibration["testnet_chain_name"] = "casper"
        _expect(RefusalCode.NETWORK_MISMATCH, plan, calibration)

    def test_typed_args_digest_must_recompute_from_the_plan(
        self, plan: dict[str, object], calibration: dict[str, object]
    ) -> None:
        calibration["lines"]["D-propose-envelope"][
            "mainnet_typed_args_sha256"
        ] = "11" * 32
        _expect(RefusalCode.CALIBRATION_BINDING_INVALID, plan, calibration)

    def test_byte_identical_digests_refuse(
        self, plan: dict[str, object], calibration: dict[str, object]
    ) -> None:
        line = calibration["lines"]["D-propose-envelope"]
        line["testnet_deploy_args_sha256"] = line["mainnet_typed_args_sha256"]
        _expect(RefusalCode.CALIBRATION_BINDING_INVALID, plan, calibration)

    def test_empty_translation_refuses(
        self, plan: dict[str, object], calibration: dict[str, object]
    ) -> None:
        calibration["lines"]["D-propose-envelope"][
            "network_profile_translation"
        ] = {"translated_fields": []}
        _expect(RefusalCode.CALIBRATION_BINDING_INVALID, plan, calibration)

    def test_unreviewed_translated_field_refuses(
        self, plan: dict[str, object], calibration: dict[str, object]
    ) -> None:
        assert "decision_code" not in REVIEWED_TRANSLATION_FIELDS
        calibration["lines"]["D-propose-envelope"][
            "network_profile_translation"
        ] = {"translated_fields": ["decision_code"]}
        _expect(RefusalCode.CALIBRATION_BINDING_INVALID, plan, calibration)

    def test_wrong_entry_point_refuses(
        self, plan: dict[str, object], calibration: dict[str, object]
    ) -> None:
        calibration["lines"]["D-propose-envelope"]["target"][
            "entry_point"
        ] = "approve_envelope"
        _expect(RefusalCode.CALIBRATION_BINDING_INVALID, plan, calibration)

    def test_install_must_pin_the_testnet_wasm(
        self, plan: dict[str, object], calibration: dict[str, object]
    ) -> None:
        calibration["lines"]["B-install-rc-wasm"]["target"]["wasm_sha256"] = (
            plan["rc"]["mainnet_wasm_sha256"]
        )
        _expect(RefusalCode.CALIBRATION_BINDING_INVALID, plan, calibration)

    def test_wrong_source_commit_refuses(
        self, plan: dict[str, object], calibration: dict[str, object]
    ) -> None:
        calibration["lines"]["D-propose-envelope"]["target"][
            "source_commit"
        ] = "ee" * 20
        _expect(RefusalCode.CALIBRATION_BINDING_INVALID, plan, calibration)


class TestReceipts:
    def test_refusal_probe_must_calibrate_its_refusal(
        self, plan: dict[str, object], calibration: dict[str, object]
    ) -> None:
        # An F9 calibration claiming SUCCESS proves the choreography was
        # wrong — the Testnet probe must have finalized with the exact
        # expected error.
        calibration["lines"]["F9-wrong-envelope-refusal"]["receipt"][
            "execution"
        ] = {"success": True, "error_message": None}
        _expect(RefusalCode.CALIBRATION_BINDING_INVALID, plan, calibration)

    def test_wrong_refusal_message_refuses(
        self, plan: dict[str, object], calibration: dict[str, object]
    ) -> None:
        calibration["lines"]["E-prequorum-finalize-refusal"]["receipt"][
            "execution"
        ]["error_message"] = "User error: 16"
        _expect(RefusalCode.CALIBRATION_BINDING_INVALID, plan, calibration)

    def test_failed_success_step_refuses(
        self, plan: dict[str, object], calibration: dict[str, object]
    ) -> None:
        calibration["lines"]["G-finalize-exact-envelope"]["receipt"][
            "execution"
        ] = {"success": False, "error_message": "User error: 10"}
        _expect(RefusalCode.CALIBRATION_BINDING_INVALID, plan, calibration)

    def test_shallow_finality_refuses(
        self, plan: dict[str, object], calibration: dict[str, object]
    ) -> None:
        receipt = calibration["lines"]["D-propose-envelope"]["receipt"]
        receipt["finality"] = {
            "chain_tip_height": int(receipt["block_height"]) + 7
        }
        _expect(RefusalCode.INSUFFICIENT_CONFIRMATIONS, plan, calibration)

    def test_non_disjoint_observations_refuse(
        self, plan: dict[str, object], calibration: dict[str, object]
    ) -> None:
        receipt = calibration["lines"]["D-propose-envelope"]["receipt"]
        receipt["observations"][1]["endpoint_host"] = receipt["observations"][
            0
        ]["endpoint_host"]
        _expect(RefusalCode.CALIBRATION_BINDING_INVALID, plan, calibration)

    def test_zero_payment_refuses(
        self, plan: dict[str, object], calibration: dict[str, object]
    ) -> None:
        calibration["lines"]["D-propose-envelope"]["payment_motes"] = "0"
        _expect(RefusalCode.CEILING_ARITHMETIC_INVALID, plan, calibration)


def _harness_for(
    plan: dict[str, object], step: dict[str, object]
) -> dict[str, object]:
    step_id = str(step["step_id"])
    line = mc_support.make_calibration(plan)["lines"][step_id]
    testnet_args = []
    translated_done = False
    for arg in step.get("typed_args") or []:
        entry = dict(arg)
        if not translated_done and entry["name"] in REVIEWED_TRANSLATION_FIELDS:
            entry["value"] = (
                "casper-test"
                if entry["name"] == "casper_chain_name"
                else "74" * 32
            )
            translated_done = True
        testnet_args.append(entry)
    return {
        "schema_id": HARNESS_OBSERVATION_SCHEMA_ID,
        "step_id": step_id,
        "testnet_chain_name": "casper-test",
        "signer_public_key_hex": "01" + "aa" * 32,
        "entry_point": step.get("entry_point"),
        "wasm_sha256": line["target"]["wasm_sha256"],
        "testnet_typed_args": testnet_args,
        "deploy_payment_motes": "5000000000",
        "deploy_hash": line["receipt"]["deploy_hash"],
        "block_hash": line["receipt"]["block_hash"],
        "block_height": line["receipt"]["block_height"],
        "execution": line["receipt"]["execution"],
        "finality": line["receipt"]["finality"],
        "observations": line["receipt"]["observations"],
    }


class TestConverter:
    def test_converter_output_revalidates(self, plan: dict[str, object]) -> None:
        harness = [
            _harness_for(plan, step)
            for step in plan["steps"]
            if step["economic"]
        ]
        document = build_calibration_from_harness(plan, harness)
        lines = validate_calibration_document(plan, document)
        assert sorted(lines) == sorted(economic_step_ids(plan))

    def test_translated_fields_are_derived_not_transcribed(
        self, plan: dict[str, object]
    ) -> None:
        harness = [
            _harness_for(plan, step)
            for step in plan["steps"]
            if step["economic"]
        ]
        document = build_calibration_from_harness(plan, harness)
        for step in plan["steps"]:
            if not step["economic"]:
                continue
            line = document["lines"][str(step["step_id"])]
            plan_args = step.get("typed_args") or []
            expected_translated = [
                str(arg["name"])
                for arg, harness_arg in zip(
                    plan_args,
                    next(
                        h["testnet_typed_args"]
                        for h in harness
                        if h["step_id"] == step["step_id"]
                    ),
                )
                if arg["value"] != harness_arg["value"]
            ]
            assert (
                line["network_profile_translation"]["translated_fields"]
                == expected_translated
            )
            assert line["mainnet_typed_args_sha256"] == typed_args_sha256(
                plan_args
            )

    def test_argument_shape_drift_refuses(self, plan: dict[str, object]) -> None:
        harness = [
            _harness_for(plan, step)
            for step in plan["steps"]
            if step["economic"]
        ]
        target = next(
            h for h in harness if h["step_id"] == "D-propose-envelope"
        )
        target["testnet_typed_args"] = list(
            reversed(target["testnet_typed_args"])
        )
        with pytest.raises(CanaryRefusal) as refusal:
            build_calibration_from_harness(plan, harness)
        assert refusal.value.code == RefusalCode.CALIBRATION_BINDING_INVALID

    def test_missing_harness_step_refuses(self, plan: dict[str, object]) -> None:
        harness = [
            _harness_for(plan, step)
            for step in plan["steps"]
            if step["economic"] and step["step_id"] != "I-executor-native-transfer"
        ]
        with pytest.raises(CanaryRefusal) as refusal:
            build_calibration_from_harness(plan, harness)
        assert refusal.value.code == RefusalCode.CALIBRATION_LINE_SET_MISMATCH

    def test_unreviewed_value_drift_refuses(self, plan: dict[str, object]) -> None:
        harness = [
            _harness_for(plan, step)
            for step in plan["steps"]
            if step["economic"]
        ]
        target = next(
            h for h in harness if h["step_id"] == "G-finalize-exact-envelope"
        )
        for arg in target["testnet_typed_args"]:
            if arg["name"] == "decision_code":
                arg["value"] = 3
        with pytest.raises(CanaryRefusal) as refusal:
            build_calibration_from_harness(plan, harness)
        assert refusal.value.code == RefusalCode.CALIBRATION_BINDING_INVALID
