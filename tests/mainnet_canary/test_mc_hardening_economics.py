"""Spend model v2: plan-derived economic manifest + human authorization.

Requirements under test:
- cost lines 1:1 with the plan's economic steps (refusal proofs included);
- the native-transfer principal is its own line (PRINCIPAL_LINE_ABSENT);
- immutable integer ceilings with checked arithmetic
  ``max_total_outlay_motes = transfer_principal_motes + max_fees_motes``;
- no zero or placeholder fee maxima;
- every fee maximum is grounded in a finalized Testnet calibration receipt
  OR an explicit conservative operator ceiling (CALIBRATION_RECEIPT_ABSENT);
- the human authorization binds plan hash, accounts, recipient, amount,
  maxima, expiry, nonce, and chain identity; a trusted-clock expiry of zero
  or in the past refuses (AUTHORIZATION_EXPIRED);
- the executor is incapable of spending above the signed ceiling.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import mc_support
from tools.mainnet_canary.economic_manifest import (
    build_economic_manifest,
    required_funding_motes,
    require_within_authorization,
    validate_economic_manifest,
    validate_human_authorization,
)
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode

CLOCK_NOW = 1_700_000_000


def _calibration_for(plan: dict[str, object]) -> dict[str, object]:
    lines = {}
    for step in plan["steps"]:
        if not step["economic"]:
            continue
        lines[str(step["step_id"])] = {
            "payment_motes": "5000000000",
            "receipt": {
                "deploy_hash": "1f" * 32,
                "block_hash": "2e" * 32,
                "finalized": True,
                "chain_name": "casper-test",
            },
        }
    return {
        "schema_id": "concordia.mainnet-canary.testnet-calibration.v1",
        "lines": lines,
    }


@pytest.fixture()
def plan(plan_inputs: dict[str, Path]) -> dict[str, object]:
    return mc_support.build_valid_plan(plan_inputs)


@pytest.fixture()
def manifest(plan: dict[str, object]) -> dict[str, object]:
    return build_economic_manifest(
        plan, calibration=_calibration_for(plan), operator_ceilings={}
    )


def _authorization(plan: dict[str, object], manifest: dict[str, object], **overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_id": "concordia.mainnet-canary.human-authorization.v1",
        "plan_hash": plan["canary_plan_sha256"],
        "chain_name": "casper",
        "treasury_source_account_hash": manifest["treasury_source_account_hash"],
        "recipient_account_hash": manifest["recipient_account_hash"],
        "transfer_principal_motes": manifest["transfer_principal_motes"],
        "max_fees_motes": manifest["max_fees_motes"],
        "max_total_outlay_motes": manifest["max_total_outlay_motes"],
        "expiry_unix": CLOCK_NOW + 3600,
        "nonce": "9d" * 32,
        "authorized_by": ["asad-public-approval"],
    }
    document.update(overrides)
    return document


class TestManifestDerivation:
    def test_lines_are_one_to_one_with_economic_plan_steps(
        self, plan: dict[str, object], manifest: dict[str, object]
    ) -> None:
        economic_ids = [
            str(step["step_id"]) for step in plan["steps"] if step["economic"]
        ]
        assert [line["step_id"] for line in manifest["lines"]] == economic_ids
        # Refusal proofs are present and never treated as free.
        assert any("wrong-envelope" in sid for sid in economic_ids)
        assert any(
            line["step_id"] == "H-no-second-economic-action" for line in manifest["lines"]
        )
        for line in manifest["lines"]:
            assert int(line["max_payment_motes"]) > 0
            assert line["entry_point"] is not None or line["kind"] in (
                "contract_install",
                "native_transfer",
            )
            assert len(line["typed_args_sha256"]) == 64
            assert line["signer_role"]

    def test_ceiling_arithmetic_is_checked(self, manifest: dict[str, object]) -> None:
        principal = int(manifest["transfer_principal_motes"])
        fees = int(manifest["max_fees_motes"])
        assert principal > 0
        assert fees == sum(int(line["max_payment_motes"]) for line in manifest["lines"])
        assert int(manifest["max_total_outlay_motes"]) == principal + fees
        validate_economic_manifest(manifest)
        tampered = dict(manifest, max_total_outlay_motes=str(principal + fees + 1))
        with pytest.raises(CanaryRefusal) as refusal:
            validate_economic_manifest(tampered)
        assert refusal.value.code == RefusalCode.CEILING_ARITHMETIC_INVALID

    def test_missing_principal_refuses(self, plan: dict[str, object]) -> None:
        gutted = dict(plan)
        gutted["steps"] = [
            step for step in plan["steps"] if step["kind"] != "native_transfer"
        ]
        with pytest.raises(CanaryRefusal) as refusal:
            build_economic_manifest(
                gutted, calibration=_calibration_for(gutted), operator_ceilings={}
            )
        assert refusal.value.code == RefusalCode.PRINCIPAL_LINE_ABSENT

    def test_uncalibrated_line_without_operator_ceiling_refuses(
        self, plan: dict[str, object]
    ) -> None:
        calibration = _calibration_for(plan)
        del calibration["lines"]["B-install-rc-wasm"]
        with pytest.raises(CanaryRefusal) as refusal:
            build_economic_manifest(plan, calibration=calibration, operator_ceilings={})
        assert refusal.value.code == RefusalCode.CALIBRATION_RECEIPT_ABSENT

    def test_explicit_operator_ceiling_substitutes_for_calibration(
        self, plan: dict[str, object]
    ) -> None:
        calibration = _calibration_for(plan)
        del calibration["lines"]["B-install-rc-wasm"]
        manifest = build_economic_manifest(
            plan,
            calibration=calibration,
            operator_ceilings={
                "B-install-rc-wasm": {
                    "conservative_ceiling_motes": "400000000000",
                    "declared_by": "asad-public-approval",
                }
            },
        )
        line = next(
            line for line in manifest["lines"] if line["step_id"] == "B-install-rc-wasm"
        )
        assert line["basis"] == "operator_ceiling"
        assert line["max_payment_motes"] == "400000000000"

    def test_unfinalized_calibration_receipt_refuses(self, plan: dict[str, object]) -> None:
        calibration = _calibration_for(plan)
        calibration["lines"]["D-propose-envelope"]["receipt"]["finalized"] = False
        with pytest.raises(CanaryRefusal) as refusal:
            build_economic_manifest(plan, calibration=calibration, operator_ceilings={})
        assert refusal.value.code == RefusalCode.CALIBRATION_RECEIPT_ABSENT

    def test_zero_fee_line_refuses(self, plan: dict[str, object]) -> None:
        calibration = _calibration_for(plan)
        calibration["lines"]["D-propose-envelope"]["payment_motes"] = "0"
        with pytest.raises(CanaryRefusal) as refusal:
            build_economic_manifest(plan, calibration=calibration, operator_ceilings={})
        assert refusal.value.code == RefusalCode.CEILING_ARITHMETIC_INVALID

    def test_funding_output_is_exactly_the_total_outlay(
        self, manifest: dict[str, object]
    ) -> None:
        assert required_funding_motes(manifest) == manifest["max_total_outlay_motes"]


class TestHumanAuthorization:
    def test_valid_authorization_passes(
        self, plan: dict[str, object], manifest: dict[str, object]
    ) -> None:
        validate_human_authorization(
            _authorization(plan, manifest), manifest=manifest, clock_unix=CLOCK_NOW
        )

    def test_expired_authorization_refuses(
        self, plan: dict[str, object], manifest: dict[str, object]
    ) -> None:
        for expiry in (0, CLOCK_NOW - 1, CLOCK_NOW):
            with pytest.raises(CanaryRefusal) as refusal:
                validate_human_authorization(
                    _authorization(plan, manifest, expiry_unix=expiry),
                    manifest=manifest,
                    clock_unix=CLOCK_NOW,
                )
            assert refusal.value.code == RefusalCode.AUTHORIZATION_EXPIRED

    @pytest.mark.parametrize(
        "field,value",
        [
            ("plan_hash", "0" * 64),
            ("chain_name", "casper-test"),
            ("recipient_account_hash", "0" * 64),
            ("transfer_principal_motes", "1"),
            ("max_fees_motes", "1"),
            ("max_total_outlay_motes", "1"),
        ],
    )
    def test_any_binding_mismatch_refuses(
        self,
        plan: dict[str, object],
        manifest: dict[str, object],
        field: str,
        value: object,
    ) -> None:
        with pytest.raises(CanaryRefusal) as refusal:
            validate_human_authorization(
                _authorization(plan, manifest, **{field: value}),
                manifest=manifest,
                clock_unix=CLOCK_NOW,
            )
        assert refusal.value.code in (
            RefusalCode.AUTHORIZATION_INVALID,
            RefusalCode.NETWORK_MISMATCH,
        )

    def test_executor_cannot_spend_above_signed_ceiling(
        self, plan: dict[str, object], manifest: dict[str, object]
    ) -> None:
        authorization = _authorization(plan, manifest)
        validate_human_authorization(
            authorization, manifest=manifest, clock_unix=CLOCK_NOW
        )
        require_within_authorization(manifest, authorization)
        inflated = dict(
            manifest,
            max_total_outlay_motes=str(int(manifest["max_total_outlay_motes"]) + 1),
        )
        with pytest.raises(CanaryRefusal) as refusal:
            require_within_authorization(inflated, authorization)
        assert refusal.value.code in (
            RefusalCode.CEILING_ARITHMETIC_INVALID,
            RefusalCode.AUTHORIZATION_INVALID,
        )
