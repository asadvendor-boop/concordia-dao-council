"""Spend model v2: plan-derived economic manifest + human authorization.

Requirements under test:
- cost lines 1:1 with the plan's economic steps (refusal proofs included);
- the native-transfer principal is its own line (PRINCIPAL_LINE_ABSENT);
- immutable integer ceilings with checked arithmetic
  ``max_total_outlay_motes = transfer_principal_motes + max_fees_motes``;
- no zero or placeholder fee maxima;
- every fee maximum is grounded in a fully bound v2 Testnet calibration
  receipt; operator ceilings are NOT a permitted substitute
  (OPERATOR_CEILING_NOT_PERMITTED), and the line set must equal the
  plan-derived economic steps exactly (CALIBRATION_LINE_SET_MISMATCH);
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
PINNED_KEYS = frozenset({mc_support.test_authorizer_public_key_hex()})


def _calibration_for(plan: dict[str, object]) -> dict[str, object]:
    return mc_support.make_calibration(plan)


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
        "authorizer_public_key_hex": mc_support.test_authorizer_public_key_hex(),
        "signature_hex": "",
    }
    document.update(overrides)
    # Sign LAST so overrides are covered by the signature.
    return mc_support.sign_authorization(document)


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

    def test_missing_calibration_line_refuses(
        self, plan: dict[str, object]
    ) -> None:
        calibration = _calibration_for(plan)
        del calibration["lines"]["B-install-rc-wasm"]
        with pytest.raises(CanaryRefusal) as refusal:
            build_economic_manifest(plan, calibration=calibration, operator_ceilings={})
        assert refusal.value.code == RefusalCode.CALIBRATION_LINE_SET_MISMATCH

    def test_operator_ceiling_is_not_a_permitted_substitute(
        self, plan: dict[str, object]
    ) -> None:
        # Finals policy: receipt-backed calibration only. Even a fully
        # calibrated manifest refuses the moment any operator ceiling is
        # supplied — the bypass path must not exist at all.
        with pytest.raises(CanaryRefusal) as refusal:
            build_economic_manifest(
                plan,
                calibration=_calibration_for(plan),
                operator_ceilings={
                    "B-install-rc-wasm": {
                        "conservative_ceiling_motes": "400000000000",
                        "declared_by": "asad-public-approval",
                    }
                },
            )
        assert refusal.value.code == RefusalCode.OPERATOR_CEILING_NOT_PERMITTED

    def test_insufficiently_confirmed_calibration_receipt_refuses(
        self, plan: dict[str, object]
    ) -> None:
        calibration = _calibration_for(plan)
        line = calibration["lines"]["D-propose-envelope"]
        receipt = line["receipt"]
        receipt["finality"] = {
            "chain_tip_height": int(receipt["block_height"]) + 7
        }
        with pytest.raises(CanaryRefusal) as refusal:
            build_economic_manifest(plan, calibration=calibration, operator_ceilings={})
        assert refusal.value.code == RefusalCode.INSUFFICIENT_CONFIRMATIONS

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
            _authorization(plan, manifest), manifest=manifest,
                clock_unix=CLOCK_NOW,
                pinned_authorizer_keys=PINNED_KEYS
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
                    pinned_authorizer_keys=PINNED_KEYS,
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
            authorization, manifest=manifest,
                clock_unix=CLOCK_NOW,
                pinned_authorizer_keys=PINNED_KEYS
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


class TestAuthorizationAuthenticity:
    """Well-formed is not authentic.

    Before this pass the authorization was only schema-checked, so any
    process able to write the file could authorize a real Mainnet spend.
    """

    def test_an_unsigned_authorization_refuses(
        self, plan: dict[str, object], manifest: dict[str, object]
    ) -> None:
        document = _authorization(plan, manifest)
        document["signature_hex"] = ""
        with pytest.raises(CanaryRefusal) as refusal:
            validate_human_authorization(
                document,
                manifest=manifest,
                clock_unix=CLOCK_NOW,
                pinned_authorizer_keys=PINNED_KEYS,
            )
        assert refusal.value.code == RefusalCode.AUTHORIZATION_UNSIGNED

    def test_a_tampered_field_invalidates_the_signature(
        self, plan: dict[str, object], manifest: dict[str, object]
    ) -> None:
        # Signed correctly, then the ceiling is raised after the fact.
        document = _authorization(plan, manifest)
        document["max_total_outlay_motes"] = str(
            int(manifest["max_total_outlay_motes"]) + 1
        )
        with pytest.raises(CanaryRefusal) as refusal:
            validate_human_authorization(
                document,
                manifest=manifest,
                clock_unix=CLOCK_NOW,
                pinned_authorizer_keys=PINNED_KEYS,
            )
        # Either the binding check or the signature catches it; both are
        # fail-closed and neither may let the raised ceiling through.
        assert refusal.value.code in (
            RefusalCode.AUTHORIZATION_INVALID,
            RefusalCode.AUTHORIZATION_SIGNATURE_INVALID,
        )

    def test_a_signature_from_an_unpinned_key_refuses(
        self, plan: dict[str, object], manifest: dict[str, object]
    ) -> None:
        document = _authorization(plan, manifest)
        with pytest.raises(CanaryRefusal) as refusal:
            validate_human_authorization(
                document,
                manifest=manifest,
                clock_unix=CLOCK_NOW,
                pinned_authorizer_keys=frozenset({"01" + "ff" * 32}),
            )
        assert refusal.value.code == RefusalCode.AUTHORIZER_NOT_PINNED

    def test_no_pinned_set_at_all_refuses(
        self, plan: dict[str, object], manifest: dict[str, object]
    ) -> None:
        # Verifying against a key the document itself nominated proves nothing.
        with pytest.raises(CanaryRefusal) as refusal:
            validate_human_authorization(
                _authorization(plan, manifest),
                manifest=manifest,
                clock_unix=CLOCK_NOW,
                pinned_authorizer_keys=frozenset(),
            )
        assert refusal.value.code == RefusalCode.AUTHORIZER_NOT_PINNED
