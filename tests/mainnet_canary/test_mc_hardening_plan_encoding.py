"""Plan v2 + Mainnet deployment-domain separator (failing-first suite).

Requirements under test:
- the Python mirror derives the Mainnet deployment domain with the pinned
  ``CONCORDIA_DOMAIN_V3_MAINNET\\0`` separator, byte-agreeing with the Rust
  golden vectors in
  contracts/odra-governance-receipt-v3/tests/network_profile.rs;
- the transfer amount is an explicit human-authorized parameter — the plan
  refuses to choose an amount silently;
- the plan contains the post-quorum wrong-envelope refusal and the
  duplicate-finalize refusal as ECONOMIC steps with exact error renderings;
- the plan pins Mainnet OfficialX402SettlementV1 as fail-closed
  (``User error: 16``) until a live `/supported` observation exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import mc_support
from tools.mainnet_canary.encoding import derive_deployment_domain
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode

# Byte-for-byte the constants pinned in the Rust suite (network_profile.rs).
TESTNET_DOMAIN_GOLDEN = (
    "40804e79504df011ccbe7326898a9d7e489e01b445f483a199467584ddfb5726"
)
MAINNET_DOMAIN_GOLDEN = (
    "738f08998497f41853bacfa94833f5b301cbe3f3530e70f663f147255b27fcfd"
)
GOLDEN_NONCE = bytes([0xA5]) * 32
PACKAGE = "concordia_governance_receipt_v3"


class TestMainnetDomainSeparator:
    def test_testnet_domain_matches_rust_golden(self) -> None:
        domain = derive_deployment_domain(
            chain_name="casper-test",
            package_key_name=PACKAGE,
            installation_nonce=GOLDEN_NONCE,
        )
        assert domain.hex() == TESTNET_DOMAIN_GOLDEN

    def test_mainnet_domain_matches_rust_golden(self) -> None:
        domain = derive_deployment_domain(
            chain_name="casper",
            package_key_name=PACKAGE,
            installation_nonce=GOLDEN_NONCE,
        )
        assert domain.hex() == MAINNET_DOMAIN_GOLDEN

    def test_domains_are_disjoint_across_networks(self) -> None:
        testnet = derive_deployment_domain(
            chain_name="casper-test",
            package_key_name=PACKAGE,
            installation_nonce=GOLDEN_NONCE,
        )
        mainnet = derive_deployment_domain(
            chain_name="casper",
            package_key_name=PACKAGE,
            installation_nonce=GOLDEN_NONCE,
        )
        assert testnet != mainnet


class TestPlanV2:
    def test_plan_pins_the_mainnet_domain_golden(
        self, plan_inputs: dict[str, Path]
    ) -> None:
        # mc_support's installation nonce IS the golden nonce (0xa5 * 32), so
        # the C-verify-install expectation must carry the Mainnet golden.
        plan = mc_support.build_valid_plan(plan_inputs)
        step = next(
            step
            for step in plan["steps"]
            if step["step_id"] == "C-verify-install"
        )
        assert step["expected_outcome"]["deployment_domain"] == MAINNET_DOMAIN_GOLDEN

    def test_amount_is_never_chosen_silently(
        self, hermetic_repo: Path, tmp_path: Path
    ) -> None:
        parameters = mc_support.make_parameters()
        del parameters["human_authorized_amount_motes"]
        inputs = mc_support.build_plan_inputs(hermetic_repo, tmp_path)
        inputs["parameters"] = mc_support.write_json(
            tmp_path / "inputs" / "parameters.json", parameters
        )
        with pytest.raises(CanaryRefusal) as refusal:
            mc_support.build_valid_plan(inputs)
        assert refusal.value.code == RefusalCode.PLAN_INPUT_INVALID

    def test_authorized_amount_above_policy_bound_refuses(
        self, hermetic_repo: Path, tmp_path: Path
    ) -> None:
        # balance 625000000000 * 800 bps // 10000 = 50000000000 is the bound.
        inputs = mc_support.build_plan_inputs(hermetic_repo, tmp_path)
        inputs["parameters"] = mc_support.write_json(
            tmp_path / "inputs" / "parameters.json",
            mc_support.make_parameters(
                human_authorized_amount_motes="50000000001",
                max_amount_motes="99999999999",
            ),
        )
        with pytest.raises(CanaryRefusal) as refusal:
            mc_support.build_valid_plan(inputs)
        assert refusal.value.code == RefusalCode.AMOUNT_MISMATCH

    def test_authorized_amount_is_the_plan_amount(
        self, hermetic_repo: Path, tmp_path: Path
    ) -> None:
        # The frozen envelope pins amount == floor(balance * bps / 10000);
        # with 40 bps of the 625000000000 snapshot the exact confirmation is
        # 2500000000 — and the plan carries precisely the authorized value.
        inputs = mc_support.build_plan_inputs(hermetic_repo, tmp_path)
        inputs["parameters"] = mc_support.write_json(
            tmp_path / "inputs" / "parameters.json",
            mc_support.make_parameters(
                approved_allocation_bps=40,
                human_authorized_amount_motes="2500000000",
            ),
        )
        plan = mc_support.build_valid_plan(inputs)
        assert plan["envelope"]["body"]["amount_motes"] == "2500000000"

    def test_wrong_envelope_refusal_is_an_economic_post_quorum_step(
        self, plan_inputs: dict[str, Path]
    ) -> None:
        plan = mc_support.build_valid_plan(plan_inputs)
        step_ids = [step["step_id"] for step in plan["steps"]]
        step = next(
            step
            for step in plan["steps"]
            if step["step_id"] == "F9-wrong-envelope-refusal"
        )
        assert step["economic"] is True
        assert step["expected_outcome"]["exact_error_message"] == "User error: 10"
        assert step["expected_outcome"]["error_name"] == "EnvelopeHashMismatch"
        # Ordering: after the final approval, before the exact finalize.
        assert step_ids.index("F9-wrong-envelope-refusal") < step_ids.index(
            "G-finalize-exact-envelope"
        )
        assert step_ids.index("F9-wrong-envelope-refusal") > step_ids.index(
            "F-approve-signer-b"
        )

    def test_duplicate_finalize_refusal_is_economic_with_exact_error(
        self, plan_inputs: dict[str, Path]
    ) -> None:
        plan = mc_support.build_valid_plan(plan_inputs)
        step = next(
            step
            for step in plan["steps"]
            if step["step_id"] == "H-no-second-economic-action"
        )
        assert step["economic"] is True
        assert step["entry_point"] == "finalize_native_transfer"
        assert step["expected_outcome"]["exact_error_message"] == "User error: 12"
        assert step["expected_outcome"]["error_name"] == "AlreadyFinalized"

    def test_plan_pins_mainnet_x402_fail_closed(
        self, plan_inputs: dict[str, Path]
    ) -> None:
        plan = mc_support.build_valid_plan(plan_inputs)
        x402 = plan["mainnet_x402"]
        assert x402["supported"] is False
        assert x402["pinned_refusal"] == "User error: 16"
        assert "live" in x402["until"].lower() or "/supported" in x402["until"]

    def test_x402_parameters_are_rejected_outright(
        self, hermetic_repo: Path, tmp_path: Path
    ) -> None:
        inputs = mc_support.build_plan_inputs(hermetic_repo, tmp_path)
        inputs["parameters"] = mc_support.write_json(
            tmp_path / "inputs" / "parameters.json",
            mc_support.make_parameters(x402_settlement={"asset": "WCSPR"}),
        )
        with pytest.raises(CanaryRefusal) as refusal:
            mc_support.build_valid_plan(inputs)
        assert refusal.value.code == RefusalCode.PLAN_INPUT_INVALID
