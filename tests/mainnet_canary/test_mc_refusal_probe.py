"""F9 refusal probe: the redirected-recipient construction, proven precisely.

The F9 step must present an envelope that is internally coherent — the
redirected ``action_id`` and ``transfer_id`` are recomputed exactly as the
contract recomputes them — so that every per-field recomputation check
passes and the refusal can only come from the envelope-commitment
comparison (``EnvelopeHashMismatch``, User error 10).  A naive single-field
change is caught EARLIER as ``InvalidActionField`` (User error 16), which
would prove the wrong thing; the on-chain half of this proof (error 10 on
the redirected coherent envelope, then exact-envelope success) lives in
``contracts/odra-governance-receipt-v3/tests/network_profile.rs``.

Properties under test (plan side):

1. finalizer, treasury source, and approved recipient are pairwise distinct;
2. the F9 recipient equals the finalizer and differs from the approved
   recipient;
3. the F9 action_id differs from G's action_id;
4. the F9 transfer_id differs from G's transfer_id;
5. independent recomputation (the frozen shared primitives) reproduces the
   F9 action_id and transfer_id from the F9 typed arguments alone;
6. the recomputed F9 envelope hash differs from the approved commitment;
7. the naive construction (recipient changed, identifiers retained) is
   refused as the InvalidActionField class — the error-16 analogue;
8. E, F9, and H record ``expected_refusal`` with stable scenarios, and no
   step claims anything was demonstrated before a live receipt exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import mc_support
from tools.mainnet_canary.crosscheck import recompute_native_identifiers
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode


@pytest.fixture()
def plan(plan_inputs: dict[str, Path]) -> dict[str, object]:
    return mc_support.build_valid_plan(plan_inputs)


def _step(plan: dict[str, object], step_id: str) -> dict[str, object]:
    return next(s for s in plan["steps"] if s["step_id"] == step_id)


def _args_by_name(step: dict[str, object]) -> dict[str, object]:
    return {arg["name"]: arg["value"] for arg in step["typed_args"]}


def _header_body_from_args(
    plan: dict[str, object], values: dict[str, object]
) -> tuple[dict, dict]:
    header_names = (
        "proposal_id",
        "proposal_nonce",
        "decision_code",
        "requested_allocation_bps",
        "approved_allocation_bps",
        "action_kind",
        "action_version",
        "action_id",
        "proposal_hash",
        "policy_hash",
        "plan_hash",
        "final_card_hash",
        "dissent_hash",
        "agent_action_hash",
        "preauth_evidence_root",
        "authorized_metadata_root",
    )
    header = {name: values[name] for name in header_names}
    header["schema_version"] = 3
    # The contract stores these two; the finalize args deliberately omit
    # them, so the reconstruction takes them from the plan's own envelope.
    header["deployment_domain"] = plan["envelope"]["header"]["deployment_domain"]
    header["casper_chain_name"] = "casper"
    body = {
        name: values[name] for name in values if name not in header_names
    }
    return header, body


class TestRedirectedRefusalProbe:
    def test_roles_are_pairwise_distinct(self, plan: dict[str, object]) -> None:
        identities = plan["identities"]
        finalizer = identities["finalizer"]["account_hash_hex"]
        source = identities["treasury_source"]["account_hash_hex"]
        recipient = identities["recipient"]["account_hash_hex"]
        assert len({finalizer, source, recipient}) == 3

    def test_f9_redirects_to_the_finalizer(self, plan: dict[str, object]) -> None:
        f9 = _args_by_name(_step(plan, "F9-wrong-envelope-refusal"))
        g = _args_by_name(_step(plan, "G-finalize-exact-envelope"))
        finalizer = plan["identities"]["finalizer"]["account_hash_hex"]
        assert f9["recipient_account"] == finalizer
        assert f9["recipient_account"] != g["recipient_account"]

    def test_f9_identifiers_differ_from_g(self, plan: dict[str, object]) -> None:
        f9 = _args_by_name(_step(plan, "F9-wrong-envelope-refusal"))
        g = _args_by_name(_step(plan, "G-finalize-exact-envelope"))
        assert f9["action_id"] != g["action_id"]
        assert f9["transfer_id"] != g["transfer_id"]
        # Everything OUTSIDE the redirected recipient and the two recomputed
        # identifiers is byte-equal to the approved envelope.
        changed = {
            name for name in f9 if f9[name] != g[name]
        }
        assert changed == {"recipient_account", "action_id", "transfer_id"}

    def test_independent_recomputation_reproduces_f9_identifiers(
        self, plan: dict[str, object]
    ) -> None:
        f9 = _args_by_name(_step(plan, "F9-wrong-envelope-refusal"))
        header, body = _header_body_from_args(plan, f9)
        # The dual-implementation gate recomputes action_id/transfer_id and
        # refuses any disagreement with the supplied values — passing IS the
        # independent reproduction.
        material = recompute_native_identifiers(
            header, body, chain_name="casper"
        )
        assert material.action_id_hex == f9["action_id"]
        assert str(material.transfer_id) == str(f9["transfer_id"])

    def test_f9_envelope_hash_differs_from_approved_commitment(
        self, plan: dict[str, object]
    ) -> None:
        f9 = _args_by_name(_step(plan, "F9-wrong-envelope-refusal"))
        header, body = _header_body_from_args(plan, f9)
        material = recompute_native_identifiers(
            header, body, chain_name="casper"
        )
        approved = plan["envelope"]["derived"]["envelope_hash"]
        assert material.envelope_hash_hex != approved
        expected = _step(plan, "F9-wrong-envelope-refusal")["expected_outcome"]
        assert expected["redirected_envelope_hash"] == material.envelope_hash_hex
        assert expected["redirected_action_id"] == material.action_id_hex
        assert expected["redirected_transfer_id"] == str(material.transfer_id)

    def test_naive_redirect_without_recomputation_is_the_error_16_class(
        self, plan: dict[str, object]
    ) -> None:
        # Change ONLY the recipient while retaining the approved action_id
        # and transfer_id: the contract recomputes both before the envelope
        # comparison and returns InvalidActionField (16), never reaching
        # EnvelopeHashMismatch (10).  The plan-side dual recomputation
        # refuses the same construction for the same reason.
        g = _args_by_name(_step(plan, "G-finalize-exact-envelope"))
        finalizer = plan["identities"]["finalizer"]["account_hash_hex"]
        naive = dict(g)
        naive["recipient_account"] = finalizer
        header, body = _header_body_from_args(plan, naive)
        with pytest.raises(CanaryRefusal) as refusal:
            recompute_native_identifiers(header, body, chain_name="casper")
        assert refusal.value.code == RefusalCode.ENVELOPE_INVALID
        assert "InvalidActionField" in refusal.value.detail
        assert "action_id" in refusal.value.detail

    def test_refusal_steps_record_expectations_not_demonstrations(
        self, plan: dict[str, object]
    ) -> None:
        scenarios = {
            "E-prequorum-finalize-refusal": "pre_quorum_finalize",
            "F9-wrong-envelope-refusal": "post_quorum_recipient_redirect",
            "H-no-second-economic-action": "duplicate_finalize_replay",
        }
        for step_id, scenario in scenarios.items():
            expected = _step(plan, step_id)["expected_outcome"]
            assert expected["expected_refusal"] is True
            assert expected["refusal_scenario"] == scenario
        # Nothing in the plan may claim a demonstration before a live
        # receipt exists: ``refusal_observed``/``attack_demonstrated`` are
        # derived by verification from finalized receipts only.
        for step in plan["steps"]:
            expected = step.get("expected_outcome", {})
            assert "refusal_observed" not in expected
            assert "attack_demonstrated" not in expected

    def test_f9_expected_outcome_pins_both_recipients(
        self, plan: dict[str, object]
    ) -> None:
        expected = _step(plan, "F9-wrong-envelope-refusal")["expected_outcome"]
        identities = plan["identities"]
        assert expected["approved_recipient"] == (
            identities["recipient"]["account_hash_hex"]
        )
        assert expected["redirected_recipient"] == (
            identities["finalizer"]["account_hash_hex"]
        )
        assert expected["error_name"] == "EnvelopeHashMismatch"
        assert expected["execution"] == "failure"
