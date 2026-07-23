"""Finality verification v2: two disjoint providers, raw evidence, no trust.

Requirements under test:
- upstream booleans are never sufficient: every observation must carry raw
  provider evidence (sanitized endpoint identity, method, request digest,
  raw response SHA-256, retrieval time, node identity);
- exactly two observations from disjoint Mainnet providers are required
  (single-source, same-provider, or 3+ sets refuse with NODE_SET_INVALID);
- any cross-provider disagreement on block identity, deploy hash, or the
  execution result refuses with NODE_DISAGREEMENT;
- wrong-network, malformed, pending, unsigned, or non-member evidence
  refuses exactly as in v1;
- explicit C (install/config readback), H (duplicate refusal), and
  J (transfer readback) evaluations.
"""

from __future__ import annotations

import pytest

import mc_support
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.finality_v2 import (
    OBSERVATION_V2_SCHEMA_ID,
    evaluate_dual_provider,
    validate_observation_v2,
)

STEP = "G-finalize-exact-envelope"


def _provider(provider_id: str, host: str) -> dict[str, object]:
    return {
        "provider_id": provider_id,
        "endpoint_host": host,
        "method": "info_get_deploy",
        "request_sha256": "11" * 32,
        "response_sha256": "22" * 32,
        "retrieved_at_unix": 1_700_000_000,
        "api_version": "2.0.0",
        "chainspec_name": "casper",
        # Comfortably deeper than FINALITY_CONFIRMATION_DEPTH so these
        # cases isolate the property they name; depth has its own tests.
        "chain_tip_height": 200,
    }


def _observation(step_id: str = STEP, provider_id: str = "provider-a", host: str = "node-a.example", **overrides: object) -> dict[str, object]:
    document = mc_support.make_observation(step_id, **overrides)
    document["schema_id"] = OBSERVATION_V2_SCHEMA_ID
    document["provider"] = _provider(provider_id, host)
    if "state_readback" not in overrides:
        document["state_readback"] = None
    return document


def _pair(**overrides_b: object) -> list[dict[str, object]]:
    return [
        _observation(),
        _observation(provider_id="provider-b", host="node-b.example", **overrides_b),
    ]


EXPECT_SUCCESS = {"type": "expected_success"}


class TestProviderSet:
    def test_agreeing_disjoint_pair_passes(self) -> None:
        result = evaluate_dual_provider(_pair(), step_id=STEP, expectation=EXPECT_SUCCESS)
        assert sorted(result["providers"]) == ["provider-a", "provider-b"]
        assert result["consensus_block_hash"] == "6f" * 32
        assert len(result["raw_response_sha256s"]) == 2

    def test_single_provider_refuses(self) -> None:
        with pytest.raises(CanaryRefusal) as refusal:
            evaluate_dual_provider(
                [_observation()], step_id=STEP, expectation=EXPECT_SUCCESS
            )
        assert refusal.value.code == RefusalCode.NODE_SET_INVALID

    def test_same_provider_twice_refuses(self) -> None:
        pair = [_observation(), _observation()]
        with pytest.raises(CanaryRefusal) as refusal:
            evaluate_dual_provider(pair, step_id=STEP, expectation=EXPECT_SUCCESS)
        assert refusal.value.code == RefusalCode.NODE_SET_INVALID

    def test_same_host_behind_two_ids_refuses(self) -> None:
        pair = [
            _observation(),
            _observation(provider_id="provider-b", host="node-a.example"),
        ]
        with pytest.raises(CanaryRefusal) as refusal:
            evaluate_dual_provider(pair, step_id=STEP, expectation=EXPECT_SUCCESS)
        assert refusal.value.code == RefusalCode.NODE_SET_INVALID

    def test_three_observations_refuse(self) -> None:
        pair = _pair() + [_observation(provider_id="provider-c", host="node-c.example")]
        with pytest.raises(CanaryRefusal) as refusal:
            evaluate_dual_provider(pair, step_id=STEP, expectation=EXPECT_SUCCESS)
        assert refusal.value.code == RefusalCode.NODE_SET_INVALID


class TestRawEvidence:
    def test_v1_schema_without_provider_evidence_refuses(self) -> None:
        document = mc_support.make_observation(STEP)
        with pytest.raises(CanaryRefusal) as refusal:
            validate_observation_v2(document)
        assert refusal.value.code == RefusalCode.OBSERVATION_MALFORMED

    @pytest.mark.parametrize(
        "field", ["response_sha256", "request_sha256", "endpoint_host", "retrieved_at_unix"]
    )
    def test_missing_raw_evidence_field_refuses(self, field: str) -> None:
        observation = _observation()
        del observation["provider"][field]
        with pytest.raises(CanaryRefusal) as refusal:
            validate_observation_v2(observation)
        assert refusal.value.code == RefusalCode.OBSERVATION_MALFORMED

    def test_wrong_network_provider_refuses(self) -> None:
        observation = _observation()
        observation["provider"]["chainspec_name"] = "casper-test"
        with pytest.raises(CanaryRefusal) as refusal:
            validate_observation_v2(observation)
        assert refusal.value.code == RefusalCode.NETWORK_MISMATCH


class TestDisagreement:
    @pytest.mark.parametrize(
        "overrides",
        [
            {"block": {"block_hash": "aa" * 32}},
            {"block": {"block_height": 121}},
            {"block": {"state_root_hash": "bb" * 32}},
            {"deploy_hash": "cc" * 32},
            {"execution": {"success": False, "error_message": "User error: 8"}},
        ],
    )
    def test_any_cross_provider_disagreement_refuses(
        self, overrides: dict[str, object]
    ) -> None:
        with pytest.raises(CanaryRefusal) as refusal:
            evaluate_dual_provider(
                _pair(**overrides), step_id=STEP, expectation=EXPECT_SUCCESS
            )
        assert refusal.value.code == RefusalCode.NODE_DISAGREEMENT

    def test_pending_on_either_provider_refuses(self) -> None:
        with pytest.raises(CanaryRefusal) as refusal:
            evaluate_dual_provider(
                _pair(block={"status": "pending"}),
                step_id=STEP,
                expectation=EXPECT_SUCCESS,
            )
        assert refusal.value.code in (
            RefusalCode.PROOF_PENDING,
            RefusalCode.NODE_DISAGREEMENT,
        )


class TestExplicitReadbacks:
    def test_c_install_readback_binds_config(self) -> None:
        state = {
            "schema_version": 3,
            "casper_chain_name": "casper",
            "deployment_domain": "ab" * 32,
            "threshold": 2,
        }
        pair = [
            _observation("C-verify-install", state_readback=state),
            _observation(
                "C-verify-install",
                provider_id="provider-b",
                host="node-b.example",
                state_readback=state,
            ),
        ]
        evaluate_dual_provider(
            pair,
            step_id="C-verify-install",
            expectation={"type": "state_readback", "state": state},
        )
        wrong = dict(state, casper_chain_name="casper-test")
        with pytest.raises(CanaryRefusal) as refusal:
            evaluate_dual_provider(
                pair,
                step_id="C-verify-install",
                expectation={"type": "state_readback", "state": wrong},
            )
        assert refusal.value.code == RefusalCode.READBACK_MISMATCH

    def test_h_duplicate_refusal_requires_exact_error(self) -> None:
        failure = {"execution": {"success": False, "error_message": "User error: 12"}}
        pair = [
            _observation("H-no-second-economic-action", **failure),
            _observation(
                "H-no-second-economic-action",
                provider_id="provider-b",
                host="node-b.example",
                **failure,
            ),
        ]
        evaluate_dual_provider(
            pair,
            step_id="H-no-second-economic-action",
            expectation={"type": "exact_refusal", "error_message": "User error: 12"},
        )
        with pytest.raises(CanaryRefusal) as refusal:
            evaluate_dual_provider(
                pair,
                step_id="H-no-second-economic-action",
                expectation={"type": "exact_refusal", "error_message": "User error: 8"},
            )
        assert refusal.value.code == RefusalCode.WRONG_REFUSAL_CODE

    def test_j_transfer_readback_binds_transfer_identity(self) -> None:
        transfer = {
            "source_account": "1a" * 32,
            "recipient_account": "2b" * 32,
            "amount_motes": "2500000000",
            "transfer_id": "77",
        }
        kwargs = {"target": {"transfer": transfer}}
        pair = [
            _observation("J-transfer-readback", **kwargs),
            _observation(
                "J-transfer-readback",
                provider_id="provider-b",
                host="node-b.example",
                **kwargs,
            ),
        ]
        evaluate_dual_provider(
            pair,
            step_id="J-transfer-readback",
            expectation={"type": "native_transfer", **transfer},
        )
        with pytest.raises(CanaryRefusal) as refusal:
            evaluate_dual_provider(
                pair,
                step_id="J-transfer-readback",
                expectation={
                    "type": "native_transfer",
                    **dict(transfer, amount_motes="9999999999"),
                },
            )
        assert refusal.value.code == RefusalCode.TRANSFER_MISMATCH


class TestConfirmationDepth:
    """FINALITY_CONFIRMATION_DEPTH was a constant nothing read; it is now
    a measured, enforced property of every observation."""

    def test_a_shallow_block_refuses(self) -> None:
        # block_height 120 with tip 127 is 7 confirmations — one short.
        shallow = _pair()
        for observation in shallow:
            observation["provider"]["chain_tip_height"] = 127
        with pytest.raises(CanaryRefusal) as refusal:
            evaluate_dual_provider(
                shallow, step_id=STEP, expectation=EXPECT_SUCCESS
            )
        assert refusal.value.code == RefusalCode.INSUFFICIENT_CONFIRMATIONS

    def test_exactly_the_required_depth_is_accepted(self) -> None:
        exact = _pair()
        for observation in exact:
            observation["provider"]["chain_tip_height"] = 128
        evaluate_dual_provider(exact, step_id=STEP, expectation=EXPECT_SUCCESS)

    def test_a_missing_chain_tip_refuses(self) -> None:
        observation = _observation()
        del observation["provider"]["chain_tip_height"]
        with pytest.raises(CanaryRefusal) as refusal:
            validate_observation_v2(observation)
        assert refusal.value.code == RefusalCode.OBSERVATION_MALFORMED
