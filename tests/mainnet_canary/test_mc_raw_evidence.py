"""Blockers 2+5 failure-first suite: raw RPC evidence and nested validation.

Summary-only evidence (labels + digests without raw bodies) refuses; edited
raw bodies refuse; recorded fields that do not re-derive from the raw bodies
refuse; and every malformed nested structure returns a NAMED refusal — never
a ``KeyError`` or any other traceback.
"""

from __future__ import annotations

import json

import pytest

import mc_support
from tools.mainnet_canary.collector import collect_provider_observation
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.finality_v2 import (
    evaluate_dual_provider,
    validate_observation_v3,
)

STEP = "G-finalize-exact-envelope"
EXPECT_SUCCESS = {"type": "expected_success"}


def _observation(**overrides: object) -> dict[str, object]:
    document = mc_support.make_observation(STEP, **overrides)
    document["schema_id"] = "concordia.mainnet-canary.step-observation.v3"
    document.setdefault("state_readback", None)
    document["provider"] = mc_support.make_v3_provider_for_observation(
        document, "provider-a", "node-a.example"
    )
    return document


class TestRawEvidenceRequired:
    def test_summary_only_provider_evidence_refuses(self) -> None:
        """Labels plus caller-supplied digests are insufficient (blocker 2)."""

        document = _observation()
        del document["provider"]["raw_exchanges"]
        with pytest.raises(CanaryRefusal) as refusal:
            validate_observation_v3(document)
        assert refusal.value.code == RefusalCode.OBSERVATION_MALFORMED

    def test_missing_one_exchange_refuses(self) -> None:
        document = _observation()
        del document["provider"]["raw_exchanges"]["chain_get_block"]
        with pytest.raises(CanaryRefusal) as refusal:
            validate_observation_v3(document)
        assert refusal.value.code == RefusalCode.RAW_EVIDENCE_ABSENT

    def test_edited_response_body_refuses(self) -> None:
        document = _observation()
        exchange = document["provider"]["raw_exchanges"]["info_get_deploy"]
        exchange["response_body"] = exchange["response_body"].replace(
            '"jsonrpc":"2.0"', '"jsonrpc":"2.1"'
        )
        with pytest.raises(CanaryRefusal) as refusal:
            validate_observation_v3(document)
        assert refusal.value.code == RefusalCode.RAW_EVIDENCE_MISMATCH

    def test_recorded_execution_that_contradicts_raw_refuses(self) -> None:
        document = _observation()
        document["execution"]["success"] = False
        document["execution"]["error_message"] = "User error: 8"
        with pytest.raises(CanaryRefusal) as refusal:
            validate_observation_v3(document)
        assert refusal.value.code == RefusalCode.RAW_EVIDENCE_MISMATCH

    def test_recorded_tip_that_contradicts_raw_refuses(self) -> None:
        document = _observation()
        document["provider"]["chain_tip_height"] = 999
        with pytest.raises(CanaryRefusal) as refusal:
            validate_observation_v3(document)
        assert refusal.value.code == RefusalCode.RAW_EVIDENCE_MISMATCH

    def test_oversized_raw_body_refuses(self) -> None:
        document = _observation()
        exchange = document["provider"]["raw_exchanges"]["info_get_status"]
        exchange["response_body"] = exchange["response_body"] + " " * 900_000
        with pytest.raises(CanaryRefusal) as refusal:
            validate_observation_v3(document)
        assert refusal.value.code in (
            RefusalCode.RAW_EVIDENCE_OVERSIZED,
            RefusalCode.RAW_EVIDENCE_MISMATCH,
        )

    def test_secretlike_raw_body_refuses(self) -> None:
        document = _observation()
        exchange = document["provider"]["raw_exchanges"]["info_get_status"]
        body = json.loads(exchange["response_body"])
        body["result"]["note"] = "-----BEGIN PRIVATE KEY-----"
        exchange["response_body"] = json.dumps(
            body, sort_keys=True, separators=(",", ":")
        )
        with pytest.raises(CanaryRefusal) as refusal:
            validate_observation_v3(document)
        assert refusal.value.code in (
            RefusalCode.KEY_INVENTORY_SECRET_MATERIAL,
            RefusalCode.RAW_EVIDENCE_MISMATCH,
        )


class TestNestedValidationNeverRaisesBare:
    """Blocker 5: malformed nested fields → named refusals, no tracebacks."""

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda d: d.__setitem__("block", None),
            lambda d: d.__setitem__("block", []),
            lambda d: d["block"].pop("block_height"),
            lambda d: d["block"].__setitem__("block_height", "tall"),
            lambda d: d["block"].__setitem__("era_id", None),
            lambda d: d["block"].__setitem__("status", "weird"),
            lambda d: d.__setitem__("execution", "ok"),
            lambda d: d["execution"].pop("success"),
            lambda d: d["execution"].__setitem__("success", "yes"),
            lambda d: d["execution"].__setitem__("cost_motes", -5),
            lambda d: d.__setitem__("provider", None),
            lambda d: d["provider"].__setitem__("chain_tip_height", "high"),
            lambda d: d.__setitem__("target", None),
        ],
    )
    def test_malformed_nested_field_returns_named_refusal(self, mutate) -> None:
        document = _observation()
        mutate(document)
        with pytest.raises(CanaryRefusal) as refusal:
            validate_observation_v3(document)
        assert refusal.value.code in (
            RefusalCode.OBSERVATION_MALFORMED,
            RefusalCode.RAW_EVIDENCE_MISMATCH,
            RefusalCode.RAW_EVIDENCE_ABSENT,
        )

    def test_malformed_pair_member_refuses_not_raises(self) -> None:
        pair = mc_support.make_v2_pair(STEP)
        del pair[1]["block"]["state_root_hash"]
        with pytest.raises(CanaryRefusal) as refusal:
            evaluate_dual_provider(
                pair, step_id=STEP, expectation=EXPECT_SUCCESS
            )
        assert refusal.value.code == RefusalCode.OBSERVATION_MALFORMED


class TestCollector:
    def _calls(self, provider: dict[str, object]):
        exchanges = provider["raw_exchanges"]

        def call(method: str, params: dict[str, object]) -> dict[str, object]:
            return json.loads(exchanges[method]["response_body"])

        return call

    def test_collector_output_validates_end_to_end(self) -> None:
        reference = _observation()
        observation = collect_provider_observation(
            self._calls(reference["provider"]),
            provider_id="provider-a",
            endpoint_host="node-a.example",
            step_id=STEP,
            deploy_hash=str(reference["deploy_hash"]),
            retrieved_at_unix=mc_support.CLOCK_UNIX,
            target=reference["target"],
            state_readback=None,
        )
        validate_observation_v3(observation)

    def test_collector_refuses_wrong_deploy_evidence(self) -> None:
        reference = _observation()
        with pytest.raises(CanaryRefusal) as refusal:
            collect_provider_observation(
                self._calls(reference["provider"]),
                provider_id="provider-a",
                endpoint_host="node-a.example",
                step_id=STEP,
                deploy_hash="ff" * 32,
                retrieved_at_unix=mc_support.CLOCK_UNIX,
                target=reference["target"],
                state_readback=None,
            )
        assert refusal.value.code == RefusalCode.RAW_EVIDENCE_MISMATCH

    def test_collector_requires_disjoint_hosts(self) -> None:
        from tools.mainnet_canary.collector import collect_dual_observations

        reference = _observation()
        call = self._calls(reference["provider"])
        with pytest.raises(CanaryRefusal) as refusal:
            collect_dual_observations(
                {"provider-a": call, "provider-b": call},
                hosts={
                    "provider-a": "node-a.example",
                    "provider-b": "node-a.example",
                },
                step_id=STEP,
                deploy_hash=str(reference["deploy_hash"]),
                retrieved_at_unix=mc_support.CLOCK_UNIX,
                target=reference["target"],
                state_readback=None,
            )
        assert refusal.value.code == RefusalCode.NODE_SET_INVALID
