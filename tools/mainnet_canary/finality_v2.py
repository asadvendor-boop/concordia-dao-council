"""Finality verification v2: two disjoint providers, raw evidence, no trust.

An upstream boolean (``finalized``, ``block_proofs_present``,
``deploy_is_member``) is never accepted on its own authority.  Every v2
observation must carry raw provider evidence — sanitized endpoint identity,
RPC method, request digest, raw response SHA-256, retrieval time, and node
identity — and every economic conclusion requires EXACTLY TWO observations
from configured, disjoint Mainnet providers that agree on the block identity,
the deploy hash, and the execution result.  Anything stale, partial,
conflicting, single-source, wrong-network, or malformed refuses.

Structural block/execution semantics are shared with the v1 evaluator in
:mod:`tools.mainnet_canary.verify`; this module adds the provider-evidence
layer, the cross-provider consensus, and explicit C/H/J evaluations.
"""

from __future__ import annotations

import re

from tools.mainnet_canary.constants import MAINNET_CHAIN_NAME
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.verify import (
    evaluate_expected_prequorum_refusal,
    evaluate_expected_success,
    evaluate_native_transfer_readback,
    require_finalized_membership,
)

OBSERVATION_V2_SCHEMA_ID = "concordia.mainnet-canary.step-observation.v2"

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")

_REQUIRED_TOP = {
    "schema_id",
    "step_id",
    "deploy_hash",
    "chain_name_observed",
    "block",
    "execution",
    "target",
    "provider",
    "state_readback",
}
_REQUIRED_PROVIDER = {
    "provider_id",
    "endpoint_host",
    "method",
    "request_sha256",
    "response_sha256",
    "retrieved_at_unix",
    "api_version",
    "chainspec_name",
}


def _refuse(code: str, detail: str) -> CanaryRefusal:
    return CanaryRefusal(code, detail)


def validate_observation_v2(document: object) -> dict[str, object]:
    """Structural validation incl. the mandatory raw provider evidence."""

    if not isinstance(document, dict) or set(document) != _REQUIRED_TOP:
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED,
            f"v2 observation must contain exactly {sorted(_REQUIRED_TOP)}",
        )
    if document["schema_id"] != OBSERVATION_V2_SCHEMA_ID:
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED,
            f"schema_id must equal {OBSERVATION_V2_SCHEMA_ID}",
        )
    deploy_hash = document["deploy_hash"]
    if not isinstance(deploy_hash, str) or _HEX64.match(deploy_hash) is None:
        raise _refuse(RefusalCode.OBSERVATION_MALFORMED, "deploy_hash must be 64 hex")
    if document["chain_name_observed"] != MAINNET_CHAIN_NAME:
        raise _refuse(
            RefusalCode.NETWORK_MISMATCH, "observation is not from chain `casper`"
        )
    provider = document["provider"]
    if not isinstance(provider, dict) or set(provider) != _REQUIRED_PROVIDER:
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED,
            "provider evidence must contain exactly "
            f"{sorted(_REQUIRED_PROVIDER)}; booleans without raw evidence "
            "are never trusted",
        )
    for digest_field in ("request_sha256", "response_sha256"):
        value = provider[digest_field]
        if not isinstance(value, str) or _HEX64.match(value) is None:
            raise _refuse(
                RefusalCode.OBSERVATION_MALFORMED,
                f"provider.{digest_field} must be a raw SHA-256 hex digest",
            )
    if not isinstance(provider["retrieved_at_unix"], int) or provider[
        "retrieved_at_unix"
    ] <= 0:
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED,
            "provider.retrieved_at_unix must be a positive unix time",
        )
    for identity_field in ("provider_id", "endpoint_host", "method", "api_version"):
        value = provider[identity_field]
        if not isinstance(value, str) or not value:
            raise _refuse(
                RefusalCode.OBSERVATION_MALFORMED,
                f"provider.{identity_field} must be a non-empty string",
            )
    if provider["chainspec_name"] != MAINNET_CHAIN_NAME:
        raise _refuse(
            RefusalCode.NETWORK_MISMATCH,
            "provider reports a chainspec other than `casper`",
        )
    return document


_CONSENSUS_BLOCK_FIELDS = (
    "block_hash",
    "block_height",
    "state_root_hash",
    "era_id",
    "status",
)


def _require_agreement(a: dict[str, object], b: dict[str, object]) -> None:
    for field in _CONSENSUS_BLOCK_FIELDS:
        if a["block"][field] != b["block"][field]:
            raise _refuse(
                RefusalCode.NODE_DISAGREEMENT,
                f"providers disagree on block.{field}; no economic "
                "conclusion may rest on conflicting evidence",
            )
    if a["deploy_hash"] != b["deploy_hash"]:
        raise _refuse(
            RefusalCode.NODE_DISAGREEMENT, "providers disagree on the deploy hash"
        )
    if (
        a["execution"]["success"] != b["execution"]["success"]
        or a["execution"]["error_message"] != b["execution"]["error_message"]
    ):
        raise _refuse(
            RefusalCode.NODE_DISAGREEMENT,
            "providers disagree on the execution result",
        )
    if a["state_readback"] != b["state_readback"]:
        raise _refuse(
            RefusalCode.NODE_DISAGREEMENT,
            "providers disagree on the state readback",
        )


def _evaluate_expectation(
    observation: dict[str, object], expectation: dict[str, object]
) -> None:
    kind = expectation.get("type")
    if kind == "expected_success":
        require_finalized_membership(observation)
        execution = observation["execution"]
        if execution["success"] is not True or execution["error_message"] is not None:
            raise _refuse(
                RefusalCode.EXECUTION_FAILED,
                "execution failed where success is required",
            )
    elif kind == "expected_success_exact_target":
        evaluate_expected_success(
            observation,
            package_hash=str(expectation["package_hash"]),
            contract_hash=str(expectation["contract_hash"]),
            entry_point=expectation["entry_point"],
            typed_args=expectation["typed_args"],
        )
    elif kind == "prequorum_refusal":
        evaluate_expected_prequorum_refusal(
            observation,
            package_hash=str(expectation["package_hash"]),
            contract_hash=str(expectation["contract_hash"]),
            entry_point=expectation["entry_point"],
            typed_args=expectation["typed_args"],
            expected_error_message=str(expectation["error_message"]),
        )
    elif kind == "exact_refusal":
        # H (duplicate action) and the wrong-envelope proof: a finalized
        # failure whose error renders EXACTLY as expected.
        require_finalized_membership(observation)
        execution = observation["execution"]
        if execution["success"] is True:
            raise _refuse(
                RefusalCode.PREQUORUM_UNEXPECTED_SUCCESS,
                "refusal proof SUCCEEDED on chain; the invariant is broken "
                "or the observation is mislabelled",
            )
        if execution["error_message"] != expectation["error_message"]:
            raise _refuse(
                RefusalCode.WRONG_REFUSAL_CODE,
                "refusal proof does not carry the exact expected error",
            )
    elif kind == "native_transfer":
        evaluate_native_transfer_readback(
            observation,
            source_account=str(expectation["source_account"]),
            recipient_account=str(expectation["recipient_account"]),
            amount_motes=str(expectation["amount_motes"]),
            transfer_id=str(expectation["transfer_id"]),
        )
    elif kind == "state_readback":
        require_finalized_membership(observation)
        if observation["state_readback"] != expectation["state"]:
            raise _refuse(
                RefusalCode.READBACK_MISMATCH,
                "installed-state readback does not match the plan exactly",
            )
    else:
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED,
            f"unknown expectation type {kind!r}",
        )


def evaluate_dual_provider(
    observations: list[dict[str, object]],
    *,
    step_id: str,
    expectation: dict[str, object],
) -> dict[str, object]:
    """Exactly two disjoint providers, both validating the same expectation."""

    matches = [
        observation
        for observation in observations
        if isinstance(observation, dict) and observation.get("step_id") == step_id
    ]
    if len(matches) != 2:
        raise _refuse(
            RefusalCode.NODE_SET_INVALID,
            f"step {step_id} requires observations from exactly two "
            f"configured disjoint Mainnet providers (got {len(matches)}); "
            "single-source evidence is never sufficient",
        )
    validated = [validate_observation_v2(observation) for observation in matches]
    ids = {str(observation["provider"]["provider_id"]) for observation in validated}
    hosts = {str(observation["provider"]["endpoint_host"]) for observation in validated}
    if len(ids) != 2 or len(hosts) != 2:
        raise _refuse(
            RefusalCode.NODE_SET_INVALID,
            "the two observations do not come from disjoint providers",
        )
    _require_agreement(validated[0], validated[1])
    for observation in validated:
        _evaluate_expectation(observation, expectation)
    return {
        "step_id": step_id,
        "consensus_block_hash": validated[0]["block"]["block_hash"],
        "consensus_block_height": validated[0]["block"]["block_height"],
        "deploy_hash": validated[0]["deploy_hash"],
        "providers": sorted(ids),
        "raw_response_sha256s": sorted(
            str(observation["provider"]["response_sha256"]) for observation in validated
        ),
    }
