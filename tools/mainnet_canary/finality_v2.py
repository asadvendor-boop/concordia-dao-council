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

from tools.mainnet_canary.constants import (
    FINALITY_CONFIRMATION_DEPTH,
    MAINNET_CHAIN_NAME,
)
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.raw_evidence import require_rederived_agreement
from tools.mainnet_canary.verify import (
    evaluate_expected_prequorum_refusal,
    evaluate_expected_success,
    evaluate_native_transfer_readback,
    require_finalized_membership,
)

OBSERVATION_V3_SCHEMA_ID = "concordia.mainnet-canary.step-observation.v3"

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
    # Each provider must state the chain tip it saw, so confirmation depth is
    # a MEASURED quantity rather than a constant nobody consults.
    "chain_tip_height",
    # Correction round (blocker 2): the raw bounded JSON-RPC exchanges are
    # part of the evidence itself; digests alone are transcription.
    "raw_exchanges",
}
# Blocker 5: nested structures are validated with exact key sets BEFORE any
# indexing, so malformed input returns a stable refusal, never a KeyError.
_REQUIRED_BLOCK = {
    "status",
    "block_hash",
    "block_height",
    "state_root_hash",
    "era_id",
    "block_proofs_present",
    "deploy_is_member",
}
_REQUIRED_EXECUTION = {"success", "error_message", "cost_motes"}
_REQUIRED_TARGET = {
    "package_hash",
    "contract_hash",
    "entry_point",
    "typed_args",
    "transfer",
}


def _refuse(code: str, detail: str) -> CanaryRefusal:
    return CanaryRefusal(code, detail)


def _require_exact_keys(
    mapping: object, expected: set[str], *, label: str
) -> dict[str, object]:
    if not isinstance(mapping, dict) or set(mapping) != expected:
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED,
            f"{label} must contain exactly {sorted(expected)}",
        )
    return mapping


def _validate_block_structure(block: object) -> dict[str, object]:
    record = _require_exact_keys(block, _REQUIRED_BLOCK, label="block")
    if record["status"] not in ("finalized", "pending"):
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED,
            "block.status must be `finalized` or `pending`",
        )
    for field in ("block_hash", "state_root_hash"):
        value = record[field]
        if not isinstance(value, str) or _HEX64.match(value) is None:
            raise _refuse(
                RefusalCode.OBSERVATION_MALFORMED,
                f"block.{field} must be 64 lowercase hex characters",
            )
    if not isinstance(record["block_height"], int) or record["block_height"] < 0:
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED,
            "block.block_height must be a non-negative integer",
        )
    if not isinstance(record["era_id"], int) or record["era_id"] < 0:
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED,
            "block.era_id must be a non-negative integer",
        )
    for field in ("block_proofs_present", "deploy_is_member"):
        if not isinstance(record[field], bool):
            raise _refuse(
                RefusalCode.OBSERVATION_MALFORMED,
                f"block.{field} must be a boolean",
            )
    return record


def _validate_execution_structure(execution: object) -> dict[str, object]:
    record = _require_exact_keys(
        execution, _REQUIRED_EXECUTION, label="execution"
    )
    if not isinstance(record["success"], bool):
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED,
            "execution.success must be a boolean",
        )
    message = record["error_message"]
    if message is not None and not isinstance(message, str):
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED,
            "execution.error_message must be null or a string",
        )
    cost = record["cost_motes"]
    if cost is not None and (
        not isinstance(cost, str) or not cost or not cost.isdigit()
    ):
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED,
            "execution.cost_motes must be null or a decimal motes string",
        )
    return record


def validate_observation_v3(document: object) -> dict[str, object]:
    """Structural + raw-evidence validation of one provider observation."""

    if not isinstance(document, dict) or set(document) != _REQUIRED_TOP:
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED,
            f"v3 observation must contain exactly {sorted(_REQUIRED_TOP)}",
        )
    if document["schema_id"] != OBSERVATION_V3_SCHEMA_ID:
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED,
            f"schema_id must equal {OBSERVATION_V3_SCHEMA_ID}",
        )
    deploy_hash = document["deploy_hash"]
    if not isinstance(deploy_hash, str) or _HEX64.match(deploy_hash) is None:
        raise _refuse(RefusalCode.OBSERVATION_MALFORMED, "deploy_hash must be 64 hex")
    if document["chain_name_observed"] != MAINNET_CHAIN_NAME:
        raise _refuse(
            RefusalCode.NETWORK_MISMATCH, "observation is not from chain `casper`"
        )
    block = _validate_block_structure(document["block"])
    execution = _validate_execution_structure(document["execution"])
    _require_exact_keys(document["target"], _REQUIRED_TARGET, label="target")

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
    tip = provider["chain_tip_height"]
    block_height = block["block_height"]
    if not isinstance(tip, int) or tip < 0:
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED,
            "provider.chain_tip_height must be a non-negative integer",
        )
    # FINALITY_CONFIRMATION_DEPTH is an enforced measurement: belt-and-braces
    # on top of Casper's per-block finality signatures.
    if tip - block_height < FINALITY_CONFIRMATION_DEPTH:
        raise _refuse(
            RefusalCode.INSUFFICIENT_CONFIRMATIONS,
            f"block is {tip - block_height} confirmations deep; "
            f"{FINALITY_CONFIRMATION_DEPTH} are required before an economic "
            "conclusion may rest on it",
        )
    # Blocker 2: the recorded fields above are CLAIMS.  Every binding —
    # deploy hash, block identity, membership, execution result, chain tip —
    # is now independently re-derived from the embedded raw RPC bodies.
    require_rederived_agreement(
        provider,
        label=f"observation[{document['step_id']}][{provider['provider_id']}]",
        expected_chain_name=MAINNET_CHAIN_NAME,
        deploy_hash=deploy_hash,
        block_hash=str(block["block_hash"]),
        block_height=block_height,
        execution_success=execution["success"],
        execution_error_message=execution["error_message"],
        era_id=int(block["era_id"]),
        state_root_hash=str(block["state_root_hash"]),
        require_proofs=bool(block["block_proofs_present"]),
        require_membership=bool(block["deploy_is_member"]),
        observed_target=document["target"]
        if isinstance(document.get("target"), dict)
        else None,
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
    validated = [validate_observation_v3(observation) for observation in matches]
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
