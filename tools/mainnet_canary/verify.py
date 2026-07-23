"""Fail-closed evaluation of read-only public Mainnet RPC observations.

Verification consumes observation documents captured from the pinned public
RPC endpoint (credential-free reads only) and compares them against the
staged plan.  Everything unexpected refuses:

- unsigned/malformed/pending block proof, missing transaction membership;
- execution error where success is expected, or success where the exact
  pre-quorum ``QuorumNotMet`` refusal is expected;
- wrong contract/package, entry point, typed args, action/envelope/transfer
  identifiers, recipient, amount, or ambiguous duplicates.

A pre-quorum deploy is positive proof only when the exact expected
``QuorumNotMet`` error is finalized on-chain.  In the preparation lane no
observation exists, so ``verify`` refuses with ``OBSERVATION_ABSENT`` and
every claim field remains BLOCKED_PENDING_LIVE_PROOF.
"""

from __future__ import annotations

import re

from tools.mainnet_canary.constants import MAINNET_CHAIN_NAME
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode

OBSERVATION_SCHEMA_ID = "concordia.mainnet-canary.step-observation.v1"

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")

_REQUIRED_TOP = {
    "schema_id",
    "step_id",
    "deploy_hash",
    "chain_name_observed",
    "block",
    "execution",
    "target",
}
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


def validate_observation(document: object) -> dict[str, object]:
    """Structural validation of one step observation; fail closed."""

    observation = _require_exact_keys(document, _REQUIRED_TOP, label="observation")
    if observation["schema_id"] != OBSERVATION_SCHEMA_ID:
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED,
            f"schema_id must equal {OBSERVATION_SCHEMA_ID}",
        )
    deploy_hash = observation["deploy_hash"]
    if not isinstance(deploy_hash, str) or _HEX64.match(deploy_hash) is None:
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED, "deploy_hash must be 64 hex"
        )
    if observation["chain_name_observed"] != MAINNET_CHAIN_NAME:
        raise _refuse(
            RefusalCode.NETWORK_MISMATCH,
            "observation is not from chain `casper`",
        )
    _require_exact_keys(observation["block"], _REQUIRED_BLOCK, label="block")
    _require_exact_keys(
        observation["execution"], _REQUIRED_EXECUTION, label="execution"
    )
    _require_exact_keys(observation["target"], _REQUIRED_TARGET, label="target")
    return observation


def require_finalized_membership(observation: dict[str, object]) -> None:
    """Block proof: finalized, signed, and containing the deploy."""

    block = observation["block"]
    status = block["status"]
    if status == "pending":
        raise _refuse(
            RefusalCode.PROOF_PENDING, "block/deploy execution still pending"
        )
    if status != "finalized":
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED,
            "block status must be `finalized` or `pending`",
        )
    if block["block_proofs_present"] is not True:
        raise _refuse(
            RefusalCode.PROOF_UNSIGNED,
            "block evidence carries no finality signatures/proofs",
        )
    block_hash = block["block_hash"]
    state_root = block["state_root_hash"]
    if (
        not isinstance(block_hash, str)
        or _HEX64.match(block_hash) is None
        or not isinstance(state_root, str)
        or _HEX64.match(state_root) is None
        or not isinstance(block["block_height"], int)
        or block["block_height"] < 0
        or not isinstance(block["era_id"], int)
    ):
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED, "block identity fields malformed"
        )
    if block["deploy_is_member"] is not True:
        raise _refuse(
            RefusalCode.PROOF_NOT_MEMBER,
            "deploy is not a member of the finalized block body",
        )


def _require_target(
    observation: dict[str, object],
    *,
    package_hash: str,
    contract_hash: str,
    entry_point: str,
    typed_args: dict[str, object],
) -> None:
    target = observation["target"]
    if target["package_hash"] != package_hash or target["contract_hash"] != (
        contract_hash
    ):
        raise _refuse(
            RefusalCode.WRONG_CONTRACT,
            "observed package/contract does not match the plan",
        )
    if target["entry_point"] != entry_point:
        raise _refuse(
            RefusalCode.WRONG_ENTRY_POINT,
            "observed entry point does not match the plan",
        )
    if target["typed_args"] != typed_args:
        raise _refuse(
            RefusalCode.WRONG_TYPED_ARGS,
            "observed typed arguments do not match the plan exactly",
        )


def evaluate_expected_success(
    observation: dict[str, object],
    *,
    package_hash: str,
    contract_hash: str,
    entry_point: str,
    typed_args: dict[str, object],
) -> None:
    """Finalized, successful, exact-target execution — anything else refuses."""

    require_finalized_membership(observation)
    _require_target(
        observation,
        package_hash=package_hash,
        contract_hash=contract_hash,
        entry_point=entry_point,
        typed_args=typed_args,
    )
    execution = observation["execution"]
    if execution["success"] is not True or execution["error_message"] is not None:
        raise _refuse(
            RefusalCode.EXECUTION_FAILED,
            "execution failed where success is required",
        )


def evaluate_expected_prequorum_refusal(
    observation: dict[str, object],
    *,
    package_hash: str,
    contract_hash: str,
    entry_point: str,
    typed_args: dict[str, object],
    expected_error_message: str,
) -> None:
    """Positive proof ONLY for the exact finalized ``QuorumNotMet`` refusal."""

    require_finalized_membership(observation)
    _require_target(
        observation,
        package_hash=package_hash,
        contract_hash=contract_hash,
        entry_point=entry_point,
        typed_args=typed_args,
    )
    execution = observation["execution"]
    if execution["success"] is True:
        raise _refuse(
            RefusalCode.PREQUORUM_UNEXPECTED_SUCCESS,
            "pre-quorum finalization SUCCEEDED; quorum enforcement is broken "
            "or the observation is mislabelled",
        )
    if execution["error_message"] != expected_error_message:
        raise _refuse(
            RefusalCode.WRONG_REFUSAL_CODE,
            "pre-quorum refusal is not the exact expected QuorumNotMet error",
        )


def evaluate_native_transfer_readback(
    observation: dict[str, object],
    *,
    source_account: str,
    recipient_account: str,
    amount_motes: str,
    transfer_id: str,
) -> None:
    """`Money moved` proof: finalized transfer with exact bound identity."""

    require_finalized_membership(observation)
    execution = observation["execution"]
    if execution["success"] is not True or execution["error_message"] is not None:
        raise _refuse(
            RefusalCode.EXECUTION_FAILED, "native transfer did not succeed"
        )
    transfer = observation["target"]["transfer"]
    expected = {
        "source_account": source_account,
        "recipient_account": recipient_account,
        "amount_motes": amount_motes,
        "transfer_id": transfer_id,
    }
    if not isinstance(transfer, dict) or set(transfer) != set(expected):
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED,
            f"transfer readback must contain exactly {sorted(expected)}",
        )
    mismatched = sorted(
        field for field, value in expected.items() if transfer[field] != value
    )
    if mismatched:
        raise _refuse(
            RefusalCode.TRANSFER_MISMATCH,
            f"transfer readback mismatch on: {mismatched}",
        )
    if _DECIMAL.match(str(transfer["amount_motes"])) is None:
        raise _refuse(
            RefusalCode.OBSERVATION_MALFORMED, "transfer amount malformed"
        )


def evaluate_step_observations(
    observations: list[dict[str, object]], *, step_id: str
) -> dict[str, object]:
    """Select exactly one observation for a step; duplicates are ambiguous."""

    matches = [
        observation
        for observation in observations
        if observation.get("step_id") == step_id
    ]
    if not matches:
        raise _refuse(
            RefusalCode.OBSERVATION_ABSENT,
            f"no observation captured for step {step_id}",
        )
    if len(matches) > 1:
        raise _refuse(
            RefusalCode.AMBIGUOUS_RESULT,
            f"multiple observations claim step {step_id}; refusing to choose",
        )
    return validate_observation(matches[0])
