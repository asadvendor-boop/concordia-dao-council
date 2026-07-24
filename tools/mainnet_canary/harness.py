"""Testnet calibration harness for the plan-derived economic steps (blocker 4).

For every economic step the FINAL Mainnet plan derives, the harness runs the
exact-equivalent Testnet deploy through a fail-closed pipeline:

    prepare -> validate/dry-run -> explicit ``--submit`` -> reconcile by the
    ORIGINAL deploy hash -> dual-node depth>=FINALITY_CONFIRMATION_DEPTH
    observation -> harness observation document

- **prepare**: derives the expected Testnet deploy spec from the plan step —
  same entry point, same argument names/types/order; only reviewed
  network-profile fields may differ in value.
- **validate/dry-run**: imports the externally wallet-signed Testnet deploy
  bytes and validates them against the spec via the same generic boundary as
  the live lane (:mod:`tools.mainnet_canary.submission`) with
  ``casper-test`` as the pinned chain.  No submission happens.
- **submit**: only with ``submit=True`` — journal-backed, exactly-once, the
  recomputed deploy hash persisted before the single broadcast.
- **reconcile**: by the original journal hash through the injected read-only
  transport.
- **observe**: the dual-node collector captures raw evidence from two
  disjoint Testnet providers; depth is measured, not asserted.
- **emit**: one ``testnet-harness-observation.v2`` document whose fields are
  DERIVED from the raw evidence, ready for
  :func:`tools.mainnet_canary.calibration.build_calibration_from_harness`.

Everything reuses the accepted transport/encoding/crypto helpers; nothing
here reimplements cryptography or handles a private key.
"""

from __future__ import annotations

from pathlib import Path

from tools.mainnet_canary.calibration import (
    HARNESS_OBSERVATION_SCHEMA_ID,
    TESTNET_CHAIN_NAME,
    economic_step_ids,
)
from tools.mainnet_canary.collector import ReadCall, collect_dual_observations
from tools.mainnet_canary.constants import FINALITY_CONFIRMATION_DEPTH
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.journal import CanaryJournal
from tools.mainnet_canary.submission import (
    SubmissionTransport,
    load_signed_deploy_bytes,
    reconcile_step,
    submit_step_exactly_once,
    validate_signed_step_deploy,
)


def _refuse(code: str, detail: str) -> CanaryRefusal:
    return CanaryRefusal(code, detail)


def _plan_step(plan: dict[str, object], step_id: str) -> dict[str, object]:
    for step in plan.get("steps", []):
        if str(step.get("step_id")) == step_id:
            return step
    raise _refuse(
        RefusalCode.PLAN_INPUT_INVALID, f"plan carries no step {step_id}"
    )


def prepare_harness_step(
    plan: dict[str, object], *, step_id: str
) -> dict[str, object]:
    """The expected Testnet deploy spec, derived from the plan step itself."""

    if step_id not in economic_step_ids(plan):
        raise _refuse(
            RefusalCode.CALIBRATION_LINE_SET_MISMATCH,
            f"step {step_id} is not one of the plan-derived economic steps; "
            "the harness calibrates exactly that set",
        )
    step = _plan_step(plan, step_id)
    plan_args = step.get("typed_args") or []
    return {
        "step_id": step_id,
        "kind": step.get("kind"),
        "testnet_chain_name": TESTNET_CHAIN_NAME,
        "entry_point": step.get("entry_point"),
        "argument_shape": [
            {"name": arg.get("name"), "type": arg.get("type")}
            for arg in plan_args
        ],
        "expected_outcome": step.get("expected_outcome"),
    }


def dry_run_harness_step(
    plan: dict[str, object],
    *,
    step_id: str,
    signed_deploy_path: Path,
    testnet_step: dict[str, object],
    max_payment_motes: int,
) -> dict[str, object]:
    """Validate the wallet-signed Testnet bytes without submitting.

    ``testnet_step`` is the Testnet-profile rendering of the plan step (same
    shape, per-network values).  Its argument names/order must equal the
    Mainnet step's — the exact-equivalence contract that calibration later
    re-checks value-by-value.
    """

    spec = prepare_harness_step(plan, step_id=step_id)
    mainnet_shape = spec["argument_shape"]
    testnet_args = testnet_step.get("typed_args") or []
    testnet_shape = [
        {"name": arg.get("name"), "type": arg.get("type")}
        for arg in testnet_args
    ]
    if testnet_shape != mainnet_shape:
        raise _refuse(
            RefusalCode.CALIBRATION_BINDING_INVALID,
            f"{step_id}: the Testnet deploy's argument names/types/order do "
            "not equal the Mainnet plan step's; it is not an exact "
            "equivalent",
        )
    raw = load_signed_deploy_bytes(signed_deploy_path)
    facts = validate_signed_step_deploy(
        raw,
        step=testnet_step,
        max_payment_motes=max_payment_motes,
        expected_chain_name=TESTNET_CHAIN_NAME,
    )
    return {"facts": facts, "signed_bytes": raw, "spec": spec}


def run_harness_step(
    plan: dict[str, object],
    *,
    step_id: str,
    signed_deploy_path: Path,
    testnet_step: dict[str, object],
    max_payment_motes: int,
    journal_path: Path,
    submit: bool,
    transport: SubmissionTransport | None = None,
    observation_calls: dict[str, ReadCall] | None = None,
    observation_hosts: dict[str, str] | None = None,
    retrieved_at_unix: int = 0,
) -> dict[str, object]:
    """prepare → dry-run → (submit → reconcile → observe → emit)."""

    dry = dry_run_harness_step(
        plan,
        step_id=step_id,
        signed_deploy_path=signed_deploy_path,
        testnet_step=testnet_step,
        max_payment_motes=max_payment_motes,
    )
    if not submit:
        return {
            "step_id": step_id,
            "action": "dry-run",
            "deploy_hash": dry["facts"]["deploy_hash_hex"],
            "signed_bytes_sha256": dry["facts"]["signed_bytes_sha256"],
            "submitted": False,
        }
    if transport is None or observation_calls is None or observation_hosts is None:
        raise _refuse(
            RefusalCode.SUBMISSION_TRANSPORT_INVALID,
            "submit requires the pinned transport and two observation "
            "providers",
        )

    plan_hash = str(plan.get("canary_plan_sha256"))
    submit_step_exactly_once(
        journal_path=journal_path,
        plan_hash=plan_hash,
        step=testnet_step,
        signed_bytes=dry["signed_bytes"],
        facts=dry["facts"],
        transport=transport,
    )
    reconciliation = reconcile_step(
        journal_path=journal_path,
        plan_hash=plan_hash,
        step_id=step_id,
        transport=transport,
    )
    deploy_hash = str(reconciliation["deploy_hash"])

    observations = collect_dual_observations(
        observation_calls,
        hosts=observation_hosts,
        step_id=step_id,
        deploy_hash=deploy_hash,
        retrieved_at_unix=retrieved_at_unix,
        target={
            "package_hash": None,
            "contract_hash": None,
            "entry_point": testnet_step.get("entry_point"),
            "typed_args": None,
            "transfer": None,
        },
        state_readback=None,
    )
    return emit_harness_observation(
        plan,
        step_id=step_id,
        testnet_step=testnet_step,
        facts=dry["facts"],
        observations=observations,
    )


def emit_harness_observation(
    plan: dict[str, object],
    *,
    step_id: str,
    testnet_step: dict[str, object],
    facts: dict[str, object],
    observations: list[dict[str, object]],
) -> dict[str, object]:
    """One harness observation document, derived from the raw evidence."""

    if len(observations) != 2:
        raise _refuse(
            RefusalCode.NODE_SET_INVALID,
            f"{step_id}: exactly two provider observations are required",
        )
    providers = []
    blocks = set()
    heights = set()
    executions = set()
    tips = []
    for observation in observations:
        block = observation.get("block")
        execution = observation.get("execution")
        provider = observation.get("provider")
        if (
            not isinstance(block, dict)
            or not isinstance(execution, dict)
            or not isinstance(provider, dict)
        ):
            raise _refuse(
                RefusalCode.OBSERVATION_MALFORMED,
                f"{step_id}: collected observation malformed",
            )
        if observation.get("deploy_hash") != facts["deploy_hash_hex"]:
            raise _refuse(
                RefusalCode.RAW_EVIDENCE_MISMATCH,
                f"{step_id}: observation is for a different deploy",
            )
        blocks.add(block.get("block_hash"))
        heights.add(block.get("block_height"))
        executions.add(
            (execution.get("success"), execution.get("error_message"))
        )
        tips.append(int(provider.get("chain_tip_height", -1)))
        providers.append(provider)
    if len(blocks) != 1 or len(heights) != 1 or len(executions) != 1:
        raise _refuse(
            RefusalCode.NODE_DISAGREEMENT,
            f"{step_id}: the two providers disagree on the receipt",
        )
    (block_hash,) = blocks
    (height,) = heights
    ((success, error_message),) = executions
    min_tip = min(tips)
    if min_tip - int(height) < FINALITY_CONFIRMATION_DEPTH:
        raise _refuse(
            RefusalCode.INSUFFICIENT_CONFIRMATIONS,
            f"{step_id}: measured depth is below "
            f"{FINALITY_CONFIRMATION_DEPTH}",
        )
    return {
        "schema_id": HARNESS_OBSERVATION_SCHEMA_ID,
        "step_id": step_id,
        "testnet_chain_name": TESTNET_CHAIN_NAME,
        "signer_public_key_hex": testnet_step.get("signer_public_key_hex"),
        "entry_point": testnet_step.get("entry_point"),
        "wasm_sha256": testnet_step.get("wasm_sha256"),
        "testnet_typed_args": testnet_step.get("typed_args"),
        "deploy_payment_motes": str(facts["payment_amount_motes"]),
        "deploy_hash": facts["deploy_hash_hex"],
        "block_hash": block_hash,
        "block_height": height,
        "execution": {"success": success, "error_message": error_message},
        "finality": {"chain_tip_height": min_tip},
        "observations": providers,
    }


def require_journal_covers_economic_steps(
    journal_path: Path, plan: dict[str, object]
) -> None:
    """Every plan-derived economic step must be terminally journaled."""

    terminal = {
        "CONFIRMED_FINALIZED",
        "FAILED_FINALIZED",
        "RECONCILED_CONFIRMED",
        "RECONCILED_FAILED",
    }
    journal = CanaryJournal.load(journal_path)
    try:
        for step_id in economic_step_ids(plan):
            status = journal.step_status(step_id)
            if status is None or status.state not in terminal:
                raise _refuse(
                    RefusalCode.RECONCILIATION_REQUIRED,
                    f"step {step_id} is not terminally reconciled in the "
                    "harness journal",
                )
    finally:
        journal.close()
