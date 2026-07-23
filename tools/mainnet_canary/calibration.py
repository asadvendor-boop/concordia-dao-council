"""Plan-bound Testnet calibration receipts (v2) — validation and conversion.

A calibration line is the ONLY permitted grounding for a Mainnet fee maximum.
v1 accepted any object carrying ``finalized: true``, a 64-hex deploy hash and
a positive ``payment_motes`` — sufficient to prove nothing.  v2 requires every
line to bind, per step:

- the final Mainnet canary plan hash and the Mainnet step's typed-arguments
  digest (recomputed here from the plan itself, never trusted);
- the corresponding Testnet deploy's runtime-arguments digest, which must
  DIFFER from the Mainnet digest — the network profiles are intentionally
  different and a byte-identical claim would be false;
- the documented network-profile translation: the exact argument names whose
  values differ, all of which must belong to the reviewed translation set;
- the signer identity, the Testnet chain identity, the target contract and
  the Wasm/source commit pins taken from the plan's RC section;
- the payment amount extracted from the actual deploy;
- the deploy hash, block hash and block height of the finalized execution
  result, which must match the plan step's expected outcome exactly
  (refusal-probe steps calibrate their REFUSALS, which also consume fees);
- a finality depth of at least :data:`FINALITY_CONFIRMATION_DEPTH` and two
  disjoint RPC observations of the same receipt.

The line-set must equal the plan's economic-step set EXACTLY — the set is
derived from the plan, never hard-coded, so a plan with ten economic steps
(the current threshold-three shape) demands exactly ten lines: no missing
line, no extra line.

``build_calibration_from_harness`` is the only sanctioned producer: it
converts verified Testnet harness observation documents into calibration
lines, computing every digest itself rather than accepting transcription.
"""

from __future__ import annotations

import hashlib
import json
import re

from tools.mainnet_canary.constants import MAINNET_CHAIN_NAME
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.finality_v2 import FINALITY_CONFIRMATION_DEPTH

CALIBRATION_SCHEMA_ID = "concordia.mainnet-canary.testnet-calibration.v2"
HARNESS_OBSERVATION_SCHEMA_ID = (
    "concordia.mainnet-canary.testnet-harness-observation.v1"
)
TESTNET_CHAIN_NAME = "casper-test"

_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")

# Argument names whose values are REVIEWED as legitimately different between
# the Testnet calibration deploy and the Mainnet canary deploy: network
# identity, dedicated per-network accounts, per-network nonces/identifiers
# derived from them, and amounts derived from the per-network treasury
# balance.  A value difference on any name OUTSIDE this set means the deploys
# are not exact equivalents and the calibration refuses.
REVIEWED_TRANSLATION_FIELDS = frozenset(
    {
        # network profile
        "casper_chain_name",
        "installation_nonce",
        # dedicated per-network identities
        "proposer",
        "finalizer",
        "signer_a",
        "signer_b",
        "signer_c",
        "source_account",
        "recipient_account",
        "target",
        # per-network proposal inputs and bound governance hashes
        "proposal_id",
        "proposal_nonce",
        "action_nonce",
        "proposal_hash",
        "policy_hash",
        "plan_hash",
        "final_card_hash",
        "dissent_hash",
        "agent_action_hash",
        "preauth_evidence_root",
        "authorized_metadata_root",
        # identifiers derived from the above
        "action_id",
        "transfer_id",
        "envelope_hash",
        "id",
        # amounts derived from the per-network treasury balance
        "amount_motes",
        "amount",
        "treasury_snapshot_balance_motes",
        "snapshot_block_hash",
        "snapshot_block_height",
    }
)

_LINE_FIELDS = {
    "mainnet_step_id",
    "mainnet_typed_args_sha256",
    "testnet_deploy_args_sha256",
    "network_profile_translation",
    "signer_public_key_hex",
    "target",
    "payment_motes",
    "receipt",
    "harness_artifact_sha256",
}
_TARGET_FIELDS = {"entry_point", "wasm_sha256", "source_commit"}
_RECEIPT_FIELDS = {
    "deploy_hash",
    "block_hash",
    "block_height",
    "execution",
    "finality",
    "observations",
}
_EXECUTION_FIELDS = {"success", "error_message"}
_FINALITY_FIELDS = {"chain_tip_height"}
_OBSERVATION_FIELDS = {"provider_id", "endpoint_host", "response_sha256"}
_HARNESS_FIELDS = {
    "schema_id",
    "step_id",
    "testnet_chain_name",
    "signer_public_key_hex",
    "entry_point",
    "wasm_sha256",
    "testnet_typed_args",
    "deploy_payment_motes",
    "deploy_hash",
    "block_hash",
    "block_height",
    "execution",
    "finality",
    "observations",
}

_PUBLIC_KEY = re.compile(r"0[12][0-9a-f]{64,66}\Z")


def _refuse(code: str, detail: str) -> CanaryRefusal:
    return CanaryRefusal(code, detail)


def typed_args_sha256(typed_args: object) -> str:
    """Canonical digest of a typed-argument list (same shape as the plan's)."""

    payload = json.dumps(typed_args, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def economic_step_ids(plan: dict[str, object]) -> list[str]:
    """The economic-step set is DERIVED from the plan, never hard-coded."""

    steps = plan.get("steps")
    if not isinstance(steps, list) or not steps:
        raise _refuse(RefusalCode.PLAN_INPUT_INVALID, "plan carries no steps")
    ids = [str(step["step_id"]) for step in steps if step.get("economic")]
    if len(ids) != len(set(ids)):
        raise _refuse(
            RefusalCode.PLAN_INPUT_INVALID, "plan economic step ids collide"
        )
    return ids


def _plan_step(plan: dict[str, object], step_id: str) -> dict[str, object]:
    for step in plan["steps"]:
        if str(step.get("step_id")) == step_id:
            return step
    raise _refuse(
        RefusalCode.PLAN_INPUT_INVALID, f"plan carries no step {step_id}"
    )


def _require_hex64(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _HEX64.match(value) is None:
        raise _refuse(
            RefusalCode.CALIBRATION_BINDING_INVALID,
            f"{field} must be 64 lowercase hex characters",
        )
    return value


def _require_exact_keys(
    mapping: object, expected: set[str], *, label: str
) -> dict[str, object]:
    if not isinstance(mapping, dict) or set(mapping) != expected:
        raise _refuse(
            RefusalCode.CALIBRATION_BINDING_INVALID,
            f"{label} must contain exactly {sorted(expected)}",
        )
    return mapping


def _validate_observations(entries: object, *, step_id: str) -> None:
    if not isinstance(entries, list) or len(entries) != 2:
        raise _refuse(
            RefusalCode.CALIBRATION_BINDING_INVALID,
            f"{step_id}: exactly two disjoint RPC observations are required",
        )
    providers, hosts = set(), set()
    for entry in entries:
        record = _require_exact_keys(
            entry, _OBSERVATION_FIELDS, label=f"{step_id} observation"
        )
        for field in ("provider_id", "endpoint_host"):
            if not isinstance(record[field], str) or not record[field]:
                raise _refuse(
                    RefusalCode.CALIBRATION_BINDING_INVALID,
                    f"{step_id}: observation {field} malformed",
                )
        _require_hex64(
            record["response_sha256"], field=f"{step_id}.response_sha256"
        )
        providers.add(record["provider_id"])
        hosts.add(record["endpoint_host"])
    if len(providers) != 2 or len(hosts) != 2:
        raise _refuse(
            RefusalCode.CALIBRATION_BINDING_INVALID,
            f"{step_id}: the two RPC observations are not disjoint",
        )


def _validate_line(
    plan: dict[str, object], step_id: str, line: object
) -> dict[str, object]:
    record = _require_exact_keys(line, _LINE_FIELDS, label=f"line {step_id}")
    step = _plan_step(plan, step_id)

    if record["mainnet_step_id"] != step_id:
        raise _refuse(
            RefusalCode.CALIBRATION_BINDING_INVALID,
            f"line {step_id} claims a different mainnet_step_id",
        )
    expected_digest = typed_args_sha256(step.get("typed_args"))
    if record["mainnet_typed_args_sha256"] != expected_digest:
        raise _refuse(
            RefusalCode.CALIBRATION_BINDING_INVALID,
            f"{step_id}: mainnet_typed_args_sha256 does not recompute from "
            "the plan step; the calibration is bound to some other plan",
        )
    testnet_digest = _require_hex64(
        record["testnet_deploy_args_sha256"],
        field=f"{step_id}.testnet_deploy_args_sha256",
    )
    if testnet_digest == expected_digest:
        raise _refuse(
            RefusalCode.CALIBRATION_BINDING_INVALID,
            f"{step_id}: Testnet and Mainnet argument digests are equal; "
            "the network profiles are intentionally different and a "
            "byte-identical claim is refused",
        )

    translation = record["network_profile_translation"]
    if (
        not isinstance(translation, dict)
        or not isinstance(translation.get("translated_fields"), list)
        or set(translation) != {"translated_fields"}
    ):
        raise _refuse(
            RefusalCode.CALIBRATION_BINDING_INVALID,
            f"{step_id}: network_profile_translation must document exactly "
            "its translated_fields",
        )
    translated = translation["translated_fields"]
    if not translated:
        raise _refuse(
            RefusalCode.CALIBRATION_BINDING_INVALID,
            f"{step_id}: an exact-equivalent Testnet deploy still differs on "
            "the network-profile fields; an empty translation is a "
            "byte-identical claim in disguise",
        )
    unreviewed = sorted(
        str(name)
        for name in translated
        if str(name) not in REVIEWED_TRANSLATION_FIELDS
    )
    if unreviewed:
        raise _refuse(
            RefusalCode.CALIBRATION_BINDING_INVALID,
            f"{step_id}: translation touches unreviewed fields {unreviewed}; "
            "the deploys are not exact equivalents",
        )

    signer = record["signer_public_key_hex"]
    if not isinstance(signer, str) or _PUBLIC_KEY.match(signer) is None:
        raise _refuse(
            RefusalCode.CALIBRATION_BINDING_INVALID,
            f"{step_id}: signer identity malformed",
        )

    target = _require_exact_keys(
        record["target"], _TARGET_FIELDS, label=f"{step_id} target"
    )
    if target["entry_point"] != step.get("entry_point"):
        raise _refuse(
            RefusalCode.CALIBRATION_BINDING_INVALID,
            f"{step_id}: calibration entry point does not equal the plan's",
        )
    rc = plan.get("rc", {})
    if str(step.get("kind")) == "contract_install":
        if target["wasm_sha256"] != rc.get("testnet_wasm_sha256"):
            raise _refuse(
                RefusalCode.CALIBRATION_BINDING_INVALID,
                f"{step_id}: install calibration must pin the RC's Testnet "
                "Wasm hash (the Mainnet build is a disjoint artifact)",
            )
    elif target["wasm_sha256"] is not None:
        raise _refuse(
            RefusalCode.CALIBRATION_BINDING_INVALID,
            f"{step_id}: only the install step carries a Wasm hash",
        )
    source_commit = target["source_commit"]
    if (
        not isinstance(source_commit, str)
        or _HEX40.match(source_commit) is None
        or source_commit != rc.get("peeled_commit_sha")
    ):
        raise _refuse(
            RefusalCode.CALIBRATION_BINDING_INVALID,
            f"{step_id}: calibration source commit does not equal the RC's "
            "peeled commit",
        )

    payment = record["payment_motes"]
    if (
        not isinstance(payment, str)
        or _DECIMAL.match(payment) is None
        or int(payment) <= 0
    ):
        raise _refuse(
            RefusalCode.CEILING_ARITHMETIC_INVALID,
            f"{step_id}: payment_motes must be a positive decimal extracted "
            "from the actual deploy",
        )

    receipt = _require_exact_keys(
        record["receipt"], _RECEIPT_FIELDS, label=f"{step_id} receipt"
    )
    _require_hex64(receipt["deploy_hash"], field=f"{step_id}.deploy_hash")
    _require_hex64(receipt["block_hash"], field=f"{step_id}.block_hash")
    height = receipt["block_height"]
    if not isinstance(height, int) or height < 0:
        raise _refuse(
            RefusalCode.CALIBRATION_BINDING_INVALID,
            f"{step_id}: block_height malformed",
        )

    execution = _require_exact_keys(
        receipt["execution"], _EXECUTION_FIELDS, label=f"{step_id} execution"
    )
    expected = step.get("expected_outcome", {})
    if expected.get("execution") == "failure":
        # Refusal-probe steps calibrate their REFUSALS: the Testnet deploy
        # must have finalized with the exact expected error, or the probe
        # choreography was wrong and its fee proves nothing.
        if execution["success"] is not False or execution[
            "error_message"
        ] != expected.get("exact_error_message"):
            raise _refuse(
                RefusalCode.CALIBRATION_BINDING_INVALID,
                f"{step_id}: refusal-probe calibration must carry the exact "
                "expected finalized error",
            )
    else:
        if execution["success"] is not True or execution["error_message"] is not None:
            raise _refuse(
                RefusalCode.CALIBRATION_BINDING_INVALID,
                f"{step_id}: calibration deploy did not succeed where the "
                "plan expects success",
            )

    finality = _require_exact_keys(
        receipt["finality"], _FINALITY_FIELDS, label=f"{step_id} finality"
    )
    tip = finality["chain_tip_height"]
    if not isinstance(tip, int) or tip - height < FINALITY_CONFIRMATION_DEPTH:
        raise _refuse(
            RefusalCode.INSUFFICIENT_CONFIRMATIONS,
            f"{step_id}: at least {FINALITY_CONFIRMATION_DEPTH} confirmations "
            "are required before a calibration receipt counts",
        )
    _validate_observations(receipt["observations"], step_id=step_id)
    _require_hex64(
        record["harness_artifact_sha256"],
        field=f"{step_id}.harness_artifact_sha256",
    )
    return record


def validate_calibration_document(
    plan: dict[str, object], calibration: object
) -> dict[str, dict[str, object]]:
    """Full v2 validation; returns the per-step validated lines."""

    if (
        not isinstance(calibration, dict)
        or calibration.get("schema_id") != CALIBRATION_SCHEMA_ID
        or not isinstance(calibration.get("lines"), dict)
    ):
        raise _refuse(
            RefusalCode.CALIBRATION_RECEIPT_ABSENT,
            f"calibration document does not match {CALIBRATION_SCHEMA_ID}",
        )
    if calibration.get("mainnet_plan_hash") != plan.get("canary_plan_sha256"):
        raise _refuse(
            RefusalCode.CALIBRATION_BINDING_INVALID,
            "calibration is bound to a different Mainnet plan hash",
        )
    if calibration.get("testnet_chain_name") != TESTNET_CHAIN_NAME:
        raise _refuse(
            RefusalCode.NETWORK_MISMATCH,
            f"calibration must be observed on {TESTNET_CHAIN_NAME}",
        )
    extra_top = set(calibration) - {
        "schema_id",
        "mainnet_plan_hash",
        "testnet_chain_name",
        "lines",
    }
    if extra_top:
        raise _refuse(
            RefusalCode.CALIBRATION_BINDING_INVALID,
            f"calibration carries unknown top-level fields {sorted(extra_top)}",
        )

    expected_ids = set(economic_step_ids(plan))
    supplied_ids = {str(step_id) for step_id in calibration["lines"]}
    missing = sorted(expected_ids - supplied_ids)
    extra = sorted(supplied_ids - expected_ids)
    if missing or extra:
        raise _refuse(
            RefusalCode.CALIBRATION_LINE_SET_MISMATCH,
            "calibration lines must equal the plan's economic steps exactly; "
            f"missing={missing} extra={extra}",
        )

    validated: dict[str, dict[str, object]] = {}
    for step_id in sorted(expected_ids):
        validated[step_id] = _validate_line(
            plan, step_id, calibration["lines"][step_id]
        )
    return validated


def _canonical_sha256(document: dict[str, object]) -> str:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_calibration_from_harness(
    plan: dict[str, object], harness_documents: list[dict[str, object]]
) -> dict[str, object]:
    """Convert verified Testnet harness observations into calibration lines.

    This is the only sanctioned producer of a calibration document: every
    digest is computed here from the plan and the harness artifacts, and the
    translated-field list is DERIVED by comparing the two argument lists —
    never transcribed by hand.  The result is re-validated before return.
    """

    by_step: dict[str, dict[str, object]] = {}
    for document in harness_documents:
        record = _require_exact_keys(
            document, _HARNESS_FIELDS, label="harness observation"
        )
        if record["schema_id"] != HARNESS_OBSERVATION_SCHEMA_ID:
            raise _refuse(
                RefusalCode.CALIBRATION_BINDING_INVALID,
                f"harness observation must be {HARNESS_OBSERVATION_SCHEMA_ID}",
            )
        if record["testnet_chain_name"] != TESTNET_CHAIN_NAME:
            raise _refuse(
                RefusalCode.NETWORK_MISMATCH,
                f"harness observation is not from {TESTNET_CHAIN_NAME}",
            )
        step_id = str(record["step_id"])
        if step_id in by_step:
            raise _refuse(
                RefusalCode.CALIBRATION_BINDING_INVALID,
                f"duplicate harness observation for step {step_id}",
            )
        by_step[step_id] = record

    rc = plan.get("rc", {})
    lines: dict[str, object] = {}
    for step_id in economic_step_ids(plan):
        harness = by_step.get(step_id)
        if harness is None:
            raise _refuse(
                RefusalCode.CALIBRATION_LINE_SET_MISMATCH,
                f"no harness observation exists for economic step {step_id}",
            )
        step = _plan_step(plan, step_id)
        plan_args = step.get("typed_args") or []
        testnet_args = harness["testnet_typed_args"]
        if not isinstance(testnet_args, list):
            raise _refuse(
                RefusalCode.CALIBRATION_BINDING_INVALID,
                f"{step_id}: harness typed args malformed",
            )
        plan_shape = [
            (arg.get("name"), arg.get("type")) for arg in plan_args
        ]
        testnet_shape = [
            (arg.get("name"), arg.get("type")) for arg in testnet_args
        ]
        if plan_shape != testnet_shape:
            raise _refuse(
                RefusalCode.CALIBRATION_BINDING_INVALID,
                f"{step_id}: Testnet deploy does not carry the identical "
                "argument names and types in the identical order; it is not "
                "an exact equivalent",
            )
        translated = [
            str(plan_arg.get("name"))
            for plan_arg, testnet_arg in zip(plan_args, testnet_args)
            if plan_arg.get("value") != testnet_arg.get("value")
        ]
        lines[step_id] = {
            "mainnet_step_id": step_id,
            "mainnet_typed_args_sha256": typed_args_sha256(plan_args),
            "testnet_deploy_args_sha256": typed_args_sha256(testnet_args),
            "network_profile_translation": {"translated_fields": translated},
            "signer_public_key_hex": harness["signer_public_key_hex"],
            "target": {
                "entry_point": harness["entry_point"],
                "wasm_sha256": harness["wasm_sha256"],
                "source_commit": rc.get("peeled_commit_sha"),
            },
            "payment_motes": harness["deploy_payment_motes"],
            "receipt": {
                "deploy_hash": harness["deploy_hash"],
                "block_hash": harness["block_hash"],
                "block_height": harness["block_height"],
                "execution": harness["execution"],
                "finality": harness["finality"],
                "observations": harness["observations"],
            },
            "harness_artifact_sha256": _canonical_sha256(harness),
        }

    document: dict[str, object] = {
        "schema_id": CALIBRATION_SCHEMA_ID,
        "mainnet_plan_hash": plan.get("canary_plan_sha256"),
        "testnet_chain_name": TESTNET_CHAIN_NAME,
        "lines": lines,
    }
    validate_calibration_document(plan, document)
    return document
