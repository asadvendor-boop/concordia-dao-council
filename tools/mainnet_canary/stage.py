"""Stage: content-addressed UNSIGNED transaction payloads only.

Staging re-runs every fail-closed gate (RC declaration, clean tree, Wasm,
identities, amount/recipient recomputation, snapshot freshness, fully
measured cost model within the human-approved ceiling) and then writes one
content-addressed unsigned-intent artifact per economic step.

The staged bytes are a canonical, versioned binary intent —
``CONCORDIA_MAINNET_CANARY_UNSIGNED_INTENT_V1\\0`` followed by canonical JSON
of the step — never a signed deploy.  Wire-format headers (timestamp, TTL,
payment) are chosen only inside the future authorized live lane, so signing
material never exists here and staged intents cannot go stale silently: the
signer must re-derive them from the same plan hash.

Stage also refuses to write anywhere below ``artifacts/`` — live canary
artifacts belong to the future live lane, and canonical namespaces are
protected outright.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from tools.mainnet_canary.constants import (
    MAINNET_CHAIN_NAME,
    PROTECTED_CANONICAL_PREFIXES,
)
from tools.mainnet_canary.cost_model import require_approved_estimate
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.journal import CanaryJournal
from tools.mainnet_canary.plan import (
    canonical_json,
    load_snapshot_observation,
    load_status_observation,
    plan_document_hash,
    require_fresh_snapshot,
)
from tools.mainnet_canary.rc_gate import validate_rc_gate

UNSIGNED_INTENT_DOMAIN = b"CONCORDIA_MAINNET_CANARY_UNSIGNED_INTENT_V1\x00"


def _require_plan(plan_document: dict[str, object]) -> str:
    expected = plan_document.get("canary_plan_sha256")
    recomputed = plan_document_hash(plan_document)
    if expected != recomputed:
        raise CanaryRefusal(
            RefusalCode.PLAN_HASH_MISMATCH,
            "plan document hash does not recompute; refusing to stage",
        )
    if plan_document.get("network", {}).get("chain_name") != MAINNET_CHAIN_NAME:
        raise CanaryRefusal(
            RefusalCode.NETWORK_MISMATCH, "plan is not for chain `casper`"
        )
    return str(expected)


def refuse_artifact_namespace_write(output_dir: Path, repo_root: Path) -> None:
    """The preparation lane may never create live/canonical artifacts."""

    try:
        relative = output_dir.resolve().relative_to(repo_root.resolve())
    except ValueError:
        return  # outside the repo is fine (operator-chosen scratch space)
    rel_text = str(relative) + "/"
    for prefix in PROTECTED_CANONICAL_PREFIXES:
        if rel_text.startswith(prefix):
            raise CanaryRefusal(
                RefusalCode.CANONICAL_NAMESPACE_PROTECTED,
                f"refusing to write below protected namespace {prefix}",
            )
    if rel_text.startswith("artifacts/"):
        raise CanaryRefusal(
            RefusalCode.LIVE_ARTIFACTS_UNAVAILABLE_IN_PREP,
            "live artifact generation is unavailable in the preparation "
            "lane; artifacts/mainnet-canary/** is created only by the "
            "future Codex-run live lane",
        )


def build_unsigned_intent(step: dict[str, object], *, plan_hash: str) -> bytes:
    """Canonical unsigned-intent bytes for one economic step."""

    intent = {
        "plan_hash": plan_hash,
        "step_id": step["step_id"],
        "kind": step["kind"],
        "chain_name": MAINNET_CHAIN_NAME,
        "signing_role": step["signing_role"],
        "signing_account_hash": step["signing_account_hash"],
        "entry_point": step["entry_point"],
        "typed_args": step["typed_args"],
        "expected_outcome": step["expected_outcome"],
    }
    return UNSIGNED_INTENT_DOMAIN + canonical_json(intent).encode("ascii")


def run_stage(
    repo_root: Path,
    *,
    plan_document: dict[str, object],
    rc_declaration_path: Path,
    snapshot_path: Path,
    status_path: Path,
    ceiling_path: Path | None,
    measured_costs_path: Path | None,
    journal_path: Path,
    output_dir: Path,
) -> dict[str, object]:
    """Re-validate everything, then persist unsigned intents + journal."""

    plan_hash = _require_plan(plan_document)
    rc = validate_rc_gate(repo_root, rc_declaration_path)
    if plan_document["rc"]["peeled_commit_sha"] != rc.peeled_commit_sha or (
        plan_document["rc"]["mainnet_wasm_sha256"] != rc.mainnet_wasm_sha256
    ):
        raise CanaryRefusal(
            RefusalCode.RC_COMMIT_MISMATCH,
            "plan was built against a different RC declaration",
        )

    snapshot = load_snapshot_observation(snapshot_path)
    status = load_status_observation(status_path)
    require_fresh_snapshot(snapshot, status)
    envelope_body = plan_document["envelope"]["body"]
    if (
        envelope_body["snapshot_block_hash"] != snapshot["block_hash"]
        or envelope_body["snapshot_block_height"] != snapshot["block_height"]
        or envelope_body["treasury_snapshot_balance_motes"]
        != snapshot["balance_motes"]
    ):
        raise CanaryRefusal(
            RefusalCode.STATE_ROOT_STALE,
            "plan snapshot no longer matches the supplied snapshot "
            "observation; re-plan against fresh state",
        )

    # Cost gate: refuses while any line is UNKNOWN or the ceiling is absent
    # or exceeded.  At the preparation base this always refuses.
    estimate = require_approved_estimate(
        repo_root,
        measured_costs_path=measured_costs_path,
        ceiling_path=ceiling_path,
    )

    refuse_artifact_namespace_write(output_dir, repo_root)
    output_dir.mkdir(parents=True, exist_ok=True)

    if journal_path.exists():
        journal = CanaryJournal.load(journal_path)
        if journal.plan_hash != plan_hash:
            raise CanaryRefusal(
                RefusalCode.PLAN_HASH_MISMATCH,
                "existing journal is bound to a different plan",
            )
        journal.require_no_in_flight(context="stage")
    else:
        journal = CanaryJournal.create(
            journal_path, plan_hash=plan_hash, rc_tag=rc.rc_tag
        )

    staged: list[dict[str, object]] = []
    for step in plan_document["steps"]:
        if not step["economic"]:
            continue
        step_id = str(step["step_id"])
        intent_bytes = build_unsigned_intent(step, plan_hash=plan_hash)
        content_address = hashlib.sha256(intent_bytes).hexdigest()
        intent_path = output_dir / f"{content_address}.unsigned-intent.bin"
        intent_path.write_bytes(intent_bytes)
        status_now = journal.step_status(step_id)
        if status_now is None:
            journal.transition(step_id, "PLANNED", plan_hash=plan_hash)
            journal.transition(
                step_id,
                "STAGED",
                plan_hash=plan_hash,
                detail=f"unsigned_intent_sha256={content_address}",
            )
        elif status_now.state == "PLANNED":
            journal.transition(
                step_id,
                "STAGED",
                plan_hash=plan_hash,
                detail=f"unsigned_intent_sha256={content_address}",
            )
        elif status_now.state != "STAGED":
            raise CanaryRefusal(
                RefusalCode.JOURNAL_CONFLICT,
                f"step {step_id} is already {status_now.state}; staging again "
                "is not a legal transition",
            )
        staged.append(
            {
                "step_id": step_id,
                "unsigned_intent_sha256": content_address,
                "unsigned_intent_path": str(intent_path),
                "signed": False,
            }
        )

    return {
        "schema_id": "concordia.mainnet-canary.stage-report.v1",
        "plan_hash": plan_hash,
        "rc_tag": rc.rc_tag,
        "staged_steps": staged,
        "cost_estimate": estimate,
        "journal_path": str(journal_path),
        "broadcast_enabled": False,
    }
