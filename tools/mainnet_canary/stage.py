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
import json
from pathlib import Path

from tools.mainnet_canary.constants import (
    MAINNET_CHAIN_NAME,
    PROTECTED_CANONICAL_PREFIXES,
)
from tools.mainnet_canary.attestation import (
    RC_ATTESTATION_SCHEMA_ID,
    require_disjoint_network_artifacts,
    verify_declared_artifact_hash,
)
from tools.mainnet_canary.cost_model import require_approved_estimate
from tools.mainnet_canary.economic_manifest import (
    build_economic_manifest,
    require_within_authorization,
    validate_human_authorization,
)
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.journal import CanaryJournal
from tools.mainnet_canary.path_policy import CanaryPathPolicy
from tools.mainnet_canary.plan import (
    canonical_json,
    load_snapshot_observation,
    load_status_observation,
    plan_document_hash,
    require_corroborated_snapshot,
    require_fresh_snapshot,
)
from tools.mainnet_canary.rc_gate import validate_rc_gate
from tools.mainnet_canary.secret_guard import refuse_if_secret_material

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


def _load_json(path: Path, *, context: str, code: str) -> dict[str, object]:
    if not path.is_file():
        raise CanaryRefusal(code, f"{context} is not present at {path.name}")
    raw = path.read_text(encoding="utf-8")
    refuse_if_secret_material(raw, context=context)
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CanaryRefusal(code, f"{context} is not valid JSON") from exc
    if not isinstance(document, dict):
        raise CanaryRefusal(code, f"{context} must be a JSON object")
    return document


def require_build_attestation(
    attestation_path: Path, *, rc_mainnet_wasm_sha256: str
) -> dict[str, object]:
    """The declared Mainnet Wasm must be backed by a double-built artifact.

    Puts :mod:`tools.mainnet_canary.attestation` on the enforcement path: a
    hash asserted in the RC declaration is worthless unless some reproducible
    build actually produced it, and the Mainnet artifact must be disjoint from
    the Testnet one (a `casper-test`-chained Wasm cannot initialise on
    Mainnet).
    """

    document = _load_json(
        attestation_path,
        context="build-attestation",
        code=RefusalCode.ARTIFACT_HASH_UNBACKED,
    )
    pair = document.get("network_artifacts")
    if not isinstance(pair, dict):
        raise CanaryRefusal(
            RefusalCode.ARTIFACT_HASH_UNBACKED,
            "attestation must carry `network_artifacts` for both profiles",
        )
    testnet = pair.get("testnet")
    mainnet = pair.get("mainnet-native")
    for label, entry in (("testnet", testnet), ("mainnet-native", mainnet)):
        if (
            not isinstance(entry, dict)
            or entry.get("schema_id") != RC_ATTESTATION_SCHEMA_ID
            or entry.get("builds") != 2
        ):
            raise CanaryRefusal(
                RefusalCode.ARTIFACT_HASH_UNBACKED,
                f"{label} attestation is absent or was not double-built",
            )
    require_disjoint_network_artifacts(testnet, mainnet)
    verify_declared_artifact_hash(mainnet, rc_mainnet_wasm_sha256)
    return document


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
    attestation_path: Path,
    calibration_path: Path,
    authorization_path: Path,
    clock_unix: int,
    snapshot_corroboration_path: Path,
    pinned_authorizer_keys: frozenset[str] | set[str],
    operator_ceilings_path: Path | None = None,
) -> dict[str, object]:
    """Re-validate everything, then persist unsigned intents + journal.

    Every safety module is on THIS path, not merely unit-tested beside it:
    the RC gate, the reproducible-build attestation, the plan-derived
    economic manifest, the signed human authorization, the durable journal,
    and the output path policy each gate staging and each fails closed.
    """

    plan_hash = _require_plan(plan_document)
    rc = validate_rc_gate(repo_root, rc_declaration_path)
    attestation = require_build_attestation(
        attestation_path, rc_mainnet_wasm_sha256=rc.mainnet_wasm_sha256
    )
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
    # The transfer amount is derived from this balance, so the balance must
    # be independently sourced rather than asserted by one file.
    require_corroborated_snapshot(
        snapshot,
        _load_json(
            snapshot_corroboration_path,
            context="treasury-snapshot-corroboration",
            code=RefusalCode.SNAPSHOT_NOT_CORROBORATED,
        ),
    )
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

    # Economic manifest v2: cost lines derived 1:1 from THIS plan's economic
    # steps, with the transfer principal inside a checked total, every fee
    # maximum grounded in a finalized calibration receipt or an explicit
    # operator ceiling, and the whole thing bound to a signed human
    # authorization that has not expired against the trusted clock.
    calibration = _load_json(
        calibration_path,
        context="testnet-calibration",
        code=RefusalCode.CALIBRATION_RECEIPT_ABSENT,
    )
    operator_ceilings: dict[str, object] = {}
    if operator_ceilings_path is not None:
        operator_ceilings = _load_json(
            operator_ceilings_path,
            context="operator-ceilings",
            code=RefusalCode.CALIBRATION_RECEIPT_ABSENT,
        )
    manifest = build_economic_manifest(
        plan_document, calibration=calibration, operator_ceilings=operator_ceilings
    )
    authorization = validate_human_authorization(
        _load_json(
            authorization_path,
            context="human-authorization",
            code=RefusalCode.AUTHORIZATION_INVALID,
        ),
        manifest=manifest,
        clock_unix=clock_unix,
        pinned_authorizer_keys=pinned_authorizer_keys,
    )
    require_within_authorization(manifest, authorization)

    refuse_artifact_namespace_write(output_dir, repo_root)
    # Every staged output resolves through the centralized path policy; the
    # preparation lane never authorizes live capture, so the output root must
    # live outside the repository.
    canary_id = plan_hash[:24] + "-prep"
    path_policy = CanaryPathPolicy(
        repo_root, output_dir, canary_id=canary_id, live_capture_authorized=False
    )

    if journal_path.exists():
        journal = CanaryJournal.load(journal_path)
        if journal.plan_hash != plan_hash:
            journal.close()
            raise CanaryRefusal(
                RefusalCode.PLAN_HASH_MISMATCH,
                "existing journal is bound to a different plan",
            )
    else:
        journal = CanaryJournal.create(
            journal_path, plan_hash=plan_hash, rc_tag=rc.rc_tag
        )

    try:
        journal.require_no_in_flight(context="stage")
        staged: list[dict[str, object]] = []
        for step in plan_document["steps"]:
            if not step["economic"]:
                continue
            step_id = str(step["step_id"])
            intent_bytes = build_unsigned_intent(step, plan_hash=plan_hash)
            content_address = hashlib.sha256(intent_bytes).hexdigest()
            intent_path = path_policy.exclusive_write_bytes(
                f"{content_address}.unsigned-intent.bin", intent_bytes
            )
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
                    f"step {step_id} is already {status_now.state}; staging "
                    "again is not a legal transition",
                )
            staged.append(
                {
                    "step_id": step_id,
                    "unsigned_intent_sha256": content_address,
                    "unsigned_intent_path": str(intent_path),
                    "signed": False,
                }
            )
    finally:
        journal.close()

    return {
        "schema_id": "concordia.mainnet-canary.stage-report.v1",
        "plan_hash": plan_hash,
        "rc_tag": rc.rc_tag,
        "staged_steps": staged,
        "cost_estimate": estimate,
        "economic_manifest": manifest,
        "human_authorization_nonce": authorization["nonce"],
        "build_attestation": {
            "testnet_wasm_sha256": attestation["network_artifacts"]["testnet"][
                "wasm_sha256"
            ],
            "mainnet_wasm_sha256": attestation["network_artifacts"][
                "mainnet-native"
            ]["wasm_sha256"],
            "double_built": True,
        },
        "journal_path": str(journal_path),
        "path_policy": {
            "canary_id": canary_id,
            "live_capture_authorized": False,
            "output_root_in_repo": False,
        },
        "broadcast_enabled": False,
    }
