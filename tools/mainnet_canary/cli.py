"""Fail-closed six-mode CLI for the Concordia Mainnet canary preparation.

Modes: ``inventory``, ``estimate``, ``plan``, ``stage``, ``verify``,
``broadcast``.  Success prints deterministic JSON and exits 0.  Every refusal
prints ``{"refusal": {code, detail}}`` and exits 2.  No mode reads
environment variables, no mode accepts a bypass flag, and no mode can sign
or submit anything.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from tools.mainnet_canary.broadcast import run_broadcast_guard
from tools.mainnet_canary.constants import (
    BLOCKED_PENDING_LIVE_PROOF,
    LIVE_AUTHORIZATION_MOUNT_PATH,
    MAINNET_CHAIN_NAME,
    MAINNET_RPC_OBSERVATION,
    MAINNET_RPC_URL,
    PREP_BASE_SHA,
    PUBLIC_KEY_INVENTORY_MOUNT_PATH,
    TESTNET_RC_WASM_SHA256_AT_PREP_BASE,
)
from tools.mainnet_canary.cost_model import build_estimate
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.keys import load_key_inventory
from tools.mainnet_canary.plan import (
    build_plan,
    canonical_json,
    plan_document_hash,
)
from tools.mainnet_canary.rc_gate import load_rc_declaration
from tools.mainnet_canary.secret_guard import refuse_if_secret_material
from tools.mainnet_canary.stage import run_stage
from tools.mainnet_canary.finality_v2 import evaluate_dual_provider
from tools.mainnet_canary.path_policy import CanaryPathPolicy
from tools.mainnet_canary.proof_bundle import (
    REQUIRED_STATEMENT,
    build_proof_bundle_document,
)
from tools.mainnet_canary.economic_manifest import (
    build_economic_manifest,
    required_funding_motes,
)

REFUSAL_EXIT_CODE = 2


def _emit(document: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(document, sort_keys=True, indent=2) + "\n")


def _read_json_file(path: Path, *, context: str) -> dict[str, object]:
    if not path.is_file():
        raise CanaryRefusal(
            RefusalCode.PLAN_INPUT_ABSENT, f"{context} file is not present"
        )
    raw = path.read_text(encoding="utf-8")
    refuse_if_secret_material(raw, context=context)
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CanaryRefusal(
            RefusalCode.PLAN_INPUT_INVALID, f"{context} is not valid JSON"
        ) from exc
    if not isinstance(document, dict):
        raise CanaryRefusal(
            RefusalCode.PLAN_INPUT_INVALID, f"{context} must be a JSON object"
        )
    return document


def _cmd_inventory(args: argparse.Namespace) -> dict[str, object]:
    """Read-only: public identities, pins, and missing prerequisites."""

    missing: list[str] = []
    roles: dict[str, object] = {}
    threshold: int | None = None
    try:
        inventory = load_key_inventory(Path(args.key_inventory))
        threshold = inventory.threshold
        for role in inventory.roles.values():
            roles[role.role] = {
                "public_key_hex": role.public_key_hex,
                "account_hash_hex": role.account_hash_hex,
                "key_file_mount_path": role.key_file_mount_path,
                "balance_motes": "UNKNOWN_NOT_OBSERVED",
            }
    except CanaryRefusal as exc:
        if exc.code != RefusalCode.KEY_INVENTORY_ABSENT:
            raise
        missing.append(
            "dedicated Mainnet public-key inventory "
            f"(future mount: {PUBLIC_KEY_INVENTORY_MOUNT_PATH})"
        )

    rc_summary: dict[str, object] = {"status": "ABSENT"}
    try:
        declaration = load_rc_declaration(Path(args.rc_declaration))
        rc_summary = {
            "status": "PRESENT_UNVALIDATED",
            "rc_tag": declaration["rc_tag"],
            "peeled_commit_sha": declaration["peeled_commit_sha"],
        }
    except CanaryRefusal as exc:
        if exc.code != RefusalCode.RC_DECLARATION_ABSENT:
            raise
        missing.append("Codex Testnet-RC declaration (release dependency)")

    missing.append(
        "Codex live authorization file "
        f"(future mount: {LIVE_AUTHORIZATION_MOUNT_PATH})"
    )
    missing.append("measured exact-equivalent Testnet costs (all lines UNKNOWN)")
    missing.append("human-approved public spending ceiling document")
    missing.append(
        "Mainnet-chain v3 Wasm attestation (Testnet RC Wasm hard-codes "
        "chain `casper-test`; see interface manifest finding B1)"
    )

    return {
        "mode": "inventory",
        "prep_base_sha": PREP_BASE_SHA,
        "network": {
            "chain_name": MAINNET_CHAIN_NAME,
            "rpc_url": MAINNET_RPC_URL,
            "rpc_observation": MAINNET_RPC_OBSERVATION,
        },
        "testnet_rc_wasm_sha256_at_prep_base": TESTNET_RC_WASM_SHA256_AT_PREP_BASE,
        "threshold": threshold,
        "roles": roles,
        "rc_declaration": rc_summary,
        "mainnet_deployment_status": BLOCKED_PENDING_LIVE_PROOF,
        "missing_prerequisites": missing,
    }


def _cmd_estimate(args: argparse.Namespace) -> dict[str, object]:
    report = build_estimate(
        Path(args.repo_root),
        measured_costs_path=(
            Path(args.measured_costs) if args.measured_costs else None
        ),
        ceiling_path=Path(args.ceiling) if args.ceiling else None,
    )
    if report["approval"] != "WITHIN_CEILING":
        raise CanaryRefusal(
            str(report["refusal_codes"][0]),
            "estimate refused: "
            + ", ".join(str(code) for code in report["refusal_codes"])
            + f"; unknown items: {report['unknown_items']}",
        )
    return {"mode": "estimate", **report}


def _cmd_plan(args: argparse.Namespace) -> dict[str, object]:
    document = build_plan(
        Path(args.repo_root),
        rc_declaration_path=Path(args.rc_declaration),
        key_inventory_path=Path(args.key_inventory),
        parameters_path=Path(args.parameters),
        snapshot_path=Path(args.snapshot),
        status_path=Path(args.status),
    )
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(document, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
    return {"mode": "plan", **document}


def _cmd_stage(args: argparse.Namespace) -> dict[str, object]:
    plan_document = _read_json_file(Path(args.plan), context="plan-document")
    report = run_stage(
        Path(args.repo_root),
        plan_document=plan_document,
        rc_declaration_path=Path(args.rc_declaration),
        snapshot_path=Path(args.snapshot),
        status_path=Path(args.status),
        ceiling_path=Path(args.ceiling) if args.ceiling else None,
        measured_costs_path=(
            Path(args.measured_costs) if args.measured_costs else None
        ),
        journal_path=Path(args.journal),
        output_dir=Path(args.out_dir),
        attestation_path=Path(args.attestation),
        calibration_path=Path(args.calibration),
        authorization_path=Path(args.authorization),
        clock_unix=int(args.clock_unix),
        operator_ceilings_path=(
            Path(args.operator_ceilings) if args.operator_ceilings else None
        ),
    )
    return {"mode": "stage", **report}


def _cmd_funding(args: argparse.Namespace) -> dict[str, object]:
    """Exact maximum funding the operator must provision — and nothing else.

    Puts :mod:`tools.mainnet_canary.economic_manifest` on a user-facing path
    without any purchase, transfer, bridge, swap, or exchange step: it prints
    one number derived from the plan's own economic steps.
    """

    plan_document = _read_json_file(Path(args.plan), context="plan-document")
    if plan_document.get("canary_plan_sha256") != plan_document_hash(plan_document):
        raise CanaryRefusal(
            RefusalCode.PLAN_HASH_MISMATCH, "plan document hash does not recompute"
        )
    calibration = _read_json_file(
        Path(args.calibration), context="testnet-calibration"
    )
    operator_ceilings: dict[str, object] = {}
    if args.operator_ceilings:
        operator_ceilings = _read_json_file(
            Path(args.operator_ceilings), context="operator-ceilings"
        )
    manifest = build_economic_manifest(
        plan_document, calibration=calibration, operator_ceilings=operator_ceilings
    )
    return {
        "mode": "funding",
        "plan_hash": plan_document["canary_plan_sha256"],
        "required_funding_motes": required_funding_motes(manifest),
        "transfer_principal_motes": manifest["transfer_principal_motes"],
        "max_fees_motes": manifest["max_fees_motes"],
        "acquisition": (
            "This lane never purchases, transfers, bridges, swaps, or "
            "exchanges CSPR; provisioning is a human action performed "
            "entirely outside this tooling."
        ),
    }


def _cmd_verify(args: argparse.Namespace) -> dict[str, object]:
    plan_document = _read_json_file(Path(args.plan), context="plan-document")
    if plan_document.get("canary_plan_sha256") != plan_document_hash(plan_document):
        raise CanaryRefusal(
            RefusalCode.PLAN_HASH_MISMATCH, "plan document hash does not recompute"
        )
    observations_path = Path(args.observations)
    if not observations_path.is_file():
        raise CanaryRefusal(
            RefusalCode.OBSERVATION_ABSENT,
            "no observation bundle exists; in the preparation lane nothing "
            "has been broadcast, so there is nothing that could verify",
        )
    raw = observations_path.read_text(encoding="utf-8")
    refuse_if_secret_material(raw, context="observation-bundle")
    try:
        bundle = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CanaryRefusal(
            RefusalCode.OBSERVATION_MALFORMED, "observation bundle is not JSON"
        ) from exc
    if not isinstance(bundle, list):
        raise CanaryRefusal(
            RefusalCode.OBSERVATION_MALFORMED, "observation bundle must be a list"
        )

    # Finality v2 is ON this path: every economic step needs TWO agreeing
    # observations from disjoint Mainnet providers, each carrying raw
    # response evidence. A single-source bundle refuses with
    # NODE_SET_INVALID rather than being quietly accepted.
    results: list[dict[str, object]] = []
    envelope = plan_document["envelope"]
    derived = envelope["derived"]
    for step in plan_document["steps"]:
        step_id = str(step["step_id"])
        if not step["economic"]:
            continue
        expected = step["expected_outcome"]
        if step["kind"] == "native_transfer":
            expectation: dict[str, object] = {
                "type": "native_transfer",
                "source_account": str(expected["source_account"]),
                "recipient_account": str(expected["recipient_account"]),
                "amount_motes": str(expected["amount_motes"]),
                "transfer_id": str(derived["transfer_id"]),
            }
        elif expected.get("execution") == "failure":
            expectation = {
                "type": "exact_refusal",
                "error_message": str(expected["exact_error_message"]),
            }
        else:
            expectation = {"type": "expected_success"}
        consensus = evaluate_dual_provider(
            bundle, step_id=step_id, expectation=expectation
        )
        results.append(
            {
                "step_id": step_id,
                "status": "observation_consistent",
                "providers": consensus["providers"],
                "consensus_block_hash": consensus["consensus_block_hash"],
                "raw_response_sha256s": consensus["raw_response_sha256s"],
            }
        )

    return {
        "mode": "verify",
        "plan_hash": plan_document["canary_plan_sha256"],
        "steps": results,
        "finality_policy": {
            "providers_required": 2,
            "disjoint_hosts_required": True,
            "upstream_booleans_trusted": False,
        },
        # Release/registry claims stay with Codex; this lane never asserts a
        # Mainnet-verified state.
        "canary_release_claim": BLOCKED_PENDING_LIVE_PROOF,
    }


def _cmd_bundle(args: argparse.Namespace) -> dict[str, object]:
    """Emit the canary proof bundle through the confined path policy.

    Puts :mod:`tools.mainnet_canary.proof_bundle` on the enforcement path: the
    lineage, the verbatim required statement, and the forbidden-claims scan
    all run before anything is written, and the write itself goes through
    :class:`CanaryPathPolicy` (never overwriting evidence, never reaching a
    protected namespace).
    """

    plan_document = _read_json_file(Path(args.plan), context="plan-document")
    plan_hash = plan_document.get("canary_plan_sha256")
    if plan_hash != plan_document_hash(plan_document):
        raise CanaryRefusal(
            RefusalCode.PLAN_HASH_MISMATCH, "plan document hash does not recompute"
        )
    verification = _read_json_file(
        Path(args.verification), context="verification-report"
    )
    manifest = _read_json_file(
        Path(args.economic_manifest), context="economic-manifest"
    )
    attestation = _read_json_file(Path(args.attestation), context="build-attestation")
    document = build_proof_bundle_document(
        plan_hash=str(plan_hash),
        rc_tag=str(plan_document.get("rc", {}).get("tag")),
        economic_manifest_sha256=hashlib.sha256(
            canonical_json(manifest).encode("ascii")
        ).hexdigest(),
        attestations={
            "testnet_wasm_sha256": attestation.get("network_artifacts", {})
            .get("testnet", {})
            .get("wasm_sha256"),
            "mainnet_wasm_sha256": attestation.get("network_artifacts", {})
            .get("mainnet-native", {})
            .get("wasm_sha256"),
        },
        step_verifications={
            str(entry["step_id"]): entry
            for entry in verification.get("steps", [])
            if isinstance(entry, dict) and "step_id" in entry
        },
        journal_head_hash=str(args.journal_head_hash),
        narrative=REQUIRED_STATEMENT,
    )
    policy = CanaryPathPolicy(
        Path(args.repo_root),
        Path(args.out_dir),
        canary_id=str(plan_hash)[:24] + "-prep",
        live_capture_authorized=False,
    )
    written = policy.exclusive_write_json("proof-bundle.json", document)
    return {"mode": "bundle", "bundle_path": str(written), **document}


def _cmd_broadcast(args: argparse.Namespace) -> dict[str, object]:
    plan_document = _read_json_file(Path(args.plan), context="plan-document")
    run_broadcast_guard(
        Path(args.repo_root),
        plan_document=plan_document,
        journal_path=Path(args.journal),
        ceiling_path=Path(args.ceiling) if args.ceiling else None,
        measured_costs_path=(
            Path(args.measured_costs) if args.measured_costs else None
        ),
    )
    raise CanaryRefusal(  # pragma: no cover - guard always refuses first
        RefusalCode.SUBMISSION_NOT_IMPLEMENTED_IN_PREP,
        "broadcast guard returned unexpectedly",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mainnet-canary",
        description=(
            "Concordia Mainnet canary preparation CLI (fail-closed; no "
            "signing, no submission, no secrets)"
        ),
    )
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[2]),
        help="repository root (defaults to this checkout)",
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    inventory = subparsers.add_parser("inventory", help="read-only identity pins")
    inventory.add_argument(
        "--key-inventory", default=PUBLIC_KEY_INVENTORY_MOUNT_PATH
    )
    inventory.add_argument(
        "--rc-declaration", default="handoff/testnet-rc-declaration.json"
    )
    inventory.set_defaults(handler=_cmd_inventory)

    estimate = subparsers.add_parser("estimate", help="upper-bound CSPR budget")
    estimate.add_argument("--measured-costs", default=None)
    estimate.add_argument("--ceiling", default=None)
    estimate.set_defaults(handler=_cmd_estimate)

    plan = subparsers.add_parser("plan", help="deterministic transaction plan")
    plan.add_argument("--rc-declaration", required=True)
    plan.add_argument("--key-inventory", required=True)
    plan.add_argument("--parameters", required=True)
    plan.add_argument("--snapshot", required=True)
    plan.add_argument("--status", required=True)
    plan.add_argument("--out", default=None)
    plan.set_defaults(handler=_cmd_plan)

    stage = subparsers.add_parser("stage", help="unsigned payloads + journal")
    stage.add_argument("--plan", required=True)
    stage.add_argument("--rc-declaration", required=True)
    stage.add_argument("--snapshot", required=True)
    stage.add_argument("--status", required=True)
    stage.add_argument("--ceiling", default=None)
    stage.add_argument("--measured-costs", default=None)
    stage.add_argument("--journal", required=True)
    stage.add_argument("--out-dir", required=True)
    # Every gate below is REQUIRED: staging cannot proceed on an unattested
    # artifact, an ungrounded cost model, or an unsigned/expired authorization.
    stage.add_argument("--attestation", required=True)
    stage.add_argument("--calibration", required=True)
    stage.add_argument("--authorization", required=True)
    stage.add_argument("--clock-unix", required=True, type=int)
    stage.add_argument("--operator-ceilings", default=None)
    stage.set_defaults(handler=_cmd_stage)

    funding = subparsers.add_parser(
        "funding", help="exact maximum funding required (no acquisition)"
    )
    funding.add_argument("--plan", required=True)
    funding.add_argument("--calibration", required=True)
    funding.add_argument("--operator-ceilings", default=None)
    funding.set_defaults(handler=_cmd_funding)

    verify = subparsers.add_parser(
        "verify", help="read-only dual-provider observation checks"
    )
    verify.add_argument("--plan", required=True)
    verify.add_argument("--observations", required=True)
    verify.set_defaults(handler=_cmd_verify)

    bundle = subparsers.add_parser(
        "bundle", help="emit the canary proof bundle through the path policy"
    )
    bundle.add_argument("--plan", required=True)
    bundle.add_argument("--verification", required=True)
    bundle.add_argument("--economic-manifest", required=True)
    bundle.add_argument("--attestation", required=True)
    bundle.add_argument("--journal-head-hash", required=True)
    bundle.add_argument("--out-dir", required=True)
    bundle.set_defaults(handler=_cmd_bundle)

    broadcast = subparsers.add_parser(
        "broadcast",
        help="guard surface only; disabled pending Codex live authorization",
    )
    broadcast.add_argument("--plan", required=True)
    broadcast.add_argument("--journal", required=True)
    broadcast.add_argument("--ceiling", default=None)
    broadcast.add_argument("--measured-costs", default=None)
    broadcast.set_defaults(handler=_cmd_broadcast)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        _emit(args.handler(args))
    except CanaryRefusal as refusal:
        _emit({"refusal": refusal.as_dict()})
        return REFUSAL_EXIT_CODE
    return 0
