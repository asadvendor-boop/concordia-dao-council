"""Fail-closed six-mode CLI for the Concordia Mainnet canary preparation.

Modes: ``inventory``, ``estimate``, ``plan``, ``stage``, ``verify``,
``broadcast``.  Success prints deterministic JSON and exits 0.  Every refusal
prints ``{"refusal": {code, detail}}`` and exits 2.  No mode reads
environment variables, no mode accepts a bypass flag, and no mode can sign
or submit anything.
"""

from __future__ import annotations

import argparse
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
from tools.mainnet_canary.plan import build_plan, plan_document_hash
from tools.mainnet_canary.rc_gate import load_rc_declaration
from tools.mainnet_canary.secret_guard import refuse_if_secret_material
from tools.mainnet_canary.stage import run_stage
from tools.mainnet_canary.verify import (
    evaluate_expected_prequorum_refusal,
    evaluate_expected_success,
    evaluate_native_transfer_readback,
    evaluate_step_observations,
    require_finalized_membership,
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
    )
    return {"mode": "stage", **report}


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

    results: list[dict[str, object]] = []
    installed_package: str | None = None
    installed_contract: str | None = None
    envelope = plan_document["envelope"]
    derived = envelope["derived"]
    for step in plan_document["steps"]:
        step_id = str(step["step_id"])
        if not step["economic"]:
            continue
        observation = evaluate_step_observations(bundle, step_id=step_id)
        expected = step["expected_outcome"]
        typed_args = {
            str(arg["name"]): arg["value"] for arg in step["typed_args"]
        }
        if step_id == "B-install-rc-wasm":
            # Install target hashes are only knowable from the readback.
            require_finalized_membership(observation)
            execution = observation["execution"]
            if execution["success"] is not True or (
                execution["error_message"] is not None
            ):
                raise CanaryRefusal(
                    RefusalCode.EXECUTION_FAILED, "install did not succeed"
                )
            target = observation["target"]
            installed_package = str(target["package_hash"])
            installed_contract = str(target["contract_hash"])
        elif step["kind"] == "native_transfer":
            evaluate_native_transfer_readback(
                observation,
                source_account=str(expected["source_account"]),
                recipient_account=str(expected["recipient_account"]),
                amount_motes=str(expected["amount_motes"]),
                transfer_id=str(derived["transfer_id"]),
            )
        else:
            if installed_package is None or installed_contract is None:
                raise CanaryRefusal(
                    RefusalCode.WRONG_CONTRACT,
                    "no verified install precedes this contract call",
                )
            if expected.get("execution") == "failure":
                evaluate_expected_prequorum_refusal(
                    observation,
                    package_hash=installed_package,
                    contract_hash=installed_contract,
                    entry_point=str(step["entry_point"]),
                    typed_args=typed_args,
                    expected_error_message=str(expected["exact_error_message"]),
                )
            else:
                evaluate_expected_success(
                    observation,
                    package_hash=installed_package,
                    contract_hash=installed_contract,
                    entry_point=str(step["entry_point"]),
                    typed_args=typed_args,
                )
        results.append(
            {"step_id": step_id, "status": "observation_consistent"}
        )

    return {
        "mode": "verify",
        "plan_hash": plan_document["canary_plan_sha256"],
        "steps": results,
        # Release/registry claims stay with Codex; this lane never asserts a
        # Mainnet-verified state.
        "canary_release_claim": BLOCKED_PENDING_LIVE_PROOF,
    }


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
    stage.set_defaults(handler=_cmd_stage)

    verify = subparsers.add_parser("verify", help="read-only observation checks")
    verify.add_argument("--plan", required=True)
    verify.add_argument("--observations", required=True)
    verify.set_defaults(handler=_cmd_verify)

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
