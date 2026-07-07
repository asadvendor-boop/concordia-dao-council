#!/usr/bin/env python3
"""Prepare and execute a fresh Plan-B quorum recording run.

This helper is intentionally narrow: it reuses the already-deployed
quorum-enabled GovernanceReceipt package and submits per-proposal calls for a
fresh supplemental demo proposal. It never reconfigures quorum and never deploys
new contracts.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.generate_dynamic_proposal import build_dynamic_artifacts, write_artifacts  # noqa: E402
from shared.casper_executor import submit_odra_call_deploy  # noqa: E402


DEFAULT_PACKAGE = "hash-1d324e319701e4adcfa9476efcde3d047462d35e79d2cd8c7326c0c384c87d96"
DEFAULT_RECORDING_TITLE = "Move 30% of treasury into high-yield strategy."
DEFAULT_RECORDING_BPS = 3000


def _artifact_path(proposal_id: str) -> Path:
    safe = proposal_id.replace("/", "-")
    return ROOT / "artifacts" / "live" / f"planb-quorum-live-{safe}.json"


def _dynamic_proof_path(proposal_id: str) -> Path:
    return ROOT / "artifacts" / "live" / f"dynamic-proposal-execution-proof-{proposal_id}.json"


def _dynamic_evidence_path(proposal_id: str) -> Path:
    return ROOT / "artifacts" / "live" / f"dynamic-evidence-{proposal_id}.json"


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def _sha256(payload: Any) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def _arg_value(args: dict[str, Any], name: str) -> Any:
    value = args.get(name)
    return value.get("value") if isinstance(value, dict) else None


def _receipt_args(proposal_id: str) -> dict[str, Any]:
    proof = _read_json(_dynamic_proof_path(proposal_id))
    args = proof.get("typed_runtime_args")
    if not isinstance(args, dict) or not args:
        raise SystemExit(
            f"Missing typed_runtime_args for {proposal_id}; run prepare first."
        )
    out = dict(args)
    out["proposal_id"] = {"cl_type": "String", "value": proposal_id}
    return out


def _envelope_hash(proposal_id: str) -> str:
    args = _receipt_args(proposal_id)
    envelope = {
        "proposal_id": proposal_id,
        "decision": _arg_value(args, "decision"),
        "approved_allocation_bps": int(_arg_value(args, "approved_allocation_bps") or 0),
        "policy_hash": _arg_value(args, "policy_hash"),
        "dissent_hash": _arg_value(args, "dissent_hash"),
        "final_card_hash": _arg_value(args, "final_card_hash"),
        "plan_hash": _arg_value(args, "plan_hash"),
    }
    return _sha256(envelope)


def _step_args(step: str, proposal_id: str) -> tuple[str, dict[str, Any]]:
    if step == "propose":
        return "propose_envelope", {
            "proposal_id": {"cl_type": "String", "value": proposal_id},
            "envelope_hash": {"cl_type": {"ByteArray": 32}, "value": _envelope_hash(proposal_id)},
        }
    if step == "pre-quorum":
        return "store_governance_receipt", _receipt_args(proposal_id)
    if step == "server-approve":
        return "approve_envelope", {"proposal_id": {"cl_type": "String", "value": proposal_id}}
    if step == "final-receipt":
        return "store_governance_receipt", _receipt_args(proposal_id)
    raise SystemExit(f"Unsupported step: {step}")


def prepare(
    proposal_id: str,
    artifact: Path,
    *,
    requested_bps: int = DEFAULT_RECORDING_BPS,
    title: str = DEFAULT_RECORDING_TITLE,
    force: bool = False,
) -> dict[str, Any]:
    evidence_path = _dynamic_evidence_path(proposal_id)
    proof_path = _dynamic_proof_path(proposal_id)
    if force or not evidence_path.exists() or not proof_path.exists():
        evidence, proof = build_dynamic_artifacts(
            proposal_id=proposal_id,
            requested_bps=requested_bps,
            title=title,
        )
        write_artifacts(evidence, proof, evidence_out=evidence_path, proof_out=proof_path)
    receipt_args = _receipt_args(proposal_id)
    packet = _read_json(artifact)
    packet.update(
        {
            "schema": "concordia.planb.quorum-live-run.v1",
            "status": packet.get("status") or "prepared",
            "proposal_id": proposal_id,
            "scope": "supplemental_planb_recording_run",
            "canonical_proof_unchanged": True,
            "package_hash": os.getenv("CASPER_QUORUM_PACKAGE_HASH", DEFAULT_PACKAGE),
            "contract_version": int(os.getenv("CASPER_QUORUM_CONTRACT_VERSION", "1")),
            "dynamic_evidence_artifact": str(evidence_path.relative_to(ROOT)),
            "dynamic_execution_artifact": str(proof_path.relative_to(ROOT)),
            "requested_allocation_bps": requested_bps,
            "proposal_title": title,
            "envelope_hash": _envelope_hash(proposal_id),
            "typed_runtime_args": receipt_args,
            "wallet_approval_url": (
                f"https://concordia.47.84.232.193.sslip.io/dashboard/proof"
                f"?proposal={proposal_id}&quorum_demo=1"
            ),
            "live_deploys": packet.get("live_deploys") or {},
            "updated_at": datetime.now(UTC).isoformat(),
        }
    )
    _write_json(artifact, packet)
    return packet


async def submit_step(args: argparse.Namespace, artifact: Path) -> dict[str, Any]:
    packet = prepare(
        args.proposal_id,
        artifact,
        requested_bps=args.requested_bps,
        title=args.title,
        force=args.force_prepare,
    )
    entry_point, argument_specs = _step_args(args.step, args.proposal_id)
    result = await submit_odra_call_deploy(
        contract_hash=args.package_hash or packet["package_hash"],
        entry_point=entry_point,
        argument_specs=argument_specs,
        call_target="package",
        contract_version=args.contract_version or int(packet["contract_version"]),
        payment_amount=args.payment_amount,
        dry_run=args.dry_run,
    )
    expected_failure = args.step == "pre-quorum"
    observed_expected_failure = False
    if expected_failure and result.get("status") == "failed":
        finality = result.get("finality") if isinstance(result.get("finality"), dict) else {}
        message = json.dumps(finality, sort_keys=True, default=str)
        observed_expected_failure = "User error: 8" in message or "QuorumNotMet" in message
    deploy_hash = result.get("deploy_hash")
    packet = _read_json(artifact)
    packet.setdefault("live_deploys", {})
    packet.setdefault("steps", {})
    packet["steps"][args.step] = {
        "status": result.get("status"),
        "entry_point": entry_point,
        "deploy_hash": deploy_hash,
        "deploy_url": f"https://testnet.cspr.live/deploy/{deploy_hash}" if deploy_hash else None,
        "expected_failure": expected_failure,
        "expected_failure_observed": observed_expected_failure,
        "finality": result.get("finality"),
        "updated_at": datetime.now(UTC).isoformat(),
    }
    if deploy_hash:
        packet["live_deploys"][args.step] = deploy_hash
    if args.step == "pre-quorum" and observed_expected_failure:
        packet["summary"] = {**packet.get("summary", {}), "pre_quorum_reverted_with_quorum_not_met": True}
    if args.step == "server-approve" and result.get("status") == "success":
        packet["summary"] = {**packet.get("summary", {}), "server_approval_processed": True}
    if args.step == "final-receipt" and result.get("status") == "success":
        packet["summary"] = {**packet.get("summary", {}), "final_receipt_processed_after_quorum": True}
        packet["status"] = "live_complete"
        proof_path = _dynamic_proof_path(args.proposal_id)
        proof = _read_json(proof_path)
        proof.update(
            {
                "status": "processed",
                "scope": "supplemental_planb_quorum_recording_run",
                "deploy_hash": deploy_hash,
                "transaction_hash": deploy_hash,
                "contract_hash": args.package_hash or packet["package_hash"],
                "entry_point": entry_point,
                "processed_at": datetime.now(UTC).isoformat(),
                "casper_submission": result,
            }
        )
        _write_json(proof_path, proof)
    _write_json(artifact, packet)
    return {
        "step": args.step,
        "artifact": str(artifact.relative_to(ROOT)),
        "proposal_id": args.proposal_id,
        "deploy_hash": deploy_hash,
        "deploy_url": f"https://testnet.cspr.live/deploy/{deploy_hash}" if deploy_hash else None,
        "status": result.get("status"),
        "expected_failure_observed": observed_expected_failure,
        "wallet_approval_url": packet.get("wallet_approval_url"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proposal-id", required=True)
    parser.add_argument(
        "--step",
        choices=["prepare", "propose", "pre-quorum", "server-approve", "final-receipt"],
        default="prepare",
    )
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--requested-bps", type=int, default=DEFAULT_RECORDING_BPS)
    parser.add_argument("--title", default=DEFAULT_RECORDING_TITLE)
    parser.add_argument("--force-prepare", action="store_true", help="Regenerate local dynamic evidence/proof artifacts before this step.")
    parser.add_argument("--package-hash", default=os.getenv("CASPER_QUORUM_PACKAGE_HASH", DEFAULT_PACKAGE))
    parser.add_argument("--contract-version", type=int, default=int(os.getenv("CASPER_QUORUM_CONTRACT_VERSION", "1")))
    parser.add_argument("--payment-amount", type=int, default=5_000_000_000)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    artifact = args.artifact or _artifact_path(args.proposal_id)
    if not artifact.is_absolute():
        artifact = ROOT / artifact
    if args.step == "prepare":
        packet = prepare(
            args.proposal_id,
            artifact,
            requested_bps=args.requested_bps,
            title=args.title,
            force=args.force_prepare,
        )
        print(json.dumps({
            "status": "prepared",
            "proposal_id": args.proposal_id,
            "artifact": str(artifact.relative_to(ROOT)),
            "wallet_approval_url": packet["wallet_approval_url"],
            "envelope_hash": packet["envelope_hash"],
            "requested_allocation_bps": packet["requested_allocation_bps"],
            "proposal_title": packet["proposal_title"],
        }, indent=2, sort_keys=True))
        return 0
    result = asyncio.run(submit_step(args, artifact))
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.step == "pre-quorum":
        return 0 if result.get("expected_failure_observed") else 1
    return 0 if result.get("status") == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
