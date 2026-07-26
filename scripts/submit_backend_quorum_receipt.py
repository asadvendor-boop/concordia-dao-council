#!/usr/bin/env python3
"""Submit or dry-run the backend-signed quorum final receipt.

This is Concordia's server-custody Option 1 proof. Browser-wallet signing
already proves the user-custody path. This script proves the VM operator key
can broadcast the same quorum-gated final receipt after the 2-of-3 threshold is
met, using the native pycspr JSON-RPC path rather than a CLI subprocess.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.prepare_odra_quorum_exercise import DEFAULT_PROPOSAL_ID, receipt_args  # noqa: E402
from shared.casper_executor import submit_odra_call_deploy  # noqa: E402

DEFAULT_ARTIFACT = ROOT / "artifacts" / "live" / "odra-quorum-exercise-plan.json"


def _load_plan(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def _package_hash(plan: dict[str, Any], explicit: str | None) -> str:
    value = (
        explicit
        or os.getenv("CASPER_QUORUM_PACKAGE_HASH", "").strip()
        or os.getenv("ODRA_QUORUM_PACKAGE_HASH", "").strip()
        or str(plan.get("package_hash") or "").strip()
    )
    if not value.startswith(("hash-", "package-")) or len(value.split("-", 1)[-1]) != 64:
        raise SystemExit("A real CASPER_QUORUM_PACKAGE_HASH/package_hash is required.")
    return value


def _contract_version(plan: dict[str, Any], explicit: int | None) -> int:
    if explicit is not None:
        return explicit
    env_value = os.getenv("CASPER_QUORUM_CONTRACT_VERSION", "").strip()
    if env_value:
        return int(env_value)
    plan_value = plan.get("contract_version")
    if plan_value:
        return int(plan_value)
    return 1


def _redacted_result(result: dict[str, Any]) -> dict[str, Any]:
    """Keep enough deploy metadata for proof without dumping huge signed JSON."""
    rpc_payload = result.pop("rpc_payload", None)
    if isinstance(rpc_payload, dict):
        deploy = ((rpc_payload.get("params") or {}).get("deploy") or {})
        result["dry_run_deploy_summary"] = {
            "hash": deploy.get("hash"),
            "body_hash": (deploy.get("header") or {}).get("body_hash"),
            "session_keys": sorted((deploy.get("session") or {}).keys()),
            "approvals_count": len(deploy.get("approvals") or []),
        }
    return result


def _update_artifact(path: Path, result: dict[str, Any], *, dry_run: bool) -> None:
    plan = _load_plan(path)
    plan.setdefault("live_deploys", {})
    plan.setdefault("summary", {})
    plan.setdefault("option1_backend_signed_receipt", {})
    key = "backend_final_store_governance_receipt_dry_run" if dry_run else "backend_final_store_governance_receipt"
    deploy_hash = result.get("deploy_hash")
    if deploy_hash:
        plan["live_deploys"][key] = deploy_hash
    if not dry_run and result.get("status") == "success":
        plan["summary"]["backend_signed_final_receipt_after_quorum"] = True
        plan["summary"]["backend_signed_final_receipt"] = deploy_hash
        plan["summary"]["backend_signed_final_receipt_url"] = f"https://testnet.cspr.live/deploy/{deploy_hash}"
        plan["option1_backend_signed_receipt"] = {
            "status": "success",
            "deploy_hash": deploy_hash,
            "deploy_url": f"https://testnet.cspr.live/deploy/{deploy_hash}",
            "entry_point": result.get("entry_point"),
            "contract_hash": result.get("contract_hash"),
            "call_target": result.get("call_target"),
            "contract_version": result.get("contract_version"),
            "finality": result.get("finality"),
            "updated_at": datetime.now(UTC).isoformat(),
        }
    elif dry_run:
        plan["option1_backend_signed_receipt"] = {
            "status": "dry_run_success" if result.get("status") == "dry_run_success" else result.get("status"),
            "deploy_hash": deploy_hash,
            "entry_point": result.get("entry_point"),
            "contract_hash": result.get("contract_hash"),
            "call_target": result.get("call_target"),
            "contract_version": result.get("contract_version"),
            "updated_at": datetime.now(UTC).isoformat(),
        }
    path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    plan = _load_plan(args.artifact)
    package_hash = _package_hash(plan, args.package_hash)
    contract_version = _contract_version(plan, args.contract_version)
    result = await submit_odra_call_deploy(
        contract_hash=package_hash,
        entry_point="store_governance_receipt",
        argument_specs=receipt_args(args.proposal_id),
        call_target="package",
        contract_version=contract_version,
        payment_amount=args.payment_amount,
        dry_run=args.dry_run,
    )
    if args.update_artifact and result.get("status") in {"dry_run_success", "success"}:
        _update_artifact(args.artifact, dict(result), dry_run=args.dry_run)
    return _redacted_result(result)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proposal-id", default=DEFAULT_PROPOSAL_ID)
    parser.add_argument("--artifact", type=Path, default=DEFAULT_ARTIFACT)
    parser.add_argument("--package-hash", default=None)
    parser.add_argument("--contract-version", type=int, default=None)
    parser.add_argument("--payment-amount", type=int, default=5_000_000_000)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--update-artifact", action="store_true")
    args = parser.parse_args()
    result = asyncio.run(_run(args))
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0 if result.get("status") in {"dry_run_success", "success"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
