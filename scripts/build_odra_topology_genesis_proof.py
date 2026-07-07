#!/usr/bin/env python3
"""Build the live supplemental Odra topology genesis proof artifact.

This does not spend CSPR. It consolidates already-processed Testnet install and
call artifacts for the auxiliary Odra modules into one reviewer-facing proof.
"""
from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LIVE = ROOT / "artifacts" / "live"

CANONICAL_PROPOSAL_ID = "DAO-PROP-6CB25C"
CANONICAL_RECEIPT = "e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852"
CANONICAL_CONTRACT = "hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1"

SOURCE_ARTIFACTS = {
    "CouncilRegistry": LIVE / "odra-topology-councilregistry-proof.json",
    "TreasuryPolicy": LIVE / "odra-topology-treasurypolicy-v3-proof.json",
    "CardIndexLedger": LIVE / "odra-topology-cardindexledger-v3-proof.json",
}

HISTORICAL_FAILURES = [
    {
        "deploy_hash": "f5097b0fabba0f8a4fd31a4f4c32a6caada9345ab7194893c9d66606e037da0b",
        "module": "CouncilRegistry",
        "status": "failed",
        "reason": "out_of_gas",
        "note": "Historical failed attempt retained for spend transparency; not part of the successful topology genesis proof.",
    },
    {
        "deploy_hash": "e046881a46b433b52d507399340a56322ce9cbbb560223a78517ed6ca3243478",
        "module": "TreasuryPolicy",
        "status": "failed",
        "reason": "missing_constructor_args_user_error_64658",
        "note": "Historical failed attempt before constructor caps were added; not part of the successful topology genesis proof.",
    },
]


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _deploy_url(deploy_hash: str) -> str:
    return f"https://testnet.cspr.live/deploy/{deploy_hash.lower()}"


def _normalise_deploy_hash(value: Any) -> str:
    return str(value or "").lower()


def _module_record(module: str, artifact: dict[str, Any]) -> dict[str, Any]:
    module_data = artifact["modules"][module]
    call = artifact["standalone_calls"][module]
    call_result = call["result"]
    install_hash = _normalise_deploy_hash(module_data["install_deploy_hash"])
    call_hash = _normalise_deploy_hash(call_result["deploy_hash"])
    return {
        "module": module,
        "status": "live_complete",
        "package_hash": module_data["package_hash"],
        "package_key_name": module_data["package_key_name"],
        "install": {
            "deploy_hash": install_hash,
            "explorer_url": _deploy_url(install_hash),
            "block_height": module_data.get("install_finality", {}).get("block_height"),
            "block_hash": module_data.get("install_finality", {}).get("block_hash"),
            "success": module_data.get("install_finality", {}).get("success") is True,
            "constructor_args": module_data.get("constructor_args", {}),
        },
        "standalone_call": {
            "entry_point": call["entry_point"],
            "deploy_hash": call_hash,
            "explorer_url": _deploy_url(call_hash),
            "block_height": call_result.get("finality", {}).get("block_height"),
            "block_hash": call_result.get("finality", {}).get("block_hash"),
            "success": call_result.get("acceptance_passed") is True,
            "typed_runtime_args": call_result.get("typed_runtime_args", {}),
        },
        "source_artifact": str(SOURCE_ARTIFACTS[module].relative_to(ROOT)),
    }


def build() -> dict[str, Any]:
    artifacts = {module: _load(path) for module, path in SOURCE_ARTIFACTS.items()}
    modules = {module: _module_record(module, artifact) for module, artifact in artifacts.items()}
    successful = all(
        item["install"]["success"] and item["standalone_call"]["success"]
        for item in modules.values()
    )
    return {
        "schema": "concordia.odra-topology-genesis-proof.v1",
        "status": "live_complete" if successful else "incomplete",
        "generated_at": datetime.now(UTC).isoformat(),
        "proof_hierarchy": {
            "canonical_reviewer_proof": {
                "proposal_id": CANONICAL_PROPOSAL_ID,
                "receipt_deploy_hash": CANONICAL_RECEIPT,
                "contract_hash": CANONICAL_CONTRACT,
                "explorer_url": _deploy_url(CANONICAL_RECEIPT),
                "note": "Frozen reviewer proof; this topology genesis is supplemental and does not replace it.",
            },
            "supplemental_topology_genesis": {
                "status": "live_complete" if successful else "incomplete",
                "modules": list(SOURCE_ARTIFACTS),
            },
        },
        "modules": modules,
        "historical_failed_attempts": HISTORICAL_FAILURES,
        "acceptance": {
            "council_registry_installed_and_called": modules["CouncilRegistry"]["standalone_call"]["success"],
            "treasury_policy_installed_with_constructor_caps_and_called": modules["TreasuryPolicy"]["standalone_call"]["success"],
            "card_index_ledger_installed_and_called": modules["CardIndexLedger"]["standalone_call"]["success"],
            "canonical_receipt_unchanged": True,
        },
        "honesty_boundary": (
            "Supplemental Odra topology genesis independently installed and exercised "
            "CouncilRegistry through a representative register_agent call, TreasuryPolicy "
            "through validate_allocation, and CardIndexLedger through seal_card_root on "
            "Casper Testnet. The canonical reviewer proof remains GovernanceReceipt deploy "
            "e926...d852; this topology proof is not a replacement for the canonical receipt "
            "and is not claimed as a fully productized four-contract DAO suite."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=LIVE / "odra-topology-genesis-proof.json")
    args = parser.parse_args()
    proof = build()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": proof["status"], "out": str(args.out)}, indent=2))
    return 0 if proof["status"] == "live_complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
