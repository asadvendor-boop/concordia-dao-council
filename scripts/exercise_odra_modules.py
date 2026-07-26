#!/usr/bin/env python3
"""Build a spend-free exercise plan for Concordia's Odra module topology.

This script intentionally does not broadcast Casper transactions. It gives
reviewers a deterministic module-by-module call plan and records the local
quorum tests that must pass before any fresh Testnet deployment is attempted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "contracts" / "odra-governance-receipt" / "migration.manifest.json"
LIB_RS = ROOT / "contracts" / "odra-governance-receipt" / "src" / "lib.rs"
DEFAULT_OUT = ROOT / "artifacts" / "live" / "odra-module-exercise-plan.json"
CANONICAL_RECEIPT_PROOF = ROOT / "artifacts" / "live" / "casper-final-receipt-proof.json"
PUBLIC_EVIDENCE = ROOT / "artifacts" / "live" / "public-evidence-reconciled.json"
DAO_CONSTITUTION = ROOT / "config" / "dao_constitution.cas.json"


def sha256_hex(payload: Any) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(body).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def canonical_receipt_roots() -> dict[str, Any]:
    proof = load_json(CANONICAL_RECEIPT_PROOF)
    return {
        "proposal_id": proof.get("proposal_id") or "DAO-PROP-6CB25C",
        "policy_hash": proof["policy_hash"],
        "final_card_hash": proof["final_card_hash"],
        "plan_hash": proof["plan_hash"],
        "dissent_hash": proof["dissent_hash"],
    }


def constitution_caps() -> dict[str, int]:
    constitution = load_json(DAO_CONSTITUTION)
    return {
        "max_single_allocation_bps": int(constitution["max_single_allocation_bps"]),
        "max_high_risk_allocation_bps": int(constitution["max_high_risk_allocation_bps"]),
    }


def card_index_roots(final_card_hash: str) -> dict[str, Any]:
    evidence = load_json(PUBLIC_EVIDENCE)
    cards = evidence.get("cards") or []
    final_card: dict[str, Any] | None = None
    terminal_card: dict[str, Any] | None = None
    for card in cards:
        card_hash = str(card.get("hash") or card.get("card_hash") or "")
        if card_hash == final_card_hash:
            final_card = card
        if card.get("sequence") is not None:
            terminal_card = card
    if not final_card:
        raise ValueError(f"receipt final_card_hash {final_card_hash} was not found in public evidence")
    if not terminal_card:
        terminal_card = final_card
    terminal_hash = str(terminal_card.get("hash") or terminal_card.get("card_hash") or final_card_hash)
    return {
        "receipt_final_card_root": {
            "label": "receipt_final_card_hash",
            "sequence": int(final_card["sequence"]),
            "card_root_hex": final_card_hash,
            "card_type": final_card.get("card_type"),
        },
        "session_terminal_card_root": {
            "label": "session_terminal_card_root",
            "sequence": int(terminal_card["sequence"]),
            "card_root_hex": terminal_hash,
            "card_type": terminal_card.get("card_type"),
        },
    }


def module_entrypoints(manifest: dict[str, Any]) -> dict[str, list[str]]:
    modules: dict[str, list[str]] = {}
    for item in manifest.get("contracts", []):
        modules[item["module"]] = [entry["name"] for entry in item.get("entrypoints", [])]
    return modules


def build_plan(manifest: dict[str, Any]) -> dict[str, Any]:
    roots = canonical_receipt_roots()
    caps = constitution_caps()
    proposal_id = manifest.get("live_proof", {}).get("proposal_id") or roots["proposal_id"]
    policy_hash = roots["policy_hash"]
    final_card_hash = roots["final_card_hash"]
    plan_hash = roots["plan_hash"]
    dissent_hash = roots["dissent_hash"]
    card_roots = card_index_roots(final_card_hash)
    receipt_card_root = card_roots["receipt_final_card_root"]
    terminal_card_root = card_roots["session_terminal_card_root"]
    envelope = {
        "proposal_id": proposal_id,
        "decision": "APPROVED_WITH_LIMITS",
        "approved_allocation_bps": caps["max_single_allocation_bps"],
        "policy_hash": policy_hash,
        "dissent_hash": dissent_hash,
        "final_card_hash": final_card_hash,
        "plan_hash": plan_hash,
    }
    envelope_hash = sha256_hex(envelope)

    return {
        "status": "dry_run_ready",
        "spends_cspr": False,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "manifest_status": manifest.get("status"),
        "honesty_boundary": manifest.get("honesty_boundary"),
        "canonical_live_proof": manifest.get("live_proof"),
        "constitution_caps": caps,
        "card_index_alignment": {
            "consistency_check": (
                "GovernanceReceipt.final_card_hash must equal "
                f"CardIndexLedger.card_root[{proposal_id}:{receipt_card_root['sequence']}]"
            ),
            "receipt_final_card_root": receipt_card_root,
            "session_terminal_card_root": terminal_card_root,
        },
        "local_quorum_tests": {
            "command": "cd contracts/odra-governance-receipt && cargo +nightly test",
            "required_tests": [
                "quorum_blocks_until_two_distinct_signers_approve",
                "quorum_rejects_non_signers_and_duplicate_approvals",
            ],
            "last_known_result": "passed_locally",
        },
        "modules": [
            {
                "module": "CouncilRegistry",
                "purpose": "Register the council signer/agent credential roots.",
                "calls": [
                    {
                        "entry_point": "register_agent",
                        "args": {
                            "agent_id": "Locke",
                            "public_key_hex": "02033c3b4d6eddae1be00f87e635aebe26a1cb5125ec8d09be1e95297208c5754ce1",
                        },
                    },
                    {
                        "entry_point": "get_agent_key",
                        "args": {"agent_id": "Locke"},
                        "expected": "registered public key",
                    },
                ],
            },
            {
                "module": "CardIndexLedger",
                "purpose": "Seal the tamper-evident card root for the evidence chain.",
                "calls": [
                    {
                        "entry_point": "seal_card_root",
                        "label": "receipt_final_card_hash",
                        "args": {
                            "proposal_id": proposal_id,
                            "sequence": receipt_card_root["sequence"],
                            "card_root_hex": receipt_card_root["card_root_hex"],
                        },
                    },
                    {
                        "entry_point": "get_card_root",
                        "label": "receipt_final_card_hash_check",
                        "args": {"proposal_id": proposal_id, "sequence": receipt_card_root["sequence"]},
                        "expected": final_card_hash,
                    },
                    {
                        "entry_point": "seal_card_root",
                        "label": "session_terminal_card_root",
                        "args": {
                            "proposal_id": proposal_id,
                            "sequence": terminal_card_root["sequence"],
                            "card_root_hex": terminal_card_root["card_root_hex"],
                        },
                    },
                    {
                        "entry_point": "get_card_root",
                        "label": "session_terminal_card_root_check",
                        "args": {"proposal_id": proposal_id, "sequence": terminal_card_root["sequence"]},
                        "expected": terminal_card_root["card_root_hex"],
                    },
                ],
            },
            {
                "module": "TreasuryPolicy",
                "purpose": "Enforce the DAO Constitution allocation cap.",
                "calls": [
                    {
                        "entry_point": "init",
                        "args": {
                            "max_single_allocation_bps": caps["max_single_allocation_bps"],
                            "max_high_risk_allocation_bps": caps["max_high_risk_allocation_bps"],
                        },
                    },
                    {
                        "entry_point": "validate_allocation",
                        "args": {"requested_bps": 3000, "high_risk": False},
                        "expected": False,
                    },
                    {
                        "entry_point": "validate_allocation",
                        "args": {"requested_bps": caps["max_single_allocation_bps"], "high_risk": False},
                        "expected": True,
                    },
                ],
            },
            {
                "module": "GovernanceReceipt",
                "purpose": "Require 2-of-3 signer quorum before storing the final receipt.",
                "calls": [
                    {
                        "entry_point": "configure_quorum",
                        "args": {
                            "signer_a": "Account 1",
                            "signer_b": "Account 2",
                            "signer_c": "Account 3",
                            "threshold": 2,
                        },
                    },
                    {
                        "entry_point": "propose_envelope",
                        "args": {"proposal_id": proposal_id, "envelope_hash": envelope_hash},
                    },
                    {
                        "entry_point": "approve_envelope",
                        "args": {"proposal_id": proposal_id, "caller": "signer_a"},
                    },
                    {
                        "entry_point": "quorum_status",
                        "args": {"proposal_id": proposal_id},
                        "expected": {"approvals": 1, "threshold": 2, "quorum_met": False},
                    },
                    {
                        "entry_point": "approve_envelope",
                        "args": {"proposal_id": proposal_id, "caller": "signer_b"},
                    },
                    {
                        "entry_point": "quorum_status",
                        "args": {"proposal_id": proposal_id},
                        "expected": {"approvals": 2, "threshold": 2, "quorum_met": True},
                    },
                    {
                        "entry_point": "store_governance_receipt",
                        "args": {
                            "proposal_id": proposal_id,
                            "decision": "APPROVED_WITH_LIMITS",
                            "approved_allocation_bps": caps["max_single_allocation_bps"],
                            "risk_score": 61,
                            "policy_hash": policy_hash,
                            "dissent_hash": dissent_hash,
                            "final_card_hash": final_card_hash,
                            "plan_hash": plan_hash,
                        },
                    },
                ],
            },
        ],
    }


def validate_plan(plan: dict[str, Any], manifest: dict[str, Any], source: str) -> list[str]:
    failures: list[str] = []
    manifest_entrypoints = module_entrypoints(manifest)
    for module in plan["modules"]:
        name = module["module"]
        if name not in manifest_entrypoints:
            failures.append(f"{name} missing from migration manifest")
            continue
        if f"pub struct {name}" not in source:
            failures.append(f"{name} missing from Odra source")
        for call in module["calls"]:
            entry = call["entry_point"]
            if entry not in manifest_entrypoints[name]:
                failures.append(f"{name}.{entry} missing from manifest")
            if f"pub fn {entry}" not in source:
                failures.append(f"{name}.{entry} missing from source")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    if not args.out.is_absolute():
        args.out = ROOT / args.out

    manifest = load_json(MANIFEST)
    source = LIB_RS.read_text(encoding="utf-8")
    plan = build_plan(manifest)
    failures = validate_plan(plan, manifest, source)
    if failures:
        print(json.dumps({"status": "failed", "failures": failures}, indent=2), flush=True)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        artifact = str(args.out.relative_to(ROOT))
    except ValueError:
        artifact = str(args.out)
    print(json.dumps({"status": "ok", "artifact": artifact}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
