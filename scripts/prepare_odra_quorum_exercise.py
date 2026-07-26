#!/usr/bin/env python3
"""Prepare a spend-free Odra M-of-N quorum exercise packet.

This does not broadcast Casper transactions. It validates the typed argument
sets for the quorum-enabled `GovernanceReceipt` flow and, when signer public
keys plus a package hash are supplied, emits wallet-ready unsigned deploy JSON
for the non-server approval steps.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shared.casper_executor import build_unsigned_odra_call_deploy  # noqa: E402

DEFAULT_OUT = ROOT / "artifacts" / "live" / "odra-quorum-exercise-plan.json"
CANONICAL_RECEIPT_PROOF = ROOT / "artifacts" / "live" / "casper-final-receipt-proof.json"
DEFAULT_PROPOSAL_ID = "DAO-PROP-6CB25C"
DEFAULT_CHROME_SIGNER = "02033c3b4d6eddae1be00f87e635aebe26a1cb5125ec8d09be1e95297208c5754ce1"


def sha256_hex(payload: Any) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def receipt_roots() -> dict[str, str]:
    proof = json.loads(CANONICAL_RECEIPT_PROOF.read_text(encoding="utf-8"))
    return {
        "policy_hash": str(proof["policy_hash"]),
        "final_card_hash": str(proof["final_card_hash"]),
        "plan_hash": str(proof["plan_hash"]),
        "dissent_hash": str(proof["dissent_hash"]),
        "proposal_hash": str(proof["proposal_hash"]),
        "agent_action_hash": str(proof["agent_action_hash"]),
    }


def envelope(proposal_id: str) -> dict[str, Any]:
    roots = receipt_roots()
    return {
        "proposal_id": proposal_id,
        "decision": "APPROVED_WITH_LIMITS",
        "approved_allocation_bps": 800,
        "policy_hash": roots["policy_hash"],
        "dissent_hash": roots["dissent_hash"],
        "final_card_hash": roots["final_card_hash"],
        "plan_hash": roots["plan_hash"],
    }


def call_specs(proposal_id: str, server_signer: str, chrome_signer: str, web_signer: str) -> list[dict[str, Any]]:
    roots = receipt_roots()
    envelope_hash = sha256_hex(envelope(proposal_id))
    return [
        {
            "step": "configure_quorum",
            "signer": "server",
            "entry_point": "configure_quorum",
            "expected": "quorum registry configured with threshold 2",
            "args": {
                "signer_a": {"cl_type": "Address", "value": server_signer},
                "signer_b": {"cl_type": "Address", "value": chrome_signer},
                "signer_c": {"cl_type": "Address", "value": web_signer},
                "threshold": {"cl_type": "U32", "value": 2},
            },
        },
        {
            "step": "propose_envelope",
            "signer": "server",
            "entry_point": "propose_envelope",
            "expected": "exact approved envelope root proposed",
            "args": {
                "proposal_id": {"cl_type": "String", "value": proposal_id},
                "envelope_hash": {"cl_type": {"ByteArray": 32}, "value": envelope_hash},
            },
        },
        {
            "step": "pre_quorum_store_governance_receipt",
            "signer": "server",
            "entry_point": "store_governance_receipt",
            "expected": "reverts with QuorumNotMet before two approvals",
            "expected_failure": True,
            "args": receipt_args(proposal_id),
        },
        {
            "step": "approve_envelope_server",
            "signer": "server",
            "entry_point": "approve_envelope",
            "expected": "approval count becomes 1 of 2",
            "args": {"proposal_id": {"cl_type": "String", "value": proposal_id}},
        },
        {
            "step": "approve_envelope_chrome_wallet",
            "signer": "chrome_wallet",
            "entry_point": "approve_envelope",
            "expected": "approval count becomes 2 of 2",
            "args": {"proposal_id": {"cl_type": "String", "value": proposal_id}},
        },
        {
            "step": "final_store_governance_receipt",
            "signer": "server",
            "entry_point": "store_governance_receipt",
            "expected": "receipt stores after quorum threshold is met",
            "args": receipt_args(proposal_id),
        },
    ]


def receipt_args(proposal_id: str) -> dict[str, dict[str, Any]]:
    roots = receipt_roots()
    return {
        "proposal_id": {"cl_type": "String", "value": proposal_id},
        "proposal_type": {"cl_type": "String", "value": "DEFI_TREASURY_REALLOCATION"},
        "proposal_hash": {"cl_type": {"ByteArray": 32}, "value": roots["proposal_hash"]},
        "policy_hash": {"cl_type": {"ByteArray": 32}, "value": roots["policy_hash"]},
        "dissent_hash": {"cl_type": {"ByteArray": 32}, "value": roots["dissent_hash"]},
        "final_card_hash": {"cl_type": {"ByteArray": 32}, "value": roots["final_card_hash"]},
        "plan_hash": {"cl_type": {"ByteArray": 32}, "value": roots["plan_hash"]},
        "agent_action_hash": {"cl_type": {"ByteArray": 32}, "value": roots["agent_action_hash"]},
        "approved_allocation_bps": {"cl_type": "U32", "value": 800},
        "risk_score": {"cl_type": "U32", "value": 61},
        "risk_level": {"cl_type": "String", "value": "MEDIUM"},
        "decision": {"cl_type": "String", "value": "APPROVED_WITH_LIMITS"},
        "treasury_action": {"cl_type": "String", "value": "cap_to_800_bps"},
        "policy_version": {"cl_type": "String", "value": "2026.06.cas-v1"},
        "casper_network": {"cl_type": "String", "value": "casper-test"},
        "agent_council_version": {"cl_type": "String", "value": "concordia-dao-council-2026.06"},
        "evidence_uri": {
            "cl_type": "String",
            "value": "ipfs://bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq",
        },
    }


def maybe_unsigned_wallet_payload(
    *,
    step: dict[str, Any],
    package_hash: str,
    package_version: int,
    chrome_signer: str,
) -> dict[str, Any] | None:
    if step["signer"] != "chrome_wallet":
        return None
    return build_unsigned_odra_call_deploy(
        signer_public_key=chrome_signer,
        contract_hash=package_hash,
        entry_point=step["entry_point"],
        argument_specs=step["args"],
        call_target="package",
        contract_version=package_version,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proposal-id", default=DEFAULT_PROPOSAL_ID)
    parser.add_argument("--server-signer", default=os.getenv("CONCORDIA_SERVER_SIGNER_PUBLIC_KEY", ""))
    parser.add_argument("--chrome-signer", default=os.getenv("CONCORDIA_CHROME_SIGNER_PUBLIC_KEY", DEFAULT_CHROME_SIGNER))
    parser.add_argument("--web-signer", default=os.getenv("CONCORDIA_WEB_SIGNER_PUBLIC_KEY", ""))
    parser.add_argument("--package-hash", default=os.getenv("CASPER_QUORUM_PACKAGE_HASH", "hash-" + ("1" * 64)))
    parser.add_argument("--package-version", type=int, default=int(os.getenv("CASPER_QUORUM_CONTRACT_VERSION", "1")))
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    if not args.out.is_absolute():
        args.out = ROOT / args.out

    missing = [
        name for name, value in {
            "server_signer": args.server_signer,
            "chrome_signer": args.chrome_signer,
            "web_signer": args.web_signer,
        }.items()
        if not value
    ]
    status = "ready" if not missing else "needs_signer_public_keys"
    steps = call_specs(args.proposal_id, args.server_signer or args.chrome_signer, args.chrome_signer, args.web_signer or args.chrome_signer)
    for step in steps:
        payload = maybe_unsigned_wallet_payload(
            step=step,
            package_hash=args.package_hash,
            package_version=args.package_version,
            chrome_signer=args.chrome_signer,
        )
        if payload:
            step["wallet_payload_status"] = payload.get("status")
            step["wallet_deploy_hash"] = payload.get("deploy_hash")
            step["wallet_payload"] = payload

    packet = {
        "schema": "concordia.odra-quorum-exercise-plan.v1",
        "status": status,
        "spends_cspr": False,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "proposal_id": args.proposal_id,
        "package_hash": args.package_hash,
        "package_version": args.package_version,
        "missing": missing,
        "signers": {
            "server": args.server_signer or None,
            "chrome_wallet": args.chrome_signer or None,
            "web_wallet": args.web_signer or None,
            "threshold": 2,
        },
        "envelope_hash": sha256_hex(envelope(args.proposal_id)),
        "steps": steps,
        "next_live_steps": [
            "Deploy the quorum-enabled GovernanceReceipt package to Casper Testnet.",
            "Configure CASPER_QUORUM_PACKAGE_HASH to the new package hash.",
            "Broadcast configure_quorum, propose_envelope, and the server approval with the VM signer.",
            "Have the Chrome wallet signer approve the emitted approve_envelope payload.",
            "Broadcast final store_governance_receipt only after quorum_status reports 2/2 approvals.",
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": status, "artifact": str(args.out.relative_to(ROOT)), "missing": missing}, indent=2))
    return 0 if status == "ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())
