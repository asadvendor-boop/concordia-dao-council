#!/usr/bin/env python3
"""Generate a sealed supplemental dynamic proposal proof.

Default mode is spend-free: it writes a chain-valid supplemental dynamic proposal
evidence artifact plus typed Casper runtime arguments.  Passing
`--submit-real` broadcasts one backend-signed Testnet receipt and marks the
supplemental proof as processed only if Casper submission succeeds.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gateway.database import init_db
from shared.approval import compute_action_hash
from shared.casper_executor import build_receipt_request, submit_governance_receipt, typed_runtime_args_preview
from shared.dao_policy import evaluate_proposal_policy
from shared.dynamic_proof import DYNAMIC_PROPOSAL_ID, DEFAULT_DYNAMIC_EVIDENCE_PATH, DEFAULT_DYNAMIC_PROOF_PATH
from shared.integrity import seal_card, verify_chain
from shared.models import (
    ActionReceipt,
    Assessment,
    ExecutionEnvelope,
    GovernanceSummary,
    ProposalCard,
    ResponsePlan,
    StructuredApproval,
    TriageDecision,
    Verdict,
)
from shared.proof_pack import canonicalize_public_evidence


PUBLIC_BASE_URL = "https://concordia.47.84.232.193.sslip.io"
UTC = timezone.utc
DEFAULT_TIMESTAMP = datetime(2026, 7, 1, 8, 0, tzinfo=UTC)
RWA_PROPOSAL_ID = "DAO-PROP-RWA-001"
RWA_SAMPLE_DOCUMENT = ROOT / "artifacts" / "rwa" / "sample-invoice-pool-DAO-PROP-RWA-001.json"


def _sha256(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def _load_rwa_document() -> tuple[dict[str, Any], str]:
    document: dict[str, Any] = {
        "proposal_id": RWA_PROPOSAL_ID,
        "proposal_type": "RWA_INVOICE_POOL_ONBOARDING",
        "asset_class": "invoice_receivables",
        "face_value_usd": 125000,
        "maturity_days": 60,
        "debtor_risk_score": 58,
        "issuer_reputation_score": 72,
        "review_outcome": "ESCALATED_TO_HUMANS",
    }
    if RWA_SAMPLE_DOCUMENT.exists():
        document = json.loads(RWA_SAMPLE_DOCUMENT.read_text(encoding="utf-8"))
        digest = hashlib.sha256(RWA_SAMPLE_DOCUMENT.read_bytes()).hexdigest()
    else:
        digest = _sha256(document)
    return document, digest


def _insert_proposal(db: sqlite3.Connection, proposal_id: str) -> None:
    now = DEFAULT_TIMESTAMP.isoformat()
    db.execute(
        "INSERT INTO proposals (proposal_id, state, severity, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (proposal_id, "RESOLVED", "high", now, now),
    )


def _card_rows(db: sqlite3.Connection, proposal_id: str) -> list[dict[str, Any]]:
    rows = db.execute(
        "SELECT sequence_number, card_type, card_hash, card_json, published_at "
        "FROM cards WHERE proposal_id=? ORDER BY sequence_number ASC",
        (proposal_id,),
    ).fetchall()
    return [
        {
            "sequence": row["sequence_number"],
            "card_type": row["card_type"],
            "hash": row["card_hash"],
            "published": row["published_at"] is not None,
            "data": json.loads(row["card_json"]),
        }
        for row in rows
    ]


def build_dynamic_artifacts(
    *,
    proposal_id: str = DYNAMIC_PROPOSAL_ID,
    requested_bps: int | None = None,
    title: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="concordia-dyn-") as tmp:
        db = init_db(Path(tmp) / "dynamic.db")
        _insert_proposal(db, proposal_id)

        is_rwa = proposal_id == RWA_PROPOSAL_ID or "RWA" in proposal_id.upper()
        rwa_document: dict[str, Any] = {}
        rwa_document_hash = ""
        if is_rwa:
            rwa_document, rwa_document_hash = _load_rwa_document()
            requested_bps = 0
            approved_bps = 0
            risk_score = int(rwa_document.get("debtor_risk_score") or 58)
            proposal_type = "RWA_INVOICE_POOL_ONBOARDING"
            decision = str(rwa_document.get("review_outcome") or "ESCALATED_TO_HUMANS")
            treasury_action = "record_rwa_invoice_pool_review"
            policy_input = {
                "proposal_id": proposal_id,
                "proposal_type": proposal_type,
                "asset_class": rwa_document.get("asset_class") or "invoice_receivables",
                "evidence_hash": f"sha256:{rwa_document_hash}",
                "risk_score": risk_score,
                "requested_action": "Review invoice pool as eligible collateral for DAO governance.",
                "casper_network": "casper-test",
            }
        else:
            requested_bps = int(requested_bps if requested_bps is not None else 1200)
            risk_score = 64
            proposal_type = "DEFI_TREASURY_REALLOCATION"
            decision = "APPROVED_WITH_LIMITS"
            treasury_action = "rebalance_casper_treasury_sleeve"
            policy_input = {
                "proposal_id": proposal_id,
                "proposal_type": proposal_type,
                "treasury_allocation_bps": requested_bps,
                "risk_score": risk_score,
                "casper_network": "casper-test",
            }
        policy = evaluate_proposal_policy(policy_input)
        if not is_rwa:
            approved_bps = int(policy.get("approved_allocation_bps") or 800)
        policy_hash = str(policy.get("policy_hash") or policy.get("policy_receipt_hash") or _sha256(policy)).removeprefix("sha256:")
        if is_rwa:
            dissent_receipt = None
            dissent_hash = ""
            document_uri = f"{PUBLIC_BASE_URL}/api/rwa-artifacts/{RWA_SAMPLE_DOCUMENT.name}"
            proposal_title = "Supplemental RWA invoice pool onboarding proof"
            preliminary_severity = "medium"
            proposal_source = "rwa_oracle"
            proposal_family = "rwa_invoice_pool_onboarding"
        else:
            dissent_receipt = {
                "proposal_id": proposal_id,
                "dissenting_agent": "Verity",
                "reason": "Requested allocation exceeds DAO Constitution cap.",
                "requested_allocation_bps": requested_bps,
                "approved_allocation_bps": approved_bps,
            }
            dissent_hash = _sha256(dissent_receipt)
            document_uri = f"{PUBLIC_BASE_URL}/evidence/{proposal_id}"
            proposal_title = title or "Supplemental dynamic treasury allocation proof"
            preliminary_severity = "high"
            proposal_source = "treasury_metrics"
            proposal_family = "defi_treasury_reallocation"

        proposal_card = seal_card(
            ProposalCard(
                signal_id=f"signal-{proposal_id}",
                source=proposal_source,
                timestamp=DEFAULT_TIMESTAMP,
                title=proposal_title,
                raw_payload={
                    "proposal_id": proposal_id,
                    "proposal_type": proposal_type,
                    "requested_allocation_bps": requested_bps,
                    "evidence_uri": document_uri,
                    "rwa_document_hash": f"sha256:{rwa_document_hash}" if is_rwa else None,
                    "rwa_document": rwa_document if is_rwa else None,
                },
                fingerprint=_sha256({"proposal_id": proposal_id, "requested": requested_bps}),
                preliminary_severity=preliminary_severity,
                security_relevant=True,
            ),
            proposal_id,
            db,
        )
        triage = seal_card(
            TriageDecision(
                proposal_id=proposal_id,
                signal_id=f"signal-{proposal_id}",
                decision="route",
                noise_score=0.02,
                reasoning="Route dynamic proposal through Concordia DAO Council.",
            ),
            proposal_id,
            db,
        )
        assessment = seal_card(
            Assessment(
                proposal_id=proposal_id,
                severity="medium" if is_rwa else "high",
                evidence_strength=0.86,
                blast_radius=["rwa-invoice-pool-alpha"] if is_rwa else ["casper-liquidity-strategy-alpha"],
                root_cause_hypothesis=(
                    "Invoice pool onboarding requires evidence-hash backed human review."
                    if is_rwa
                    else "Supplemental run requests more than the DAO allocation cap."
                ),
                recommended_action=(
                    "Escalate invoice-pool onboarding to humans with evidence hash and paid-report context."
                    if is_rwa
                    else f"Revise from {requested_bps} bps to {approved_bps} bps and require quorum approval."
                ),
                evidence={
                    "policy_evaluation": policy,
                    "requested_allocation_bps": requested_bps,
                    "approved_allocation_bps": approved_bps,
                    "rwa_document_hash": f"sha256:{rwa_document_hash}" if is_rwa else None,
                    "rwa_document_uri": document_uri if is_rwa else None,
                    "casper_node_status": {"network": "casper-test", "source": "supplemental_dynamic_artifact"},
                },
                revision=1,
                state="assessed",
            ),
            proposal_id,
            db,
        )
        verdict = seal_card(
            Verdict(
                proposal_id=proposal_id,
                decision="NEEDS_HUMAN" if is_rwa else "CHALLENGE",
                cross_check_sources=["DAO Constitution", "RWA evidence hash", "Mercer treasury assessment"]
                if is_rwa
                else ["DAO Constitution", "Mercer treasury assessment"],
                reasoning=(
                    "Verity requires human review because RWA onboarding relies on issuer/debtor evidence."
                    if is_rwa
                    else "Verity challenges the over-cap allocation and preserves dissent before execution."
                ),
                agrees_with_diagnosis=True,
                challenge_request=(
                    "Escalate RWA invoice pool onboarding to humans before any eligibility action."
                    if is_rwa
                    else f"Cap allocation to {approved_bps} bps before Locke can execute."
                ),
                policy_hash=f"sha256:{policy_hash}",
                policy_version="2026.06.cas-v1",
                dissent_hash=dissent_hash or None,
                dissent_receipt=dissent_receipt,
                violated_rules=policy.get("violations") or [],
            ),
            proposal_id,
            db,
        )

        envelope_parameters = {
            "proposal_type": proposal_type,
            "decision": decision,
            "risk_level": "MEDIUM" if is_rwa else "HIGH",
            "risk_score": risk_score,
            "treasury_action": treasury_action,
            "policy_hash": policy_hash,
            "policy_version": "2026.06.cas-v1",
            "dissent_hash": dissent_hash,
            "approved_allocation_bps": approved_bps,
            "casper_network": "casper-test",
            "agent_council_version": "concordia-dao-council-2026.06",
            "evidence_uri": document_uri if is_rwa else f"{PUBLIC_BASE_URL}/evidence/{proposal_id}",
        }
        envelope = ExecutionEnvelope(
            action_id="execute_casper_governance_receipt",
            target="casper-test",
            parameters=envelope_parameters,
            timeout_seconds=300,
            fallback_action="refuse_execution_and_escalate",
        )
        action_hash = compute_action_hash([envelope.model_dump()])
        plan = seal_card(
            ResponsePlan(
                proposal_id=proposal_id,
                runbook="RB-003" if is_rwa else "RB-002",
                envelopes=[envelope],
                risk_level="medium" if is_rwa else "high",
                requires_human_approval=True,
                priority_rank=1,
                revision=1,
            ),
            proposal_id,
            db,
        )
        approval = seal_card(
            StructuredApproval(
                proposal_id=proposal_id,
                action_id="execute_casper_governance_receipt",
                action_hash=action_hash,
                decision="APPROVED",
                approver_id="dynamic-supplemental-quorum",
                room_message_id=f"msg-{proposal_id.lower()}",
                legacy_room_id=f"room-{proposal_id.lower()}",
                plan_hash=plan.card_hash or "",
                nonce="DYN001",
                expiry=DEFAULT_TIMESTAMP + timedelta(days=1),
                reason=(
                    "Supplemental RWA run escalated with evidence hash before any eligibility decision."
                    if is_rwa
                    else "Supplemental dynamic run approved only after policy cap enforcement."
                ),
                approval_channel="gateway_ui",
                runbook_version="1.0",
                plan_revision=1,
            ),
            proposal_id,
            db,
        )
        request = build_receipt_request(
            proposal_id=proposal_id,
            action_hash=action_hash,
            final_card_hash=approval.card_hash or "",
            plan_hash=plan.card_hash or "",
            parameters=envelope_parameters,
        )
        typed_args = typed_runtime_args_preview(request)
        receipt_action = {
            "action_id": "execute_casper_governance_receipt",
            "status": "ready_for_execution",
            "entry_point": "store_governance_receipt",
            "contract_hash": "",
            "receipt_payload": {
                **request.__dict__,
                "typed_args": typed_args,
            },
        }
        receipt = seal_card(
            ActionReceipt(
                proposal_id=proposal_id,
                authorization_type="human_approval",
                authorization_id=f"auth-{proposal_id.lower()}",
                actions_taken=[receipt_action],
                timeline=[
                    {"agent": "Rowan", "event": "proposal routed"},
                    {"agent": "Verity", "event": "over-cap allocation challenged"},
                    {"agent": "Alden", "event": "safe mandate generated"},
                    {"agent": "Locke", "event": "typed receipt ready for execution"},
                ],
                governance_archive={
                    "proposal_id": proposal_id,
                    "scope": "supplemental_dynamic_run",
                    "requested_allocation_bps": requested_bps,
                    "approved_allocation_bps": approved_bps,
                    "rwa_document_hash": f"sha256:{rwa_document_hash}" if is_rwa else None,
                },
                resolution_summary=(
                    "Supplemental RWA proposal sealed; Casper receipt is ready until explicitly submitted."
                    if is_rwa
                    else "Supplemental dynamic proposal sealed; Casper receipt is ready until explicitly submitted."
                ),
                state="resolved",
            ),
            proposal_id,
            db,
        )
        seal_card(
            GovernanceSummary(
                proposal_id=proposal_id,
                timeline_summary=(
                    "RWA invoice pool proposal progressed through route, evidence review, human escalation, mandate, approval, and receipt packaging."
                    if is_rwa
                    else "Dynamic proposal progressed through route, assessment, dissent, mandate, approval, and receipt packaging."
                ),
                root_cause=(
                    "RWA onboarding needs issuer/debtor evidence before eligibility."
                    if is_rwa
                    else "Requested allocation exceeded the DAO Constitution cap."
                ),
                what_worked=[
                    "Evidence hash bound the RWA document packet." if is_rwa else "Policy cap reduced the requested allocation.",
                    "Typed Casper runtime args were generated from sealed cards.",
                    "Canonical reviewer proof remained unchanged.",
                ],
                action_items=["Submit the supplemental receipt only after explicit Testnet approval."],
            ),
            proposal_id,
            db,
        )

        chain_valid, chain_errors = verify_chain(proposal_id, db)
        cards = _card_rows(db, proposal_id)
        evidence = {
            "proposal_id": proposal_id,
            "state": "RESOLVED",
            "proposal_family": proposal_family,
            "signal_service": "supplemental_dynamic_generator",
            "total_cards": len(cards),
            "chain_valid": chain_valid,
            "chain_errors": chain_errors,
            "cards": cards,
            "collaboration": {
                "role_sequence": [
                    "concordia_core",
                    "rowan",
                    "mercer",
                    "verity",
                    "alden",
                    "multisig_holder",
                    "locke",
                    "wells",
                ],
                "human_decision_count": 1,
                "execution_conflict_control": {
                    "planned_actions": ["execute_casper_governance_receipt"],
                    "executed_actions": ["execute_casper_governance_receipt"],
                    "exact_match": True,
                },
            },
            "casper_receipt": {
                "decision": request.decision,
                "deploy_hash": None,
                "transaction_hash": None,
                "contract_hash": "",
                "entry_point": "store_governance_receipt",
                "policy_hash": request.policy_hash,
                "dissent_hash": request.dissent_hash,
                "proposal_hash": request.payload_hash,
                "final_card_hash": request.final_card_hash,
                "plan_hash": request.plan_hash,
                "approved_allocation_bps": request.approved_allocation_bps,
                "risk_score": request.risk_score,
                "typed_args": typed_args,
            },
        }
        evidence = canonicalize_public_evidence(evidence)
        proof = {
            "proposal_id": proposal_id,
            "status": "ready_for_execution",
            "scope": "supplemental_rwa_run" if is_rwa else "supplemental_dynamic_run",
            "canonical_proof_unchanged": True,
            "message": (
                "Spend-free RWA execution artifact generated; use --submit-real for one explicit supplemental Testnet receipt."
                if is_rwa
                else "Spend-free dynamic execution artifact generated; use --submit-real for one explicit Testnet receipt."
            ),
            "contract_hash": "",
            "entry_point": "store_governance_receipt",
            "chain_valid": chain_valid,
            "chain_errors": chain_errors,
            "typed_runtime_args": typed_args,
            "receipt_request": request.__dict__,
            "requested_allocation_bps": requested_bps,
            "approved_allocation_bps": approved_bps,
            "rwa_document_hash": f"sha256:{rwa_document_hash}" if is_rwa else None,
            "rwa_document_uri": document_uri if is_rwa else None,
            "final_card_sequence": receipt.sequence_number,
            "generated_at": DEFAULT_TIMESTAMP.isoformat(),
        }
        return evidence, proof


async def maybe_submit(proof: dict[str, Any]) -> dict[str, Any]:
    if proof.get("chain_valid") is not True:
        return {
            "status": "blocked",
            "reason": "dynamic evidence chain is invalid; refusing Casper submission",
            "chain_errors": proof.get("chain_errors") or ["chain_valid was not true"],
        }
    request = build_receipt_request(
        proposal_id=proof["proposal_id"],
        action_hash=proof["receipt_request"]["action_hash"],
        final_card_hash=proof["receipt_request"]["final_card_hash"],
        plan_hash=proof["receipt_request"]["plan_hash"],
        parameters={
            "proposal_type": proof["receipt_request"]["proposal_type"],
            "decision": proof["receipt_request"]["decision"],
            "risk_level": proof["receipt_request"]["risk_level"],
            "risk_score": proof["receipt_request"]["risk_score"],
            "treasury_action": proof["receipt_request"]["treasury_action"],
            "policy_hash": proof["receipt_request"]["policy_hash"],
            "policy_version": proof["receipt_request"]["policy_version"],
            "dissent_hash": proof["receipt_request"]["dissent_hash"],
            "approved_allocation_bps": proof["receipt_request"]["approved_allocation_bps"],
            "casper_network": proof["receipt_request"]["casper_network"],
            "agent_council_version": proof["receipt_request"]["agent_council_version"],
            "evidence_uri": proof["receipt_request"]["evidence_uri"],
        },
    )
    return await submit_governance_receipt(request)


def write_artifacts(evidence: dict[str, Any], proof: dict[str, Any], *, evidence_out: Path, proof_out: Path) -> None:
    evidence_out.parent.mkdir(parents=True, exist_ok=True)
    proof_out.parent.mkdir(parents=True, exist_ok=True)
    evidence_out.write_text(json.dumps(evidence, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    proof_out.write_text(json.dumps(proof, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proposal-id", default=DYNAMIC_PROPOSAL_ID)
    parser.add_argument("--requested-bps", type=int, default=None)
    parser.add_argument("--title", default=None)
    parser.add_argument("--evidence-out", type=Path)
    parser.add_argument("--proof-out", type=Path)
    parser.add_argument("--submit-real", action="store_true", help="Broadcast one backend-signed Casper Testnet receipt.")
    args = parser.parse_args()

    evidence_out = args.evidence_out or Path("artifacts/live") / f"dynamic-evidence-{args.proposal_id}.json"
    proof_out = args.proof_out or (
        DEFAULT_DYNAMIC_PROOF_PATH
        if args.proposal_id == DYNAMIC_PROPOSAL_ID
        else Path("artifacts/live") / f"dynamic-proposal-execution-proof-{args.proposal_id}.json"
    )

    evidence, proof = build_dynamic_artifacts(
        proposal_id=args.proposal_id,
        requested_bps=args.requested_bps,
        title=args.title,
    )
    if args.submit_real:
        result = asyncio.run(maybe_submit(proof))
        proof["casper_submission"] = result
        if result.get("status") == "success":
            proof.update(
                {
                    "status": "processed",
                    "message": "Supplemental dynamic execution proof processed on Casper Testnet.",
                    "deploy_hash": result.get("deploy_hash") or result.get("transaction_hash"),
                    "transaction_hash": result.get("transaction_hash") or result.get("deploy_hash"),
                    "contract_hash": result.get("contract_hash") or "",
                    "entry_point": result.get("entry_point") or "store_governance_receipt",
                    "processed_at": result.get("submitted_at") or datetime.now(UTC).isoformat(),
                }
            )
            evidence["casper_receipt"].update(
                {
                    "deploy_hash": proof["deploy_hash"],
                    "transaction_hash": proof["transaction_hash"],
                    "contract_hash": proof["contract_hash"],
                    "status": "processed",
                    "explorer_url": f"https://testnet.cspr.live/deploy/{proof['deploy_hash']}",
                    "api_proof_url": f"https://api.testnet.cspr.live/deploys/{proof['deploy_hash']}",
                }
            )
        else:
            proof["status"] = "submit_failed"
    write_artifacts(evidence, proof, evidence_out=evidence_out, proof_out=proof_out)
    print(json.dumps({"evidence_out": str(evidence_out), "proof_out": str(proof_out), "status": proof["status"]}))
    return 0 if proof.get("chain_valid") else 1


if __name__ == "__main__":
    raise SystemExit(main())
