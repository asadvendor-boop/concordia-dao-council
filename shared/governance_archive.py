"""Deterministic Wells governance archive builder.

Wells can still provide narrative enrichment, but the judge-facing archive must
not depend on an optional chat turn. This module creates the structured archive
that is embedded in Locke's sealed CasperExecutionReceipt after Casper success.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any


def _hash_payload(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_governance_archive(
    *,
    proposal_id: str,
    actions_taken: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build Wells' terminal archive from the successful Casper action."""
    casper_action = next(
        (
            action for action in reversed(actions_taken)
            if action.get("action_id") == "execute_casper_governance_receipt"
        ),
        {},
    )
    receipt_payload = casper_action.get("receipt_payload") or {}

    archive = {
        "archive_type": "ConcordiaGovernanceArchive",
        "proposal_id": proposal_id,
        "decision": receipt_payload.get("decision", ""),
        "created_by": "Wells",
        "created_at": datetime.now(UTC).isoformat(),
        "network": casper_action.get("network") or receipt_payload.get("casper_network", "casper-test"),
        "contract_hash": casper_action.get("contract_hash", ""),
        "entry_point": casper_action.get("entry_point", "store_governance_receipt"),
        "casper_transaction_hash": casper_action.get("transaction_hash", ""),
        "proposal_hash": receipt_payload.get("payload_hash", ""),
        "final_card_hash": receipt_payload.get("final_card_hash", ""),
        "plan_hash": receipt_payload.get("plan_hash", ""),
        "policy_hash": receipt_payload.get("policy_hash", ""),
        "policy_version": receipt_payload.get("policy_version", ""),
        "dissent_hash": receipt_payload.get("dissent_hash", ""),
        "risk_level": receipt_payload.get("risk_level", ""),
        "risk_score": receipt_payload.get("risk_score", ""),
        "approved_allocation_bps": receipt_payload.get("approved_allocation_bps", ""),
        "evidence_uri": receipt_payload.get("evidence_uri", ""),
        "timeline_events": [item.get("event") for item in timeline if item.get("event")],
    }
    archive["archive_hash"] = _hash_payload(archive)
    return archive
