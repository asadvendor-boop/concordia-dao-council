"""Deterministic governance archive builder.

Concordia Core builds the structured archive and Locke seals it inside the
CasperExecutionReceipt after Casper success. Wells is presentation-only; the
authority-bearing archive never depends on an optional persona or model turn.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any


def _hash_payload(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _observed_at(timeline: list[dict[str, Any]]) -> str:
    """Return the latest input event time as canonical UTC-Z.

    The archive timestamp is part of its hash. Deriving it from the sealed
    input timeline keeps repeated builds byte-stable; silently substituting the
    wall clock would make the same evidence produce different archives.
    """

    for item in reversed(timeline):
        raw = item.get("timestamp")
        if not isinstance(raw, str) or not raw.strip():
            continue
        try:
            parsed = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("archive requires a valid UTC timeline timestamp") from exc
        if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
            raise ValueError("archive requires a valid UTC timeline timestamp")
        return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")
    raise ValueError("archive requires a valid UTC timeline timestamp")


def build_governance_archive(
    *,
    proposal_id: str,
    actions_taken: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build Core's deterministic archive for Locke to seal."""
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
        "created_by": "Concordia Core",
        "sealed_by": "Locke",
        "presentation_persona": "Wells",
        "created_at": _observed_at(timeline),
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
