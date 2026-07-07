"""DAO Constitution policy checks for Concordia.

The LLM can explain these outcomes, but it cannot override them. This module
turns proposal facts into a deterministic policy evaluation, a structured
dissent receipt, and payload fields that Locke can anchor on Casper Testnet.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


DEFAULT_CONSTITUTION = Path("config/dao_constitution.cas.json")


def to_bps_allocation(target: dict[str, float | int]) -> dict[str, list[Any]]:
    """Convert fractional treasury sleeves into exact 10,000 BPS weights.

    The allocation is sorted for deterministic contract inputs, floors each
    sleeve, then distributes leftover basis points to the largest fractional
    remainders. This removes floating-point drift before any on-chain action.
    """
    if not target:
        raise ValueError("allocation target must contain at least one sleeve")
    sleeve_ids = sorted(str(key) for key in target)
    values = [float(target[key]) for key in sleeve_ids]
    if any(not math.isfinite(value) or value < 0 for value in values):
        raise ValueError("allocation weights must be finite non-negative numbers")
    total = sum(values)
    if total <= 0:
        raise ValueError("allocation weights must sum to a positive number")
    normalized = [value / total for value in values]
    raw = [value * 10_000 for value in normalized]
    floored = [math.floor(value) for value in raw]
    remainder = 10_000 - sum(floored)
    by_fraction = sorted(
        ((index, value - math.floor(value)) for index, value in enumerate(raw)),
        key=lambda item: (-item[1], sleeve_ids[item[0]]),
    )
    for index, _fraction in by_fraction:
        if remainder <= 0:
            break
        floored[index] += 1
        remainder -= 1
    if sum(floored) != 10_000:
        raise ValueError("allocation rounding failed to reach exactly 10,000 bps")
    return {"sleeve_ids": sleeve_ids, "weights_bps": floored}


def _hash_payload(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _safe_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        match = re.search(r"-?\d+(?:\.\d+)?", value)
        if match:
            number = float(match.group(0))
            if "%" in value:
                return int(round(number * 100))
            return int(round(number))
    return default


def load_constitution() -> dict[str, Any]:
    """Load the machine-readable DAO Constitution."""
    configured = os.getenv("DAO_CONSTITUTION_PATH", "").strip()
    path = Path(configured) if configured else DEFAULT_CONSTITUTION
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def constitution_hash(constitution: dict[str, Any] | None = None) -> str:
    """Return the stable hash of the active DAO Constitution."""
    return _hash_payload(constitution or load_constitution())


def normalize_proposal_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize simulator, card, or tool payload fields into policy facts."""
    proposal_type = str(payload.get("proposal_type") or "").strip()
    requested_bps = _safe_int(
        payload.get("treasury_allocation_bps")
        or payload.get("requested_allocation_bps")
        or payload.get("allocation_bps")
        or payload.get("current_allocation")
    )
    target_protocol = str(payload.get("target_protocol") or payload.get("dao_target") or "").strip()
    asset_class = str(payload.get("asset_class") or "").strip()
    evidence_hash = str(payload.get("evidence_hash") or "").strip()

    if not proposal_type:
        text = " ".join(str(payload.get(key, "")) for key in (
            "proposal_summary",
            "requested_action",
            "recommended_action",
            "dao_target",
            "source",
        )).lower()
        if "rwa" in text or "invoice" in text or "receivable" in text:
            proposal_type = "RWA_INVOICE_POOL_ONBOARDING"
        else:
            proposal_type = "DEFI_TREASURY_REALLOCATION"

    return {
        "proposal_id": str(payload.get("proposal_id") or "").strip(),
        "proposal_type": proposal_type,
        "requested_allocation_bps": requested_bps,
        "target_protocol": target_protocol,
        "asset_class": asset_class,
        "evidence_hash": evidence_hash,
        "casper_network": str(payload.get("casper_network") or "casper-testnet"),
        "requested_action": str(payload.get("requested_action") or payload.get("proposal_summary") or "").strip(),
        "risk_score": _safe_int(payload.get("risk_score") or payload.get("risk_exposure_pct"), default=0),
    }


def evaluate_proposal_policy(
    payload: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Evaluate a proposal against the DAO Constitution.

    Returns a serializable policy evaluation with a Dissent Receipt when the
    proposal violates policy. The dissent hash is still returned in the final
    approved path so judges can see that unsafe intent was preserved.
    """
    constitution = load_constitution()
    facts = normalize_proposal_payload(payload)
    policy_hash = constitution_hash(constitution)
    proposal_hash = _hash_payload(payload)
    max_single = int(constitution.get("max_single_allocation_bps", 0))
    requires_rwa_hash = bool(constitution.get("requires_rwa_evidence_hash", True))
    requested_bps = int(facts["requested_allocation_bps"] or 0)
    approved_bps = requested_bps if requested_bps else max_single

    violated_rules: list[dict[str, Any]] = []
    if facts["proposal_type"] == "DEFI_TREASURY_REALLOCATION" and requested_bps > max_single:
        approved_bps = max_single
        violated_rules.append({
            "rule_id": "MAX_SINGLE_ALLOCATION_BPS",
            "severity": "HIGH",
            "observed": requested_bps,
            "allowed": max_single,
            "message": f"Requested allocation {requested_bps} bps exceeds {max_single} bps DAO cap.",
        })

    if facts["proposal_type"] == "RWA_INVOICE_POOL_ONBOARDING" and requires_rwa_hash and not facts["evidence_hash"]:
        violated_rules.append({
            "rule_id": "RWA_EVIDENCE_HASH_REQUIRED",
            "severity": "HIGH",
            "observed": "missing",
            "allowed": "sha256 evidence hash",
            "message": "RWA onboarding requires an evidence hash before approval.",
        })

    decision = "APPROVED_WITH_LIMITS" if violated_rules and facts["proposal_type"] == "DEFI_TREASURY_REALLOCATION" else "APPROVED"
    if violated_rules and facts["proposal_type"] == "RWA_INVOICE_POOL_ONBOARDING":
        decision = "NEEDS_HUMAN"

    dissent_receipt = {
        "proposal_id": facts["proposal_id"],
        "dissenting_agent": "Verity",
        "dissent_type": violated_rules[0]["rule_id"] if violated_rules else "NONE",
        "policy_hash": policy_hash,
        "policy_version": constitution.get("policy_version", ""),
        "proposal_hash": proposal_hash,
        "challenged_plan_hash": _hash_payload({
            "requested_allocation_bps": requested_bps,
            "target_protocol": facts["target_protocol"],
            "proposal_type": facts["proposal_type"],
        }),
        "reason_hash": _hash_payload([rule["message"] for rule in violated_rules]),
        "severity": "HIGH" if violated_rules else "LOW",
        "violated_rules": violated_rules,
        "created_at": (now or datetime.now(UTC)).isoformat(),
    }
    dissent_hash = _hash_payload(dissent_receipt) if violated_rules else ""

    return {
        "dao_name": constitution.get("dao_name", "Concordia Treasury DAO"),
        "policy_version": constitution.get("policy_version", ""),
        "policy_hash": policy_hash,
        "proposal_hash": proposal_hash,
        "proposal_type": facts["proposal_type"],
        "requested_allocation_bps": requested_bps,
        "approved_allocation_bps": approved_bps,
        "allowed_execution_network": constitution.get("allowed_execution_network", "casper-test"),
        "allowed_receipt_entry_point": constitution.get("allowed_receipt_entry_point", "store_governance_receipt"),
        "risk_score": facts["risk_score"],
        "risk_level": _risk_level(facts["risk_score"], violated_rules, constitution),
        "decision": decision,
        "passed": not violated_rules,
        "violated_rules": violated_rules,
        "dissent_receipt": dissent_receipt if violated_rules else None,
        "dissent_hash": dissent_hash,
        "human_approval_required": bool(constitution.get("requires_multisig_for_execution", True)),
    }


def _risk_level(score: int, violated_rules: list[dict[str, Any]], constitution: dict[str, Any]) -> str:
    if violated_rules:
        return "HIGH"
    thresholds = constitution.get("risk_thresholds", {})
    high = int(thresholds.get("high", 85))
    medium = int(thresholds.get("medium", 65))
    low = int(thresholds.get("low", 35))
    if score >= high:
        return "HIGH"
    if score >= medium:
        return "MEDIUM"
    if score >= low:
        return "LOW"
    return "INFO"


def evidence_uri_for(proposal_id: str) -> str:
    """Return a public evidence URL when PUBLIC_BASE_URL is configured."""
    base_url = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
    if base_url:
        return f"{base_url}/evidence/{proposal_id}"
    return f"/evidence/{proposal_id}"
