"""Supplemental dynamic proof artifact helpers.

The canonical reviewer proof remains immutable.  This module only exposes
artifact-backed supplemental runs, so non-canonical proposals can demonstrate
the reusable receipt packager without rewriting the historical proof chain.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


DYNAMIC_PROPOSAL_ID = "DAO-PROP-DYN-002"
DEFAULT_DYNAMIC_PROOF_PATH = Path("artifacts/live/dynamic-proposal-execution-proof.json")
DEFAULT_DYNAMIC_EVIDENCE_PATH = Path(f"artifacts/live/dynamic-evidence-{DYNAMIC_PROPOSAL_ID}.json")


def dynamic_proof_path() -> Path:
    return Path(os.getenv("CONCORDIA_DYNAMIC_PROOF_PATH", str(DEFAULT_DYNAMIC_PROOF_PATH)))


def dynamic_evidence_path() -> Path:
    return Path(os.getenv("CONCORDIA_DYNAMIC_EVIDENCE_PATH", str(DEFAULT_DYNAMIC_EVIDENCE_PATH)))


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _candidate_evidence_paths(proposal_id: str) -> list[Path]:
    """Return dynamic evidence locations, most specific first."""

    specific = Path("artifacts/live") / f"dynamic-evidence-{proposal_id}.json"
    paths = [specific, dynamic_evidence_path(), DEFAULT_DYNAMIC_EVIDENCE_PATH]
    seen: set[str] = set()
    unique: list[Path] = []
    for path in paths:
        key = str(path)
        if key not in seen:
            unique.append(path)
            seen.add(key)
    return unique


def _candidate_proof_paths(proposal_id: str) -> list[Path]:
    """Return dynamic execution proof locations, most specific first."""

    specific = Path("artifacts/live") / f"dynamic-proposal-execution-proof-{proposal_id}.json"
    paths = [specific, dynamic_proof_path(), DEFAULT_DYNAMIC_PROOF_PATH]
    seen: set[str] = set()
    unique: list[Path] = []
    for path in paths:
        key = str(path)
        if key not in seen:
            unique.append(path)
            seen.add(key)
    return unique


def load_dynamic_evidence(proposal_id: str) -> dict[str, Any] | None:
    """Return sealed supplemental evidence when it matches the requested proposal."""

    for path in _candidate_evidence_paths(proposal_id):
        evidence = _read_json(path)
        if not evidence or evidence.get("proposal_id") != proposal_id:
            continue
        if evidence.get("chain_valid") is not True:
            continue
        return evidence
    return None


def load_dynamic_execution_proof(proposal_id: str) -> dict[str, Any] | None:
    """Return supplemental execution proof metadata for the requested proposal."""

    for path in _candidate_proof_paths(proposal_id):
        proof = _read_json(path)
        if not proof or proof.get("proposal_id") != proposal_id:
            continue
        return proof
    return None


def dynamic_proof_is_processed(proof: dict[str, Any] | None) -> bool:
    if not isinstance(proof, dict):
        return False
    return str(proof.get("status") or "").lower() == "processed"


def merge_dynamic_receipt(evidence: dict[str, Any], proof: dict[str, Any] | None) -> dict[str, Any]:
    """Merge processed supplemental proof fields into an evidence export.

    The merge is conservative: it only overlays the Casper receipt block, so the
    card chain and chain validation state remain the original sealed evidence.
    """

    if not dynamic_proof_is_processed(proof):
        return evidence
    typed_runtime_args = proof.get("typed_runtime_args")
    if not isinstance(typed_runtime_args, dict) or not typed_runtime_args:
        return evidence
    receipt = dict(evidence.get("casper_receipt") or {})
    receipt.update(
        {
            "proposal_id": evidence.get("proposal_id"),
            "deploy_hash": proof.get("deploy_hash") or proof.get("transaction_hash"),
            "transaction_hash": proof.get("transaction_hash") or proof.get("deploy_hash"),
            "contract_hash": proof.get("contract_hash") or receipt.get("contract_hash"),
            "entry_point": proof.get("entry_point") or receipt.get("entry_point") or "store_governance_receipt",
            "status": proof.get("status"),
            "typed_args": typed_runtime_args,
            "proposal_hash": _typed_value(typed_runtime_args, "proposal_hash") or receipt.get("proposal_hash"),
            "policy_hash": _typed_value(typed_runtime_args, "policy_hash") or receipt.get("policy_hash"),
            "dissent_hash": _typed_value(typed_runtime_args, "dissent_hash") or receipt.get("dissent_hash"),
            "final_card_hash": _typed_value(typed_runtime_args, "final_card_hash") or receipt.get("final_card_hash"),
            "plan_hash": _typed_value(typed_runtime_args, "plan_hash") or receipt.get("plan_hash"),
            "agent_action_hash": _typed_value(typed_runtime_args, "agent_action_hash") or receipt.get("agent_action_hash"),
            "approved_allocation_bps": _typed_value(typed_runtime_args, "approved_allocation_bps")
            or receipt.get("approved_allocation_bps"),
            "risk_score": _typed_value(typed_runtime_args, "risk_score") or receipt.get("risk_score"),
            "decision": _typed_value(typed_runtime_args, "decision") or receipt.get("decision"),
            "risk_level": _typed_value(typed_runtime_args, "risk_level") or receipt.get("risk_level"),
        }
    )
    merged = dict(evidence)
    merged["casper_receipt"] = receipt
    merged["supplemental_dynamic_proof"] = {
        "status": proof.get("status"),
        "proposal_id": proof.get("proposal_id"),
        "deploy_hash": proof.get("deploy_hash") or proof.get("transaction_hash"),
        "proof_path": str(dynamic_proof_path()),
        "scope": "supplemental_dynamic_run",
    }
    return merged


def _typed_value(typed_runtime_args: dict[str, Any], name: str) -> Any:
    spec = typed_runtime_args.get(name)
    if isinstance(spec, dict):
        return spec.get("value")
    return None
