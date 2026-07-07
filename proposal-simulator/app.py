"""Concordia DAO proposal simulator.

This local FastAPI service supplies deterministic Casper-oriented evidence for
Council Chamber demos. The route names are intentionally stable for the existing
frontend proxy, while the data model is DAO governance, treasury risk, RWA, and
Casper Testnet execution evidence.
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import FastAPI, Request
from shared.dao_policy import evaluate_proposal_policy, evidence_uri_for

app = FastAPI(title="Concordia DAO Proposal Simulator", version="1.0.0")

SCENARIO_BY_PROPOSAL: dict[str, str] = {}
SOURCE_LABEL = "concordia_dao_simulator"

SCENARIOS: dict[str, dict[str, Any]] = {
    "treasury": {
        "name": "DeFi Treasury Reallocation Proposal",
        "source": "governance_feed",
        "preliminary_severity": "medium",
        "security_relevant": True,
        "proposal_type": "DEFI_TREASURY_REALLOCATION",
        "requested_action": "Move 30% of DAO treasury into a high-yield liquidity strategy",
        "treasury_allocation_bps": 3000,
        "approved_allocation_bps": 800,
        "target_protocol": "Simulated Casper Liquidity Pool",
        "expected_apy": 18.4,
        "liquidity_depth_score": 42,
        "impermanent_loss_risk": "HIGH",
        "risk_score": 72,
        "dao_target": "casper-liquidity-strategy-alpha",
        "current_allocation": "30% proposed treasury allocation",
        "guardrail_cap": "8% maximum policy allocation",
        "risk_exposure_pct": 72.0,
        "volatility_bps": 1180,
        "policy_compliance_pct": 61.0,
        "recommended_action": "limit exposure with treasury guardrail cap and anchor approved receipt on Casper Testnet",
        "risk_level": "high",
        "anomaly": True,
        "proposal_summary": "A DAO proposal requests moving 30% of treasury into a high-yield liquidity strategy.",
    },
    "rwa": {
        "name": "RWA Invoice Pool Onboarding Proposal",
        "source": "rwa_oracle",
        "preliminary_severity": "medium",
        "security_relevant": True,
        "proposal_type": "RWA_INVOICE_POOL_ONBOARDING",
        "requested_action": "Approve an invoice receivables pool as eligible collateral",
        "asset_class": "invoice_receivables",
        "face_value_usd": 125000,
        "maturity_days": 60,
        "debtor_risk_score": 58,
        "issuer_reputation_score": 72,
        "evidence_hash": "sha256:6b7f0d6e3e41d1a5e70a812f6f836ad91237f0d22c2f2756f0a4d09d44a04f3d",
        "risk_score": 58,
        "dao_target": "rwa-invoice-pool-alpha",
        "current_allocation": "125000 USD invoice pool onboarding",
        "guardrail_cap": "issuer evidence hash and multisig required",
        "risk_exposure_pct": 58.0,
        "volatility_bps": 390,
        "policy_compliance_pct": 76.0,
        "recommended_action": "approve with evidence-hash binding and anchor RWA receipt on Casper Testnet",
        "risk_level": "medium",
        "anomaly": True,
        "proposal_summary": "Approve a 60-day invoice receivables pool as DAO collateral after evidence-hash review.",
    },
    "oracle": {
        "name": "Oracle Feed Anomaly Proposal",
        "source": "rwa_oracle",
        "preliminary_severity": "medium",
        "security_relevant": True,
        "dao_target": "rwa-receivables-oracle",
        "current_allocation": "oracle update requested",
        "guardrail_cap": "dual-source verification required",
        "risk_exposure_pct": 54.0,
        "volatility_bps": 640,
        "policy_compliance_pct": 72.0,
        "recommended_action": "challenge oracle evidence and require verified RWA source attestation",
        "risk_level": "medium",
        "anomaly": True,
        "proposal_summary": "Approve an RWA invoice oracle update with conflicting off-chain evidence.",
    },
    "yield": {
        "name": "Yield Spike Proposal",
        "source": "treasury_metrics",
        "preliminary_severity": "low",
        "security_relevant": False,
        "dao_target": "cspr-yield-vault-beta",
        "current_allocation": "16.4% advertised APY",
        "guardrail_cap": "APY anomaly review",
        "risk_exposure_pct": 31.0,
        "volatility_bps": 420,
        "policy_compliance_pct": 83.0,
        "recommended_action": "anchor observation receipt and delay execution until liquidity stabilizes",
        "risk_level": "medium",
        "anomaly": True,
        "proposal_summary": "Evaluate a sudden APY spike before treasury allocation.",
    },
    "exposure": {
        "name": "Treasury Exposure Limit Proposal",
        "source": "treasury_metrics",
        "preliminary_severity": "medium",
        "security_relevant": True,
        "dao_target": "dao-treasury-policy",
        "current_allocation": "18% exposure requested",
        "guardrail_cap": "10% per-strategy cap",
        "risk_exposure_pct": 66.0,
        "volatility_bps": 860,
        "policy_compliance_pct": 57.0,
        "recommended_action": "revise allocation downward and require multisig approval",
        "risk_level": "high",
        "anomaly": True,
        "proposal_summary": "Requested exposure exceeds the DAO treasury concentration policy.",
    },
    "policy": {
        "name": "Protocol Drift Proposal",
        "source": "casper_events",
        "preliminary_severity": "low",
        "security_relevant": True,
        "dao_target": "governance-policy-engine",
        "current_allocation": "parameter update proposed",
        "guardrail_cap": "policy version lock required",
        "risk_exposure_pct": 44.0,
        "volatility_bps": 510,
        "policy_compliance_pct": 79.0,
        "recommended_action": "anchor policy drift finding and require revised execution envelope",
        "risk_level": "medium",
        "anomaly": True,
        "proposal_summary": "Execution parameters drift from the approved DAO policy envelope.",
    },
    "credential": {
        "name": "RWA Credential Expiry Proposal",
        "source": "rwa_oracle",
        "preliminary_severity": "low",
        "security_relevant": True,
        "dao_target": "tokenized-receivables-pool",
        "current_allocation": "credential expires in 36h",
        "guardrail_cap": "fresh issuer attestation required",
        "risk_exposure_pct": 39.0,
        "volatility_bps": 350,
        "policy_compliance_pct": 81.0,
        "recommended_action": "pause RWA oracle approval until credential refresh is anchored",
        "risk_level": "medium",
        "anomaly": True,
        "proposal_summary": "RWA credential must be refreshed before the DAO approves asset onboarding.",
    },
}

CLEAN_METRICS = {
    "dao_target": "casper-liquidity-strategy-alpha",
    "volatility_index": 85,
    "policy_compliance_percentage": 99.4,
    "risk_exposure_pct": 2.1,
    "volatility_bps": 85,
    "policy_compliance_pct": 99.4,
    "anomaly_detected": False,
    "source": SOURCE_LABEL,
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _scenario_for(proposal_id: str) -> str:
    return SCENARIO_BY_PROPOSAL.get(proposal_id, "treasury")


def _proposal_id_from_body(body: dict[str, Any] | None = None) -> str:
    requested = str((body or {}).get("proposal_id") or "").strip()
    if requested:
        return requested
    return f"DAO-PROP-{uuid.uuid4().hex[:6].upper()}"


def _fingerprint(scenario: str, proposal_id: str) -> str:
    return hashlib.sha256(f"{scenario}:{proposal_id}".encode()).hexdigest()


def _signal(scenario: str, proposal_id: str) -> dict[str, Any]:
    data = SCENARIOS[scenario]
    raw = {
        "proposal_id": proposal_id,
        "proposal_type": data.get("proposal_type", scenario.upper()),
        "requested_action": data.get("requested_action", data["proposal_summary"]),
        "treasury_allocation_bps": data.get("treasury_allocation_bps", 0),
        "approved_allocation_bps": data.get("approved_allocation_bps", 0),
        "target_protocol": data.get("target_protocol", data["dao_target"]),
        "expected_apy": data.get("expected_apy"),
        "liquidity_depth_score": data.get("liquidity_depth_score"),
        "impermanent_loss_risk": data.get("impermanent_loss_risk"),
        "asset_class": data.get("asset_class"),
        "face_value_usd": data.get("face_value_usd"),
        "maturity_days": data.get("maturity_days"),
        "debtor_risk_score": data.get("debtor_risk_score"),
        "issuer_reputation_score": data.get("issuer_reputation_score"),
        "evidence_hash": data.get("evidence_hash"),
        "risk_score": data.get("risk_score", int(data["risk_exposure_pct"])),
        "dao_target": data["dao_target"],
        "service": data["dao_target"],  # compatibility field used by the existing dashboard facts extractor
        "environment": "casper-testnet",
        "version": data["current_allocation"],
        "target_version": data["guardrail_cap"],
        "risk_level": data["risk_level"],
        "risk_exposure_pct": data["risk_exposure_pct"],
        "error_rate": data["risk_exposure_pct"],  # compatibility alias for deterministic severity logic
        "volatility_bps": data["volatility_bps"],
        "volatility_index": data["volatility_bps"],
        "policy_compliance_percentage": data["policy_compliance_pct"],
        "policy_compliance_pct": data["policy_compliance_pct"],
        "recommended_action": data["recommended_action"],
        "proposal_summary": data["proposal_summary"],
        "casper_network": "casper-testnet",
        "evidence_uri": evidence_uri_for(proposal_id),
        "created_at": _now().isoformat(),
    }
    raw["policy_evaluation"] = evaluate_proposal_policy(raw)
    return {
        "signal_type": scenario,
        "source": data["source"],
        "title": f"{data['name']}: {data['dao_target']}",
        "preliminary_severity": data["preliminary_severity"],
        "security_relevant": bool(data["security_relevant"]),
        "fingerprint": f"sha256:{_fingerprint(scenario, proposal_id)}",
        "raw_payload": raw,
    }


async def _activate(request: Request, scenario: str) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception:
        body = {}
    proposal_id = _proposal_id_from_body(body)
    if scenario not in SCENARIOS:
        scenario = "treasury"
    SCENARIO_BY_PROPOSAL[proposal_id] = scenario
    signal = _signal(scenario, proposal_id)
    return {
        "ok": True,
        "proposal_id": proposal_id,
        "scenario_type": scenario,
        "signal": signal,
        "dao_target": signal["raw_payload"]["dao_target"],
        "service": signal["raw_payload"]["dao_target"],
        "source": SOURCE_LABEL,
    }


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "concordia-dao-proposal-simulator", "active": len(SCENARIO_BY_PROPOSAL)}


@app.post("/admin/scenario/treasury")
async def trigger_risky_treasury(request: Request):
    return await _activate(request, "treasury")


@app.post("/admin/scenario/defi-treasury")
async def trigger_defi_treasury(request: Request):
    return await _activate(request, "treasury")


@app.post("/admin/scenario/rwa-onboarding")
async def trigger_rwa_onboarding(request: Request):
    return await _activate(request, "rwa")


@app.post("/admin/scenario/oracle")
async def trigger_oracle_signal(request: Request):
    return await _activate(request, "oracle")


@app.post("/admin/scenario/yield")
async def trigger_yield_spike(request: Request):
    return await _activate(request, "yield")


@app.post("/admin/scenario/exposure")
async def trigger_treasury_exposure(request: Request):
    return await _activate(request, "exposure")


@app.post("/admin/scenario/policy")
async def trigger_protocol_drift(request: Request):
    return await _activate(request, "policy")


@app.post("/admin/scenario/credential")
async def trigger_rwa_credential(request: Request):
    return await _activate(request, "credential")


@app.post("/admin/scenario/{proposal_id}/reset")
def reset_one(proposal_id: str) -> dict[str, Any]:
    existed = proposal_id in SCENARIO_BY_PROPOSAL
    SCENARIO_BY_PROPOSAL.pop(proposal_id, None)
    return {"ok": True, "proposal_id": proposal_id, "removed": existed}


@app.post("/admin/scenario/reset-all")
def reset_all() -> dict[str, Any]:
    cleared = len(SCENARIO_BY_PROPOSAL)
    SCENARIO_BY_PROPOSAL.clear()
    return {"ok": True, "cleared": cleared}


@app.get("/api/v1/treasury/metrics")
def get_treasury_metrics(proposal_id: str = "") -> dict[str, Any]:
    if not proposal_id or proposal_id not in SCENARIO_BY_PROPOSAL:
        return CLEAN_METRICS
    scenario = _scenario_for(proposal_id)
    data = SCENARIOS[scenario]
    return {
        "proposal_id": proposal_id,
        "dao_target": data["dao_target"],
        "service": data["dao_target"],
        "proposal_type": data.get("proposal_type", scenario.upper()),
        "requested_action": data.get("requested_action", data["proposal_summary"]),
        "treasury_allocation_bps": data.get("treasury_allocation_bps", 0),
        "approved_allocation_bps": data.get("approved_allocation_bps", 0),
        "target_protocol": data.get("target_protocol", data["dao_target"]),
        "expected_apy": data.get("expected_apy"),
        "liquidity_depth_score": data.get("liquidity_depth_score"),
        "impermanent_loss_risk": data.get("impermanent_loss_risk"),
        "asset_class": data.get("asset_class"),
        "face_value_usd": data.get("face_value_usd"),
        "maturity_days": data.get("maturity_days"),
        "risk_score": data.get("risk_score", int(data["risk_exposure_pct"])),
        "risk_exposure_pct": data["risk_exposure_pct"],
        "volatility_index": data["volatility_bps"],
        "volatility_bps": data["volatility_bps"],
        "policy_compliance_percentage": data["policy_compliance_pct"],
        "policy_compliance_pct": data["policy_compliance_pct"],
        "anomaly_detected": bool(data["anomaly"]),
        "recommended_action_hint": data["recommended_action"],
        "source": SOURCE_LABEL,
    }


@app.get("/api/v1/governance/risk-events")
def get_recent_risk_events(proposal_id: str = "") -> dict[str, Any]:
    scenario = _scenario_for(proposal_id)
    data = SCENARIOS[scenario]
    return {
        "proposal_id": proposal_id,
        "dao_target": data["dao_target"],
        "errors": [
            {
                "type": "GovernanceRiskSignal",
                "message": data["proposal_summary"],
                "severity": data["preliminary_severity"],
                "observed_at": (_now() - timedelta(minutes=6)).isoformat(),
                "evidence_uri": evidence_uri_for(proposal_id or "sample"),
            }
        ] if proposal_id else [],
        "anomaly_detected": bool(data["anomaly"]) if proposal_id else False,
        "source": SOURCE_LABEL,
    }


@app.get("/api/v1/casper/events/recent")
def get_recent_governance_events(proposal_id: str = "") -> dict[str, Any]:
    scenario = _scenario_for(proposal_id)
    return {
        "proposal_id": proposal_id,
        "governance_events": [
            {
                "governance_event": "proposal_submitted",
                "proposal_hash": _fingerprint(scenario, proposal_id or "sample"),
                "contract_package": "concordia-governance-receipt",
                "network": "casper-testnet",
                "submitted_by": "dao-proposer",
                "created_at": (_now() - timedelta(minutes=9)).isoformat(),
                "governance_event_gap_minutes": 3,
            }
        ] if proposal_id else [],
        "source": SOURCE_LABEL,
    }


@app.get("/api/v1/policy/compliance")
def get_policy_compliance(proposal_id: str = "") -> dict[str, Any]:
    if not proposal_id or proposal_id not in SCENARIO_BY_PROPOSAL:
        return {**CLEAN_METRICS, "url": "casper-testnet", "status_code": 200}
    scenario = _scenario_for(proposal_id)
    data = SCENARIOS[scenario]
    return {
        "proposal_id": proposal_id,
        "url": "casper-testnet://governance-receipt",
        "status_code": 200 if data["policy_compliance_pct"] >= 70 else 409,
        "policy_compliance_percentage": data["policy_compliance_pct"],
        "policy_compliance_pct": data["policy_compliance_pct"],
        "anomaly_detected": bool(data["anomaly"]),
        "policy_evaluation": evaluate_proposal_policy({
            "proposal_id": proposal_id,
            "proposal_type": data.get("proposal_type", scenario.upper()),
            "requested_action": data.get("requested_action", data["proposal_summary"]),
            "treasury_allocation_bps": data.get("treasury_allocation_bps", 0),
            "target_protocol": data.get("target_protocol", data["dao_target"]),
            "dao_target": data["dao_target"],
            "asset_class": data.get("asset_class"),
            "evidence_hash": data.get("evidence_hash"),
            "risk_score": data.get("risk_score", int(data["risk_exposure_pct"])),
            "casper_network": "casper-testnet",
        }),
        "source": SOURCE_LABEL,
    }
