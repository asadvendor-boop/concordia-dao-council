"""Mercer, Treasury Intelligence Agent — local Council Chamber runtime + LLM.

Investigates proposals by querying DAO, treasury, RWA, and Casper-oriented evidence endpoints via local tools.
Computes evidence_strength via deterministic aggregation of advisory-model-reviewed
relevance. Submits sealed Assessment via Gateway.

Architecture:
  - TreasuryIntelligencePreprocessor: thin validator (sender, seal, Pydantic, reject suppress)
  - Stores trusted per-proposal context for tool callbacks
  - LocalRoomAgent invokes the LLM-assisted diagnosis callback after acceptance
  - Tools use CustomToolDef: tuple[BaseModel, Callable]
  - Tool names derived by get_custom_tool_name: strips "Input", lowercases
  - submit_assessment callback: deterministic evidence_strength + severity + saga

Tool contract (local runtime):
  - additional_tools: list[CustomToolDef] = list[tuple[type[BaseModel], Callable]]
  - execute_custom_tool: model, func = tool; validated = model.model_validate(args); func(validated)
  - Callbacks receive a VALIDATED PYDANTIC MODEL, not **kwargs
  - Tool names: QueryTreasuryMetrics → "query_treasury_metrics", SubmitAssessment → "submitassessment"

Honest claims:
  - "LLM-backed": LLM synthesizes advisory diagnosis text when credentials are set
  - "Deterministic evidence_strength": deterministic aggregation of advisory-model-reviewed relevance
  - "Deterministic severity": from impact metrics, not LLM-decided
  - "has_seal_fields": structural pre-filter, not cryptographic proof
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx
from pydantic import BaseModel, Field

from shared.card_intake import (
    derive_idempotency_key,
    extract_sealed_card,
    has_seal_fields,
)
from shared.casper_mcp import (
    get_casper_balance,
    get_casper_deploy_status,
    get_casper_node_status,
    get_casper_public_status,
    get_cspr_trade_quote,
)
from shared.cspr_cloud import (
    get_account_context,
    get_cspr_rate,
    get_deploy_context,
    node_rpc_context,
    streaming_subscription_context,
)
from shared.config import (
    ACTIVE_PROPOSALS,
    MODELS,
    get_provider_settings,
    get_agent_api_key,
)
from shared.dao_policy import evaluate_proposal_policy, evidence_uri_for
from shared.evidence import compute_evidence_strength
from shared.models import Assessment, TriageDecision, Verdict
from shared.proposal_room import ProposalRoomClient
from shared.replay_guard import should_skip_stale_card, should_skip_stale_chatter
from shared.submission_client import SubmissionClient, SubmissionError, format_card_message
from shared.local_room_runtime import LocalDefaultPreprocessor, LocalRoomAgent
from shared.llm_reasoning import ask_llm_json, bounded_text
from shared.supervisor import run_with_supervisor

logger = logging.getLogger("concordia.diagnosis")

# Gateway URL for SubmissionClient
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")

# Victim app URL for evidence queries
PROPOSAL_SIMULATOR_URL = os.getenv("PROPOSAL_SIMULATOR_URL", "http://localhost:9000")


# ---------------------------------------------------------------------------
# Trusted per-proposal context (populated by preprocessor, consumed by tools)
# ---------------------------------------------------------------------------

@dataclass
class ProposalContext:
    """Trusted context for an proposal, populated by the preprocessor.

    Tool callbacks read from this — never from model-supplied values
    for sensitive fields (room_id, room_message_id, etc.).
    """
    proposal_id: str
    signal_id: str
    room_id: str
    room_message_id: str
    source_card_hash: str
    triage_decision_raw: dict
    # room message created_at for freshness (if available), else receipt time
    signal_timestamp: float = field(default_factory=time.time)
    created_at: float = field(default_factory=time.time)
    # Tool results cached here (source-of-truth for anomaly_detected)
    tool_results: dict[str, dict] = field(default_factory=dict)
    tools_completed: set[str] = field(default_factory=set)
    submitted: bool = False
    revision: int = 1
    challenge_request: str | None = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


# Module-level trusted context store, keyed by proposal_id
_trusted_context: dict[str, ProposalContext] = {}

# Rooms where Mercer has already published a sealed Assessment.
# Non-card messages in these rooms are silently consumed (anti-chatter-loop).
_handoff_rooms: set[str] = set()

# Shared httpx client for proposal-simulator queries (avoid per-call leaks)
_http_client: httpx.AsyncClient | None = None

# Required evidence tools before submission — ALL four sources must be queried.
# treasury_metrics: needed for severity derivation (risk exposure and volatility)
# risk_events: governance risk event stream
# governance_events: Casper governance/deploy event correlation
# policy_compliance: policy-compliance score for severity threshold
# Prompt instructions are NOT deterministic enforcement — this is.
REQUIRED_TOOLS = frozenset({"treasury_metrics", "risk_events", "governance_events", "policy_compliance", "casper_node_status"})


async def _get_http_client() -> httpx.AsyncClient:
    """Get or create shared httpx client."""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(timeout=15.0)
    return _http_client


# ---------------------------------------------------------------------------
# Severity derivation — from IMPACT metrics, NOT evidence confidence
# ---------------------------------------------------------------------------

def derive_severity(
    treasury_metrics: dict,
    policy_compliance: dict,
) -> str:
    """Derive severity from impact signals, NOT evidence_strength.

    Evidence strength = "How strongly is the hypothesis supported?"
    Severity = "How damaging is the proposal?"

    Source: tool-cached results from proposal-simulator, not advisory-model-reviewed.

    Args:
        treasury_metrics: From ctx.tool_results["treasury_metrics"] (proposal-simulator /api/v1/treasury/metrics)
        policy_compliance: From ctx.tool_results["policy_compliance"] (proposal-simulator /api/v1/policy/compliance)
    """
    risk_exposure_pct = treasury_metrics.get("risk_exposure_pct", 0.0)
    volatility_bps = treasury_metrics.get("volatility_bps", 0)
    policy_compliance_pct = policy_compliance.get("policy_compliance_percentage", 100.0)

    if risk_exposure_pct >= 25.0 or policy_compliance_pct < 95.0:
        return "P1"  # Critical DAO risk
    elif risk_exposure_pct >= 10.0 or volatility_bps >= 5000:
        return "P2"  # Significant DAO risk
    elif risk_exposure_pct >= 2.0 or volatility_bps >= 2000:
        return "P3"  # Moderate DAO risk
    else:
        return "P4"  # Informational


# ---------------------------------------------------------------------------
# Tool Input Models (Pydantic) — local-runtime CustomToolDef contract
#
# local-runtime derives tool names via get_custom_tool_name:
#   strips "Input" suffix, lowercases → QueryTreasuryMetrics → "query_treasury_metrics"
# Callbacks receive VALIDATED PYDANTIC MODEL, not **kwargs.
# ---------------------------------------------------------------------------

class QueryTreasuryMetrics(BaseModel):
    """Query treasury risk metrics for a DAO proposal."""
    proposal_id: str = Field(description="The proposal identifier to query metrics for")


class QueryRiskEvents(BaseModel):
    """Query recent governance risk events for a DAO proposal."""
    proposal_id: str = Field(description="The proposal identifier to query governance risk events for")


class QueryGovernanceEvents(BaseModel):
    """Query recent Casper governance events for a DAO proposal."""
    proposal_id: str = Field(description="The proposal identifier to query Casper governance events for")


class QueryPolicyCompliance(BaseModel):
    """Query policy-compliance telemetry for a DAO proposal."""
    proposal_id: str = Field(description="The proposal identifier to query policy-compliance telemetry for")


class QueryCasperNodeStatus(BaseModel):
    """Query the live Casper node status for a DAO proposal."""
    proposal_id: str = Field(description="The proposal identifier being evaluated against Casper Testnet")


class SubmitAssessment(BaseModel):
    """Submit the final diagnostic assessment for an proposal.

    MUST be called after querying evidence tools. The assessment will be
    submitted to Gateway and published to the Council Chamber.
    """
    proposal_id: str = Field(description="The proposal identifier")
    root_cause_hypothesis: str = Field(description="Root cause analysis")
    recommended_action: str = Field(description="Recommended governance execution")
    blast_radius: list[str] = Field(description="List of affected systems/services")
    risk_events_relevance: float = Field(ge=0.0, le=1.0, description="Error signal relevance (0.0-1.0)")
    treasury_metrics_relevance: float = Field(ge=0.0, le=1.0, description="Metric signal relevance (0.0-1.0)")
    governance_events_relevance: float = Field(ge=0.0, le=1.0, description="governance event signal relevance (0.0-1.0)")
    policy_compliance_relevance: float = Field(ge=0.0, le=1.0, description="policy compliance signal relevance (0.0-1.0)")
    casper_node_status_relevance: float = Field(ge=0.0, le=1.0, description="Casper node status relevance (0.0-1.0)")


# ---------------------------------------------------------------------------
# Tool Callbacks — receive validated Pydantic model (NOT **kwargs)
# ---------------------------------------------------------------------------

async def handle_query_treasury_metrics(input: QueryTreasuryMetrics) -> str:
    """Query treasury metrics from proposal-simulator. Caches result in trusted context."""
    ctx = _trusted_context.get(input.proposal_id)
    if ctx is None:
        return json.dumps({"error": f"Unknown proposal: {input.proposal_id}"})

    try:
        client = await _get_http_client()
        resp = await client.get(
            f"{PROPOSAL_SIMULATOR_URL}/api/v1/treasury/metrics",
            params={"proposal_id": input.proposal_id},
        )
        resp.raise_for_status()
        data = resp.json()

        treasury_public_key = os.getenv("CASPER_TREASURY_PUBLIC_KEY", "concordia-demo-treasury")
        try:
            data["cspr_cloud_rate"] = await get_cspr_rate("usd")
            data["cspr_cloud_account_context"] = await get_account_context(treasury_public_key)
            data["casper_mcp_balance"] = await get_casper_balance(treasury_public_key)
            data["cspr_trade_quote"] = await get_cspr_trade_quote("CSPR", "DAO-USDC", "1000")
        except Exception as enrich_exc:
            data["casper_tooling_enrichment_error"] = type(enrich_exc).__name__

        async with ctx.lock:
            ctx.tool_results["treasury_metrics"] = data
            ctx.tools_completed.add("treasury_metrics")

        logger.info(
            f"[diagnosis] query_treasury_metrics for {input.proposal_id}: "
            f"risk_exposure_pct={data.get('risk_exposure_pct')}, anomaly={data.get('anomaly_detected')}"
        )
        return json.dumps(data)
    except Exception as exc:
        logger.error(
            "[diagnosis] query_treasury_metrics failed for %s (%s)",
            input.proposal_id,
            type(exc).__name__,
        )
        return json.dumps({
            "error": f"treasury metrics query failed ({type(exc).__name__})",
            "anomaly_detected": False,
        })


async def handle_query_risk_events(input: QueryRiskEvents) -> str:
    """Query governance risk events from proposal-simulator. Caches result under the risk_events key."""
    ctx = _trusted_context.get(input.proposal_id)
    if ctx is None:
        return json.dumps({"error": f"Unknown proposal: {input.proposal_id}"})

    try:
        client = await _get_http_client()
        resp = await client.get(
            f"{PROPOSAL_SIMULATOR_URL}/api/v1/governance/risk-events",
            params={"proposal_id": input.proposal_id},
        )
        resp.raise_for_status()
        data = resp.json()

        # Cache under "risk_events" key to match shared/evidence.py SOURCES
        async with ctx.lock:
            ctx.tool_results["risk_events"] = data
            ctx.tools_completed.add("risk_events")

        logger.info(
            f"[diagnosis] query_risk_events for {input.proposal_id}: "
            f"anomaly={data.get('anomaly_detected')}"
        )
        return json.dumps(data)
    except Exception as exc:
        logger.error(
            "[diagnosis] query_risk_events failed for %s (%s)",
            input.proposal_id,
            type(exc).__name__,
        )
        return json.dumps({
            "error": f"risk-event query failed ({type(exc).__name__})",
            "anomaly_detected": False,
        })


async def handle_query_governance_events(input: QueryGovernanceEvents) -> str:
    """Query Casper governance events from proposal-simulator. Caches result in trusted context."""
    ctx = _trusted_context.get(input.proposal_id)
    if ctx is None:
        return json.dumps({"error": f"Unknown proposal: {input.proposal_id}"})

    try:
        client = await _get_http_client()
        resp = await client.get(
            f"{PROPOSAL_SIMULATOR_URL}/api/v1/casper/events/recent",
            params={"proposal_id": input.proposal_id},
        )
        resp.raise_for_status()
        data = resp.json()

        deploy_hash = (
            data.get("latest_deploy_hash")
            or data.get("deploy_hash")
            or data.get("transaction_hash")
            or "concordia-demo-governance-receipt"
        )
        try:
            data["cspr_cloud_deploy_context"] = await get_deploy_context(str(deploy_hash))
            data["cspr_cloud_stream_context"] = streaming_subscription_context("contract")
            data["cspr_cloud_node_context"] = node_rpc_context()
            data["casper_mcp_deploy_status"] = await get_casper_deploy_status(str(deploy_hash))
        except Exception as enrich_exc:
            data["casper_tooling_enrichment_error"] = type(enrich_exc).__name__

        async with ctx.lock:
            ctx.tool_results["governance_events"] = data
            ctx.tools_completed.add("governance_events")

        logger.info(
            f"[diagnosis] query_governance_events for {input.proposal_id}: "
            f"anomaly={data.get('anomaly_detected')}"
        )
        return json.dumps(data)
    except Exception as exc:
        logger.error(
            "[diagnosis] query_governance_events failed for %s (%s)",
            input.proposal_id,
            type(exc).__name__,
        )
        return json.dumps({
            "error": f"governance event query failed ({type(exc).__name__})",
            "anomaly_detected": False,
        })


async def handle_query_policy_compliance(input: QueryPolicyCompliance) -> str:
    """Query policy compliance from proposal-simulator. Caches result in trusted context."""
    ctx = _trusted_context.get(input.proposal_id)
    if ctx is None:
        return json.dumps({"error": f"Unknown proposal: {input.proposal_id}"})

    try:
        client = await _get_http_client()
        resp = await client.get(
            f"{PROPOSAL_SIMULATOR_URL}/api/v1/policy/compliance",
            params={"proposal_id": input.proposal_id},
        )
        resp.raise_for_status()
        data = resp.json()

        async with ctx.lock:
            ctx.tool_results["policy_compliance"] = data
            ctx.tools_completed.add("policy_compliance")

        logger.info(
            f"[diagnosis] query_policy_compliance for {input.proposal_id}: "
            f"policy_compliance={data.get('policy_compliance_percentage')}%, anomaly={data.get('anomaly_detected')}"
        )
        return json.dumps(data)
    except Exception as exc:
        logger.error(
            "[diagnosis] query_policy_compliance failed for %s (%s)",
            input.proposal_id,
            type(exc).__name__,
        )
        return json.dumps({
            "error": f"policy-compliance query failed ({type(exc).__name__})",
            "anomaly_detected": False,
        })


async def handle_query_casper_node_status(input: QueryCasperNodeStatus) -> str:
    """Perform a Casper Testnet node/public-status read and cache it as evidence."""
    ctx = _trusted_context.get(input.proposal_id)
    if ctx is None:
        return json.dumps({"error": f"Unknown proposal: {input.proposal_id}"})

    try:
        node_status = await get_casper_node_status()
        public_status = await get_casper_public_status()
        live = bool(node_status.get("live")) or bool(public_status.get("live"))
        data = {
            "proposal_id": input.proposal_id,
            "anomaly_detected": not live,
            "live_read": live,
            "node_status": node_status,
            "public_status": public_status,
            "source": "casper-node-status",
        }
        async with ctx.lock:
            ctx.tool_results["casper_node_status"] = data
            ctx.tools_completed.add("casper_node_status")
        logger.info(
            "[diagnosis] query_casper_node_status for %s: live=%s",
            input.proposal_id,
            live,
        )
        return json.dumps(data)
    except Exception as exc:
        logger.error(
            "[diagnosis] query_casper_node_status failed for %s (%s)",
            input.proposal_id,
            type(exc).__name__,
        )
        return json.dumps({
            "error": f"Casper node status query failed ({type(exc).__name__})",
            "anomaly_detected": True,
            "live_read": False,
        })


async def handle_submit_assessment(input: SubmitAssessment) -> str:
    """Submit the final Assessment. Deterministic code owns scoring + saga.

    This callback:
    1. Validates proposal_id in trusted context
    2. Requires treasury and policy evidence in tools_completed (for severity)
    3. Reads anomaly_detected from tool-cached results (NOT from LLM)
    4. Uses LLM-supplied relevance_scores only
    5. Computes evidence_strength via shared/evidence.py
    6. Derives severity from impact metrics
    7. Runs prepare → recruit → publish @mention → confirm saga
    """
    ctx = _trusted_context.get(input.proposal_id)
    if ctx is None:
        return f"Error: unknown proposal {input.proposal_id}. Cannot submit assessment."

    async with ctx.lock:
        if ctx.submitted:
            # _handle_challenge() resets submitted=False before re-investigation,
            # so this guard only blocks true duplicates (not challenge re-entries).
            return f"Assessment already submitted for {input.proposal_id}."

        # --- Require required evidence tools before severity/assessment ---
        missing = REQUIRED_TOOLS - ctx.tools_completed
        if missing:
            return (
                f"Error: required evidence tools not yet called: {missing}. "
                f"Query them first before submitting assessment."
            )

        # --- Build signals from tool-cached results (NOT from LLM) ---
        signals: dict[str, Any] = {}
        relevance_map = {
            "risk_events": input.risk_events_relevance,
            "treasury_metrics": input.treasury_metrics_relevance,
            "governance_events": input.governance_events_relevance,
            "policy_compliance": input.policy_compliance_relevance,
            "casper_node_status": input.casper_node_status_relevance,
        }
        for source_key in ("risk_events", "treasury_metrics", "governance_events", "policy_compliance", "casper_node_status"):
            tool_data = ctx.tool_results.get(source_key, {})
            signals[source_key] = {
                "anomaly_detected": tool_data.get("anomaly_detected", False),
                "relevance_score": max(0.0, min(1.0, relevance_map[source_key])),
            }

        # Temporal correlation from Casper governance event data
        governance_events_data = ctx.tool_results.get("governance_events", {})
        # governance_event_gap_minutes lives inside governance_events[0], not top-level
        gap = governance_events_data.get("governance_event_gap_minutes")
        if gap is None:
            governance_events_list = governance_events_data.get("governance_events", [])
            if governance_events_list and isinstance(governance_events_list, list):
                gap = governance_events_list[0].get("governance_event_gap_minutes")
        if gap is not None:
            signals["governance_event_gap_minutes"] = gap

        # Freshness from room message timestamp (when TriageDecision was posted),
        # NOT Diagnosis receipt time. Falls back to receipt time if unavailable.
        freshness = (time.time() - ctx.signal_timestamp) / 60.0
        signals["freshness_minutes"] = freshness

        # --- Deterministic evidence_strength ---
        evidence_strength = compute_evidence_strength(
            signals, input.root_cause_hypothesis,
        )

        # --- Deterministic severity from IMPACT metrics ---
        # policy_compliance from ctx.tool_results["policy_compliance"], not model output
        treasury_metrics_data = ctx.tool_results.get("treasury_metrics", {})
        policy_compliance_data = ctx.tool_results.get("policy_compliance", {})
        policy_evaluation = (
            policy_compliance_data.get("policy_evaluation")
            or treasury_metrics_data.get("policy_evaluation")
            or evaluate_proposal_policy({
                **treasury_metrics_data,
                "proposal_id": input.proposal_id,
            })
        )
        severity = derive_severity(treasury_metrics_data, policy_compliance_data)
        casper_node_status = ctx.tool_results.get("casper_node_status", {})
        evidence_uri = evidence_uri_for(input.proposal_id)

        # --- Build Assessment card ---
        assessment = Assessment(
            proposal_id=input.proposal_id,
            severity=severity,
            evidence_strength=round(evidence_strength, 4),
            blast_radius=input.blast_radius or [],
            root_cause_hypothesis=input.root_cause_hypothesis,
            recommended_action=input.recommended_action,
            revision=ctx.revision,
            evidence={
                "signals": {
                    k: v for k, v in signals.items()
                    if isinstance(v, dict)
                },
                "tools_completed": sorted(ctx.tools_completed),
                "relevance_scores": {
                    "risk_events": input.risk_events_relevance,
                    "treasury_metrics": input.treasury_metrics_relevance,
                    "governance_events": input.governance_events_relevance,
                    "policy_compliance": input.policy_compliance_relevance,
                    "casper_node_status": input.casper_node_status_relevance,
                },
                "policy_evaluation": policy_evaluation,
                "casper_node_status": casper_node_status,
                "evidence_uri": evidence_uri,
                "proposal_context": {
                    "proposal_type": policy_evaluation.get("proposal_type"),
                    "requested_allocation_bps": policy_evaluation.get("requested_allocation_bps"),
                    "approved_allocation_bps": policy_evaluation.get("approved_allocation_bps"),
                    "risk_score": policy_evaluation.get("risk_score"),
                    "target_protocol": treasury_metrics_data.get("target_protocol") or treasury_metrics_data.get("dao_target"),
                },
                "temporal_gap_minutes": gap,
                "freshness_minutes": round(freshness, 1),
                "challenge_response": ctx.challenge_request,
            },
        )

        # --- SubmissionClient saga ---
        try:
            submission_key = os.getenv("DIAGNOSIS_SUBMISSION_KEY", "")
            idem_key = derive_idempotency_key(
                "diagnosis", ctx.room_message_id, ctx.source_card_hash,
            )

            async with SubmissionClient(
                gateway_url=GATEWAY_URL,
                agent_key=submission_key,
            ) as sc:
                # 1. Prepare — with bounded state retry for publish-before-confirm race.
                # Triage flow: prepare → recruit Diagnosis → publish → confirm.
                # Diagnosis can receive the published TriageDecision BEFORE Triage
                # calls confirm(), so Gateway may still be at DETECTED (not TRIAGED).
                # Gateway returns 409 ("wrong state") → we retry with backoff.
                STATE_RETRY_DELAYS = [0.5, 1.0, 2.0, 3.0]  # max wait ~3.5s (last delay unused)
                prepared = None
                for attempt, delay in enumerate(STATE_RETRY_DELAYS):
                    try:
                        prepared = await sc.prepare(assessment, idempotency_key=idem_key)
                        break  # Success
                    except SubmissionError as e:
                        if e.status_code == 409 and attempt < len(STATE_RETRY_DELAYS) - 1:
                            logger.warning(
                                f"[diagnosis] prepare() got 409 (state race) on attempt "
                                f"{attempt + 1}/{len(STATE_RETRY_DELAYS)}. Waiting {delay}s "
                                f"for Triage to confirm TRIAGED..."
                            )
                            await asyncio.sleep(delay)
                        else:
                            raise  # Non-409 or final attempt → propagate

                if prepared is None:
                    raise RuntimeError("[diagnosis] prepare() failed after all retries")

                publish_room = prepared.room_id or ctx.room_id
                sealed_message = format_card_message(prepared.sealed_card)

                # 2. Recruit Risk & Legal Agent BEFORE publishing
                reviewer_id = os.getenv("SAFETY_REVIEWER_AGENT_ID", "")
                if not reviewer_id:
                    raise RuntimeError(
                        "[diagnosis] Cannot recruit: SAFETY_REVIEWER_AGENT_ID "
                        "not configured."
                    )

                room_client = ProposalRoomClient(
                    sender_id=os.getenv("DIAGNOSIS_AGENT_ID", "diagnosis"),
                    sender_role="diagnosis",
                )

                try:
                    await room_client.add_participant(
                        publish_room,
                        reviewer_id,
                        role="safety_reviewer",
                        display_name="Risk & Legal Agent",
                    )
                    logger.info(
                        f"[diagnosis] Recruited Risk & Legal Agent "
                        f"{reviewer_id[:12]}... into room {publish_room[:12]}..."
                    )

                    # 3. Publish Assessment @mentioning Risk & Legal Agent
                    message_id = await room_client.post_message(
                        publish_room,
                        sealed_message,
                        mentions=[reviewer_id],
                        metadata={
                            "publisher": "diagnosis",
                            "card_hash": prepared.card_hash,
                        },
                    )
                finally:
                    await room_client.aclose()

                # 4. Confirm (TRIAGED → ASSESSED)
                confirm = await sc.confirm(
                    submission_id=prepared.submission_id,
                    proposal_id=prepared.proposal_id,
                    card_hash=prepared.card_hash,
                    message_id=message_id,
                    room_id=publish_room,
                )

                logger.info(
                    f"[diagnosis] Assessment confirmed: "
                    f"proposal={input.proposal_id}, severity={severity}, "
                    f"evidence_strength={evidence_strength:.3f}, "
                    f"state={confirm.new_state}"
                )

            ctx.submitted = True
            # Mark room for post-handoff silence (anti-chatter-loop).
            _handoff_rooms.add(ctx.room_id)
            logger.info(
                f"[diagnosis] Marked room {ctx.room_id[:12]}... for "
                f"post-handoff silence (proposal {input.proposal_id})"
            )
            return (
                f"Assessment submitted successfully for {input.proposal_id}. "
                f"Severity: {severity}, Evidence Strength: {evidence_strength:.2f}. "
                f"Risk & Legal Agent has been recruited and will review. "
                f"YOUR WORK IS DONE — do NOT reply, do NOT explain, do NOT "
                f"send any follow-up message. STOP NOW."
            )

        except Exception as exc:
            logger.error(
                "[diagnosis] Assessment submission failed (%s)",
                type(exc).__name__,
            )
            return f"Error submitting assessment ({type(exc).__name__})"


def _root_cause_from_evidence(ctx: ProposalContext) -> tuple[str, str, list[str]]:
    """Build a compact diagnosis from trusted evidence tool results."""
    metrics = ctx.tool_results.get("treasury_metrics", {})
    risk_events = ctx.tool_results.get("risk_events", {})
    governance_events = ctx.tool_results.get("governance_events", {})
    policy = ctx.tool_results.get("policy_compliance", {})
    casper_node = ctx.tool_results.get("casper_node_status", {})
    policy_eval = policy.get("policy_evaluation", {})

    service = (
        metrics.get("service")
        or risk_events.get("service")
        or governance_events.get("service")
        or policy.get("service")
        or "dao-governance-target"
    )
    parts: list[str] = []
    if governance_events.get("anomaly_detected"):
        parts.append("recent Casper governance event correlation")
    if risk_events.get("anomaly_detected"):
        parts.append("risk-event spike")
    if metrics.get("anomaly_detected"):
        parts.append(
            f"treasury metric anomaly risk_exposure={metrics.get('risk_exposure_pct', '?')} "
            f"volatility_bps={metrics.get('volatility_bps', '?')}"
        )
    if policy.get("anomaly_detected"):
        parts.append(f"policy-compliance degradation policy_compliance={policy.get('policy_compliance_percentage', '?')}")
    if policy_eval.get("dissent_hash"):
        parts.append(
            f"DAO Constitution violation {policy_eval.get('dissent_hash')} "
            f"requested_allocation_bps={policy_eval.get('requested_allocation_bps')} "
            f"approved_cap_bps={policy_eval.get('approved_allocation_bps')}"
        )
    if casper_node:
        status = "OK" if casper_node.get("live_read") else "unavailable"
        parts.append(f"Casper Testnet live node read={status}")
    if not parts:
        parts.append("no strong anomaly across treasury, governance, risk, and policy evidence sources")

    root_cause = f"{service}: " + "; ".join(parts)
    recommended_action = "Use the least-risk governance execution matching the verified root cause."
    if "governance event" in root_cause.lower():
        recommended_action = "Cap or veto the correlated governance action."
    elif "volatility" in root_cause.lower() or "yield" in root_cause.lower():
        recommended_action = "Apply treasury guardrails and delay execution until risk normalizes."
    elif "policy_compliance" in root_cause.lower():
        recommended_action = "Restore policy compliance and verify the governance receipt envelope."
    if policy_eval.get("approved_allocation_bps") and policy_eval.get("requested_allocation_bps"):
        recommended_action = (
            "Revise treasury allocation from "
            f"{policy_eval.get('requested_allocation_bps')} bps to "
            f"{policy_eval.get('approved_allocation_bps')} bps, preserve Verity dissent, "
            "and anchor the approved capped decision to Casper Testnet."
        )

    blast_radius = [service]
    return root_cause[:600], recommended_action[:400], blast_radius


def _relevance_from_tool(data: dict) -> float:
    return 0.9 if data.get("anomaly_detected") else 0.25


async def run_local_diagnosis(event) -> None:
    """Run Diagnosis without an external adapter after preprocessor acceptance."""
    payload = getattr(event, "payload", None)
    content = getattr(payload, "content", "") if payload else ""
    card = extract_sealed_card(content)
    if not card:
        return
    card_type = card.get("card_type")
    if card_type == "TriageDecision":
        proposal_id = card.get("proposal_id", "")
    elif card_type == "Verdict" and card.get("decision") == "CHALLENGE":
        proposal_id = card.get("proposal_id", "")
    else:
        return

    ctx = _trusted_context.get(proposal_id)
    if ctx is None or ctx.submitted:
        return

    await handle_query_treasury_metrics(QueryTreasuryMetrics(proposal_id=proposal_id))
    await handle_query_risk_events(QueryRiskEvents(proposal_id=proposal_id))
    await handle_query_governance_events(QueryGovernanceEvents(proposal_id=proposal_id))
    await handle_query_policy_compliance(QueryPolicyCompliance(proposal_id=proposal_id))
    await handle_query_casper_node_status(QueryCasperNodeStatus(proposal_id=proposal_id))

    root_cause, recommended_action, blast_radius = _root_cause_from_evidence(ctx)
    llm = await ask_llm_json(
        role="diagnosis",
        system=(
            "You are Mercer, the Treasury Intelligence Agent. Synthesize the trusted "
            "evidence into a concise root-cause hypothesis and recommended "
            "governance execution. Do not invent evidence and do not decide severity."
        ),
        user={
            "proposal_id": proposal_id,
            "challenge_request": ctx.challenge_request,
            "tool_results": ctx.tool_results,
            "deterministic_baseline": {
                "root_cause_hypothesis": root_cause,
                "recommended_action": recommended_action,
                "blast_radius": blast_radius,
            },
            "expected_json_keys": [
                "root_cause_hypothesis",
                "recommended_action",
                "blast_radius",
            ],
        },
    )
    if llm:
        root_cause = bounded_text(llm.get("root_cause_hypothesis"), max_len=600) or root_cause
        recommended_action = (
            bounded_text(llm.get("recommended_action"), max_len=400)
            or recommended_action
        )
        if isinstance(llm.get("blast_radius"), list):
            llm_radius = [
                item.strip()[:80]
                for item in llm["blast_radius"]
                if isinstance(item, str) and item.strip()
            ]
            if llm_radius:
                blast_radius = llm_radius[:5]
    assessment = SubmitAssessment(
        proposal_id=proposal_id,
        root_cause_hypothesis=root_cause,
        recommended_action=recommended_action,
        blast_radius=blast_radius,
        risk_events_relevance=_relevance_from_tool(ctx.tool_results.get("risk_events", {})),
        treasury_metrics_relevance=_relevance_from_tool(ctx.tool_results.get("treasury_metrics", {})),
        governance_events_relevance=_relevance_from_tool(ctx.tool_results.get("governance_events", {})),
        policy_compliance_relevance=_relevance_from_tool(ctx.tool_results.get("policy_compliance", {})),
        casper_node_status_relevance=0.8 if ctx.tool_results.get("casper_node_status", {}).get("live_read") else 0.5,
    )
    result = await handle_submit_assessment(assessment)
    logger.info("[diagnosis] Local diagnosis result: %s", result)


# ---------------------------------------------------------------------------
# Diagnosis Preprocessor (thin: validate → store context → delegate)
# ---------------------------------------------------------------------------

class DiagnosisPreprocessor:
    """Thin preprocessor for Mercer, the Treasury Intelligence Agent.

    Intercepts TriageDecision(route) messages from Council Chamber. Validates sender
    (must be Triage), checks seal fields, Pydantic-validates, rejects
    suppress decisions, stores trusted per-proposal context, and delegates
    to the local runtime for tool orchestration.

    SDK contract: process(ctx, event, **kwargs) → AgentInput | None
    - Return AgentInput → local runtime invokes the diagnosis callback
    - Return None → event consumed silently
    """

    def __init__(
        self,
        *,
        diagnosis_agent_id: str,
        diagnosis_api_key: str,
    ):
        self._diagnosis_agent_id = diagnosis_agent_id
        self._diagnosis_api_key = diagnosis_api_key
        self._triage_agent_id = os.getenv("TRIAGE_AGENT_ID", "")
        self._safety_reviewer_agent_id = os.getenv("SAFETY_REVIEWER_AGENT_ID", "")
        self._default_preprocessor = None
        self._boot_epoch = time.time()

    async def _ensure_default(self):
        """Lazily import and create DefaultPreprocessor."""
        if self._default_preprocessor is None:
            self._default_preprocessor = LocalDefaultPreprocessor()

    async def process(self, ctx, event, **kwargs):
        """Process a room event.

        Intercepts TriageDecision(route) → stores context → delegates to adapter.
        Other messages → pass through to default preprocessor.
        """
        await self._ensure_default()

        # Only handle MessageEvents
        event_type = type(event).__name__
        if event_type != "MessageEvent":
            return await self._default_preprocessor.process(ctx, event, **kwargs)

        payload = getattr(event, "payload", None)
        if payload is None:
            return await self._default_preprocessor.process(ctx, event, **kwargs)

        content = getattr(payload, "content", None) or ""
        sender_id = getattr(payload, "sender_id", "") or ""
        sender_type = getattr(payload, "sender_type", "") or ""

        # room_id lives on the EVENT, not the payload (Council Chamber 1.0)
        room_id = getattr(event, "room_id", "") or ""

        # room message ID for idempotency derivation
        room_message_id = getattr(payload, "id", "") or ""

        # Ignore own messages
        if sender_id == self._diagnosis_agent_id:
            return None

        # Try to extract a TriageDecision
        card_data = extract_sealed_card(content)
        if not card_data:
            # No sealed card — post-handoff silence check.
            # If Assessment was already submitted for this room, silently
            # consume non-card messages to prevent chatter loops.
            if room_id and room_id in _handoff_rooms:
                logger.debug(
                    f"[diagnosis] Post-handoff silence: consuming non-card "
                    f"message in room {room_id[:12]}..."
                )
                return None

            # Check freshness for non-sealed chatter
            inserted_at = getattr(payload, "inserted_at", None)
            if should_skip_stale_chatter(str(inserted_at) if inserted_at else None, self._boot_epoch, "diagnosis"):
                return None
            return await self._default_preprocessor.process(ctx, event, **kwargs)

        card_type = card_data.get("card_type")

        # ---- Handle Verdict(CHALLENGE) from Risk & Legal Agent ----
        if card_type == "Verdict":
            return await self._handle_challenge(
                card_data, sender_id, sender_type, room_id,
                room_message_id, ctx, event, **kwargs,
            )

        if card_type != "TriageDecision":
            # Not a TriageDecision or Verdict — silent consume if sealed
            if has_seal_fields(card_data):
                logger.info(
                    f"[diagnosis] Silently consuming unsupported sealed "
                    f"card {card_type} for routing"
                )
                return None
            # Card-shaped but no seal fields — reject + log
            if card_type:
                logger.warning(
                    f"[diagnosis] Card-shaped payload missing seal fields "
                    f"(type={card_type}) — rejected"
                )
                return None
            # Non-card content — pass through
            return await self._default_preprocessor.process(ctx, event, **kwargs)

        # ----- Sender Validation -----
        if sender_type != "Agent":
            logger.warning(
                f"[diagnosis] REJECTED TriageDecision from non-agent "
                f"sender_type={sender_type!r}"
            )
            return None

        if not self._triage_agent_id:
            logger.error(
                "[diagnosis] REJECTED TriageDecision: TRIAGE_AGENT_ID not configured. "
                "Cannot verify sender identity."
            )
            return None

        if sender_id != self._triage_agent_id:
            logger.warning(
                f"[diagnosis] REJECTED TriageDecision from untrusted agent "
                f"{sender_id!r} — expected Triage {self._triage_agent_id!r}"
            )
            return None

        # ----- Seal Field Check -----
        if not has_seal_fields(card_data):
            return None

        # ----- Active Proposal Allowlist (credit protection) -----
        proposal_id_for_guard = card_data.get("proposal_id", "")
        if ACTIVE_PROPOSALS and proposal_id_for_guard not in ACTIVE_PROPOSALS:
            logger.info(f"[diagnosis] Skipping non-active proposal {proposal_id_for_guard}")
            return None

        # ----- Stale Card Guard (cost optimization) -----
        card_seq = card_data.get("sequence_number")
        if proposal_id_for_guard and await should_skip_stale_card(proposal_id_for_guard, card_seq, "diagnosis"):
            return None

        # ----- Pydantic Validation -----
        try:
            validated = TriageDecision(**card_data)
        except Exception as exc:
            logger.warning(
                "[diagnosis] TriageDecision validation failed (%s)",
                type(exc).__name__,
            )
            return None

        # ----- Reject suppress (defense-in-depth) -----
        if validated.decision == "suppress":
            logger.info(
                f"[diagnosis] Ignoring TriageDecision(suppress) for "
                f"{validated.proposal_id}"
            )
            return None

        # ----- Reject duplicate (active OR already submitted) -----
        # Challenge re-entry is handled by _handle_challenge() which receives
        # Verdict(CHALLENGE) via the card-type router, not this TriageDecision path.
        proposal_id = validated.proposal_id
        existing = _trusted_context.get(proposal_id)
        if existing is not None:
            if existing.submitted:
                logger.warning(
                    f"[diagnosis] Redelivered TriageDecision for already-submitted "
                    f"proposal {proposal_id} — ignoring (prevents duplicate Assessment)"
                )
            else:
                logger.warning(
                    f"[diagnosis] Duplicate TriageDecision for active proposal "
                    f"{proposal_id} — ignoring"
                )
            return None

        # ------------------------------------------------------------------
        # CHALLENGE re-entry: If the incoming message is a Verdict(CHALLENGE)
        # from Risk & Legal Agent, reset context for re-investigation.
        # ------------------------------------------------------------------
        # (This block is never reached for TriageDecisions — it's a fallback
        # for when the card_type check above redirects to the Verdict handler.)
        # The actual CHALLENGE handler is below, after the TriageDecision path.

        # Extract room message timestamp for freshness calculation.
        # Local room payloads use inserted_at: str (ISO 8601), not created_at.
        msg_inserted_at = getattr(payload, "inserted_at", None)
        if msg_inserted_at is not None:
            try:
                # inserted_at is an ISO 8601 string (e.g. "2026-06-13T14:00:00Z")
                # Python 3.11+ fromisoformat handles Z suffix natively.
                signal_ts = datetime.fromisoformat(str(msg_inserted_at)).timestamp()
            except (ValueError, TypeError):
                signal_ts = time.time()
        else:
            signal_ts = time.time()

        _trusted_context[proposal_id] = ProposalContext(
            proposal_id=proposal_id,
            signal_id=validated.signal_id,
            room_id=room_id,
            room_message_id=room_message_id,
            source_card_hash=card_data.get("card_hash", ""),
            triage_decision_raw=card_data,
            signal_timestamp=signal_ts,
        )

        logger.info(
            f"[diagnosis] Accepted TriageDecision(route) for {proposal_id}. "
        f"Context stored. Delegating to local LLM investigation."
        )

        # ----- Delegate to local proposal-room runtime -----
        return await self._default_preprocessor.process(ctx, event, **kwargs)

    async def _handle_challenge(
        self, card_data: dict, sender_id: str, sender_type: str,
        room_id: str, room_message_id: str, ctx, event, **kwargs,
    ):
        """Handle Verdict(CHALLENGE) from Risk & Legal Agent.

        Validates sender, checks that an Assessment was previously submitted,
        resets tool results, increments revision, and re-delegates locally
        for re-investigation.
        """
        # Sender validation: only Risk & Legal Agent may CHALLENGE (fail-closed)
        if sender_type != "Agent":
            logger.warning(
                f"[diagnosis] REJECTED Verdict from non-agent "
                f"sender_type={sender_type!r}"
            )
            return None

        if not self._safety_reviewer_agent_id:
            logger.warning(
                "[diagnosis] REJECTED CHALLENGE — SAFETY_REVIEWER_AGENT_ID "
                "not configured. Fail-closed: cannot verify sender."
            )
            return None

        if sender_id != self._safety_reviewer_agent_id:
            logger.warning(
                f"[diagnosis] REJECTED Verdict from untrusted agent "
                f"{sender_id!r} — expected Risk & Legal Agent "
                f"{self._safety_reviewer_agent_id!r}"
            )
            return None

        # Pydantic validation
        try:
            verdict = Verdict(**card_data)
        except Exception as exc:
            logger.warning(
                "[diagnosis] Verdict validation failed (%s)",
                type(exc).__name__,
            )
            return None

        # Only process CHALLENGE decisions
        if verdict.decision != "CHALLENGE":
            logger.info(
                f"[diagnosis] Received Verdict({verdict.decision}) for "
                f"{verdict.proposal_id} — not a CHALLENGE, ignoring"
            )
            return None

        proposal_id = verdict.proposal_id

        # ----- Active Proposal Allowlist (credit protection) -----
        if ACTIVE_PROPOSALS and proposal_id not in ACTIVE_PROPOSALS:
            logger.info(f"[diagnosis] Skipping CHALLENGE for non-active proposal {proposal_id}")
            return None

        existing = _trusted_context.get(proposal_id)

        # CHALLENGE requires a prior submitted Assessment
        if existing is None or not existing.submitted:
            logger.warning(
                f"[diagnosis] CHALLENGE for {proposal_id} but no "
                f"submitted Assessment exists — ignoring"
            )
            return None

        # Reset context for re-investigation
        async with existing.lock:
            existing.submitted = False
            existing.tool_results.clear()
            existing.tools_completed.clear()
            existing.revision += 1
            existing.challenge_request = verdict.challenge_request
            existing.room_message_id = room_message_id
            existing.source_card_hash = card_data.get("card_hash", "")

        logger.info(
            f"[diagnosis] CHALLENGE accepted for {proposal_id} "
            f"(revision {existing.revision}). "
            f"Challenge: {verdict.challenge_request or 'no specific request'}. "
            f"Re-investigating."
        )

        # Re-delegate for local LLM-assisted re-investigation
        return await self._default_preprocessor.process(ctx, event, **kwargs)


# ---------------------------------------------------------------------------
# Agent factory
# ---------------------------------------------------------------------------

async def create_diagnosis_agent():
    """Create the Treasury Intelligence Agent on the Gateway-owned proposal-room runtime."""
    # Validate inexpensive configuration before starting the local runtime.
    # This makes deployment errors fail immediately and keeps startup
    # validation tests from initializing provider runtimes unnecessarily.
    diagnosis_agent_id = os.getenv("DIAGNOSIS_AGENT_ID", "")
    diagnosis_api_key = get_agent_api_key("diagnosis")
    required_vars = {
        "DIAGNOSIS_AGENT_ID": diagnosis_agent_id,
        "TRIAGE_AGENT_ID": os.getenv("TRIAGE_AGENT_ID", ""),
        "DIAGNOSIS_SUBMISSION_KEY": os.getenv("DIAGNOSIS_SUBMISSION_KEY", ""),
        "SAFETY_REVIEWER_AGENT_ID": os.getenv("SAFETY_REVIEWER_AGENT_ID", ""),
        "DIAGNOSIS_API_KEY": diagnosis_api_key,
        "LLM_API_KEY": get_provider_settings()["llm"]["api_key"],
        "PROPOSAL_SIMULATOR_URL": PROPOSAL_SIMULATOR_URL,
    }
    missing = [name for name, value in required_vars.items() if not value]
    if missing:
        raise RuntimeError(
            "Treasury Intelligence Agent cannot start: missing required env vars: "
            f"{', '.join(missing)}. Set them in .env before starting."
        )
    logger.info("[diagnosis] Startup validation passed — all required IDs configured")

    config = MODELS["diagnosis"]
    preprocessor = DiagnosisPreprocessor(
        diagnosis_agent_id=diagnosis_agent_id,
        diagnosis_api_key=diagnosis_api_key,
    )

    agent = LocalRoomAgent(
        role="diagnosis",
        agent_id=diagnosis_agent_id,
        agent_key=diagnosis_api_key,
        preprocessor=preprocessor,
        on_agent_input=run_local_diagnosis,
        framework="Council Runtime + LLM",
        model=config.model,
    )

    return agent


async def main():
    logging.basicConfig(level=logging.INFO)
    await run_with_supervisor(create_diagnosis_agent, "diagnosis")


if __name__ == "__main__":
    asyncio.run(main())
