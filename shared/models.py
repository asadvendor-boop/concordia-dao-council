"""Concordia DAO Council Structured Message Protocol — Pydantic v2 card schemas.

All agent communication uses typed cards posted to Council Chambers.
Cards are sealed by the Gateway before posting (seal-before-send).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class CardBase(BaseModel):
    """All cards include Gateway-assigned chain fields for integrity."""
    sequence_number: int | None = None
    previous_card_hash: str | None = None
    card_hash: str | None = None

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of the card excluding the hash field itself."""
        canonical = json.dumps(
            self.model_dump(exclude={"card_hash"}),
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Card Types
# ---------------------------------------------------------------------------

class ProposalCard(CardBase):
    """Incoming signal normalized by Recorder from external sources."""
    card_type: Literal["ProposalCard"] = "ProposalCard"
    signal_id: str
    source: Literal["governance_feed", "treasury_metrics", "casper_events", "rwa_oracle"]
    timestamp: datetime
    title: str
    raw_payload: dict = Field(default_factory=dict)
    fingerprint: str  # SHA-256 for dedup
    preliminary_severity: Literal[
        "critical", "high", "medium", "low", "P1", "P2", "P3", "P4", "unknown"
    ] = "unknown"
    security_relevant: bool = False


class TriageDecision(CardBase):
    """Proposal Sentinel's routing decision for a signal."""
    card_type: Literal["TriageDecision"] = "TriageDecision"
    proposal_id: str
    signal_id: str
    decision: Literal["route", "suppress"]
    noise_score: float = Field(ge=0.0, le=1.0, default=0.0)
    suppression_rule_id: str | None = None  # If suppressed, which rule matched
    reasoning: str = ""


class Assessment(CardBase):
    """Treasury Intelligence Agent's investigation result."""
    card_type: Literal["Assessment"] = "Assessment"
    proposal_id: str
    severity: Literal["critical", "high", "medium", "low", "P1", "P2", "P3", "P4"]
    evidence_strength: float = Field(ge=0.0, le=1.0)
    blast_radius: list[str] = Field(default_factory=list)
    root_cause_hypothesis: str
    recommended_action: str
    evidence: dict = Field(default_factory=dict)
    revision: int = 1
    state: str = "assessed"


class Verdict(CardBase):
    """Risk & Legal Agent's independent review of the Treasury Intelligence Agent assessment."""
    card_type: Literal["Verdict"] = "Verdict"
    proposal_id: str
    decision: Literal["CONFIRM", "CHALLENGE", "FALSE_ALARM", "NEEDS_HUMAN"]
    cross_check_sources: list[str] = Field(default_factory=list)
    reasoning: str
    agrees_with_diagnosis: bool
    challenge_request: str | None = None
    suppression_advice: str | None = None
    policy_hash: str | None = None
    policy_version: str | None = None
    dissent_hash: str | None = None
    dissent_receipt: dict | None = None
    violated_rules: list[dict] = Field(default_factory=list)


class ExecutionEnvelope(BaseModel):
    """A single typed action within a ResponsePlan.
    
    Humans approve the exact typed envelopes, not a text description.
    The action_hash covers the canonical JSON of all envelopes.
    """
    action_id: str  # e.g. "execute_casper_governance_receipt"
    target: str     # e.g. "casper-testnet", "dao-treasury"
    parameters: dict = Field(default_factory=dict)
    timeout_seconds: int = 300
    fallback_action: str | None = None


class ResponsePlan(CardBase):
    """Protocol Strategy Agent's governance execution plan with typed execution envelopes."""
    card_type: Literal["ResponsePlan"] = "ResponsePlan"
    proposal_id: str
    runbook: Literal["RB-001", "RB-002", "RB-003", "RB-004", "RB-005", "RB-006"]
    envelopes: list[ExecutionEnvelope] = Field(default_factory=list)
    risk_level: Literal["low", "medium", "high", "critical"]
    requires_human_approval: bool
    priority_rank: int | None = None
    revision: int = 1


class StructuredApproval(CardBase):
    """Both Protocol Strategy Agent and Casper Execution Agent independently verify from PlatformMessage."""
    card_type: Literal["StructuredApproval"] = "StructuredApproval"
    proposal_id: str
    action_id: str
    action_hash: str
    decision: Literal["APPROVED", "REJECTED", "FALSE_ALARM"]
    approver_id: str
    room_message_id: str = ""
    legacy_room_id: str = ""
    plan_hash: str
    nonce: str  # 6-char challenge nonce
    expiry: datetime
    reason: str | None = None
    approval_channel: Literal["room", "gateway_ui"] = "room"
    runbook_version: str = "1.0"
    plan_revision: int = 1


class PolicyAuthorization(CardBase):
    """Deterministic authorization for low-risk actions — no human needed."""
    card_type: Literal["PolicyAuthorization"] = "PolicyAuthorization"
    proposal_id: str
    authorization_id: str
    plan_hash: str
    action_hash: str
    risk_level: Literal["low", "medium"]
    policy_rule: str
    expiry: datetime
    envelopes: list[dict] = Field(default_factory=list)
    runbook_version: str = "1.0"


class ActionReceipt(CardBase):
    """Casper Execution Agent's record of actions taken."""
    card_type: Literal["CasperExecutionReceipt"] = "CasperExecutionReceipt"
    proposal_id: str
    authorization_type: Literal["human_approval", "policy"]
    authorization_id: str
    actions_taken: list[dict] = Field(default_factory=list)
    timeline: list[dict] = Field(default_factory=list)
    governance_archive: dict = Field(default_factory=dict)
    resolution_summary: str = ""
    state: str = "executed"


class GovernanceSummary(CardBase):
    """Optional presentation summary with no authorization or execution role."""
    card_type: Literal["GovernanceSummary"] = "GovernanceSummary"
    proposal_id: str
    timeline_summary: str = ""
    root_cause: str = ""
    what_worked: list[str] = Field(default_factory=list)
    action_items: list[str] = Field(default_factory=list)


class AuditSeal(BaseModel):
    """Non-chain model — anchors the chain, not inside it.
    Posted by Recorder via REST event, not as a chat message."""
    card_type: Literal["AuditSeal"] = "AuditSeal"
    proposal_id: str
    chain_root_hash: str
    total_cards: int
    sealed_at: datetime


# ---------------------------------------------------------------------------
# Run Summary (for ROI dashboard)
# ---------------------------------------------------------------------------

class RunSummary(BaseModel):
    """Aggregated metrics for a completed proposal run."""
    proposal_id: str
    total_signals: int = 0
    suppressed_signals: int = 0
    time_to_diagnosis_seconds: float = 0.0
    time_to_resolution_seconds: float = 0.0
    challenge_loops: int = 0
    human_escalations: int = 0
    total_cost_usd: float = 0.0
    cards_in_chain: int = 0
    chain_verified: bool = False


# ---------------------------------------------------------------------------
# Card Registry & Parser
# ---------------------------------------------------------------------------

CARD_TYPES = {
    "ProposalCard": ProposalCard,
    "TriageDecision": TriageDecision,
    "Assessment": Assessment,
    "Verdict": Verdict,
    "ResponsePlan": ResponsePlan,
    "StructuredApproval": StructuredApproval,
    "PolicyAuthorization": PolicyAuthorization,
    "CasperExecutionReceipt": ActionReceipt,
    "GovernanceSummary": GovernanceSummary,
}


def parse_card(card_json: str | dict) -> CardBase:
    """Parse a JSON string or dict into the correct card type via discriminated union."""
    if isinstance(card_json, str):
        data = json.loads(card_json)
    else:
        data = card_json
    card_type = data.get("card_type")
    if card_type not in CARD_TYPES:
        raise ValueError(f"Unknown card_type: {card_type}")
    return CARD_TYPES[card_type].model_validate(data)
