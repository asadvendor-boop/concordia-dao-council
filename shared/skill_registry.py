"""Agent skill registry for Concordia DAO Council.

This deterministic metadata lets the Gateway, dashboard, tests, and
submission documentation point to the same first-class list of DAO governance
skills without requiring live model calls.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .personas import PERSONAS

PUBLIC_TOOL_NAMESPACES = {
    "triage": "rowan",
    "diagnosis": "mercer",
    "safety_reviewer": "verity",
    "commander": "alden",
    "operator": "locke",
    "recorder": "core",
    "scribe": "wells",
}


@dataclass(frozen=True)
class AgentSkill:
    role: str
    agent_name: str
    persona_title: str
    skill_id: str
    skill_name: str
    category: str
    model_role: str
    input_contract: str
    output_contract: str
    tool_name: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    prompt_contract: str
    deterministic_guardrail: str
    evidence_artifact: str
    model_use: str
    dao_requirement: str
    demo_cue: str


def _skill(
    role: str,
    skill_id: str,
    skill_name: str,
    category: str,
    model_role: str,
    input_contract: str,
    output_contract: str,
    prompt_contract: str,
    deterministic_guardrail: str,
    evidence_artifact: str,
    model_use: str,
    dao_requirement: str,
    demo_cue: str,
) -> AgentSkill:
    persona = PERSONAS[role]
    public_namespace = PUBLIC_TOOL_NAMESPACES[role]
    tool_name = f"concordia.{public_namespace}.{skill_id.replace('-', '_')}"
    return AgentSkill(
        role=role,
        agent_name=persona.full_name,
        persona_title=persona.title,
        skill_id=skill_id,
        skill_name=skill_name,
        category=category,
        model_role=model_role,
        input_contract=input_contract,
        output_contract=output_contract,
        tool_name=tool_name,
        input_schema={
            "type": "object",
            "title": f"{skill_name} input",
            "required": ["proposal_id", "previous_card_hash", "payload"],
            "properties": {
                "proposal_id": {"type": "string"},
                "previous_card_hash": {"type": "string"},
                "payload": {"type": "object", "description": input_contract},
            },
        },
        output_schema={
            "type": "object",
            "title": f"{skill_name} output",
            "required": ["card_type", "card_hash", "decision_payload"],
            "properties": {
                "card_type": {"type": "string", "const": evidence_artifact},
                "card_hash": {"type": "string"},
                "decision_payload": {"type": "object", "description": output_contract},
            },
        },
        prompt_contract=prompt_contract,
        deterministic_guardrail=deterministic_guardrail,
        evidence_artifact=evidence_artifact,
        model_use=model_use,
        dao_requirement=dao_requirement,
        demo_cue=demo_cue,
    )


AGENT_SKILLS: tuple[AgentSkill, ...] = (
    _skill(
        "triage",
        "proposal-routing",
        "Proposal intake and routing",
        "intake",
        "Fast advisory model",
        "ProposalCard plus treasury policy hints and source fingerprint.",
        "One ProposalRoutingDecision: route, suppress, or escalate.",
        "Classify proposal validity, policy relevance, and the next responsible role.",
        "High-risk treasury or compliance proposals always route to specialist review.",
        "TriageDecision",
        "The model supplies bounded routing reasoning; deterministic policy owns the final route.",
        "Specialized agent role assignment",
        "Show the first handoff from Proposal Recorder to Proposal Intake in the evidence timeline.",
    ),
    _skill(
        "diagnosis",
        "treasury-analysis",
        "Treasury and protocol analysis",
        "analysis",
        "Deep advisory model",
        "ProposalRoutingDecision plus policy, treasury, liquidity, and contract snapshots.",
        "One TreasuryRiskAssessment with severity, evidence strength, and action hint.",
        "Fuse governance evidence into risk, treasury impact, and proposed action.",
        "Challenge redelivery forces a fresh revision and clears cached tool context.",
        "Assessment",
        "The model fuses evidence snapshots into a bounded Assessment payload.",
        "Specialized treasury analysis",
        "Open an Assessment card and point to the cited policy, treasury, liquidity, and contract evidence.",
    ),
    _skill(
        "safety_reviewer",
        "risk-legal-challenge",
        "Independent risk and legal review",
        "governance",
        "Deep advisory model",
        "TreasuryRiskAssessment with evidence summary and revision context.",
        "One RiskLegalVerdict: CONFIRM, CHALLENGE, FALSE_ALARM, or NEEDS_HUMAN.",
        "Confirm, challenge, escalate, or close the proposal with explicit reasoning.",
        "A challenge is sealed as a Verdict and returns the proposal to Treasury Intelligence Agent.",
        "Verdict",
        "The model performs independent review; deterministic checks prevent weak evidence from passing.",
        "Disagreement resolution",
        "Show a Verdict(CHALLENGE) followed by Assessment(revision=2).",
    ),
    _skill(
        "commander",
        "governance-planning",
        "Governance execution planning",
        "planning",
        "Deep advisory model",
        "Confirmed Verdict, Assessment, treasury policy, and rejection history.",
        "One GovernanceExecutionPlan with nonce-bound exact action envelopes.",
        "Select a safe execution path and produce exact action envelopes for approval.",
        "Risk policy and human rejection history bound the allowed envelopes.",
        "ResponsePlan",
        "The model proposes the plan; policy code narrows unsafe choices.",
        "Negotiated planning",
        "Show a human rejection forcing the Planner to issue a revised ResponsePlan.",
    ),
    _skill(
        "operator",
        "casper-execution",
        "Casper transaction execution",
        "execution",
        "Fast advisory model",
        "Consumed authorization plus sealed GovernanceExecutionPlan envelopes.",
        "One CasperExecutionReceipt with transaction hash and Casper Testnet anchoring result.",
        "Execute only the approved envelope and commit the governance receipt to Casper Testnet.",
        "Any target, parameter, count, or action mismatch is rejected before side effects.",
        "CasperExecutionReceipt",
        "The model narrates execution intent; the exact-envelope checker owns side effects.",
        "Autonomous on-chain coordination",
        "Show that CasperExecutionReceipt matches the approved envelope and includes a Casper transaction hash.",
    ),
    _skill(
        "recorder",
        "evidence-sealing",
        "Evidence sealing and state transition",
        "control-plane",
        "Deterministic Gateway",
        "Prepared cards, idempotency keys, nonces, and publication receipts.",
        "Canonical card rows, state transitions, evidence exports, and room messages.",
        "Normalize cards, enforce state transitions, and publish the governance-room trail.",
        "SHA-256 card hashes, nonce binding, and publication verification are owned by the Gateway.",
        "ProposalCard",
        "Deterministic control-plane skill; no model call is needed to seal authority.",
        "Shared memory and audit substrate",
        "Show /evidence/{proposal_id} recomputing the card chain.",
    ),
    _skill(
        "scribe",
        "governance-summary",
        "GovernanceSummary enrichment",
        "summary",
        "Optional advisory model",
        "Terminal evidence chain and CasperExecutionReceipt summary.",
        "Optional governance narrative that cannot authorize or execute.",
        "Turn the final evidence chain into a concise governance summary.",
        "The scribe never authorizes or executes transactions; it is summary-only.",
        "GovernanceSummary",
        "Optional narrative layer over terminal evidence.",
        "Post-resolution collaboration",
        "Mention as optional enrichment after CasperExecutionReceipt, not as an authority boundary.",
    ),
)


def list_agent_skills() -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for skill in AGENT_SKILLS:
        data = asdict(skill)
        # Backward-compatible dashboard aliases.
        data["llm_cloud_use"] = data["model_use"]
        data["dao_requirement"] = data["dao_requirement"]
        data["review_demo_cue"] = data["demo_cue"]
        payloads.append(data)
    return payloads


def skill_roles() -> list[str]:
    return [skill.role for skill in AGENT_SKILLS]


def skill_manifest() -> dict[str, Any]:
    """Return the public, MCP-style skill manifest for dashboard review."""
    skills = list_agent_skills()
    return {
        "project": "Concordia DAO Council",
        "manifest_version": "concordia.dao-council.skill-manifest.v1",
        "style": "MCP-style tool contract manifest",
        "mcp_integration": (
            "Inspectable tool contracts are exposed by this manifest. "
            "An optional FastMCP bridge is available in integrations/mcp/ "
            "for Casper MCP and CSPR.trade MCP tool calls."
        ),
        "primary_direction": "Multi-Agent DAO Governance & Execution",
        "total_skills": len(skills),
        "roles": skill_roles(),
        "evidence_endpoints": {
            "skill_registry": "/agent-skills",
            "evidence_chain": "/evidence/{proposal_id}",
            "run_summary": "/stats/runsummary",
        },
        "claims": {
            "distinct_capabilities": "Each role exposes one named tool contract and one evidence artifact.",
            "task_decomposition": "Role-owned cards form the DAO proposal handoff sequence.",
            "disagreement_resolution": "Verdict(CHALLENGE) and StructuredApproval(REJECTED) force revisions.",
            "execution_conflict_resolution": "Casper Execution Agent output must exactly match the authorized envelope.",
            "on_chain_coordination": "Approved final card hashes are anchored to Casper Testnet.",
        },
        "skills": skills,
    }
