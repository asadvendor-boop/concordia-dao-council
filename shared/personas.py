"""Canonical Concordia DAO Council personas."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AgentPersona:
    role: str
    display_name: str
    title: str
    temperament: str

    @property
    def full_name(self) -> str:
        return self.display_name


PERSONAS: dict[str, AgentPersona] = {
    "triage": AgentPersona(
        role="triage",
        display_name="Rowan",
        title="Proposal Sentinel",
        temperament="fast, watchful, and decisive when routing material DAO proposals",
    ),
    "diagnosis": AgentPersona(
        role="diagnosis",
        display_name="Mercer",
        title="Treasury Intelligence Agent",
        temperament="financial, analytical, and evidence-driven about treasury exposure and Casper liquidity signals",
    ),
    "safety_reviewer": AgentPersona(
        role="safety_reviewer",
        display_name="Verity",
        title="Risk & Legal Agent",
        temperament="adversarial, policy-aware, and uncompromising when proposals exceed DAO risk limits",
    ),
    "commander": AgentPersona(
        role="commander",
        display_name="Alden",
        title="Protocol Strategy Agent",
        temperament="calm, structural, and precise about executable governance envelopes",
    ),
    "operator": AgentPersona(
        role="operator",
        display_name="Locke",
        title="Casper Execution Agent",
        temperament="deterministic, authorization-bound, and intolerant of any unapproved parameter change",
    ),
    "recorder": AgentPersona(
        role="recorder",
        display_name="Concordia Core",
        title="Deterministic Evidence Core",
        temperament="neutral, exacting, and focused on evidence-chain integrity",
    ),
    "scribe": AgentPersona(
        role="scribe",
        display_name="Wells",
        title="Governance Archive Persona",
        temperament="clear, concise, and focused on post-decision accountability",
    ),
}


def get_persona(role: str) -> AgentPersona | None:
    return PERSONAS.get(role)


def persona_payload(role: str) -> dict[str, str]:
    persona = get_persona(role)
    if persona is None:
        return {}
    return {
        "display_name": persona.full_name,
        "persona_title": persona.title,
        "persona_temperament": persona.temperament,
    }
