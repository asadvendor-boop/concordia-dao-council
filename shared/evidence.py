"""Concordia DAO Council Evidence Strength Computation — Deterministic formula.

Measures how well evidence supports the specific root-cause hypothesis.
NOT just counting anomalous sources — weights hypothesis-relevant signals.

The aggregation formula is deterministic. The relevance_score inputs are
advisory-model reviewed by Mercer against a rubric. We claim the aggregation is
deterministic, not the input judgments.
"""
from __future__ import annotations


SOURCES = ("risk_events", "treasury_metrics", "governance_events", "policy_compliance", "casper_node_status")


def compute_evidence_strength(signals: dict, hypothesis: str | None = None) -> float:
    """Compute evidence strength from multi-source signals.

    Args:
        signals: Dict with keys per source. Each source has:
            - anomaly_detected: bool
            - relevance_score: float (0.0-1.0, advisory-model reviewed)
        hypothesis: Root-cause hypothesis string (for documentation; not
            used in formula — relevance_score already encodes it).

    Returns:
        Float 0.0-1.0 representing evidence quality.

    Example outputs:
        Unsafe governance event (all 4 anomalous, all highly relevant): ~0.90
        Risky treasury proposal (3/4, mixed relevance): ~0.53
        Stale noisy signal (2/4, low relevance, old): ~0.10
    """
    hypothesis_support = 0.0
    for source in SOURCES:
        source_data = signals.get(source, {})
        if source_data.get("anomaly_detected", False):
            relevance = source_data.get("relevance_score", 0.5)
            hypothesis_support += relevance / len(SOURCES)

    temporal = compute_temporal_correlation(signals)
    recency = compute_recency(signals)
    return round(hypothesis_support * temporal * recency, 2)


def compute_temporal_correlation(signals: dict) -> float:
    """Derive from governance-event timestamp gap. Deterministic.

    - ≤5min  → 0.95 (strong temporal link)
    - ≤15min → 0.80
    - ≤60min → 0.50
    - >60min → 0.20 (weak temporal link)
    - No governance event → 1.0 (neutral)
    """
    gap_minutes = signals.get("governance_event_gap_minutes")
    if gap_minutes is None:
        return 1.0
    if gap_minutes <= 5:
        return 0.95
    elif gap_minutes <= 15:
        return 0.8
    elif gap_minutes <= 60:
        return 0.5
    else:
        return 0.2


def compute_recency(signals: dict) -> float:
    """Derive from ProposalCard timestamp vs current time. Deterministic.

    - <10 minutes old → 1.0 (fresh)
    - ≥10 minutes old → 0.7 (stale discount)
    """
    freshness_minutes = signals.get("freshness_minutes", 0)
    return 1.0 if freshness_minutes < 10 else 0.7
