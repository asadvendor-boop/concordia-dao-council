from __future__ import annotations

from pathlib import Path

import pytest

from shared.governance_archive import build_governance_archive
from shared.proof_pack import build_council_reputation
from shared.skill_registry import list_agent_skills


ROOT = Path(__file__).resolve().parents[1]


def _casper_action() -> dict[str, object]:
    return {
        "action_id": "execute_casper_governance_receipt",
        "network": "casper-test",
        "contract_hash": "a" * 64,
        "entry_point": "store_governance_receipt",
        "transaction_hash": "b" * 64,
        "receipt_payload": {
            "decision": "APPROVED_WITH_LIMITS",
            "payload_hash": "c" * 64,
            "final_card_hash": "d" * 64,
            "plan_hash": "e" * 64,
            "policy_hash": "f" * 64,
            "policy_version": "2026.06.cas-v1",
            "dissent_hash": "1" * 64,
            "risk_level": "high",
            "risk_score": 72,
            "approved_allocation_bps": 800,
            "evidence_uri": "https://example.test/evidence/DAO-PROP-TEST",
        },
    }


def test_future_archive_is_core_built_locke_sealed_and_deterministic() -> None:
    timeline = [
        {
            "timestamp": "2026-07-22T18:41:03+00:00",
            "event": "casper_transaction_verified",
        }
    ]

    first = build_governance_archive(
        proposal_id="DAO-PROP-TEST",
        actions_taken=[_casper_action()],
        timeline=timeline,
    )
    second = build_governance_archive(
        proposal_id="DAO-PROP-TEST",
        actions_taken=[_casper_action()],
        timeline=timeline,
    )

    assert first == second
    assert first["created_by"] == "Concordia Core"
    assert first["sealed_by"] == "Locke"
    assert first["presentation_persona"] == "Wells"
    assert first["created_at"] == "2026-07-22T18:41:03Z"
    assert first["archive_hash"].startswith("sha256:")


@pytest.mark.parametrize(
    "timeline",
    [
        [],
        [{"event": "casper_transaction_verified"}],
        [{"event": "casper_transaction_verified", "timestamp": "not-a-time"}],
        [{"event": "casper_transaction_verified", "timestamp": "2026-07-22T18:41:03"}],
    ],
)
def test_future_archive_requires_an_observed_utc_timeline_timestamp(
    timeline: list[dict[str, str]],
) -> None:
    with pytest.raises(ValueError, match="UTC timeline timestamp"):
        build_governance_archive(
            proposal_id="DAO-PROP-TEST",
            actions_taken=[_casper_action()],
            timeline=timeline,
        )


def test_reputation_separates_core_archive_from_optional_wells_summary() -> None:
    evidence = {
        "cards": [
            {
                "card_type": "CasperExecutionReceipt",
                "data": {
                    "card_type": "CasperExecutionReceipt",
                    "actions_taken": [],
                    "governance_archive": {"archive_hash": "sha256:" + "a" * 64},
                },
            },
            {
                "card_type": "GovernanceSummary",
                "data": {"card_type": "GovernanceSummary"},
            },
        ]
    }

    reputation = build_council_reputation(evidence, {"status": "unavailable"})
    by_metric = {(item["agent"], item["metric"]): item["value"] for item in reputation}

    assert by_metric[("Concordia Core", "Archives sealed")] == 1
    assert by_metric[("Wells", "Optional summaries")] == 1


def test_locke_runtime_uses_core_archive_event_and_optional_wells_request() -> None:
    source = (ROOT / "agents" / "locke" / "__init__.py").read_text(encoding="utf-8")

    assert '"event": "core_governance_archive_created"' in source
    assert '"event": "wells_governance_archive_created"' not in source
    assert "non-authoritative presentation persona" in source
    assert '"response_expected": False' in source


def test_wells_is_declared_as_a_non_reasoning_presentation_persona() -> None:
    source = (ROOT / "agents" / "wells" / "__init__.py").read_text(encoding="utf-8")
    wells = next(skill for skill in list_agent_skills() if skill["role"] == "scribe")

    assert '"model": "none"' in source
    assert "LLM_SCRIBE_MODEL" not in source
    assert wells["model_role"] == "Non-reasoning presentation persona"
    assert "no model call" in wells["model_use"].lower()


def test_gateway_describes_the_actual_role_taxonomy() -> None:
    source = (ROOT / "gateway" / "app.py").read_text(encoding="utf-8")

    assert "six-agent core" not in source
    assert "four deliberative agents" in source
    assert "authorization-bound Locke" in source
    assert "presentation-only Wells" in source
    assert "Wells, the Governance Archivist, produces" not in source
