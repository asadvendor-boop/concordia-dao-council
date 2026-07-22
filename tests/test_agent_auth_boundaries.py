"""Adversarial tests for role-bound Gateway transport authentication."""

from __future__ import annotations

import pytest

from gateway import auth
from gateway.routes import submission


@pytest.fixture(autouse=True)
def _clear_auth_caches(monkeypatch: pytest.MonkeyPatch):
    names = [
        "GATEWAY_SECRET",
        "RECORDER_SUBMISSION_KEY",
        "TRIAGE_SUBMISSION_KEY",
        "DIAGNOSIS_SUBMISSION_KEY",
        "SAFETY_REVIEWER_SUBMISSION_KEY",
        "COMMANDER_SUBMISSION_KEY",
        "OPERATOR_SUBMISSION_KEY",
        "SCRIBE_SUBMISSION_KEY",
        "PROPOSAL_ROOM_API_KEY",
    ]
    for name in names:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(f"{name}_FILE", raising=False)
    auth._reset_for_testing()
    submission._reset_agent_keys_for_testing()
    yield
    auth._reset_for_testing()
    submission._reset_agent_keys_for_testing()


def test_gateway_secret_is_never_an_agent_identity(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GATEWAY_SECRET", "global-secret")

    assert auth.get_role_for_key("global-secret") is None
    allowed, _ = submission._authenticate_agent("global-secret", "ProposalCard")
    assert allowed is False


def test_dedicated_role_key_retains_least_privilege(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("TRIAGE_SUBMISSION_KEY", "triage-only")

    assert auth.get_role_for_key("triage-only") == "triage"
    assert submission._authenticate_agent("triage-only", "TriageDecision") == (
        True,
        "triage",
    )
    allowed, detail = submission._authenticate_agent("triage-only", "Verdict")
    assert allowed is False
    assert "cannot submit Verdict" in detail


def test_duplicate_key_across_roles_fails_closed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("TRIAGE_SUBMISSION_KEY", "ambiguous")
    monkeypatch.setenv("DIAGNOSIS_SUBMISSION_KEY", "ambiguous")

    assert auth.get_role_for_key("ambiguous") is None
    allowed, _ = submission._authenticate_agent("ambiguous", "TriageDecision")
    assert allowed is False


def test_proposal_room_scribe_fallback_is_role_bound(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PROPOSAL_ROOM_API_KEY", "scribe-only")

    assert auth.get_role_for_key("scribe-only") == "scribe"
    allowed, _ = submission._authenticate_agent("scribe-only", "ProposalCard")
    assert allowed is False
