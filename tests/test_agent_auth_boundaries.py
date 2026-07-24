"""Adversarial tests for role-bound Gateway transport authentication."""

from __future__ import annotations

import pytest

from gateway import auth
from gateway.routes import submission
from shared import proposal_room


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
    for role in (
        "RECORDER",
        "TRIAGE",
        "DIAGNOSIS",
        "SAFETY_REVIEWER",
        "COMMANDER",
        "OPERATOR",
        "SCRIBE",
    ):
        monkeypatch.delenv(f"{role}_AGENT_ID", raising=False)
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

    with pytest.raises(auth.AgentIdentityConfigurationError, match="duplicate agent key"):
        auth.validate_agent_identity_configuration()
    with pytest.raises(auth.AgentIdentityConfigurationError, match="duplicate agent key"):
        submission._authenticate_agent("ambiguous", "TriageDecision")


def test_duplicate_agent_id_across_roles_fails_configuration(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("TRIAGE_SUBMISSION_KEY", "triage-key")
    monkeypatch.setenv("DIAGNOSIS_SUBMISSION_KEY", "diagnosis-key")
    monkeypatch.setenv("TRIAGE_AGENT_ID", "same-agent")
    monkeypatch.setenv("DIAGNOSIS_AGENT_ID", "same-agent")

    with pytest.raises(auth.AgentIdentityConfigurationError, match="duplicate agent id"):
        auth.validate_agent_identity_configuration()


def test_proposal_room_scribe_fallback_is_role_bound(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PROPOSAL_ROOM_API_KEY", "scribe-only")

    assert auth.get_role_for_key("scribe-only") == "scribe"
    allowed, _ = submission._authenticate_agent("scribe-only", "ProposalCard")
    assert allowed is False


class _Response:
    def __init__(self, body: dict):
        self._body = body

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._body


class _RecordingClient:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    async def post(self, path: str, *, json: dict):
        self.calls.append((path, json))
        if path.endswith("/messages"):
            return _Response({"message_id": "msg-1"})
        return _Response({})

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_proposal_room_client_never_uses_gateway_secret_or_sends_identity(
    monkeypatch: pytest.MonkeyPatch,
):
    recording = _RecordingClient()
    monkeypatch.setenv("GATEWAY_SECRET", "global-secret")
    monkeypatch.setenv("RECORDER_SUBMISSION_KEY", "recorder-only")
    monkeypatch.setattr(proposal_room.httpx, "AsyncClient", lambda **_kwargs: recording)

    client = proposal_room.ProposalRoomClient(
        sender_id="caller-supplied-id",
        sender_role="recorder",
    )
    await client.post_message(
        "room-1",
        "hello",
        sender_id="forged-id",
        sender_role="commander",
        sender_type="User",
    )
    await client.add_participant("room-1", "triage-id", role="commander")

    assert client.agent_key == "recorder-only"
    assert recording.calls[0] == (
        "/rooms/room-1/messages",
        {
            "content": "hello",
            "mentions": [],
            "message_type": "message",
            "metadata": {},
        },
    )
    assert recording.calls[1] == (
        "/rooms/room-1/participants",
        {"participant_id": "triage-id"},
    )
