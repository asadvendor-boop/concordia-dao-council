"""Shared, unique agent-principal authentication for Gateway endpoints.

Extracted from the per-request loader in routes/submission.py to avoid
duplicating auth logic across heartbeat, suppression, and other endpoints.

Usage:
    from gateway.auth import get_role_for_key, is_valid_key

    role = get_role_for_key(request.headers.get("X-Agent-Key", ""))
    if role != "safety_reviewer":
        return JSONResponse({"error": "unauthorized"}, 403)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from shared.runtime_secrets import read_secret

_ROLES = [
    "recorder",
    "triage",
    "diagnosis",
    "safety_reviewer",
    "commander",
    "operator",
    "scribe",
]


class AgentIdentityConfigurationError(RuntimeError):
    """Configured keys or agent IDs do not form a one-to-one principal map."""


@dataclass(frozen=True, slots=True)
class AgentPrincipal:
    role: str
    agent_id: str
    key: str = field(repr=False)


# Module-level caches — assigned atomically only after complete validation.
_key_to_principal: dict[str, AgentPrincipal] | None = None
_role_to_principal: dict[str, AgentPrincipal] | None = None
_id_to_principal: dict[str, AgentPrincipal] | None = None


def _configured_agent_id(role: str) -> str:
    value = os.getenv(f"{role.upper()}_AGENT_ID", role)
    if (
        not value
        or not value.isascii()
        or not 1 <= len(value) <= 120
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise AgentIdentityConfigurationError(
            f"agent id for role {role} is not a printable ASCII identity"
        )
    return value


def _load() -> None:
    """Load an unambiguous key, role and agent-ID mapping."""
    global _key_to_principal, _role_to_principal, _id_to_principal
    if _key_to_principal is not None:
        return

    role_keys: dict[str, str] = {}
    for role in _ROLES:
        key = read_secret(f"{role.upper()}_SUBMISSION_KEY")
        if key:
            role_keys[role] = key
    scribe_fallback = read_secret("PROPOSAL_ROOM_API_KEY")
    if scribe_fallback and "scribe" not in role_keys:
        role_keys["scribe"] = scribe_fallback

    key_to_principal: dict[str, AgentPrincipal] = {}
    role_to_principal: dict[str, AgentPrincipal] = {}
    id_to_principal: dict[str, AgentPrincipal] = {}
    for role in _ROLES:
        key = role_keys.get(role)
        if not key:
            continue
        existing_key = key_to_principal.get(key)
        if existing_key is not None:
            raise AgentIdentityConfigurationError(
                f"duplicate agent key configured for roles {existing_key.role} and {role}"
            )
        agent_id = _configured_agent_id(role)
        existing_id = id_to_principal.get(agent_id)
        if existing_id is not None:
            raise AgentIdentityConfigurationError(
                f"duplicate agent id configured for roles {existing_id.role} and {role}"
            )
        principal = AgentPrincipal(role=role, agent_id=agent_id, key=key)
        key_to_principal[key] = principal
        role_to_principal[role] = principal
        id_to_principal[agent_id] = principal

    _key_to_principal = key_to_principal
    _role_to_principal = role_to_principal
    _id_to_principal = id_to_principal


def validate_agent_identity_configuration() -> None:
    """Require configured principals to have unique keys and identities."""

    _load()


def get_role_for_key(agent_key: str) -> str | None:
    """Return role name if key is valid, None otherwise."""
    principal = get_principal_for_key(agent_key)
    return principal.role if principal is not None else None


def get_principal_for_key(agent_key: str) -> AgentPrincipal | None:
    """Resolve one key to exactly one validated principal."""

    _load()
    assert _key_to_principal is not None
    return _key_to_principal.get(agent_key)


def get_principal_for_agent_id(agent_id: str) -> AgentPrincipal | None:
    """Resolve one registered agent ID to exactly one validated principal."""

    _load()
    assert _id_to_principal is not None
    return _id_to_principal.get(agent_id)


def configured_key_to_role() -> dict[str, str]:
    """Return a copy for legacy card-ACL integration without a second parser."""

    _load()
    assert _key_to_principal is not None
    return {key: principal.role for key, principal in _key_to_principal.items()}


def is_valid_key(agent_key: str) -> bool:
    """Check if an agent key is registered."""
    return get_principal_for_key(agent_key) is not None


def get_key_for_role(role: str) -> str:
    """Return the submission key for a given role, or empty string."""
    _load()
    assert _role_to_principal is not None
    principal = _role_to_principal.get(role)
    return principal.key if principal is not None else ""


def _reset_for_testing() -> None:
    """Reset cached keys — call in test fixtures with monkeypatched env vars.

    Without this, the first _load() wins and subsequent tests with
    different env values see stale keys.
    """
    global _key_to_principal, _role_to_principal, _id_to_principal
    _key_to_principal = None
    _role_to_principal = None
    _id_to_principal = None
