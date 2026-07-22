"""Shared agent-key authentication for Gateway endpoints.

Extracted from the per-request loader in routes/submission.py to avoid
duplicating auth logic across heartbeat, suppression, and other endpoints.

Usage:
    from gateway.auth import get_role_for_key, is_valid_key

    role = get_role_for_key(request.headers.get("X-Agent-Key", ""))
    if role != "safety_reviewer":
        return JSONResponse({"error": "unauthorized"}, 403)
"""

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

# Module-level cache — populated once on first call.
_key_to_role: dict[str, str] | None = None
_role_to_key: dict[str, str] | None = None


def _load() -> None:
    """Load per-agent submission keys from environment variables."""
    global _key_to_role, _role_to_key
    if _key_to_role is not None:
        return

    _key_to_role = {}
    _role_to_key = {}

    ambiguous_keys: set[str] = set()

    def register(key: str, role: str) -> None:
        if not key or key in ambiguous_keys:
            return
        existing = _key_to_role.get(key)
        if existing is not None and existing != role:
            ambiguous_keys.add(key)
            _key_to_role.pop(key, None)
            _role_to_key.pop(existing, None)
            _role_to_key.pop(role, None)
            return
        _key_to_role[key] = role
        _role_to_key[role] = key

    for role in _ROLES:
        key = read_secret(f"{role.upper()}_SUBMISSION_KEY")
        if key:
            register(key, role)

    scribe_fallback = read_secret("PROPOSAL_ROOM_API_KEY")
    if scribe_fallback and "scribe" not in _role_to_key:
        register(scribe_fallback, "scribe")


def get_role_for_key(agent_key: str) -> str | None:
    """Return role name if key is valid, None otherwise."""
    _load()
    return _key_to_role.get(agent_key)  # type: ignore[union-attr]


def is_valid_key(agent_key: str) -> bool:
    """Check if an agent key is registered."""
    _load()
    return agent_key in _key_to_role  # type: ignore[operator]


def get_key_for_role(role: str) -> str:
    """Return the submission key for a given role, or empty string."""
    _load()
    return _role_to_key.get(role, "")  # type: ignore[union-attr]


def _reset_for_testing() -> None:
    """Reset cached keys — call in test fixtures with monkeypatched env vars.

    Without this, the first _load() wins and subsequent tests with
    different env values see stale keys.
    """
    global _key_to_role, _role_to_key
    _key_to_role = None
    _role_to_key = None
