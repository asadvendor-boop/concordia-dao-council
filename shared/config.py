"""Concordia configuration: model routing, gateway settings, and agents."""
from __future__ import annotations

import logging as _logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

from .runtime_secrets import read_secret

load_dotenv()

_TRUE_VALUES = {"1", "true", "yes", "on"}
_PLACEHOLDER_MARKERS = (
    "your-llm-api-key",
    "replace-with",
    "generate-",
    "changeme",
    "placeholder",
    "dummy",
)
DEFAULT_LLM_BASE_URL = "https://api.openai.com/v1"
DEFAULT_FAST_MODEL = "gpt-4o-mini"
DEFAULT_DEEP_MODEL = "gpt-4o"


def get_llm_api_key() -> str:
    """Return the configured OpenAI-compatible API key."""
    return read_secret("LLM_API_KEY") or read_secret("OPENAI_API_KEY")


def get_llm_base_url() -> str:
    """Return the configured OpenAI-compatible base URL."""
    return os.getenv("LLM_BASE_URL", "") or os.getenv("OPENAI_BASE_URL", "") or DEFAULT_LLM_BASE_URL


def live_llm_required() -> bool:
    """Return True when DAO treasury must fail closed without live model config."""
    if os.getenv("CONCORDIA_TEST_MODE", "").strip().lower() in _TRUE_VALUES:
        return False
    return (
        os.getenv("APP_ENV", "").strip().lower() in {"production", "prod"}
        or os.getenv("CONCORDIA_REQUIRE_LIVE_LLM", "").strip().lower() in _TRUE_VALUES
    )


def _looks_like_placeholder(value: str) -> bool:
    normalized = value.strip().lower()
    return any(marker in normalized for marker in _PLACEHOLDER_MARKERS)


def _positive_int_setting(name: str, default: int, errors: list[str]) -> bool:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default > 0
    try:
        value = int(raw)
    except ValueError:
        errors.append(f"{name} must be a positive integer")
        return False
    if value <= 0:
        errors.append(f"{name} must be a positive integer")
        return False
    return True


def _explicit_llm_base_url() -> str:
    return os.getenv("LLM_BASE_URL", "").strip() or os.getenv("OPENAI_BASE_URL", "").strip()


def _model_setting(persona_name: str, legacy_name: str, default: str) -> str:
    return os.getenv(persona_name, "").strip() or os.getenv(legacy_name, "").strip() or default


@dataclass
class ModelConfig:
    """Configuration for a single agent's advisory model."""
    adapter: str
    model: str
    fallback: str | None = None
    streaming: bool = True
    provider: str = "openai-compatible"
    fallback_provider: str = "openai-compatible"
    max_tokens: int | None = None
    extra: dict = field(default_factory=dict)


MODELS: dict[str, ModelConfig] = {
    "triage": ModelConfig(
        adapter="langchain_openai",
        model=_model_setting("LLM_ROWAN_MODEL", "LLM_TRIAGE_MODEL", DEFAULT_FAST_MODEL),
        fallback=_model_setting("LLM_ROWAN_FALLBACK_MODEL", "LLM_TRIAGE_FALLBACK_MODEL", DEFAULT_DEEP_MODEL),
        streaming=False,
    ),
    "diagnosis": ModelConfig(
        adapter="local_room_llm",
        model=_model_setting("LLM_MERCER_MODEL", "LLM_DIAGNOSIS_MODEL", DEFAULT_DEEP_MODEL),
        fallback=_model_setting("LLM_MERCER_FALLBACK_MODEL", "LLM_DIAGNOSIS_FALLBACK_MODEL", DEFAULT_FAST_MODEL),
        max_tokens=4096,
    ),
    "safety_reviewer": ModelConfig(
        adapter="local_room_llm",
        model=_model_setting("LLM_VERITY_MODEL", "LLM_SAFETY_MODEL", DEFAULT_DEEP_MODEL),
        fallback=_model_setting("LLM_VERITY_FALLBACK_MODEL", "LLM_SAFETY_FALLBACK_MODEL", DEFAULT_FAST_MODEL),
    ),
    "commander": ModelConfig(
        adapter="local_room_llm",
        model=_model_setting("LLM_ALDEN_MODEL", "LLM_COMMANDER_MODEL", DEFAULT_DEEP_MODEL),
        fallback=_model_setting("LLM_ALDEN_FALLBACK_MODEL", "LLM_COMMANDER_FALLBACK_MODEL", DEFAULT_FAST_MODEL),
        max_tokens=2000,
    ),
    "operator": ModelConfig(
        adapter="local_room_llm",
        model=_model_setting("LLM_LOCKE_MODEL", "LLM_OPERATOR_MODEL", DEFAULT_FAST_MODEL),
        fallback=_model_setting("LLM_LOCKE_FALLBACK_MODEL", "LLM_OPERATOR_FALLBACK_MODEL", DEFAULT_DEEP_MODEL),
        streaming=False,
    ),
}


def llm_readiness_status() -> dict:
    """Return sanitized live-model readiness details for DAO treasury gates."""
    required = live_llm_required()
    errors: list[str] = []

    api_key = get_llm_api_key().strip()
    api_key_ok = bool(api_key) and not _looks_like_placeholder(api_key)
    if required and not api_key:
        errors.append("LLM_API_KEY or OPENAI_API_KEY is required")
    elif required and not api_key_ok:
        errors.append("LLM API key looks like a placeholder")

    explicit_base_url = _explicit_llm_base_url()
    effective_base_url = get_llm_base_url().strip()
    parsed = urlparse(explicit_base_url or effective_base_url)
    base_url_ok = parsed.scheme == "https" and bool(parsed.netloc)
    if required and not explicit_base_url:
        errors.append("LLM_BASE_URL or OPENAI_BASE_URL must be set explicitly")
    elif required and not base_url_ok:
        errors.append("LLM base URL must be an absolute https:// URL")

    model_names = {role: cfg.model.strip() for role, cfg in MODELS.items()}
    invalid_models = [role for role, model in model_names.items() if not model]
    if required and invalid_models:
        errors.append("Invalid model configuration for: " + ", ".join(sorted(invalid_models)))

    rate_limits_ok = (
        _positive_int_setting("CONCORDIA_RATE_LIMIT_PER_MINUTE", 600, errors)
        and _positive_int_setting("CONCORDIA_RATE_LIMIT_WINDOW_SECONDS", 60, errors)
    )

    ready = not errors
    return {
        "status": "ready" if ready else "not_ready",
        "required": required,
        "ready": ready,
        "provider": "openai-compatible",
        "checks": {
            "api_key_present": bool(api_key),
            "api_key_placeholder": bool(api_key) and not api_key_ok,
            "base_url_explicit": bool(explicit_base_url),
            "base_url_https": base_url_ok,
            "models_configured": not invalid_models,
            "rate_limits_positive": rate_limits_ok,
        },
        "base_url": effective_base_url if base_url_ok else None,
        "models": model_names,
        "errors": errors,
    }


def public_llm_readiness_status(status: dict | None = None) -> dict:
    """Return readiness details safe for unauthenticated public health checks."""
    status = status or llm_readiness_status()
    model_names = status.get("models") or {}
    return {
        "status": status.get("status"),
        "required": status.get("required"),
        "ready": status.get("ready"),
        "provider": status.get("provider"),
        "checks": status.get("checks") or {},
        "endpoint": "redacted" if status.get("base_url") else None,
        "model_roles": sorted(model_names.keys()),
        "errors": status.get("errors") or [],
    }


def require_live_llm_ready() -> dict:
    """Return readiness status or raise RuntimeError when DAO treasury is unsafe."""
    status = llm_readiness_status()
    if status["required"] and not status["ready"]:
        raise RuntimeError("; ".join(status["errors"]))
    return status


def configure_openai_compatible_env() -> None:
    """Populate compatibility variables for clients that read global settings."""
    api_key = get_llm_api_key()
    base_url = get_llm_base_url()
    if api_key:
        os.environ.setdefault("OPENAI_API_KEY", api_key)
    if base_url:
        os.environ.setdefault("OPENAI_API_BASE", base_url)
        os.environ.setdefault("OPENAI_BASE_URL", base_url)


_fallback_logger = _logging.getLogger("concordia.config")
_agents_on_fallback: dict[str, bool] = {}


def get_model_with_fallback(role: str) -> tuple[str, str]:
    """Return (model_string, provider) for an agent role."""
    cfg = MODELS.get(role)
    if cfg is None:
        raise ValueError(f"Unknown agent role: {role}")
    if _agents_on_fallback.get(role, False) and cfg.fallback:
        _fallback_logger.info("[config] Using fallback model for %s: %s", role, cfg.fallback)
        return cfg.fallback, cfg.fallback_provider
    return cfg.model, cfg.provider


def switch_to_fallback(role: str) -> bool:
    """Switch an agent to its fallback model. Returns True if switched."""
    cfg = MODELS.get(role)
    if cfg is None or not cfg.fallback:
        _fallback_logger.warning("[config] Cannot switch %s to fallback", role)
        return False
    if not _agents_on_fallback.get(role, False):
        _agents_on_fallback[role] = True
        _fallback_logger.warning("[config] Switched %s to fallback model %s", role, cfg.fallback)
        return True
    return False


def reset_to_primary(role: str) -> None:
    """Reset an agent back to its primary model."""
    _agents_on_fallback.pop(role, None)


def get_agent_ids() -> dict[str, str]:
    """Load registered agent IDs from environment."""
    return {
        "recorder": os.getenv("RECORDER_AGENT_ID", ""),
        "triage": os.getenv("TRIAGE_AGENT_ID", ""),
        "diagnosis": os.getenv("DIAGNOSIS_AGENT_ID", ""),
        "safety_reviewer": os.getenv("SAFETY_REVIEWER_AGENT_ID", ""),
        "commander": os.getenv("COMMANDER_AGENT_ID", ""),
        "operator": os.getenv("OPERATOR_AGENT_ID", ""),
        "scribe": os.getenv("SCRIBE_AGENT_ID", ""),
    }


def get_trusted_agent_ids() -> set[str]:
    """Get the set of all trusted agent UUIDs for lookup_peers filtering."""
    return {v for v in get_agent_ids().values() if v}


def get_agent_api_key(role: str) -> str:
    """Get transport API key for a specific agent role."""
    key = os.getenv(f"{role.upper()}_SUBMISSION_KEY", "")
    if not key:
        key = os.getenv(f"{role.upper()}_API_KEY", "")
    if not key:
        key = os.getenv("PROPOSAL_ROOM_API_KEY", "") or os.getenv("GATEWAY_SECRET", "")
    return key


def get_provider_settings() -> dict:
    """Get API keys and base URLs for all model providers."""
    settings = {"api_key": get_llm_api_key(), "api_base": get_llm_base_url()}
    return {"openai_compatible": settings, "openai-compatible": settings, "llm": settings}



GATEWAY_HOST = os.getenv("GATEWAY_HOST", "0.0.0.0")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "8000"))
GATEWAY_SECRET = os.getenv("GATEWAY_SECRET", "")
GATEWAY_DB_PATH = Path(os.getenv("GATEWAY_DB_PATH", "concordia.db"))

HUMAN_APPROVER_IDS: set[str] = set(filter(None, os.getenv("HUMAN_APPROVER_IDS", "").split(",")))

ACTIVE_PROPOSALS: frozenset[str] = frozenset(
    s.strip() for s in os.getenv("ACTIVE_PROPOSALS", "").split(",") if s.strip()
)
