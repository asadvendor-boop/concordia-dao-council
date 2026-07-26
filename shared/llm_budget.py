"""File-backed daily LLM token circuit breaker."""
from __future__ import annotations

import fcntl
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class LLMBudgetExceeded(RuntimeError):
    """Raised before a LLM call when the daily budget would be exceeded."""


def _today() -> str:
    return datetime.now(UTC).date().isoformat()


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise LLMBudgetExceeded(f"{name} must be an integer") from exc


def daily_limit() -> int:
    return _int_env("CONCORDIA_DAILY_TOKEN_LIMIT", 250_000)


def meter_path() -> Path:
    return Path(os.getenv("CONCORDIA_LLM_USAGE_METER_PATH", "/llm-usage/concordia-llm-usage.json"))


def estimate_tokens(*values: Any, max_tokens: int) -> int:
    text = json.dumps(values, ensure_ascii=False, sort_keys=True, default=str)
    prompt_estimate = max(1, len(text) // 4)
    return prompt_estimate + max(1, max_tokens) + 256


def response_total_tokens(response: Any) -> int:
    usage = getattr(response, "usage", None)
    if usage is None and isinstance(response, dict):
        usage = response.get("usage")
    if usage is None:
        return 0
    if isinstance(usage, dict):
        return int(usage.get("total_tokens") or usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0) or 0)
    total = getattr(usage, "total_tokens", None)
    if total is not None:
        return int(total or 0)
    return int((getattr(usage, "prompt_tokens", 0) or 0) + (getattr(usage, "completion_tokens", 0) or 0))


@dataclass(slots=True)
class TokenReservation:
    estimated_tokens: int
    limit: int
    path: Path
    committed: bool = False

    def commit(self, actual_tokens: int | None = None) -> None:
        if self.committed:
            return
        actual = max(0, int(actual_tokens or self.estimated_tokens))
        _mutate_meter(
            self.path,
            limit=self.limit,
            reserve_delta=-self.estimated_tokens,
            actual_delta=actual,
            request_delta=1,
            enforce=False,
        )
        self.committed = True

    def release(self) -> None:
        if self.committed:
            return
        _mutate_meter(
            self.path,
            limit=self.limit,
            reserve_delta=-self.estimated_tokens,
            actual_delta=0,
            request_delta=0,
            enforce=False,
        )
        self.committed = True


def reserve(estimated_tokens: int) -> TokenReservation:
    limit = daily_limit()
    if limit <= 0:
        raise LLMBudgetExceeded("CONCORDIA_DAILY_TOKEN_LIMIT must be positive in DAO treasury")
    estimated = max(1, int(estimated_tokens))
    path = meter_path()
    _mutate_meter(
        path,
        limit=limit,
        reserve_delta=estimated,
        actual_delta=0,
        request_delta=0,
        enforce=True,
    )
    return TokenReservation(estimated_tokens=estimated, limit=limit, path=path)


def _load(raw: str) -> dict[str, Any]:
    if not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _mutate_meter(
    path: Path,
    *,
    limit: int,
    reserve_delta: int,
    actual_delta: int,
    request_delta: int,
    enforce: bool,
) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        handle.seek(0)
        data = _load(handle.read())
        if data.get("date") != _today():
            data = {
                "date": _today(),
                "actual_tokens": 0,
                "reserved_tokens": 0,
                "requests": 0,
            }
        actual = max(0, int(data.get("actual_tokens", 0) or 0))
        reserved = max(0, int(data.get("reserved_tokens", 0) or 0))
        requests = max(0, int(data.get("requests", 0) or 0))
        if enforce and actual + reserved + reserve_delta > limit:
            raise LLMBudgetExceeded(
                f"daily LLM token budget exceeded: used={actual}, reserved={reserved}, "
                f"requested={reserve_delta}, limit={limit}"
            )
        data.update(
            {
                "actual_tokens": max(0, actual + actual_delta),
                "reserved_tokens": max(0, reserved + reserve_delta),
                "requests": max(0, requests + request_delta),
                "limit": limit,
                "updated_at": datetime.now(UTC).isoformat(),
            }
        )
        handle.seek(0)
        handle.truncate()
        handle.write(json.dumps(data, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
        return data
