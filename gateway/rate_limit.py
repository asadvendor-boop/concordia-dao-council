"""Small in-process request rate limiter for the single-VM review profile."""
from __future__ import annotations

import hashlib
import os
import time
from collections import defaultdict, deque

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response


_PUBLIC_READ_PREFIXES = (
    "/stats",
    "/agent-status",
    "/agent-skills",
    "/proposals",
    "/evidence",
    "/room-messages",
    "/suppression-rules",
)

_AGENT_CONTROL_PLANE_PREFIXES = (
    "/api/rooms",
    "/heartbeat",
)


def _positive_int_env(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        *,
        requests_per_window: int | None = None,
        window_seconds: int | None = None,
        trust_proxy_headers: bool | None = None,
    ) -> None:
        super().__init__(app)
        self.requests_per_window = (
            requests_per_window
            if requests_per_window is not None
            else _positive_int_env("CONCORDIA_RATE_LIMIT_PER_MINUTE", 600)
        )
        self.window_seconds = (
            window_seconds
            if window_seconds is not None
            else _positive_int_env("CONCORDIA_RATE_LIMIT_WINDOW_SECONDS", 60)
        )
        if self.requests_per_window <= 0 or self.window_seconds <= 0:
            raise ValueError("CONCORDIA rate limits must be positive")
        self.trust_proxy_headers = (
            trust_proxy_headers
            if trust_proxy_headers is not None
            else os.getenv("CONCORDIA_TRUST_PROXY_HEADERS", "").lower() in {"1", "true", "yes"}
        )
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if self._rate_limited(request):
            return JSONResponse(
                {
                    "success": False,
                    "error": "Rate limit exceeded",
                    "retry_after_seconds": self.window_seconds,
                },
                status_code=429,
                headers={"Retry-After": str(self.window_seconds)},
            )
        return await call_next(request)

    def _rate_limited(self, request: Request) -> bool:
        if self.requests_per_window <= 0 or self.window_seconds <= 0:
            return False
        if request.url.path in {"/health", "/ready"}:
            return False
        if (
            request.method in {"GET", "HEAD", "OPTIONS"}
            and request.url.path.startswith(_PUBLIC_READ_PREFIXES)
        ):
            return False
        if request.url.path.startswith(_AGENT_CONTROL_PLANE_PREFIXES) and request.headers.get(
            "x-agent-key"
        ):
            return False
        now = time.monotonic()
        hits = self._hits[self._rate_limit_key(request)]
        cutoff = now - self.window_seconds
        while hits and hits[0] < cutoff:
            hits.popleft()
        if len(hits) >= self.requests_per_window:
            return True
        hits.append(now)
        return False

    def _rate_limit_key(self, request: Request) -> str:
        for header in ("x-agent-key", "x-operator-token", "authorization"):
            value = request.headers.get(header)
            if value:
                digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
                return f"credential:{header}:{digest}"
        ip = None
        if self.trust_proxy_headers:
            forwarded_for = request.headers.get("x-forwarded-for", "")
            ip = forwarded_for.split(",", 1)[0].strip() if forwarded_for else None
            ip = ip or request.headers.get("x-real-ip")
        ip = ip or (request.client.host if request.client else "unknown")
        return f"ip:{ip}"
