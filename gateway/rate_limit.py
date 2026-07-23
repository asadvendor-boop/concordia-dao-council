"""Small in-process request rate limiter for the single-VM review profile."""
from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import OrderedDict, defaultdict, deque
from collections.abc import Callable

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


class SafePayAdmissionLimiter:
    """Bounded fixed-window admission for public SafePay v2 operations.

    The caller supplies only the client identity already resolved through the
    Caddy attestation boundary. Authorization and forwarding headers never
    participate in the key. Per-operation/per-client limits sit beneath one
    aggregate budget shared by every operation and identity. A full live
    bucket table or exhausted aggregate budget fails closed.
    """

    def __init__(
        self,
        *,
        quote_requests_per_window: int | None = None,
        payment_intent_requests_per_window: int | None = None,
        redemption_requests_per_window: int | None = None,
        global_requests_per_window: int | None = None,
        window_seconds: int | None = None,
        max_buckets: int | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.quote_requests_per_window = (
            quote_requests_per_window
            if quote_requests_per_window is not None
            else _positive_int_env(
                "SAFEPAY_GATEWAY_QUOTE_REQUESTS_PER_WINDOW", 12
            )
        )
        self.redemption_requests_per_window = (
            redemption_requests_per_window
            if redemption_requests_per_window is not None
            else _positive_int_env(
                "SAFEPAY_GATEWAY_REDEMPTION_REQUESTS_PER_WINDOW", 60
            )
        )
        self.payment_intent_requests_per_window = (
            payment_intent_requests_per_window
            if payment_intent_requests_per_window is not None
            else _positive_int_env(
                "SAFEPAY_GATEWAY_PAYMENT_INTENT_REQUESTS_PER_WINDOW", 24
            )
        )
        self.global_requests_per_window = (
            global_requests_per_window
            if global_requests_per_window is not None
            else _positive_int_env(
                "SAFEPAY_GATEWAY_GLOBAL_REQUESTS_PER_WINDOW", 600
            )
        )
        self.window_seconds = (
            window_seconds
            if window_seconds is not None
            else _positive_int_env("SAFEPAY_GATEWAY_WINDOW_SECONDS", 60)
        )
        self.max_buckets = (
            max_buckets
            if max_buckets is not None
            else _positive_int_env("SAFEPAY_GATEWAY_MAX_RATE_BUCKETS", 10_000)
        )
        if (
            self.quote_requests_per_window <= 0
            or self.payment_intent_requests_per_window <= 0
            or self.redemption_requests_per_window <= 0
            or self.global_requests_per_window <= 0
            or self.window_seconds <= 0
            or self.max_buckets <= 0
        ):
            raise ValueError("SafePay admission limits must be positive")
        self._clock = clock
        self._buckets: OrderedDict[tuple[str, str], tuple[int, int]] = (
            OrderedDict()
        )
        self._global_window = -1
        self._global_count = 0
        self._lock = threading.Lock()

    def admit(self, operation: str, client_identity: str) -> bool:
        if operation == "quotes":
            limit = self.quote_requests_per_window
        elif operation == "payment_intents":
            limit = self.payment_intent_requests_per_window
        elif operation == "redemptions":
            limit = self.redemption_requests_per_window
        else:
            raise ValueError("unknown SafePay admission operation")
        if not isinstance(client_identity, str) or not client_identity:
            return False

        bucket_key = (operation, client_identity)
        with self._lock:
            # Clock sampling and window-state mutation share one critical
            # section. A delayed request can therefore never apply an older
            # sample after another thread has advanced the limiter.
            current_window = int(self._clock() // self.window_seconds)
            if self._global_window < 0:
                self._global_window = current_window
                self._global_count = 0
            elif current_window > self._global_window:
                self._global_window = current_window
                self._global_count = 0
            elif current_window < self._global_window:
                # Wall/fixture clock regression: fail closed rather than
                # rewinding and manufacturing another aggregate allowance.
                return False
            existing = self._buckets.get(bucket_key)
            if existing is not None and existing[0] == current_window:
                if (
                    existing[1] >= limit
                    or self._global_count >= self.global_requests_per_window
                ):
                    return False
                self._buckets[bucket_key] = (current_window, existing[1] + 1)
                self._global_count += 1
                return True
            if existing is not None:
                del self._buckets[bucket_key]

            if len(self._buckets) >= self.max_buckets:
                expired = [
                    key
                    for key, (window, _count) in self._buckets.items()
                    if window != current_window
                ]
                for key in expired:
                    del self._buckets[key]
            if len(self._buckets) >= self.max_buckets:
                return False
            if self._global_count >= self.global_requests_per_window:
                return False
            self._buckets[bucket_key] = (current_window, 1)
            self._global_count += 1
            return True


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
        if request.url.path.startswith("/x402/v2/"):
            # SafePay has a dedicated admission contract whose frozen response
            # bodies and attested client identity cannot be supplied by this
            # generic credential/IP limiter.
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
