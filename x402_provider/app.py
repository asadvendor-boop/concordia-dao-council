"""Separate x402 paid risk-report provider for Concordia.

This service is intentionally separate from the main gateway so the public
demo can prove a provider redemption flow instead of treating Concordia's own
report endpoint as the paid data provider.

SafePay Lite supplemental v2 (G1 frozen, handoff/G1_INTERFACE_SPEC.md §12):

- ``POST /x402/v2/quotes`` issues and durably persists an immutable quote
  before returning HTTP 402 (two-phase: rate/reservation preflight, report
  resolution outside any write lock, final capacity-checked issue).
- ``POST /x402/v2/redemptions`` is the only consumption authority: exact
  persisted-quote binding, read-only consumption lookup, terminal
  404/409/410/422 outcomes, exact structured Casper verification, and an
  atomic ``(network, payment_hash)`` claim with an immutable stored
  fulfillment for idempotent replay.

The legacy ``GET /x402/risk-report`` + ``X-Payment`` flow remains only for
historical continuity and can never create supplemental-v2 evidence.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac as _hmac
import inspect
import ipaddress
import json
import logging
import os
import re
import secrets as _secrets
import threading
import time
import uuid
from collections import OrderedDict, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from shared.telemetry import init_telemetry, instrument_fastapi_app, instrument_httpx, telemetry_status
from shared.x402_payments import (
    SAFEPAY_V2_BINDING_CHECK_FIELDS,
    SAFEPAY_V2_MAX_PUBLIC_REQUEST_BYTES,
    SAFEPAY_V2_MAX_REPORT_DECODED_BYTES,
    SAFEPAY_V2_QUOTE_FIELDS,
    SAFEPAY_V2_QUOTE_REQUEST_SCHEMA,
    SAFEPAY_V2_REDEMPTION_REQUEST_SCHEMA,
    SAFEPAY_V2_REPORT_MEDIA_TYPE,
    SAFEPAY_V2_SCHEMA_VERSION,
    SAFEPAY_V2_OBSERVATION_FIELDS,
    evaluate_safepay_v2_observation,
    observe_safepay_v2_payment,
    parse_safepay_v2_strict_json,
    payment_required_headers,
    safepay_v2_body_digest,
    safepay_v2_error_body,
    safepay_v2_quote_hash,
    validate_safepay_v2_observation,
    validate_safepay_v2_quote,
    verify_casper_transfer_payment_with_retry,
)
from x402_provider.ledger import (
    CrossBindingRejected,
    QuoteBindingInvalid,
    QuoteCapacityExhausted,
    QuoteExpired,
    QuoteRateLimited,
    ReportConflict,
    SafePayCaps,
    SafePayLedger,
)


_LAG_ATTEMPTS: dict[tuple[str, str], int] = defaultdict(int)

_LOGGER = logging.getLogger("x402_provider.safepay_v2")

_PROPOSAL_ID_RE_TEXT = r"^[A-Z0-9-]{1,64}$"
_HEX64 = frozenset("0123456789abcdef")

_V2_HEADERS = {
    "Cache-Control": "no-store",
    "X-Concordia-SafePay-Version": "safepay-v2",
}

_DEFAULT_LEDGER_PATH = "/data/safepay.db"


@dataclass(frozen=True)
class SafePayRedemptionAdmissionCaps:
    """Fixed-window bounds for provider-side slow redemption work."""

    per_client_limit: int = 60
    global_limit: int = 600
    window_seconds: int = 60
    max_client_buckets: int = 10_000


class SafePayRedemptionAdmission:
    """Bounded provider admission before simulated lag or chain observation.

    Callers pass only the already HMACed identity produced by ``_client_key``.
    The fixed-size live bucket table fails closed for new identities when full.
    Exact stored replays are served before this guard and therefore remain
    available without consuming slow-path capacity.
    """

    def __init__(
        self,
        caps: SafePayRedemptionAdmissionCaps | None = None,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.caps = caps or SafePayRedemptionAdmissionCaps()
        if (
            self.caps.per_client_limit <= 0
            or self.caps.global_limit <= 0
            or self.caps.window_seconds <= 0
            or self.caps.max_client_buckets <= 0
        ):
            raise ValueError("SafePay provider redemption admission limits must be positive")
        self._clock = clock
        self._client_buckets: OrderedDict[str, tuple[int, int]] = OrderedDict()
        self._global_window = -1
        self._global_count = 0
        self._lock = threading.Lock()

    def admit(self, client_key: str) -> bool:
        if not isinstance(client_key, str) or not client_key:
            return False
        current_window = int(self._clock() // self.caps.window_seconds)
        with self._lock:
            if self._global_window != current_window:
                self._global_window = current_window
                self._global_count = 0

            existing = self._client_buckets.get(client_key)
            client_count = (
                existing[1]
                if existing is not None and existing[0] == current_window
                else 0
            )
            if (
                client_count >= self.caps.per_client_limit
                or self._global_count >= self.caps.global_limit
            ):
                return False

            if existing is None or existing[0] != current_window:
                if existing is not None:
                    del self._client_buckets[client_key]
                if len(self._client_buckets) >= self.caps.max_client_buckets:
                    expired = [
                        key
                        for key, (window, _count) in self._client_buckets.items()
                        if window != current_window
                    ]
                    for key in expired:
                        del self._client_buckets[key]
                if len(self._client_buckets) >= self.caps.max_client_buckets:
                    return False

            self._client_buckets[client_key] = (current_window, client_count + 1)
            self._client_buckets.move_to_end(client_key)
            self._global_count += 1
            return True


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _test_mode() -> bool:
    return os.getenv("CONCORDIA_TEST_MODE", "").strip().lower() in {"1", "true", "yes"}


def _load_runtime_secret(env_name: str, *, minimum_bytes: int = 32) -> bytes:
    """Load a runtime secret through its ``*_FILE`` environment variable.

    Missing, unreadable, or shorter-than-32-byte secrets fail process startup.
    Only when the variable is entirely unset AND the repository-wide
    CONCORDIA_TEST_MODE convention is active does the provider generate an
    ephemeral in-process secret (never persisted, never logged) so that
    credential-free local tests can construct the app.
    """
    path = os.getenv(env_name, "").strip()
    if not path:
        if _test_mode():
            return _secrets.token_bytes(minimum_bytes)
        raise RuntimeError(f"{env_name} is required and must point to a readable secret file")
    try:
        data = Path(path).read_bytes().rstrip(b"\n")
    except OSError as exc:
        raise RuntimeError(f"{env_name} secret file is unreadable") from exc
    if len(data) < minimum_bytes:
        raise RuntimeError(f"{env_name} secret must be at least {minimum_bytes} bytes")
    return data


def _parse_trusted_proxy_cidrs(raw: str | None) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise RuntimeError("SAFEPAY_TRUSTED_PROXY_CIDRS contains an invalid CIDR") from exc
    if not networks and not _test_mode():
        raise RuntimeError(
            "SAFEPAY_TRUSTED_PROXY_CIDRS requires at least one valid CIDR"
        )
    return networks


def _normalize_ip_text(value: str | None) -> str | None:
    """Parse and canonicalize one IP address per the frozen normalization rule.

    Zone identifiers and invalid values are rejected (None). IPv4-mapped IPv6
    collapses to IPv4; all other addresses use lowercase compressed form.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if "%" in text:
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address).lower()


def resolve_safepay_client_ip(
    socket_peer: str | None,
    client_ip_header: str | None,
    proxy_attestation_header: str | None,
    trusted_proxy_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
    proxy_secret: bytes,
) -> str:
    """Resolve the normalized client identity for rate limiting.

    The forwarded client IP header is trusted only when the immediate socket
    peer belongs to the configured trusted proxy CIDRs AND the proxy
    attestation matches the runtime secret in constant time. Otherwise both
    headers are ignored and the socket peer is used.
    """
    peer_normalized = _normalize_ip_text(socket_peer)
    trusted = False
    if peer_normalized is not None and trusted_proxy_cidrs:
        peer_address = ipaddress.ip_address(peer_normalized)
        in_trusted_cidr = any(peer_address in network for network in trusted_proxy_cidrs)
        attestation = (proxy_attestation_header or "").encode("utf-8", errors="replace")
        attestation_ok = _hmac.compare_digest(attestation, proxy_secret)
        trusted = in_trusted_cidr and attestation_ok
    if trusted:
        forwarded = _normalize_ip_text(client_ip_header)
        if forwarded is not None:
            return forwarded
    if peer_normalized is not None:
        return peer_normalized
    # Unparseable socket peer (for example an in-process test client): fall
    # back to the raw peer string so identity remains stable and headers stay
    # untrusted.
    return str(socket_peer or "unknown-peer")


def default_safepay_report_source(proposal_id: str, resource_id: str) -> bytes:
    """Deterministic protected report bytes for one (proposal, resource)."""
    payload = {
        "schema_version": "safepay-report-v2",
        "proposal_id": proposal_id,
        "resource_id": resource_id,
        "provider": "concordia-risk-oracle-provider",
        "risk_report": {
            "risk_level": "medium-after-policy-cap",
            "requested_allocation_bps": 3000,
            "approved_policy_cap_bps": 800,
            "provider_signal": "external_paid_provider_verified_before_release",
            "recommendation": "Release specialist report only after Casper payment proof settles.",
        },
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")


def _is_lower_hex64(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX64


def _v2_error(status_code: int, code: str, retryable: bool, replay_disposition: str) -> JSONResponse:
    # The body comes from the shared frozen builder so the ledger's evidence
    # digest recomputation can never drift from the body actually served.
    return JSONResponse(
        safepay_v2_error_body(code, retryable, replay_disposition),
        status_code=status_code,
        headers=dict(_V2_HEADERS),
    )


# Canonical digest of the exact 409 cross-binding body this app serves; recorded
# on every cross_binding_rejected observation and revalidated by the summary.
_CROSS_BINDING_409_DIGEST = safepay_v2_body_digest(
    safepay_v2_error_body("payment_already_consumed_for_other_binding", False, "cross_binding_rejected")
)


def _log_sanitized_failure(endpoint_id: str, exc: BaseException) -> None:
    """Stable log line: event id, endpoint id, exception class, timestamp only."""
    _LOGGER.error(
        "event_id=%s endpoint_id=%s exception_class=%s timestamp=%d",
        uuid.uuid4(),
        endpoint_id,
        type(exc).__name__,
        int(time.time()),
    )


async def _read_safepay_v2_request_body(request: Request) -> bytes | None:
    """Read no more than the frozen public-body limit plus one sentinel byte."""
    content_lengths = request.headers.getlist("content-length")
    if content_lengths:
        if (
            len(content_lengths) != 1
            or not content_lengths[0].isascii()
            or not content_lengths[0].isdigit()
        ):
            return None
        if int(content_lengths[0]) > SAFEPAY_V2_MAX_PUBLIC_REQUEST_BYTES:
            return None

    body = bytearray()
    async for chunk in request.stream():
        remaining = SAFEPAY_V2_MAX_PUBLIC_REQUEST_BYTES + 1 - len(body)
        if remaining <= 0:
            return None
        body.extend(chunk[:remaining])
        if len(chunk) > remaining or len(body) > SAFEPAY_V2_MAX_PUBLIC_REQUEST_BYTES:
            return None
    return bytes(body)


def create_app(
    *,
    ledger_path: str | None = None,
    caps: SafePayCaps | None = None,
    report_source: Callable[[str, str], bytes] | Callable[[str, str], Awaitable[bytes]] | None = None,
    chain_observer: Callable[[str, str], Awaitable[dict[str, Any]]] | None = None,
    clock: Callable[[], float] | None = None,
    payee_account_hash: str | None = None,
    amount_motes: str | None = None,
    simulated_lag_attempts: int = 0,
    redemption_admission: SafePayRedemptionAdmission | None = None,
) -> FastAPI:
    init_telemetry(os.getenv("OTEL_SERVICE_NAME", "concordia-x402-provider"))
    instrument_httpx()
    app = FastAPI(title="Concordia Risk Oracle Provider", version="0.2.0")
    instrument_fastapi_app(app)

    caps = caps or SafePayCaps()
    clock = clock or time.time
    report_source = report_source or default_safepay_report_source
    redemption_admission = redemption_admission or SafePayRedemptionAdmission(
        clock=clock
    )
    resolved_ledger_path = ledger_path or os.getenv("X402_LEDGER", _DEFAULT_LEDGER_PATH)
    v2_lag_counters: dict[str, int] = defaultdict(int)

    # Runtime secrets: missing/short secrets fail startup (test mode may use
    # ephemeral in-process values; see _load_runtime_secret).
    proxy_secret = _load_runtime_secret("SAFEPAY_PROXY_SECRET_FILE")
    client_key_hmac_secret = _load_runtime_secret("SAFEPAY_CLIENT_KEY_HMAC_SECRET_FILE")
    trusted_proxy_cidrs = _parse_trusted_proxy_cidrs(os.getenv("SAFEPAY_TRUSTED_PROXY_CIDRS"))

    ledger: SafePayLedger | None = None
    try:
        ledger = SafePayLedger(resolved_ledger_path, caps)
    except Exception:
        # In production a broken ledger path fails startup. Under the
        # repository-wide test convention the legacy endpoints stay importable
        # and the v2 endpoints answer 503 provider_unavailable until a ledger
        # path is available.
        if not _test_mode():
            raise

    def _require_ledger() -> SafePayLedger:
        nonlocal ledger
        if ledger is None:
            ledger = SafePayLedger(resolved_ledger_path, caps)
        return ledger

    async def _default_observer(network: str, payment_hash: str) -> dict[str, Any]:
        return await observe_safepay_v2_payment(network=network, payment_hash=payment_hash)

    observer = chain_observer or _default_observer

    def _client_key(request: Request) -> str:
        socket_peer = request.client.host if request.client else None
        normalized = resolve_safepay_client_ip(
            socket_peer,
            request.headers.get("X-Concordia-Client-IP"),
            request.headers.get("X-Concordia-SafePay-Proxy"),
            trusted_proxy_cidrs,
            proxy_secret,
        )
        return _hmac.new(client_key_hmac_secret, normalized.encode("utf-8"), hashlib.sha256).hexdigest()

    def _quote_terms() -> tuple[str, str]:
        payee = payee_account_hash or os.getenv(
            "SAFEPAY_PAYEE_ACCOUNT_HASH", os.getenv("X402_PAYMENT_ACCOUNT_HASH", "")
        )
        payee = payee.strip().lower().removeprefix("account-hash-").removeprefix("hash-")
        amount = (amount_motes or os.getenv("SAFEPAY_AMOUNT_MOTES", "")).strip()
        if not _is_lower_hex64(payee):
            raise RuntimeError("SafePay v2 payee account hash is not configured as 64 lowercase hex")
        if not amount.isdigit() or amount != str(int(amount)) or int(amount) < 1 or int(amount) >= 2**512:
            raise RuntimeError("SafePay v2 amount_motes is not a canonical unsigned decimal")
        return payee, amount

    async def _resolve_report_bytes(proposal_id: str, resource_id: str) -> bytes:
        if inspect.iscoroutinefunction(report_source):
            awaitable = report_source(proposal_id, resource_id)
        else:
            awaitable = asyncio.to_thread(report_source, proposal_id, resource_id)
        raw = await asyncio.wait_for(awaitable, timeout=caps.report_resolution_timeout_seconds)
        if not isinstance(raw, (bytes, bytearray)):
            raise ValueError("report source must return bytes")
        raw = bytes(raw)
        if len(raw) > min(caps.max_report_decoded_bytes, SAFEPAY_V2_MAX_REPORT_DECODED_BYTES):
            raise ValueError("report exceeds the maximum decoded size")
        return raw

    # ------------------------------------------------------------------ health

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "concordia-x402-provider",
            "telemetry": telemetry_status(),
        }

    # -------------------------------------------------- SafePay v2: quote issue

    @app.post("/x402/v2/quotes")
    async def issue_quote_v2(request: Request):
        try:
            return await _issue_quote_v2(request)
        except Exception as exc:
            _log_sanitized_failure("quotes", exc)
            return _v2_error(503, "provider_unavailable", True, "not_attempted")

    async def _issue_quote_v2(request: Request):
        try:
            raw_body = await _read_safepay_v2_request_body(request)
            if raw_body is None:
                return _v2_error(400, "invalid_request", False, "not_attempted")
            body = parse_safepay_v2_strict_json(raw_body)
        except Exception:
            return _v2_error(400, "invalid_request", False, "not_attempted")
        if not isinstance(body, dict) or set(body) != {"schema_version", "proposal_id", "resource_id"}:
            return _v2_error(400, "invalid_request", False, "not_attempted")
        if body["schema_version"] != SAFEPAY_V2_QUOTE_REQUEST_SCHEMA:
            return _v2_error(400, "invalid_request", False, "not_attempted")
        proposal_id = body["proposal_id"]
        resource_id = body["resource_id"]
        if not isinstance(proposal_id, str) or not re.match(_PROPOSAL_ID_RE_TEXT, proposal_id):
            return _v2_error(400, "invalid_request", False, "not_attempted")
        if (
            not isinstance(resource_id, str)
            or not resource_id.isascii()
            or not 1 <= len(resource_id) <= 200
            or not all(0x20 <= ord(char) <= 0x7E for char in resource_id)
        ):
            return _v2_error(400, "invalid_request", False, "not_attempted")

        payee, amount = _quote_terms()
        store = _require_ledger()
        client_key = _client_key(request)
        now = int(clock())

        try:
            reservation_id = store.preflight_reservation(
                client_key=client_key, proposal_id=proposal_id, resource_id=resource_id, now=now
            )
        except QuoteRateLimited:
            return _v2_error(429, "quote_rate_limited", True, "not_attempted")
        except QuoteCapacityExhausted:
            return _v2_error(503, "quote_capacity_exhausted", True, "not_attempted")

        # Report resolution happens only after a committed reservation, with a
        # hard timeout, outside every SQLite write transaction. A failure still
        # consumes the fixed-window attempt.
        try:
            report_bytes = await _resolve_report_bytes(proposal_id, resource_id)
        except Exception as exc:
            _log_sanitized_failure("quotes.report_source", exc)
            store.mark_reservation_failed(reservation_id, now=int(clock()))
            return _v2_error(503, "report_source_unavailable", True, "not_attempted")

        try:
            quote = store.finalize_quote(
                reservation_id=reservation_id,
                proposal_id=proposal_id,
                resource_id=resource_id,
                payee_account_hash=payee,
                amount_motes=amount,
                report_bytes=report_bytes,
                clock=clock,
            )
        except QuoteCapacityExhausted:
            return _v2_error(503, "quote_capacity_exhausted", True, "not_attempted")
        except ReportConflict as exc:
            # Content-addressed hash conflict: issuance fails closed.
            _log_sanitized_failure("quotes.report_conflict", exc)
            return _v2_error(503, "provider_unavailable", True, "not_attempted")

        return JSONResponse(
            {
                "schema_version": SAFEPAY_V2_SCHEMA_VERSION,
                "error": {"code": "payment_required", "retryable": False},
                "quote": quote,
                "payment_requirements": {
                    "network": quote["network"],
                    "payee_account_hash": quote["payee_account_hash"],
                    "amount_motes": quote["amount_motes"],
                    "correlation_id": quote["correlation_id"],
                    "expires_at": quote["expires_at"],
                },
            },
            status_code=402,
            headers=dict(_V2_HEADERS),
        )

    # -------------------------------------------------- SafePay v2: redemption

    @app.post("/x402/v2/redemptions")
    async def redeem_v2(request: Request):
        try:
            return await _redeem_v2(request)
        except Exception as exc:
            _log_sanitized_failure("redemptions", exc)
            return _v2_error(503, "provider_unavailable", True, "verification_pending")

    async def _redeem_v2(request: Request):
        try:
            raw_body = await _read_safepay_v2_request_body(request)
            if raw_body is None:
                return _v2_error(400, "invalid_request", False, "not_attempted")
            body = parse_safepay_v2_strict_json(raw_body)
        except Exception:
            return _v2_error(400, "invalid_request", False, "not_attempted")
        if not isinstance(body, dict) or set(body) != {"schema_version", "quote", "payment_hash"}:
            return _v2_error(400, "invalid_request", False, "not_attempted")
        if body["schema_version"] != SAFEPAY_V2_REDEMPTION_REQUEST_SCHEMA:
            return _v2_error(400, "invalid_request", False, "not_attempted")
        payment_hash = body["payment_hash"]
        if not _is_lower_hex64(payment_hash):
            return _v2_error(400, "invalid_request", False, "not_attempted")
        quote = body["quote"]
        # Canonical-network validation (aliases rejected, never normalized)
        # happens inside strict quote validation, before ANY ledger access.
        if validate_safepay_v2_quote(quote) is not None:
            return _v2_error(400, "invalid_request", False, "not_attempted")

        store = _require_ledger()
        now = int(clock())

        quote_row = store.load_quote(quote["quote_id"])
        if quote_row is None:
            # Terminal: never looks up or observes the payment.
            return _v2_error(404, "quote_not_issued", False, "not_attempted")

        recomputed_quote_hash = _recompute_quote_hash(quote_row)
        submitted_matches = (
            all(
                quote[field] == quote_row[field]
                for field in SAFEPAY_V2_QUOTE_FIELDS
                if field not in {"schema_version", "expires_at"}
            )
            and int(quote["expires_at"]) == int(quote_row["expires_at"])
            and recomputed_quote_hash == quote_row["quote_hash"]
            and quote["quote_hash"] == recomputed_quote_hash
        )
        if not submitted_matches:
            return _v2_error(422, "quote_binding_invalid", False, "not_attempted")

        network = quote_row["network"]
        quote_id = quote_row["quote_id"]
        resource_id = quote_row["resource_id"]

        # Read-only consumption lookup: existing exact or cross-binding retries
        # never need a fresh chain call, including after quote expiry.
        existing = store.find_consumption(network, payment_hash)
        if existing is not None:
            if (
                existing["quote_id"] == quote_id
                and existing["resource_id"] == resource_id
                and existing["quote_hash"] == quote_row["quote_hash"]
            ):
                store.record_redemption_observation(
                    kind="idempotent_replay",
                    http_status=200,
                    network=network,
                    payment_hash=payment_hash,
                    quote_id=quote_id,
                    resource_id=resource_id,
                    now=now,
                    response_digest=existing["response_hash"],
                    consumed_response_hash=existing["response_hash"],
                )
                return _v2_success(json.loads(existing["fulfillment_json"]), "idempotent_replay")
            store.record_redemption_observation(
                kind="cross_binding_rejected",
                http_status=409,
                network=network,
                payment_hash=payment_hash,
                quote_id=quote_id,
                resource_id=resource_id,
                now=now,
                response_digest=_CROSS_BINDING_409_DIGEST,
                consumed_response_hash=existing["response_hash"],
            )
            return _v2_error(409, "payment_already_consumed_for_other_binding", False, "cross_binding_rejected")
        consumed_by_other_payment = store.find_consumption_for_quote(quote_id)
        if consumed_by_other_payment is not None:
            store.record_redemption_observation(
                kind="cross_binding_rejected",
                http_status=409,
                network=network,
                payment_hash=payment_hash,
                quote_id=quote_id,
                resource_id=resource_id,
                now=now,
                response_digest=_CROSS_BINDING_409_DIGEST,
                consumed_response_hash=consumed_by_other_payment["response_hash"],
            )
            return _v2_error(409, "payment_already_consumed_for_other_binding", False, "cross_binding_rejected")

        # Unconsumed expired quote: terminal 410 BEFORE any chain observation.
        if now >= int(quote_row["expires_at"]):
            return _v2_error(410, "quote_expired", False, "not_attempted")

        # Fulfillment content is served only from the persisted
        # content-addressed bytes; integrity failure fails closed.
        stored_report = store.load_report(quote_row["report_hash"])
        if (
            stored_report is None
            or stored_report[0] != SAFEPAY_V2_REPORT_MEDIA_TYPE
            or hashlib.sha256(stored_report[1]).hexdigest() != quote_row["report_hash"]
        ):
            _log_sanitized_failure("redemptions.report_integrity", ValueError("report integrity"))
            return _v2_error(503, "provider_unavailable", True, "verification_pending")

        # Direct callers can reach the provider's public hostname without
        # traversing Gateway admission. Bound every still-unconsumed slow path
        # here using only the HMACed Caddy-attested client identity. Exact
        # idempotent/cross-binding lookups above remain cheap and available.
        if not redemption_admission.admit(_client_key(request)):
            return _v2_error(
                503, "provider_unavailable", True, "verification_pending"
            )

        # Test-only simulated indexer lag; defaults OFF and is never enabled in
        # production (constructor parameter only, no environment switch).
        if simulated_lag_attempts > 0 and v2_lag_counters[payment_hash] < simulated_lag_attempts:
            v2_lag_counters[payment_hash] += 1
            return _v2_error(425, "payment_not_finalized", True, "verification_pending")

        # Chain observation: outside every SQLite write transaction.
        try:
            observation = dict(await observer(network, payment_hash))
        except Exception as exc:
            _log_sanitized_failure("redemptions.observer", exc)
            return _v2_error(503, "payment_observer_unavailable", True, "verification_pending")
        # The v2 observation contract REQUIRES the raw pre-filter transfer count
        # as a strict integer. An observer that omits or mistypes it (including
        # bool True / numeric strings, which int() would silently coerce to a
        # passing 1) produced no usable observation: fail closed as an observer
        # outage — retryable, nothing consumed — never assume exactly one.
        native_transfer_count = observation.pop("native_transfer_count", None)
        if isinstance(native_transfer_count, bool) or not isinstance(native_transfer_count, int):
            return _v2_error(503, "payment_observer_unavailable", True, "verification_pending")

        execution_status = observation.get("execution_status")
        finality_status = observation.get("finality_status")
        execution_error = observation.get("execution_error")
        if execution_status in {"pending", "unknown"} or (
            execution_status == "processed"
            and execution_error is None
            and finality_status != "finalized"
        ):
            return _v2_error(425, "payment_not_finalized", True, "verification_pending")
        if execution_status == "failed" or execution_error is not None:
            return _v2_error(422, "payment_binding_invalid", False, "verification_rejected")

        checks = evaluate_safepay_v2_observation(
            quote_row, observation, native_transfer_count=native_transfer_count
        )
        binding_checks = {
            **checks,
            "proposal_exact": True,
            "resource_exact": True,
            "correlation_exact": True,
            "report_version_exact": True,
            "report_hash_exact": True,
            "quote_hash_recomputed": True,
        }
        binding_checks = {name: bool(binding_checks[name]) for name in SAFEPAY_V2_BINDING_CHECK_FIELDS}
        if not all(binding_checks.values()):
            return _v2_error(422, "payment_binding_invalid", False, "verification_rejected")

        # The embedded wire observation carries exactly the frozen 12 fields
        # and must describe this payment; anything else is an observer fault.
        wire_observation = {field: observation.get(field) for field in SAFEPAY_V2_OBSERVATION_FIELDS}
        if (
            validate_safepay_v2_observation(wire_observation) is not None
            or wire_observation["payment_hash"] != payment_hash
        ):
            _log_sanitized_failure("redemptions.observation_shape", ValueError("observation shape"))
            return _v2_error(503, "payment_observer_unavailable", True, "verification_pending")
        observation = wire_observation

        report_object = {
            "report_version": quote_row["report_version"],
            "proposal_id": quote_row["proposal_id"],
            "resource_id": resource_id,
            "correlation_id": quote_row["correlation_id"],
            "media_type": SAFEPAY_V2_REPORT_MEDIA_TYPE,
            "content_base64": base64.b64encode(stored_report[1]).decode("ascii"),
            "report_hash": quote_row["report_hash"],
        }
        try:
            fulfillment, disposition = store.claim_consumption(
                quote_row=quote_row,
                payment_hash=payment_hash,
                payment_observation=observation,
                report_object=report_object,
                binding_checks=binding_checks,
                observed_at=str(observation.get("observed_at")),
                now=int(clock()),
            )
        except QuoteExpired:
            return _v2_error(410, "quote_expired", False, "not_attempted")
        except QuoteBindingInvalid:
            return _v2_error(422, "quote_binding_invalid", False, "not_attempted")
        except CrossBindingRejected:
            # Bind the observation to the consumption that actually blocked the
            # claim; if it cannot be loaded the 409 still goes out but no
            # unbound evidence row is fabricated (fail closed on evidence).
            blocking = store.find_consumption(network, payment_hash)
            if blocking is not None:
                store.record_redemption_observation(
                    kind="cross_binding_rejected",
                    http_status=409,
                    network=network,
                    payment_hash=payment_hash,
                    quote_id=quote_id,
                    resource_id=resource_id,
                    now=now,
                    response_digest=_CROSS_BINDING_409_DIGEST,
                    consumed_response_hash=blocking["response_hash"],
                )
            return _v2_error(409, "payment_already_consumed_for_other_binding", False, "cross_binding_rejected")
        if disposition == "idempotent_replay":
            replayed = store.find_consumption(network, payment_hash)
            if replayed is not None:
                store.record_redemption_observation(
                    kind="idempotent_replay",
                    http_status=200,
                    network=network,
                    payment_hash=payment_hash,
                    quote_id=quote_id,
                    resource_id=resource_id,
                    now=now,
                    response_digest=replayed["response_hash"],
                    consumed_response_hash=replayed["response_hash"],
                )
        return _v2_success(fulfillment, disposition)

    def _v2_success(fulfillment: dict[str, Any], disposition: str) -> JSONResponse:
        return JSONResponse(
            {
                "schema_version": SAFEPAY_V2_SCHEMA_VERSION,
                "fulfillment": fulfillment,
                "delivery": {"replay_disposition": disposition},
            },
            status_code=200,
            headers=dict(_V2_HEADERS),
        )

    def _recompute_quote_hash(quote_row: dict[str, Any]) -> str:
        return safepay_v2_quote_hash(
            quote_id=quote_row["quote_id"],
            proposal_id=quote_row["proposal_id"],
            resource_id=quote_row["resource_id"],
            network=quote_row["network"],
            payee_account_hash=quote_row["payee_account_hash"],
            amount_motes=quote_row["amount_motes"],
            correlation_id=int(quote_row["correlation_id"]),
            report_version=quote_row["report_version"],
            report_hash=quote_row["report_hash"],
            expires_at=int(quote_row["expires_at"]),
            quote_nonce=bytes.fromhex(quote_row["quote_nonce"]),
        )

    # ------------------------------------------------------- legacy v1 (frozen)
    # Historical continuity only: this flow can never generate or substantiate
    # new supplemental-v2 evidence.

    @app.get("/x402/risk-report")
    async def risk_report(request: Request, proposal_id: str = "DAO-PROP-6CB25C", resource: str | None = None):
        paid_resource = resource or f"concordia-governance-report:{proposal_id}"
        payment = request.headers.get("X-Payment", "").strip()
        if not payment:
            return JSONResponse(
                {
                    "error": "payment_required",
                    "provider": "concordia-risk-oracle-provider",
                    "resource": paid_resource,
                    "message": "Send a Casper Testnet transfer deploy hash in X-Payment to unlock this risk report.",
                },
                status_code=402,
                headers=payment_required_headers(paid_resource),
            )

        lag_attempts = max(0, _int_env("X402_PROVIDER_SIMULATE_LAG_ATTEMPTS", 0))
        lag_key = (paid_resource, payment.lower())
        if _LAG_ATTEMPTS[lag_key] < lag_attempts:
            _LAG_ATTEMPTS[lag_key] += 1
            return JSONResponse(
                {
                    "status": "indexer_lag",
                    "provider": "concordia-risk-oracle-provider",
                    "resource": paid_resource,
                    "attempt": _LAG_ATTEMPTS[lag_key],
                    "message": "Payment not visible to provider indexer yet; retry the same X-Payment proof.",
                },
                status_code=425,
            )

        settlement = await verify_casper_transfer_payment_with_retry(
            resource=paid_resource,
            payment_header=payment,
        )
        if settlement.get("status") != "settled":
            return JSONResponse(
                {
                    "error": "payment_not_verified",
                    "provider": "concordia-risk-oracle-provider",
                    "resource": paid_resource,
                    "settlement": settlement,
                },
                status_code=402,
                headers=payment_required_headers(paid_resource),
            )

        return {
            "status": "paid",
            "provider": "concordia-risk-oracle-provider",
            "resource": paid_resource,
            "proposal_id": proposal_id,
            "settlement": settlement,
            "risk_report": {
                "risk_level": "medium-after-policy-cap",
                "requested_allocation_bps": 3000,
                "approved_policy_cap_bps": 800,
                "provider_signal": "external_paid_provider_verified_before_release",
                "recommendation": "Release specialist report only after Casper payment proof settles.",
            },
        }

    return app


app = create_app()
