"""Concordia DAO Council Gateway — controlled full-pipeline demo routes.

Every supported scenario follows the same path:
  proposal-simulator scenario endpoint → Recorder Council Chamber → sealed ProposalCard → agents

Demo capability v1 (G1 freeze, §12):
    - The Gateway is the sole issuer, HMAC validator, operator-token holder,
      durable capability ledger, and activation authority.
    - ``POST /internal/demo/capability`` issues a signed opaque capability;
      ``POST /internal/demo/activate`` validates it (constant-time HMAC,
      expiry, scenario scoping, client binding, one-use/idempotent) and runs
      the trigger pipeline. Both require ``X-Concordia-Dashboard-Token``
      loaded from ``DASHBOARD_DEMO_GATEWAY_TOKEN_FILE`` and are internal-only
      (never routed through Caddy — Codex release layer).
    - The public reset route DOES NOT EXIST. Cleanup is ownership-scoped via
      gateway.routes.demo_cleanup.remove_demo_proposals(db, demo_run_id).
    - Every demo-created record carries ``demo_run_id`` + ``is_demo=true``
      (recorded in the ``demo_runs`` provenance table).
    - Demo proposal IDs use the distinct ``DAO-DEMO-`` prefix so they can
      never collide with canonical ``DAO-PROP-6CB25C``.

The legacy operator-token ``POST /demo/trigger`` remains for server-side
operator tooling only; the public browser path is capability-only.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import secrets as pysecrets
import struct
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from .demo_cleanup import (
    ensure_demo_tables,
    is_protected_proposal_id,
    is_strict_demo_proposal_id,
)
from shared.config import llm_readiness_status
from shared.runtime_secrets import read_secret

router = APIRouter()
logger = logging.getLogger("gateway.demo")

PROPOSAL_SIMULATOR_URL = os.getenv("PROPOSAL_SIMULATOR_URL", "http://127.0.0.1:9000")
GATEWAY_URL = os.getenv("GATEWAY_URL", "http://127.0.0.1:8000")
TRIAGE_AGENT_ID = os.getenv("TRIAGE_AGENT_ID", "")

SCENARIO_ENDPOINTS: dict[str, str] = {
    "treasury": "/admin/scenario/treasury",
    "defi-treasury": "/admin/scenario/defi-treasury",
    "oracle": "/admin/scenario/oracle",
    "yield": "/admin/scenario/yield",
    "exposure": "/admin/scenario/exposure",
    "policy": "/admin/scenario/policy",
    "credential": "/admin/scenario/credential",
    "rwa-onboarding": "/admin/scenario/rwa-onboarding",
}

_SCENARIO_ROOM_LABELS = {
    "treasury": "Risky Treasury Allocation Proposal",
    "defi-treasury": "DeFi Treasury Reallocation Proposal",
    "oracle": "Oracle Feed Anomaly Proposal",
    "yield": "Yield Spike Proposal",
    "exposure": "Treasury Exposure Limit Proposal",
    "policy": "Protocol Drift Proposal",
    "credential": "RWA Credential Expiry Proposal",
    "rwa-onboarding": "RWA Invoice Pool Onboarding Proposal",
}
_SOURCE_VALUES = frozenset({"governance_feed", "treasury_metrics", "casper_events", "rwa_oracle"})
_SEVERITY_VALUES = frozenset({
    "critical",
    "high",
    "medium",
    "low",
    "unknown",
    # Backward-compatible simulator aliases.
    "P1",
    "P2",
    "P3",
    "P4",
})

# Preserve the existing single-trigger lock and 30-second cooldown (the
# cooldown applies to the legacy operator route; the capability path uses the
# frozen per-client/global activation limits below).
_trigger_lock = asyncio.Lock()
_last_trigger_time: float = 0.0
_COOLDOWN_SECONDS = 30.0

# ---------------------------------------------------------------------------
# Demo capability v1 — frozen constants (G1 spec §12 + machine schemas)
# ---------------------------------------------------------------------------

_CAPABILITY_DOMAIN = b"CONCORDIA_DEMO_CAPABILITY_V1\x00"
_CLIENT_BINDING_DOMAIN = b"CONCORDIA_DEMO_CLIENT_V1\x00"
_CAPABILITY_SCHEMA_VERSION = 1
_CAPABILITY_LIFETIME_SECONDS = 120  # maximum_lifetime_seconds (frozen)
_DASHBOARD_TOKEN_HEADER = "X-Concordia-Dashboard-Token"
_CLIENT_NONCE_HEADER = "X-Concordia-Demo-Client"
_DEMO_PROPOSAL_PREFIX = "DAO-DEMO-"  # never collides with DAO-PROP-6CB25C

# Bounded loop-allocation attempts for the readable 6-hex demo-proposal suffix:
# each candidate is collision-checked against BOTH proposals and demo_runs, and
# allocation fails closed once the attempts are exhausted.
_DEMO_ID_ALLOCATION_ATTEMPTS = 16

# Frozen abuse controls: 3 activations / client / 10 min, 20 global / 10 min.
_ACTIVATION_WINDOW_SECONDS = 600
_PER_CLIENT_ACTIVATION_LIMIT = 3
_GLOBAL_ACTIVATION_LIMIT = 20

# Durable capability ISSUANCE admission (WP3-6): per-client + global fixed-window
# limits, outstanding + retained-row caps, bounded expired-row GC. Atomic
# admission across independent DB connections is enforced by wrapping the whole
# check-and-insert in one BEGIN IMMEDIATE (the shared SQLite write lock
# serialises concurrent issuers).
_ISSUE_WINDOW_SECONDS = 600
_PER_CLIENT_ISSUE_LIMIT = 12
_GLOBAL_ISSUE_LIMIT = 120
_MAX_OUTSTANDING_CAPABILITIES = 2000  # unconsumed AND unexpired
_MAX_RETAINED_CAPABILITIES = 10000    # all rows, including expired/consumed
_EXPIRED_CLEANUP_BATCH = 100          # bounded GC per issuance

# Durable capability lifecycle (WP3-1): a RUNNING claim older than this lease is
# treated as crashed and recovered to a terminal FAILED WITHOUT re-running the
# pipeline. The lease exceeds the capability lifetime so an unexpired run always
# recovers via expiry first.
_RUNNING_LEASE_SECONDS = 180

# Durable lifecycle state values (ISSUED -> RUNNING -> SUCCEEDED|FAILED).
_STATE_ISSUED = "ISSUED"
_STATE_RUNNING = "RUNNING"
_STATE_SUCCEEDED = "SUCCEEDED"
_STATE_FAILED = "FAILED"
_TERMINAL_STATES = frozenset({_STATE_SUCCEEDED, _STATE_FAILED})


class DemoTriggerRequest(BaseModel):
    scenario_type: str = "treasury"


class CapabilityIssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scenario_id: str


class CapabilityActivateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capability: str
    scenario_id: str


def _operator_error(request: Request) -> JSONResponse | None:
    """Require an explicit operator token for legacy demo mutations."""
    operator_token = read_secret("CONCORDIA_OPERATOR_TOKEN")
    if not operator_token:
        return JSONResponse(
            {"success": False, "error": "CONCORDIA_OPERATOR_TOKEN is not configured"},
            status_code=503,
        )
    supplied = request.headers.get("x-operator-token", "")
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        supplied = authorization[7:]
    if not hmac.compare_digest(supplied, operator_token):
        return JSONResponse(
            {"success": False, "error": "Valid operator token is required"},
            status_code=401,
        )
    return None


# ---------------------------------------------------------------------------
# Capability primitives
# ---------------------------------------------------------------------------

def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes | None:
    """Strict unpadded-base64url decode.

    Canonicality is enforced (re-encode must equal the input) so trailing
    slack bits cannot yield two distinct encodings of the same bytes.
    """
    if not value or not isinstance(value, str):
        return None
    pad = "=" * (-len(value) % 4)
    try:
        raw = base64.urlsafe_b64decode(value + pad)
    except (binascii.Error, ValueError):
        return None
    if _b64url_encode(raw) != value:
        return None
    return raw


def _dashboard_token_error(request: Request) -> JSONResponse | None:
    """Constant-time check of the dashboard→gateway service token."""
    expected = read_secret("DASHBOARD_DEMO_GATEWAY_TOKEN")
    if not expected:
        return JSONResponse(
            {"error": "DASHBOARD_DEMO_GATEWAY_TOKEN is not configured"},
            status_code=503,
        )
    supplied = request.headers.get(_DASHBOARD_TOKEN_HEADER, "")
    if not hmac.compare_digest(supplied, expected):
        return JSONResponse(
            {"error": "A valid dashboard service token is required"},
            status_code=403,
        )
    return None


def _capability_secret() -> tuple[bytes | None, str]:
    """Load the dedicated demo-capability HMAC secret.

    Enforced at load: at least 32 bytes, and it may not reuse the operator
    token or any approval secret (constant-time comparison — values are
    never logged or echoed).
    """
    value = read_secret("DEMO_CAPABILITY_HMAC_SECRET")
    if not value:
        return None, "DEMO_CAPABILITY_HMAC_SECRET is not configured"
    secret = value.encode("utf-8")
    if len(secret) < 32:
        return None, "DEMO_CAPABILITY_HMAC_SECRET must be at least 32 bytes"

    reuse_candidates = [read_secret("CONCORDIA_OPERATOR_TOKEN")]
    try:
        from gateway.routes.approve_ui import _SECRET_ENV_NAMES, _load_secret

        reuse_candidates.extend(
            _load_secret(env_name) for env_name in _SECRET_ENV_NAMES.values()
        )
    except Exception:  # pragma: no cover — defensive import guard
        pass
    for candidate in reuse_candidates:
        if candidate and hmac.compare_digest(value, candidate):
            return None, (
                "DEMO_CAPABILITY_HMAC_SECRET must not reuse the operator or "
                "approval secrets"
            )
    return secret, ""


def _client_binding_hash_from_request(request: Request) -> bytes | None:
    """Decode X-Concordia-Demo-Client and derive the client binding hash.

    The wire value is unpadded base64url of exactly 32 random bytes; the
    bound value is SHA-256("CONCORDIA_DEMO_CLIENT_V1\\0" || raw nonce).
    IP address and user agent are never used.
    """
    wire = request.headers.get(_CLIENT_NONCE_HEADER, "")
    raw = _b64url_decode(wire)
    if raw is None or len(raw) != 32:
        return None
    return hashlib.sha256(_CLIENT_BINDING_DOMAIN + raw).digest()


def _mint_capability(
    secret: bytes,
    scenario_id: str,
    client_binding_hash: bytes,
) -> dict[str, Any]:
    capability_id = uuid.uuid4()
    issued_at = int(time.time())
    expires_at = issued_at + _CAPABILITY_LIFETIME_SECONDS
    nonce = pysecrets.token_bytes(32)
    scenario_bytes = scenario_id.encode("ascii")
    payload = (
        struct.pack(">I", _CAPABILITY_SCHEMA_VERSION)
        + capability_id.bytes
        + struct.pack(">I", len(scenario_bytes))
        + scenario_bytes
        + struct.pack(">Q", issued_at)
        + struct.pack(">Q", expires_at)
        + client_binding_hash
        + nonce
    )
    tag = hmac.new(secret, _CAPABILITY_DOMAIN + payload, hashlib.sha256).digest()
    token = f"{_b64url_encode(payload)}.{_b64url_encode(tag)}"
    return {
        "token": token,
        "capability_id": str(capability_id),
        "scenario_id": scenario_id,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "client_binding_hash": client_binding_hash.hex(),
        "nonce_hash": hashlib.sha256(nonce).hexdigest(),
    }


def _parse_capability(token: str, secret: bytes) -> dict[str, Any] | None:
    """Verify (constant-time) and strictly parse an opaque capability token."""
    if not token or not isinstance(token, str) or token.count(".") != 1:
        return None
    payload_part, tag_part = token.split(".", 1)
    payload = _b64url_decode(payload_part)
    tag = _b64url_decode(tag_part)
    if payload is None or tag is None:
        return None
    expected_tag = hmac.new(
        secret, _CAPABILITY_DOMAIN + payload, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(tag, expected_tag):
        return None

    # Strict field parse: u32_be(1) || uuid_16 || lp(scenario) || u64_be(issued)
    # || u64_be(expires) || binding(32) || nonce(32) — exact length required.
    offset = 0
    if len(payload) < 4 + 16 + 4:
        return None
    (schema_version,) = struct.unpack_from(">I", payload, offset)
    offset += 4
    if schema_version != _CAPABILITY_SCHEMA_VERSION:
        return None
    capability_id_raw = payload[offset : offset + 16]
    offset += 16
    (scenario_len,) = struct.unpack_from(">I", payload, offset)
    offset += 4
    if scenario_len < 1 or scenario_len > 64:
        return None
    if len(payload) != offset + scenario_len + 8 + 8 + 32 + 32:
        return None
    try:
        scenario_id = payload[offset : offset + scenario_len].decode("ascii")
    except UnicodeDecodeError:
        return None
    offset += scenario_len
    (issued_at,) = struct.unpack_from(">Q", payload, offset)
    offset += 8
    (expires_at,) = struct.unpack_from(">Q", payload, offset)
    offset += 8
    client_binding_hash = payload[offset : offset + 32]
    offset += 32
    nonce = payload[offset : offset + 32]
    return {
        "capability_id": str(uuid.UUID(bytes=capability_id_raw)),
        "scenario_id": scenario_id,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "client_binding_hash": client_binding_hash,
        "nonce_hash": hashlib.sha256(nonce).hexdigest(),
    }


def _stored_response_integrity_error() -> JSONResponse:
    """Terminal fail-closed error for a corrupt stored activation result."""
    return JSONResponse(
        {
            "error": "Stored demo activation result failed integrity validation",
            "error_code": "stored_response_integrity",
        },
        status_code=503,
    )


def _stored_capability_response(row) -> JSONResponse:
    """Replay the stored one-use activation result (idempotent semantics).

    The COMPLETE stored-result schema is validated: ``response_status`` must be
    an int in the sane HTTP range 100-599 and ``response_json`` must parse to a
    JSON object. A terminal row violating either replays as a terminal 503
    integrity error — corruption is never turned into an empty 200 success.
    """
    status_code = row["response_status"]
    if not isinstance(status_code, int) or not 100 <= status_code <= 599:
        return _stored_response_integrity_error()
    raw_body = row["response_json"]
    if not isinstance(raw_body, str) or not raw_body:
        return _stored_response_integrity_error()
    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError:
        return _stored_response_integrity_error()
    if not isinstance(body, dict):
        return _stored_response_integrity_error()
    if body.get("status") == "started":
        body = {**body, "status": "idempotent_replay"}
    return JSONResponse(body, status_code=status_code)


def _activation_counts(db, client_binding_hash_hex: str) -> tuple[int, int]:
    window_start = int(time.time()) - _ACTIVATION_WINDOW_SECONDS
    client_count = db.execute(
        "SELECT COUNT(*) FROM demo_capabilities "
        "WHERE consumed_at IS NOT NULL AND consumed_at >= ? "
        "AND client_binding_hash = ?",
        (window_start, client_binding_hash_hex),
    ).fetchone()[0]
    global_count = db.execute(
        "SELECT COUNT(*) FROM demo_capabilities "
        "WHERE consumed_at IS NOT NULL AND consumed_at >= ?",
        (window_start,),
    ).fetchone()[0]
    return int(client_count), int(global_count)


# ---------------------------------------------------------------------------
# Capability issuance admission (WP3-6)
# ---------------------------------------------------------------------------

def _issue_rate_error() -> JSONResponse:
    return JSONResponse(
        {
            "error": "Demo capability issuance rate limit reached",
            "error_code": "issue_rate_limited",
        },
        status_code=429,
    )


def _issue_capacity_error() -> JSONResponse:
    return JSONResponse(
        {
            "error": "Demo capability issuance capacity exhausted",
            "error_code": "issue_capacity_exhausted",
        },
        status_code=503,
    )


def _counter_value(db, scope: str, client_key: str, window_start: int) -> int:
    row = db.execute(
        "SELECT count FROM demo_capability_issue_counters "
        "WHERE scope=? AND client_key=? AND window_start=?",
        (scope, client_key, window_start),
    ).fetchone()
    return int(row[0]) if row else 0


def _bump_counter(db, scope: str, client_key: str, window_start: int) -> None:
    db.execute(
        "INSERT INTO demo_capability_issue_counters "
        "(scope, client_key, window_start, count) VALUES (?, ?, ?, 1) "
        "ON CONFLICT(scope, client_key, window_start) DO UPDATE SET "
        "count=count+1",
        (scope, client_key, window_start),
    )


def _admit_and_persist_capability(db, minted: dict[str, Any]) -> JSONResponse | None:
    """Atomic issuance admission + durable capability insert (WP3-6).

    One ``BEGIN IMMEDIATE`` runs bounded expired-row GC, retained/outstanding
    capacity checks, durable per-client + global fixed-window rate admission,
    and the ``demo_capabilities`` insert. Because the whole check-then-write is
    under the shared SQLite write lock, concurrent issuers on independent
    connections cannot bypass the limits. Returns an error response on refusal,
    or ``None`` when the capability was persisted.
    """
    now = int(minted["issued_at"])
    client_key = minted["client_binding_hash"]
    window_start = (now // _ISSUE_WINDOW_SECONDS) * _ISSUE_WINDOW_SECONDS

    db.execute("BEGIN IMMEDIATE")
    try:
        # Bounded GC of expired, UNCONSUMED capabilities (consumed/terminal rows
        # are never touched) and of stale counter windows.
        db.execute(
            "DELETE FROM demo_capabilities WHERE capability_id IN ("
            "  SELECT capability_id FROM demo_capabilities "
            "  WHERE consumed_at IS NULL AND expires_at <= ? "
            "  ORDER BY expires_at ASC LIMIT ?"
            ")",
            (now, _EXPIRED_CLEANUP_BATCH),
        )
        db.execute(
            "DELETE FROM demo_capability_issue_counters WHERE window_start < ?",
            (window_start - _ISSUE_WINDOW_SECONDS,),
        )

        retained = db.execute(
            "SELECT COUNT(*) FROM demo_capabilities"
        ).fetchone()[0]
        if retained >= _MAX_RETAINED_CAPABILITIES:
            db.execute("COMMIT")
            return _issue_capacity_error()

        outstanding = db.execute(
            "SELECT COUNT(*) FROM demo_capabilities "
            "WHERE consumed_at IS NULL AND expires_at > ?",
            (now,),
        ).fetchone()[0]
        if outstanding >= _MAX_OUTSTANDING_CAPABILITIES:
            db.execute("COMMIT")
            return _issue_capacity_error()

        client_count = _counter_value(db, "client", client_key, window_start)
        global_count = _counter_value(db, "global", "global", window_start)
        if (
            client_count >= _PER_CLIENT_ISSUE_LIMIT
            or global_count >= _GLOBAL_ISSUE_LIMIT
        ):
            db.execute("COMMIT")
            return _issue_rate_error()

        _bump_counter(db, "client", client_key, window_start)
        _bump_counter(db, "global", "global", window_start)
        db.execute(
            "INSERT INTO demo_capabilities "
            "(capability_id, scenario_id, client_binding_hash, nonce_hash, "
            "issued_at, expires_at, state) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                minted["capability_id"],
                minted["scenario_id"],
                minted["client_binding_hash"],
                minted["nonce_hash"],
                minted["issued_at"],
                minted["expires_at"],
                _STATE_ISSUED,
            ),
        )
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    return None


# ---------------------------------------------------------------------------
# Preallocated demo-proposal identity (WP3-2)
# ---------------------------------------------------------------------------

def _assert_demo_proposal_id(preallocated: str, observed: str) -> None:
    """Require ``observed`` to EXACTLY equal the preallocated strict demo id.

    Enforced BEFORE the first proposal mutation: a canonical/historical,
    pre-existing, or otherwise non-matching id (even one that happens to equal a
    protected id) fails closed.
    """
    if not is_strict_demo_proposal_id(preallocated) or is_protected_proposal_id(
        preallocated
    ):
        raise ValueError("preallocated demo proposal id is not a strict demo id")
    if observed != preallocated:
        raise ValueError(
            "simulator/preparer proposal id does not equal the preallocated "
            "DAO-DEMO-* id"
        )
    if not is_strict_demo_proposal_id(observed) or is_protected_proposal_id(observed):
        raise ValueError("observed proposal id is not a strict demo id")


def _allocate_demo_proposal_id(db) -> str | None:
    """Loop-allocate a unique, strict ``DAO-DEMO-*`` proposal id.

    The readable 6-hex suffix format is kept, but every candidate is checked
    against BOTH ``proposals`` and ``demo_runs``: a collision with ANY existing
    row is skipped so a pre-existing ``DAO-DEMO-*`` record is never silently
    adopted (and never becomes cleanup-owned). Returns ``None`` — fail closed —
    once ``_DEMO_ID_ALLOCATION_ATTEMPTS`` candidates are exhausted. Callers
    hold ``_trigger_lock``, which serialises the check-then-reserve sequence.
    """
    for _ in range(_DEMO_ID_ALLOCATION_ATTEMPTS):
        candidate = f"{_DEMO_PROPOSAL_PREFIX}{uuid.uuid4().hex[:6].upper()}"
        if not is_strict_demo_proposal_id(candidate) or is_protected_proposal_id(
            candidate
        ):  # pragma: no cover — defensive; a uuid suffix is always strict
            continue
        existing_proposal = db.execute(
            "SELECT 1 FROM proposals WHERE proposal_id=? LIMIT 1", (candidate,)
        ).fetchone()
        existing_run = db.execute(
            "SELECT 1 FROM demo_runs WHERE proposal_id=? LIMIT 1", (candidate,)
        ).fetchone()
        if existing_proposal is None and existing_run is None:
            return candidate
    return None


async def _run_simulator_scenario(
    endpoint: str, requested_proposal_id: str
) -> dict[str, Any]:
    """Activate one simulator scenario and return its JSON payload.

    Extracted so the preallocated-id contract can be unit/integration tested
    without a live proposal-simulator service.
    """
    async with httpx.AsyncClient(timeout=10.0) as http:
        response = await http.post(
            f"{PROPOSAL_SIMULATOR_URL}{endpoint}",
            json={"proposal_id": requested_proposal_id},
        )
        response.raise_for_status()
        return response.json()


# ---------------------------------------------------------------------------
# Simulator payload validation (unchanged pipeline semantics)
# ---------------------------------------------------------------------------

def _fallback_proposal_signal(payload: dict[str, Any]) -> dict[str, Any]:
    """Adapt the simulator response into a DAO treasury proposal."""
    proposal = payload.get("proposal") or payload.get("treasury") or {}
    service = str(proposal.get("service") or proposal.get("dao_target") or "dao-treasury")
    version = str(proposal.get("version") or proposal.get("current_allocation") or "unknown")
    proposer = str(proposal.get("proposer") or "dao-proposer")
    return {
        "signal_type": "risky_treasury_allocation",
        "source": "governance_feed",
        "title": f"Risky treasury allocation: {service} v{version} by {proposer}",
        "preliminary_severity": "medium",
        "service": service,
        "security_relevant": True,
        "fingerprint": f"sha256:treasury-{service}-{proposer}",
        "raw_payload": proposal,
    }


def _validate_signal_payload(
    scenario_type: str,
    simulator_payload: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    proposal_id = str(simulator_payload.get("proposal_id") or "").strip()
    if not proposal_id:
        raise ValueError("simulator response did not include proposal_id")

    signal = simulator_payload.get("signal")
    if not isinstance(signal, dict):
        if scenario_type != "treasury":
            raise ValueError("simulator response did not include signal payload")
        signal = _fallback_proposal_signal(simulator_payload)

    source = str(signal.get("source") or "")
    preliminary_severity = str(signal.get("preliminary_severity") or "unknown")
    raw_payload = signal.get("raw_payload")
    if source not in _SOURCE_VALUES:
        raise ValueError("simulator response included unsupported signal source")
    if preliminary_severity not in _SEVERITY_VALUES:
        raise ValueError("simulator response included unsupported preliminary severity")
    if not isinstance(raw_payload, dict):
        raise ValueError("simulator response raw_payload must be an object")
    if not str(signal.get("title") or "").strip():
        raise ValueError("simulator response did not include signal title")
    return proposal_id, signal


# ---------------------------------------------------------------------------
# Shared trigger executor (legacy operator route + capability activation)
# ---------------------------------------------------------------------------

async def _execute_demo_trigger(
    db,
    scenario_type: str,
    *,
    demo_run_id: str,
    enforce_cooldown: bool,
) -> tuple[int, dict[str, Any]]:
    """Run one scenario through the full Council pipeline.

    Returns ``(status_code, payload)``. Every created proposal is recorded in
    the ``demo_runs`` provenance table with ``demo_run_id`` + ``is_demo=1``.
    """
    global _last_trigger_time

    llm = llm_readiness_status()
    if llm["required"] and not llm["ready"]:
        return 503, {
            "success": False,
            "error": "Live LLM readiness failed; workflow start refused",
            "llm": llm,
        }

    from agents.recorder import Recorder
    from shared.models import ProposalCard
    from shared.submission_client import SubmissionClient, format_card_message

    endpoint = SCENARIO_ENDPOINTS.get(scenario_type)
    if endpoint is None:
        return 400, {
            "success": False,
            "error": (
                f"Unknown scenario_type: {scenario_type}. Allowed: "
                f"{', '.join(SCENARIO_ENDPOINTS)}"
            ),
        }

    if not TRIAGE_AGENT_ID:
        return 503, {
            "success": False,
            "error": "TRIAGE_AGENT_ID not configured",
        }
    if _trigger_lock.locked():
        return 429, {
            "success": False,
            "error": "A demo trigger is already in progress",
        }

    if enforce_cooldown:
        now = time.monotonic()
        if now - _last_trigger_time < _COOLDOWN_SECONDS:
            remaining = max(1, int(_COOLDOWN_SECONDS - (now - _last_trigger_time)))
            return 429, {
                "success": False,
                "error": f"Cooldown active — retry in {remaining}s",
            }

    recorder = None
    simulator_active = False
    proposal_id = ""

    async with _trigger_lock:
        # Preallocate the exact, unique demo-proposal identity BEFORE any
        # mutation (WP3-2). The distinct DAO-DEMO- prefix can never collide
        # with the canonical DAO-PROP-6CB25C namespace; the readable 6-hex
        # suffix is loop-allocated under the trigger lock with a collision
        # check against BOTH proposals and demo_runs, so a pre-existing
        # DAO-DEMO-* record is never silently adopted (and never becomes
        # cleanup-owned). Fails closed after bounded attempts.
        ensure_demo_tables(db)
        demo_proposal_id = _allocate_demo_proposal_id(db)
        if demo_proposal_id is None:
            return 500, {
                "success": False,
                "error": "Failed to allocate a demo proposal id",
            }

        # Reserve run provenance BEFORE the first durable mutation (WP3-3).
        # Kept on EVERY partial failure so the run stays discoverable and
        # exactly cleanable via remove_demo_proposals(db, demo_run_id).
        db.execute(
            "INSERT OR IGNORE INTO demo_runs "
            "(demo_run_id, proposal_id, scenario_id, is_demo, created_at) "
            "VALUES (?, ?, ?, 1, ?)",
            (
                demo_run_id,
                demo_proposal_id,
                scenario_type,
                datetime.now(timezone.utc).isoformat(),
            ),
        )

        try:
            simulator_payload = await _run_simulator_scenario(
                endpoint, demo_proposal_id
            )

            if not isinstance(simulator_payload, dict):
                raise ValueError("simulator response was not a JSON object")
            returned_proposal_id, signal_payload = _validate_signal_payload(
                scenario_type, simulator_payload
            )

            # The simulator/preparer id MUST equal the preallocated id, checked
            # BEFORE the first proposal mutation (WP3-2). Canonical/historical
            # or pre-existing ids fail closed here.
            _assert_demo_proposal_id(demo_proposal_id, returned_proposal_id)
            proposal_id = demo_proposal_id

            # Cooldown starts only after simulator activation succeeds,
            # preserving a deterministic one-click demo path.
            _last_trigger_time = time.monotonic()
            simulator_active = True

            signal = ProposalCard(
                signal_id=proposal_id,
                source=signal_payload["source"],
                timestamp=datetime.now(timezone.utc),
                title=str(signal_payload["title"]),
                raw_payload=signal_payload["raw_payload"],
                fingerprint=str(
                    signal_payload.get("fingerprint")
                    or f"sha256:dao-proposal-{scenario_type}-{proposal_id}"
                ),
                preliminary_severity=signal_payload["preliminary_severity"],
                security_relevant=bool(
                    signal_payload.get("security_relevant", False)
                ),
            )

            async with SubmissionClient(
                GATEWAY_URL, agent_key=read_secret("RECORDER_SUBMISSION_KEY")
            ) as submission:
                prepared = await submission.prepare(
                    signal, idempotency_key=str(uuid.uuid4())
                )
                # The sealed proposal id must still equal the preallocated id.
                _assert_demo_proposal_id(demo_proposal_id, prepared.proposal_id)

                recorder = Recorder()
                room_title = (
                    f"🔴 {prepared.proposal_id} — {_SCENARIO_ROOM_LABELS[scenario_type]}"
                )
                room_id = await recorder.create_room(
                    room_title,
                    proposal_id=prepared.proposal_id,
                )
                await recorder.add_participant(room_id, TRIAGE_AGENT_ID)

                message_id = await recorder.post_message(
                    room_id,
                    format_card_message(prepared.sealed_card),
                    [TRIAGE_AGENT_ID],
                )
                confirmed = await submission.confirm(
                    submission_id=prepared.submission_id,
                    proposal_id=prepared.proposal_id,
                    card_hash=prepared.card_hash,
                    message_id=message_id,
                    room_id=room_id,
                )

            return 200, {
                "success": True,
                "scenario_type": scenario_type,
                "signal_type": signal_payload.get("signal_type"),
                "target": signal_payload.get("raw_payload", {}).get("dao_target"),
                "severity": signal_payload.get("severity"),
                "proposal_id": prepared.proposal_id,
                "demo_run_id": demo_run_id,
                "is_demo": True,
                "room_id": room_id,
                "state": confirmed.new_state,
                "card_hash": prepared.card_hash[:24] + "...",
            }

        except Exception as exc:
            logger.error(
                "Demo trigger failed for scenario=%s (%s)",
                scenario_type,
                type(exc).__name__,
            )
            # Provenance is intentionally NOT removed — the partial run must
            # stay discoverable and exactly cleanable (WP3-3).
            if simulator_active and proposal_id:
                try:
                    async with httpx.AsyncClient(timeout=5.0) as http:
                        await http.post(
                            f"{PROPOSAL_SIMULATOR_URL}/admin/scenario/{proposal_id}/reset"
                        )
                except Exception as compensation_exc:
                    logger.warning(
                        "Demo compensation failed (%s)",
                        type(compensation_exc).__name__,
                    )
            return 502, {
                "success": False,
                "error": "Demo trigger failed — check server logs",
            }
        finally:
            if recorder is not None:
                try:
                    await recorder.client.aclose()
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# Internal endpoints — demo capability v1 (dashboard-proxied)
# ---------------------------------------------------------------------------

@router.post("/internal/demo/capability")
async def issue_demo_capability(body: CapabilityIssueRequest, request: Request):
    """Issue a signed, short-lived, scenario-scoped, client-bound capability."""
    if error := _dashboard_token_error(request):
        return error

    scenario_id = body.scenario_id
    if scenario_id not in SCENARIO_ENDPOINTS:
        return JSONResponse(
            {
                "error": (
                    f"Unknown scenario_id: {scenario_id or '(missing)'}. Allowed: "
                    f"{', '.join(SCENARIO_ENDPOINTS)}"
                )
            },
            status_code=400,
        )

    client_binding_hash = _client_binding_hash_from_request(request)
    if client_binding_hash is None:
        return JSONResponse(
            {
                "error": (
                    f"{_CLIENT_NONCE_HEADER} must be unpadded base64url of "
                    "exactly 32 bytes"
                )
            },
            status_code=400,
        )

    secret, secret_error = _capability_secret()
    if secret is None:
        return JSONResponse({"error": secret_error}, status_code=503)

    minted = _mint_capability(secret, scenario_id, client_binding_hash)

    db = request.app.state.db
    ensure_demo_tables(db)
    # Durable per-client/global rate + capacity admission and the capability
    # insert happen atomically in one BEGIN IMMEDIATE (WP3-6).
    admission_error = _admit_and_persist_capability(db, minted)
    if admission_error is not None:
        return admission_error

    # Frozen issue-response shape: exactly these four fields.
    return {
        "schema_version": "demo-capability-v1",
        "capability": minted["token"],
        "scenario_id": minted["scenario_id"],
        "expires_at": minted["expires_at"],
    }


@router.post("/internal/demo/activate")
async def activate_demo_capability(body: CapabilityActivateRequest, request: Request):
    """Validate a capability and run its scenario (one-use/idempotent)."""
    if error := _dashboard_token_error(request):
        return error

    client_binding_hash = _client_binding_hash_from_request(request)
    if client_binding_hash is None:
        return JSONResponse(
            {
                "error": (
                    f"{_CLIENT_NONCE_HEADER} must be unpadded base64url of "
                    "exactly 32 bytes"
                )
            },
            status_code=400,
        )

    secret, secret_error = _capability_secret()
    if secret is None:
        return JSONResponse({"error": secret_error}, status_code=503)

    payload = _parse_capability(body.capability, secret)
    if payload is None or payload["scenario_id"] not in SCENARIO_ENDPOINTS:
        return JSONResponse(
            {"error": "Invalid capability", "error_code": "invalid_capability"},
            status_code=401,
        )

    if body.scenario_id != payload["scenario_id"]:
        # A capability may activate only its own scenario.
        return JSONResponse(
            {
                "error": "Capability is not valid for this scenario",
                "error_code": "scenario_mismatch",
            },
            status_code=403,
        )

    if not hmac.compare_digest(client_binding_hash, payload["client_binding_hash"]):
        return JSONResponse(
            {
                "error": "Capability is bound to a different client",
                "error_code": "client_binding_mismatch",
            },
            status_code=403,
        )

    now = int(time.time())
    if now >= payload["expires_at"]:
        return JSONResponse(
            {"error": "Capability expired", "error_code": "capability_expired"},
            status_code=403,
        )

    db = request.app.state.db
    ensure_demo_tables(db)
    client_hash_hex = payload["client_binding_hash"].hex()

    # Durable capability lifecycle (WP3-1 / addendum 1-2). ONE BEGIN IMMEDIATE
    # dispatches terminal/running retries, recovers a crashed/expired RUNNING
    # claim WITHOUT re-running, enforces activation limits, and atomically
    # claims ISSUED -> RUNNING. No retry path can ever return an empty 200.
    demo_run_id: str | None = None
    db.execute("BEGIN IMMEDIATE")
    try:
        row = db.execute(
            "SELECT * FROM demo_capabilities WHERE capability_id=?",
            (payload["capability_id"],),
        ).fetchone()
        if (
            row is None
            or row["scenario_id"] != payload["scenario_id"]
            or row["client_binding_hash"] != client_hash_hex
            or row["nonce_hash"] != payload["nonce_hash"]
            or row["issued_at"] != payload["issued_at"]
            or row["expires_at"] != payload["expires_at"]
        ):
            # Signed but not present/consistent in the durable ledger — refuse.
            # ALL signed immutable fields must equal the durable row, including
            # issued_at/expires_at.
            db.execute("COMMIT")
            return JSONResponse(
                {"error": "Invalid capability", "error_code": "invalid_capability"},
                status_code=401,
            )

        state = row["state"] or _STATE_ISSUED

        if state in _TERMINAL_STATES:
            # Terminal retry returns the EXACT stored status/body.
            db.execute("COMMIT")
            return _stored_capability_response(row)

        if state == _STATE_RUNNING:
            lease_deadline = int(row["consumed_at"] or 0) + _RUNNING_LEASE_SECONDS
            if now < lease_deadline and now < int(row["expires_at"]):
                # A concurrent, still-in-flight retry: honest 202 with the SAME
                # run identity — never an empty 200.
                running_run_id = row["demo_run_id"]
                db.execute("COMMIT")
                return JSONResponse(
                    {
                        "schema_version": "demo-run-v1",
                        "status": "running",
                        "demo_run_id": running_run_id,
                        "scenario_id": row["scenario_id"],
                        "is_demo": True,
                    },
                    status_code=202,
                )
            # Crash/expiry recovery: transition to terminal FAILED WITHOUT
            # re-running any mutation.
            crash_body = {
                "schema_version": "demo-run-v1",
                "status": "failed",
                "error": "Demo run did not finish (crash/expiry recovery)",
                "demo_run_id": row["demo_run_id"],
                "scenario_id": row["scenario_id"],
                "is_demo": True,
            }
            db.execute(
                "UPDATE demo_capabilities SET state=?, response_status=?, "
                "response_json=? WHERE capability_id=? AND state=?",
                (
                    _STATE_FAILED,
                    503,
                    json.dumps(crash_body),
                    payload["capability_id"],
                    _STATE_RUNNING,
                ),
            )
            db.execute("COMMIT")
            return JSONResponse(crash_body, status_code=503)

        # state == ISSUED — enforce activation limits, then claim RUNNING.
        client_count, global_count = _activation_counts(db, client_hash_hex)
        if (
            client_count >= _PER_CLIENT_ACTIVATION_LIMIT
            or global_count >= _GLOBAL_ACTIVATION_LIMIT
        ):
            # Throttled BEFORE consumption — the capability stays ISSUED and
            # usable within its remaining lifetime.
            db.execute("COMMIT")
            return JSONResponse(
                {"error": "Demo activation limit reached", "error_code": "throttled"},
                status_code=429,
            )

        demo_run_id = f"demo-run-{uuid.uuid4().hex}"
        db.execute(
            "UPDATE demo_capabilities SET state=?, consumed_at=?, demo_run_id=? "
            "WHERE capability_id=? AND state=?",
            (
                _STATE_RUNNING,
                now,
                demo_run_id,
                payload["capability_id"],
                _STATE_ISSUED,
            ),
        )
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise

    # This request now exclusively owns the RUNNING claim. The pipeline runs
    # OUTSIDE the write lock; provenance is reserved inside it (WP3-3).
    status_code, trigger_payload = await _execute_demo_trigger(
        db,
        payload["scenario_id"],
        demo_run_id=demo_run_id,
        enforce_cooldown=False,
    )

    if status_code == 200 and trigger_payload.get("success"):
        response_body: dict[str, Any] = {
            "schema_version": "demo-run-v1",
            "status": "started",
            "demo_run_id": demo_run_id,
            "scenario_id": payload["scenario_id"],
            "is_demo": True,
            "created_proposal_ids": [trigger_payload.get("proposal_id")],
        }
        terminal_state = _STATE_SUCCEEDED
    else:
        # Honest degraded state — no fabricated success.
        response_body = trigger_payload
        terminal_state = _STATE_FAILED

    response_status = (
        200 if response_body.get("schema_version") == "demo-run-v1" else status_code
    )

    # Record the terminal state + stored response atomically so terminal
    # retries replay the exact status/body. Exactly one row must be updated:
    # zero rows means the RUNNING claim was terminalized concurrently (lease
    # expiry + crash recovery), and the durable ledger — not the in-memory
    # result — is the authority for what this request returns.
    db.execute("BEGIN IMMEDIATE")
    try:
        cursor = db.execute(
            "UPDATE demo_capabilities SET state=?, response_status=?, "
            "response_json=? WHERE capability_id=? AND state=?",
            (
                terminal_state,
                response_status,
                json.dumps(response_body),
                payload["capability_id"],
                _STATE_RUNNING,
            ),
        )
        if cursor.rowcount != 1:
            # Lost claim: re-read INSIDE the same BEGIN IMMEDIATE and replay
            # the persisted terminal state via the validated stored-response
            # path — never the in-memory result.
            row = db.execute(
                "SELECT * FROM demo_capabilities WHERE capability_id=?",
                (payload["capability_id"],),
            ).fetchone()
            db.execute("COMMIT")
            if row is None or (row["state"] or "") not in _TERMINAL_STATES:
                # A missing/non-terminal ledger row after a lost claim is
                # corruption — fail closed, never fabricate success.
                return _stored_response_integrity_error()
            return _stored_capability_response(row)
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise

    return JSONResponse(response_body, status_code=response_status)


# ---------------------------------------------------------------------------
# Legacy operator route (server-side tooling only; public path is
# capability-only and the public reset route no longer exists)
# ---------------------------------------------------------------------------

@router.post("/demo/trigger")
async def demo_trigger(
    request: Request,
    body: DemoTriggerRequest | None = None,
):
    """Activate one scenario and seed the complete Council Chamber agent pipeline."""
    if error := _operator_error(request):
        return error

    scenario_type = (body.scenario_type if body else "treasury").strip().lower()
    if scenario_type not in SCENARIO_ENDPOINTS:
        return JSONResponse(
            {
                "success": False,
                "error": (
                    f"Unknown scenario_type: {scenario_type}. Allowed: "
                    f"{', '.join(SCENARIO_ENDPOINTS)}"
                ),
            },
            status_code=400,
        )

    demo_run_id = f"demo-run-{uuid.uuid4().hex}"
    status_code, payload = await _execute_demo_trigger(
        request.app.state.db,
        scenario_type,
        demo_run_id=demo_run_id,
        enforce_cooldown=True,
    )
    if status_code == 200:
        return payload
    return JSONResponse(payload, status_code=status_code)
