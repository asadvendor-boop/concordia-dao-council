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

from .demo_cleanup import ensure_demo_tables
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

# Frozen abuse controls: 3 activations / client / 10 min, 20 global / 10 min.
_ACTIVATION_WINDOW_SECONDS = 600
_PER_CLIENT_ACTIVATION_LIMIT = 3
_GLOBAL_ACTIVATION_LIMIT = 20


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


def _stored_capability_response(row) -> JSONResponse:
    """Replay the stored one-use activation result (idempotent semantics)."""
    status_code = int(row["response_status"] or 200)
    try:
        body = json.loads(row["response_json"] or "{}")
    except json.JSONDecodeError:
        body = {}
    if isinstance(body, dict) and body.get("status") == "started":
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
        try:
            # Distinct demo prefix — can never collide with the canonical
            # DAO-PROP-6CB25C namespace record.
            requested_proposal_id = (
                f"{_DEMO_PROPOSAL_PREFIX}{uuid.uuid4().hex[:6].upper()}"
            )
            async with httpx.AsyncClient(timeout=10.0) as http:
                response = await http.post(
                    f"{PROPOSAL_SIMULATOR_URL}{endpoint}",
                    json={"proposal_id": requested_proposal_id},
                )
                response.raise_for_status()
                simulator_payload = response.json()

            if not isinstance(simulator_payload, dict):
                raise ValueError("simulator response was not a JSON object")
            proposal_id, signal_payload = _validate_signal_payload(
                scenario_type, simulator_payload
            )

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

            # Durable provenance: every demo-created record carries
            # demo_run_id + is_demo=true.
            ensure_demo_tables(db)
            db.execute(
                "INSERT OR IGNORE INTO demo_runs "
                "(demo_run_id, proposal_id, scenario_id, is_demo, created_at) "
                "VALUES (?, ?, ?, 1, ?)",
                (
                    demo_run_id,
                    prepared.proposal_id,
                    scenario_type,
                    datetime.now(timezone.utc).isoformat(),
                ),
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
    db.execute(
        "INSERT INTO demo_capabilities "
        "(capability_id, scenario_id, client_binding_hash, nonce_hash, "
        "issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        (
            minted["capability_id"],
            minted["scenario_id"],
            minted["client_binding_hash"],
            minted["nonce_hash"],
            minted["issued_at"],
            minted["expires_at"],
        ),
    )
    db.commit()

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
    row = db.execute(
        "SELECT * FROM demo_capabilities WHERE capability_id=?",
        (payload["capability_id"],),
    ).fetchone()
    if (
        row is None
        or row["scenario_id"] != payload["scenario_id"]
        or row["client_binding_hash"] != payload["client_binding_hash"].hex()
        or row["nonce_hash"] != payload["nonce_hash"]
    ):
        # Signed but not present/consistent in the durable ledger — refuse.
        return JSONResponse(
            {"error": "Invalid capability", "error_code": "invalid_capability"},
            status_code=401,
        )

    if row["consumed_at"] is not None:
        # One-use with idempotent exact-retry semantics.
        return _stored_capability_response(row)

    client_count, global_count = _activation_counts(
        db, payload["client_binding_hash"].hex()
    )
    if (
        client_count >= _PER_CLIENT_ACTIVATION_LIMIT
        or global_count >= _GLOBAL_ACTIVATION_LIMIT
    ):
        # Throttled BEFORE consumption — the capability stays usable within
        # its remaining lifetime.
        return JSONResponse(
            {"error": "Demo activation limit reached", "error_code": "throttled"},
            status_code=429,
        )

    # Atomic one-use claim.
    cursor = db.execute(
        "UPDATE demo_capabilities SET consumed_at=? "
        "WHERE capability_id=? AND consumed_at IS NULL",
        (now, payload["capability_id"]),
    )
    db.commit()
    if cursor.rowcount != 1:
        row = db.execute(
            "SELECT * FROM demo_capabilities WHERE capability_id=?",
            (payload["capability_id"],),
        ).fetchone()
        return _stored_capability_response(row)

    demo_run_id = f"demo-run-{uuid.uuid4().hex}"
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
    else:
        # Honest degraded state — no fabricated success.
        response_body = trigger_payload

    response_status = 200 if response_body.get("schema_version") == "demo-run-v1" else status_code
    db.execute(
        "UPDATE demo_capabilities SET demo_run_id=?, response_status=?, "
        "response_json=? WHERE capability_id=?",
        (
            demo_run_id,
            response_status,
            json.dumps(response_body),
            payload["capability_id"],
        ),
    )
    db.commit()

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
