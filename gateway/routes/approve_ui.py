"""Concordia DAO Council Gateway — Human Approval Web Page.

GET  /approve/{proposal_id} — Renders approval form (Caddy-authenticated).
POST /approve/{proposal_id} — Consumes nonce via _do_consume_nonce().

Approval boundary v1 (G1 freeze, §12):
    - Caddy performs Basic Auth and OVERWRITES ``X-Proxy-Secret`` from a
      server-side secret; it never forwards a caller-supplied value. That
      Caddy provisioning lives in the Codex-owned release layer
      (Caddyfile + compose) — see handoff/INTERFACE_MANIFEST_WP3.md.
    - The Gateway trusts only the overwritten ``X-Proxy-Secret`` header and
      then independently verifies proxy secret, Basic credentials with
      bcrypt, the approver allowlist, the CSRF token, and the nonce.
    - Runtime secrets use ``_FILE`` loading. The five frozen configuration
      names are ``APPROVAL_PROXY_SECRET_FILE``, ``APPROVAL_UI_USER_FILE``,
      ``APPROVAL_UI_APPROVER_ID_FILE``, ``APPROVAL_UI_BCRYPT_HASH_FILE``,
      and ``APPROVAL_UI_CSRF_SECRET_FILE``, each pointing at a
      ``/run/secrets/...`` file in production. Direct value variables are
      ignored in production; a clearly-labeled test-mode fallback exists
      only behind ``CONCORDIA_TEST_MODE``.

CSRF protection via HMAC of nonce + secret.
"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path

import base64
import hashlib
import html as html_mod
import hmac
import json
import logging
import os

import bcrypt
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from gateway.routes.rooms import store_room_message, store_room_participant
from shared.config import HUMAN_APPROVER_IDS
from shared.runtime_secrets import read_secret

logger = logging.getLogger("concordia.approve_ui")

router = APIRouter()


# ---------------------------------------------------------------------------
# Configuration (loaded once; _FILE-only in production)
# ---------------------------------------------------------------------------

_TRUE_VALUES = {"1", "true", "yes", "on"}

# Frozen G1 approval-boundary configuration names (spec §12, Approval
# boundary v1). Each secret is delivered through ``<NAME>_FILE``.
_SECRET_ENV_NAMES = {
    "proxy_secret": "APPROVAL_PROXY_SECRET",
    "user": "APPROVAL_UI_USER",
    "approver_id": "APPROVAL_UI_APPROVER_ID",
    "bcrypt_hash": "APPROVAL_UI_BCRYPT_HASH",
    "csrf_secret": "APPROVAL_UI_CSRF_SECRET",
}

_config_cache: dict | None = None


def _test_mode_enabled() -> bool:
    """Explicit test-mode gate (same env the repo already uses)."""
    return os.getenv("CONCORDIA_TEST_MODE", "").strip().lower() in _TRUE_VALUES


def _load_secret(env_name: str) -> str:
    """Load one approval secret.

    Production: ``_FILE``-only — the value is read from the file named by
    ``<env_name>_FILE`` (``/run/secrets/...``). Direct value variables are
    ignored, per the frozen approval-boundary contract.

    TEST-MODE FALLBACK (``CONCORDIA_TEST_MODE`` only): resolves through
    ``shared.runtime_secrets.read_secret`` so tests may inject either the
    direct variable or a ``_FILE`` pointing at a temporary file.
    """
    if _test_mode_enabled():
        return read_secret(env_name)
    file_path = os.getenv(f"{env_name}_FILE", "").strip()
    if not file_path:
        return ""
    try:
        return Path(file_path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _get_config() -> dict:
    global _config_cache
    if _config_cache is None:
        _config_cache = {
            key: _load_secret(env_name)
            for key, env_name in _SECRET_ENV_NAMES.items()
        }
    return _config_cache


def _reset_config_for_testing() -> None:
    """Reset the config cache — call in test fixtures with patched env.

    Mirrors gateway.auth._reset_for_testing: without this, the first
    _get_config() wins and later tests see stale secrets.
    """
    global _config_cache
    _config_cache = None


# ---------------------------------------------------------------------------
# Auth — proxy secret + bcrypt second layer
# ---------------------------------------------------------------------------

def _authenticate(request: Request) -> str:
    """Authenticate and return the approved human approver_id.

    Three layers:
        1. X-Proxy-Secret must match (proves Caddy forwarded this)
        2. Basic Auth password verified via bcrypt (independent of Caddy)
        3. Approver ID must be in HUMAN_APPROVER_IDS allowlist
    """
    cfg = _get_config()

    # Layer 1: Proxy secret
    secret = request.headers.get("X-Proxy-Secret", "")
    if not cfg["proxy_secret"] or not hmac.compare_digest(secret, cfg["proxy_secret"]):
        raise HTTPException(status_code=403, detail="Direct access forbidden")

    # Layer 2: Basic Auth password (bcrypt) — the authoritative check
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Basic "):
        raise HTTPException(
            status_code=401,
            detail="Basic authentication required",
            headers={"WWW-Authenticate": "Basic"},
        )
    try:
        decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
        username, password = decoded.split(":", 1)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid auth header")

    if username != cfg["user"]:
        raise HTTPException(status_code=403, detail="Unknown user")

    if not cfg["bcrypt_hash"]:
        raise HTTPException(status_code=500, detail="APPROVAL_UI_BCRYPT_HASH not configured")

    if not bcrypt.checkpw(password.encode(), cfg["bcrypt_hash"].encode()):
        raise HTTPException(status_code=403, detail="Invalid credentials")

    # Layer 3: Map to approver
    if not cfg["approver_id"] or cfg["approver_id"] not in HUMAN_APPROVER_IDS:
        raise HTTPException(status_code=500, detail="Approver not configured or not in allowlist")

    return cfg["approver_id"]


# ---------------------------------------------------------------------------
# CSRF — HMAC of nonce
# ---------------------------------------------------------------------------

def _csrf_token(nonce: str) -> str:
    """Generate CSRF token from nonce + secret."""
    secret = _get_config()["csrf_secret"]
    if not secret:
        raise HTTPException(status_code=500, detail="CSRF secret not configured")
    return hmac.new(secret.encode(), nonce.encode(), hashlib.sha256).hexdigest()


def _verify_csrf(nonce: str, token: str) -> bool:
    """Verify CSRF token."""
    expected = _csrf_token(nonce)
    return hmac.compare_digest(expected, token)


# ---------------------------------------------------------------------------
# Plan loader — uses proven predicate
# ---------------------------------------------------------------------------

def _load_response_plan(db, proposal_id: str) -> dict | None:
    """Load confirmed ResponsePlan and derive hashes.

    CRITICAL: Both the SELECT predicate and the hash derivation MUST
    mirror the proven code exactly:
    - SELECT: published_at IS NOT NULL (nonce.py:490, authorization.py:516)
    - Hashes: compute_plan_hash(normalize_plan_for_hash(...)) (nonce.py:515-517)
    Using a different predicate (e.g. card_json LIKE) or different
    derivation → validate_nonce_only returns 'Plan hash mismatch' → silent 400.
    """
    from shared.approval import (
        compute_plan_hash, compute_action_hash, normalize_plan_for_hash,
    )

    plan_card = db.execute(
        "SELECT card_json FROM cards "
        "WHERE proposal_id=? AND card_type='ResponsePlan' "
        "AND published_at IS NOT NULL "
        "ORDER BY sequence_number DESC LIMIT 1",
        (proposal_id,),
    ).fetchone()

    if not plan_card:
        return None

    plan_data = json.loads(plan_card["card_json"])
    return {
        "plan_data": plan_data,
        "plan_hash": compute_plan_hash(normalize_plan_for_hash(plan_data)),
        "action_hash": compute_action_hash(plan_data.get("envelopes", [])),
    }


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

_APPROVAL_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Concordia DAO Council Approval — {proposal_id}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       max-width: 640px; margin: 2rem auto; padding: 0 1rem;
       background: #0d1117; color: #c9d1d9; }}
h1 {{ color: #58a6ff; font-size: 1.4rem; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px;
         padding: 1rem; margin: 1rem 0; }}
.risk-high {{ border-left: 4px solid #f85149; }}
.actions {{ list-style: none; padding: 0; }}
.actions li {{ padding: 0.25rem 0; }}
button {{ background: #238636; color: white; border: none; padding: 0.75rem 1.5rem;
          border-radius: 6px; cursor: pointer; font-size: 1rem; font-weight: 600; }}
button:hover {{ background: #2ea043; }}
.success {{ color: #3fb950; font-weight: 600; }}
.error {{ color: #f85149; font-weight: 600; }}
pre {{ background: #0d1117; border: 1px solid #30363d; padding: 0.5rem;
       border-radius: 4px; overflow-x: auto; font-size: 0.8rem; }}
</style>
</head>
<body>
{content}
</body>
</html>"""

_PLAN_CONTENT = """
<h1>🔐 Approval Required — {proposal_id}</h1>
<div class="card risk-high">
  <strong>Governance playbook:</strong> {runbook}<br>
  <strong>Risk:</strong> {risk_level}<br>
  <strong>Nonce expires:</strong> {expiry}
</div>
<div class="card">
  <strong>Actions:</strong>
  <ul class="actions">
    {action_items}
  </ul>
</div>
<details>
  <summary>Full plan JSON</summary>
  <pre>{plan_json}</pre>
</details>
<form method="POST" id="decision-form">
  <input type="hidden" name="csrf_token" value="{csrf_token}">
  <input type="hidden" name="nonce" value="{nonce}">

  <div style="margin: 1.5rem 0;">
    <button type="submit" name="decision" value="approve"
            style="width:100%%; margin-bottom:0.75rem;">✅ APPROVE PLAN</button>
  </div>

  <div class="card" style="border-left: 4px solid #d29922;">
    <strong style="color:#d29922;">🔄 Reject &amp; Request Revision</strong>
    <div style="margin: 0.5rem 0;">
      <label for="revision_instructions" style="display:block; margin-bottom:0.25rem; color:#8b949e; font-size:0.85rem;">
        What should be changed? (required, max 1000 characters):
      </label>
      <textarea name="revision_instructions" id="revision_instructions"
                placeholder="e.g. reduce allocation to 8%, require dual oracle evidence, add risk cap..."
                maxlength="1000" rows="3"
                style="width:100%%; padding:0.5rem; background:#0d1117; border:1px solid #30363d;
                       border-radius:4px; color:#c9d1d9; font-size:0.9rem; resize:vertical;
                       box-sizing:border-box;"></textarea>
      <div style="text-align:right; color:#8b949e; font-size:0.75rem;">
        <span id="char-count">0</span>/1000
      </div>
    </div>
    <button type="submit" name="decision" value="revise"
            style="background:#d29922; width:100%%;"
            onmouseover="this.style.background='#e3b341'"
            onmouseout="this.style.background='#d29922'"
            onclick="var t=document.getElementById('revision_instructions').value.trim();if(!t){{signal('Please provide revision instructions');return false;}}if(t.length>1000){{signal('Instructions too long (max 1000 characters)');return false;}}">
      🔄 REJECT &amp; REQUEST REVISION</button>
  </div>

  <div style="margin-top: 0.75rem;">
    <button type="submit" name="decision" value="false_alarm"
            style="background:#da3633; width:100%%;"
            onmouseover="this.style.background='#f85149'"
            onmouseout="this.style.background='#da3633'"
            onclick="return confirm('Are you sure this is a false alarm? This action is terminal — the proposal will be closed.')">
      🚫 REJECT — THIS IS A FALSE ALARM</button>
  </div>
</form>
<script>
(function(){{
  var ta = document.getElementById('revision_instructions');
  var cc = document.getElementById('char-count');
  if(ta && cc) ta.addEventListener('input', function(){{ cc.textContent = ta.value.length; }});
}})();
</script>
"""

_SUCCESS_CONTENT = """
<h1>✅ Approved — {proposal_id}</h1>
<p class="success">{message}</p>
"""

_REJECTED_CONTENT = """
<h1>❌ Rejected — {proposal_id}</h1>
<p class="error">{message}</p>
"""

_REVISION_REQUESTED_CONTENT = """
<h1>🔄 Revision Requested — {proposal_id}</h1>
<p style="color:#d29922; font-weight:600;">{message}</p>
<p style="color:#8b949e;">Protocol Strategy Agent will propose a revised plan. Refresh this page when notified.</p>
"""

_FALSE_ALARM_CONTENT = """
<h1>🚫 Closed — False Alarm — {proposal_id}</h1>
<p class="error">{message}</p>
<p style="color:#8b949e;">This proposal has been sealed as a false alarm. No further automation will run.</p>
"""

_ERROR_CONTENT = """
<h1>⚠️ Error — {proposal_id}</h1>
<p class="error">{message}</p>
"""

_NO_PENDING_CONTENT = """
<h1>ℹ️ No Pending Approval — {proposal_id}</h1>
<p>No active approval challenge found for this proposal.</p>
<p>State: <code>{state}</code></p>
"""


# ---------------------------------------------------------------------------
# GET — render approval page
# ---------------------------------------------------------------------------

@router.get("/approve/{proposal_id}", response_class=HTMLResponse)
async def approval_page(proposal_id: str, request: Request):
    """Render the approval page for a human approver."""
    _authenticate(request)  # 403/401 if not authenticated

    db = request.app.state.db

    # Check proposal state
    inc = db.execute(
        "SELECT state FROM proposals WHERE proposal_id=?",
        (proposal_id,),
    ).fetchone()
    if not inc:
        return HTMLResponse(
            _APPROVAL_PAGE.format(
                proposal_id=html_mod.escape(proposal_id),
                content=_ERROR_CONTENT.format(
                    proposal_id=html_mod.escape(proposal_id),
                    message="Proposal not found",
                ),
            ),
            status_code=404,
        )

    state = inc["state"]

    # Already approved/executed → success
    if state in ("APPROVED", "EXECUTED"):
        return HTMLResponse(
            _APPROVAL_PAGE.format(
                proposal_id=html_mod.escape(proposal_id),
                content=_SUCCESS_CONTENT.format(
                    proposal_id=html_mod.escape(proposal_id),
                    message=f"Already {html_mod.escape(state.lower())}. No action needed.",
                ),
            ),
        )

    # Check for PUBLISHED auth → already done
    auth_published = db.execute(
        "SELECT authorization_id FROM authorizations "
        "WHERE proposal_id=? AND authorization_type='human_approval' "
        "AND status='PUBLISHED'",
        (proposal_id,),
    ).fetchone()
    if auth_published:
        return HTMLResponse(
            _APPROVAL_PAGE.format(
                proposal_id=html_mod.escape(proposal_id),
                content=_SUCCESS_CONTENT.format(
                    proposal_id=html_mod.escape(proposal_id),
                    message="Approval already published. Awaiting execution.",
                ),
            ),
        )

    # Check for PENDING auth → resume page
    auth_pending = db.execute(
        "SELECT authorization_id, nonce FROM authorizations "
        "WHERE proposal_id=? AND authorization_type='human_approval' "
        "AND status='PENDING'",
        (proposal_id,),
    ).fetchone()
    if auth_pending:
        csrf = _csrf_token(auth_pending["nonce"])
        esc_id = html_mod.escape(proposal_id)
        return HTMLResponse(
            _APPROVAL_PAGE.format(
                proposal_id=esc_id,
                content=(
                    '<h1>⏳ Pending Resume — {proposal_id}</h1>'
                    '<div class="card">'
                    '<p>A previous approval attempt is pending (room publication may have failed).</p>'
                    '<p>Click below to retry the room publication.</p>'
                    '</div>'
                    '<form method="POST">'
                    '<input type="hidden" name="csrf_token" value="{csrf}">'
                    '<input type="hidden" name="nonce" value="{nonce}">'
                    '<input type="hidden" name="resume" value="1">'
                    '<input type="hidden" name="decision" value="approve">'
                    '<button type="submit">🔄 Retry Publication</button>'
                    '</form>'
                ).format(
                    proposal_id=esc_id,
                    csrf=html_mod.escape(csrf),
                    nonce=html_mod.escape(auth_pending["nonce"]),
                ),
            ),
        )

    # Check for active nonce → show plan
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    nonce_row = db.execute(
        "SELECT nonce, expiry FROM nonces "
        "WHERE proposal_id=? AND consumed=0 AND invalidated=0 "
        "AND expiry > ? AND challenge_message_id IS NOT NULL "
        "AND length(trim(challenge_message_id)) > 0 "
        "ORDER BY rowid DESC LIMIT 1",
        (proposal_id, now),
    ).fetchone()

    if not nonce_row:
        return HTMLResponse(
            _APPROVAL_PAGE.format(
                proposal_id=html_mod.escape(proposal_id),
                content=_NO_PENDING_CONTENT.format(
                    proposal_id=html_mod.escape(proposal_id),
                    state=html_mod.escape(state),
                ),
            ),
        )

    # Load plan
    plan_info = _load_response_plan(db, proposal_id)
    if not plan_info:
        return HTMLResponse(
            _APPROVAL_PAGE.format(
                proposal_id=html_mod.escape(proposal_id),
                content=_ERROR_CONTENT.format(
                    proposal_id=html_mod.escape(proposal_id),
                    message="No confirmed ResponsePlan found",
                ),
            ),
            status_code=500,
        )

    plan_data = plan_info["plan_data"]
    envelopes = plan_data.get("envelopes", [])
    action_items = "\n    ".join(
        f'<li>📋 {html_mod.escape(e.get("action_id", "unknown"))}</li>' for e in envelopes
    )

    csrf = _csrf_token(nonce_row["nonce"])

    return HTMLResponse(
        _APPROVAL_PAGE.format(
            proposal_id=html_mod.escape(proposal_id),
            content=_PLAN_CONTENT.format(
                proposal_id=html_mod.escape(proposal_id),
                runbook=html_mod.escape(str(plan_data.get("runbook", "unknown"))),
                risk_level=html_mod.escape(str(plan_data.get("risk_level", "unknown"))),
                expiry=html_mod.escape(str(nonce_row["expiry"])),
                action_items=action_items,
                plan_json=html_mod.escape(json.dumps(plan_data, indent=2)),
                csrf_token=html_mod.escape(csrf),
                nonce=html_mod.escape(nonce_row["nonce"]),
            ),
        ),
    )


# ---------------------------------------------------------------------------
# POST — human decision (approve / revise / false alarm)
# ---------------------------------------------------------------------------

@router.post("/approve/{proposal_id}", response_class=HTMLResponse)
async def approve_proposal(proposal_id: str, request: Request):
    """Process human decision via web form.

    Three decisions:
        approve     → existing StructuredApproval(APPROVED) flow
        revise      → seal StructuredApproval(REJECTED, reason=...) → Protocol Strategy Agent revises
        false_alarm → seal StructuredApproval(FALSE_ALARM) → terminal closure

    CSRF is verified BEFORE any branching (Council P0 fix).
    """
    approver_id = _authenticate(request)

    db = request.app.state.db

    # Parse form data
    form = await request.form()
    nonce = form.get("nonce", "")
    csrf_token = form.get("csrf_token", "")
    is_resume = form.get("resume", "") == "1"
    decision = form.get("decision", "")
    revision_instructions = form.get("revision_instructions", "").strip()

    # ---- CSRF FIRST (before ANY decision branching) ----
    if not nonce or not csrf_token:
        return HTMLResponse(
            _APPROVAL_PAGE.format(
                proposal_id=html_mod.escape(proposal_id),
                content=_ERROR_CONTENT.format(
                    proposal_id=html_mod.escape(proposal_id),
                    message="Missing nonce or CSRF token",
                ),
            ),
            status_code=400,
        )

    if not _verify_csrf(nonce, csrf_token):
        return HTMLResponse(
            _APPROVAL_PAGE.format(
                proposal_id=html_mod.escape(proposal_id),
                content=_ERROR_CONTENT.format(
                    proposal_id=html_mod.escape(proposal_id),
                    message="CSRF verification failed",
                ),
            ),
            status_code=403,
        )

    # ---- Input validation for revise ----
    if decision == "revise":
        if not revision_instructions:
            return HTMLResponse(
                _APPROVAL_PAGE.format(
                    proposal_id=html_mod.escape(proposal_id),
                    content=_ERROR_CONTENT.format(
                        proposal_id=html_mod.escape(proposal_id),
                        message="Revision instructions are required.",
                    ),
                ),
                status_code=400,
            )
        if len(revision_instructions) > 1000:
            return HTMLResponse(
                _APPROVAL_PAGE.format(
                    proposal_id=html_mod.escape(proposal_id),
                    content=_ERROR_CONTENT.format(
                        proposal_id=html_mod.escape(proposal_id),
                        message="Revision instructions too long (max 1000 characters).",
                    ),
                ),
                status_code=400,
            )

    # ---- Load plan (needed for all decision paths) ----
    plan_info = _load_response_plan(db, proposal_id)
    if not plan_info:
        return HTMLResponse(
            _APPROVAL_PAGE.format(
                proposal_id=html_mod.escape(proposal_id),
                content=_ERROR_CONTENT.format(
                    proposal_id=html_mod.escape(proposal_id),
                    message="No confirmed ResponsePlan found",
                ),
            ),
            status_code=500,
        )

    # ---- Branch on decision ----
    if decision == "approve":
        return await _handle_approve(
            proposal_id, nonce, plan_info, approver_id, is_resume, db,
        )
    elif decision == "revise":
        return await _handle_revise(
            proposal_id, nonce, plan_info, approver_id,
            revision_instructions, db,
        )
    elif decision == "false_alarm":
        return await _handle_false_alarm(
            proposal_id, nonce, plan_info, approver_id, db,
        )
    else:
        return HTMLResponse(
            _APPROVAL_PAGE.format(
                proposal_id=html_mod.escape(proposal_id),
                content=_ERROR_CONTENT.format(
                    proposal_id=html_mod.escape(proposal_id),
                    message=f"Unknown decision: {html_mod.escape(decision)}",
                ),
            ),
            status_code=400,
        )


# ---------------------------------------------------------------------------
# Decision handlers
# ---------------------------------------------------------------------------

async def _handle_approve(
    proposal_id: str, nonce: str, plan_info: dict,
    approver_id: str, is_resume: bool, db,
) -> HTMLResponse:
    """Handle APPROVE decision — existing flow via _do_consume_nonce."""
    from gateway.routes.nonce import _do_consume_nonce

    try:
        result = await _do_consume_nonce(
            proposal_id=proposal_id,
            nonce=nonce,
            plan_hash=plan_info["plan_hash"],
            action_hash=plan_info["action_hash"],
            consumed_by=approver_id,
            room_message_id="",  # UI path — no external approval message from human
            approval_channel="gateway_ui",
            db=db,
        )

        return HTMLResponse(
            _APPROVAL_PAGE.format(
                proposal_id=html_mod.escape(proposal_id),
                content=_SUCCESS_CONTENT.format(
                    proposal_id=html_mod.escape(proposal_id),
                    message=f"Approved! Authorization: {html_mod.escape(str(result.authorization_id))}",
                ),
            ),
        )

    except HTTPException as e:
        # Check if already approved (double-click)
        inc = db.execute(
            "SELECT state FROM proposals WHERE proposal_id=?",
            (proposal_id,),
        ).fetchone()
        if inc and inc["state"] in ("APPROVED", "EXECUTED"):
            return HTMLResponse(
                _APPROVAL_PAGE.format(
                    proposal_id=html_mod.escape(proposal_id),
                    content=_SUCCESS_CONTENT.format(
                        proposal_id=html_mod.escape(proposal_id),
                        message=f"Already {html_mod.escape(inc['state'].lower())}. No action needed.",
                    ),
                ),
            )

        return HTMLResponse(
            _APPROVAL_PAGE.format(
                proposal_id=html_mod.escape(proposal_id),
                content=_ERROR_CONTENT.format(
                    proposal_id=html_mod.escape(proposal_id),
                    message=f"Approval failed: {html_mod.escape(str(e.detail))}",
                ),
            ),
            status_code=e.status_code,
        )


async def _handle_revise(
    proposal_id: str, nonce: str, plan_info: dict,
    approver_id: str, revision_instructions: str, db,
) -> HTMLResponse:
    """Handle REJECT & REVISE — seal StructuredApproval(REJECTED), publish to room @Protocol Strategy Agent.

    State ordering (Council P0): seal card while state is still PLANNED,
    then state transitions to REJECTED on card confirmation.
    Nonce validation (Council P0-1): validate_nonce_only before sealing.
    """
    from shared.models import StructuredApproval
    from shared.integrity import seal_card_in_transaction
    from shared.card_intake import derive_idempotency_key
    from shared.approval import validate_nonce_only

    plan_data = plan_info["plan_data"]
    plan_revision = plan_data.get("revision", 1)

    try:
        db.execute("BEGIN IMMEDIATE")

        # Guard 1: state must be PLANNED (StructuredApproval requires PLANNED)
        inc = db.execute(
            "SELECT state, room_id, legacy_room_id FROM proposals WHERE proposal_id=?",
            (proposal_id,),
        ).fetchone()
        if not inc or inc["state"] != "PLANNED":
            db.execute("ROLLBACK")
            return HTMLResponse(
                _APPROVAL_PAGE.format(
                    proposal_id=html_mod.escape(proposal_id),
                    content=_ERROR_CONTENT.format(
                        proposal_id=html_mod.escape(proposal_id),
                        message=f"Cannot revise: proposal state is '{inc['state'] if inc else 'NOT_FOUND'}', expected 'PLANNED'",
                    ),
                ),
                status_code=409,
            )

        # Guard 2: nonce must be valid (not expired, not consumed, not
        # invalidated, hash-bound to current plan) — Council P0-1 fix
        valid, reason, nonce_row = validate_nonce_only(
            proposal_id=proposal_id,
            nonce=nonce,
            plan_hash=plan_info["plan_hash"],
            action_hash=plan_info["action_hash"],
            db=db,
            require_challenge_visibility=True,
        )
        if not valid:
            db.execute("ROLLBACK")
            logger.warning(
                "[approve_ui] Revise nonce rejected: %s (proposal=%s)",
                reason,
                proposal_id,
            )
            return HTMLResponse(
                _APPROVAL_PAGE.format(
                    proposal_id=html_mod.escape(proposal_id),
                    content=_ERROR_CONTENT.format(
                        proposal_id=html_mod.escape(proposal_id),
                        message=f"Nonce validation failed: {html_mod.escape(reason)}",
                    ),
                ),
                status_code=409,
            )

        room_id = inc["room_id"] or inc["legacy_room_id"] or ""
        expiry_str = nonce_row["expiry"] if nonce_row else (
            datetime.now(timezone.utc).isoformat()
        )

        # Seal StructuredApproval(REJECTED) card
        rejection_card = StructuredApproval(
            proposal_id=proposal_id,
            action_id="plan_revision_request",
            action_hash=plan_info["action_hash"],
            decision="REJECTED",
            approver_id=approver_id,
            room_message_id="",
            legacy_room_id=room_id,
            plan_hash=plan_info["plan_hash"],
            nonce=nonce,
            expiry=datetime.fromisoformat(expiry_str) if isinstance(expiry_str, str) else expiry_str,
            reason=revision_instructions,
            approval_channel="gateway_ui",
            plan_revision=plan_revision,
        )

        idem_key = derive_idempotency_key(
            "gateway_rejection", proposal_id, nonce,
        )

        sealed = seal_card_in_transaction(
            rejection_card, proposal_id, db,
            idempotency_key=idem_key,
            prepared_by_role="gateway",
        )
        sealed_card_hash = sealed.card_hash

        # Invalidate nonce atomically (within same transaction)
        db.execute(
            "UPDATE nonces SET invalidated=1 WHERE proposal_id=? AND nonce=? AND consumed=0",
            (proposal_id, nonce),
        )

        # Advance state atomically in the SAME transaction.
        # Card + state + nonce always commit together — DB is never inconsistent.
        from gateway.routes.submission import _resolve_state
        card_json_str = sealed.model_dump_json()
        new_state = _resolve_state("StructuredApproval", card_json_str)
        if new_state:
            now_str = datetime.now(timezone.utc).isoformat()
            db.execute(
                "UPDATE proposals SET state=?, updated_at=? WHERE proposal_id=?",
                (new_state, now_str, proposal_id),
            )
            logger.info(
                f"[approve_ui] State atomically advanced: {proposal_id} → {new_state}"
            )

        db.execute("COMMIT")

    except HTTPException:
        raise
    except Exception as exc:
        db.execute("ROLLBACK")
        logger.error(
            "[approve_ui] Revise seal failed (%s)",
            type(exc).__name__,
        )
        return HTMLResponse(
            _APPROVAL_PAGE.format(
                proposal_id=html_mod.escape(proposal_id),
                content=_ERROR_CONTENT.format(
                    proposal_id=html_mod.escape(proposal_id),
                    message="Failed to seal rejection due to an internal error.",
                ),
            ),
            status_code=500,
        )

    # Post-commit: publish sealed card to the Council Chamber (best-effort notification).
    # The decision is already applied (card sealed, state advanced, nonce burned).
    # Room notification lets Protocol Strategy Agent act on it; if it fails, the decision
    # is still applied (state advanced, nonce burned).
    # P1-4: Retry up to 3 times with exponential backoff before giving up.
    published = False
    import asyncio as _asyncio
    ROOM_RETRY_DELAYS = [0.5, 1.5, 3.0]
    for attempt, delay in enumerate(ROOM_RETRY_DELAYS):
        try:
            published = await _publish_rejection_to_room(
                db, proposal_id, sealed_card_hash, room_id, mention_commander=True,
            )
            if published:
                break
        except Exception as exc:
            logger.warning(
                "[approve_ui] Room rejection notification attempt %s/%s failed (%s)",
                attempt + 1,
                len(ROOM_RETRY_DELAYS),
                type(exc).__name__,
            )
        if attempt < len(ROOM_RETRY_DELAYS) - 1:
            await _asyncio.sleep(delay)

    if not published:
        # Decision IS applied — state is REJECTED, card is sealed.
        # But Protocol Strategy Agent wasn't notified. Show honest 'notification pending' message.
        logger.warning(
            f"[approve_ui] Revise card sealed, state advanced to REJECTED, "
            f"but room notification failed for {proposal_id}"
        )
        return HTMLResponse(
            _APPROVAL_PAGE.format(
                proposal_id=html_mod.escape(proposal_id),
                content=_REVISION_REQUESTED_CONTENT.format(
                    proposal_id=html_mod.escape(proposal_id),
                    message=(
                        "Revision request sealed and state advanced to REJECTED. "
                        "Room notification pending — if Protocol Strategy Agent does not act, "
                        "an operator may need to re-send the notification."
                    ),
                ),
            ),
        )

    logger.info(
        f"[approve_ui] Plan REJECTED (revise) for {proposal_id}: "
        f"{revision_instructions[:100]}"
    )

    return HTMLResponse(
        _APPROVAL_PAGE.format(
            proposal_id=html_mod.escape(proposal_id),
            content=_REVISION_REQUESTED_CONTENT.format(
                proposal_id=html_mod.escape(proposal_id),
                message=f"Revision requested. Your instructions: \"{html_mod.escape(revision_instructions[:200])}\"",
            ),
        ),
    )


async def _handle_false_alarm(
    proposal_id: str, nonce: str, plan_info: dict,
    approver_id: str, db,
) -> HTMLResponse:
    """Handle FALSE ALARM — seal StructuredApproval(FALSE_ALARM), terminal closure.

    Nonce validation (Council P0-1): validate_nonce_only before sealing.
    """
    from shared.models import StructuredApproval
    from shared.integrity import seal_card_in_transaction
    from shared.card_intake import derive_idempotency_key
    from shared.approval import validate_nonce_only

    plan_data = plan_info["plan_data"]
    plan_revision = plan_data.get("revision", 1)

    try:
        db.execute("BEGIN IMMEDIATE")

        # Guard 1: state must be PLANNED
        inc = db.execute(
            "SELECT state, room_id, legacy_room_id FROM proposals WHERE proposal_id=?",
            (proposal_id,),
        ).fetchone()
        if not inc or inc["state"] != "PLANNED":
            db.execute("ROLLBACK")
            return HTMLResponse(
                _APPROVAL_PAGE.format(
                    proposal_id=html_mod.escape(proposal_id),
                    content=_ERROR_CONTENT.format(
                        proposal_id=html_mod.escape(proposal_id),
                        message=f"Cannot close: proposal state is '{inc['state'] if inc else 'NOT_FOUND'}', expected 'PLANNED'",
                    ),
                ),
                status_code=409,
            )

        # Guard 2: nonce valid — Council P0-1 fix
        valid, reason, nonce_row = validate_nonce_only(
            proposal_id=proposal_id,
            nonce=nonce,
            plan_hash=plan_info["plan_hash"],
            action_hash=plan_info["action_hash"],
            db=db,
            require_challenge_visibility=True,
        )
        if not valid:
            db.execute("ROLLBACK")
            logger.warning(
                "[approve_ui] False alarm nonce rejected: %s (proposal=%s)",
                reason,
                proposal_id,
            )
            return HTMLResponse(
                _APPROVAL_PAGE.format(
                    proposal_id=html_mod.escape(proposal_id),
                    content=_ERROR_CONTENT.format(
                        proposal_id=html_mod.escape(proposal_id),
                        message=f"Nonce validation failed: {html_mod.escape(reason)}",
                    ),
                ),
                status_code=409,
            )

        room_id = inc["room_id"] or inc["legacy_room_id"] or ""
        expiry_str = nonce_row["expiry"] if nonce_row else (
            datetime.now(timezone.utc).isoformat()
        )

        # Seal StructuredApproval(FALSE_ALARM) card
        false_alarm_card = StructuredApproval(
            proposal_id=proposal_id,
            action_id="false_alarm_closure",
            action_hash=plan_info["action_hash"],
            decision="FALSE_ALARM",
            approver_id=approver_id,
            room_message_id="",
            legacy_room_id=room_id,
            plan_hash=plan_info["plan_hash"],
            nonce=nonce,
            expiry=datetime.fromisoformat(expiry_str) if isinstance(expiry_str, str) else expiry_str,
            reason="Human determined this is a false alarm",
            approval_channel="gateway_ui",
            plan_revision=plan_revision,
        )

        idem_key = derive_idempotency_key(
            "gateway_false_alarm", proposal_id, nonce,
        )

        sealed = seal_card_in_transaction(
            false_alarm_card, proposal_id, db,
            idempotency_key=idem_key,
            prepared_by_role="gateway",
        )
        sealed_card_hash = sealed.card_hash

        # Invalidate nonce
        db.execute(
            "UPDATE nonces SET invalidated=1 WHERE proposal_id=? AND nonce=? AND consumed=0",
            (proposal_id, nonce),
        )

        # Advance state atomically.
        from gateway.routes.submission import _resolve_state
        card_json_str = sealed.model_dump_json()
        new_state = _resolve_state("StructuredApproval", card_json_str)
        if new_state:
            now_str = datetime.now(timezone.utc).isoformat()
            db.execute(
                "UPDATE proposals SET state=?, updated_at=? WHERE proposal_id=?",
                (new_state, now_str, proposal_id),
            )
            logger.info(
                f"[approve_ui] State atomically advanced: {proposal_id} → {new_state}"
            )

        # Create suppression rule from ProposalCard fingerprint (bounded learning)
        try:
            signal_row = db.execute(
                """SELECT card_json FROM cards
                   WHERE proposal_id=? AND json_extract(card_json, '$.card_type') = 'ProposalCard'
                   ORDER BY sequence_number ASC LIMIT 1""",
                (proposal_id,),
            ).fetchone()
            if signal_row:
                import json as json_mod
                signal_data = json_mod.loads(signal_row["card_json"])
                fp = signal_data.get("fingerprint", "")
                if fp:
                    # Only create if no active rule exists for this fingerprint
                    existing = db.execute(
                        "SELECT id FROM suppression_rules WHERE fingerprint=? AND active=1",
                        (fp,),
                    ).fetchone()
                    if not existing:
                        db.execute(
                            """INSERT INTO suppression_rules
                               (fingerprint, reason, source_proposal_id, created_at, max_suppressions)
                               VALUES (?, ?, ?, datetime('now'), 3)""",
                            (fp, "Human FALSE_ALARM determination", proposal_id),
                        )
                        logger.info(
                            f"[approve_ui] Created suppression rule for fp={fp[:16]}... "
                            f"from FALSE_ALARM on {proposal_id}"
                        )
        except Exception as exc:
            logger.warning(
                "[approve_ui] Failed to create suppression rule (%s)",
                type(exc).__name__,
            )

        db.execute("COMMIT")

    except HTTPException:
        raise
    except Exception as exc:
        db.execute("ROLLBACK")
        logger.error(
            "[approve_ui] False alarm seal failed (%s)",
            type(exc).__name__,
        )
        return HTMLResponse(
            _APPROVAL_PAGE.format(
                proposal_id=html_mod.escape(proposal_id),
                content=_ERROR_CONTENT.format(
                    proposal_id=html_mod.escape(proposal_id),
                    message="Failed to seal false alarm due to an internal error.",
                ),
            ),
            status_code=500,
        )

    # Post-commit: publish to Council Chamber (best-effort notification)
    published = False
    try:
        published = await _publish_rejection_to_room(
            db, proposal_id, sealed_card_hash, room_id, mention_commander=True,
        )
    except Exception as exc:
        logger.error(
            "[approve_ui] Room publication of false alarm failed (%s)",
            type(exc).__name__,
        )

    if not published:
        # Decision IS applied — but agents weren't notified via the room.
        logger.warning(
            f"[approve_ui] False alarm sealed, state advanced, "
            f"but room notification failed for {proposal_id}"
        )
        return HTMLResponse(
            _APPROVAL_PAGE.format(
                proposal_id=html_mod.escape(proposal_id),
                content=_FALSE_ALARM_CONTENT.format(
                    proposal_id=html_mod.escape(proposal_id),
                    message=(
                        "Proposal closed as false alarm. Sealed in evidence chain. "
                        "Room notification pending — if agents do not sync, "
                        "an operator may need to re-send the notification."
                    ),
                ),
            ),
        )

    logger.info(f"[approve_ui] Proposal {proposal_id} CLOSED as FALSE ALARM")

    return HTMLResponse(
        _APPROVAL_PAGE.format(
            proposal_id=html_mod.escape(proposal_id),
            content=_FALSE_ALARM_CONTENT.format(
                proposal_id=html_mod.escape(proposal_id),
                message="Proposal closed as false alarm. Sealed in the evidence chain.",
            ),
        ),
    )


# ---------------------------------------------------------------------------
# Shared: publish sealed rejection/false-alarm card to the room (notification only)
# ---------------------------------------------------------------------------

async def _publish_rejection_to_room(
    db, proposal_id: str, sealed_card_hash: str, room_id: str,
    *, mention_commander: bool = True,
) -> bool:
    """Publish a sealed StructuredApproval(REJECTED|FALSE_ALARM) to the Council Chamber.

    Returns True when the room message is stored, False otherwise.

    State advance is handled atomically in the seal transaction. This function is post-commit best-effort notification
    only. On success, stores message id + published_at in the cards
    table (Council High-2 fix).
    """
    from shared.submission_client import format_card_message

    if not room_id:
        logger.warning(f"[approve_ui] No Council Chamber for {proposal_id} — skipping publication")
        return False

    # Load sealed card from DB and inject card_hash for room-message copy
    row = db.execute(
        "SELECT card_json, card_hash FROM cards WHERE card_hash=? AND proposal_id=?",
        (sealed_card_hash, proposal_id),
    ).fetchone()
    if not row:
        logger.error(f"[approve_ui] Sealed card {sealed_card_hash} not found in DB")
        return False

    sealed_card_data = json.loads(row["card_json"])
    sealed_card_data["card_hash"] = row["card_hash"]  # Message copy only — DB untouched
    sealed_message = format_card_message(sealed_card_data)

    # Build mentions
    mentions = []
    if mention_commander:
        commander_id = os.getenv("COMMANDER_AGENT_ID", "")
        if commander_id:
            store_room_participant(
                db,
                room_id,
                commander_id,
                role="commander",
                display_name="Protocol Strategy Agent",
            )
            mentions.append(commander_id)

    recorder_agent_id = os.getenv("RECORDER_AGENT_ID", "recorder")
    try:
        message = store_room_message(
            db,
            room_id,
            sealed_message,
            sender_id=recorder_agent_id,
            sender_role="recorder",
            mentions=mentions,
            metadata={
                "publisher": "gateway",
                "card_hash": sealed_card_hash,
            },
        )
    except Exception as exc:
        logger.error(
            "[approve_ui] Room notification failed. Decision already applied "
            "in DB; manual re-send of room notification may be required (%s).",
            type(exc).__name__,
        )
        return False

    message_id = message["message_id"]
    logger.info(
        f"[approve_ui] Rejection card published to Council Chamber: "
        f"proposal={proposal_id}, message={message_id}"
    )

    # Store message id + published_at (Council High-2 fix). The column keeps
    # its old name until schema compatibility cleanup.
    # Guard with published_at IS NULL to prevent double-write.
    try:
        now_str = datetime.now(timezone.utc).isoformat()
        updated = db.execute(
            "UPDATE cards SET published_at=?, room_message_id=? "
            "WHERE card_hash=? AND proposal_id=? AND published_at IS NULL",
            (now_str, message_id, sealed_card_hash, proposal_id),
        ).rowcount
        db.commit()
        if updated:
            logger.info(
                f"[approve_ui] Card published_at + message id stored: "
                f"{sealed_card_hash[:12]}, message={message_id}"
            )
        else:
            logger.info(
                f"[approve_ui] Card {sealed_card_hash[:12]} already published (idempotent)"
            )
    except Exception as exc:
        logger.warning(
            "[approve_ui] message-id storage failed (non-fatal, %s)",
            type(exc).__name__,
        )

    return True
