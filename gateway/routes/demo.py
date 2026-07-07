"""Concordia DAO Council Gateway — controlled full-pipeline demo routes.

Every supported scenario follows the same path:
  proposal-simulator scenario endpoint → Recorder Council Chamber → sealed ProposalCard → agents

POST /demo/trigger accepts an optional ``scenario_type`` (default ``treasury``).
POST /demo/reset restores simulator telemetry and removes local demo records.
"""
from __future__ import annotations

import asyncio
import hmac
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .demo_cleanup import remove_demo_proposals
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

# Preserve the existing single-trigger lock and 30-second cooldown.
_trigger_lock = asyncio.Lock()
_last_trigger_time: float = 0.0
_COOLDOWN_SECONDS = 30.0


class DemoTriggerRequest(BaseModel):
    scenario_type: str = "treasury"


def _operator_error(request: Request) -> JSONResponse | None:
    """Require an explicit operator token for demo mutations."""
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


@router.post("/demo/trigger")
async def demo_trigger(
    request: Request,
    body: DemoTriggerRequest | None = None,
):
    """Activate one scenario and seed the complete Council Chamber agent pipeline."""
    global _last_trigger_time
    if error := _operator_error(request):
        return error

    llm = llm_readiness_status()
    if llm["required"] and not llm["ready"]:
        return JSONResponse(
            {
                "success": False,
                "error": "Live LLM readiness failed; workflow start refused",
                "llm": llm,
            },
            status_code=503,
        )

    from agents.recorder import Recorder
    from shared.models import ProposalCard
    from shared.submission_client import SubmissionClient, format_card_message

    scenario_type = (body.scenario_type if body else "treasury").strip().lower()
    endpoint = SCENARIO_ENDPOINTS.get(scenario_type)
    if endpoint is None:
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

    if not TRIAGE_AGENT_ID:
        return JSONResponse(
            {"success": False, "error": "TRIAGE_AGENT_ID not configured"},
            status_code=503,
        )
    if _trigger_lock.locked():
        return JSONResponse(
            {"success": False, "error": "A demo trigger is already in progress"},
            status_code=429,
        )

    now = time.monotonic()
    if now - _last_trigger_time < _COOLDOWN_SECONDS:
        remaining = max(1, int(_COOLDOWN_SECONDS - (now - _last_trigger_time)))
        return JSONResponse(
            {"success": False, "error": f"Cooldown active — retry in {remaining}s"},
            status_code=429,
        )

    recorder = None
    simulator_active = False
    proposal_id = ""

    async with _trigger_lock:
        try:
            requested_proposal_id = f"DAO-PROP-{uuid.uuid4().hex[:6].upper()}"
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

            # Cooldown starts only after simulator activation succeeds, preserving
            # a deterministic one-click demo path.
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

            return {
                "success": True,
                "scenario_type": scenario_type,
                "signal_type": signal_payload.get("signal_type"),
                "target": signal_payload.get("raw_payload", {}).get("dao_target"),
                "severity": signal_payload.get("severity"),
                "proposal_id": prepared.proposal_id,
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
            return JSONResponse(
                {"success": False, "error": "Demo trigger failed — check server logs"},
                status_code=502,
            )
        finally:
            if recorder is not None:
                try:
                    await recorder.client.aclose()
                except Exception:
                    pass


@router.post("/demo/reset")
async def demo_reset(request: Request):
    """Reset simulator telemetry and clear only local synthetic proposal data."""
    if error := _operator_error(request):
        return error
    async with _trigger_lock:
        try:
            # Simulator first: if reset fails, retain Gateway rows so an active
            # proposal cannot disappear from the dashboard as an orphan.
            async with httpx.AsyncClient(timeout=10.0) as http:
                response = await http.post(
                    f"{PROPOSAL_SIMULATOR_URL}/admin/scenario/reset-all"
                )
                response.raise_for_status()
                simulator_result = response.json()

            cleanup = remove_demo_proposals(request.app.state.db)
            return {
                "success": True,
                "status": "reset",
                "simulator_scenarios_cleared": (
                    simulator_result.get("cleared", 0)
                    if isinstance(simulator_result, dict)
                    else 0
                ),
                **cleanup,
            }
        except Exception as exc:
            logger.error("Demo reset failed (%s)", type(exc).__name__)
            return JSONResponse(
                {"success": False, "error": "Demo reset failed — check server logs"},
                status_code=502,
            )
