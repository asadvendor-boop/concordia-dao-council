"""Wells, Governance Archive Persona.

Concordia Core builds the deterministic Governance Archive and Locke seals it
inside the CasperExecutionReceipt after Casper execution succeeds. This
heartbeat keeps Wells visible only as a non-reasoning presentation persona; it
does not poll rooms, deliberate, generate cards, authorize, or execute.
"""
from __future__ import annotations

import asyncio
import logging
import os


logger = logging.getLogger("concordia.scribe")


async def _heartbeat_loop() -> None:
    import httpx

    gateway_url = os.getenv("GATEWAY_URL", "http://localhost:8000")
    agent_key = os.getenv("SCRIBE_SUBMISSION_KEY", "")
    agent_id = os.getenv("SCRIBE_AGENT_ID", "wells-governance-archivist")
    payload = {
        "role": "scribe",
        "agent_id": agent_id,
        "framework": "Council roster heartbeat",
        "model": "none",
        "display_name": "Wells",
        "persona_title": "Governance Archive Persona",
        "persona_temperament": "methodical, audit-minded, and precise about final evidence packets",
    }

    async with httpx.AsyncClient(timeout=5) as client:
        while True:
            try:
                response = await client.post(
                    f"{gateway_url}/heartbeat",
                    json=payload,
                    headers={"X-Agent-Key": agent_key},
                )
                response.raise_for_status()
            except Exception as exc:
                logger.warning("[scribe] Wells heartbeat failed (%s)", type(exc).__name__)
            await asyncio.sleep(30)


async def main() -> None:
    logger.info(
        "[scribe] Wells presentation heartbeat online. Concordia Core builds "
        "deterministic archives and Locke seals them after Casper execution succeeds."
    )
    await _heartbeat_loop()
