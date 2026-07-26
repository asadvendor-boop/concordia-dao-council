"""Recorder heartbeat — keeps the Recorder agent visible on the dashboard.

The Recorder is a deterministic (no-LLM) agent that runs on-demand via the
gateway to fetch and archive Council Chamber messages. Since it doesn't use
run_with_supervisor, this lightweight script sends heartbeats independently.
"""
import asyncio
import os
import logging

logger = logging.getLogger("concordia.recorder_heartbeat")


async def heartbeat_loop():
    import httpx

    gw = os.getenv("GATEWAY_URL", "http://localhost:8000")
    key = os.getenv("RECORDER_SUBMISSION_KEY", "")

    agent_id = os.getenv("RECORDER_AGENT_ID", "recorder-heartbeat")

    async with httpx.AsyncClient(timeout=5) as client:
        while True:
            try:
                resp = await client.post(
                    f"{gw}/heartbeat",
                    json={
                        "role": "recorder",
                        "agent_id": agent_id,
                        "framework": "local proposal-room runtime",
                        "model": "deterministic",
                        "display_name": "Concordia Core",
                        "persona_title": "Council Runtime Recorder",
                        "persona_temperament": "deterministic, evidence-preserving, and non-LLM",
                    },
                    headers={"X-Agent-Key": key},
                )
                resp.raise_for_status()
            except Exception as exc:
                logger.warning(
                    "[recorder] Heartbeat failed (%s)",
                    type(exc).__name__,
                )
            await asyncio.sleep(30)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("[recorder] Starting heartbeat...")
    asyncio.run(heartbeat_loop())
