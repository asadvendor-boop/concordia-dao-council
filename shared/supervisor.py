"""CONCORDIA Agent Supervisor — process-level resilience wrapper.

This supervisor guards against our code crashes (room runtime bugs, adapter
errors, and tool failures). Auth/policy failures exit non-zero instead of
blind-retrying so deployment checks catch revoked keys.
"""
from __future__ import annotations

import asyncio
import logging
import os

from .personas import persona_payload

logger = logging.getLogger("concordia.supervisor")


async def _heartbeat_loop(role: str, meta: dict | None = None) -> None:
    """Background heartbeat: POST /heartbeat every 30s. Best-effort."""
    import httpx

    if meta is None:
        meta = {}
    gw = os.getenv("GATEWAY_URL", "http://localhost:8000")
    agent_key = os.getenv(f"{role.upper()}_SUBMISSION_KEY", "")

    async with httpx.AsyncClient(timeout=5) as client:
        while True:
            try:
                await client.post(
                    f"{gw}/heartbeat",
                    json={
                        "role": role,
                        "agent_id": meta.get("agent_id", ""),
                        "framework": meta.get("framework", ""),
                        "model": meta.get("model", ""),
                        "display_name": meta.get("display_name", ""),
                        "persona_title": meta.get("persona_title", ""),
                        "persona_temperament": meta.get("persona_temperament", ""),
                    },
                    headers={"X-Agent-Key": agent_key},
                )
            except Exception:
                pass  # Best-effort — never crash the agent over a heartbeat
            await asyncio.sleep(30)


async def run_with_supervisor(create_agent_fn, role: str, meta: dict | None = None):
    """Run an agent with crash restart and best-effort heartbeat.

    Args:
        create_agent_fn: Async callable that creates and returns a configured agent.
        role: Agent role name for logging.
        meta: Optional dict with agent_id, framework, model for heartbeat.
    """
    consecutive_failures = 0
    MAX_FAILURES = 5
    heartbeat_task = None

    while True:
        try:
            logger.info(f"[{role}] Creating agent...")
            agent = await create_agent_fn()
            logger.info(f"[{role}] Agent created, running supervised loop...")
            consecutive_failures = 0
            heartbeat_meta = {**persona_payload(role), **(meta or {})}
            heartbeat_meta.setdefault("agent_id", getattr(agent, "agent_id", ""))
            heartbeat_meta.setdefault("framework", getattr(agent, "framework", ""))
            heartbeat_meta.setdefault("model", getattr(agent, "model", ""))

            # Start heartbeat AFTER agent creation succeeds (Fix 5: truthful status)
            if heartbeat_task is None or heartbeat_task.done():
                heartbeat_task = asyncio.create_task(_heartbeat_loop(role, heartbeat_meta))

            if hasattr(agent, "run"):
                await agent.run()
            elif callable(agent):
                await agent()
            else:
                raise RuntimeError(
                    f"{role} factory returned unsupported agent object "
                    f"{type(agent).__name__}"
                )

            logger.info(f"[{role}] Agent shut down gracefully")
            if heartbeat_task:
                heartbeat_task.cancel()
            break

        except (KeyboardInterrupt, SystemExit):
            logger.info(f"[{role}] Shutdown requested")
            if heartbeat_task:
                heartbeat_task.cancel()
            break

        except asyncio.CancelledError:
            logger.info(f"[{role}] Cancelled (signal shutdown)")
            if heartbeat_task:
                heartbeat_task.cancel()
            break

        except Exception as exc:
            error_name = type(exc).__name__
            # Don't retry auth failures — exit so concordia doctor catches them
            if "auth" in error_name.lower() or "policy" in error_name.lower():
                logger.critical(
                    "[%s] Auth/policy failure (%s) — exiting",
                    role,
                    error_name,
                )
                raise SystemExit(1)

            consecutive_failures += 1
            if consecutive_failures >= MAX_FAILURES:
                logger.critical(
                    f"[{role}] {consecutive_failures} consecutive failures — exiting"
                )
                raise SystemExit(1)

            wait = min(5 * consecutive_failures, 30)
            logger.warning(
                "[%s] Crashed (%s). Restarting in %ss (attempt %s/%s)",
                role,
                error_name,
                wait,
                consecutive_failures,
                MAX_FAILURES,
            )
            await asyncio.sleep(wait)
