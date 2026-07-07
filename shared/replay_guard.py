"""Shared replay guard — sequence-monotonic staleness + inserted_at freshness.

Used by all 5 agent preprocessors to filter stale messages after Council Chamber
reconnects / agent restarts, saving LLM quota.

Two functions:
- should_skip_stale_card: cost optimization for sealed cards (fail-open)
- should_skip_stale_chatter: freshness filter for non-sealed, non-exempt messages

Design:
- Strict >: skip ONLY if a card with HIGHER sequence_number is already published.
  ==: own confirm landed (normal). <: pre-confirm window. Neither is stale.
- Fail-open: if sequence_number is missing/unparseable or Gateway unreachable,
  proceed. Gateway's confirm-time checks are the authoritative backstop.
- This is a cost-optimization layer, NOT an integrity guarantee.
"""
import os
import logging
from datetime import datetime

import httpx

logger = logging.getLogger("concordia.replay_guard")

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8000")


async def should_skip_stale_card(
    proposal_id: str,
    this_card_seq: int | None,
    role: str,
) -> bool:
    """Return True if a HIGHER-seq card is already published. FAIL-OPEN.

    Args:
        proposal_id: Proposal to check.
        this_card_seq: sequence_number from the incoming card. None = fail-open.
        role: Agent role for logging.

    Returns:
        True → skip (stale), False → process.
    """
    if this_card_seq is None:
        logger.info(f"[{role}] No sequence_number on card — proceeding (fail-open)")
        return False

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{GATEWAY_URL}/proposals/{proposal_id}")
        if resp.status_code != 200:
            logger.warning(
                f"[{role}] Gateway {resp.status_code} for {proposal_id} "
                f"— proceeding (fail-open)"
            )
            return False

        cards = resp.json().get("cards", [])
        max_published_seq = max(
            (
                c["sequence_number"]
                for c in cards
                if c.get("published_at") is not None
            ),
            default=0,
        )

        # Strict >: skip ONLY if higher-seq is published
        if max_published_seq > this_card_seq:
            logger.info(
                f"[{role}] Skipping stale card seq {this_card_seq} for "
                f"{proposal_id}: higher seq {max_published_seq} published"
            )
            return True
        return False

    except Exception as exc:
        logger.warning(
            "[%s] Gateway staleness check failed (%s); proceeding fail-open",
            role,
            type(exc).__name__,
        )
        return False


def should_skip_stale_chatter(
    inserted_at_str: str | None,
    boot_epoch: float,
    role: str,
) -> bool:
    """Skip non-sealed, non-exempt chatter older than boot_epoch - 60s.

    Args:
        inserted_at_str: room message inserted_at timestamp (ISO string).
        boot_epoch: Agent boot time as epoch seconds (time.time()).
        role: Agent role for logging.

    Returns:
        True → skip (stale chatter), False → process.
    """
    if inserted_at_str is None:
        return False
    try:
        msg_epoch = datetime.fromisoformat(str(inserted_at_str)).timestamp()
    except (ValueError, TypeError):
        logger.debug(f"[{role}] Malformed inserted_at — proceeding (fail-open)")
        return False

    if msg_epoch < boot_epoch - 60:
        logger.info(f"[{role}] Skipping stale chatter (inserted {inserted_at_str})")
        return True
    return False
