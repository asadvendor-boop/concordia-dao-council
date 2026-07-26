"""CONCORDIA Card Intake Helpers — Shared extraction and validation functions.

These functions are used by multiple agents (Triage, Diagnosis, etc.) to
extract, validate, and fingerprint sealed cards from room messages.

Extracted from agents/triage/__init__.py to avoid cross-agent imports
and prevent 5-way copy-paste drift as more agents need card intake.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re

logger = logging.getLogger("concordia.card_intake")


def extract_sealed_card(content: str) -> dict | None:
    """Extract a sealed card JSON from a room message.

    Sealed cards are published as fenced JSON blocks:
    ```json
    { ... card fields ... }
    ```

    Also handles raw JSON objects.
    """
    # Try fenced JSON block first
    fenced = re.findall(r'```(?:json)?\s*\n(.*?)\n```', content, re.DOTALL)
    for block in fenced:
        try:
            data = json.loads(block.strip())
            if isinstance(data, dict) and "card_type" in data:
                return data
        except json.JSONDecodeError:
            continue

    # Try raw JSON object
    json_pattern = re.compile(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}')
    for m in json_pattern.finditer(content):
        try:
            data = json.loads(m.group())
            if isinstance(data, dict) and "card_type" in data:
                return data
        except json.JSONDecodeError:
            continue

    return None


def has_seal_fields(card_data: dict) -> bool:
    """Check that an inbound card has the structural fields set by
    Gateway's /prepare endpoint (card_hash and sequence_number).

    This is a pre-filter, NOT cryptographic sealing proof. It rejects
    obviously raw/unserialized cards. The actual integrity guarantee is
    the Gateway's hash chain (verify_chain); agents do a structural
    sanity check here.

    To fully authenticate a card, receivers would need to query Gateway
    and verify the source binding (card exists, type matches, confirmed,
    room_message_id matches). That contract is deferred to the Gateway
    boundary — this pre-filter catches the easy cases.
    """
    card_hash = card_data.get("card_hash")
    sequence_number = card_data.get("sequence_number")

    if not card_hash or not isinstance(card_hash, str):
        logger.warning(
            "[card_intake] REJECTED card: missing card_hash (no seal fields)"
        )
        return False

    if sequence_number is None or not isinstance(sequence_number, int):
        logger.warning(
            "[card_intake] REJECTED card: missing sequence_number (no seal fields)"
        )
        return False

    if sequence_number < 1:
        logger.warning(
            f"[card_intake] REJECTED card: invalid sequence_number={sequence_number}"
        )
        return False

    return True


def derive_idempotency_key(
    agent_role: str, room_message_id: str, card_hash: str,
) -> str:
    """Derive a deterministic idempotency key from agent role, room message
    ID, and the source card hash.

    Using a deterministic key means redelivery of the same room message
    produces the same sealed card (or a 409 Conflict) instead of a
    duplicate. This is safe for Council Chamber's at-least-once delivery.

    Args:
        agent_role: Agent role prefix (e.g. "triage", "diagnosis")
        room_message_id: The room message ID that triggered this processing
        card_hash: The source card's hash from Gateway
    """
    raw = f"{agent_role}:{room_message_id}:{card_hash}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]
