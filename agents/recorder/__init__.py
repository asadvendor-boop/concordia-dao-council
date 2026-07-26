"""Concordia Core — deterministic Gateway agent (no LLM).

Creates Gateway-owned Council Chambers, adds participants, publishes ProposalCards,
and posts audit events. No LLM — pure deterministic code.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone

from shared.proposal_room import ProposalRoomClient
from shared.models import ProposalCard

logger = logging.getLogger("concordia.recorder")

VALID_SEVERITIES = frozenset({"P1", "P2", "P3", "P4", "unknown"})


class Recorder:
    """Gateway trust anchor — creates rooms, posts cards, posts events."""

    def __init__(self):
        self.agent_id = os.getenv("RECORDER_AGENT_ID", "")
        self.room_client = ProposalRoomClient(
            sender_id=self.agent_id or "recorder",
            sender_role="recorder",
        )
        # Compatibility for older call sites that close recorder.client.
        self.client = self.room_client

    async def create_room(self, title: str, proposal_id: str | None = None) -> str:
        """Create a new Gateway Council Chamber. Returns the room_id."""
        room_id = await self.room_client.create_room(title, proposal_id=proposal_id)
        logger.info(f"Created room: {room_id} ({title})")
        return room_id

    async def add_participant(self, room_id: str, agent_id: str) -> None:
        """Add an agent to a room (invite-before-mention)."""
        await self.room_client.add_participant(
            room_id,
            agent_id,
            role=agent_id,
            display_name=agent_id,
        )
        logger.info(f"Added participant {agent_id} to room {room_id}")

    async def post_message(
        self,
        room_id: str,
        content: str,
        mentions: list[str] | None = None,
    ) -> str:
        """Post a message to an Council Chamber. Returns the message_id."""
        return await self.room_client.post_message(
            room_id,
            content,
            mentions=mentions or [],
        )

    async def get_messages(self, room_id: str) -> list[dict]:
        """Fetch messages from a Gateway Council Chamber."""
        return await self.room_client.get_messages(room_id)

    async def post_event(
        self,
        room_id: str,
        content: str,
        message_type: str = "task",
    ) -> None:
        """Post an event to an Council Chamber."""
        await self.room_client.post_event(room_id, content, message_type=message_type)
        logger.info(f"Posted {message_type} event to room {room_id}")

    def normalize_signal(
        self,
        source: str,
        raw_payload: dict,
    ) -> ProposalCard:
        """Normalize a raw webhook/poller payload into an ProposalCard."""
        fingerprint_data = json.dumps(
            {"source": source, "key_fields": self._extract_key_fields(source, raw_payload)},
            sort_keys=True,
        )
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()

        title = self._extract_title(source, raw_payload)
        severity = self._classify_preliminary_severity(source, raw_payload)
        security = self._is_security_relevant(source, raw_payload)

        return ProposalCard(
            signal_id=str(uuid.uuid4()),
            source=source,
            timestamp=datetime.now(timezone.utc),
            title=title,
            raw_payload=raw_payload,
            fingerprint=fingerprint,
            preliminary_severity=severity,
            security_relevant=security,
        )

    def _extract_key_fields(self, source: str, payload: dict) -> dict:
        """Extract dedup-relevant fields by DAO/Casper source type."""
        if source == "governance_feed":
            return {
                "proposal_id": payload.get("proposal_id", ""),
                "dao_target": payload.get("dao_target", payload.get("service", "")),
                "proposer": payload.get("proposer", payload.get("submitted_by", "")),
            }
        if source == "treasury_metrics":
            return {
                "dao_target": payload.get("dao_target", ""),
                "risk_exposure_pct": payload.get("risk_exposure_pct", ""),
                "policy_compliance_pct": payload.get("policy_compliance_pct", ""),
            }
        if source in {"rwa_oracle", "oracle"}:
            return {
                "asset_id": payload.get("asset_id", ""),
                "issuer": payload.get("issuer", ""),
                "evidence_uri": payload.get("evidence_uri", ""),
            }
        if source == "casper_events":
            return {
                "deploy_hash": payload.get("deploy_hash", ""),
                "contract_hash": payload.get("contract_hash", ""),
            }
        if source == "policy_compliance":
            return {
                "policy_id": payload.get("policy_id", ""),
                "compliance": payload.get("policy_compliance_pct", ""),
            }
        return {"dao_target": payload.get("dao_target", "")}

    def _extract_title(self, source: str, payload: dict) -> str:
        """Extract a human-readable proposal title from the payload."""
        if payload.get("title"):
            return str(payload["title"])
        target = payload.get("dao_target") or payload.get("service") or "DAO treasury"
        if source == "governance_feed":
            return f"Governance proposal: {target}"
        if source == "treasury_metrics":
            return f"Treasury risk signal: {target}"
        if source in {"rwa_oracle", "oracle"}:
            return f"RWA oracle evidence review: {target}"
        if source == "casper_events":
            return f"Casper contract event: {target}"
        if source == "policy_compliance":
            return f"Policy compliance signal: {target}"
        return f"DAO signal from {source}"

    def _classify_preliminary_severity(self, source: str, payload: dict) -> str:
        """Deterministic heuristic for the proposal intake gate."""
        raw = payload.get("preliminary_severity") or payload.get("severity")
        if raw in VALID_SEVERITIES:
            return str(raw)

        risk = float(payload.get("risk_exposure_pct", payload.get("error_rate", 0)) or 0)
        compliance = float(payload.get("policy_compliance_pct", payload.get("uptime_percentage", 100)) or 100)
        if risk >= 70 or compliance < 65:
            return "P1"
        if risk >= 40 or compliance < 80:
            return "P2"
        if risk >= 15 or compliance < 90:
            return "P3"
        return "P4"

    def _is_security_relevant(self, source: str, payload: dict) -> bool:
        """Return True when the proposal touches treasury, RWA, or contract authority."""
        if bool(payload.get("security_relevant", False)):
            return True
        text = " ".join(str(payload.get(key, "")) for key in ("title", "proposal_summary", "recommended_action")).lower()
        keywords = ("treasury", "wallet", "multisig", "oracle", "rwa", "contract", "pause", "veto", "drain")
        return source in {"governance_feed", "rwa_oracle", "casper_events"} or any(word in text for word in keywords)

    async def close(self):
        """Clean up HTTP client."""
        await self.client.aclose()
