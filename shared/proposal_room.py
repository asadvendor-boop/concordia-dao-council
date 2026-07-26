"""Gateway-owned Council Chamber client.

This is the replacement collaboration transport for the cloud/LLM version.
It talks to the Gateway's `/api/rooms/*` endpoints and deliberately mirrors the
small method surface agents already need: create room, add participant, post
message, and fetch messages.
"""
from __future__ import annotations

import os
from typing import Any

import httpx


class ProposalRoomClient:
    """Async client for Gateway-managed Council Chambers."""

    def __init__(
        self,
        *,
        gateway_url: str | None = None,
        agent_key: str | None = None,
        sender_id: str | None = None,
        sender_role: str = "recorder",
        timeout: float = 30.0,
    ):
        self.gateway_url = (gateway_url or os.getenv("GATEWAY_URL", "http://127.0.0.1:8000")).rstrip("/")
        self.agent_key = agent_key or os.getenv(f"{sender_role.upper()}_SUBMISSION_KEY", "") or os.getenv("GATEWAY_SECRET", "")
        self.sender_id = sender_id or os.getenv(f"{sender_role.upper()}_AGENT_ID", sender_role)
        self.sender_role = sender_role
        self.client = httpx.AsyncClient(
            base_url=f"{self.gateway_url}/api",
            headers={
                "X-Agent-Key": self.agent_key,
                "Content-Type": "application/json",
            },
            timeout=timeout,
        )

    async def aclose(self) -> None:
        await self.client.aclose()

    async def create_room(self, title: str, proposal_id: str | None = None) -> str:
        response = await self.client.post(
            "/rooms",
            json={"title": title, "proposal_id": proposal_id},
        )
        response.raise_for_status()
        data = response.json()
        room = data.get("data", data)
        return room["room_id"]

    async def add_participant(
        self,
        room_id: str,
        participant_id: str,
        *,
        role: str | None = None,
        display_name: str | None = None,
    ) -> None:
        response = await self.client.post(
            f"/rooms/{room_id}/participants",
            json={
                "participant_id": participant_id,
                "role": role,
                "display_name": display_name,
            },
        )
        response.raise_for_status()

    async def post_message(
        self,
        room_id: str,
        content: str,
        mentions: list[str] | None = None,
        *,
        message_type: str = "message",
        metadata: dict[str, Any] | None = None,
        sender_id: str | None = None,
        sender_role: str | None = None,
        sender_type: str = "Agent",
    ) -> str:
        response = await self.client.post(
            f"/rooms/{room_id}/messages",
            json={
                "content": content,
                "sender_id": sender_id or self.sender_id,
                "sender_role": sender_role or self.sender_role,
                "sender_type": sender_type,
                "mentions": mentions or [],
                "message_type": message_type,
                "metadata": metadata or {},
            },
        )
        response.raise_for_status()
        data = response.json()
        message = data.get("data", data)
        return message["message_id"]

    async def post_event(
        self,
        room_id: str,
        content: str,
        message_type: str = "event",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        return await self.post_message(
            room_id,
            content,
            message_type=message_type,
            metadata=metadata,
        )

    async def get_messages(
        self,
        room_id: str,
        *,
        after_id: int = 0,
        limit: int = 100,
    ) -> list[dict]:
        response = await self.client.get(
            f"/rooms/{room_id}/messages",
            params={"after_id": after_id, "limit": limit},
        )
        response.raise_for_status()
        data = response.json()
        return data.get("messages", [])

    async def list_rooms(
        self,
        *,
        participant_id: str | None = None,
        state: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        response = await self.client.get(
            "/rooms",
            params={
                "participant_id": participant_id,
                "state": state,
                "limit": limit,
            },
        )
        response.raise_for_status()
        data = response.json()
        return data.get("rooms", [])
