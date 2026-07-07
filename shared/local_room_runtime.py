"""Local proposal-room runtime for CONCORDIA agents.

Agents poll Gateway-owned Council Chambers, feed messages into deterministic
preprocessors, and run a role-specific callback when a message should reach the
agent's reasoning/execution layer.
"""
from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Awaitable, Callable

from shared.proposal_room import ProposalRoomClient

logger = logging.getLogger("concordia.local_room_runtime")


@dataclass
class LocalAgentInput:
    """Marker returned by the local default preprocessor."""

    event: "MessageEvent"


class LocalDefaultPreprocessor:
    """Tiny replacement for the external SDK default preprocessor.

    The deterministic preprocessors return this marker when they want the
    agent's reasoning/execution layer to handle a message.  Unsupported chatter
    can still be consumed by returning ``None`` before this is reached.
    """

    async def process(self, ctx, event, **kwargs):
        return LocalAgentInput(event=event)


class MessageEvent:
    """Council Chamber-compatible event shape backed by a Gateway room message row."""

    def __init__(self, message: dict):
        self.room_id = message.get("room_id", "")
        self.payload = SimpleNamespace(
            id=message.get("message_id") or message.get("id", ""),
            content=message.get("content", ""),
            sender_id=message.get("sender_id", ""),
            sender_role=message.get("sender_role", ""),
            sender_type=message.get("sender_type", "Agent"),
            inserted_at=message.get("inserted_at") or message.get("created_at"),
            created_at=message.get("created_at"),
            mentions=message.get("mentions", []),
            metadata=message.get("metadata", {}),
        )


AgentCallback = Callable[[MessageEvent], Awaitable[None]]


class LocalRoomAgent:
    """Poll Gateway-owned rooms and dispatch messages through a preprocessor."""

    def __init__(
        self,
        *,
        role: str,
        agent_id: str,
        preprocessor,
        on_agent_input: AgentCallback | None = None,
        poll_interval: float = 1.0,
        gateway_url: str | None = None,
        agent_key: str | None = None,
        framework: str = "",
        model: str = "",
    ):
        self.role = role
        self.agent_id = agent_id
        self.preprocessor = preprocessor
        self.on_agent_input = on_agent_input
        self.poll_interval = poll_interval
        self.framework = framework
        self.model = model
        self.client = ProposalRoomClient(
            gateway_url=gateway_url,
            agent_key=agent_key,
            sender_id=agent_id or role,
            sender_role=role,
        )
        self._offsets: dict[str, int] = {}
        self._stopping = asyncio.Event()

        # Ensure preprocessors share the local no-op default processor.
        if hasattr(self.preprocessor, "_default_preprocessor"):
            self.preprocessor._default_preprocessor = LocalDefaultPreprocessor()

    async def aclose(self) -> None:
        self._stopping.set()
        await self.client.aclose()

    async def stop(self, timeout: float = 40.0) -> None:
        await self.aclose()

    async def run(self) -> None:
        logger.info(
            "[%s] Local proposal-room runtime started (agent_id=%s)",
            self.role,
            self.agent_id or "<unset>",
        )
        while not self._stopping.is_set():
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning(
                    "[%s] Room poll failed (%s)",
                    self.role,
                    type(exc).__name__,
                )
            await asyncio.sleep(self.poll_interval)

    async def _poll_once(self) -> None:
        rooms = await self.client.list_rooms(
            participant_id=self.agent_id or None,
            limit=int(os.getenv("CONCORDIA_ROOM_POLL_LIMIT", "100")),
        )
        for room in rooms:
            room_id = room.get("room_id") or room.get("id")
            if not room_id:
                continue
            after_id = self._offsets.get(room_id, 0)
            messages = await self.client.get_messages(room_id, after_id=after_id)
            for message in messages:
                sequence = int(message.get("sequence") or 0)
                try:
                    await self._process_message(message)
                finally:
                    if sequence:
                        self._offsets[room_id] = max(
                            self._offsets.get(room_id, 0),
                            sequence,
                        )

    async def _process_message(self, message: dict) -> None:
        event = MessageEvent(message)
        result = await self.preprocessor.process(
            None,
            event,
            agent_id=self.agent_id,
        )
        if isinstance(result, LocalAgentInput) and self.on_agent_input:
            await self.on_agent_input(event)
