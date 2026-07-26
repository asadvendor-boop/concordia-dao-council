"""Gateway-owned Council Chamber API.

These routes are the local collaboration substrate for provider-neutral LLM
agents and the deterministic Gateway ledger. They store rooms, participants, and messages in the Gateway ledger.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from gateway.auth import get_role_for_key

router = APIRouter()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _role_or_401(agent_key: str) -> str:
    role = get_role_for_key(agent_key)
    if not role:
        raise HTTPException(status_code=401, detail="invalid_agent_key")
    return role


class CreateRoomRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    proposal_id: str | None = Field(default=None, max_length=120)


class ParticipantRequest(BaseModel):
    participant_id: str = Field(min_length=1, max_length=120)
    role: str | None = Field(default=None, max_length=80)
    display_name: str | None = Field(default=None, max_length=120)


class MessageRequest(BaseModel):
    content: str = Field(min_length=1)
    sender_id: str | None = Field(default=None, max_length=120)
    sender_role: str | None = Field(default=None, max_length=80)
    sender_type: str = Field(default="Agent", max_length=40)
    mentions: list[str] = Field(default_factory=list)
    message_type: str = Field(default="message", max_length=60)
    metadata: dict[str, Any] = Field(default_factory=dict)


def _room_to_response(row: sqlite3.Row) -> dict:
    return {
        "id": row["room_id"],
        "room_id": row["room_id"],
        "proposal_id": row["proposal_id"],
        "title": row["title"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _message_to_response(row: sqlite3.Row) -> dict:
    try:
        mentions = json.loads(row["mentions_json"] or "[]")
    except json.JSONDecodeError:
        mentions = []
    try:
        metadata = json.loads(row["metadata_json"] or "{}")
    except json.JSONDecodeError:
        metadata = {}
    return {
        "id": row["message_id"],
        "message_id": row["message_id"],
        "room_id": row["room_id"],
        "proposal_id": row["proposal_id"],
        "sender_id": row["sender_id"],
        "sender_role": row["sender_role"],
        "sender_type": row["sender_type"],
        "content": row["content"],
        "mentions": mentions,
        "message_type": row["message_type"],
        "metadata": metadata,
        "created_at": row["created_at"],
        "inserted_at": row["inserted_at"],
        "sequence": row["id"],
    }


def store_room_participant(
    db,
    room_id: str,
    participant_id: str,
    *,
    role: str | None = None,
    display_name: str | None = None,
) -> dict:
    """Insert or update an proposal-room participant."""
    room = db.execute("SELECT room_id FROM proposal_rooms WHERE room_id=?", (room_id,)).fetchone()
    if not room:
        raise HTTPException(status_code=404, detail="room_not_found")

    now = _now()
    db.execute(
        """
        INSERT INTO proposal_room_participants
        (room_id, participant_id, role, display_name, joined_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(room_id, participant_id) DO UPDATE SET
            role=excluded.role,
            display_name=excluded.display_name
        """,
        (room_id, participant_id, role, display_name, now),
    )
    return {
        "participant_id": participant_id,
        "role": role,
        "display_name": display_name,
    }


def store_room_message(
    db,
    room_id: str,
    content: str,
    *,
    sender_id: str,
    sender_role: str,
    sender_type: str = "Agent",
    mentions: list[str] | None = None,
    message_type: str = "message",
    metadata: dict[str, Any] | None = None,
) -> dict:
    """Append a message to a Gateway-owned Council Chamber."""
    room = db.execute("SELECT * FROM proposal_rooms WHERE room_id=?", (room_id,)).fetchone()
    if not room:
        raise HTTPException(status_code=404, detail="room_not_found")

    message_id = f"msg-{uuid.uuid4()}"
    now = _now()
    db.execute(
        """
        INSERT INTO proposal_room_messages
        (message_id, room_id, proposal_id, sender_id, sender_role, sender_type,
         content, mentions_json, message_type, metadata_json, created_at, inserted_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            message_id,
            room_id,
            room["proposal_id"],
            sender_id,
            sender_role,
            sender_type,
            content,
            json.dumps(mentions or [], sort_keys=True),
            message_type,
            json.dumps(metadata or {}, sort_keys=True),
            now,
            now,
        ),
    )
    row = db.execute(
        "SELECT * FROM proposal_room_messages WHERE message_id=?",
        (message_id,),
    ).fetchone()
    return _message_to_response(row)


@router.post("/rooms")
async def create_room(
    body: CreateRoomRequest,
    request: Request,
    x_agent_key: str = Header(default="", alias="X-Agent-Key"),
):
    role = _role_or_401(x_agent_key)
    db = request.app.state.db
    now = _now()

    existing = None
    if body.proposal_id:
        existing = db.execute(
            "SELECT * FROM proposal_rooms WHERE proposal_id=?",
            (body.proposal_id,),
        ).fetchone()
    if existing:
        room = _room_to_response(existing)
        return {"status": "already_exists", "data": room, **room}

    room_id = f"room-{uuid.uuid4()}"
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            """
            INSERT INTO proposal_rooms
            (room_id, proposal_id, title, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (room_id, body.proposal_id, body.title, role, now, now),
        )
        if body.proposal_id:
            db.execute(
                """
                UPDATE proposals
                SET room_id=?, legacy_room_id=COALESCE(legacy_room_id, ?), updated_at=?
                WHERE proposal_id=?
                """,
                (room_id, room_id, now, body.proposal_id),
            )
        db.commit()
    except Exception:
        db.rollback()
        raise

    row = db.execute("SELECT * FROM proposal_rooms WHERE room_id=?", (room_id,)).fetchone()
    room = _room_to_response(row)
    return {"status": "created", "data": room, **room}


@router.post("/rooms/{room_id}/participants")
async def add_participant(
    room_id: str,
    body: ParticipantRequest,
    request: Request,
    x_agent_key: str = Header(default="", alias="X-Agent-Key"),
):
    _role_or_401(x_agent_key)
    db = request.app.state.db
    participant = store_room_participant(
        db,
        room_id,
        body.participant_id,
        role=body.role,
        display_name=body.display_name,
    )
    return {
        "status": "joined",
        "room_id": room_id,
        "participant": participant,
    }


@router.post("/rooms/{room_id}/messages")
async def post_message(
    room_id: str,
    body: MessageRequest,
    request: Request,
    x_agent_key: str = Header(default="", alias="X-Agent-Key"),
):
    role = _role_or_401(x_agent_key)
    db = request.app.state.db
    sender_role = body.sender_role or role
    sender_id = body.sender_id or sender_role
    message = store_room_message(
        db,
        room_id,
        body.content,
        sender_id=sender_id,
        sender_role=sender_role,
        sender_type=body.sender_type,
        mentions=body.mentions,
        message_type=body.message_type,
        metadata=body.metadata,
    )
    return {"status": "posted", "data": message, **message}


@router.get("/rooms/{room_id}/messages")
async def list_messages(
    room_id: str,
    request: Request,
    after_id: int = 0,
    limit: int = 100,
    x_agent_key: str = Header(default="", alias="X-Agent-Key"),
):
    _role_or_401(x_agent_key)
    db = request.app.state.db
    limit = max(1, min(limit, 500))
    rows = db.execute(
        """
        SELECT * FROM proposal_room_messages
        WHERE room_id=? AND id > ?
        ORDER BY id ASC
        LIMIT ?
        """,
        (room_id, after_id, limit),
    ).fetchall()
    messages = [_message_to_response(row) for row in rows]
    return {
        "room_id": room_id,
        "message_count": len(messages),
        "messages": messages,
    }


@router.get("/rooms")
async def list_rooms(
    request: Request,
    participant_id: str | None = None,
    state: str | None = None,
    limit: int = 100,
    x_agent_key: str = Header(default="", alias="X-Agent-Key"),
):
    """List Council Chambers visible to an agent.

    The local agent runtime uses this endpoint instead of an external room
    websocket.  ``participant_id`` keeps each agent scoped to rooms it has
    actually been recruited into.
    """
    _role_or_401(x_agent_key)
    db = request.app.state.db
    limit = max(1, min(limit, 500))

    clauses: list[str] = []
    params: list[Any] = []
    join = ""
    if participant_id:
        join = """
        JOIN proposal_room_participants p
          ON p.room_id = r.room_id AND p.participant_id = ?
        """
        params.append(participant_id)
    if state:
        clauses.append("i.state = ?")
        params.append(state)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = db.execute(
        f"""
        SELECT r.*,
               i.state AS proposal_state,
               COALESCE(MAX(m.id), 0) AS last_sequence
        FROM proposal_rooms r
        LEFT JOIN proposals i ON i.proposal_id = r.proposal_id
        LEFT JOIN proposal_room_messages m ON m.room_id = r.room_id
        {join}
        {where}
        GROUP BY r.room_id
        ORDER BY r.updated_at DESC
        LIMIT ?
        """,
        (*params, limit),
    ).fetchall()

    rooms = []
    for row in rows:
        room = _room_to_response(row)
        room["proposal_state"] = row["proposal_state"]
        room["last_sequence"] = row["last_sequence"]
        rooms.append(room)
    return {"rooms": rooms, "room_count": len(rooms)}
