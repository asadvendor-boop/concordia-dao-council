"""Gateway-owned Council Chamber API.

These routes are the local collaboration substrate for provider-neutral LLM
agents and the deterministic Gateway ledger. They store rooms, participants, and messages in the Gateway ledger.

Room identity v1 (G1 freeze, §12):
    - ``sender_id`` / ``sender_role`` / ``sender_type`` are derived ONLY from
      the authenticated key mapping (role from the agent key, agent id from
      the ``{ROLE}_AGENT_ID`` environment pattern).
    - PRODUCTION BOUNDARY (WP3-7 / Codex addendum item 7): EVERY caller-supplied
      sender/participant identity field is rejected with 400
      ``identity_fields_are_server_derived`` — even one that exactly equals the
      authenticated principal.
    - !! FLAGGED DEV/TEST COMPAT GATE !! Outside production an EXACT match is
      tolerated (conflicts still rejected) because the frozen Codex-owned
      ``shared/proposal_room.py`` ALWAYS transmits ``sender_id`` /
      ``sender_role`` / ``sender_type`` (and ``role`` on add_participant). Those
      exact call sites MUST be migrated to stop sending identity fields before
      production strictness holds end-to-end; recorded in
      ``handoff/INTERFACE_MANIFEST_WP3.md`` as remaining_for_codex. Stored
      identity is ALWAYS server-derived regardless of mode.
    - Agent keys can never emit ``User`` or ``System`` sender types. Human
      approval enters only through the approval boundary (approve_ui calls
      the internal ``store_room_message`` / ``store_room_participant``
      helpers server-side; their signatures are unchanged).
    - Create/join/list/read/post enforce room membership and the frozen
      role-operation matrix. List endpoints are scoped to the authenticated
      caller. Returning an existing room on create additionally requires
      membership (or the creator role's idempotent ``creator_auto_joined``
      re-join) — an existing room is never disclosed merely because the
      caller holds create permission.
    - The legacy GATEWAY_SECRET → ``gateway`` full-ACL fallback is NOT an
      authenticated room principal in ANY environment: every room route
      rejects it as unauthenticated (401), matching the integrated tree where
      gateway/auth.py (Codex-owned) removed the fallback globally, so the
      observable contract is identical pre- and post-merge.
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from gateway.auth import get_role_for_key

router = APIRouter()

_TRUE_VALUES = {"1", "true", "yes", "on"}

# Frozen role-operation matrix (G1 machine schema, room_identity_v1).
# join targets: which registered role each role may add to a member room.
# ``None`` means any registered role (gateway only).
_JOIN_TARGETS: dict[str, set[str] | None] = {
    "gateway": None,
    "recorder": {"triage"},
    "triage": {"diagnosis"},
    "diagnosis": {"safety_reviewer"},
    "safety_reviewer": {"commander"},
    "commander": {"operator"},
    "operator": set(),
}
_CREATE_ROOM_ROLES = {"gateway", "recorder"}
_MATRIX_ROLES = frozenset(_JOIN_TARGETS)

_IDENTITY_REJECTION = {
    "detail": "identity_fields_are_server_derived",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _production_mode() -> bool:
    if os.getenv("CONCORDIA_TEST_MODE", "").strip().lower() in _TRUE_VALUES:
        return False
    return os.getenv("APP_ENV", "").strip().lower() in {"production", "prod"}


def _derived_agent_id(role: str) -> str:
    """Server-side agent identity for a role ({ROLE}_AGENT_ID pattern)."""
    return os.getenv(f"{role.upper()}_AGENT_ID", role) or role


def _agent_id_index() -> tuple[dict[str, str], frozenset[str]]:
    """Deterministic reverse map ``agent_id -> role`` plus collided agent ids.

    Roles are iterated in a stable **sorted** order — never set-iteration
    order (WP3-8). An agent id derived for more than one role is a duplicate /
    ambiguous principal; it is recorded as collided and removed from the index
    so every lookup and every principal resolution for it fails closed instead
    of silently resolving to whichever role set iteration happened to reach
    first. (Rejecting duplicate role *keys* at startup is Codex-owned in
    gateway/auth.py.)
    """
    index: dict[str, str] = {}
    collided: set[str] = set()
    for role in sorted(_MATRIX_ROLES):
        if role == "gateway":
            continue
        agent_id = _derived_agent_id(role)
        existing = index.get(agent_id)
        if existing is not None and existing != role:
            collided.add(agent_id)
        else:
            index[agent_id] = role
    for agent_id in collided:
        index.pop(agent_id, None)
    return index, frozenset(collided)


def _registered_role_for_agent_id(agent_id: str) -> str | None:
    """Unique reverse lookup: registered agent id → matrix role.

    Returns ``None`` for an unknown OR ambiguous (collided) agent id.
    """
    index, _ = _agent_id_index()
    return index.get(agent_id)


def _role_or_401(agent_key: str) -> str:
    role = get_role_for_key(agent_key)
    if not role or role == "gateway":
        # Integrated contract: a caller presenting only the legacy
        # GATEWAY_SECRET full-ACL fallback (the sole source of the
        # ``gateway`` role in gateway/auth.py) is UNAUTHENTICATED for room
        # routes in EVERY environment — the same rejection auth.py issues for
        # missing/invalid credentials. On the integrated tree the fallback is
        # removed globally in gateway/auth.py (Codex-owned); this route-level
        # guard makes the observable contract identical before that merge.
        raise HTTPException(status_code=401, detail="invalid_agent_key")
    return role


def _principal_or_error(agent_key: str) -> tuple[str, str]:
    """Authenticated principal: (role, derived agent id).

    Roles outside the frozen matrix (e.g. ``scribe``) have no room
    operations under room identity v1. A caller whose role derives a duplicated
    (collided) agent id has no unique principal and is refused (WP3-8): identity
    binds the stable authenticated principal, not a set-iteration lookup.
    """
    role = _role_or_401(agent_key)
    if role not in _MATRIX_ROLES:
        raise HTTPException(status_code=403, detail="role_not_permitted")
    agent_id = _derived_agent_id(role)
    if role != "gateway":
        _, collided = _agent_id_index()
        if agent_id in collided:
            raise HTTPException(status_code=403, detail="ambiguous_principal")
    return role, agent_id


def _require_room(db, room_id: str) -> sqlite3.Row:
    room = db.execute(
        "SELECT * FROM proposal_rooms WHERE room_id=?", (room_id,)
    ).fetchone()
    if not room:
        raise HTTPException(status_code=404, detail="room_not_found")
    return room


def _is_member(db, room_id: str, participant_id: str) -> bool:
    row = db.execute(
        "SELECT 1 FROM proposal_room_participants "
        "WHERE room_id=? AND participant_id=?",
        (room_id, participant_id),
    ).fetchone()
    return row is not None


def _require_membership(db, room_id: str, role: str, agent_id: str) -> None:
    """Membership gate with the matrix's gateway bypass."""
    if role == "gateway":
        return
    if not _is_member(db, room_id, agent_id):
        raise HTTPException(status_code=403, detail="not_a_room_member")


_SENDER_IDENTITY_FIELDS = ("sender_id", "sender_role", "sender_type")


def _reject_supplied_sender_identity(body, *, role: str, agent_id: str) -> None:
    """Enforce that message sender identity is exclusively server-derived.

    **Production boundary (WP3-7 / addendum 7):** EVERY caller-supplied identity
    field is rejected — even one that exactly equals the authenticated principal.

    **Dev/test compat gate (flagged, non-production only):** the frozen
    Codex-owned ``shared/proposal_room.py`` ALWAYS transmits
    ``sender_id``/``sender_role``/``sender_type`` (see the module docstring and
    ``handoff/INTERFACE_MANIFEST_WP3.md`` — those exact call sites must be
    migrated to stop sending identity fields before production strictness can
    hold end-to-end). Until then, outside production an EXACT match is tolerated
    while any conflict is still rejected. Stored identity is ALWAYS derived.
    """
    supplied = {f for f in _SENDER_IDENTITY_FIELDS if f in body.model_fields_set}
    if _production_mode():
        if supplied:
            raise HTTPException(status_code=400, **_IDENTITY_REJECTION)
        return
    # Non-production compat gate: tolerate exact match, reject any conflict.
    if body.sender_type != "Agent":
        raise HTTPException(status_code=400, **_IDENTITY_REJECTION)
    if body.sender_id is not None and body.sender_id != agent_id:
        raise HTTPException(status_code=400, **_IDENTITY_REJECTION)
    if body.sender_role is not None and body.sender_role != role:
        raise HTTPException(status_code=400, **_IDENTITY_REJECTION)


class CreateRoomRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    proposal_id: str | None = Field(default=None, max_length=120)


class ParticipantRequest(BaseModel):
    participant_id: str = Field(min_length=1, max_length=120)
    # ``role`` is accepted for wire compatibility but IGNORED: the
    # participant role is derived from the registered agent id (room
    # identity v1 — caller-supplied identity fields are ignored/rejected).
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
    """Insert or update an proposal-room participant.

    Internal server-side helper — signature unchanged (approve_ui and the
    nonce publication path call this directly with server-derived identity).
    """
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
    """Append a message to a Gateway-owned Council Chamber.

    Internal server-side helper — signature unchanged. The trusted human
    approval boundary (approve_ui) publishes through this path with
    server-derived identity; the HTTP route derives identity from the
    authenticated key before calling it.
    """
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
    role, agent_id = _principal_or_error(x_agent_key)
    if role not in _CREATE_ROOM_ROLES:
        raise HTTPException(status_code=403, detail="role_not_permitted")

    db = request.app.state.db
    now = _now()

    existing = None
    if body.proposal_id:
        existing = db.execute(
            "SELECT * FROM proposal_rooms WHERE proposal_id=?",
            (body.proposal_id,),
        ).fetchone()
    if existing:
        # Re-audit item 3: an existing room is returned on create ONLY under
        # the frozen matrix's read/join rights — never merely because the
        # caller holds create permission. A current member reads its own
        # room; the room's creator ROLE is atomically (re)joined per the
        # frozen create_room contract (``creator_auto_joined``) — the
        # idempotent re-create path. Every other caller receives the standard
        # membership rejection and learns nothing further about the room.
        existing_room_id = existing["room_id"]
        if not _is_member(db, existing_room_id, agent_id):
            if existing["created_by"] != role:
                raise HTTPException(status_code=403, detail="not_a_room_member")
            # Idempotent completion of creator_auto_joined: atomically
            # restore the creator's server-derived identity as a participant.
            try:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    """
                    INSERT INTO proposal_room_participants
                    (room_id, participant_id, role, display_name, joined_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(room_id, participant_id) DO UPDATE SET
                        role=excluded.role
                    """,
                    (existing_room_id, agent_id, role, None, now),
                )
                db.commit()
            except Exception:
                db.rollback()
                raise
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
        # creator_auto_joined (frozen create_room contract) — the creator's
        # derived identity becomes a participant atomically.
        db.execute(
            """
            INSERT INTO proposal_room_participants
            (room_id, participant_id, role, display_name, joined_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(room_id, participant_id) DO UPDATE SET
                role=excluded.role
            """,
            (room_id, agent_id, role, None, now),
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
    role, agent_id = _principal_or_error(x_agent_key)
    db = request.app.state.db
    _require_room(db, room_id)

    # Requester must be a room member unless gateway (frozen join contract).
    _require_membership(db, room_id, role, agent_id)

    # The participant role is a server-derived identity field. On the production
    # boundary a caller-supplied ``role`` is rejected (WP3-7). Outside production
    # it is ignored (documented compat gate — the recorder sends role=agent_id
    # junk on every add_participant; see the module docstring / interface
    # manifest for the exact Codex-owned call site to migrate).
    if _production_mode() and "role" in body.model_fields_set:
        raise HTTPException(status_code=400, **_IDENTITY_REJECTION)

    # Idempotent re-join: adding an existing member grants nothing new.
    existing = db.execute(
        "SELECT participant_id, role, display_name FROM proposal_room_participants "
        "WHERE room_id=? AND participant_id=?",
        (room_id, body.participant_id),
    ).fetchone()
    if existing:
        return {
            "status": "joined",
            "room_id": room_id,
            "participant": {
                "participant_id": existing["participant_id"],
                "role": existing["role"],
                "display_name": existing["display_name"],
            },
        }

    # participant_role is derived from the registered agent id (unique reverse
    # lookup). A collided/ambiguous id fails closed rather than resolving to an
    # arbitrary role (WP3-8).
    _index, _collided = _agent_id_index()
    if body.participant_id in _collided:
        raise HTTPException(status_code=400, detail="ambiguous_participant")
    target_role = _registered_role_for_agent_id(body.participant_id)
    if target_role is None:
        raise HTTPException(status_code=400, detail="unknown_participant")

    allowed_targets = _JOIN_TARGETS[role]
    if allowed_targets is not None and target_role not in allowed_targets:
        raise HTTPException(status_code=403, detail="join_target_not_permitted")

    participant = store_room_participant(
        db,
        room_id,
        body.participant_id,
        role=target_role,
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
    role, agent_id = _principal_or_error(x_agent_key)

    # The legacy gateway-secret fallback never reaches this point: it is
    # rejected as unauthenticated (401) for every room route in every
    # environment inside _role_or_401 (integrated-tree contract).

    # Identity is server-derived; agent keys can never emit User/System.
    _reject_supplied_sender_identity(body, role=role, agent_id=agent_id)

    db = request.app.state.db
    _require_room(db, room_id)
    _require_membership(db, room_id, role, agent_id)

    message = store_room_message(
        db,
        room_id,
        body.content,
        sender_id=agent_id,
        sender_role=role,
        sender_type="Agent",
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
    role, agent_id = _principal_or_error(x_agent_key)
    db = request.app.state.db
    _require_room(db, room_id)
    _require_membership(db, room_id, role, agent_id)

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
    """List Council Chambers visible to the AUTHENTICATED caller.

    Non-gateway results are always scoped to the caller's own membership
    (room identity v1): a caller-selected foreign ``participant_id`` is
    rejected, so one agent can never enumerate another agent's rooms.
    """
    role, agent_id = _principal_or_error(x_agent_key)
    db = request.app.state.db
    limit = max(1, min(limit, 500))

    clauses: list[str] = []
    params: list[Any] = []
    join = ""
    if role == "gateway":
        # Gateway service scope (matrix list_rooms) — optional filter allowed.
        if participant_id:
            join = """
            JOIN proposal_room_participants p
              ON p.room_id = r.room_id AND p.participant_id = ?
            """
            params.append(participant_id)
    else:
        if participant_id and participant_id != agent_id:
            raise HTTPException(status_code=400, **_IDENTITY_REJECTION)
        join = """
        JOIN proposal_room_participants p
          ON p.room_id = r.room_id AND p.participant_id = ?
        """
        params.append(agent_id)
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
