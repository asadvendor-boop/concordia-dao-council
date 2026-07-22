"""Read-only exact-preimage export for Concordia's sealed card chain."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
from collections.abc import Mapping
from datetime import datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit


SCHEMA_VERSION = "concordia.card_chain.v1"
ROOTS_SCHEMA_VERSION = "concordia.card_chain_roots.v1"
MAX_CARD_COUNT = 256
MAX_TOTAL_PREIMAGE_BYTES = 8 * 1024 * 1024
# The limited SQL CTE returns at most MAX_CARD_COUNT + 1 rows.  This quotient
# therefore makes the maximum card_json materialized by SQLite no larger than
# the total artifact budget, even for the one overflow row used to detect an
# excessive card count.
MAX_CARD_JSON_BYTES = MAX_TOTAL_PREIMAGE_BYTES // (MAX_CARD_COUNT + 1)
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_ROOTS_FILE_BYTES = 64 * 1024
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_PROPOSAL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_URL_CONTROL_OR_SPACE_RE = re.compile(r"[\x00-\x20\x7f]")
_RFC3339_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$"
)
_PUBLISHED_AT_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:Z|\+00:00)$"
)
_SECRET_KEY_SUBSTRINGS = (
    "authorization",
    "api_key",
    "apikey",
    "access_token",
    "auth_token",
    "bearer",
    "client_secret",
    "credential",
    "docker_secret",
    "env_var",
    "environment_variable",
    "jwt",
    "llm_api_key",
    "openai",
    "passphrase",
    "passwd",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "session_token",
    "token",
    "wallet_secret",
)
_SECRET_EXACT_FIELD_NAMES = frozenset({"key"})
_PUBLIC_SECRETISH_FIELD_WHITELIST = frozenset(
    {
        "authorization_id",
        # Frozen CasperExecutionReceipt schema: public enum, never a credential.
        "authorization_type",
        "token_usage",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
    }
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"(?i)\b(sk|pk|ak|eyJ)[A-Za-z0-9._~+/=-]{16,}"),
    re.compile(r"/(?:opt|etc|home|Users)/[^\s\"']*(?:secret|key|env|pem)[^\s\"']*", re.I),
)
_HISTORICAL_IDENTITY_FIELD = {
    "ProposalCard": "signal_id",
    "TriageDecision": "proposal_id",
    "Assessment": "proposal_id",
    "Verdict": "proposal_id",
    "ResponsePlan": "proposal_id",
    "StructuredApproval": "proposal_id",
    "PolicyAuthorization": "proposal_id",
    "CasperExecutionReceipt": "proposal_id",
    "GovernanceSummary": "proposal_id",
}


class CardChainArtifactError(ValueError):
    """Stored card-chain rows cannot be published as an exact artifact."""


class CardChainNotFound(CardChainArtifactError):
    """The requested proposal does not exist."""


class CardChainRootsError(CardChainArtifactError):
    """The immutable release-root configuration is absent or malformed."""


class _DuplicateJsonKey(ValueError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def load_card_chain_release_roots(path_value: object) -> Mapping[str, str]:
    """Load a bounded, strict root mapping once for immutable process use."""

    if type(path_value) is not str or not path_value.strip():
        raise CardChainRootsError("card-chain roots file is not configured")
    path = Path(path_value)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CardChainRootsError("card-chain roots file is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise CardChainRootsError("card-chain roots file must be a regular file")
        if metadata.st_size > MAX_ROOTS_FILE_BYTES:
            raise CardChainRootsError("card-chain roots file exceeds size limit")
        chunks: list[bytes] = []
        remaining = MAX_ROOTS_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except OSError as exc:
        raise CardChainRootsError("card-chain roots file is unreadable") from exc
    finally:
        os.close(descriptor)
    if len(raw) > MAX_ROOTS_FILE_BYTES:
        raise CardChainRootsError("card-chain roots file exceeds size limit")
    try:
        text = raw.decode("utf-8")
        document = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CardChainRootsError("card-chain roots file is invalid JSON") from exc
    if type(document) is not dict or set(document) != {"schema_version", "roots"}:
        raise CardChainRootsError("card-chain roots file has invalid shape")
    if document.get("schema_version") != ROOTS_SCHEMA_VERSION:
        raise CardChainRootsError("card-chain roots schema_version is invalid")
    raw_roots = document.get("roots")
    if type(raw_roots) is not dict or len(raw_roots) > MAX_CARD_COUNT:
        raise CardChainRootsError("card-chain roots mapping is invalid")
    roots: dict[str, str] = {}
    for proposal_id, final_card_hash in raw_roots.items():
        if _PROPOSAL_ID_RE.fullmatch(proposal_id) is None:
            raise CardChainRootsError("card-chain root proposal_id is invalid")
        if type(final_card_hash) is not str or _HEX32_RE.fullmatch(final_card_hash) is None:
            raise CardChainRootsError("card-chain final root is invalid")
        roots[proposal_id] = final_card_hash
    return MappingProxyType(roots)


def _parse_preimage(raw: object, sequence_number: int) -> tuple[str, dict[str, Any]]:
    if type(raw) is not str:
        raise CardChainArtifactError(f"card {sequence_number}: card_json must be text")
    try:
        encoded = raw.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CardChainArtifactError(
            f"card {sequence_number}: card_json is not valid UTF-8"
        ) from exc
    if len(encoded) > MAX_CARD_JSON_BYTES:
        raise CardChainArtifactError(f"card {sequence_number}: card_json size limit exceeded")
    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateJsonKey as exc:
        raise CardChainArtifactError(f"card {sequence_number}: {exc}") from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise CardChainArtifactError(
            f"card {sequence_number}: canonical_card_json is invalid JSON"
        ) from exc
    if type(parsed) is not dict:
        raise CardChainArtifactError(
            f"card {sequence_number}: canonical_card_json must contain a JSON object"
        )
    return encoded.decode("utf-8"), parsed


def _secret_scan_findings(value: object, path: str = "$") -> list[str]:
    findings: list[str] = []
    if type(value) is dict:
        for key, raw in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            child = f"{path}.{key}"
            secretish_name = normalized in _SECRET_EXACT_FIELD_NAMES or any(
                pattern in normalized for pattern in _SECRET_KEY_SUBSTRINGS
            )
            if (
                normalized not in _PUBLIC_SECRETISH_FIELD_WHITELIST
                and secretish_name
                and raw not in (None, "[REDACTED]")
            ):
                findings.append(f"{child}: secret-like key")
            findings.extend(_secret_scan_findings(raw, child))
    elif type(value) is list:
        for index, item in enumerate(value):
            findings.extend(_secret_scan_findings(item, f"{path}[{index}]"))
    elif type(value) is str:
        if any(pattern.search(value) for pattern in _SECRET_VALUE_PATTERNS):
            findings.append(f"{path}: secret-like value")
    return findings


def _require_rfc3339_utc(value: object, label: str, *, published: bool = False) -> str:
    pattern = _PUBLISHED_AT_RE if published else _RFC3339_UTC_RE
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise CardChainArtifactError(f"{label} must be RFC3339 UTC")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise CardChainArtifactError(f"{label} must be RFC3339 UTC") from exc
    if parsed.utcoffset() != timedelta(0):
        raise CardChainArtifactError(f"{label} must be RFC3339 UTC")
    return value


def _validate_public_metadata(
    *,
    proposal_id: object,
    captured_at: object,
    source_url: object,
) -> tuple[str, str, str]:
    if type(proposal_id) is not str or _PROPOSAL_ID_RE.fullmatch(proposal_id) is None:
        raise CardChainArtifactError("proposal_id is invalid")
    captured = _require_rfc3339_utc(captured_at, "captured_at")
    if type(source_url) is not str:
        raise CardChainArtifactError("source_url is invalid")
    if _URL_CONTROL_OR_SPACE_RE.search(source_url):
        raise CardChainArtifactError("source_url is invalid")
    try:
        source_url_bytes = source_url.encode("utf-8")
        parsed = urlsplit(source_url)
        port = parsed.port
    except (UnicodeEncodeError, ValueError) as exc:
        raise CardChainArtifactError("source_url is invalid") from exc
    if len(source_url_bytes) > 2048:
        raise CardChainArtifactError("source_url is invalid")
    host = parsed.hostname
    if (
        host is None
        or host != host.lower()
        or len(host) > 253
        or any(_DNS_LABEL_RE.fullmatch(label) is None for label in host.split("."))
        or port is not None and not 1 <= port <= 65535
    ):
        raise CardChainArtifactError("source_url is invalid")
    canonical_netloc = host if port is None else f"{host}:{port}"
    expected_path = f"/proof-artifacts/v1/{proposal_id}/card-chain"
    if (
        parsed.scheme != "https"
        or parsed.netloc != canonical_netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != expected_path
    ):
        raise CardChainArtifactError("source_url is invalid")
    return proposal_id, captured, source_url


def _validate_row(
    row: sqlite3.Row,
    *,
    proposal_id: str,
    expected_sequence: int,
    expected_previous_hash: str | None,
) -> dict[str, object]:
    sequence_number = row["sequence_number"]
    if type(sequence_number) is not int or sequence_number != expected_sequence:
        raise CardChainArtifactError(
            f"card chain sequence must be contiguous at {expected_sequence}"
        )
    card_type = row["card_type"]
    if type(card_type) is not str or not card_type:
        raise CardChainArtifactError(f"card {sequence_number}: card_type is invalid")
    card_hash = row["card_hash"]
    if type(card_hash) is not str or _HEX32_RE.fullmatch(card_hash) is None:
        raise CardChainArtifactError(f"card {sequence_number}: card_hash is invalid")
    canonical_card_json, parsed = _parse_preimage(row["card_json"], sequence_number)
    recomputed = hashlib.sha256(canonical_card_json.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(recomputed, card_hash):
        raise CardChainArtifactError(f"card {sequence_number}: card_hash mismatch")
    if "card_hash" in parsed:
        raise CardChainArtifactError(
            f"card {sequence_number}: canonical_card_json must exclude card_hash"
        )
    if type(parsed.get("sequence_number")) is not int or parsed["sequence_number"] != sequence_number:
        raise CardChainArtifactError(
            f"card {sequence_number}: sequence_number does not match wrapper"
        )
    if parsed.get("card_type") != card_type:
        raise CardChainArtifactError(f"card {sequence_number}: card_type does not match wrapper")
    if expected_sequence == 1 and card_type != "ProposalCard":
        raise CardChainArtifactError("card 1 must be ProposalCard")
    if expected_sequence > 1 and card_type == "ProposalCard":
        raise CardChainArtifactError("only card 1 may be ProposalCard")
    identity_field = _HISTORICAL_IDENTITY_FIELD.get(card_type)
    if identity_field is None:
        raise CardChainArtifactError(
            f"card {sequence_number}: card_type has no frozen proposal identity schema"
        )
    if parsed.get(identity_field) != proposal_id:
        raise CardChainArtifactError(
            f"card {sequence_number}: proposal identity does not match artifact"
        )
    if "previous_card_hash" not in parsed:
        raise CardChainArtifactError(
            f"card {sequence_number}: previous_card_hash is missing"
        )
    previous_hash = parsed["previous_card_hash"]
    if previous_hash != expected_previous_hash:
        raise CardChainArtifactError(
            f"card {sequence_number}: previous_card_hash does not match prior card"
        )
    published_at = row["published_at"]
    if published_at is not None and type(published_at) is not str:
        raise CardChainArtifactError(f"card {sequence_number}: published_at is invalid")
    if published_at is not None:
        _require_rfc3339_utc(published_at, f"card {sequence_number}: published_at", published=True)
    if _secret_scan_findings(parsed):
        raise CardChainArtifactError(
            f"card {sequence_number}: exact preimage contains secret-like material"
        )
    return {
        "sequence_number": sequence_number,
        "card_type": card_type,
        "card_hash": card_hash,
        "canonical_card_json": canonical_card_json,
        "published_at": published_at,
    }


def _read_rows(db: sqlite3.Connection, proposal_id: str) -> list[sqlite3.Row]:
    db.execute("BEGIN DEFERRED")
    try:
        cursor = db.execute(
            "WITH limited_cards AS MATERIALIZED ("
            "SELECT sequence_number, card_type, card_hash, "
            "CASE WHEN length(CAST(card_json AS BLOB)) <= ? "
            "THEN card_json ELSE NULL END AS card_json, published_at, "
            "length(CAST(card_json AS BLOB)) AS card_json_bytes "
            "FROM cards WHERE proposal_id=? "
            "ORDER BY sequence_number ASC LIMIT ?"
            ") "
            "SELECT p.proposal_id AS known_proposal_id, c.sequence_number, "
            "c.card_type, c.card_hash, c.card_json, c.published_at, "
            "c.card_json_bytes "
            "FROM proposals AS p LEFT JOIN limited_cards AS c ON 1=1 "
            "WHERE p.proposal_id=? ORDER BY c.sequence_number ASC",
            (
                MAX_CARD_JSON_BYTES,
                proposal_id,
                MAX_CARD_COUNT + 1,
                proposal_id,
            ),
        )
        rows: list[sqlite3.Row] = []
        cumulative_bytes = 0
        for row in cursor:
            if row["sequence_number"] is not None:
                card_bytes = row["card_json_bytes"]
                if type(card_bytes) is not int or card_bytes > MAX_CARD_JSON_BYTES:
                    raise CardChainArtifactError(
                        f"card {row['sequence_number']}: card_json size limit exceeded"
                    )
                cumulative_bytes += card_bytes
                if cumulative_bytes > MAX_TOTAL_PREIMAGE_BYTES:
                    raise CardChainArtifactError("total card_json size limit exceeded")
                if row["card_json"] is None:
                    raise CardChainArtifactError(
                        f"card {row['sequence_number']}: bounded card_json unavailable"
                    )
            rows.append(row)
        db.execute("COMMIT")
        return rows
    except Exception:
        db.execute("ROLLBACK")
        raise


def build_card_chain_artifact(
    db: sqlite3.Connection,
    *,
    proposal_id: str,
    captured_at: str,
    source_url: str,
    expected_final_card_hash: str,
) -> dict[str, object]:
    """Return exact stored card preimages without parsing or reserializing them."""

    proposal_id, captured_at, source_url = _validate_public_metadata(
        proposal_id=proposal_id,
        captured_at=captured_at,
        source_url=source_url,
    )
    rows = _read_rows(db, proposal_id)
    if not rows:
        raise CardChainNotFound("proposal not found")
    if (
        type(expected_final_card_hash) is not str
        or _HEX32_RE.fullmatch(expected_final_card_hash) is None
    ):
        raise CardChainArtifactError("expected_final_card_hash is invalid")
    card_rows = [row for row in rows if row["sequence_number"] is not None]
    if not card_rows:
        raise CardChainArtifactError("card chain must be non-empty")
    if len(card_rows) > MAX_CARD_COUNT:
        raise CardChainArtifactError("card-count limit exceeded")
    cards: list[dict[str, object]] = []
    previous_hash: str | None = None
    total_preimage_bytes = 0
    for expected_sequence, row in enumerate(card_rows, start=1):
        card = _validate_row(
            row,
            proposal_id=proposal_id,
            expected_sequence=expected_sequence,
            expected_previous_hash=previous_hash,
        )
        total_preimage_bytes += len(str(card["canonical_card_json"]).encode("utf-8"))
        if total_preimage_bytes > MAX_TOTAL_PREIMAGE_BYTES:
            raise CardChainArtifactError("total card_json size limit exceeded")
        cards.append(card)
        previous_hash = str(card["card_hash"])
    if not hmac.compare_digest(previous_hash or "", expected_final_card_hash):
        raise CardChainArtifactError("expected_final_card_hash does not match terminal card")
    artifact: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "proposal_id": proposal_id,
        "captured_at": captured_at,
        "source_url": source_url,
        "cards": cards,
    }
    response_bytes = json.dumps(
        artifact,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(response_bytes) > MAX_RESPONSE_BYTES:
        raise CardChainArtifactError("artifact response-size limit exceeded")
    return artifact
