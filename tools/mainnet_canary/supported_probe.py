"""Redacting helper for the CSPR.cloud ``/supported`` probe.

Upstream pin (Telegram addendum): CSPR.cloud authenticates with the RAW
token as the ``Authorization`` header value — never the ``Bearer`` scheme.
A bearer-prefixed value would both fail upstream and normalise a wrong
convention into our tooling, so it refuses.

Failed authenticated probes may reflect the submitted authorization text in
their response bodies; this helper therefore NEVER emits body text.  A probe
observation carries only: the endpoint host, the status code, the body's
SHA-256 (omitted entirely for failed authenticated probes), and scalar
fields extracted through a strict allowlist.

This module never reads token material from disk and performs no network
I/O; the future live lane passes the mounted token in and captures the
response bytes out-of-band.
"""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit

from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode

PROBE_OBSERVATION_SCHEMA_ID = "concordia.mainnet-canary.supported-probe.v1"

_TOKEN = re.compile(r"[!-~]+\Z")  # printable ASCII, no whitespace of any kind

# Scalar response fields that may appear in sanitized form.  Everything else
# (free text, nested objects, arrays) is dropped; only the hash remains.
_ALLOWLISTED_FIELDS = {
    "supported": bool,
    "network": str,
    "asset_contract": str,
    "chain_name": str,
    "api_version": str,
}
_SAFE_STRING = re.compile(r"[a-z0-9:_\-\.]{1,80}\Z")


def build_authorization_header(token: str) -> dict[str, str]:
    """The raw token as the header value — the bearer scheme is refused."""

    if not isinstance(token, str) or not token or _TOKEN.match(token) is None:
        raise CanaryRefusal(
            RefusalCode.PROBE_HEADER_INVALID,
            "token must be a single-line printable value with no whitespace",
        )
    if token.lower().startswith("bearer"):
        raise CanaryRefusal(
            RefusalCode.PROBE_HEADER_INVALID,
            "CSPR.cloud authenticates with the raw token — never the Bearer "
            "scheme; refusing a bearer-prefixed value",
        )
    return {"Authorization": token}


def redact_probe_observation(
    *,
    url: str,
    status_code: int,
    body_bytes: bytes,
    authenticated: bool,
) -> dict[str, object]:
    """A probe record safe to persist: hashes and allowlisted scalars only."""

    host = urlsplit(url).hostname or ""
    record: dict[str, object] = {
        "schema_id": PROBE_OBSERVATION_SCHEMA_ID,
        "endpoint_host": host,
        "status_code": int(status_code),
        "authenticated": bool(authenticated),
        "body_sha256": None,
        "body_bytes_len": len(body_bytes),
        "body_disposition": "HASHED",
        "sanitized_fields": {},
    }
    if authenticated and status_code != 200:
        # A failed authenticated response may reflect the submitted
        # authorization text: neither its bytes nor its hash leave here.
        record["body_disposition"] = "REDACTED_FAILED_AUTHENTICATED_PROBE"
        record["body_bytes_len"] = 0
        return record
    record["body_sha256"] = hashlib.sha256(body_bytes).hexdigest()
    try:
        document = json.loads(body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        record["body_disposition"] = "HASHED_NON_JSON"
        return record
    if isinstance(document, dict):
        sanitized: dict[str, object] = {}
        for field, expected_type in _ALLOWLISTED_FIELDS.items():
            value = document.get(field)
            if expected_type is bool and isinstance(value, bool):
                sanitized[field] = value
            elif (
                expected_type is str
                and isinstance(value, str)
                and _SAFE_STRING.match(value) is not None
            ):
                sanitized[field] = value
        record["sanitized_fields"] = sanitized
    return record
