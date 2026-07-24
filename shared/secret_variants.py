"""Shared, bounded secret-key normalization and reversible canary encodings."""

from __future__ import annotations

import base64
import re


def normalize_sensitive_key(value: str) -> str:
    """Normalize snake, kebab, dotted, spaced, and camel-case key spellings."""

    if not isinstance(value, str):
        raise TypeError("sensitive key must be text")
    return re.sub(r"[^a-z0-9]", "", value.lower())


def secret_variants(raw: bytes) -> tuple[bytes, ...]:
    """Return the closed set of reversible encodings scanned at release gates."""

    if not isinstance(raw, bytes):
        raise TypeError("secret canary must be bytes")
    if not raw:
        return ()
    standard = base64.b64encode(raw)
    urlsafe = base64.urlsafe_b64encode(raw)
    candidates = (
        raw,
        standard,
        standard.rstrip(b"="),
        urlsafe,
        urlsafe.rstrip(b"="),
        raw.hex().encode("ascii"),
        raw.hex().upper().encode("ascii"),
        b"".join(f"%{value:02X}".encode("ascii") for value in raw),
    )
    return tuple(dict.fromkeys(candidate for candidate in candidates if candidate))
