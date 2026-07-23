"""Fail-closed secret detection and secret-path refusal.

The canary tooling must never read, copy, enumerate, or test private keys or
secrets.  This module enforces two rules:

1. Any operator-supplied document (key inventory, RC declaration, ceiling,
   authorization) is scanned for key-like material before use.  A match
   refuses the whole document; the matched content itself is NEVER echoed —
   only the pattern name appears in the refusal detail.
2. Paths under secret mounts are refused before any ``open`` can happen.
"""

from __future__ import annotations

import re
from pathlib import Path

from tools.mainnet_canary.constants import SECRET_KEY_MOUNT_PREFIX
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode

# Pattern names are stable identifiers; refusal details reference only these
# names, never the matched text.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "pem_private_key_block",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    ),
    ("putty_private_key", re.compile(r"PuTTY-User-Key-File")),
    ("openssh_private_key", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----")),
    (
        "labelled_secret_hex",
        re.compile(
            r"(?i)\b(?:secret|private)[_ -]?key\b[^0-9a-f]{0,16}[0-9a-fA-F]{48,}"
        ),
    ),
    (
        "labelled_secret_value",
        re.compile(r"(?i)\b(?:secret_key|private_key|seed_phrase|mnemonic)\b"),
    ),
    ("authorization_header", re.compile(r"(?i)\bauthorization\s*:\s*\S")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}")),
)


def scan_for_secret_material(text: str) -> tuple[str, ...]:
    """Return the stable names of every secret-like pattern found."""

    return tuple(name for name, pattern in _SECRET_PATTERNS if pattern.search(text))


def refuse_if_secret_material(text: str, *, context: str) -> None:
    """Refuse fail-closed when a document contains key-like material.

    The refusal detail contains only the pattern names and the caller-supplied
    context label — never any part of the matched content.
    """

    matches = scan_for_secret_material(text)
    if matches:
        raise CanaryRefusal(
            RefusalCode.KEY_INVENTORY_SECRET_MATERIAL,
            f"{context}: secret-like material detected "
            f"(patterns: {', '.join(matches)}); content withheld",
        )


def refuse_secret_path(path: str | Path, *, context: str) -> None:
    """Refuse any attempt to read below a secret mount or a key file."""

    text = str(path)
    lowered = text.lower()
    if (
        text.startswith(SECRET_KEY_MOUNT_PREFIX)
        or text.startswith("/run/secrets/")
        or lowered.endswith((".pem", ".sk", ".secret", "secret_key.txt"))
    ):
        raise CanaryRefusal(
            RefusalCode.SECRET_PATH_READ_REFUSED,
            f"{context}: refusing to read a secret path; "
            "this lane never opens key files",
        )


def require_secret_mount_reference(path_value: str, *, field: str) -> str:
    """Validate that a key-file REFERENCE points below the secret mount.

    The reference is recorded verbatim for the future live lane; the file is
    never opened here.
    """

    if not isinstance(path_value, str) or not path_value.startswith(
        SECRET_KEY_MOUNT_PREFIX
    ):
        raise CanaryRefusal(
            RefusalCode.KEY_INVENTORY_INVALID,
            f"{field}: key-file mount reference must sit below "
            f"{SECRET_KEY_MOUNT_PREFIX}",
        )
    return path_value
