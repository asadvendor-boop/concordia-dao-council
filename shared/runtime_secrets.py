"""Runtime secret helpers for env-var and Docker-secret deployments."""
from __future__ import annotations

import os
from pathlib import Path


def read_secret(name: str) -> str:
    """Return a secret from NAME or NAME_FILE, trimming surrounding whitespace."""
    value = os.getenv(name, "").strip()
    if value:
        return value
    file_path = os.getenv(f"{name}_FILE", "").strip()
    if not file_path:
        return ""
    try:
        return Path(file_path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def read_secret_file_only(name: str) -> str:
    """Return a secret only through NAME_FILE, ignoring direct env values."""

    file_path = os.getenv(f"{name}_FILE", "").strip()
    if not file_path:
        return ""
    try:
        return Path(file_path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""
