"""Current public URL configuration shared by generated Concordia links."""

from __future__ import annotations

import os


DEFAULT_PUBLIC_BASE_URL = "https://concordiadao.xyz"


def get_public_base_url() -> str:
    """Return the configured public base without a trailing slash.

    ``PUBLIC_BASE_URL`` is authoritative. The older public-base and hostname
    variables remain supported so existing runtime configuration keeps working.
    """

    for name in ("PUBLIC_BASE_URL", "CONCORDIA_PUBLIC_BASE_URL"):
        configured = os.getenv(name, "").strip().rstrip("/")
        if configured:
            return configured

    hostname = os.getenv("CONCORDIA_HOSTNAME", "").strip().rstrip("/")
    if hostname:
        if hostname.startswith(("http://", "https://")):
            return hostname
        return f"https://{hostname}"

    return DEFAULT_PUBLIC_BASE_URL
