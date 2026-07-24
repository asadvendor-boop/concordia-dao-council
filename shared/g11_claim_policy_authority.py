"""Independent authority for the release-specific G11 claim-policy digest."""

from __future__ import annotations

import re

from shared.release_gate_contract import (
    G11_CLAIM_POLICY_AUTHORITY_SCHEMA_VERSION,
    G11_CLAIM_POLICY_PATH,
)

AUTHORITY_SCHEMA_VERSION = G11_CLAIM_POLICY_AUTHORITY_SCHEMA_VERSION
POLICY_PATH = G11_CLAIM_POLICY_PATH

# This remains fail-closed until the independently reviewed policy is committed.
# The authority is intentionally separate from the stable command contract so
# approving release copy cannot invalidate the G2/G9 runner contract.
G11_CLAIM_POLICY_SHA256 = "0" * 64

_LOWER_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def approved_policy_sha256() -> str:
    """Return the approved policy digest, rejecting placeholders or drift."""

    value = G11_CLAIM_POLICY_SHA256
    if (
        not isinstance(value, str)
        or _LOWER_SHA256.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise ValueError("no independently approved G11 policy digest")
    return value
