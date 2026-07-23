"""Exact, self-verifying JSON serialization for ``pycspr`` deploys.

``pycspr==1.2.0`` formats timestamps by slicing the result of
``datetime.isoformat()``.  Python omits the fractional component at an exact
whole second, so that slice also removes the seconds and changes the deploy
header on a JSON round-trip.  This adapter writes the timestamp from the
already-hashed deploy as explicit UTC milliseconds, then proves the JSON still
decodes to the exact original bytes and hashes before it can leave Concordia.
"""

from __future__ import annotations

import copy
import math
import re
from datetime import UTC, datetime
from typing import Any, Mapping, Sequence

from pycspr import serializer
from pycspr.factory.digests import (
    create_digest_of_deploy,
    create_digest_of_deploy_body,
)
from pycspr.types.node.rpc import Deploy


class ExactDeployJsonError(ValueError):
    """A deploy cannot be represented as hash-preserving Casper RPC JSON."""


_HEX_RE = re.compile(r"[0-9a-fA-F]+")


def _exact_timestamp(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ExactDeployJsonError("deploy timestamp must be a finite number")
    numeric = float(value)
    if not math.isfinite(numeric):
        raise ExactDeployJsonError("deploy timestamp must be a finite number")
    milliseconds = round(numeric * 1000)
    try:
        moment = datetime.fromtimestamp(milliseconds / 1000, tz=UTC)
    except (OverflowError, OSError, ValueError):
        raise ExactDeployJsonError("deploy timestamp is outside UTC range") from None
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _normalized_timestamp_text(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        return value
    return _exact_timestamp(parsed.timestamp())


def normalize_deploy_rpc_json(value: object) -> object:
    """Normalize semantically identical deploy JSON for strict comparison."""

    if isinstance(value, Mapping):
        normalized: dict[str, object] = {}
        for key, item in value.items():
            name = str(key)
            normalized[name] = (
                _normalized_timestamp_text(item)
                if name == "timestamp" and isinstance(item, str)
                else normalize_deploy_rpc_json(item)
            )
        return normalized
    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        return [normalize_deploy_rpc_json(item) for item in value]
    if (
        isinstance(value, str)
        and len(value) % 2 == 0
        and _HEX_RE.fullmatch(value) is not None
    ):
        return value.lower()
    return value


def canonical_deploy_rpc_json(deploy: Deploy) -> dict[str, Any]:
    """Serialize a decoded deploy with an unambiguous millisecond timestamp."""

    if not isinstance(deploy, Deploy):
        raise ExactDeployJsonError("deploy must be a pycspr Deploy")
    value = serializer.to_json(deploy)
    value["header"]["timestamp"] = _exact_timestamp(
        deploy.header.timestamp.value
    )
    return value


def exact_deploy_rpc_json(deploy: Deploy) -> dict[str, Any]:
    """Return outbound RPC JSON only after an exact bytes-and-hashes round-trip."""

    expected_body_hash = create_digest_of_deploy_body(
        deploy.payment,
        deploy.session,
    )
    expected_deploy_hash = create_digest_of_deploy(deploy.header)
    if deploy.header.body_hash != expected_body_hash:
        raise ExactDeployJsonError("deploy body hash differs from exact bytes")
    if deploy.hash != expected_deploy_hash:
        raise ExactDeployJsonError("deploy hash differs from exact header bytes")

    value = canonical_deploy_rpc_json(deploy)
    try:
        decoded = serializer.from_json(copy.deepcopy(value), Deploy)
    except ExactDeployJsonError:
        raise
    except Exception:
        raise ExactDeployJsonError(
            "deploy JSON cannot be decoded canonically"
        ) from None

    if serializer.to_bytes(decoded) != serializer.to_bytes(deploy):
        raise ExactDeployJsonError(
            "deploy JSON round-trip differs from exact deploy bytes"
        )
    if decoded.header.body_hash != create_digest_of_deploy_body(
        decoded.payment,
        decoded.session,
    ):
        raise ExactDeployJsonError(
            "decoded deploy body hash differs from exact bytes"
        )
    if decoded.hash != create_digest_of_deploy(decoded.header):
        raise ExactDeployJsonError(
            "decoded deploy hash differs from exact header bytes"
        )
    return value
