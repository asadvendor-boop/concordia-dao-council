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

from pycspr import crypto, serializer
from pycspr.factory.digests import (
    create_digest_of_deploy,
    create_digest_of_deploy_body,
)
from pycspr.types.cl import (
    CLT_Type_U32,
    CLV_ByteArray,
    CLV_Option,
    CLV_String,
    CLV_U32,
)
from pycspr.types.node.rpc import (
    Deploy,
    DeployOfStoredContractByHashVersioned,
)


class ExactDeployJsonError(ValueError):
    """A deploy cannot be represented as hash-preserving Casper RPC JSON."""


_HEX_RE = re.compile(r"[0-9a-fA-F]+")


def _bytesrepr_vector(items: Sequence[bytes]) -> bytes:
    """Encode a Casper bytesrepr vector of already-encoded values."""

    return len(items).to_bytes(4, "little") + b"".join(items)


def _versioned_package_session_bytes(
    session: DeployOfStoredContractByHashVersioned,
) -> bytes:
    """Return node-compatible bytesrepr for a versioned package call.

    ``pycspr==1.2.0`` uses the legacy stored-contract discriminant and a raw
    U32 version when hashing this session variant. Casper nodes expect the
    current ``StoredVersionedContractByHash`` discriminant and an
    ``Option<U32>``. Keep the correction here so builders and verifiers share
    one exact implementation.
    """

    version_value = (
        None if session.version is None else CLV_U32(int(session.version))
    )
    return (
        bytes([3])
        + serializer.to_bytes(CLV_ByteArray(session.hash))
        + serializer.to_bytes(CLV_Option(version_value, CLT_Type_U32()))
        + serializer.to_bytes(CLV_String(session.entry_point))
        + _bytesrepr_vector(
            [serializer.to_bytes(argument) for argument in session.arguments]
        )
    )


def exact_deploy_body_hash(deploy: Deploy) -> bytes:
    """Compute the body hash using the exact bytes accepted by Casper nodes."""

    if not isinstance(deploy, Deploy):
        raise ExactDeployJsonError("deploy must be a pycspr Deploy")
    if isinstance(
        deploy.session,
        DeployOfStoredContractByHashVersioned,
    ):
        return crypto.get_hash(
            serializer.to_bytes(deploy.payment)
            + _versioned_package_session_bytes(deploy.session)
        )
    return create_digest_of_deploy_body(
        deploy.payment,
        deploy.session,
    )


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


def normalize_deploy_rpc_json(value: object) -> object:
    """Normalize hex casing while preserving strict JSON spellings."""

    if isinstance(value, Mapping):
        return {
            str(key): normalize_deploy_rpc_json(item)
            for key, item in value.items()
        }
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

    expected_body_hash = exact_deploy_body_hash(deploy)
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
    if decoded.header.body_hash != exact_deploy_body_hash(decoded):
        raise ExactDeployJsonError(
            "decoded deploy body hash differs from exact bytes"
        )
    if decoded.hash != create_digest_of_deploy(decoded.header):
        raise ExactDeployJsonError(
            "decoded deploy hash differs from exact header bytes"
        )
    return value
