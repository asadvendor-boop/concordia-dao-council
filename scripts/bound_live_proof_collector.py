#!/usr/bin/env python3
"""Bound direct collector for SafePay-v2 and official-x402 release evidence.

The public ``collect`` command runs the private ``_worker`` command through
``shared.bound_command``.  The worker receives only a strict request plan: it
contains static proof inputs and request bytes, but no response bytes,
acquisition hashes, status claims, runtime identities, SQLite images, or
``live`` booleans.  The worker directly obtains every HTTP/RPC response,
Docker runtime identity, and SQLite online-backup byte sequence through fixed
endpoints and fixed local volume paths.  Full bundle and artifact bytes return
through descriptor-bound private outputs; stdout carries only a small status
record.

This command never accepts a URL, database path, collector identity,
acquisition row, receipt document, or capture-mode label from its caller.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import hmac
import http.client
import json
import os
import re
import select
import socket
import sqlite3
import stat
import sys
import time
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final


PLAN_SCHEMA_VERSION: Final = "concordia.bound_live_collector_plan.v1"
WORKER_RESULT_SCHEMA_VERSION: Final = "concordia.bound_live_collector_result.v1"
MAX_PLAN_BYTES: Final = 16 * 1024 * 1024
MAX_HTTP_BYTES: Final = 16 * 1024 * 1024
MAX_BUNDLE_BYTES: Final = 64 * 1024 * 1024
MAX_ARTIFACT_BYTES: Final = 64 * 1024 * 1024
MAX_TRANSCRIPT_BYTES: Final = 4 * 1024 * 1024

_ROOT = Path(__file__).resolve().parents[1]
_DOCKER_SOCKET = Path("/var/run/docker.sock")
_LEDGER_PATHS = {
    "safepay_v2": Path(
        "/var/lib/docker/volumes/"
        "concordia_x402_provider_data/_data/safepay.db"
    ),
    "official_x402_settlement_v1": Path(
        "/var/lib/docker/volumes/"
        "concordia_x402_official_data/_data/x402-official.db"
    ),
}
_SERVICE_NAMES = {
    "safepay_v2": "x402-provider",
    "official_x402_settlement_v1": "x402-official",
}
_FIXED_PLAN_PATHS = {
    "safepay_v2": "release/capture-plans/safepay-v2.json",
    "official_x402_settlement_v1": (
        "release/capture-plans/official-x402-settlement-v1.json"
    ),
}
_HEALTH_URLS = {
    "safepay_v2": "https://safepay.concordiadao.xyz/health",
    "official_x402_settlement_v1": "https://x402.concordiadao.xyz/health",
}
_FIXED_URLS = {
    "safepay_v2": {
        "casper_rpc_a": "https://node.testnet.casper.network/rpc",
        "casper_rpc_b": "https://node.testnet.cspr.cloud/rpc",
        "redemption": (
            "https://safepay.concordiadao.xyz/x402/v2/redemptions"
        ),
    },
    "official_x402_settlement_v1": {
        "facilitator_supported": "https://x402-facilitator.cspr.cloud/supported",
        "facilitator_verify": "https://x402-facilitator.cspr.cloud/verify",
        "facilitator_settle": "https://x402-facilitator.cspr.cloud/settle",
        "casper_rpc": "https://node.testnet.casper.network/rpc",
        "settlement_rpc_a": "https://node.testnet.casper.network/rpc",
        "settlement_rpc_b": "https://node.testnet.cspr.cloud/rpc",
        "paid_resource_origin": "https://x402.concordiadao.xyz",
    },
}
_FACILITATOR_TOKEN_PATH = Path(
    "/opt/apps/concordia/secrets/x402_official_cspr_cloud_token"
)
_WCSPR_PACKAGE = "3d80df21ba4ee4d66a2a1f60c32570dd5685e4b279f6538162a5fd1314847c1e"
_WCSPR_CONTRACT = "032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a"
_WCSPR_VERSION = 8
_SAFE_HEADERS = frozenset(
    {
        "accept",
        "content-type",
        "payment-signature",
        "x-payment",
        "x-concordia-quote-capability",
    }
)
_FORBIDDEN_PLAN_KEYS = frozenset(
    {
        "response",
        "response_status",
        "response_body_base64",
        "sqlite_backup_base64",
        "service_instance_id",
        "container_id",
        "image_digest",
        "capture_mode",
        "verified",
        "passed",
        "acquisitions",
        "acquisition_transcript_sha256",
        "tool_identity",
        "command_assets",
        "runner_commit",
        "runner_sha256",
        "runtime_identity",
        "live",
    }
)
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_WORKER_ARM_DOMAIN: Final = b"CONCORDIA_BOUND_LIVE_WORKER_ARM_V1\x00"


class LiveCollectorError(RuntimeError):
    """The fixed collector could not obtain or bind direct observations."""


class _DuplicateKey(ValueError):
    pass


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _canonical(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise LiveCollectorError("collector value is not canonical JSON") from exc


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateKey(key)
        value[key] = item
    return value


def _strict_json(raw: bytes, label: str, *, limit: int) -> dict[str, Any]:
    if not raw or len(raw) > limit:
        raise LiveCollectorError(f"{label} is empty or oversized")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_object_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey, ValueError) as exc:
        raise LiveCollectorError(f"{label} is not strict JSON") from exc
    if type(value) is not dict:
        raise LiveCollectorError(f"{label} is not one object")
    return value


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_b64(value: object, label: str, *, limit: int = MAX_HTTP_BYTES) -> bytes:
    if type(value) is not str:
        raise LiveCollectorError(f"{label} is not base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise LiveCollectorError(f"{label} is not base64") from exc
    if len(raw) > limit or _b64(raw) != value:
        raise LiveCollectorError(f"{label} is not canonical base64")
    return raw


def _mapping(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise LiveCollectorError(f"{label} must be an object")
    return value


def _list(value: object, label: str) -> list[Any]:
    if type(value) is not list:
        raise LiveCollectorError(f"{label} must be an array")
    return value


def _read_regular(path: Path, *, limit: int, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LiveCollectorError(f"{label} is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise LiveCollectorError(f"{label} is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(raw) != before.st_size
            or len(raw) > limit
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
        ):
            raise LiveCollectorError(f"{label} changed while being read")
        return raw
    finally:
        os.close(descriptor)


def _read_secure_secret(path: Path, *, limit: int, label: str) -> bytes:
    """Read one exact owner-private secret without following any path link."""

    directory_fd: int | None = None
    descriptor: int | None = None
    try:
        if (
            not path.is_absolute()
            or path.name in {"", ".", ".."}
            or any(part in {"", ".", ".."} for part in path.parts[1:])
        ):
            raise OSError("unsafe secret path")
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        directory_fd = os.open(path.anchor, directory_flags)
        for component in path.parts[1:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        descriptor = os.open(
            path.name,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
            or not 0 < before.st_size <= limit
        ):
            raise OSError("unsafe secret file")
        raw = os.read(descriptor, limit + 1)
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_uid,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if (
            len(raw) != before.st_size
            or len(raw) > limit
            or identity(before) != identity(after)
        ):
            raise OSError("secret changed")
        return raw
    except OSError as exc:
        raise LiveCollectorError(f"{label} could not be loaded safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_fd is not None:
            os.close(directory_fd)


def _reflected_secret_forms(secret: bytes) -> tuple[bytes, ...]:
    stripped = secret.strip()
    if not stripped:
        raise LiveCollectorError("facilitator token is empty")
    return (
        stripped,
        base64.b64encode(stripped),
        stripped.hex().encode("ascii"),
    )


def _assert_no_secret_reflection(
    value: bytes,
    *,
    secrets_to_scan: Sequence[bytes],
    label: str,
) -> None:
    for secret in secrets_to_scan:
        if any(form and form in value for form in _reflected_secret_forms(secret)):
            raise LiveCollectorError(f"{label} reflected protected secret material")


def _write_bound_output(path: Path, raw: bytes, *, limit: int, label: str) -> None:
    if not path.is_absolute() or len(raw) > limit:
        raise LiveCollectorError(f"{label} output contract differs")
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != 0
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o777 != 0o600
        ):
            raise LiveCollectorError(f"{label} private output is not descriptor-bound")
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise LiveCollectorError(f"{label} output write failed")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _scan_for_forbidden_plan_fields(value: object, *, path: str = "$") -> None:
    if type(value) is dict:
        for key, nested in value.items():
            if key in _FORBIDDEN_PLAN_KEYS:
                raise LiveCollectorError(
                    f"collector plan contains forbidden observed field at {path}.{key}"
                )
            _scan_for_forbidden_plan_fields(nested, path=f"{path}.{key}")
    elif type(value) is list:
        for index, nested in enumerate(value):
            _scan_for_forbidden_plan_fields(nested, path=f"{path}[{index}]")


def _set_path(document: dict[str, Any], path: Sequence[object], value: object) -> None:
    current: object = document
    for part in path[:-1]:
        if type(part) is str and type(current) is dict:
            if part not in current:
                current[part] = {}
            current = current[part]
        elif type(part) is int and type(current) is list and 0 <= part < len(current):
            current = current[part]
        else:
            raise LiveCollectorError("collector target path differs")
    final = path[-1]
    if type(final) is str and type(current) is dict:
        if final in current:
            raise LiveCollectorError("collector plan pre-populated observed evidence")
        current[final] = value
    elif type(final) is int and type(current) is list and 0 <= final < len(current):
        if current[final] is not None:
            raise LiveCollectorError("collector plan pre-populated observed evidence")
        current[final] = value
    else:
        raise LiveCollectorError("collector target path differs")


def _request_plan(value: object, label: str) -> dict[str, Any]:
    request = _mapping(value, label)
    if set(request) != {"method", "body_base64", "headers"}:
        raise LiveCollectorError(f"{label} schema differs")
    method = request.get("method")
    if method not in {"GET", "POST"}:
        raise LiveCollectorError(f"{label} method differs")
    _decode_b64(request.get("body_base64"), f"{label} body")
    headers = _mapping(request.get("headers"), f"{label} headers")
    normalized: dict[str, str] = {}
    for key, item in headers.items():
        if (
            type(key) is not str
            or key.lower() not in _SAFE_HEADERS
            or type(item) is not str
            or "\r" in item
            or "\n" in item
            or len(item) > 64 * 1024
        ):
            raise LiveCollectorError(f"{label} header is outside the allowlist")
        lowered = key.lower()
        if lowered in normalized:
            raise LiveCollectorError(f"{label} header is duplicated")
        normalized[lowered] = item
    return {
        "method": method,
        "body_base64": request["body_base64"],
        "headers": normalized,
    }


def _expected_method(acquisition_id: str) -> str:
    return (
        "GET"
        if acquisition_id == "facilitator_supported"
        or acquisition_id.startswith("paid_")
        else "POST"
    )


def _requires_plan_request(acquisition_id: str) -> bool:
    if acquisition_id == "facilitator_settle":
        # Executed only by Concordia's settlement transport, but the immutable
        # expected bytes are required to select and validate its journal rows.
        return True
    if acquisition_id.startswith(("casper_rpc_", "settlement_rpc_", "wcspr_")):
        return False
    return (
        _operation_kind(acquisition_id) in {"https", "casper_rpc"}
        and acquisition_id != "service_health_after_restart"
    )


def _validate_plan_document(value: object) -> dict[str, Any]:
    plan = _mapping(value, "collector plan")
    if set(plan) != {
        "schema_version",
        "proof_id",
        "source_commit",
        "deployment_commit",
        "bundle_skeleton",
        "requests",
    }:
        raise LiveCollectorError("collector plan schema differs")
    proof_id = plan.get("proof_id")
    if (
        plan.get("schema_version") != PLAN_SCHEMA_VERSION
        or proof_id not in {"safepay_v2", "official_x402_settlement_v1"}
        or type(plan.get("source_commit")) is not str
        or _HEX40.fullmatch(plan["source_commit"]) is None
        or type(plan.get("deployment_commit")) is not str
        or _HEX40.fullmatch(plan["deployment_commit"]) is None
    ):
        raise LiveCollectorError("collector plan identity differs")
    skeleton = _mapping(plan.get("bundle_skeleton"), "collector bundle skeleton")
    _scan_for_forbidden_plan_fields(skeleton)
    requests = _mapping(plan.get("requests"), "collector requests")
    expected = {
        acquisition_id
        for acquisition_id in _required_ids(str(proof_id))
        if _requires_plan_request(acquisition_id)
    }
    if set(requests) != expected:
        raise LiveCollectorError("collector request inventory differs")
    normalized_requests: dict[str, dict[str, Any]] = {}
    for acquisition_id in sorted(expected):
        request = _request_plan(
            requests[acquisition_id],
            f"collector request {acquisition_id}",
        )
        if request["method"] != _expected_method(acquisition_id):
            raise LiveCollectorError(
                f"collector request {acquisition_id} method differs"
            )
        normalized_requests[acquisition_id] = request
    return {
        **plan,
        "bundle_skeleton": skeleton,
        "requests": normalized_requests,
    }


def _fixed_plan_path(root: Path, proof_id: str) -> Path:
    try:
        relative = _FIXED_PLAN_PATHS[proof_id]
    except KeyError as exc:
        raise LiveCollectorError("collector proof identity is unsupported") from exc
    return root / relative


def _http_request(
    *,
    url: str,
    request: Mapping[str, Any],
    authorization_secret: bytes | None = None,
) -> dict[str, Any]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise LiveCollectorError("fixed collector URL is invalid")
    body = _decode_b64(request.get("body_base64"), "HTTP request body")
    headers = {str(key): str(value) for key, value in request["headers"].items()}
    if authorization_secret is not None:
        try:
            headers["authorization"] = authorization_secret.decode(
                "ascii", errors="strict"
            )
        except UnicodeDecodeError as exc:
            raise LiveCollectorError("facilitator token is not ASCII") from exc
    connection_type = (
        http.client.HTTPSConnection
        if parsed.scheme == "https"
        else http.client.HTTPConnection
    )
    connection = connection_type(parsed.hostname, parsed.port, timeout=30)
    target = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    try:
        connection.request(str(request["method"]), target, body=body or None, headers=headers)
        response = connection.getresponse()
        raw = response.read(MAX_HTTP_BYTES + 1)
        if len(raw) > MAX_HTTP_BYTES:
            raise LiveCollectorError("HTTP response exceeds its bound")
        response_headers: dict[str, str] = {}
        for key, item in response.getheaders():
            lowered = key.lower()
            if lowered in response_headers:
                response_headers[lowered] = response_headers[lowered] + "," + item
            else:
                response_headers[lowered] = item
        observed_at = _utc_now()
        return {
            "method": request["method"],
            "url": url,
            "request_body_base64": _b64(body),
            "request_headers": dict(request["headers"]),
            "response_status": response.status,
            "response_headers": response_headers,
            "response_content_type": response_headers.get("content-type", ""),
            "response_body_base64": _b64(raw),
            "observed_at": observed_at,
        }
    except (OSError, http.client.HTTPException) as exc:
        raise LiveCollectorError("fixed HTTP acquisition failed") from exc
    finally:
        connection.close()


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: Path):
        super().__init__("docker", timeout=30)
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path.as_posix())


def _docker_request(method: str, path: str) -> tuple[int, bytes, object | None]:
    connection = _UnixHTTPConnection(_DOCKER_SOCKET)
    try:
        connection.request(method, path, headers={"Host": "docker"})
        response = connection.getresponse()
        raw = response.read(MAX_HTTP_BYTES + 1)
        if len(raw) > MAX_HTTP_BYTES:
            raise LiveCollectorError("Docker observation failed")
        value: object | None = None
        if raw:
            value = json.loads(
                raw,
                object_pairs_hook=_object_pairs,
                parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)),
            )
        return response.status, raw, value
    except (OSError, http.client.HTTPException, json.JSONDecodeError, ValueError) as exc:
        raise LiveCollectorError("Docker observation failed") from exc
    finally:
        connection.close()


def _docker_json(path: str) -> tuple[bytes, object]:
    status_code, raw, value = _docker_request("GET", path)
    if status_code != 200 or value is None:
        raise LiveCollectorError("Docker observation failed")
    return raw, value


def _service_instance_id(identity: Mapping[str, Any]) -> str:
    material = {
        "container_id": identity["container_id"],
        "started_at": identity["started_at"],
        "image_digest": identity["image_digest"],
    }
    return hashlib.sha256(
        b"CONCORDIA_LIVE_SERVICE_INSTANCE_V1\x00" + _canonical(material)
    ).hexdigest()


def _docker_runtime_identity(proof_id: str) -> tuple[dict[str, Any], bytes]:
    service = _SERVICE_NAMES[proof_id]
    filters = urllib.parse.quote(
        json.dumps(
            {
                "label": [
                    "com.docker.compose.project=concordia",
                    f"com.docker.compose.service={service}",
                ]
            },
            separators=(",", ":"),
        )
    )
    list_raw, listed = _docker_json(f"/containers/json?all=1&filters={filters}")
    if type(listed) is not list or len(listed) != 1:
        raise LiveCollectorError("fixed collector service cardinality differs")
    container_id = listed[0].get("Id")
    if type(container_id) is not str or re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
        raise LiveCollectorError("collector container identity differs")
    inspect_raw, inspect = _docker_json(f"/containers/{container_id}/json")
    details = _mapping(inspect, "Docker inspect")
    config = _mapping(details.get("Config"), "Docker config")
    labels = _mapping(config.get("Labels"), "Docker labels")
    state = _mapping(details.get("State"), "Docker state")
    image_id = details.get("Image")
    if (
        state.get("Running") is not True
        or type(image_id) is not str
        or not image_id.startswith("sha256:")
        or labels.get("com.docker.compose.project") != "concordia"
        or labels.get("com.docker.compose.service") != service
    ):
        raise LiveCollectorError("collector runtime labels or state differ")
    started_at = state.get("StartedAt")
    restart_count = details.get("RestartCount")
    if type(started_at) is not str or type(restart_count) is not int:
        raise LiveCollectorError("collector runtime identity differs")
    observed_at = _utc_now()
    identity = {
        "container_id": container_id,
        "image_digest": image_id,
        "started_at": started_at,
        "observed_at": observed_at,
        "restart_count": restart_count,
    }
    identity["service_instance_id"] = _service_instance_id(identity)
    return identity, list_raw + b"\n" + inspect_raw


def _docker_restart_and_wait(
    proof_id: str,
    before: Mapping[str, Any],
    *,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[dict[str, Any], bytes]:
    """Restart exactly one previously inspected Concordia service."""

    container_id = before.get("container_id")
    if type(container_id) is not str or re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
        raise LiveCollectorError("restart target identity differs")
    status_code, restart_raw, response = _docker_request(
        "POST", f"/containers/{container_id}/restart?t=30"
    )
    if status_code != 204 or restart_raw or response is not None:
        raise LiveCollectorError("fixed service restart was not accepted")
    observations: list[bytes] = [b"POST restart:204"]
    for _attempt in range(60):
        try:
            current, raw = _docker_runtime_identity(proof_id)
        except LiveCollectorError:
            sleep(2)
            continue
        observations.append(raw)
        if (
            current["container_id"] == container_id
            and current["image_digest"] == before.get("image_digest")
            and current["started_at"] != before.get("started_at")
            and current["service_instance_id"] != before.get("service_instance_id")
            and current["restart_count"] == int(before.get("restart_count", 0)) + 1
        ):
            return current, b"\n".join(observations)
        sleep(2)
    raise LiveCollectorError("fixed Concordia service did not become a new instance")


def _sqlite_online_backup(proof_id: str) -> tuple[bytes, str]:
    path = _LEDGER_PATHS[proof_id]
    try:
        source = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise LiveCollectorError("fixed SQLite ledger is unavailable") from exc
    destination = sqlite3.connect(":memory:")
    try:
        source.backup(destination)
        if destination.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise LiveCollectorError("SQLite online backup failed integrity check")
        raw = destination.serialize()
    except sqlite3.Error as exc:
        raise LiveCollectorError("SQLite online backup failed") from exc
    finally:
        destination.close()
        source.close()
    return raw, _utc_now()


def _required_ids(proof_id: str) -> tuple[str, ...]:
    # Imported lazily only in the outer/normal source tree. The bound worker's
    # authoritative list is duplicated as a closed constant so it has no
    # unbound local import.
    if proof_id == "safepay_v2":
        return (
            "runtime_before_restart",
            "redemption_first_consumption",
            "ledger_after_first_consumption",
            "service_restart",
            "runtime_after_restart",
            "service_health_after_restart",
            "redemption_exact_retry",
            "ledger_after_exact_retry",
            "redemption_cross_binding_reuse",
            "ledger_after_cross_binding_reuse",
            "casper_rpc_a_info_get_deploy",
            "casper_rpc_a_chain_get_block",
            "casper_rpc_a_info_get_status",
            "casper_rpc_b_info_get_deploy",
            "casper_rpc_b_chain_get_block",
            "casper_rpc_b_info_get_status",
        )
    if proof_id == "official_x402_settlement_v1":
        return (
            "runtime_before_restart",
            "facilitator_supported",
            "wcspr_pre_verify",
            "facilitator_verify",
            "wcspr_pre_settle",
            # The first protected-resource request enters Concordia's own
            # durable settlement pipeline.  Its journal is the authoritative
            # direct record of the one external facilitator /settle call.
            "paid_first_release",
            "journal_after_first_release",
            "facilitator_settle",
            "fulfillment_first_row",
            "settlement_rpc_a_info_get_transaction",
            "settlement_rpc_a_chain_get_block",
            "settlement_rpc_a_info_get_status",
            "settlement_rpc_b_info_get_transaction",
            "settlement_rpc_b_chain_get_block",
            "settlement_rpc_b_info_get_status",
            "wcspr_post_settle",
            "service_restart",
            "runtime_after_restart",
            "service_health_after_restart",
            "journal_after_restart",
            "fulfillment_post_restart_row",
            "paid_exact_retry",
            "journal_after_exact_retry",
            "paid_cross_binding_reuse",
            "journal_after_cross_binding_reuse",
        )
    raise LiveCollectorError("collector proof identity is unsupported")


def _operation_kind(acquisition_id: str) -> str:
    if acquisition_id == "service_restart":
        return "docker_restart"
    if acquisition_id.startswith("runtime_"):
        return "docker_inspect"
    if acquisition_id.startswith(("ledger_", "journal_")):
        return "sqlite_backup"
    if acquisition_id.startswith("fulfillment_"):
        return "sqlite_row"
    if acquisition_id == "facilitator_settle":
        return "sqlite_row"
    if (
        "_rpc_" in acquisition_id
        or acquisition_id.startswith("wcspr_")
    ):
        return "casper_rpc"
    return "https"


def _fixed_url(proof_id: str, acquisition_id: str, base: Mapping[str, Any]) -> str:
    urls = _FIXED_URLS[proof_id]
    if acquisition_id == "service_health_after_restart":
        return _HEALTH_URLS[proof_id]
    if proof_id == "safepay_v2":
        if acquisition_id.startswith("casper_rpc_a_"):
            return urls["casper_rpc_a"]
        if acquisition_id.startswith("casper_rpc_b_"):
            return urls["casper_rpc_b"]
        return urls["redemption"]
    if acquisition_id.startswith("facilitator_"):
        return urls[acquisition_id]
    if acquisition_id.startswith("wcspr_"):
        return urls["casper_rpc"]
    if acquisition_id.startswith("settlement_rpc_a_"):
        return urls["settlement_rpc_a"]
    if acquisition_id.startswith("settlement_rpc_b_"):
        return urls["settlement_rpc_b"]
    resource_url = _mapping(
        base.get("imported_authorization"), "imported authorization"
    ).get("resource_url")
    if type(resource_url) is not str:
        raise LiveCollectorError("official resource URL is unavailable")
    parsed = urllib.parse.urlsplit(resource_url)
    fixed = urllib.parse.urlsplit(str(urls["paid_resource_origin"]))
    if (
        parsed.scheme != fixed.scheme
        or parsed.netloc != fixed.netloc
        or not parsed.path.startswith("/resource/")
        or parsed.query
        or parsed.fragment
    ):
        raise LiveCollectorError("official paid resource URL is outside the fixed origin")
    return resource_url


def _exchange_for_bundle(
    proof_id: str, acquisition_id: str, observed: Mapping[str, Any]
) -> dict[str, Any]:
    if _operation_kind(acquisition_id) == "casper_rpc":
        return {
            "url": observed["url"],
            "request_body_base64": observed["request_body_base64"],
            "response_status": observed["response_status"],
            "response_content_type": observed["response_content_type"],
            "response_body_base64": observed["response_body_base64"],
            "observed_at": observed["observed_at"],
        }
    if proof_id == "official_x402_settlement_v1" and acquisition_id.startswith(
        "paid_"
    ):
        request_headers = _canonical(observed["request_headers"]).rstrip(b"\n")
        response_headers = _canonical(observed["response_headers"]).rstrip(b"\n")
        return {
            "method": observed["method"],
            "url": observed["url"],
            "request_headers_canonical_json_base64": _b64(request_headers),
            "request_body_base64": observed["request_body_base64"],
            "response_status": observed["response_status"],
            "response_headers_canonical_json_base64": _b64(response_headers),
            "response_content_type": observed["response_content_type"],
            "response_body_base64": observed["response_body_base64"],
            "observed_at": observed["observed_at"],
        }
    return {
        "method": observed["method"],
        "url": observed["url"],
        "request_body_base64": observed["request_body_base64"],
        "response_status": observed["response_status"],
        "response_content_type": observed["response_content_type"],
        "response_body_base64": observed["response_body_base64"],
        "observed_at": observed["observed_at"],
    }


def _observed_response_document(
    observations: Mapping[str, Mapping[str, Any]],
    acquisition_id: str,
) -> dict[str, Any]:
    try:
        observed = observations[acquisition_id]
    except KeyError as exc:
        raise LiveCollectorError(
            f"derived request lacks prior observation {acquisition_id}"
        ) from exc
    if observed.get("response_status") != 200:
        raise LiveCollectorError(
            f"derived request prior observation {acquisition_id} is not successful"
        )
    raw = _decode_b64(
        observed.get("response_body_base64"),
        f"{acquisition_id} response body",
    )
    return _strict_json(
        raw,
        f"{acquisition_id} response",
        limit=MAX_HTTP_BYTES,
    )


def _rpc_request(
    *,
    request_id: object,
    method: str,
    params: object,
) -> dict[str, Any]:
    return {
        "method": "POST",
        "body_base64": _b64(
            _canonical(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": method,
                    "params": params,
                }
            ).rstrip(b"\n")
        ),
        "headers": {"content-type": "application/json"},
    }


def _lower_hex64(value: object, label: str) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise LiveCollectorError(f"{label} is not lowercase 32-byte hex")
    return value


def _safepay_payment_hash(requests: Mapping[str, Any]) -> str:
    first = _request_plan(
        requests.get("redemption_first_consumption"),
        "first SafePay redemption request",
    )
    body = _strict_json(
        _decode_b64(
            first["body_base64"],
            "first SafePay redemption request body",
        ),
        "first SafePay redemption request body",
        limit=MAX_HTTP_BYTES,
    )
    if set(body) != {"schema_version", "quote", "payment_hash"}:
        raise LiveCollectorError("first SafePay redemption request schema differs")
    quote = _mapping(body.get("quote"), "first SafePay redemption quote")
    if (
        body.get("schema_version") != "safepay-redemption-v2"
        or quote.get("network") != "casper:casper-test"
    ):
        raise LiveCollectorError("first SafePay redemption binding differs")
    return _lower_hex64(body.get("payment_hash"), "SafePay payment hash")


def _derived_request(
    *,
    proof_id: str,
    acquisition_id: str,
    requests: Mapping[str, Any],
    observations: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    if proof_id == "safepay_v2" and acquisition_id.startswith("casper_rpc_"):
        provider = "a" if acquisition_id.startswith("casper_rpc_a_") else "b"
        suffix = acquisition_id.split("_", 3)[3]
        payment_hash = _safepay_payment_hash(requests)
        if suffix == "info_get_deploy":
            return _rpc_request(
                request_id=1,
                method="info_get_deploy",
                params={
                    "deploy_hash": payment_hash,
                    "finalized_approvals": True,
                },
            )
        if suffix == "chain_get_block":
            deploy = _observed_response_document(
                observations,
                f"casper_rpc_{provider}_info_get_deploy",
            )
            try:
                block_hash = deploy["result"]["execution_info"]["block_hash"]
            except (KeyError, TypeError) as exc:
                raise LiveCollectorError(
                    "SafePay deploy response lacks its finalized block selector"
                ) from exc
            return _rpc_request(
                request_id=2,
                method="chain_get_block",
                params={
                    "block_identifier": {
                        "Hash": _lower_hex64(
                            block_hash,
                            "SafePay finalized block hash",
                        )
                    }
                },
            )
        if suffix == "info_get_status":
            return _rpc_request(
                request_id=3,
                method="info_get_status",
                params=[],
            )
    if proof_id == "official_x402_settlement_v1" and acquisition_id.startswith(
        "settlement_rpc_"
    ):
        provider = "a" if acquisition_id.startswith("settlement_rpc_a_") else "b"
        suffix = acquisition_id.split("_", 3)[3]
        settle = _observed_response_document(observations, "facilitator_settle")
        if settle.get("success") is not True:
            raise LiveCollectorError("facilitator settlement was not successful")
        transaction = _lower_hex64(
            settle.get("transaction"),
            "facilitator settlement transaction",
        )
        if suffix == "info_get_transaction":
            return _rpc_request(
                request_id=f"official-{provider}-transaction",
                method="info_get_transaction",
                params={
                    "transaction_hash": {"Version1": transaction},
                    "finalized_approvals": True,
                },
            )
        if suffix == "chain_get_block":
            transaction_response = _observed_response_document(
                observations,
                f"settlement_rpc_{provider}_info_get_transaction",
            )
            try:
                block_hash = transaction_response["result"]["execution_info"][
                    "block_hash"
                ]
            except (KeyError, TypeError) as exc:
                raise LiveCollectorError(
                    "settlement transaction response lacks its block selector"
                ) from exc
            return _rpc_request(
                request_id=f"official-{provider}-block",
                method="chain_get_block",
                params={
                    "block_identifier": {
                        "Hash": _lower_hex64(
                            block_hash,
                            "official settlement block hash",
                        )
                    }
                },
            )
        if suffix == "info_get_status":
            return _rpc_request(
                request_id=f"official-{provider}-status",
                method="info_get_status",
                params=[],
            )
    raise LiveCollectorError(
        f"collector request {acquisition_id} cannot be derived from prior evidence"
    )


def _rpc_response_document(
    observed: Mapping[str, Any],
    *,
    label: str,
) -> dict[str, Any]:
    if (
        observed.get("response_status") != 200
        or observed.get("response_content_type") != "application/json"
    ):
        raise LiveCollectorError(f"{label} is not a successful JSON RPC response")
    return _strict_json(
        _decode_b64(observed.get("response_body_base64"), f"{label} body"),
        label,
        limit=MAX_HTTP_BYTES,
    )


def _wcspr_readback(
    *,
    acquisition_id: str,
    url: str,
    http_acquire: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    """Obtain status -> package -> active-contract bytes from one fixed node."""

    phase = {
        "wcspr_pre_verify": "pre-verify",
        "wcspr_pre_settle": "pre-settle",
        "wcspr_post_settle": "post-settle",
    }.get(acquisition_id)
    if phase is None:
        raise LiveCollectorError("WCSPR readback phase differs")
    status_request = _rpc_request(
        request_id=f"{phase}-status",
        method="info_get_status",
        params=[],
    )
    status_observed = http_acquire(
        url=url,
        request=status_request,
        authorization_secret=None,
    )
    status_response = _rpc_response_document(
        status_observed,
        label=f"{phase} WCSPR status",
    )
    try:
        status_result = status_response["result"]
        tip = status_result["last_added_block_info"]
        tip_hash = _lower_hex64(tip["hash"], f"{phase} WCSPR tip hash")
        state_root = _lower_hex64(
            tip["state_root_hash"],
            f"{phase} WCSPR state root",
        )
    except (KeyError, TypeError) as exc:
        raise LiveCollectorError(
            f"{phase} WCSPR status lacks canonical tip selectors"
        ) from exc
    if status_result.get("chainspec_name") != "casper-test":
        raise LiveCollectorError(f"{phase} WCSPR status network differs")
    package_request = _rpc_request(
        request_id=f"{phase}-package",
        method="state_get_package",
        params={
            "package_identifier": {
                "ContractPackageHash": f"contract-package-{_WCSPR_PACKAGE}"
            },
            "block_identifier": {"Hash": tip_hash},
        },
    )
    package_observed = http_acquire(
        url=url,
        request=package_request,
        authorization_secret=None,
    )
    package_response = _rpc_response_document(
        package_observed,
        label=f"{phase} WCSPR package",
    )
    try:
        package = package_response["result"]["package"]["ContractPackage"]
        versions = package["versions"]
        disabled_raw = package["disabled_versions"]
        lock_status = package["lock_status"]
    except (KeyError, TypeError) as exc:
        raise LiveCollectorError(
            f"{phase} WCSPR package response is malformed"
        ) from exc
    if (
        type(versions) is not list
        or type(disabled_raw) is not list
        or lock_status != "Unlocked"
    ):
        raise LiveCollectorError(f"{phase} WCSPR package inventory differs")
    disabled: set[tuple[int, int]] = set()
    for item in disabled_raw:
        if (
            type(item) is not list
            or len(item) != 2
            or type(item[0]) is not int
            or type(item[1]) is not int
            or item[0] < 0
            or item[1] < 0
        ):
            raise LiveCollectorError(
                f"{phase} WCSPR disabled-version inventory differs"
            )
        disabled.add((item[0], item[1]))
    active: list[tuple[int, int, str]] = []
    for item in versions:
        if type(item) is not dict:
            raise LiveCollectorError(
                f"{phase} WCSPR version inventory differs"
            )
        protocol_major = item.get("protocol_version_major")
        contract_version = item.get("contract_version")
        contract_hash = item.get("contract_hash")
        if (
            type(protocol_major) is not int
            or type(contract_version) is not int
            or protocol_major < 0
            or contract_version < 0
            or type(contract_hash) is not str
            or re.fullmatch(r"contract-[0-9a-f]{64}", contract_hash) is None
        ):
            raise LiveCollectorError(
                f"{phase} WCSPR version inventory differs"
            )
        if (protocol_major, contract_version) not in disabled:
            active.append(
                (protocol_major, contract_version, contract_hash.removeprefix("contract-"))
            )
    active.sort(key=lambda item: (item[1], item[0]), reverse=True)
    expected = [
        item
        for item in active
        if item[0] == 2 and item[1] == _WCSPR_VERSION
    ]
    if (
        len(expected) != 1
        or not active
        or active[0] != expected[0]
        or expected[0][2] != _WCSPR_CONTRACT
    ):
        raise LiveCollectorError(
            f"{phase} WCSPR active v8 contract differs"
        )
    derived_contract = expected[0][2]
    contract_request = _rpc_request(
        request_id=f"{phase}-contract",
        method="query_global_state",
        params={
            "state_identifier": {"StateRootHash": state_root},
            "key": f"hash-{derived_contract}",
            "path": [],
        },
    )
    contract_observed = http_acquire(
        url=url,
        request=contract_request,
        authorization_secret=None,
    )
    contract_response = _rpc_response_document(
        contract_observed,
        label=f"{phase} WCSPR contract",
    )
    requests = [
        _strict_json(
            _decode_b64(request["body_base64"], f"{phase} WCSPR request"),
            f"{phase} WCSPR request",
            limit=MAX_HTTP_BYTES,
        )
        for request in (status_request, package_request, contract_request)
    ]
    responses = [status_response, package_response, contract_response]
    return {
        "method": "POST",
        "url": url,
        "request_body_base64": _b64(_canonical(requests).rstrip(b"\n")),
        "request_headers": {"content-type": "application/json"},
        "response_status": 200,
        "response_headers": {"content-type": "application/json"},
        "response_content_type": "application/json",
        "response_body_base64": _b64(_canonical(responses).rstrip(b"\n")),
        "observed_at": contract_observed["observed_at"],
    }


def _settlement_block_height(
    observations: Mapping[str, Mapping[str, Any]],
    *,
    provider: str,
) -> tuple[str, int]:
    block = _observed_response_document(
        observations,
        f"settlement_rpc_{provider}_chain_get_block",
    )
    try:
        versioned = block["result"]["block_with_signatures"]["block"]
        body = versioned.get("Version2", versioned.get("Version1"))
        block_hash = _lower_hex64(
            body["hash"],
            f"settlement provider {provider} block hash",
        )
        height = body["header"]["height"]
    except (AttributeError, KeyError, TypeError) as exc:
        raise LiveCollectorError(
            f"settlement provider {provider} block response is malformed"
        ) from exc
    if type(height) is not int or height < 0:
        raise LiveCollectorError(
            f"settlement provider {provider} block height is malformed"
        )
    return block_hash, height


def _status_tip_height(observed: Mapping[str, Any], *, label: str) -> int:
    response = _rpc_response_document(observed, label=label)
    try:
        result = response["result"]
        height = result["last_added_block_info"]["height"]
    except (KeyError, TypeError) as exc:
        raise LiveCollectorError(f"{label} tip response is malformed") from exc
    if result.get("chainspec_name") != "casper-test" or type(height) is not int:
        raise LiveCollectorError(f"{label} chain identity differs")
    return height


def _poll_finalized_settlement_status(
    *,
    acquisition_id: str,
    url: str,
    request: Mapping[str, Any],
    observations: Mapping[str, Mapping[str, Any]],
    http_acquire: Callable[..., dict[str, Any]],
    sleep: Callable[[float], None],
    authorization_secret: bytes | None,
) -> dict[str, Any]:
    provider = "a" if acquisition_id.startswith("settlement_rpc_a_") else "b"
    _block_hash, block_height = _settlement_block_height(
        observations,
        provider=provider,
    )
    for attempt in range(60):
        observed = http_acquire(
            url=url,
            request=request,
            authorization_secret=authorization_secret,
        )
        if authorization_secret is not None:
            try:
                response_material = base64.b64decode(
                    str(observed["response_body_base64"]), validate=True
                )
                response_headers = _canonical(
                    observed.get("response_headers", {})
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise LiveCollectorError(
                    f"settlement provider {provider} poll response is malformed"
                ) from exc
            _assert_no_secret_reflection(
                response_material + b"\n" + response_headers,
                secrets_to_scan=(authorization_secret,),
                label=f"settlement provider {provider} poll response",
            )
        if _status_tip_height(
            observed,
            label=f"settlement provider {provider} status",
        ) >= block_height + 8:
            return observed
        if attempt != 59:
            sleep(min(0.25 * (attempt + 1), 2.0))
    raise LiveCollectorError(
        f"settlement provider {provider} did not reach eight confirmations"
    )


def _poll_paid_first_release(
    *,
    url: str,
    request: Mapping[str, Any],
    http_acquire: Callable[..., dict[str, Any]],
    sleep: Callable[[float], None],
    secrets_to_scan: Sequence[bytes],
) -> tuple[dict[str, Any], bytes]:
    """Poll only reconciliation until the finalized row releases bytes.

    The service's first call durably reserves the authorization before its
    sole upstream submission.  Subsequent identical calls can only reconcile
    that original transaction; they never submit it again.
    """

    attempts: list[dict[str, Any]] = []
    for attempt in range(120):
        observed = http_acquire(
            url=url,
            request=request,
            authorization_secret=None,
        )
        body = _decode_b64(
            observed.get("response_body_base64"),
            "paid first-release response body",
        )
        response_headers = _canonical(observed.get("response_headers", {}))
        _assert_no_secret_reflection(
            body + b"\n" + response_headers,
            secrets_to_scan=secrets_to_scan,
            label="paid first-release response",
        )
        status = observed.get("response_status")
        attempts.append(
            {
                "response_status": status,
                "response_headers": observed.get("response_headers"),
                "response_body_base64": observed.get("response_body_base64"),
                "observed_at": observed.get("observed_at"),
            }
        )
        if status == 200:
            return observed, _canonical(attempts)
        if (
            status != 503
            or observed.get("response_content_type") != "application/json"
            or _strict_json(
                body,
                "paid first-release pending response",
                limit=MAX_HTTP_BYTES,
            )
            != {"error": "reconciliation_pending"}
        ):
            raise LiveCollectorError(
                "paid first release returned a terminal non-release response"
            )
        if attempt != 119:
            sleep(min(0.25 * (attempt + 1), 2.0))
    raise LiveCollectorError("paid first release did not finalize in time")


def _require_shared_settlement_finality(
    observations: Mapping[str, Mapping[str, Any]],
) -> None:
    blocks = {
        provider: _settlement_block_height(observations, provider=provider)
        for provider in ("a", "b")
    }
    if blocks["a"] != blocks["b"]:
        raise LiveCollectorError("settlement providers disagree on finalized block")
    for provider in ("a", "b"):
        observed = observations.get(f"settlement_rpc_{provider}_info_get_status")
        if observed is None:
            raise LiveCollectorError("settlement finality status is unavailable")
        if _status_tip_height(
            observed,
            label=f"settlement provider {provider} final status",
        ) < blocks[provider][1] + 8:
            raise LiveCollectorError(
                "settlement post-state readback precedes eight confirmations"
            )


def _target_path(proof_id: str, acquisition_id: str) -> tuple[object, ...] | None:
    if proof_id == "safepay_v2":
        mapping: dict[str, tuple[object, ...] | None] = {
            "runtime_before_restart": ("provider", "instances", "before_restart"),
            "runtime_after_restart": ("provider", "instances", "after_restart"),
            "service_restart": None,
            "service_health_after_restart": None,
            "redemption_first_consumption": (
                "redemptions",
                "first_consumption",
                "exchange",
            ),
            "redemption_exact_retry": ("redemptions", "exact_retry", "exchange"),
            "redemption_cross_binding_reuse": (
                "redemptions",
                "cross_binding_reuse",
                "exchange",
            ),
            "ledger_after_first_consumption": (
                "ledger_snapshots_observed",
                "after_first_consumption",
            ),
            "ledger_after_exact_retry": (
                "ledger_snapshots_observed",
                "after_exact_retry",
            ),
            "ledger_after_cross_binding_reuse": (
                "ledger_snapshots_observed",
                "after_cross_binding_reuse",
            ),
        }
        if acquisition_id.startswith("casper_rpc_"):
            provider = 0 if acquisition_id.startswith("casper_rpc_a_") else 1
            suffix = acquisition_id.split("_", 3)[3]
            return ("chain", "providers", provider, suffix)
        return mapping[acquisition_id]
    mapping = {
        "facilitator_supported": ("facilitator", "supported"),
        "facilitator_verify": ("facilitator", "verify"),
        "facilitator_settle": ("facilitator", "settle"),
        "wcspr_pre_verify": ("wcspr_readbacks", "pre_verify", "rpc_transcript"),
        "wcspr_pre_settle": ("wcspr_readbacks", "pre_settle", "rpc_transcript"),
        "wcspr_post_settle": ("wcspr_readbacks", "post_settle", "rpc_transcript"),
        "fulfillment_first_row": ("fulfillment", "first_row"),
        "fulfillment_post_restart_row": ("fulfillment", "post_restart_row"),
        "paid_first_release": ("fulfillment", "first_release"),
        "paid_exact_retry": ("fulfillment", "exact_retry"),
        "paid_cross_binding_reuse": ("fulfillment", "cross_binding_reuse"),
        "journal_after_first_release": (
            "fulfillment",
            "journal",
            "snapshots",
            "after_first_release",
        ),
        "journal_after_exact_retry": (
            "fulfillment",
            "journal",
            "snapshots",
            "after_exact_retry",
        ),
        "journal_after_cross_binding_reuse": (
            "fulfillment",
            "journal",
            "snapshots",
            "after_cross_binding_reuse",
        ),
        "runtime_before_restart": None,
        "runtime_after_restart": None,
        "service_restart": None,
        "service_health_after_restart": None,
        "journal_after_restart": None,
    }
    if acquisition_id.startswith("settlement_rpc_"):
        provider = 0 if acquisition_id.startswith("settlement_rpc_a_") else 1
        suffix = acquisition_id.split("_", 3)[3]
        return ("settlement_providers", provider, suffix)
    return mapping[acquisition_id]


def _fulfillment_row_from_backup(
    raw: bytes,
    *,
    imported: Mapping[str, Any],
) -> bytes:
    signed_hash = imported.get("signed_payment_payload_hash")
    if type(signed_hash) is not str or re.fullmatch(r"[0-9a-f]{64}", signed_hash) is None:
        raise LiveCollectorError("signed payment hash is unavailable")
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.deserialize(raw)
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA query_only=ON")
        rows = connection.execute(
            "SELECT * FROM x402_fulfillments "
            "WHERE network=? AND signed_payment_payload_hash=?",
            ("casper:casper-test", signed_hash),
        ).fetchall()
    except sqlite3.Error as exc:
        raise LiveCollectorError("fulfillment row query failed") from exc
    finally:
        connection.close()
    if len(rows) != 1:
        raise LiveCollectorError("fulfillment row cardinality differs")
    # The accepted service stores snake_case columns while the proof schema is
    # camelCase. Keep one closed conversion table; never accept operator rows.
    aliases = {
        "network": "network",
        "wcspr_contract": "wcsprContract",
        "signed_payment_payload_hash": "signedPaymentPayloadHash",
        "payer_account_hash": "payerAccountHash",
        "payee_account_hash": "payeeAccountHash",
        "authorization_nonce": "authorizationNonce",
        "resource_id": "resourceId",
        "action_id": "actionId",
        "envelope_hash": "envelopeHash",
        "report_hash": "reportHash",
        "payment_requirements_hash": "paymentRequirementsHash",
        "settlement_response_hash": "settlementResponseHash",
        "settlement_transaction_hash": "settlementTransactionHash",
        "status": "status",
        "created_at": "createdAt",
        "settled_at": "settledAt",
        "updated_at": "updatedAt",
    }
    row = {aliases[key]: rows[0][key] for key in aliases}
    return _canonical(row).rstrip(b"\n")


def _facilitator_settle_from_backup(
    raw: bytes,
    *,
    request: Mapping[str, Any],
    authorization_secret: bytes,
) -> tuple[dict[str, Any], bytes, bytes]:
    """Recover the one upstream /settle exchange from its durable journal."""

    expected_body = _decode_b64(
        request.get("body_base64"),
        "planned facilitator settle request body",
    )
    expected_headers = _mapping(
        request.get("headers"),
        "planned facilitator settle request headers",
    )
    if (
        request.get("method") != "POST"
        or expected_headers != {"content-type": "application/json"}
    ):
        raise LiveCollectorError("planned facilitator settle request differs")

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.deserialize(raw)
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA query_only=ON")
        rows = connection.execute(
            "SELECT event_type,call_id,request_method,request_url,"
            "request_headers_canonical_json,request_body,request_body_sha256,"
            "response_status,response_headers_canonical_json,response_body,"
            "response_body_sha256,failure_code,observed_at "
            "FROM x402_upstream_settle_calls "
            "WHERE network='casper:casper-test' AND request_body_sha256=? "
            "OR (network='casper:casper-test' AND call_id IN ("
            "SELECT call_id FROM x402_upstream_settle_calls "
            "WHERE event_type='request_started' AND request_body_sha256=?)) "
            "ORDER BY sequence",
            (
                hashlib.sha256(expected_body).hexdigest(),
                hashlib.sha256(expected_body).hexdigest(),
            ),
        ).fetchall()
    except sqlite3.Error as exc:
        raise LiveCollectorError(
            "facilitator settle journal query failed"
        ) from exc
    finally:
        connection.close()
    if (
        len(rows) != 2
        or rows[0]["event_type"] != "request_started"
        or rows[1]["event_type"] != "response_observed"
        or rows[0]["call_id"] != rows[1]["call_id"]
    ):
        raise LiveCollectorError(
            "facilitator settle journal cardinality differs"
        )
    started, terminal = rows
    try:
        request_headers_raw = bytes(started["request_headers_canonical_json"])
        request_body = bytes(started["request_body"])
        response_headers_raw = bytes(terminal["response_headers_canonical_json"])
        response_body = bytes(terminal["response_body"])
    except (TypeError, ValueError) as exc:
        raise LiveCollectorError(
            "facilitator settle journal bytes differ"
        ) from exc
    request_headers = _strict_json(
        request_headers_raw,
        "journaled facilitator request headers",
        limit=4096,
    )
    response_headers = _strict_json(
        response_headers_raw,
        "journaled facilitator response headers",
        limit=4096,
    )
    if (
        request_headers_raw != _canonical(request_headers).rstrip(b"\n")
        or response_headers_raw != _canonical(response_headers).rstrip(b"\n")
        or request_headers != expected_headers
        or response_headers != {"content-type": "application/json"}
        or started["request_method"] != "POST"
        or started["request_url"]
        != _FIXED_URLS["official_x402_settlement_v1"]["facilitator_settle"]
        or request_body != expected_body
        or started["request_body_sha256"]
        != hashlib.sha256(request_body).hexdigest()
        or terminal["response_status"] != 200
        or terminal["response_body_sha256"]
        != hashlib.sha256(response_body).hexdigest()
        or started["failure_code"] is not None
        or terminal["failure_code"] is not None
        or type(started["observed_at"]) is not str
        or type(terminal["observed_at"]) is not str
        or started["observed_at"] > terminal["observed_at"]
    ):
        raise LiveCollectorError("facilitator settle journal binding differs")
    # Parse now so malformed/non-JSON upstream bytes never reach assembly.
    _strict_json(
        response_body,
        "journaled facilitator settle response",
        limit=MAX_HTTP_BYTES,
    )
    _assert_no_secret_reflection(
        response_body + b"\n" + response_headers_raw,
        secrets_to_scan=(authorization_secret,),
        label="journaled facilitator settle response",
    )
    return (
        {
            "method": "POST",
            "url": str(started["request_url"]),
            "request_body_base64": _b64(request_body),
            "request_headers": request_headers,
            "response_status": 200,
            "response_headers": response_headers,
            "response_content_type": "application/json",
            "response_body_base64": _b64(response_body),
            # This is the upstream observation instant.  The acquisition
            # transcript separately records the later SQLite snapshot time.
            "observed_at": str(terminal["observed_at"]),
        },
        request_body,
        response_body,
    )


def _collect_worker(
    plan: Mapping[str, Any],
    *,
    http_acquire: Callable[..., dict[str, Any]] = _http_request,
    runtime_acquire: Callable[[str], tuple[dict[str, Any], bytes]] = (
        _docker_runtime_identity
    ),
    restart_acquire: Callable[
        [str, Mapping[str, Any]], tuple[dict[str, Any], bytes]
    ] = _docker_restart_and_wait,
    sqlite_acquire: Callable[[str], tuple[bytes, str]] = _sqlite_online_backup,
    secret_acquire: Callable[..., bytes] = _read_secure_secret,
    poll_sleep: Callable[[float], None] = time.sleep,
) -> tuple[bytes, bytes]:
    normalized = _validate_plan_document(plan)
    proof_id = str(normalized["proof_id"])
    bundle = json.loads(_canonical(normalized["bundle_skeleton"]))
    requests = _mapping(normalized["requests"], "collector requests")
    required = _required_ids(proof_id)
    if proof_id == "safepay_v2":
        chain = _mapping(bundle.get("chain"), "SafePay chain skeleton")
        providers = _list(chain.get("providers"), "SafePay provider skeletons")
        if len(providers) != 2 or any(type(item) is not dict or item for item in providers):
            raise LiveCollectorError("SafePay provider skeleton inventory differs")
        providers[0].update(
            {
                "endpoint_id": "casper-rpc-a",
                "origin": _FIXED_URLS[proof_id]["casper_rpc_a"],
            }
        )
        providers[1].update(
            {
                "endpoint_id": "casper-rpc-b",
                "origin": _FIXED_URLS[proof_id]["casper_rpc_b"],
            }
        )

    acquisitions: list[dict[str, object]] = []
    wire_observations: dict[str, dict[str, Any]] = {}
    sqlite_snapshots: dict[str, tuple[bytes, str]] = {}
    runtime_identities: dict[str, dict[str, Any]] = {}
    restarted_identity: dict[str, Any] | None = None
    token: bytes | None = None
    for acquisition_id in required:
        kind = _operation_kind(acquisition_id)
        request_material: bytes
        response_material: bytes
        observed_at: str
        target = _target_path(proof_id, acquisition_id)

        if kind == "docker_inspect":
            identity, raw = runtime_acquire(proof_id)
            if acquisition_id == "runtime_after_restart":
                before = runtime_identities.get("runtime_before_restart")
                if (
                    before is None
                    or restarted_identity is None
                    or identity["service_instance_id"]
                    != restarted_identity["service_instance_id"]
                    or identity["service_instance_id"]
                    == before["service_instance_id"]
                    or identity["image_digest"] != before["image_digest"]
                ):
                    raise LiveCollectorError(
                        "post-restart service identity did not reconcile"
                    )
            observed_at = str(identity["observed_at"])
            request_material = _canonical(
                {"service": _SERVICE_NAMES[proof_id], "docker_socket": "fixed"}
            )
            response_material = raw
            runtime_identities[acquisition_id] = identity
            if proof_id == "safepay_v2":
                projected = {
                    **{
                        key: identity[key]
                        for key in (
                            "container_id",
                            "image_digest",
                            "started_at",
                            "observed_at",
                            "restart_count",
                        )
                    },
                    "deployment_id": f"safepay-{plan['deployment_commit'][:12]}",
                }
                if acquisition_id == "runtime_before_restart":
                    provider = _mapping(bundle.get("provider"), "provider")
                    if set(provider) != {"instances"}:
                        raise LiveCollectorError(
                            "collector provider skeleton is not exact"
                        )
                    provider["url"] = _FIXED_URLS[proof_id]["redemption"].rsplit(
                        "/x402/v2/redemptions", 1
                    )[0]
                    provider["deployment_id"] = projected["deployment_id"]
                    provider["image_digest"] = identity["image_digest"]
                _set_path(bundle, target or (), projected)
            elif acquisition_id == "runtime_before_restart":
                if "service_image_digest" in bundle:
                    raise LiveCollectorError(
                        "collector plan pre-populated service image identity"
                    )
                bundle["service_image_digest"] = identity["image_digest"]
            continue_row = {
                "acquisition_id": acquisition_id,
                "transport": kind,
                "request_sha256": hashlib.sha256(request_material).hexdigest(),
                "response_sha256": hashlib.sha256(response_material).hexdigest(),
                "observed_at": observed_at,
            }
            acquisitions.append(continue_row)
            continue
        if kind == "docker_restart":
            before = runtime_identities.get("runtime_before_restart")
            if before is None:
                raise LiveCollectorError("restart lacks a bound before identity")
            restarted_identity, raw = restart_acquire(proof_id, before)
            observed_at = str(restarted_identity["observed_at"])
            request_material = _canonical(
                {
                    "project": "concordia",
                    "service": _SERVICE_NAMES[proof_id],
                    "container_id": before["container_id"],
                }
            )
            response_material = raw
            acquisitions.append(
                {
                    "acquisition_id": acquisition_id,
                    "transport": kind,
                    "request_sha256": hashlib.sha256(request_material).hexdigest(),
                    "response_sha256": hashlib.sha256(response_material).hexdigest(),
                    "observed_at": observed_at,
                }
            )
            continue

        if kind == "sqlite_backup":
            if acquisition_id in sqlite_snapshots:
                raw, observed_at = sqlite_snapshots[acquisition_id]
            else:
                raw, observed_at = sqlite_acquire(proof_id)
                sqlite_snapshots[acquisition_id] = (raw, observed_at)
            request_material = _canonical(
                {
                    "database": (
                        "safepay-provider-ledger"
                        if proof_id == "safepay_v2"
                        else "x402-official-ledger"
                    ),
                    "method": "sqlite-online-backup",
                }
            )
            response_material = raw
            snapshot: dict[str, Any] = {
                "sqlite_backup_base64": _b64(raw),
                "observed_at": observed_at,
            }
            if proof_id == "official_x402_settlement_v1":
                runtime_key = (
                    "runtime_before_restart"
                    if acquisition_id == "journal_after_first_release"
                    else "runtime_after_restart"
                )
                snapshot["service_instance_id"] = runtime_identities[runtime_key][
                    "service_instance_id"
                ]
            if target is not None:
                _set_path(bundle, target, snapshot)
        elif kind == "sqlite_row":
            if acquisition_id == "facilitator_settle":
                if "journal_after_first_release" not in sqlite_snapshots:
                    raise LiveCollectorError(
                        "facilitator settlement lacks its direct journal snapshot"
                    )
                if token is None:
                    raise LiveCollectorError(
                        "facilitator settlement lacks its token reflection guard"
                    )
                raw, snapshot_observed_at = sqlite_snapshots[
                    "journal_after_first_release"
                ]
                observed, request_material, response_material = (
                    _facilitator_settle_from_backup(
                        raw,
                        request=_mapping(
                            requests.get(acquisition_id),
                            "planned facilitator settle request",
                        ),
                        authorization_secret=token,
                    )
                )
                wire_observations[acquisition_id] = dict(observed)
                _set_path(
                    bundle,
                    target or (),
                    _exchange_for_bundle(
                        proof_id,
                        acquisition_id,
                        observed,
                    ),
                )
                # The transcript attests when the durable rows were directly
                # acquired; the embedded exchange retains the earlier
                # journaled upstream response time.
                observed_at = snapshot_observed_at
                acquisitions.append(
                    {
                        "acquisition_id": acquisition_id,
                        "transport": kind,
                        "request_sha256": hashlib.sha256(
                            request_material
                        ).hexdigest(),
                        "response_sha256": hashlib.sha256(
                            response_material
                        ).hexdigest(),
                        "observed_at": observed_at,
                    }
                )
                continue
            snapshot_key = (
                "journal_after_first_release"
                if acquisition_id == "fulfillment_first_row"
                else "journal_after_restart"
            )
            if snapshot_key not in sqlite_snapshots:
                raise LiveCollectorError(
                    "fulfillment row lacks its directly captured journal snapshot"
                )
            raw, observed_at = sqlite_snapshots[snapshot_key]
            row_raw = _fulfillment_row_from_backup(
                raw,
                imported=_mapping(
                    bundle.get("imported_authorization"),
                    "imported authorization",
                ),
            )
            request_material = _canonical(
                {"table": "x402_fulfillments", "key": "signed_payment_payload_hash"}
            )
            response_material = row_raw
            runtime_key = (
                "runtime_before_restart"
                if acquisition_id == "fulfillment_first_row"
                else "runtime_after_restart"
            )
            _set_path(
                bundle,
                target or (),
                {
                    "row_canonical_json_base64": _b64(row_raw),
                    "observed_at": observed_at,
                    "service_instance_id": runtime_identities[runtime_key][
                        "service_instance_id"
                    ],
                },
            )
        else:
            url = _fixed_url(proof_id, acquisition_id, bundle)
            auth: bytes | None = None
            polled_response_material: bytes | None = None
            if acquisition_id.startswith("wcspr_"):
                if acquisition_id == "wcspr_post_settle":
                    _require_shared_settlement_finality(wire_observations)
                observed = _wcspr_readback(
                    acquisition_id=acquisition_id,
                    url=url,
                    http_acquire=http_acquire,
                )
            else:
                request = (
                    {
                        "method": "GET",
                        "body_base64": "",
                        "headers": {"accept": "application/json"},
                    }
                    if acquisition_id == "service_health_after_restart"
                    else (
                        _mapping(
                            requests[acquisition_id],
                            f"collector request {acquisition_id}",
                        )
                        if acquisition_id in requests
                        else _derived_request(
                            proof_id=proof_id,
                            acquisition_id=acquisition_id,
                            requests=requests,
                            observations=wire_observations,
                        )
                    )
                )
                host = urllib.parse.urlsplit(url).hostname or ""
                if host == "x402-facilitator.cspr.cloud" or host.endswith(
                    ".cspr.cloud"
                ):
                    if token is None:
                        token = secret_acquire(
                            _FACILITATOR_TOKEN_PATH,
                            limit=64 * 1024,
                            label="facilitator token",
                        ).strip()
                        if not token:
                            raise LiveCollectorError("facilitator token is empty")
                    auth = token
                if acquisition_id.endswith("_info_get_status") and acquisition_id.startswith(
                    "settlement_rpc_"
                ):
                    observed = _poll_finalized_settlement_status(
                        acquisition_id=acquisition_id,
                        url=url,
                        request=request,
                        observations=wire_observations,
                        http_acquire=http_acquire,
                        sleep=poll_sleep,
                        authorization_secret=auth,
                    )
                elif acquisition_id == "paid_first_release":
                    if token is None:
                        raise LiveCollectorError(
                            "paid first release lacks its token reflection guard"
                        )
                    observed, polled_response_material = (
                        _poll_paid_first_release(
                            url=url,
                            request=request,
                            http_acquire=http_acquire,
                            sleep=poll_sleep,
                            secrets_to_scan=(token,),
                        )
                    )
                else:
                    observed = http_acquire(
                        url=url, request=request, authorization_secret=auth
                    )
            wire_observations[acquisition_id] = dict(observed)
            observed_at = str(observed["observed_at"])
            request_material = _canonical(
                {
                    "method": observed["method"],
                    "url": observed["url"],
                    "request_body_base64": observed["request_body_base64"],
                    "authorization_present": auth is not None,
                }
            )
            response_material = (
                polled_response_material
                if polled_response_material is not None
                else base64.b64decode(
                    str(observed["response_body_base64"]), validate=True
                )
            )
            if token is not None:
                _assert_no_secret_reflection(
                    response_material
                    + b"\n"
                    + _canonical(observed.get("response_headers", {})),
                    secrets_to_scan=(token,),
                    label=acquisition_id,
                )
            if acquisition_id == "service_health_after_restart":
                if observed.get("response_status") != 200:
                    raise LiveCollectorError(
                        "restarted service health check did not pass"
                    )
            else:
                _set_path(
                    bundle,
                    target or (),
                    _exchange_for_bundle(proof_id, acquisition_id, observed),
                )

        acquisitions.append(
            {
                "acquisition_id": acquisition_id,
                "transport": kind,
                "request_sha256": hashlib.sha256(request_material).hexdigest(),
                "response_sha256": hashlib.sha256(response_material).hexdigest(),
                "observed_at": observed_at,
            }
        )

    # Root identity is collector-derived, not caller supplied.
    if any(
        field in bundle
        for field in ("captured_at", "source_commit", "deployment_commit")
    ):
        raise LiveCollectorError("collector plan pre-populated capture identity")
    bundle["captured_at"] = acquisitions[-1]["observed_at"]
    bundle["source_commit"] = normalized["source_commit"]
    bundle["deployment_commit"] = normalized["deployment_commit"]
    raw_bundle = _canonical(bundle)
    transcript = _canonical(
        {
            "schema_version": WORKER_RESULT_SCHEMA_VERSION,
            "proof_id": proof_id,
            "started_at": acquisitions[0]["observed_at"],
            "ended_at": acquisitions[-1]["observed_at"],
            "acquisitions": acquisitions,
        }
    )
    if len(raw_bundle) > MAX_BUNDLE_BYTES or len(transcript) > MAX_TRANSCRIPT_BYTES:
        raise LiveCollectorError("collector output exceeds its bound")
    if token is not None:
        _assert_no_secret_reflection(
            raw_bundle + transcript,
            secrets_to_scan=(token,),
            label="collector outputs",
        )
    return raw_bundle, transcript


def _build_artifact(proof_id: str, bundle_raw: bytes) -> bytes:
    bundle = _strict_json(bundle_raw, "collector raw bundle", limit=MAX_BUNDLE_BYTES)
    if proof_id == "safepay_v2":
        from scripts.safepay_v2_capture import (
            build_safepay_v2_artifact,
            canonical_artifact_bytes,
        )

        return canonical_artifact_bytes(build_safepay_v2_artifact(bundle))
    from scripts.official_x402_capture import build_official_x402_artifact
    from shared.official_x402_release_adapter import _canonical as adapter_canonical

    return adapter_canonical(build_official_x402_artifact(bundle))


def _worker_arm_binding(
    nonce: bytes,
    *,
    proof_id: str,
    plan_id: str,
    bundle_output: str,
    transcript_output: str,
) -> str:
    if len(nonce) != 32:
        raise LiveCollectorError("BOUND_WORKER_ARM_REQUIRED")
    if (
        proof_id not in _FIXED_PLAN_PATHS
        or plan_id != _FIXED_PLAN_PATHS[proof_id]
        or Path(bundle_output).name != "raw-bundle.json"
        or Path(transcript_output).name != "acquisitions.json"
    ):
        raise LiveCollectorError("BOUND_WORKER_ARM_BINDING_INVALID")
    binding = _canonical(
        {
            "proof_id": proof_id,
            "plan_id": plan_id,
            "bundle_output_name": "raw-bundle.json",
            "transcript_output_name": "acquisitions.json",
        }
    ).rstrip(b"\n")
    return hashlib.sha256(_WORKER_ARM_DOMAIN + nonce + binding).hexdigest()


def _prepare_worker_capability(
    *,
    proof_id: str,
    plan_id: str,
    bundle_output: str,
    transcript_output: str,
) -> tuple[int, str]:
    """Create the one-use descriptor required by the parent/worker protocol.

    This closes accidental or direct-CLI invocation of the hidden worker.  It
    is not an authentication boundary against a malicious local process able
    to execute arbitrary Python and construct its own pipe and digest.
    """
    nonce = bytearray(os.urandom(32))
    read_descriptor = -1
    write_descriptor = -1
    try:
        read_descriptor, write_descriptor = os.pipe()
        for descriptor in (read_descriptor, write_descriptor):
            os.set_inheritable(descriptor, False)
            fcntl.fcntl(
                descriptor,
                fcntl.F_SETFD,
                fcntl.fcntl(descriptor, fcntl.F_GETFD) | fcntl.FD_CLOEXEC,
            )
        written = 0
        while written < len(nonce):
            count = os.write(write_descriptor, nonce[written:])
            if count <= 0:
                raise LiveCollectorError("worker capability pipe write failed")
            written += count
        digest = _worker_arm_binding(
            bytes(nonce),
            proof_id=proof_id,
            plan_id=plan_id,
            bundle_output=bundle_output,
            transcript_output=transcript_output,
        )
    except BaseException:
        if read_descriptor >= 0:
            os.close(read_descriptor)
        raise
    finally:
        if write_descriptor >= 0:
            os.close(write_descriptor)
        for index in range(len(nonce)):
            nonce[index] = 0
    return read_descriptor, digest


def _inherited_fifo_descriptors() -> tuple[int, ...]:
    directory = Path("/dev/fd" if sys.platform == "darwin" else "/proc/self/fd")
    try:
        names = tuple(entry.name for entry in directory.iterdir())
    except OSError as exc:
        raise LiveCollectorError("BOUND_WORKER_ARM_DESCRIPTOR_SCAN_FAILED") from exc
    values: list[int] = []
    for name in names:
        if not name.isdecimal():
            continue
        descriptor = int(name)
        if descriptor <= 2:
            continue
        try:
            metadata = os.fstat(descriptor)
            flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        except OSError:
            continue
        if (
            stat.S_ISFIFO(metadata.st_mode)
            and flags & os.O_ACCMODE == os.O_RDONLY
        ):
            values.append(descriptor)
    return tuple(sorted(values))


def _consume_worker_capability(
    *,
    descriptor: object,
    expected_digest: object,
    proof_id: str,
    plan_id: str,
    bundle_output: str,
    transcript_output: str,
) -> None:
    if (
        type(descriptor) is not int
        or descriptor <= 2
        or type(expected_digest) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
        or _inherited_fifo_descriptors() != (descriptor,)
    ):
        raise LiveCollectorError("BOUND_WORKER_ARM_REQUIRED")
    nonce = bytearray()
    try:
        metadata = os.fstat(descriptor)
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        if (
            not stat.S_ISFIFO(metadata.st_mode)
            or flags & os.O_ACCMODE != os.O_RDONLY
        ):
            raise LiveCollectorError("BOUND_WORKER_ARM_REQUIRED")
        fcntl.fcntl(
            descriptor,
            fcntl.F_SETFD,
            fcntl.fcntl(descriptor, fcntl.F_GETFD) | fcntl.FD_CLOEXEC,
        )
        os.set_blocking(descriptor, False)
        deadline = time.monotonic() + 1.0
        eof = False
        while len(nonce) <= 32:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready, _, _ = select.select((descriptor,), (), (), remaining)
            if not ready:
                break
            part = os.read(descriptor, 33 - len(nonce))
            if not part:
                eof = True
                break
            nonce.extend(part)
        if len(nonce) != 32 or not eof:
            raise LiveCollectorError("BOUND_WORKER_ARM_REQUIRED")
        actual = _worker_arm_binding(
            bytes(nonce),
            proof_id=proof_id,
            plan_id=plan_id,
            bundle_output=bundle_output,
            transcript_output=transcript_output,
        )
        if not hmac.compare_digest(actual, expected_digest):
            raise LiveCollectorError("BOUND_WORKER_ARM_REQUIRED")
    except OSError as exc:
        raise LiveCollectorError("BOUND_WORKER_ARM_REQUIRED") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
        for index in range(len(nonce)):
            nonce[index] = 0


def _worker_main(args: argparse.Namespace) -> int:
    _consume_worker_capability(
        descriptor=args.arm_fd,
        expected_digest=args.arm_digest,
        proof_id=args.proof_id,
        plan_id=args.plan_id,
        bundle_output=args.bundle_output,
        transcript_output=args.transcript_output,
    )
    plan_raw = _read_regular(Path(args.plan), limit=MAX_PLAN_BYTES, label="collector plan")
    plan = _validate_plan_document(
        _strict_json(plan_raw, "collector plan", limit=MAX_PLAN_BYTES)
    )
    if plan.get("proof_id") != args.proof_id:
        raise LiveCollectorError("collector worker proof identity differs")
    bundle_raw, transcript_raw = _collect_worker(plan)
    _write_bound_output(
        Path(args.bundle_output),
        bundle_raw,
        limit=MAX_BUNDLE_BYTES,
        label="raw bundle",
    )
    _write_bound_output(
        Path(args.transcript_output),
        transcript_raw,
        limit=MAX_TRANSCRIPT_BYTES,
        label="acquisition transcript",
    )
    sys.stdout.write(
        json.dumps(
            {
                "schema_version": WORKER_RESULT_SCHEMA_VERSION,
                "proof_id": plan["proof_id"],
                "transcript_sha256": hashlib.sha256(transcript_raw).hexdigest(),
            },
            sort_keys=True,
        )
        + "\n"
    )
    return 0


def _immutable_plan_binding(
    root: Path,
    proof_id: str,
    plan_path: Path,
    plan_raw: bytes,
) -> str:
    from shared.bound_command import BoundCommandError, _run_bound_git

    fixed = _fixed_plan_path(root, proof_id)
    try:
        if plan_path.resolve(strict=True) != fixed.resolve(strict=True):
            raise LiveCollectorError("collector plan must use its fixed path")
    except OSError as exc:
        raise LiveCollectorError("collector plan fixed path is unavailable") from exc
    relative = _FIXED_PLAN_PATHS[proof_id]
    try:
        first_result = _run_bound_git(
            root,
            (
                "log",
                "--diff-filter=A",
                "--format=%H",
                "--reverse",
                "--",
                relative,
            ),
        )
        latest_result = _run_bound_git(
            root, ("log", "-1", "--format=%H", "--", relative)
        )
        first_rows = first_result.stdout.decode("ascii").splitlines()
        latest = latest_result.stdout.decode("ascii").strip()
        if len(first_rows) != 1 or first_rows[0] != latest:
            raise LiveCollectorError("collector plan is not immutable first-add data")
        committed = _run_bound_git(
            root,
            ("show", f"{latest}:{relative}"),
            stdout_limit=MAX_PLAN_BYTES + 1,
        ).stdout
    except (BoundCommandError, UnicodeDecodeError) as exc:
        raise LiveCollectorError("collector plan Git binding is unavailable") from exc
    if _HEX40.fullmatch(latest) is None or committed != plan_raw:
        raise LiveCollectorError("collector plan differs from immutable Git bytes")
    return latest


def _load_collector_plan(
    root: Path,
    proof_id: str,
) -> tuple[Path, bytes, dict[str, Any], str, str]:
    plan = _fixed_plan_path(root, proof_id)
    plan_raw = _read_regular(plan, limit=MAX_PLAN_BYTES, label="collector plan")
    plan_document = _validate_plan_document(
        _strict_json(plan_raw, "collector plan", limit=MAX_PLAN_BYTES)
    )
    if plan_document.get("proof_id") != proof_id:
        raise LiveCollectorError("collector plan proof identity differs")
    plan_commit = _immutable_plan_binding(root, proof_id, plan, plan_raw)
    request_plan_sha256 = hashlib.sha256(
        _canonical(plan_document["requests"])
    ).hexdigest()
    return plan, plan_raw, plan_document, plan_commit, request_plan_sha256


def _collector_command_environment(
    source: Mapping[str, str],
) -> dict[str, str]:
    """Remove daemon-routing state the fixed worker neither needs nor accepts."""

    result = dict(source)
    result.pop("DOCKER_HOST", None)
    return result


def _execute_live_capture(
    *,
    root: Path,
    proof_id: str,
    plan: Path,
    plan_raw: bytes,
    plan_commit: str,
) -> int:
    # Imports are intentionally outside the bound worker. The worker itself is
    # standalone and obtains the bytes; this wrapper binds its source/runtime
    # identity and descriptor-safe outputs.
    from shared.bound_command import (
        PrivateOutputSpec,
        _run_bound_git,
        run_bound_command,
    )
    from shared.live_collector_provenance import (
        COLLECTOR_RUNNER_PATH,
        LIVE_COLLECTOR_ARTIFACT_PATHS,
        LIVE_COLLECTOR_PLAN_PATHS,
        LIVE_COLLECTOR_RAW_PATHS,
        LIVE_COLLECTOR_RECEIPT_PATHS,
        build_collector_receipt,
    )
    from shared.release_manifest import (
        _create_capture_batch_once,
        _host_toolchain_binding,
        _require_clean_worktree,
        _sanitized_command_environment,
        _verifier_source_tree_sha256,
        _verifier_tool_commit,
    )

    authority, host_bound, _projection = _host_toolchain_binding(root)
    runner = root / COLLECTOR_RUNNER_PATH
    plan_id = LIVE_COLLECTOR_PLAN_PATHS[proof_id]
    read_descriptor, arm_digest = _prepare_worker_capability(
        proof_id=proof_id,
        plan_id=plan_id,
        bundle_output="raw-bundle.json",
        transcript_output="acquisitions.json",
    )
    # The worker addresses the fixed Docker socket directly and must not inherit
    # a caller-selectable daemon endpoint.  The broader release collector uses
    # one fixed DOCKER_HOST value, but this worker receives no daemon override.
    command_environment = _collector_command_environment(
        _sanitized_command_environment()
    )
    try:
        result = run_bound_command(
            cwd=root,
            tool_id="python",
            argv=(
                "python",
                runner.as_posix(),
                "_worker",
                "--proof-id",
                proof_id,
                "--plan-id",
                plan_id,
                "--arm-fd",
                str(read_descriptor),
                "--arm-digest",
                arm_digest,
                plan.as_posix(),
                "raw-bundle.json",
                "acquisitions.json",
            ),
            env=command_environment,
            stdout_limit=1024 * 1024,
            stderr_limit=1024 * 1024,
            timeout_s=900,
            accepted_authority=authority,
            command_asset_root=root / "scripts",
            bound_data_inputs=(plan,),
            private_output_specs=(
                PrivateOutputSpec(12, "raw-bundle.json", MAX_BUNDLE_BYTES),
                PrivateOutputSpec(13, "acquisitions.json", MAX_TRANSCRIPT_BYTES),
            ),
            inherited_private_descriptor=read_descriptor,
        )
    finally:
        try:
            os.close(read_descriptor)
        except OSError:
            pass
    outputs = {item.name: item for item in result.private_outputs}
    if set(outputs) != {"raw-bundle.json", "acquisitions.json"}:
        raise LiveCollectorError("bound collector output inventory differs")
    artifact_raw = _build_artifact(proof_id, outputs["raw-bundle.json"].raw)
    transcript = _strict_json(
        outputs["acquisitions.json"].raw,
        "acquisition transcript",
        limit=MAX_TRANSCRIPT_BYTES,
    )
    if (
        transcript.get("schema_version") != WORKER_RESULT_SCHEMA_VERSION
        or transcript.get("proof_id") != proof_id
        or type(transcript.get("acquisitions")) is not list
    ):
        raise LiveCollectorError("acquisition transcript identity differs")

    runner_commit_result = _run_bound_git(
        root, ("log", "-1", "--format=%H", "--", COLLECTOR_RUNNER_PATH)
    )
    runner_commit = runner_commit_result.stdout.decode("ascii").strip()
    if _HEX40.fullmatch(runner_commit) is None:
        raise LiveCollectorError("collector runner commit is unavailable")
    runner_raw = _run_bound_git(
        root, ("show", f"{runner_commit}:{COLLECTOR_RUNNER_PATH}")
    ).stdout
    assembler_commit = _verifier_tool_commit(root)
    assembler_tree_sha256 = _verifier_source_tree_sha256(root, assembler_commit)
    receipt = build_collector_receipt(
        proof_id=proof_id,
        started_at=str(transcript["started_at"]),
        ended_at=str(transcript["ended_at"]),
        runner_path=COLLECTOR_RUNNER_PATH,
        runner_commit=runner_commit,
        runner_sha256=hashlib.sha256(runner_raw).hexdigest(),
        plan_path=LIVE_COLLECTOR_PLAN_PATHS[proof_id],
        plan_commit=plan_commit,
        plan_sha256=hashlib.sha256(plan_raw).hexdigest(),
        assembler_commit=assembler_commit,
        assembler_source_tree_sha256=assembler_tree_sha256,
        host_authority_sha256=host_bound.sha256,
        tool_identity=result.tool_identity,
        command_assets=result.command_assets,
        raw_bundle_path=LIVE_COLLECTOR_RAW_PATHS[proof_id],
        raw_bundle_bytes=outputs["raw-bundle.json"].raw,
        artifact_path=LIVE_COLLECTOR_ARTIFACT_PATHS[proof_id],
        artifact_bytes=artifact_raw,
        acquisitions=transcript["acquisitions"],
    )
    receipt_raw = _canonical(receipt)
    # The bound worker is confined to descriptor outputs. Recheck the tree
    # before publication so unbound writes can never be silently discarded.
    _require_clean_worktree(root)
    _create_capture_batch_once(
        root,
        {
            LIVE_COLLECTOR_RAW_PATHS[proof_id]: outputs["raw-bundle.json"].raw,
            LIVE_COLLECTOR_ARTIFACT_PATHS[proof_id]: artifact_raw,
            LIVE_COLLECTOR_RECEIPT_PATHS[proof_id]: receipt_raw,
        },
    )
    sys.stdout.write(
        json.dumps(
            {
                "status": "captured",
                "proof_id": proof_id,
                "receipt_path": LIVE_COLLECTOR_RECEIPT_PATHS[proof_id],
            },
            sort_keys=True,
        )
        + "\n"
    )
    return 0


def _collect_main(args: argparse.Namespace) -> int:
    from shared.live_collector_provenance import (
        LIVE_COLLECTOR_ARTIFACT_PATHS,
        LIVE_COLLECTOR_PLAN_PATHS,
        LIVE_COLLECTOR_RAW_PATHS,
        LIVE_COLLECTOR_RECEIPT_PATHS,
    )
    from shared.release_manifest import (
        ReleaseManifestError,
        _preflight_outputs_absent,
        _recover_capture_publication,
        _repository_release_lock,
        _require_clean_worktree,
        _require_repository,
    )

    if bool(args.submit) == bool(args.dry_run):
        raise LiveCollectorError("EXPLICIT_MODE_REQUIRED: choose --dry-run or --submit")
    root = Path(args.repository_root).resolve(strict=True)
    proof_id = str(args.proof_id)
    if proof_id not in LIVE_COLLECTOR_RECEIPT_PATHS:
        raise LiveCollectorError("collector proof identity is unsupported")

    if args.dry_run:
        _, plan_raw, plan_document, _, request_plan_sha256 = _load_collector_plan(
            root,
            proof_id,
        )
        sys.stdout.write(
            json.dumps(
                {
                    "status": "validated",
                    "mode": "dry_run",
                    "proof_id": proof_id,
                    "plan_path": LIVE_COLLECTOR_PLAN_PATHS[proof_id],
                    "plan_sha256": hashlib.sha256(plan_raw).hexdigest(),
                    "request_plan_sha256": request_plan_sha256,
                },
                sort_keys=True,
            )
            + "\n"
        )
        return 0

    lock_descriptor: int | None = None
    try:
        _require_repository(root)
        lock_descriptor = _repository_release_lock(root)
        recovery = _recover_capture_publication(root)
        if recovery != "none":
            raise LiveCollectorError(
                "CAPTURE_RECOVERY_REQUIRED: recovered an interrupted release operation"
            )
        _require_clean_worktree(root)
        plan, plan_raw, _plan_document, plan_commit, _request_sha = (
            _load_collector_plan(root, proof_id)
        )
        _preflight_outputs_absent(
            root,
            (
                LIVE_COLLECTOR_RAW_PATHS[proof_id],
                LIVE_COLLECTOR_ARTIFACT_PATHS[proof_id],
                LIVE_COLLECTOR_RECEIPT_PATHS[proof_id],
            ),
        )
        return _execute_live_capture(
            root=root,
            proof_id=proof_id,
            plan=plan,
            plan_raw=plan_raw,
            plan_commit=plan_commit,
        )
    except ReleaseManifestError as exc:
        raise LiveCollectorError("collector release preflight failed closed") from exc
    finally:
        if lock_descriptor is not None:
            os.close(lock_descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    collect = subparsers.add_parser("collect")
    collect.add_argument("--repository-root", required=True)
    collect.add_argument(
        "--proof-id",
        required=True,
        choices=("safepay_v2", "official_x402_settlement_v1"),
    )
    modes = collect.add_mutually_exclusive_group()
    modes.add_argument("--dry-run", action="store_true")
    modes.add_argument("--submit", action="store_true")
    collect.set_defaults(handler=_collect_main)

    worker = subparsers.add_parser("_worker", help=argparse.SUPPRESS)
    worker.add_argument("--proof-id", required=True)
    worker.add_argument("--plan-id", required=True)
    worker.add_argument("--arm-fd", required=True, type=int)
    worker.add_argument("--arm-digest", required=True)
    worker.add_argument("plan")
    worker.add_argument("bundle_output")
    worker.add_argument("transcript_output")
    worker.set_defaults(handler=_worker_main)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (LiveCollectorError, OSError, sqlite3.Error) as exc:
        sys.stderr.write(
            json.dumps(
                {"status": "refused", "code": "LIVE_COLLECTOR_REFUSED", "error": str(exc)},
                sort_keys=True,
            )
            + "\n"
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
