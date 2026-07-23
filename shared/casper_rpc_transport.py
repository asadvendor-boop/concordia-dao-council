"""URL-credential-free, DNS-pinned HTTPS transport for Casper JSON-RPC.

The treasury release operator uses exactly two independently addressed public
RPC endpoints.  Validation happens before any request and pins the resolved
public IPs for the lifetime of the transport, preventing redirects and DNS
rebinding between policy validation and connection establishment.  A URL may
be bound to a raw Authorization token loaded from an owner-private file; no
credential is accepted in a URL or command argument.

Distinct hostnames and disjoint pinned IPs provide transport corroboration,
not proof of administrative independence.  That stronger operational claim
must be established separately by the release manifest.

This module deliberately never includes response bodies in exceptions.  A
Casper node can reflect request data in an error response, so logging a body is
not safe even when the caller believes its request was credential-free.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

from shared.secure_secret_file import SecureSecretFileError, read_secure_secret_file


MAX_RPC_REQUEST_BYTES = 4 * 1024 * 1024
MAX_RPC_RESPONSE_BYTES = 32 * 1024 * 1024
RPC_TIMEOUT_SECONDS = 20.0

_READ_METHODS = frozenset(
    {
        "info_get_status",
        "info_get_deploy",
        "chain_get_block",
        "chain_get_state_root_hash",
        "query_global_state",
        "state_get_dictionary_item",
        "query_balance_details",
        "chain_get_block_transfers",
    }
)
_WRITE_METHOD = "account_put_deploy"


class RpcEndpointPolicyError(ValueError):
    """An RPC URL or its resolved addresses violate the release policy."""


class RpcTransportError(RuntimeError):
    """A public RPC request did not yield a bounded valid JSON-RPC response."""


class RpcRemoteError(RpcTransportError):
    """A node returned JSON-RPC error metadata (never its message/body)."""

    def __init__(self, code: int | None):
        super().__init__("public RPC returned an error response")
        self.code = code


@dataclass(frozen=True, slots=True)
class ValidatedRpcEndpoint:
    url: str
    host: str
    port: int
    path: str
    addresses: tuple[str, ...]
    pinned_ip: str


Resolver = Callable[[str], Iterable[str]]
MAX_AUTHORIZATION_BYTES = 4_096

_RESULT_FIELDS: dict[str, tuple[str, ...]] = {
    "info_get_status": (
        "api_version",
        "chainspec_name",
        "last_added_block_info",
        "lastAddedBlockInfo",
    ),
    "info_get_deploy": (
        "api_version",
        "deploy",
        "execution_info",
        "execution_results",
    ),
    "chain_get_block": ("api_version", "block", "block_with_signatures"),
    "chain_get_state_root_hash": ("api_version", "state_root_hash"),
    "query_global_state": (
        "api_version",
        "block_header",
        "stored_value",
        "merkle_proof",
    ),
    "state_get_dictionary_item": (
        "api_version",
        "dictionary_key",
        "stored_value",
        "merkle_proof",
    ),
    "query_balance_details": (
        "api_version",
        "total_balance",
        "available_balance",
        "total_balance_proof",
        "holds",
        "balance",
    ),
    "chain_get_block_transfers": ("api_version", "block_hash", "transfers"),
    "account_put_deploy": ("api_version", "deploy_hash", "transaction_hash"),
}

_STATUS_BLOCK_FIELDS = (
    "hash",
    "height",
    "state_root_hash",
    "era_id",
    "timestamp",
    "protocol_version",
)

_BLOCK_FIELDS = ("hash", "header", "body", "Version1", "Version2")
_BLOCK_HEADER_FIELDS = (
    "parent_hash",
    "state_root_hash",
    "stateRootHash",
    "body_hash",
    "random_bit",
    "accumulated_seed",
    "era_end",
    "timestamp",
    "era_id",
    "height",
    "protocol_version",
    "proposer",
)
_BLOCK_BODY_FIELDS = (
    "proposer",
    "deploy_hashes",
    "transfer_hashes",
    "transactions",
    "rewarded_signatures",
)
_DEPLOY_FIELDS = ("hash", "header", "payment", "session", "approvals")
_EXECUTION_INFO_FIELDS = ("block_hash", "block_height", "execution_result")


def _is_strictly_public_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Return true only for ordinary globally routed unicast addresses."""

    return bool(
        address.is_global
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_private
    )


def _default_resolver(host: str) -> tuple[str, ...]:
    try:
        records = socket.getaddrinfo(
            host,
            443,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise RpcEndpointPolicyError(
            "public RPC hostname could not be resolved"
        ) from exc
    return tuple(sorted({str(record[4][0]) for record in records}))


def _public_addresses(host: str, resolver: Resolver) -> tuple[str, ...]:
    try:
        raw = tuple(resolver(host))
    except RpcEndpointPolicyError:
        raise
    except Exception as exc:
        raise RpcEndpointPolicyError(
            "public RPC hostname could not be resolved"
        ) from exc
    if not raw:
        raise RpcEndpointPolicyError("public RPC hostname has no addresses")
    addresses: list[str] = []
    for value in raw:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise RpcEndpointPolicyError(
                "public RPC DNS returned an invalid address"
            ) from exc
        if not _is_strictly_public_address(address):
            raise RpcEndpointPolicyError("public RPC DNS returned a non-public address")
        canonical = address.compressed
        if canonical not in addresses:
            addresses.append(canonical)
    return tuple(sorted(addresses))


def validate_public_rpc_endpoints(
    urls: Iterable[str],
    *,
    resolver: Resolver | None = None,
) -> tuple[ValidatedRpcEndpoint, ValidatedRpcEndpoint]:
    """Validate and pin exactly two distinct credential-free HTTPS endpoints."""

    candidates = tuple(urls)
    if len(candidates) != 2:
        raise RpcEndpointPolicyError("exactly two public RPC endpoints are required")
    resolve = resolver or _default_resolver
    validated: list[ValidatedRpcEndpoint] = []
    for raw_url in candidates:
        if type(raw_url) is not str or not raw_url:
            raise RpcEndpointPolicyError("public RPC URL is invalid")
        try:
            parts = urlsplit(raw_url)
            port = parts.port
        except ValueError as exc:
            raise RpcEndpointPolicyError("public RPC URL is invalid") from exc
        host = parts.hostname
        if (
            parts.scheme != "https"
            or host is None
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or parts.path != "/rpc"
            or port not in (None, 443)
        ):
            raise RpcEndpointPolicyError(
                "public RPC URL must be credential-free HTTPS on /rpc"
            )
        normalized_host = host.casefold().rstrip(".")
        if (
            not normalized_host
            or not normalized_host.isascii()
            or normalized_host in {"localhost", "localhost.localdomain"}
            or normalized_host.endswith(".local")
            or "." not in normalized_host
        ):
            raise RpcEndpointPolicyError("public RPC hostname is not public DNS")
        try:
            ipaddress.ip_address(normalized_host.strip("[]"))
        except ValueError:
            pass
        else:
            raise RpcEndpointPolicyError("public RPC endpoint must use a DNS hostname")
        addresses = _public_addresses(normalized_host, resolve)
        canonical_url = f"https://{normalized_host}/rpc"
        if canonical_url != raw_url:
            raise RpcEndpointPolicyError("public RPC URL must use canonical form")
        validated.append(
            ValidatedRpcEndpoint(
                url=canonical_url,
                host=normalized_host,
                port=443,
                path="/rpc",
                addresses=addresses,
                pinned_ip=addresses[0],
            )
        )
    first, second = validated
    if first.host == second.host or first.url == second.url:
        raise RpcEndpointPolicyError("public RPC endpoints must use distinct hosts")
    if set(first.addresses).intersection(second.addresses):
        raise RpcEndpointPolicyError(
            "public RPC endpoints must resolve to disjoint addresses"
        )
    return first, second


def parse_rpc_authorization_file_args(
    values: Sequence[str],
    endpoints: Sequence[str],
) -> dict[str, Path]:
    """Parse public ``URL=/absolute/file`` bindings without accepting tokens."""

    allowed = set(endpoints)
    result: dict[str, Path] = {}
    for value in values:
        if type(value) is not str or value.count("=") != 1:
            raise RpcEndpointPolicyError("RPC authorization file binding is invalid")
        endpoint, raw_path = value.split("=", 1)
        path = Path(raw_path)
        if (
            endpoint not in allowed
            or endpoint in result
            or not raw_path
            or not path.is_absolute()
        ):
            raise RpcEndpointPolicyError("RPC authorization file binding is invalid")
        result[endpoint] = path
    return result


def _load_authorization_file(path: Path) -> str:
    """Read one token without following symlinks or reflecting path/content."""

    try:
        raw = read_secure_secret_file(path, max_bytes=MAX_AUTHORIZATION_BYTES)
        token = raw.decode("ascii")
        if token.endswith("\r\n"):
            token = token[:-2]
        elif token.endswith("\n"):
            token = token[:-1]
        if not token or any(not 0x21 <= ord(character) <= 0x7E for character in token):
            raise OSError("invalid credential")
        return token
    except (OSError, SecureSecretFileError, UnicodeDecodeError):
        raise RpcEndpointPolicyError(
            "RPC authorization credential could not be loaded safely"
        ) from None


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that dials a policy-checked IP but retains TLS SNI."""

    def __init__(
        self,
        endpoint: ValidatedRpcEndpoint,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(
            endpoint.host,
            endpoint.port,
            timeout=timeout,
            context=context,
        )
        self._pinned_ip = endpoint.pinned_ip

    def connect(self) -> None:
        try:
            raw = socket.create_connection(
                (self._pinned_ip, self.port),
                self.timeout,
                self.source_address,
            )
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            if getattr(self, "sock", None) is not None:
                self.sock.close()
            raise


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(_: str) -> object:
    raise ValueError("non-finite JSON number")


def _contains_secret(value: object, secrets: Sequence[str]) -> bool:
    if type(value) is str:
        return any(secret in value for secret in secrets)
    if type(value) is list:
        return any(_contains_secret(item, secrets) for item in value)
    if type(value) is dict:
        return any(
            _contains_secret(key, secrets) or _contains_secret(item, secrets)
            for key, item in value.items()
        )
    return False


def _project_fields(value: object, fields: Sequence[str]) -> dict[str, object]:
    if type(value) is not dict:
        raise RpcTransportError("public RPC result schema is invalid")
    return {field: copy.deepcopy(value[field]) for field in fields if field in value}


def _project_block(value: object) -> dict[str, object]:
    block = _project_fields(value, _BLOCK_FIELDS)
    versions = [name for name in ("Version1", "Version2") if name in block]
    if versions:
        if len(versions) != 1 or set(block) != {versions[0]}:
            raise RpcTransportError("public RPC block schema is invalid")
        return {versions[0]: _project_block(block[versions[0]])}
    if "header" in block:
        block["header"] = _project_fields(block["header"], _BLOCK_HEADER_FIELDS)
    if "body" in block:
        block["body"] = _project_fields(block["body"], _BLOCK_BODY_FIELDS)
    return block


def _project_method_result(method: str, value: object) -> dict[str, object]:
    result = _project_fields(value, _RESULT_FIELDS[method])
    if method == "info_get_status":
        for field in ("last_added_block_info", "lastAddedBlockInfo"):
            if field in result:
                result[field] = _project_fields(result[field], _STATUS_BLOCK_FIELDS)
    elif method == "chain_get_block":
        if "block" in result:
            result["block"] = _project_block(result["block"])
        if "block_with_signatures" in result:
            wrapper = _project_fields(
                result["block_with_signatures"],
                ("block", "proofs"),
            )
            if "block" in wrapper:
                wrapper["block"] = _project_block(wrapper["block"])
            result["block_with_signatures"] = wrapper
    elif method == "info_get_deploy":
        if "deploy" in result:
            result["deploy"] = _project_fields(result["deploy"], _DEPLOY_FIELDS)
        if "execution_info" in result:
            execution_info = result["execution_info"]
            if execution_info is None:
                result["execution_info"] = None
            elif type(execution_info) is not dict or set(execution_info) != set(
                _EXECUTION_INFO_FIELDS
            ):
                raise RpcTransportError("public RPC execution schema is invalid")
            else:
                result["execution_info"] = copy.deepcopy(execution_info)
        if "execution_results" in result:
            execution_results = result["execution_results"]
            if type(execution_results) is not list:
                raise RpcTransportError("public RPC result schema is invalid")
            result["execution_results"] = [
                _project_fields(item, ("block_hash", "result"))
                for item in execution_results
            ]
    return result


def _normalize_success_response(
    parsed: dict[str, object],
    *,
    method: str,
    request_id: object,
) -> dict[str, object]:
    raw_result = parsed["result"]
    if type(raw_result) is not dict:
        raise RpcTransportError("public RPC result schema is invalid")
    if "name" in raw_result or "value" in raw_result:
        if (
            set(raw_result) != {"name", "value"}
            or type(raw_result.get("name")) is not str
        ):
            raise RpcTransportError("public RPC result wrapper is invalid")
        result: dict[str, object] = {
            "name": raw_result["name"],
            "value": _project_method_result(method, raw_result["value"]),
        }
    else:
        result = _project_method_result(method, raw_result)
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


class PinnedHttpsJsonRpc:
    """Bounded Casper JSON-RPC client over two prevalidated endpoints."""

    def __init__(
        self,
        endpoints: Iterable[str],
        *,
        resolver: Resolver | None = None,
        timeout_seconds: float = RPC_TIMEOUT_SECONDS,
        max_response_bytes: int = MAX_RPC_RESPONSE_BYTES,
        ssl_context: ssl.SSLContext | None = None,
        authorization_files: Mapping[str, Path] | None = None,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
            or timeout_seconds > 60
        ):
            raise RpcEndpointPolicyError("RPC timeout must be within 0-60 seconds")
        if (
            type(max_response_bytes) is not int
            or not 1 <= max_response_bytes <= MAX_RPC_RESPONSE_BYTES
        ):
            raise RpcEndpointPolicyError("RPC response limit is invalid")
        self._validated = validate_public_rpc_endpoints(endpoints, resolver=resolver)
        self.endpoints = tuple(item.url for item in self._validated)
        self._by_url = {item.url: item for item in self._validated}
        bindings = dict(authorization_files or {})
        if any(type(endpoint) is not str for endpoint in bindings) or set(
            bindings
        ).difference(self.endpoints):
            raise RpcEndpointPolicyError("RPC authorization file binding is invalid")
        self._authorizations = {
            endpoint: _load_authorization_file(Path(path))
            for endpoint, path in bindings.items()
        }
        self._authorization_values = tuple(self._authorizations.values())
        self._timeout = float(timeout_seconds)
        self._max_response = max_response_bytes
        self._ssl_context = ssl_context or ssl.create_default_context()

    def call(
        self,
        endpoint: str,
        method: str,
        params: dict[str, object],
        request_id: object,
        *,
        allow_submit: bool = False,
    ) -> dict[str, object]:
        selected = self._by_url.get(endpoint)
        if selected is None:
            raise RpcEndpointPolicyError("RPC endpoint was not prevalidated")
        if method == _WRITE_METHOD:
            if allow_submit is not True:
                raise RpcEndpointPolicyError(
                    "RPC mutation requires explicit submit authority"
                )
        elif method not in _READ_METHODS or allow_submit:
            raise RpcEndpointPolicyError("RPC method is not allowed by this transport")
        if (
            type(params) is not dict
            or type(request_id) not in (str, int)
            or request_id == ""
        ):
            raise RpcTransportError("RPC request shape is invalid")
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        try:
            body = json.dumps(
                request,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
        except (TypeError, ValueError, UnicodeEncodeError) as exc:
            raise RpcTransportError("RPC request is not canonical JSON") from exc
        if len(body) > MAX_RPC_REQUEST_BYTES:
            raise RpcTransportError("RPC request exceeds size limit")

        connection = _PinnedHTTPSConnection(
            selected,
            timeout=self._timeout,
            context=self._ssl_context,
        )
        try:
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "User-Agent": "Concordia-Treasury-Executor/1",
                "Connection": "close",
            }
            authorization = self._authorizations.get(selected.url)
            if authorization is not None:
                # CSPR.cloud requires the token itself, not a Bearer scheme.
                headers["Authorization"] = authorization
            connection.request(
                "POST",
                selected.path,
                body=body,
                headers=headers,
            )
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise RpcTransportError("public RPC redirects are forbidden")
            if response.status != 200:
                raise RpcTransportError("public RPC returned a non-success HTTP status")
            content_type = (
                response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            )
            if content_type not in {"application/json", "application/json-rpc"}:
                raise RpcTransportError("public RPC response is not JSON")
            content_encoding = (
                response.getheader("Content-Encoding", "").strip().lower()
            )
            if content_encoding not in {"", "identity"}:
                raise RpcTransportError("encoded public RPC responses are forbidden")
            content_length = response.getheader("Content-Length", "").strip()
            if content_length:
                if not content_length.isascii() or not content_length.isdecimal():
                    raise RpcTransportError("public RPC content length is invalid")
                if int(content_length) > self._max_response:
                    raise RpcTransportError("public RPC response exceeds size limit")
            raw = response.read(self._max_response + 1)
            if len(raw) > self._max_response:
                raise RpcTransportError("public RPC response exceeds size limit")
        except RpcTransportError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError):
            raise RpcTransportError("public RPC request failed") from None
        finally:
            connection.close()
        try:
            parsed = json.loads(
                raw,
                object_pairs_hook=_reject_duplicate_pairs,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise RpcTransportError("public RPC response is invalid JSON") from None
        if (
            type(parsed) is not dict
            or parsed.get("jsonrpc") != "2.0"
            or parsed.get("id") != request_id
        ):
            raise RpcTransportError("public RPC response identity is invalid")
        if "error" in parsed and parsed["error"] is not None:
            error = parsed["error"]
            code = error.get("code") if type(error) is dict else None
            raise RpcRemoteError(code if type(code) is int else None)
        if "result" not in parsed:
            raise RpcTransportError("public RPC response has no result")
        if self._authorization_values and _contains_secret(
            parsed,
            self._authorization_values,
        ):
            raise RpcTransportError("public RPC response failed secret-safety policy")
        return _normalize_success_response(
            parsed,
            method=method,
            request_id=request_id,
        )


__all__ = [
    "PinnedHttpsJsonRpc",
    "RpcEndpointPolicyError",
    "RpcRemoteError",
    "RpcTransportError",
    "ValidatedRpcEndpoint",
    "parse_rpc_authorization_file_args",
    "validate_public_rpc_endpoints",
]
