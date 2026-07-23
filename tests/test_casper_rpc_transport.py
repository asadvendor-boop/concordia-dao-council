"""Offline safety tests for the shared pinned Casper JSON-RPC transport."""

from __future__ import annotations

import json
import ssl
from pathlib import Path

import pytest

import shared.casper_rpc_transport as transport
from shared.casper_rpc_transport import (
    PinnedHttpsJsonRpc,
    RpcEndpointPolicyError,
    RpcRemoteError,
    RpcTransportError,
    ValidatedRpcEndpoint,
    parse_rpc_authorization_file_args,
    validate_public_rpc_endpoints,
)


NODE_A = "https://rpc-a.example/rpc"
NODE_B = "https://rpc-b.example/rpc"


def _resolver(host: str) -> tuple[str, ...]:
    return {
        "rpc-a.example": ("8.8.8.8",),
        "rpc-b.example": ("1.1.1.1",),
    }[host]


class _RawSocket:
    def __init__(self) -> None:
        self.closed = False
        self.options: list[tuple[object, ...]] = []

    def setsockopt(self, *values: object) -> None:
        self.options.append(values)

    def close(self) -> None:
        self.closed = True


class _TlsContext:
    def __init__(self) -> None:
        self.server_hostname: str | None = None
        self.raw: object | None = None

    def wrap_socket(self, raw: object, *, server_hostname: str) -> object:
        self.raw = raw
        self.server_hostname = server_hostname
        return raw


def test_pinned_ip_dial_retains_original_tls_sni(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint = ValidatedRpcEndpoint(
        url=NODE_A,
        host="rpc-a.example",
        port=443,
        path="/rpc",
        addresses=("8.8.8.8",),
        pinned_ip="8.8.8.8",
    )
    raw = _RawSocket()
    dialed: list[tuple[object, ...]] = []

    def create_connection(*args: object, **kwargs: object) -> _RawSocket:
        dialed.append((*args, kwargs))
        return raw

    monkeypatch.setattr(transport.socket, "create_connection", create_connection)
    context = _TlsContext()
    connection = transport._PinnedHTTPSConnection(  # noqa: SLF001 - policy unit
        endpoint,
        timeout=7.0,
        context=context,  # type: ignore[arg-type]
    )
    connection.connect()

    assert dialed[0][0] == ("8.8.8.8", 443)
    assert context.server_hostname == "rpc-a.example"
    assert context.raw is raw


class _Response:
    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        content_type: str = "application/json",
        content_length: str = "",
        content_encoding: str = "",
    ) -> None:
        self.body = body
        self.status = status
        self.content_type = content_type
        self.content_length = content_length
        self.content_encoding = content_encoding
        self.read_limits: list[int] = []

    def getheader(self, name: str, default: str = "") -> str:
        return {
            "Content-Type": self.content_type,
            "Content-Length": self.content_length,
            "Content-Encoding": self.content_encoding,
        }.get(name, default)

    def read(self, limit: int) -> bytes:
        self.read_limits.append(limit)
        return self.body[:limit]


class _Connection:
    response: _Response
    requests: list[tuple[object, ...]] = []

    def __init__(self, *_: object, **__: object) -> None:
        pass

    def request(self, *args: object, **kwargs: object) -> None:
        self.requests.append((*args, kwargs))

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        return None


def _client(
    monkeypatch: pytest.MonkeyPatch,
    response: _Response,
    *,
    max_response_bytes: int = 1024,
    authorization_files: dict[str, Path] | None = None,
) -> PinnedHttpsJsonRpc:
    _Connection.response = response
    _Connection.requests = []
    monkeypatch.setattr(transport, "_PinnedHTTPSConnection", _Connection)
    return PinnedHttpsJsonRpc(
        (NODE_A, NODE_B),
        resolver=_resolver,
        max_response_bytes=max_response_bytes,
        ssl_context=ssl.create_default_context(),
        authorization_files=authorization_files,
    )


def test_bounded_read_stops_at_limit_plus_one(monkeypatch: pytest.MonkeyPatch) -> None:
    response = _Response(b"x" * 65)
    client = _client(monkeypatch, response, max_response_bytes=64)

    with pytest.raises(RpcTransportError, match="size limit"):
        client.call(NODE_A, "info_get_status", {}, "bounded")

    assert response.read_limits == [65]

    declared = _Response(b"must-not-be-read", content_length="65")
    client = _client(monkeypatch, declared, max_response_bytes=64)
    with pytest.raises(RpcTransportError, match="size limit"):
        client.call(NODE_A, "info_get_status", {}, "declared")
    assert declared.read_limits == []


@pytest.mark.parametrize(
    ("response", "error_type"),
    [
        (
            _Response(b"reflected-super-secret", status=302),
            RpcTransportError,
        ),
        (
            _Response(
                b'{"jsonrpc":"2.0","id":"x","error":'
                b'{"code":-32001,"message":"reflected-super-secret https://hidden/"}}'
            ),
            RpcRemoteError,
        ),
        (
            _Response(b'{"jsonrpc":"2.0","id":"x","result":{"a":1,"a":2}}'),
            RpcTransportError,
        ),
    ],
)
def test_redirect_remote_error_and_duplicate_keys_fail_without_reflection(
    monkeypatch: pytest.MonkeyPatch,
    response: _Response,
    error_type: type[Exception],
) -> None:
    client = _client(monkeypatch, response)

    with pytest.raises(error_type) as captured:
        client.call(NODE_A, "info_get_status", {}, "x")

    message = str(captured.value)
    assert "reflected-super-secret" not in message
    assert "https://hidden/" not in message
    assert NODE_A not in message
    assert captured.value.__cause__ is None


@pytest.mark.parametrize("constant", ("NaN", "Infinity", "-Infinity"))
def test_non_finite_json_numbers_are_rejected_before_result_consumption(
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
) -> None:
    client = _client(
        monkeypatch,
        _Response(
            f'{{"jsonrpc":"2.0","id":"x","result":{{"value":{constant}}}}}'.encode()
        ),
    )

    with pytest.raises(RpcTransportError, match="invalid JSON") as captured:
        client.call(NODE_A, "info_get_status", {}, "x")

    assert captured.value.__cause__ is None


def test_endpoint_scoped_raw_authorization_file_never_reflects_on_401(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "test-only-cspr-cloud-token"
    token_file = tmp_path / "cspr-cloud-token"
    token_file.write_text(secret + "\n", encoding="ascii")
    token_file.chmod(0o600)
    reflected = _Response(
        f'{{"authorization":"{secret}","scheme":"Bearer {secret}"}}'.encode(),
        status=401,
    )
    client = _client(
        monkeypatch,
        reflected,
        authorization_files={NODE_B: token_file},
    )

    with pytest.raises(RpcTransportError) as captured:
        client.call(NODE_B, "info_get_status", {}, "reflected")

    request = _Connection.requests[0]
    headers = request[-1]["headers"]
    assert headers["Authorization"] == secret
    assert not headers["Authorization"].startswith("Bearer ")
    assert reflected.read_limits == []
    assert secret not in str(captured.value)
    assert str(token_file) not in str(captured.value)
    assert captured.value.__cause__ is None

    _Connection.response = _Response(b'{"jsonrpc":"2.0","id":"plain","result":{}}')
    client.call(NODE_A, "info_get_status", {}, "plain")
    plain_headers = _Connection.requests[-1][-1]["headers"]
    assert "Authorization" not in plain_headers


def test_authorization_binding_accepts_only_endpoint_scoped_absolute_files(
    tmp_path: Path,
) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("token", encoding="ascii")
    token_file.chmod(0o600)
    assert parse_rpc_authorization_file_args(
        [f"{NODE_B}={token_file}"],
        [NODE_A, NODE_B],
    ) == {NODE_B: token_file}

    for binding in (
        "token-value-without-file",
        f"https://unknown.example/rpc={token_file}",
        f"{NODE_B}=relative-token-file",
    ):
        with pytest.raises(RpcEndpointPolicyError, match="binding"):
            parse_rpc_authorization_file_args([binding], [NODE_A, NODE_B])


def test_authorization_file_errors_never_disclose_path_or_contents(
    tmp_path: Path,
) -> None:
    secret = "super-secret-reflection-canary"
    unsafe = tmp_path / "unsafe-token"
    unsafe.write_text(secret + "\nsecond-line", encoding="ascii")
    unsafe.chmod(0o600)

    with pytest.raises(RpcEndpointPolicyError) as captured:
        PinnedHttpsJsonRpc(
            (NODE_A, NODE_B),
            resolver=_resolver,
            authorization_files={NODE_B: unsafe},
        )

    assert secret not in str(captured.value)
    assert str(unsafe) not in str(captured.value)
    assert captured.value.__cause__ is None


def test_successful_credentialed_response_cannot_reflect_loaded_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "test-only-success-reflection-canary-4b1a"
    token_file = tmp_path / "cspr-cloud-token"
    token_file.write_text(secret + "\n", encoding="ascii")
    token_file.chmod(0o600)
    client = _client(
        monkeypatch,
        _Response(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "success-reflection",
                    "result": {
                        "api_version": "2.0.0",
                        "chainspec_name": "casper-test",
                        "ignored": {"authorization": f"Bearer {secret}"},
                    },
                }
            ).encode("ascii")
        ),
        authorization_files={NODE_B: token_file},
    )

    with pytest.raises(RpcTransportError) as captured:
        client.call(NODE_B, "info_get_status", {}, "success-reflection")

    assert secret not in str(captured.value)
    assert str(token_file) not in str(captured.value)
    assert captured.value.__cause__ is None


def test_success_response_is_projected_to_method_schema_before_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client(
        monkeypatch,
        _Response(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "projected",
                    "trace": "must-not-cross-boundary",
                    "result": {
                        "api_version": "2.0.0",
                        "chainspec_name": "casper-test",
                        "last_added_block_info": {
                            "hash": "ab" * 32,
                            "height": 7,
                            "state_root_hash": "cd" * 32,
                            "ignored": "must-not-cross-boundary",
                        },
                        "ignored": "must-not-cross-boundary",
                    },
                }
            ).encode("ascii")
        ),
    )

    response = client.call(NODE_A, "info_get_status", {}, "projected")

    assert response == {
        "jsonrpc": "2.0",
        "id": "projected",
        "result": {
            "api_version": "2.0.0",
            "chainspec_name": "casper-test",
            "last_added_block_info": {
                "hash": "ab" * 32,
                "height": 7,
                "state_root_hash": "cd" * 32,
            },
        },
    }


@pytest.mark.parametrize(
    "method",
    (
        "info_get_status",
        "info_get_deploy",
        "chain_get_block",
        "chain_get_state_root_hash",
        "query_global_state",
        "state_get_dictionary_item",
        "query_balance_details",
        "chain_get_block_transfers",
        "account_put_deploy",
    ),
)
def test_every_allowed_method_projects_away_unrecognized_result_fields(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
) -> None:
    client = _client(
        monkeypatch,
        _Response(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": method,
                    "result": {
                        "api_version": "2.0.0",
                        "unrecognized": {"must": "not cross evidence boundary"},
                    },
                }
            ).encode("ascii")
        ),
    )

    response = client.call(
        NODE_A,
        method,
        {},
        method,
        allow_submit=method == "account_put_deploy",
    )
    assert response == {
        "jsonrpc": "2.0",
        "id": method,
        "result": {"api_version": "2.0.0"},
    }


def test_named_result_wrapper_is_projected_without_changing_rpc_dialect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client(
        monkeypatch,
        _Response(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "wrapped",
                    "result": {
                        "name": "info_get_status_result",
                        "value": {
                            "api_version": "2.0.0",
                            "chainspec_name": "casper-test",
                            "unrecognized": "drop-me",
                        },
                    },
                }
            ).encode("ascii")
        ),
    )

    assert client.call(NODE_A, "info_get_status", {}, "wrapped") == {
        "jsonrpc": "2.0",
        "id": "wrapped",
        "result": {
            "name": "info_get_status_result",
            "value": {
                "api_version": "2.0.0",
                "chainspec_name": "casper-test",
            },
        },
    }


def test_mutation_needs_explicit_allow_submit_and_state_reads_are_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ok = _Response(b'{"jsonrpc":"2.0","id":"x","result":{}}')
    client = _client(monkeypatch, ok)

    with pytest.raises(RpcEndpointPolicyError, match="explicit submit"):
        client.call(
            NODE_A,
            "account_put_deploy",
            {"deploy": {}},
            "x",
        )
    assert _Connection.requests == []

    for method in (
        "chain_get_state_root_hash",
        "query_global_state",
        "state_get_dictionary_item",
    ):
        _Connection.response = _Response(
            f'{{"jsonrpc":"2.0","id":"{method}","result":{{}}}}'.encode()
        )
        assert client.call(NODE_A, method, {}, method)["result"] == {}

    _Connection.response = ok
    assert (
        client.call(
            NODE_A,
            "account_put_deploy",
            {"deploy": {}},
            "x",
            allow_submit=True,
        )["result"]
        == {}
    )


def test_endpoints_are_exactly_two_public_disjoint_canonical_dns_hosts() -> None:
    first, second = validate_public_rpc_endpoints((NODE_A, NODE_B), resolver=_resolver)
    assert first.pinned_ip == "8.8.8.8"
    assert second.pinned_ip == "1.1.1.1"

    with pytest.raises(RpcEndpointPolicyError):
        validate_public_rpc_endpoints((NODE_A,), resolver=_resolver)
    with pytest.raises(RpcEndpointPolicyError):
        validate_public_rpc_endpoints((NODE_A, NODE_A), resolver=_resolver)


@pytest.mark.parametrize(
    "forbidden_address",
    (
        "224.0.0.1",
        "ff02::1",
        "192.0.2.1",
        "0.0.0.0",
        "127.0.0.1",
        "169.254.1.1",
        "10.0.0.1",
    ),
)
def test_endpoint_policy_rejects_every_non_unicast_public_address_class(
    forbidden_address: str,
) -> None:
    def resolver(host: str) -> tuple[str, ...]:
        return (forbidden_address,) if host == "rpc-a.example" else ("1.1.1.1",)

    with pytest.raises(RpcEndpointPolicyError, match="non-public"):
        validate_public_rpc_endpoints((NODE_A, NODE_B), resolver=resolver)
