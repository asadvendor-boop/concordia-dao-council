from __future__ import annotations

import builtins
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

import gateway.app as gateway_app
import shared.telemetry as telemetry


_VALID_CID = "b" + ("a" * 32)
_DEPLOY_HASH = "d" * 64
_SIGNER = "01" + ("a" * 64)
_SIGNATURE = "01" + ("b" * 128)
_SECRET_DETAIL = "private-host.internal:4318/release-token"


def _signed_deploy() -> dict[str, object]:
    return {
        "hash": _DEPLOY_HASH,
        "approvals": [{"signer": _SIGNER, "signature": _SIGNATURE}],
    }


def test_ipfs_validation_error_is_bounded_at_public_boundary(monkeypatch) -> None:
    async def fail_validation(_cid: str):
        raise ValueError(_SECRET_DETAIL)

    monkeypatch.setattr(gateway_app, "fetch_ipfs_cid", fail_validation)
    client = TestClient(gateway_app.create_app(db_path=":memory:"))

    response = client.get(f"/api/ipfs/{_VALID_CID}")

    assert response.status_code == 400
    assert response.json() == {
        "status": "invalid_cid",
        "error": "invalid_ipfs_cid",
    }
    assert _SECRET_DETAIL not in response.text


def test_ipfs_transport_error_is_bounded_at_public_boundary(monkeypatch) -> None:
    async def fail_transport(_cid: str):
        request = httpx.Request("GET", "https://ipfs.invalid/")
        raise httpx.ConnectError(_SECRET_DETAIL, request=request)

    monkeypatch.setattr(gateway_app, "fetch_ipfs_cid", fail_transport)
    client = TestClient(gateway_app.create_app(db_path=":memory:"))

    response = client.get(f"/api/ipfs/{_VALID_CID}")

    assert response.status_code == 502
    assert response.json() == {
        "status": "unavailable",
        "error": "ipfs_fetch_unavailable",
    }
    assert _SECRET_DETAIL not in response.text


def test_wallet_broadcast_exception_is_bounded_at_public_boundary(monkeypatch) -> None:
    class FailingClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args) -> None:
            return None

        async def post(self, *args, **kwargs):
            raise RuntimeError(_SECRET_DETAIL)

    monkeypatch.setattr(gateway_app.httpx, "AsyncClient", FailingClient)
    client = TestClient(gateway_app.create_app(db_path=":memory:"))

    response = client.post(
        "/api/casper/broadcast-deploy",
        json={"deploy": _signed_deploy()},
    )

    assert response.status_code == 502
    assert response.json() == {
        "status": "failed",
        "deploy_hash": _DEPLOY_HASH,
        "error": "casper_rpc_broadcast_failed",
    }
    assert _SECRET_DETAIL not in response.text


def test_wallet_broadcast_rpc_rejection_does_not_echo_provider_body(
    monkeypatch,
) -> None:
    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, object]:
            return {
                "jsonrpc": "2.0",
                "id": "internal-request",
                "error": {
                    "code": -32000,
                    "message": _SECRET_DETAIL,
                    "data": {"upstream": _SECRET_DETAIL},
                },
            }

    class RejectingClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args) -> None:
            return None

        async def post(self, *args, **kwargs) -> Response:
            return Response()

    monkeypatch.setattr(gateway_app.httpx, "AsyncClient", RejectingClient)
    client = TestClient(gateway_app.create_app(db_path=":memory:"))

    response = client.post(
        "/api/casper/broadcast-deploy",
        json={"deploy": _signed_deploy()},
    )

    assert response.status_code == 400
    assert response.json() == {
        "status": "failed",
        "deploy_hash": _DEPLOY_HASH,
        "error": "casper_rpc_rejected",
    }
    assert _SECRET_DETAIL not in response.text


def test_telemetry_dependency_failure_never_enters_public_status(monkeypatch) -> None:
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "opentelemetry":
            raise ImportError(_SECRET_DETAIL)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.setenv("OTEL_ENABLED", "1")
    monkeypatch.setattr(telemetry, "_INITIALIZED", False)
    monkeypatch.setattr(
        telemetry,
        "_STATUS",
        {"enabled": False, "reason": "not_initialized"},
    )

    status = telemetry.init_telemetry("concordia-test")

    assert status == {"enabled": False, "reason": "dependency_missing"}
    assert telemetry.telemetry_status() == status
    assert _SECRET_DETAIL not in repr(status)


def test_public_gateway_responses_never_render_exception_types() -> None:
    source = Path("gateway/app.py").read_text(encoding="utf-8")

    assert '"error_type": type(exc).__name__' not in source
    assert "({type(exc).__name__})" not in source
