"""CSPR.cloud adapters used by Concordia agents.

These helpers are explicit about integration state:
- mock mode returns deterministic local rehearsal data;
- real mode calls configured CSPR.cloud REST/Node endpoints;
- real mode without credentials returns a not_configured result instead of
  fabricating live chain data.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from shared.runtime_secrets import read_secret


@dataclass(frozen=True)
class CSPRCloudConfig:
    api_url: str
    stream_url: str
    node_rpc_url: str
    access_token: str
    mock: bool


class CSPRCloudConfigError(ValueError):
    """A configured CSPR.cloud boundary or token is unsafe."""


_REDACTED_INVALID_URL = "redacted_invalid"


def get_cspr_cloud_config() -> CSPRCloudConfig:
    app_env = os.getenv("APP_ENV", "development").strip().lower()
    return CSPRCloudConfig(
        api_url=os.getenv(
            "CSPR_CLOUD_API_URL", "https://api.testnet.cspr.cloud"
        ).rstrip("/"),
        stream_url=os.getenv(
            "CSPR_CLOUD_STREAM_URL", "wss://streaming.testnet.cspr.cloud"
        ).rstrip("/"),
        node_rpc_url=os.getenv(
            "CSPR_NODE_RPC_URL", "https://node.testnet.casper.network/rpc"
        ).rstrip("/"),
        access_token=read_secret(
            "CSPR_CLOUD_ACCESS_TOKEN",
            allow_env=app_env not in {"prod", "production"},
        ),
        mock=os.getenv(
            "CSPR_CLOUD_MOCK", os.getenv("CASPER_EXECUTION_MODE", "mock")
        ).lower()
        == "mock",
    )


def cspr_cloud_status() -> dict[str, Any]:
    config = get_cspr_cloud_config()
    service_scope = os.getenv("CSPR_CLOUD_SERVICE_SCOPE", "").strip()
    try:
        api_url = _validated_api_url(config)
        node_rpc_url = _validated_node_rpc_url(config)
        stream_url = _validated_stream_url(config)
        if config.access_token:
            _validated_raw_access_token(config.access_token)
    except CSPRCloudConfigError:
        return {
            "status": "invalid_config",
            "rest_configured": False,
            "credential_service_declared": bool(service_scope),
            "credential_available_to_this_process": False,
            "credential_scope": "none",
            "api_url": _REDACTED_INVALID_URL,
            "node_rpc_url": _REDACTED_INVALID_URL,
            "stream_url": _REDACTED_INVALID_URL,
            "streaming_roadmap_only": True,
            "note": "One or more configured CSPR.cloud boundaries are invalid.",
        }
    return {
        "status": "mock"
        if config.mock
        else "live_configured"
        if config.access_token
        else "service_scoped"
        if service_scope
        else "not_configured",
        "rest_configured": bool(config.access_token),
        "credential_service_declared": bool(service_scope),
        "credential_available_to_this_process": bool(config.access_token),
        "credential_scope": (
            service_scope
            if service_scope
            else "this_process"
            if config.access_token
            else "none"
        ),
        "api_url": api_url,
        "node_rpc_url": node_rpc_url,
        "stream_url": stream_url,
        "streaming_roadmap_only": True,
        "note": (
            "CSPR.cloud REST reads are live when CSPR_CLOUD_ACCESS_TOKEN is configured."
            if config.access_token
            else f"CSPR.cloud REST credential is scoped to {service_scope}."
            if service_scope
            else "Set CSPR_CLOUD_ACCESS_TOKEN_FILE for the consuming service; direct Casper Node RPC remains credential-free."
        ),
    }


def _validated_raw_access_token(token: str) -> str:
    if token.lower().startswith("bearer ") or any(
        ord(character) < 0x21 or ord(character) > 0x7E for character in token
    ):
        raise CSPRCloudConfigError("CSPR.cloud token is not a raw header value")
    return token


def _configured_chain_name() -> str:
    chain_name = os.getenv("CASPER_CHAIN_NAME", "casper-test").strip()
    if chain_name not in {"casper-test", "casper"}:
        raise CSPRCloudConfigError("Unsupported Casper chain")
    return chain_name


def _expected_cspr_cloud_hosts() -> tuple[str, str]:
    chain_name = _configured_chain_name()
    if chain_name == "casper-test":
        return "api.testnet.cspr.cloud", "node.testnet.cspr.cloud"
    if chain_name == "casper":
        return "api.cspr.cloud", "node.cspr.cloud"
    raise CSPRCloudConfigError("Casper chain has no pinned CSPR.cloud origin")


def _network_label() -> str:
    chain_name = _configured_chain_name()
    if chain_name == "casper-test":
        return "casper-testnet"
    if chain_name == "casper":
        return "casper-mainnet"
    raise CSPRCloudConfigError("Casper chain has no public network label")


def _expected_stream_host() -> str:
    chain_name = _configured_chain_name()
    if chain_name == "casper-test":
        return "streaming.testnet.cspr.cloud"
    if chain_name == "casper":
        return "streaming.cspr.cloud"
    raise CSPRCloudConfigError("Casper chain has no pinned streaming origin")


def _split_url(url: str, *, boundary: str):
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise CSPRCloudConfigError(f"{boundary} is invalid") from exc
    return parsed, port


def _validated_api_url(config: CSPRCloudConfig) -> str:
    parsed, port = _split_url(config.api_url, boundary="CSPR.cloud API origin")
    expected_api_host, _ = _expected_cspr_cloud_hosts()
    if (
        parsed.scheme != "https"
        or parsed.hostname != expected_api_host
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise CSPRCloudConfigError("CSPR.cloud API origin is not allowlisted")
    return config.api_url


def _validated_stream_url(config: CSPRCloudConfig) -> str:
    parsed, port = _split_url(config.stream_url, boundary="CSPR.cloud Streaming origin")
    if (
        parsed.scheme != "wss"
        or parsed.hostname != _expected_stream_host()
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise CSPRCloudConfigError("CSPR.cloud Streaming origin is not allowlisted")
    return config.stream_url


def _validated_node_rpc_url(config: CSPRCloudConfig) -> str:
    parsed, port = _split_url(config.node_rpc_url, boundary="Casper Node RPC origin")
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.path != "/rpc"
        or parsed.query
        or parsed.fragment
    ):
        raise CSPRCloudConfigError("Casper Node RPC origin is invalid")

    _, expected_node_host = _expected_cspr_cloud_hosts()
    cspr_cloud_hosts = {"node.testnet.cspr.cloud", "node.cspr.cloud"}
    if parsed.hostname in cspr_cloud_hosts and parsed.hostname != expected_node_host:
        raise CSPRCloudConfigError("CSPR.cloud Node RPC origin is not allowlisted")
    return config.node_rpc_url


def _validated_public_status_url(url: str) -> str:
    parsed, port = _split_url(url, boundary="Casper public status origin")
    if (
        parsed.scheme != "https"
        or parsed.hostname != "testnet.cspr.live"
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise CSPRCloudConfigError("Casper public status origin is not allowlisted")
    return url


def _headers(config: CSPRCloudConfig) -> dict[str, str]:
    headers = {"accept": "application/json"}
    _validated_api_url(config)
    if config.access_token:
        # CSPR.cloud expects the access token itself, never a Bearer scheme.
        headers["authorization"] = _validated_raw_access_token(config.access_token)
    return headers


def _node_headers(config: CSPRCloudConfig) -> dict[str, str]:
    """Authenticate only the two exact CSPR.cloud Casper Node RPC origins."""

    headers = {"content-type": "application/json"}
    _validated_node_rpc_url(config)
    if not config.access_token:
        return headers
    parsed = urlsplit(config.node_rpc_url)
    _, expected_node_host = _expected_cspr_cloud_hosts()
    cspr_cloud_hosts = {"node.testnet.cspr.cloud", "node.cspr.cloud"}
    if parsed.hostname not in cspr_cloud_hosts:
        return headers
    if parsed.hostname != expected_node_host:
        raise CSPRCloudConfigError("CSPR.cloud Node RPC origin is not allowlisted")
    headers["authorization"] = _validated_raw_access_token(config.access_token)
    return headers


def _not_configured(feature: str) -> dict[str, Any]:
    return {
        "source": "cspr.cloud.not_configured",
        "feature": feature,
        "status": "not_configured",
        "error": "Set CSPR_CLOUD_ACCESS_TOKEN_FILE for live CSPR.cloud reads.",
        "network": _network_label(),
    }


async def get_account_context(public_key: str) -> dict[str, Any]:
    """Return account context through CSPR.cloud REST, or deterministic rehearsal data."""
    config = get_cspr_cloud_config()
    if config.mock:
        return {
            "source": "cspr.cloud.mock",
            "public_key": public_key,
            "balance_motes": "250000000000",
            "delegated": False,
            "network": _network_label(),
        }
    if not config.access_token:
        return _not_configured("account_context") | {"public_key": public_key}
    async with httpx.AsyncClient(
        timeout=15.0, follow_redirects=False, trust_env=False
    ) as client:
        response = await client.get(
            f"{_validated_api_url(config)}/accounts/{public_key}",
            headers=_headers(config),
        )
        response.raise_for_status()
        return {"source": "cspr.cloud.rest", "account": response.json()}


async def get_deploy_context(deploy_hash: str) -> dict[str, Any]:
    """Return deploy/transaction context through CSPR.cloud REST, or deterministic rehearsal data."""
    config = get_cspr_cloud_config()
    if config.mock:
        return {
            "source": "cspr.cloud.mock",
            "deploy_hash": deploy_hash,
            "status": "processed",
            "execution_result": "success",
            "network": _network_label(),
        }
    if not config.access_token:
        return _not_configured("deploy_context") | {"deploy_hash": deploy_hash}
    async with httpx.AsyncClient(
        timeout=15.0, follow_redirects=False, trust_env=False
    ) as client:
        response = await client.get(
            f"{_validated_api_url(config)}/deploys/{deploy_hash}",
            headers=_headers(config),
        )
        response.raise_for_status()
        return {"source": "cspr.cloud.rest", "deploy": response.json()}


async def get_cspr_rate(currency: str = "usd") -> dict[str, Any]:
    """Return CSPR rate context for treasury analysis."""
    config = get_cspr_cloud_config()
    if config.mock:
        return {
            "source": "cspr.cloud.mock",
            "currency": currency.lower(),
            "amount": 0.02,
            "network": _network_label(),
        }
    if not config.access_token:
        return _not_configured("cspr_rate") | {"currency": currency.lower()}
    async with httpx.AsyncClient(
        timeout=15.0, follow_redirects=False, trust_env=False
    ) as client:
        response = await client.get(
            f"{_validated_api_url(config)}/rates/cspr/{currency.lower()}",
            headers=_headers(config),
        )
        response.raise_for_status()
        return {"source": "cspr.cloud.rest", "rate": response.json()}


async def get_node_status() -> dict[str, Any]:
    """Call the configured Casper Node JSON-RPC endpoint for live network status.

    This is a real network boundary used by the optional MCP bridge and by
    pre-submission checks. It does not fabricate success in real mode.
    """
    if os.getenv("CASPER_MCP_OFFLINE_MOCK", "0").lower() in {"1", "true", "yes"}:
        return {
            "source": "casper-node.mock",
            "live": False,
            "network": _network_label(),
            "status": {
                "chainspec_name": _configured_chain_name(),
                "last_added_block_info": {"height": 0},
            },
            "note": "Offline mock enabled by CASPER_MCP_OFFLINE_MOCK=1",
        }
    config = get_cspr_cloud_config()
    payload = {
        "jsonrpc": "2.0",
        "id": "concordia-info-status",
        "method": "info_get_status",
        "params": [],
    }
    try:
        headers = _node_headers(config)
        async with httpx.AsyncClient(
            timeout=15.0, follow_redirects=False, trust_env=False
        ) as client:
            response = await client.post(
                _validated_node_rpc_url(config), headers=headers, json=payload
            )
            response.raise_for_status()
            data = response.json()
            return {
                "source": "casper-node.rpc",
                "live": True,
                "status": data.get("result", data),
                "network": _network_label(),
            }
    except CSPRCloudConfigError:
        return {
            "source": "casper-node.rpc.unavailable",
            "live": False,
            "network": _network_label(),
            "error": "CSPRCloudConfigError",
            "node_rpc_url": _REDACTED_INVALID_URL,
        }
    except Exception as exc:
        return {
            "source": "casper-node.rpc.unavailable",
            "live": False,
            "network": _network_label(),
            "error": type(exc).__name__,
            "node_rpc_url": _validated_node_rpc_url(config),
        }


async def get_public_testnet_probe() -> dict[str, Any]:
    """Make a real read-only HTTPS GET to a public Casper Testnet URL.

    This proves the optional MCP bridge can cross a live network boundary even
    when credential-gated CSPR.cloud REST endpoints are not configured. It does
    not fabricate treasury balances or DeFi quotes.
    """
    url = os.getenv("CASPER_PUBLIC_STATUS_URL", "https://testnet.cspr.live").strip()
    checked_at = datetime.now(UTC).isoformat()
    try:
        url = _validated_public_status_url(url)
    except CSPRCloudConfigError:
        return {
            "source": "casper-public-status.https-get.unavailable",
            "live": False,
            "url": _REDACTED_INVALID_URL,
            "ok": False,
            "error": "CSPRCloudConfigError",
            "checked_at": checked_at,
        }
    if os.getenv("CASPER_MCP_OFFLINE_MOCK", "0") == "1":
        return {
            "source": "casper-public-status.mock",
            "live": False,
            "url": url,
            "status_code": 200,
            "checked_at": checked_at,
            "note": "Offline mock enabled with CASPER_MCP_OFFLINE_MOCK=1.",
        }
    try:
        async with httpx.AsyncClient(
            timeout=10.0, follow_redirects=False, trust_env=False
        ) as client:
            response = await client.get(
                url, headers={"accept": "text/html,application/json"}
            )
        return {
            "source": "casper-public-status.https-get",
            "live": True,
            "url": url,
            "status_code": response.status_code,
            "ok": 200 <= response.status_code < 500,
            "content_type": response.headers.get("content-type", ""),
            "sample": response.text[:160],
            "checked_at": checked_at,
        }
    except Exception as exc:  # pragma: no cover - depends on external network
        return {
            "source": "casper-public-status.https-get.unavailable",
            "live": False,
            "url": url,
            "ok": False,
            "error": type(exc).__name__,
            "checked_at": checked_at,
        }


def streaming_subscription_context(entity: str = "deploy") -> dict[str, Any]:
    """Return CSPR.cloud Streaming API connection metadata used by listeners."""
    config = get_cspr_cloud_config()
    try:
        stream_url = _validated_stream_url(config)
    except CSPRCloudConfigError:
        return {
            "source": "cspr.cloud.streaming",
            "stream_url": _REDACTED_INVALID_URL,
            "entity": entity,
            "persistent_session_supported": False,
            "requires_access_token": True,
            "mode": "invalid_config",
        }
    return {
        "source": "cspr.cloud.streaming",
        "stream_url": stream_url,
        "entity": entity,
        "persistent_session_supported": True,
        "requires_access_token": not bool(config.access_token),
        "mode": "mock"
        if config.mock
        else "live_configured"
        if config.access_token
        else "not_configured",
    }


def node_rpc_context() -> dict[str, Any]:
    """Return the configured Casper Node RPC endpoint via CSPR.cloud or direct node."""
    config = get_cspr_cloud_config()
    try:
        node_rpc_url = _validated_node_rpc_url(config)
    except CSPRCloudConfigError:
        return {
            "source": "cspr.cloud.node",
            "status": "invalid_config",
            "node_rpc_url": _REDACTED_INVALID_URL,
            "network": _network_label(),
        }
    return {
        "source": "cspr.cloud.node",
        "status": "configured",
        "node_rpc_url": node_rpc_url,
        "network": _network_label(),
    }
