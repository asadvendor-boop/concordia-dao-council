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

import httpx


@dataclass(frozen=True)
class CSPRCloudConfig:
    api_url: str
    stream_url: str
    node_rpc_url: str
    access_token: str
    mock: bool


def get_cspr_cloud_config() -> CSPRCloudConfig:
    return CSPRCloudConfig(
        api_url=os.getenv("CSPR_CLOUD_API_URL", "https://api.testnet.cspr.cloud").rstrip("/"),
        stream_url=os.getenv("CSPR_CLOUD_STREAM_URL", "wss://streaming.testnet.cspr.cloud").rstrip("/"),
        node_rpc_url=os.getenv("CSPR_NODE_RPC_URL", "https://node.testnet.casper.network/rpc").rstrip("/"),
        access_token=os.getenv("CSPR_CLOUD_ACCESS_TOKEN", "").strip(),
        mock=os.getenv("CSPR_CLOUD_MOCK", os.getenv("CASPER_EXECUTION_MODE", "mock")).lower() == "mock",
    )


def cspr_cloud_status() -> dict[str, Any]:
    config = get_cspr_cloud_config()
    return {
        "status": "mock" if config.mock else "live_configured" if config.access_token else "not_configured",
        "rest_configured": bool(config.access_token),
        "api_url": config.api_url,
        "node_rpc_url": config.node_rpc_url,
        "stream_url": config.stream_url,
        "streaming_roadmap_only": True,
        "note": (
            "CSPR.cloud REST reads are live when CSPR_CLOUD_ACCESS_TOKEN is configured."
            if config.access_token
            else "Set CSPR_CLOUD_ACCESS_TOKEN to verify CSPR.cloud REST reads; direct Casper Node RPC remains live without it."
        ),
    }


def _headers(config: CSPRCloudConfig) -> dict[str, str]:
    headers = {"accept": "application/json"}
    if config.access_token:
        token = config.access_token
        headers["authorization"] = token if token.lower().startswith("bearer ") else f"Bearer {token}"
    return headers


def _not_configured(feature: str) -> dict[str, Any]:
    return {
        "source": "cspr.cloud.not_configured",
        "feature": feature,
        "status": "not_configured",
        "error": "Set CSPR_CLOUD_ACCESS_TOKEN for live CSPR.cloud reads.",
        "network": "casper-testnet",
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
            "network": "casper-testnet",
        }
    if not config.access_token:
        return _not_configured("account_context") | {"public_key": public_key}
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(f"{config.api_url}/accounts/{public_key}", headers=_headers(config))
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
            "network": "casper-testnet",
        }
    if not config.access_token:
        return _not_configured("deploy_context") | {"deploy_hash": deploy_hash}
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(f"{config.api_url}/deploys/{deploy_hash}", headers=_headers(config))
        response.raise_for_status()
        return {"source": "cspr.cloud.rest", "deploy": response.json()}


async def get_cspr_rate(currency: str = "usd") -> dict[str, Any]:
    """Return CSPR rate context for treasury analysis."""
    config = get_cspr_cloud_config()
    if config.mock:
        return {"source": "cspr.cloud.mock", "currency": currency.lower(), "amount": 0.02, "network": "casper-testnet"}
    if not config.access_token:
        return _not_configured("cspr_rate") | {"currency": currency.lower()}
    async with httpx.AsyncClient(timeout=15.0) as client:
        response = await client.get(f"{config.api_url}/rates/cspr/{currency.lower()}", headers=_headers(config))
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
            "network": "casper-testnet",
            "status": {"chainspec_name": "casper-test", "last_added_block_info": {"height": 0}},
            "note": "Offline mock enabled by CASPER_MCP_OFFLINE_MOCK=1",
        }
    config = get_cspr_cloud_config()
    payload = {"jsonrpc": "2.0", "id": "concordia-info-status", "method": "info_get_status", "params": []}
    headers = {"content-type": "application/json", **_headers(config)}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(config.node_rpc_url, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()
            return {"source": "casper-node.rpc", "live": True, "status": data.get("result", data), "network": "casper-testnet"}
    except Exception as exc:
        return {
            "source": "casper-node.rpc.unavailable",
            "live": False,
            "network": "casper-testnet",
            "error": f"{type(exc).__name__}: {exc}",
            "node_rpc_url": config.node_rpc_url,
        }



async def get_public_testnet_probe() -> dict[str, Any]:
    """Make a real read-only HTTPS GET to a public Casper Testnet URL.

    This proves the optional MCP bridge can cross a live network boundary even
    when credential-gated CSPR.cloud REST endpoints are not configured. It does
    not fabricate treasury balances or DeFi quotes.
    """
    url = os.getenv("CASPER_PUBLIC_STATUS_URL", "https://testnet.cspr.live").strip()
    checked_at = datetime.now(UTC).isoformat()
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
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(url, headers={"accept": "text/html,application/json"})
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
            "error": f"{type(exc).__name__}: {exc}",
            "checked_at": checked_at,
        }

def streaming_subscription_context(entity: str = "deploy") -> dict[str, Any]:
    """Return CSPR.cloud Streaming API connection metadata used by listeners."""
    config = get_cspr_cloud_config()
    return {
        "source": "cspr.cloud.streaming",
        "stream_url": config.stream_url,
        "entity": entity,
        "persistent_session_supported": True,
        "requires_access_token": not bool(config.access_token),
        "mode": "mock" if config.mock else "live_configured" if config.access_token else "not_configured",
    }


def node_rpc_context() -> dict[str, Any]:
    """Return the configured Casper Node RPC endpoint via CSPR.cloud or direct node."""
    config = get_cspr_cloud_config()
    return {"source": "cspr.cloud.node", "node_rpc_url": config.node_rpc_url, "network": "casper-testnet"}
