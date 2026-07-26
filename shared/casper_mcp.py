"""Casper MCP and CSPR.trade MCP adapters for Concordia.

The council workflow can run without an external MCP server by returning
clearly labelled rehearsal context for non-critical reads. For reviewer proof,
`get_casper_node_status` performs a real Casper Node JSON-RPC call and
`get_casper_public_status` performs a real HTTPS GET to a configured public
Casper status/explorer URL unless offline mock mode is explicitly enabled.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

import httpx

from shared.cspr_cloud import get_node_status, get_public_testnet_probe


MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}


def _mcp_json(response: httpx.Response) -> dict[str, Any]:
    """Decode JSON or text/event-stream MCP responses."""
    content_type = response.headers.get("content-type", "")
    if "text/event-stream" not in content_type:
        return response.json()
    data_lines: list[str] = []
    for line in response.text.splitlines():
        if line.startswith("data:"):
            data_lines.append(line.removeprefix("data:").strip())
    if not data_lines:
        return {}
    return httpx.Response(
        200,
        content="\n".join(data_lines).encode("utf-8"),
        headers={"content-type": "application/json"},
    ).json()


def _mcp_text_payload(payload: dict[str, Any]) -> str:
    content = ((payload.get("result") or {}).get("content") or [])
    if not content:
        return ""
    first = content[0] if isinstance(content[0], dict) else {}
    return str(first.get("text") or "")


async def call_mcp_tool(server_url: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Call a Streamable HTTP MCP tool with explicit initialization.

    Newer MCP servers, including the public CSPR.trade endpoint, require an
    initialize request and `mcp-session-id` before accepting tool calls.
    """
    async with httpx.AsyncClient(timeout=20.0) as client:
        init_response = await client.post(
            server_url,
            json={
                "jsonrpc": "2.0",
                "id": f"concordia-init-{int(time.time() * 1000)}",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "concordia-dao-council", "version": "2026.06"},
                },
            },
            headers=MCP_HEADERS,
        )
        init_response.raise_for_status()
        session_id = init_response.headers.get("mcp-session-id", "")
        headers = dict(MCP_HEADERS)
        if session_id:
            headers["mcp-session-id"] = session_id
        await client.post(
            server_url,
            json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            headers=headers,
        )
        payload = {
            "jsonrpc": "2.0",
            "id": f"concordia-{tool_name}",
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        response = await client.post(
            server_url,
            json=payload,
            headers=headers,
        )
        response.raise_for_status()
        return _mcp_json(response)


async def get_casper_node_status() -> dict[str, Any]:
    """Live-read Casper Testnet node status through the configured Node API."""
    return await get_node_status()


async def get_casper_public_status() -> dict[str, Any]:
    """Live-read a public Casper Testnet explorer/status page with HTTPS GET."""
    return await get_public_testnet_probe()


async def get_casper_balance(public_key: str) -> dict[str, Any]:
    url = os.getenv("CASPER_MCP_URL", "").strip()
    if not url:
        return {
            "source": "casper-mcp.mock",
            "tool": "GetAccountBalance",
            "public_key": public_key,
            "balance_motes": "250000000000",
            "note": "Set CASPER_MCP_URL for a live Casper MCP account-balance tool call.",
        }
    return await call_mcp_tool(url, "GetAccountBalance", {"public_key": public_key})


async def get_casper_deploy_status(deploy_hash: str) -> dict[str, Any]:
    url = os.getenv("CASPER_MCP_URL", "").strip()
    if not url:
        return {
            "source": "casper-mcp.mock",
            "tool": "GetDeploy",
            "deploy_hash": deploy_hash,
            "status": "processed",
            "note": "Set CASPER_MCP_URL for a live Casper MCP deploy-status tool call.",
        }
    return await call_mcp_tool(url, "GetDeploy", {"deploy_hash": deploy_hash})


async def get_cspr_trade_quote(token_in: str, token_out: str, amount: str) -> dict[str, Any]:
    """Return a quote-only CSPR.trade result.

    Supports two real transports:
    - `CSPR_TRADE_MCP_URL`: JSON-RPC MCP `tools/call` bridge.
    - `CSPR_TRADE_API_URL`: REST adapter compatible with `/build_swap`.

    If neither is configured, return an explicitly labelled local rehearsal
    quote. This keeps the demo honest while making the live quote path a pure
    configuration change.
    """
    mcp_url = os.getenv("CSPR_TRADE_MCP_URL", "").strip()
    api_url = os.getenv("CSPR_TRADE_API_URL", "").strip().rstrip("/")
    if api_url:
        payload = {
            "tokenIn": token_in,
            "tokenOut": token_out,
            "amountIn": amount,
            "slippageBps": int(os.getenv("CSPR_TRADE_SLIPPAGE_BPS", "50")),
        }
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(f"{api_url}/build_swap", json=payload)
            response.raise_for_status()
            quote = response.json()
        return {
            "source": "cspr.trade.rest",
            "tool": "build_swap",
            "token_in": token_in,
            "token_out": token_out,
            "amount_in": amount,
            "amount_out": str(quote.get("amountOut", "")),
            "route": quote.get("route", []),
            "deploy_payload_present": bool(quote.get("deployPayload")),
            "raw": quote,
        }
    if not mcp_url:
        return {
            "source": "cspr.trade-mcp.mock",
            "tool": "get_quote",
            "token_in": token_in,
            "token_out": token_out,
            "amount_in": amount,
            "amount_out": "9847.32",
            "price_impact": "0.12%",
            "route": [token_in, "WCSPR", token_out],
            "note": "Set CSPR_TRADE_MCP_URL for a live CSPR.trade MCP quote.",
        }
    mcp_payload = await call_mcp_tool(
        mcp_url,
        "get_quote",
        {"token_in": token_in, "token_out": token_out, "amount": amount, "type": "exact_in"},
    )
    text = _mcp_text_payload(mcp_payload)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {
            "source": "cspr.trade.mcp",
            "tool": "get_quote",
            "status": "error" if text.startswith("Error:") else "live_unparsed",
            "token_in": token_in,
            "token_out": token_out,
            "amount_in": amount,
            "message": text,
            "raw": mcp_payload,
        }
    return {
        "source": "cspr.trade.mcp",
        "tool": "get_quote",
        "status": "live",
        "token_in": token_in,
        "token_out": token_out,
        "amount_in": str(parsed.get("amountInFormatted", amount)),
        "amount_out": str(parsed.get("amountOutFormatted", "")),
        "execution_price": str(parsed.get("executionPrice", "")),
        "mid_price": str(parsed.get("midPrice", "")),
        "price_impact": str(parsed.get("priceImpact", "")),
        "recommended_slippage_bps": str(parsed.get("recommendedSlippageBps", "")),
        "route": parsed.get("pathSymbols") or parsed.get("path") or [],
        "raw": parsed,
    }


def cspr_trade_status() -> dict[str, Any]:
    mcp_url = os.getenv("CSPR_TRADE_MCP_URL", "").strip()
    api_url = os.getenv("CSPR_TRADE_API_URL", "").strip()
    return {
        "status": "live_configured" if (mcp_url or api_url) else "not_configured",
        "quote_only_supported": True,
        "mcp_url_configured": bool(mcp_url),
        "rest_api_url_configured": bool(api_url),
        "active_transport": "mcp" if mcp_url else "rest" if api_url else "mock",
        "note": (
            "Quote-only path is live when CSPR_TRADE_MCP_URL or CSPR_TRADE_API_URL is configured."
            if (mcp_url or api_url)
            else "Set CSPR_TRADE_MCP_URL or CSPR_TRADE_API_URL to verify a real CSPR.trade quote."
        ),
    }


def mcp_manifest() -> dict[str, Any]:
    return {
        "name": "concordia-casper-mcp-adapter",
        "tools": [
            {"name": "casper_node_status", "server": "Concordia FastMCP bridge", "mode": "live JSON-RPC read"},
            {"name": "casper_public_status", "server": "Concordia FastMCP bridge", "mode": "live HTTPS GET read"},
            {"name": "GetAccountBalance", "server": "Casper MCP Server", "mode": "live when CASPER_MCP_URL is set"},
            {"name": "GetDeploy", "server": "Casper MCP Server", "mode": "live when CASPER_MCP_URL is set"},
            {"name": "get_quote", "server": "CSPR.trade MCP Server", "mode": "live when CSPR_TRADE_MCP_URL is set"},
            {"name": "build_swap", "server": "CSPR.trade REST adapter", "mode": "live when CSPR_TRADE_API_URL is set"},
        ],
        "mock_when_unconfigured": ["GetAccountBalance", "GetDeploy", "get_quote"],
        "live_read_without_external_mcp": ["casper_node_status", "casper_public_status"],
    }
