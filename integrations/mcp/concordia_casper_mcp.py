"""Optional FastMCP bridge for Concordia Casper tools.

Run this only if `fastmcp` is installed. The bridge exposes the same tool
boundaries used by `shared.casper_mcp`, including live Casper Node JSON-RPC and
public HTTPS read probes for reviewers.
"""
from __future__ import annotations

try:
    from fastmcp import FastMCP
except Exception:  # pragma: no cover - optional dependency
    FastMCP = None

from shared.casper_mcp import (
    get_casper_balance,
    get_casper_deploy_status,
    get_casper_node_status,
    get_casper_public_status,
    get_cspr_trade_quote,
)

if FastMCP is None:  # pragma: no cover
    raise SystemExit("Install fastmcp to run this optional bridge")

mcp = FastMCP("concordia-casper-mcp")


@mcp.tool()
async def casper_node_status() -> dict:
    """Read live Casper Testnet node status through the configured Node API."""
    return await get_casper_node_status()


@mcp.tool()
async def casper_public_status() -> dict:
    """Perform a simple HTTPS GET against the configured public Casper status URL."""
    return await get_casper_public_status()


@mcp.tool()
async def casper_balance(public_key: str) -> dict:
    return await get_casper_balance(public_key)


@mcp.tool()
async def casper_deploy_status(deploy_hash: str) -> dict:
    return await get_casper_deploy_status(deploy_hash)


@mcp.tool()
async def cspr_trade_quote(token_in: str, token_out: str, amount: str) -> dict:
    return await get_cspr_trade_quote(token_in, token_out, amount)


if __name__ == "__main__":
    mcp.run()
