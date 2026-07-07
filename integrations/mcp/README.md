# Concordia Casper MCP Bridge

This folder exposes Concordia's Casper tool boundary through an optional FastMCP server.

Tools:

| Tool | Mode |
|---|---|
| `casper_balance(public_key)` | Calls `CASPER_MCP_URL` if configured; otherwise returns explicit local demo context. |
| `casper_deploy_status(deploy_hash)` | Calls `CASPER_MCP_URL` if configured; otherwise returns explicit local demo context. |
| `casper_node_status()` | Performs a live Casper Testnet JSON-RPC `info_get_status` call unless `CASPER_MCP_OFFLINE_MOCK=1`. |
| `cspr_trade_quote(token_in, token_out, amount)` | Calls `CSPR_TRADE_MCP_URL` if configured; otherwise returns explicit local demo context. |

Run:

```bash
pip install fastmcp
uv run python integrations/mcp/concordia_casper_mcp.py
```

For fully offline rehearsals:

```bash
CASPER_MCP_OFFLINE_MOCK=1
```

For a public node-status boundary check, leave `CASPER_MCP_OFFLINE_MOCK=0` and set `CASPER_NODE_ADDRESS` if you want to override the default Testnet RPC endpoint.
