# Concordia MCP Judge Tool

Concordia includes an optional FastMCP bridge at `integrations/mcp/concordia_casper_mcp.py`.
It lets a reviewer connect Claude, Cursor, or another MCP client and ask it to
audit the Casper proof using Concordia's read-only Casper tools.

## Honest Scope

This bridge is a judge/auditor tool surface. It does not sign transactions,
change the canonical proof, or mutate Casper state.

Live without external MCP configuration:

- `casper_node_status` reads Casper Testnet JSON-RPC node status.
- `casper_public_status` performs a public HTTPS status probe.

Live only when configured:

- `casper_balance` calls an external Casper MCP server when `CASPER_MCP_URL` is set.
- `casper_deploy_status` calls an external Casper MCP server when `CASPER_MCP_URL` is set.
- `cspr_trade_quote` calls CSPR.trade MCP or REST when `CSPR_TRADE_MCP_URL` or `CSPR_TRADE_API_URL` is set.

When those external URLs are not configured, the bridge returns explicitly
labelled mock/rehearsal responses instead of pretending to be live.

## Run Locally

```bash
uv sync --frozen --python 3.12.11
uv run --frozen --isolated --python 3.12.11 python integrations/mcp/concordia_casper_mcp.py
```

If `fastmcp` is not installed in your environment, install it in the local
review environment or use the non-MCP verifier instead:

```bash
python scripts/verify_concordia_receipt.py \
  --base-url https://concordia.47.84.232.193.sslip.io \
  --proposal-id DAO-PROP-6CB25C \
  --live-chain
```

## Suggested Reviewer Prompts

Ask your MCP client:

```text
Use the Concordia Casper MCP tools to audit DAO-PROP-6CB25C.
Check Casper node status, then inspect deploy
e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852.
Confirm it is the canonical reviewer receipt and explain the quorum proof
9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928 as
supplemental.
```

```text
Use Concordia's MCP bridge to compare the canonical receipt, browser-wallet
receipt, x402 SafePay Lite payment, IPFS CID, and supplemental dynamic proof
against the public proof hierarchy in README.md.
```

## Canonical Proof Values

| Proof item | Value |
|---|---|
| Canonical proposal | `DAO-PROP-6CB25C` |
| Canonical reviewer receipt | `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852` |
| Canonical contract | `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1` |
| Quorum proof | `9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928` |
| Browser wallet receipt | `56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf` |
| x402 SafePay Lite payment | `dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c` |
| IPFS archive CID | `bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq` |

## Non-Mutating Verification Path

For a deterministic audit without MCP, run:

```bash
python scripts/verify_concordia_receipt.py \
  --proof-pack artifacts/live/live-proof-pack-current.json \
  --live-chain
```

The verifier checks the proof pack, evidence-chain claims, quorum artifact, and
live Casper deploy metadata. The Odra receipt dictionary lookup is intentionally
reported as `skipped` because the public proof pack does not expose the contract
dictionary URef; the deploy/runtime-argument diff remains the authoritative
reviewer check for this mode.
