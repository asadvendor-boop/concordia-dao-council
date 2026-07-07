# Concordia DAO Council — Submission Package — Verified Fixes

## Project title

Concordia DAO Council

## Track

Multi-Agent DAO Governance & Execution

## Tagline

A multi-agent DAO governance council that deliberates on treasury proposals and anchors approved decisions to Casper Testnet.

## Short description

Concordia DAO Council coordinates six specialized agents — Rowan, Mercer, Verity, Alden, Locke, and Wells — inside a Council Chamber. The agents review DAO proposals, challenge unsafe plans, require multisig-style approval, and commit the final approved governance receipt to Casper Testnet.

## Core proof to show in the demo

```text
DAO proposal
-> Rowan classifies the proposal
-> Mercer analyzes treasury / Casper context
-> Verity challenges excessive risk
-> Alden revises the execution plan
-> Multisig Approval Gate approves the exact envelope
-> Locke submits the governance receipt to Casper Testnet
-> Wells archives the evidence chain
```

## Built with

Core proof:

```text
Casper Testnet
Casper smart contract / Wasm governance receipt
Casper CLI / SDK execution adapter
CSPR.cloud Node RPC endpoint
FastAPI
SQLite
Next.js
LiteLLM / OpenAI-compatible advisory LLM interface
```

Credential-gated / V2 paths:

```text
CSPR.cloud REST latest-block/account/deploy/rate adapters
CSPR.cloud Streaming subscription metadata
Casper MCP and CSPR.trade MCP bridge adapters
x402 paid governance-report demo endpoint
Odra migration scaffold
CSPR.click wallet/signing setup documentation
```

## Demo proof to fill before submitting

```text
Repository URL:
Demo video URL:
Casper Testnet contract hash:
Casper Testnet transaction hash:
Hero proposal ID:
Evidence URL:
Team name:
Contact:
```

## Do not submit until this is true

```text
CASPER_EXECUTION_MODE=real
Locke returns status=success
Locke returns a real Casper Testnet transaction/deploy hash
The video shows the transaction hash and evidence page
```

## Preflight commands

```bash
python -m compileall -q shared gateway agents proposal-simulator scripts
python -m pytest -q
node --check integrations/casper-sdk/submit_receipt.mjs
find dashboard/app -name '*.js' -print0 | xargs -0 -n1 node --check
python scripts/check_repo_hygiene.py
python scripts/casper_preflight.py
```

`casper_preflight.py` will fail until your funded Testnet keypair, hash-prefixed contract hash, and selected Casper execution driver are configured.

## Honest ecosystem-tooling language

Use this wording:

> The core prototype uses a Casper Testnet receipt contract and Locke's execution adapter to anchor the final approved governance decision on-chain. CSPR.cloud, MCP, x402, CSPR.click, and Odra are represented as credential-gated adapters and production roadmap paths; live reads can be enabled with the documented environment variables.

Avoid claiming that optional rails are fully production-live unless you configure and show them during the demo.

## Verification fixes included

- Integration truth table separates required Casper Testnet proof from optional adapters.
- MCP bridge includes live read tools: `casper_node_status` via JSON-RPC and `casper_public_status` via HTTPS GET.
- Casper preflight checks key path, execution driver, and `hash-` contract-hash prefix.
- Casper CLI runtime args intentionally keep `name:string='value'` format.
- Dashboard/gateway naming contract is tested to keep `proposal_id` consistent.
