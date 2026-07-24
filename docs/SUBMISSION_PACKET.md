# Submission Packet

## Project title

Concordia DAO Council

## Tagline

Concordia DAO Council is the Casper governance firewall for AI-run DAOs: Dissent Receipts preserve Verity's objection, Locke is bound to the exact approved hash, and browser-wallet quorum is proven on-chain when execution is reverted before quorum and accepted after quorum.

## Short description

Concordia DAO Council coordinates specialized agents — Rowan, Mercer, Verity, Alden, Locke, and Wells — inside a Council Chamber. The agents enforce a machine-readable DAO Constitution, challenge unsafe DeFi/RWA proposals, preserve structured Dissent Receipts, bind Locke to the exact approved hash, require multisig-style approval, and commit the final approved governance receipt to Casper Testnet.

Demo hook: a malicious AI tries to push an unsafe 30% treasury allocation. Concordia catches the violation, Verity challenges it with Dissent Receipts, the DAO Mandate caps it to 8%, Locke can execute only the exact approved hash, and browser-wallet quorum proves the same action is reverted before quorum and accepted after quorum.

## Track alignment

Multi-Agent DAO Governance & Execution.

## Built with

Core proof path:

```text
Casper Testnet
Casper governance receipt smart contract / Wasm
Python-native Casper JSON-RPC execution adapter
typed Casper CLValues: ByteArray(32) roots and U32 governance fields
DAO Constitution / policy-as-code
Dissent Receipt hashes
FastAPI
SQLite
Next.js
LiteLLM / OpenAI-compatible advisory LLM interface
```

Implemented optional/credential-gated proof extensions:

```text
Casper Node JSON-RPC live-read MCP tool
CSPR.cloud REST / Node API adapters
Casper MCP and CSPR.trade MCP adapters when external URLs are configured
x402 paid governance-report adapter with real Casper transfer proof and facilitator/provider retry paths
IPFS evidence pinning helper
Casper Wallet unsigned receipt intent
Proof Center
downloadable Concordia Governance Archive packet
one-command receipt verifier
compile-checked multi-contract Odra migration package
SafePay Lite conditional paid specialist-report settlement
Judge Walkthrough, public trace API, CSV exports, printable HTML certificate, and downloadable PDF certificate
```

## Canonical proof hierarchy

| Proof item | Canonical value |
|---|---|
| Proposal | `DAO-PROP-6CB25C` |
| Canonical reviewer receipt | `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852` |
| Canonical contract | `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1` |
| Quorum proof | `9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928` |
| Supplemental dynamic lifecycle proof | `DAO-PROP-DYN-002` -> `68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0` |
| Browser wallet receipt | `56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf` |
| x402 SafePay Lite payment | `dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c` |
| IPFS archive CID | `bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq` |

Contract lineage note: the canonical reviewer receipt writes to the Jun 29 v1 GovernanceReceipt receipt anchor (`hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1`, package `hash-992b3a457eedf67f1b50c29f7971199b757d9576dcbaa51e0d52fda3a0fa4c4a`). The supplemental quorum receipt `9d631...` writes through the Jun 30 v2 quorum-enabled GovernanceReceipt package (`hash-1d324e319701e4adcfa9476efcde3d047462d35e79d2cd8c7326c0c384c87d96`) after two approvals. Link the v1 contract as `https://testnet.cspr.live/contract/a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1`.

SafePay Lite demonstrates conditional paid specialist-report settlement: Concordia verifies Casper payment, validates the provider report hash, shows deterministic duplicate-proof replay, records provider reputation delta, and includes the result in the governance proof. It is not a full escrow, refund contract, or marketplace claim.

Technical jury note: the canonical reviewer proof is frozen for reproducibility. Dynamic proposals are preview/execution-ready unless fully evidenced and signed; the Odra topology genesis proves auxiliary modules independently; and full cross-contract production enforcement is roadmap, not overclaimed. Public note: https://concordiadao.xyz/technical-jury-note

Roadmap-only:

```text
Full Enterprise IAM and durable queues
Full Event Streaming / SSE finality pipeline
```

## Demo proof to fill before submission

```text
Repository URL:
Demo video URL:
Casper Testnet contract hash: hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1
Casper Testnet transaction hash: e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852
Casper Testnet explorer URL: https://testnet.cspr.live/deploy/e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852
Casper Testnet API proof URL: https://api.testnet.cspr.live/deploys/e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852
Casper block height: 8340490
Hero proposal ID: DAO-PROP-6CB25C
Entry point: store_governance_receipt
Final card hash: 710b406d7b960d03c633e110fb2edda890b12594967b5db9dba533198a25d622
Plan hash: 603c61df5efc7c911d6c3cbc9063ba3e7b7ac3d580a61e90c89aa0673ef2ac93
Policy hash: cae4a845c1edabba79ec77a2266c455e2d2492793bc707fb92639a6e4239f1a6
Dissent hash: 53fb4bc558cf2ee3d70d1a61b2462bdc3da92cd6e2ee24594eabff7f7a2055da
Approved allocation bps: 800
Evidence URL: https://concordiadao.xyz/evidence/DAO-PROP-6CB25C
Team name:
Contact:
```

Current live proof status:

```text
Live app URL: https://concordiadao.xyz/dashboard
Judge Walkthrough URL: https://concordiadao.xyz/dashboard/judge
Technical Jury Note URL: https://concordiadao.xyz/technical-jury-note
Casper Testnet live read: verified
Hosted execution mode: real
Hosted Testnet public key: 019aeeb6276a9bfe8534a1b51cc7c1e0b72b63cd307566f08d91223bee9e610151
Hosted Locke driver: pycspr native Python JSON-RPC
Native Python deploy assembly: live broadcast complete
Receipt contract hash: hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1
Final transaction hash: e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852
Final receipt proof artifact: artifacts/live/casper-final-receipt-proof.json
Final CSPR.live API artifact: artifacts/live/casper-final-receipt-cspr-live.json
IPFS archive CID: bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq
x402 SafePay Lite payment hash: dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c
Supplemental quorum receipt: 9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928
Supplemental dynamic lifecycle receipt: 68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0
Browser wallet receipt: 56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf
```

The Casper proof fields above are complete. Demo video URL:
https://www.youtube.com/watch?v=GU01V83Jrko

Repository URL: https://github.com/asadvendor-boop/concordia-dao-council

## Judging map

| Criterion | Concordia proof |
|---|---|
| Technical execution | Typed cards, deterministic state machine, approval nonce, exact-envelope checking, Casper execution adapter. |
| Innovation | Policy-governed agent execution plus on-chain Dissent Receipts and approved decision roots. |
| Agentic AI | Distinct agents with independent roles, disagreement handling, and execution delegation. |
| Real-world applicability | DAO treasury and RWA governance proposals need policy caps, evidence hashes, dissent preservation, and human-controlled execution. |
| UX | Council Chamber dashboard, evidence explorer, approval gate, and replay view. |
| Working smart contracts | Governance receipt contract stored the approved decision root on Casper Testnet in deploy `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852`. |
| Launch plan | 30 days: Testnet pilot and CSPR.cloud status reads. 60 days: Odra registry and x402 reports. 90 days: DAO pilot, agent reputation, and RWA templates. |
| Casper ecosystem impact | Positions Casper as the trust and settlement layer for autonomous DAO decisions. |
