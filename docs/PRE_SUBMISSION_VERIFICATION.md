# Pre-Submission Verification Notes

These notes separate the qualification-critical proof path from optional ecosystem adapters.

Product framing: Concordia DAO Council is the Casper governance firewall for AI-run DAOs: Dissent Receipts preserve Verity's objection, Locke is bound to the exact approved hash, and browser-wallet quorum is proven on-chain when execution is reverted before quorum and accepted after quorum.

Demo hook: a malicious AI tries to push an unsafe 30% treasury allocation. Concordia catches the violation, Verity challenges it with Dissent Receipts, the DAO Mandate caps it to 8%, Locke can execute only the exact approved hash, and browser-wallet quorum proves the same action is reverted before quorum and accepted after quorum.

## Organizer-mandated finals release gate

The release is blocked until all of these checks pass against the exact public
release commit:

- the GitHub repository is public and correctly named, with its description,
  website, and topics configured; topics include `casper-blockchain`,
  `casper-network`, and `buildathon`;
- the GitHub community profile is complete, CodeQL and Dependabot alerts are
  enabled, CI/security workflows are green, and no High or Critical alert is
  open;
- the deployed MVP is fully functional on Casper Testnet;
- the judge playbook is concise, step-by-step, and operational rather than
  marketing copy;
- the BUIDL page names every current contract package hash and describes the
  sample Testnet transactions it links; and
- a fresh incognito crawl checks every application route, anchor, redirect,
  explorer receipt, documentation link, repository link, video link, and BUIDL
  link. Any dead link, doubled dashboard base path, unavailable anchor, console
  error, or failed required request blocks publication.

The qualification-round proof below remains historical context. Finals v3,
treasury, SafePay v2, and official-x402 claims are published only after their
separately versioned live artifacts and release gates pass.

## Core proof path

The final proof is Locke submitting the approved governance receipt to a deployed Casper Testnet contract. A mock receipt hash is only for rehearsal.

```text
Council Chamber approval -> Locke -> governance receipt contract -> Casper Testnet transaction
```

## Ecosystem adapter status

- The canonical live proof uses the Jun 29 v1 Odra `GovernanceReceipt.store_governance_receipt` receipt anchor at `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1` with deploy `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852`. The supplemental quorum exercise uses the Jun 30 v2 quorum-enabled GovernanceReceipt package and is live-complete: `configure_quorum`, `propose_envelope`, pre-quorum blocked `store_governance_receipt`, server signer approval, browser-wallet approval, and final receipt after quorum are recorded in `artifacts/live/odra-quorum-exercise-plan.json`. `CouncilRegistry` was exercised through a representative `register_agent` call, and `TreasuryPolicy` / `CardIndexLedger` were independently called through `validate_allocation` / `seal_card_root` in `artifacts/live/odra-topology-genesis-proof.json`. Verify the package with `python scripts/verify_odra_migration.py`, `python scripts/exercise_odra_modules.py`, `python scripts/prepare_odra_quorum_exercise.py`, `python scripts/build_odra_topology_genesis_proof.py`, `cargo +nightly test`, and the `RUSTFLAGS='-C link-arg=--allow-undefined' cargo +nightly build --target wasm32-unknown-unknown --release --bin concordia_odra_governance_receipt_build_contract` command in `contracts/odra-governance-receipt/migration.manifest.json`.
- CSPR.cloud REST and Streaming adapters are credential-gated; without `CSPR_CLOUD_ACCESS_TOKEN`, they report mock or not-configured status instead of fabricating live data.
- CSPR.trade MCP and Casper MCP tools call external MCP URLs only when configured.
- x402 supports local demo proof, real CSPR transfer-hash verification through CSPR.live, and credential-gated facilitator/provider settlement paths with indexer-lag retry; the Casper governance receipt remains the primary Testnet proof path.
- IPFS evidence pinning is live on the hosted deployment through Concordia's Kubo node. The final proof pack includes CID `bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq`, served through `/api/ipfs/{cid}`. Pinata remains an optional external pinner; Web3.Storage/NFT.Storage token paths are treated as legacy unless their current UCAN/w3up-style auth flows are configured.

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

SafePay Lite demonstrates conditional paid specialist-report settlement: Concordia verifies Casper payment, validates the provider report hash, shows deterministic duplicate-proof replay, records provider reputation delta, and includes the result in the governance proof. It must remain visibly unverified if payment verification, provider response validation, report-hash verification, or deterministic duplicate-proof replay fails.

## MCP live read boundary

The optional FastMCP bridge exposes two non-mutating Casper read tools:

```text
casper_node_status   -> JSON-RPC info_get_status through configured node endpoint
casper_public_status -> HTTPS GET to CASPER_PUBLIC_STATUS_URL
```

Use these to demonstrate that the tool boundary is real without pretending that mocked treasury quotes are live.

## Casper execution runtime arguments

Concordia no longer sends every value as text. The receipt contract expects:

```text
proposal_hash: ByteArray(32)
final_card_hash: ByteArray(32)
plan_hash: ByteArray(32)
policy_hash: ByteArray(32)
dissent_hash: ByteArray(32)
agent_action_hash: ByteArray(32)
risk_score: U32
approved_allocation_bps: U32
```

The hosted runtime builds the same values as native `pycspr` CLValue objects,
signs the deploy in Python, serializes it to Casper JSON, and broadcasts over
HTTPS JSON-RPC. It does not call host CLI binaries or Node scripts for Locke's
final proof transaction. Malformed control characters, oversized strings, and
non-numeric U32 values fail closed before execution. Apostrophes remain valid in
JSON-RPC/CLString metadata and are not rejected merely because the old CLI path
once needed quote scrubbing.

## Preflight

Before recording the final demo, run:

```bash
CASPER_EXECUTION_MODE=real make casper-preflight
```

The check fails if the key path is unreadable, the execution driver is missing, or `CASPER_RECEIPT_CONTRACT_HASH` is not copied with the `hash-` prefix.

## Final Casper proof

The submission has a real Casper Testnet transaction hash for the approved Concordia governance receipt.

Current hosted status:

```text
Public URL: https://concordia.47.84.232.193.sslip.io/dashboard
Casper Testnet live read: verified from the hosted gateway
Hosted execution mode: real
Hosted receipt contract hash: hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1
Hosted Testnet public key: 019aeeb6276a9bfe8534a1b51cc7c1e0b72b63cd307566f08d91223bee9e610151
Hosted Locke driver: pycspr native Python JSON-RPC
Native Python deploy assembly: live broadcast complete
Final receipt transaction: e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852
Explorer: https://testnet.cspr.live/deploy/e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852
```

Completed proof steps:

1. Funded the hosted Testnet public key.
2. Deployed the governance receipt contract.
3. Confirmed the hosted env is in real mode with a non-placeholder
   `CASPER_RECEIPT_CONTRACT_HASH`.
4. Ran the approved Concordia proposal flow and recorded Locke's real transaction hash
   in `docs/SUBMISSION_PACKET.md`.
