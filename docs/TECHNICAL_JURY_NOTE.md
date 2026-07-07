# Concordia Technical Jury Note

This note is written for technical reviewers who inspect whether Concordia is a reusable governance engine or only a scripted demo.

## Positioning

Concordia DAO Council is the Casper governance firewall for AI-run DAOs: Dissent Receipts preserve Verity's objection, Locke is bound to the exact approved hash, and browser-wallet quorum is proven on-chain when execution is reverted before quorum and accepted after quorum.

## Implementation Lineage

The Concordia-native module names (`agents.rowan`, `agents.mercer`, `agents.verity`, `agents.alden`, `agents.locke`, `agents.wells`) are the supported public entry points for the submitted council and now hold the active implementations. Earlier engineering package names remain only as small compatibility shims so older scripts, environment variables, recorded proof artifacts, and regression tests continue to resolve during the buildathon review window. This is a naming lineage boundary, not a separate hidden product path: the proof hierarchy, dashboard personas, docs, and public demo should be read through the Concordia council names.

## Canonical Proof Hierarchy

Use this hierarchy when cross-checking the repository, Proof Center, Judge Walkthrough, proof pack, audit packet, certificate, and CSPR.live links:

| Proof item | Value |
|---|---|
| Canonical proposal | `DAO-PROP-6CB25C` |
| Canonical reviewer receipt | `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852` |
| Canonical contract | `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1` |
| Canonical contract explorer URL | `https://testnet.cspr.live/contract/a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1` |
| Supplemental quorum receipt | `9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928` |
| Browser wallet receipt | `56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf` |
| Supplemental dynamic lifecycle proof | `DAO-PROP-DYN-002` -> `68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0` |
| Supplemental RWA invoice-pool receipt | `DAO-PROP-RWA-001` -> `3803a5bb561a84a8c103e3c4e8eea99b3a1c893c63644c56ed38daa1986825cc` |
| x402 SafePay Lite payment | `dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c` |
| IPFS archive CID | `bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq` |

Older proof hashes may remain in artifacts only as historical or superseded evidence. They are not the canonical reviewer receipt.

## Why The Canonical Proof Is Frozen

The canonical proof is frozen for reproducibility. It lets judges verify one stable governance lifecycle across:

- public evidence chain
- Casper Testnet deploy
- typed runtime arguments
- IPFS archive
- SafePay Lite proof
- quorum exercise
- downloadable audit packet
- certificate QR links

The frozen proof is not a claim that every possible DAO proposal has already been executed on-chain. It is the canonical reviewer proof for the final submission.

## Dynamic Proposal Boundary

Concordia supports non-canonical proposal handling in two modes:

1. Dynamic preview mode for proposals that have evidence but have not been separately signed and anchored.
2. Supplemental dynamic execution proof for `DAO-PROP-DYN-002`, which is processed on Casper Testnet through receipt `68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0`.

Non-canonical proposals are not advertised as fully executed unless their own evidence chain, typed deploy payload, signature, finality record, and proof artifact exist.

`DAO-PROP-RWA-001` is a supplemental RWA invoice-pool proof. It has its own evidence packet and backend-signed Casper Testnet receipt `3803a5bb561a84a8c103e3c4e8eea99b3a1c893c63644c56ed38daa1986825cc`, but it is not the canonical reviewer receipt.

## Odra Contract Boundary

Concordia has two live GovernanceReceipt iterations:

- v1 receipt anchor, deployed Jun 29: `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1` under package `hash-992b3a457eedf67f1b50c29f7971199b757d9576dcbaa51e0d52fda3a0fa4c4a`. The canonical reviewer receipt `e926...`, browser-wallet receipt `56b6...`, and supplemental dynamic receipt `68fd...` write here.
- v2 quorum-enabled GovernanceReceipt package, deployed Jun 30: `hash-1d324e319701e4adcfa9476efcde3d047462d35e79d2cd8c7326c0c384c87d96`. The supplemental final quorum receipt `9d631...` writes through this package after the 2-of-3 approval gate passes.

Auxiliary Odra modules are independently exercised as supplemental topology genesis proof:

- `CouncilRegistry.register_agent` through a representative Locke registration.
- `TreasuryPolicy.validate_allocation`.
- `CardIndexLedger.seal_card_root`.

This proves the auxiliary modules can be installed and called on Casper Testnet. It does not claim the current canonical reviewer receipt actively cross-calls every auxiliary module in a fully productized four-contract production DAO suite.

## SafePay Lite Boundary

SafePay Lite demonstrates conditional paid specialist-report settlement:

- Concordia verifies a Casper payment hash.
- Concordia validates the returned provider report hash.
- Concordia shows deterministic duplicate-proof replay.
- Concordia records provider reputation delta.
- Concordia includes the result in the governance proof.

SafePay Lite is not described as full escrow, a refund contract, or a marketplace.

## Roadmap Boundary

Full cross-contract production enforcement remains roadmap unless a future proof table lists it as live. That production version would require GovernanceReceipt to actively depend on CouncilRegistry, TreasuryPolicy, and CardIndexLedger during receipt execution.

Roadmap-only items are:

- full Enterprise IAM and durable queues
- full Event Streaming / SSE finality pipeline
- fully productized cross-contract DAO suite with on-chain registry/policy/index dependencies

The final submission should be evaluated as a canonical, reproducible Casper governance proof with supplemental dynamic execution, quorum, SafePay Lite, IPFS, and topology-genesis evidence.
