# Proof & Verification

Concordia's live proof is designed so a judge can verify the whole governance
loop **without trusting the demo narration**. Every claim below is checkable
from public surfaces.

## Canonical proof hierarchy

Use these values for public review. Older hashes may appear in artifacts only
as clearly labeled historical or superseded evidence.

| Proof item | Canonical value |
|---|---|
| Proposal | `DAO-PROP-6CB25C` |
| Canonical reviewer receipt | `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852` |
| Canonical contract | `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1` |
| Quorum pre-quorum rejection proof | `6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431` (`User error: 8` / `QuorumNotMet`, block 8,349,116) |
| Quorum acceptance proof (block 8,350,034) | `9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928` |
| Browser wallet receipt | `56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf` |
| Supplemental dynamic lifecycle proof | `DAO-PROP-DYN-002` → `68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0` |
| Supplemental RWA receipt | `DAO-PROP-RWA-001` → `3803a5bb561a84a8c103e3c4e8eea99b3a1c893c63644c56ed38daa1986825cc` |
| x402 SafePay Lite payment (historical, v1 flow) | `dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c` |
| IPFS archive CID | `bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq` |

## The Proof Center

The dashboard's Proof Center is the judge-facing proof surface:

- <https://concordia.47.84.232.193.sslip.io/dashboard/proof?proposal=DAO-PROP-6CB25C>

It shows the compact proof table, the policy leash meter, the blocked rogue
action, the outcome gallery, and links to every downloadable artifact. The
guided version of the same story is the
[Judge Walkthrough](judge-walkthrough.md).

## CSPR.live receipts

Every on-chain claim resolves to a public explorer page:

- Canonical reviewer receipt:
  <https://testnet.cspr.live/deploy/e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852>
- Supplemental quorum receipt:
  <https://testnet.cspr.live/deploy/9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928>
- Supplemental dynamic receipt:
  <https://testnet.cspr.live/deploy/68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0>
- Canonical v1 contract:
  <https://testnet.cspr.live/contract/a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1>

Compare the deploy's entry point (`store_governance_receipt`) and typed
runtime arguments against the evidence chain and proof pack — they must match
field by field.

## Evidence chain

The public evidence endpoint recomputes the SHA-256 card chain on request and
reports verification status:

- <https://concordia.47.84.232.193.sslip.io/evidence/DAO-PROP-6CB25C>

Changing any historical card would break the chain, so a passing recomputation
is evidence the deliberation record is intact.

## Certificate

The certificate renders the canonical proof with QR links for offline review:

- HTML: <https://concordia.47.84.232.193.sslip.io/certificate/DAO-PROP-6CB25C>
- PDF: <https://concordia.47.84.232.193.sslip.io/certificate/DAO-PROP-6CB25C/pdf>

## Audit packet

The downloadable governance archive bundles the evidence chain, proof pack,
and receipt references:

- <https://concordia.47.84.232.193.sslip.io/proof-pack/DAO-PROP-6CB25C/download>

The archive is also pinned to IPFS under CID
`bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq`.

## Independent verifier script

The standalone verifier is dependency-free and runs against the public API:

```bash
python scripts/verify_concordia_receipt.py \
  --base-url https://concordia.47.84.232.193.sslip.io \
  --proposal-id DAO-PROP-6CB25C
```

It checks evidence-chain validity, the Casper deploy hash, the receipt
contract hash, the `store_governance_receipt` entry point, the
`policy_hash`/`dissent_hash`/`final_card_hash`/`plan_hash` roots, the typed
Casper arguments, and the blocked-rogue-execution proof.

With network access, add live-chain mode:

```bash
python scripts/verify_concordia_receipt.py \
  --base-url https://concordia.47.84.232.193.sslip.io \
  --proposal-id DAO-PROP-6CB25C \
  --live-chain
```

Live-chain mode additionally queries Casper Testnet/CSPR.live, confirms the
deploy finalized successfully, and diffs the live contract hash, entry point,
and typed runtime arguments against the local proof pack.

## MCP judge bridge (optional)

An optional read-only FastMCP bridge lets an MCP-capable client audit the
proof conversationally (`integrations/mcp/concordia_casper_mcp.py`). It does
not sign transactions or mutate state; node status is a real JSON-RPC read,
and anything requiring unconfigured external services is explicitly labelled
mock instead of pretending to be live.

## What "verified" means here

Proof items are reported across separate dimensions — generation, lineage
(canonical vs supplemental), observation mode, temporal scope, verification
status, and execution outcome. An expected rejection (like the pre-quorum
`QuorumNotMet`) is a verified proof with outcome `expected_rejection`. Nothing
renders green unless every required check for that proof type passed against
an available observation.
