# Proof & Verification

Concordia's live proof is designed so a judge can verify the whole governance
loop **without trusting the demo narration**. Every claim below is checkable
from public surfaces.

## Canonical proof hierarchy

Every value in the table below is **frozen historical proof** already live on
Casper Testnet — use these for public review. Older hashes may appear in
artifacts only as clearly labeled historical or superseded evidence. Values for
the finals **current work** (GovernanceReceipt v3, SafePay Lite v2, official
x402, native-transfer execution) are **not** in this table: they are sourced
from a generated, schema-validated release manifest after live capture and are
`PENDING_PROOF` until then — see
[On-Chain Governance Receipts](governance-receipts.md).

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

The public evidence endpoint recomputes the SHA-256 card chain server-side on
request and reports verification status:

- <https://concordia.47.84.232.193.sslip.io/evidence/DAO-PROP-6CB25C>

Changing any historical card would break the chain, so a passing recomputation
is evidence the deliberation record is internally intact. Note the observation
source: this recomputation is performed by Concordia's own hosted endpoint. The
independent, trust-nothing check is comparing the on-chain deploys on CSPR.live
(below) against the evidence chain and proof pack field by field.

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

## Verifier script — scope and honest limits

`scripts/verify_concordia_receipt.py` is a dependency-free consistency checker
for a Concordia proof pack or the hosted proof endpoints. It is deliberately
**narrow**, and its output declares its own `verification_scope` and
`observation_sources` so a reader never has to guess what was actually checked.

```bash
python scripts/verify_concordia_receipt.py \
  --base-url https://concordia.47.84.232.193.sslip.io \
  --proposal-id DAO-PROP-6CB25C
```

What it checks (artifact/transcript scope):

- the evidence packet's self-reported chain-validity flag and required root
  fields (`policy_hash`, `dissent_hash`, `final_card_hash`, `plan_hash`) are
  present and well-formed;
- the receipt's deploy/transaction hash and contract hash are well-formed, the
  entry point is `store_governance_receipt`, and the typed args carry
  `ByteArray(32)` roots and `U32` numeric fields;
- the compact proof table, execution-firewall flag, and quorum outcome are
  internally consistent.

What it does **not** do: it does not independently reconstruct the exact stored
card preimages, and it does not by itself recompute the full SHA-256 evidence
chain from raw card contents — it trusts the artifact's declared roots and
booleans. Its `verification_scope` is therefore *artifact/transcript
consistency*, not *independent chain recomputation*.

With network access, `--live-chain` adds an on-chain cross-check:

```bash
python scripts/verify_concordia_receipt.py \
  --base-url https://concordia.47.84.232.193.sslip.io \
  --proposal-id DAO-PROP-6CB25C \
  --live-chain
```

Live mode looks the deploy up on a **trusted, operator-configured** Casper node
RPC and the public CSPR.live explorer, confirms the deploy finalized, and diffs
the deploy hash, contract hash, entry point, and the typed runtime arguments it
reads there against the local pack. Those RPC/explorer endpoints must be
explicitly trusted HTTPS endpoints — never URLs taken from the artifact. Run
**without** `--live-chain`, the tool performs offline artifact review only and
reports it as such (`observation_sources: [artifact]`); offline output is never
described as a current-chain observation.

!!! note "Independent recompute-from-scratch verifier — PENDING_PROOF"
    A verifier that independently reconstructs the exact card preimages and
    recomputes the whole evidence chain from your own machine — the
    `@concordia-dao/verify` CLI (`npm install @concordia-dao/verify`) — is a
    finals deliverable that is **not yet published**. Until it passes its card,
    historical-receipt, v3, treasury, SafePay, official-x402, freshness,
    provenance, and safe live-observer gates, no tool here should be read as an
    independent recomputation of the chain.
    `PENDING_PROOF`: `@concordia-dao/verify` published + clean-room recompute.
    The strongest independent surface today is the public CSPR.live deploys
    linked above — compare their entry point and typed runtime arguments against
    the evidence chain and proof pack yourself.

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
