# Verifier SDK / CLI

Concordia is meant to be checked from your own machine, not just read about.
Two verification surfaces exist, with deliberately different scopes.

## Available today: the consistency checker

`scripts/verify_concordia_receipt.py` is a dependency-free Python **consistency
checker** for a Concordia proof pack or the hosted proof endpoints. Its scope
and honest limits are documented in full on
[Proof & Verification](proof-verification.md):

- it validates the evidence packet's self-reported chain-validity flag and
  required root fields, the receipt's deploy/contract-hash shape, the
  `store_governance_receipt` entry point, the typed-argument shape, and the
  quorum outcome;
- with `--live-chain` it looks the deploy up on a **trusted, operator-configured**
  Casper node RPC and CSPR.live and diffs the deploy hash, contract hash, entry
  point, and typed runtime arguments it reads there against the local pack;
- it does **not** reconstruct the exact card preimages or independently recompute
  the full evidence chain — it trusts the artifact's declared roots. Its output
  declares its own `verification_scope` and `observation_sources` so its reach is
  never overstated.

Treat this tool as *artifact/transcript consistency*, not *independent chain
recomputation*.

## Finals deliverable: `@concordia-dao/verify`

!!! warning "Not yet published"
    The independent recompute-from-scratch verifier is a finals deliverable that
    is **not yet published**. `PENDING_PROOF`: `@concordia-dao/verify` published
    to npm + clean-room install + independent recompute against hosted evidence.

The planned `@concordia-dao/verify` package is a single canonical library plus a
`concordia-verify` CLI. By design it **never trusts artifact booleans**
(`passed`, `chain_valid`, `verified`, `duplicate_proof_rejected`) and instead
independently recomputes:

- card/evidence hashes and their linkage;
- v3 envelope and action hashes and the shared encoding vectors;
- v3 package/contract/runtime/finality facts;
- SafePay Lite quote/payment/report/consumption binding;
- official-x402 requirements/payload/settlement/report binding;
- native-transfer source/recipient/amount/transfer-ID/finality.

It will distinguish **invalid** from **unavailable/unknown**, return
deterministic JSON with stable exit codes, and support local-file, URL,
proposal/base-URL, and optional live-chain modes.

Until it is published and passes its release gates (pack/clean-room/provenance,
valid-proof success, tampered-proof refusal), no tool here should be described as
an independent recomputation of the chain. The strongest independent surface
today is the set of public CSPR.live deploys — compare their entry point and
typed runtime arguments against the evidence chain yourself, as described in the
[Judge Walkthrough](judge-walkthrough.md).
