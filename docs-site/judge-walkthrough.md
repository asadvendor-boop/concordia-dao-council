# Judge Walkthrough Quickstart

Verify Concordia's core claims in about five minutes, using only public
surfaces. No account, wallet, or local install is required for steps 1–6.

## 1. Open the guided walkthrough

- <https://concordia.47.84.232.193.sslip.io/dashboard/judge>

This walks the flagship scenario end to end: the unsafe 30% treasury request,
Verity's dissent, the 8% DAO Mandate cap, exact-envelope approval, pre-quorum
rejection, quorum acceptance, and the final receipt.

## 2. Open the Proof Center

- <https://concordia.47.84.232.193.sslip.io/dashboard/proof?proposal=DAO-PROP-6CB25C>

This is the expert drill-down: proof table, policy leash meter, blocked rogue
action, and artifact downloads.

## 3. Check the evidence chain

- <https://concordia.47.84.232.193.sslip.io/evidence/DAO-PROP-6CB25C>

The endpoint recomputes the SHA-256 card chain live and reports verification
status. The proof packet for the hero run shows `decision:
APPROVED_WITH_LIMITS`, requested allocation `3000 bps`, approved allocation
`800 bps`, and the `max_single_allocation_bps` policy event, together with the
dissent, policy, and final card hashes.

## 4. Confirm the receipts on CSPR.live

- Canonical reviewer receipt:
  <https://testnet.cspr.live/deploy/e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852>
- Quorum acceptance (block 8,350,034):
  <https://testnet.cspr.live/deploy/9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928>

For the quorum story, note that the *pre-quorum* attempt
`6280b8e1...bcf67431` failed on-chain with `User error: 8` (`QuorumNotMet`) at
block 8,349,116 — the acceptance only succeeded after the 2-of-3 gate passed,
including a browser-wallet approval.

## 5. Download the certificate and audit packet

- Certificate (HTML): <https://concordia.47.84.232.193.sslip.io/certificate/DAO-PROP-6CB25C>
- Certificate (PDF, with QR links): <https://concordia.47.84.232.193.sslip.io/certificate/DAO-PROP-6CB25C/pdf>
- Audit packet: <https://concordia.47.84.232.193.sslip.io/proof-pack/DAO-PROP-6CB25C/download>

## 6. Read the scope boundary

- <https://concordia.47.84.232.193.sslip.io/technical-jury-note>

Concordia freezes the canonical proof for reproducibility and states its
boundaries explicitly: what is live, what is supplemental, and what is
roadmap. Nothing is presented as production that is not.

## 7. (Optional) Run the consistency checker locally

```bash
python scripts/verify_concordia_receipt.py \
  --base-url https://concordia.47.84.232.193.sslip.io \
  --proposal-id DAO-PROP-6CB25C \
  --live-chain
```

This dependency-free Python tool is a **narrow consistency checker**, not an
independent recomputation of the chain (see
[Proof & Verification](proof-verification.md) for its exact
`verification_scope`). With `--live-chain` it looks the deploy up on a trusted,
operator-configured Casper node RPC and CSPR.live and diffs the deploy hash,
contract hash, entry point, and typed runtime arguments it reads there against
the local proof pack; run without `--live-chain` it is offline artifact review
only. A verifier that reconstructs the card preimages and recomputes the whole
evidence chain from your own machine — the `@concordia-dao/verify` CLI — is a
finals deliverable and is not yet published (`PENDING_PROOF`). The strongest
independent check today is step 4 above: compare the public CSPR.live deploys
against the evidence chain yourself.

## What you have verified

- The deliberation record is hash-chained and recomputes cleanly.
- The on-chain receipt matches the local evidence field by field.
- Policy enforcement is real: the 30% request was capped to 8%, with dissent
  preserved by hash.
- Quorum is enforced by the contract, not the UI: the same action failed
  before quorum and succeeded after it, on the public chain.
