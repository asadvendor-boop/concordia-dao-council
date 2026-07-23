# DoraHacks Submission Text

Ready-to-paste copy for the DoraHacks Casper buildathon finals BUIDL. Every
statement about unreleased finals work carries a machine-searchable
`PENDING_PROOF` marker; a marker is removed only when the release manifest proves
its gate. Do not publish while any `PENDING_PROOF` marker remains.

## Project Title

Concordia DAO Council

## Lead

The constitutional execution firewall for AI-run DAOs on Casper.

## Short Description

Concordia DAO Council is the Casper governance firewall for AI-run DAOs: four
deliberative agents advise, a deterministic core owns every state transition and
binds execution to the exact approved envelope, dissent is preserved as an
on-chain receipt, and browser-wallet quorum is proven on-chain — the same action
is reverted before quorum and accepted after quorum.

## The problem — a DeFi and RWA treasury-risk problem

A DAO treasury is a DeFi position with no risk desk. The dollar-risk class is the
**governance-attack treasury drain**: value lost not through a broken contract
but through a proposal that passes — flash-loaned voting power, low turnout,
rushed execution — where the amount at risk is the entire treasury balance,
exposed once per passed proposal. Nobody reads the contract call it executes
until the funds are gone.

The same failure mode governs **real-world assets**. When a treasury holds
tokenized property, receivables, or a cap table, an unreviewed allocation is not
just a token transfer — it is a claim on real collateral, and it inherits every
consequence of the underlying asset. Governance that can be bypassed by one
well-timed proposal is exactly what keeps institutional RWA capital out of
on-chain treasuries. Concordia is governance for the machine economy: automated
agents can deliberate over real value, but they cannot move it without clearing a
deterministic, on-chain-anchored firewall.

## How it works — deliberation advises, deterministic code decides

Concordia has six named personas, but they do not carry equal authority:

- **Four deliberative agents — Rowan, Mercer, Verity, Alden** — reason over the
  proposal. Their model output is purely advisory.
- **Locke** is an authorization-bound, model-involved execution role — not a
  fifth deliberative agent. It submits only the exact envelope the deterministic
  core has authorized.
- **Concordia Core** is deterministic infrastructure, not a model. It owns every
  policy check, nonce, quorum gate, exact-envelope binding, and Casper execution.
- **Wells** is a non-reasoning archival/presentation persona. The deterministic
  archive is produced by Locke/Core; Wells presents the record and performs no
  model reasoning.

No model has authority. Agents advise; the chain decides; a human keeps the
final no.

## Honest council-depth comparison

Many "AI-run DAO" designs stop at a chat of agents that summarize, recommend, and
then quietly act. Concordia's depth is not a count of personas — it is the
separation of powers between an advisory reasoning layer and a deterministic
execution authority, and the fact that disagreement is recorded rather than
smoothed away. We do not claim a larger number of agents than any other project;
we claim that our agents cannot execute, and that the deterministic core can
refuse anything that is not byte-exactly what quorum approved.

## The proof

A malicious AI tries to move **30% of the DAO treasury**. The DAO Constitution
caps allocations at **8%**. The deterministic invariant runner catches the
violation off-chain, Verity seals her objection as a **Dissent Receipt**, Alden
converts the safe action into a **DAO Mandate**, and Locke cannot submit anything
else. In this historical run, quorum was enforced on-chain; exact-envelope
binding was enforced off-chain by the deterministic core.

Then the centerpiece: the **same execution envelope**, submitted twice —

- Before quorum, the contract itself reverts it: `6280b8e1…` — `User error: 8`
  (`QuorumNotMet`), block 8,349,116.
- After 2-of-3 quorum (including a browser-wallet approval), accepted:
  `9d631fe1…`, block 8,350,034.

The only difference is the quorum. The chain said no in public, and handed us the
receipt.

## Contract lineage — historical v1/v2 vs current v3

- **v1 — historical typed receipt anchor** (deployed Jun 29): holds the canonical
  reviewer receipt `e926582f…` under contract
  `hash-a8640466…` / package `hash-992b3a45…`.
- **v2 — historical quorum-gated receipt storage** (deployed Jun 30, package
  `hash-1d324e31…`): the 2-of-3 quorum gate is enforced on-chain (the receipt
  pair above); exact-envelope enforcement remained off-chain in the deterministic
  core.
- **v3 — current exact-envelope enforcement** (finals upgrade): a new sibling
  contract crate and a new Testnet package that moves exact-envelope binding
  on-chain. It does not modify or retroactively re-protect the historical v1/v2
  receipts, and an old receipt never proves a v3 property.
  `PENDING_PROOF`: v3 install (package/contract hash + install deploy) and the
  four-outcome live proof (`QuorumNotMet`, `EnvelopeHashMismatch`, exact
  acceptance, `AlreadyFinalized` deploy hashes + block heights +
  `action_authorized=true` readback).

## Real value moved — three separate claims, never conflated

### 1. Treasury execution — native CSPR, authorized on-chain

A real treasury transfer, authorized by on-chain quorum, bound to the approved
envelope hash, executed as a native transfer (a 625 CSPR snapshot → a 50 CSPR
transfer, transfer ID bound to the authorized envelope). One-time v3 finalization
is authorization, not execution; the executor's durable journal is the replay
lock. Documented boundary, stated plainly: Concordia prevents duplicate execution
through its trusted executor; it cannot prevent an independently compromised
treasury key from bypassing that executor.
`PENDING_PROOF`: treasury execution — finalized native-transfer deploy
(625 CSPR snapshot → 50 CSPR transfer, bound transfer ID) + execution artifact.

### 2. SafePay Lite — supplemental payments in native CSPR

The historical, verified receipt: the council pays for an external specialist
risk report, and 2.5 CSPR settles on-chain before that evidence is allowed to
influence the decision — `dcb35f42…`, verified at block 8,339,447, in **native
CSPR** through SafePay Lite (a naming correction from round 1, which imprecisely
labelled it "x402"). The finals upgrade gives SafePay Lite durable single-use
consumption (v2): every issued quote is persisted immutably, every payment is
consumed exactly once, an exact same-resource retry is idempotent, any
cross-resource reuse is terminally rejected, and all of it survives provider
restart.
`PENDING_PROOF`: SafePay Lite v2 replay-safe live artifact — idempotent
same-resource retry + terminal cross-resource rejection, both surviving provider
restart.

### 3. Official x402 — WCSPR via the CSPR.cloud facilitator

A separate, greenfield settlement service implements the official x402 protocol
(x402 version 2, `exact` scheme, network `casper:casper-test`): a signed
`transfer_with_authorization` over **WCSPR** — a wrapped token distinct from
native CSPR — verified and settled through the official CSPR.cloud facilitator,
gated behind on-chain v3 finalization of the governing envelope. The service is
fail-closed: HTTP 200, `/supported`, or `isValid:true` are never treated as
settlement success; only `success:true` plus a finalized, read-back on-chain
transfer counts.
`PENDING_PROOF`: official x402 settlement — facilitator `success:true` +
finalized WCSPR `transfer_with_authorization` + post-settlement on-chain
readback.

## Final Round updates

- **Full link audit, same day.** During qualification review, reviewers flagged
  broken links. We audited every link on every page the same day, found one
  malformed link on the judge walkthrough (a Next.js `basePath` doubling), and
  fixed it within hours, publicly. The automated sweep now passes with zero
  broken links, and we re-run it throughout the judging window.
- **Failure handling promoted to the headline.** The unhappy path is the demo,
  and judges can reproduce it live.
- **No fixture mode in the judge path.** The deployment you are testing runs with
  mocking disabled — model calls, chain reads, and payments are live against
  Casper Testnet. The judge walkthrough replays a genuine recorded run from its
  sealed evidence chain (labelled as a reconstruction, never a fabricated
  animation), and you can trigger a fresh proposal yourself from the dashboard.
- **Finals engineering upgrade.** A typed exact-envelope v3 contract, three
  cleanly separated payment claims, a hardened judge-demo path, a public docs
  site, and an npm verifier package — each carries its own proof status; nothing
  pending is presented as done.

## Verify everything yourself

- Live Judge Walkthrough: https://concordia.47.84.232.193.sslip.io/dashboard/judge
- Proof Center: https://concordia.47.84.232.193.sslip.io/dashboard/proof
- Evidence Chain: https://concordia.47.84.232.193.sslip.io/evidence/DAO-PROP-6CB25C
- Proof Pack: https://concordia.47.84.232.193.sslip.io/proof-pack/DAO-PROP-6CB25C
- Technical Jury Note: https://concordia.47.84.232.193.sslip.io/technical-jury-note
- Certificate: https://concordia.47.84.232.193.sslip.io/certificate/DAO-PROP-6CB25C
- Canonical reviewer receipt: https://testnet.cspr.live/deploy/e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852
- Quorum acceptance receipt: https://testnet.cspr.live/deploy/9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928
- IPFS evidence archive CID: `bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq`
- SafePay Lite settlement (native CSPR, historical): https://testnet.cspr.live/deploy/dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c

## Verify Concordia from your own tools

- **On-chain, trust-nothing.** Click any receipt hash — each opens on
  testnet.cspr.live. Compare the entry point (`store_governance_receipt`) and the
  typed runtime arguments against the evidence chain field by field. This is the
  strongest independent check available today.
- **Consistency checker.** `python3 scripts/verify_concordia_receipt.py
  --base-url https://concordia.47.84.232.193.sslip.io --proposal-id
  DAO-PROP-6CB25C` runs a dependency-free consistency check whose output declares
  its own `verification_scope` and `observation_sources`. With `--live-chain` it
  diffs the deploy against a trusted, operator-configured Casper node RPC and
  CSPR.live. It is an artifact/transcript consistency checker, not an independent
  recomputation of the chain.
- **Independent recompute verifier.** `@concordia-dao/verify` recomputes card and
  evidence hashes from scratch and never trusts artifact booleans.
  `PENDING_PROOF`: `@concordia-dao/verify` published to npm + clean-room install +
  independent recompute against hosted evidence.
- **MCP judge tool.** Interrogate the proofs from your own MCP client: check
  Casper node status, inspect the canonical receipt, and audit `DAO-PROP-6CB25C`
  end to end.

## Launch surfaces (pending publication)

These ship inside the final round; the existing sslip links above are the
working, submitted aliases and never change.

- Production domain: `concordiadao.xyz` (+ `www`, `x402` subdomain).
  `PENDING_PROOF`: production domain live, sslip aliases intact.
- Documentation site: `docs.concordiadao.xyz`.
  `PENDING_PROOF`: docs site live over HTTPS.
- Verifier package: `npm install @concordia-dao/verify`.
  `PENDING_PROOF`: npm publish + clean-room install.

## Published repository and video

- Public repository: https://github.com/asadvendor-boop/concordia-dao-council
- Demo video (current): https://www.youtube.com/watch?v=GU01V83Jrko
  A new finals video covering the four v3 outcomes and all three payment claims
  replaces this link before submission.
  `PENDING_PROOF`: new finals video — incognito-verified public URL showing all
  four v3 outcomes and all three payment claims.

## Honest scope

Concordia is a canonical, reproducible Casper governance proof system with
supplemental dynamic execution evidence — not a claim of a fully productized
enterprise DAO suite, a full escrow marketplace, or a fully productized
four-contract DAO suite. Historical and current claims are kept separate: v1 is
the historical typed receipt anchor, v2 is historical quorum-gated receipt
storage whose exact-envelope enforcement remained off-chain, and v3 is the
current exact-envelope enforcement upgrade with its own live proof pending. Every
claim on this page either ends in a public receipt or carries an explicit
`PENDING_PROOF` marker until its gate passes.
