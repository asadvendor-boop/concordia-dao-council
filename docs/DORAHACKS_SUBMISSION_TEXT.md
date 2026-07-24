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
binds off-chain execution to the exact approved envelope, dissent is preserved in
the evidence chain and its hash is anchored in the on-chain receipt, and
browser-wallet quorum is proven on-chain — the same action is reverted before
quorum and accepted after quorum.

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
- **Concordia Core** is deterministic infrastructure, not a model. It owns the
  off-chain policy checks, nonces, exact-envelope authorization, and trusted
  execution boundary. Casper contracts independently enforce on-chain quorum;
  the v3 contract adds on-chain exact-envelope authorization once its separately
  versioned live proof passes.
- **Wells** is a non-reasoning archival/presentation persona. The deterministic
  archive is produced by Locke/Core; Wells presents the record and performs no
  model reasoning.

No model has authority. Agents advise; deterministic Core constrains off-chain
authorization; the contract decides on-chain quorum; a human keeps the final no.

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

The finals live sequence is designed to execute one real native-CSPR treasury
transfer authorized by on-chain quorum and bound to the approved envelope hash
(a 625 CSPR snapshot → a 50 CSPR transfer, with the transfer ID bound to the
authorized envelope). One-time v3 finalization is authorization, not execution;
the executor's durable journal is the replay lock. Documented boundary, stated
plainly: once the pending live gate passes, this proves duplicate prevention
inside Concordia's trusted executor; it cannot prevent an independently
compromised treasury key from bypassing that executor.
`PENDING_PROOF`: treasury execution — finalized native-transfer deploy
(625 CSPR snapshot → 50 CSPR transfer, bound transfer ID) + execution artifact.

### 2. SafePay Lite — supplemental payments in native CSPR

The historical, verified receipt: the council pays for an external specialist
risk report, and 2.5 CSPR settles on-chain before that evidence is allowed to
influence the decision — `dcb35f42…`, verified at block 8,339,447, in **native
CSPR** through SafePay Lite (a naming correction from round 1, which imprecisely
labelled it "x402"). The locally verified finals implementation adds durable
single-use consumption (v2): every issued quote is persisted immutably, every
payment is consumed exactly once, an exact same-resource retry is idempotent,
any cross-resource reuse is terminally rejected, and all of it survives provider
restart. Those are implementation properties, not a hosted/live claim until the
pending exercise below passes.
`PENDING_PROOF`: SafePay Lite v2 replay-safe live artifact — idempotent
same-resource retry + terminal cross-resource rejection, both surviving provider
restart.

### 3. Official x402 — WCSPR via the CSPR.cloud facilitator

The finals candidate contains a separate greenfield service for the official
x402 protocol (x402 version 2, `exact` scheme, network
`casper:casper-test`). Its intended live sequence is a signed
`transfer_with_authorization` over **WCSPR** — a wrapped token distinct from
native CSPR — verified and settled through the CSPR.cloud facilitator, gated
behind on-chain v3 finalization of the governing envelope. The local service
fails closed: HTTP 200, `/supported`, or `isValid:true` are never treated as
settlement success; only `success:true` plus a finalized, read-back on-chain
transfer can lift the pending live gate.
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
- **No fabricated proof in the judge path.** The current walkthrough replays a
  genuine recorded run from its sealed evidence chain (labelled as a
  reconstruction, never a fabricated animation). The finals release will enable
  its judge-safe fresh-proposal path only after the hosted configuration proves
  live model calls, chain reads, and payment boundaries.
  `PENDING_PROOF`: hosted RC configuration + fresh-proposal capability exercise.
- **Finals engineering upgrade.** A typed exact-envelope v3 contract, three
  cleanly separated payment claims, a hardened judge-demo path, a public docs
  site, and an npm verifier package — each carries its own proof status; nothing
  pending is presented as done.

## Built on the Casper AI Toolkit

Concordia directly implements Casper's example direction #3,
**Multi-Agent DAO Governance & Execution** — then adds constitutional
exact-envelope enforcement and public refusal receipts. The integration map is
concrete:

- **Odra:** the sibling GovernanceReceipt v3 contract enforces quorum,
  proposal-independent action uniqueness, and exact-envelope authorization on
  Casper Testnet once its live gate below passes.
- **Official x402 + Casper EIP-712:** WCSPR
  `transfer_with_authorization` uses the pinned official Casper x402 and typed
  signing implementations; settlement cannot start until the separate v3
  governance envelope is finalized.
- **CSPR.cloud:** bounded Casper reads and the official facilitator provide the
  middleware and settlement boundary; `/supported` and `/verify` are never
  mistaken for finalized payment evidence.
- **CSPR.click / Casper Wallet:** a real browser-wallet signer already
  participates in the historical quorum proof; the official-x402 finals path
  uses the supported tagged Casper signing formats and independently recomputes
  their account hashes.
- **Casper RPC and MCP-readable proof:** raw deploy, block, state, and transfer
  observations are exposed through proof surfaces and a judge tool rather than
  hidden behind dashboard status labels.

Transaction rails make autonomous agents capable of spending. Concordia makes
the exact financial action constitutionally governable.

## Long-term launch and Casper ecosystem impact

- Community presence is already public at
  [@ConcordiaDAO](https://x.com/ConcordiaDAO), including the
  [launch post](https://x.com/ConcordiaDAO/status/2074438324769689653).
- The purchased `concordiadao.xyz` domain, public documentation portal, and
  `@concordia-dao/verify` package make the policy templates and proof verifier
  reusable outside this demo. Their publication gates remain explicit below.
- **30 days:** onboard one Casper DAO or treasury-design partner, publish three
  reusable policy packs (treasury allocation, RWA onboarding, protocol
  parameters), and open public milestones/issues.
- **60 days:** pilot the exact-envelope controller with one Casper DAO and one
  RWA review workflow, publish latency/refusal/recovery metrics, and expand
  CSPR.click custody guidance.
- **90 days:** ship organization deployment templates, audited policy
  administration, event-stream finality monitoring, and a separately versioned
  Mainnet canary without rewriting the Testnet proof lineage.
- **Six months:** offer Concordia as open governance middleware plus hosted
  evidence/compliance operations for Casper DAOs and RWA protocols.

## Verify everything yourself

- Live Judge Walkthrough: https://concordiadao.xyz/dashboard/judge
- Proof Center: https://concordiadao.xyz/dashboard/proof
- Evidence Chain: https://concordiadao.xyz/evidence/DAO-PROP-6CB25C
- Proof Pack: https://concordiadao.xyz/proof-pack/DAO-PROP-6CB25C
- Technical Jury Note: https://concordiadao.xyz/technical-jury-note
- Certificate: https://concordiadao.xyz/certificate/DAO-PROP-6CB25C
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
  --base-url https://concordiadao.xyz --proposal-id
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

## Finals public URL map

- Main application: `https://concordiadao.xyz`; `https://www.concordiadao.xyz`
  redirects to the main application.
- SafePay v2 provider: `https://safepay.concordiadao.xyz` for the native-CSPR
  provider flow.
- Official WCSPR facilitator: `https://x402.concordiadao.xyz` for the separate
  official x402 settlement flow.
- Documentation site: `https://docs.concordiadao.xyz`.
  `PENDING_PROOF`: HTTPS/publication evidence for these finals surfaces.
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
