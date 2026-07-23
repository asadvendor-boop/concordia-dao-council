# Concordia DAO Council

**Concordia DAO Council is the Casper governance firewall for AI-run DAOs.**
Deliberative agents advise, but they cannot execute. A deterministic core owns
every state transition, seals every decision into a tamper-evident evidence
chain, and binds execution to the exact approved envelope. Dissent Receipts
preserve the risk agent's objection, the execution role is bound to the exact
approved hash, and browser-wallet quorum is proven on-chain: the same action is
reverted before quorum and accepted after quorum.

!!! info "Proof status and release data"
    Concordia separates **frozen historical proof** from **current finals work**.
    The canonical reviewer receipt, the two-way quorum proof, and the historical
    SafePay Lite payment are live on Casper Testnet and are cited with their
    frozen on-chain values throughout this site. The finals upgrades — the
    GovernanceReceipt **v3** exact-envelope contract, SafePay Lite **v2**, and the
    **official x402** settlement service — are still being captured. Every current
    identifier, hash, block height, URL, and status for them is sourced from a
    generated, schema-validated release manifest written only after the live
    capture passes; until a value is present in that manifest it is shown as
    `PENDING_PROOF`, never as verified. See
    [On-Chain Governance Receipts](governance-receipts.md) for the full v1/v2/v3
    lineage.

## The constitutional execution firewall

Most "AI-run DAO" designs let a language model summarize, recommend — and then
quietly act. Concordia inverts that. The council's reasoning layer is advisory
by construction, and a constitutional execution firewall sits between
deliberation and the chain:

1. **Deliberation is off-chain and fully recorded.** Every council step is
   sealed into a SHA-256 hash-chained evidence trail.
2. **Policy is code.** The DAO Constitution caps what any proposal may do
   (in the flagship scenario, a 30% treasury request is capped to 8%).
3. **Dissent is preserved, not overwritten.** An unsafe proposal produces a
   structured Dissent Receipt whose hash travels with the final decision.
4. **Approval binds a nonce to an exact action hash.** The multisig approval
   gate authorizes one exact envelope, once.
5. **Execution is narrow.** The deterministic core refuses any target,
   parameter, action count, or hash mismatch, so only the approved envelope
   reaches Casper. Moving this exact-envelope binding from core code into the
   contract itself is the GovernanceReceipt v3 finals work (proof status
   pending — see [On-Chain Governance Receipts](governance-receipts.md)).
6. **The receipt is public.** The final governance receipt is anchored to
   Casper Testnet, where anyone can verify it against the evidence chain.

## Four deliberative agents, one execution role, one deterministic core

The council has **six named personas**, but they are not six voices of equal
authority:

- **Four deliberative agents** — Rowan, Mercer, Verity, and Alden — reason over
  the proposal. Their model output is purely advisory: they classify, analyze,
  challenge, and draft, but nothing they say can authorize or execute anything.
- **Locke** is an **authorization-bound execution role**, not a fifth
  deliberative agent. It is model-involved only as a narrow echo: it can submit
  the exact envelope the deterministic core has already authorized, and nothing
  else.
- **Concordia Core** is deterministic code (not a persona). It seals cards,
  owns state transitions, validates nonces, and enforces exact-envelope binding.
- **Wells** is a **non-reasoning archival/presentation persona**. It presents
  the sealed record for review; it does not reason, summarize, decide, or
  produce the archive. The deterministic governance archive is produced by
  Locke/Core, not by Wells.

| Persona | Role | Nature |
|---|---|---|
| **Rowan** | Proposal Sentinel — classifies incoming DAO proposals and opens the Council Chamber. | Deliberative agent (advisory) |
| **Mercer** | Treasury Intelligence Agent — reviews treasury exposure, liquidity context, RWA impact, and Casper ecosystem signals. | Deliberative agent (advisory) |
| **Verity** | Risk & Legal Agent — challenges unsafe proposals and files structured Dissent Receipts. | Deliberative agent (advisory) |
| **Alden** | Protocol Strategy Agent — converts deliberation into an exact governance execution envelope. | Deliberative agent (advisory) |
| **Locke** | Casper Execution Role — submits only the envelope the deterministic core has authorized and anchors the receipt on-chain. | Authorization-bound execution role (model-involved, not deliberative) |
| **Wells** | Governance Archivist persona — presents the sealed evidence trail for review. | Non-reasoning archival/presentation persona |
| **Concordia Core** | Deterministic Evidence Core — seals cards, owns state transitions, validates nonces, and enforces exact-envelope binding. | Deterministic code (not a persona) |

The Gateway's live-readiness gate covers five model-involved roles reported by
the public `/ready` endpoint: `triage`, `diagnosis`, `safety_reviewer`, and
`commander` (the four deliberative agents) plus `operator` (Locke's execution
role). Wells's `scribe` role is intentionally not gated — its archive is
deterministic code, not model reasoning. The reasoning layer is
provider-agnostic: models are advisory and interchangeable, while policy checks,
nonce binding, exact-envelope validation, quorum gating, and Casper execution
are enforced by deterministic code.

## The flagship scenario

A malicious or over-eager proposal asks to move **30% of the DAO treasury**
into a high-yield liquidity strategy:

1. Rowan routes the proposal into the Council Chamber.
2. Mercer analyzes treasury exposure, policy state, and Casper node status.
3. Verity blocks it — it violates the DAO Constitution's 8% single-allocation
   cap — and records a Dissent Receipt.
4. Alden revises the plan to a policy-compliant 8% capped allocation.
5. A human multisig approver approves the exact revised envelope.
6. Locke anchors the approved, capped decision — including the dissent hash —
   to Casper Testnet.
7. The deterministic core seals the final governance archive; Wells presents it
   for review.

Every step above is verifiable after the fact: see
[Proof & Verification](proof-verification.md) for how to check it yourself,
and [On-Chain Governance Receipts](governance-receipts.md) for the contract
lineage behind the receipts.

## Where to go next

- [Architecture](architecture.md) — how the Council Chamber, Gateway, and
  Concordia Core are separated.
- [On-Chain Governance Receipts](governance-receipts.md) — the v1/v2 receipt
  contracts (historical, live) and the v3 exact-envelope contract (current
  work).
- [Judge Walkthrough Quickstart](judge-walkthrough.md) — verify the live proof
  in minutes.
- [Links](links.md) — live application, repository, and demo video.
