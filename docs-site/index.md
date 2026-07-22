# Concordia DAO Council

**Concordia DAO Council is the Casper governance firewall for AI-run DAOs.**
Advisory agents deliberate, but they cannot execute. A deterministic core owns
every state transition, seals every decision into a tamper-evident evidence
chain, and permits execution only for the exact approved envelope. Dissent
Receipts preserve the risk agent's objection, the execution agent is bound to
the exact approved hash, and browser-wallet quorum is proven on-chain: the same
action is reverted before quorum and accepted after quorum.

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
5. **Execution is narrow.** The execution agent refuses any target, parameter,
   action count, or hash mismatch. Only the approved envelope reaches Casper.
6. **The receipt is public.** The final governance receipt is anchored to
   Casper Testnet, where anyone can verify it against the evidence chain.

## Six personas, five reasoning agents, one deterministic core

The council has **six named personas**, of which **exactly five are live
reasoning (advisory) agents**. The sixth, Wells, is the archivist: his
governance-archive pipeline is deterministic code, not model reasoning — the
archive is a truth constraint, not an opinion.

| Persona | Role | Nature |
|---|---|---|
| **Rowan** | Proposal Sentinel — classifies incoming DAO proposals and opens the Council Chamber. | Reasoning agent |
| **Mercer** | Treasury Intelligence Agent — reviews treasury exposure, liquidity context, RWA impact, and Casper ecosystem signals. | Reasoning agent |
| **Verity** | Risk & Legal Agent — challenges unsafe proposals and files structured Dissent Receipts. | Reasoning agent |
| **Alden** | Protocol Strategy Agent — converts deliberation into an exact governance execution envelope. | Reasoning agent |
| **Locke** | Casper Execution Agent — executes only the approved envelope and anchors the receipt on-chain. | Reasoning agent (deliberately low-authority) |
| **Wells** | Governance Archivist — summarizes the session and records the sealed evidence trail. | Deterministic archival pipeline |
| **Concordia Core** | Deterministic Evidence Core — seals cards, owns state transitions, validates nonces, and enforces exact-envelope execution. | Deterministic code (not a persona) |

The Gateway's live-readiness gate covers exactly five advisory roles —
`triage`, `diagnosis`, `safety_reviewer`, `commander`, and `operator` — the
same five reported by the public `/ready` endpoint. Wells is intentionally not
one of them. The reasoning layer is provider-agnostic: models are advisory and
interchangeable, while policy checks, nonce binding, exact-envelope validation,
quorum gating, and Casper execution are enforced by deterministic code.

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
7. Wells produces the final governance archive.

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
