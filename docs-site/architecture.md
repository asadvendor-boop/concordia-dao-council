# Architecture

Concordia DAO Council is an off-chain multi-agent governance council with an
on-chain Casper receipt anchor. Three layers are deliberately separated:

```text
Proposal simulator / DAO feed
        |
        v
FastAPI Gateway / Concordia Core        <- deterministic authority
  - proposal state machine
  - Council Chamber messages
  - card sealing
  - nonce lifecycle
  - authorization lifecycle
        |
        +--> Rowan  / Proposal Sentinel            \
        +--> Mercer / Treasury Intelligence Agent    |  Deliberative agents
        +--> Verity / Risk & Legal Agent             |  (advisory only)
        +--> Alden  / Protocol Strategy Agent        /
        |
        +--> Locke  / Casper Execution Role   <- authorization-bound, not advisory
        +--> Wells  / Archival persona        <- non-reasoning presentation
        |
        v
Casper Testnet governance receipt contract   <- on-chain anchor
```

## Council Chamber (advisory layer)

The Council Chamber is where the four **deliberative agents** — Rowan, Mercer,
Verity, and Alden — reason over a proposal. They can explain routing, assess
evidence, challenge proposals, and draft plans, but nothing they say can
authorize or execute anything. **Locke** is not a deliberative voice: it is an
authorization-bound execution role that can only submit the exact envelope the
deterministic core has already authorized. **Wells** is a non-reasoning
archival/presentation persona; it presents the sealed record but does not
reason, summarize, or close the session — session closure and the deterministic
archive are owned by Concordia Core (see below), not by Wells. Chamber identity
is authenticated: message sender identity comes from the authenticated key
mapping, never from caller-supplied fields, and agent keys cannot impersonate
human or system senders. Human approval enters only through a separately
hardened approval boundary.

## Gateway / Concordia Core (deterministic authority)

The FastAPI Gateway hosts Concordia Core, which owns everything that matters:

- **Proposal state machine** — every state transition is code, not model
  output.
- **Card sealing** — each decision step becomes a typed card in a SHA-256
  hash chain (see the evidence model below).
- **Nonce lifecycle** — the multisig approval gate binds a single-use nonce
  to the exact action hash it approves.
- **Authorization lifecycle** — Locke can execute only a consumed
  authorization whose exact action envelope matches the approved hash. Any
  mismatch in target, parameter, action count, or hash is refused.
- **Policy enforcement** — the DAO Constitution (policy-as-code) is evaluated
  deterministically; violations produce Dissent Receipts, not silent edits.

## Evidence model

Every decision is a typed card:

```text
ProposalCard -> TriageDecision -> Assessment -> Verdict -> ResponsePlan
  -> StructuredApproval -> PolicyAuthorization -> CasperExecutionReceipt
  -> GovernanceSummary
```

Each card carries `sequence_number`, `previous_card_hash`, and `card_hash`.
Changing any historical card breaks the chain, and the public
`/evidence/{proposal_id}` endpoint recomputes and reports verification status.

## On-chain anchor

The final on-chain receipt stores the identity of the approved decision, not a
re-narration of it:

```text
proposal_id, proposal_hash, final_card_hash, plan_hash, decision,
risk_level, treasury_action, evidence_uri, agent_action_hash
```

Reviewers can therefore compare the local evidence chain with the Casper
Testnet transaction field by field. Receipt roots are typed Casper CLValues
(`ByteArray(32)` for roots, `U32` for numeric risk/allocation fields), so the
comparison is exact rather than textual.

## Casper services used

- **Casper Testnet** for the transaction-producing receipt.
- **Odra receipt contracts** in `contracts/` (see
  [On-Chain Governance Receipts](governance-receipts.md) for the v1/v2/v3
  lineage).
- **Python-native Casper execution** — the Gateway builds, signs, serializes,
  and broadcasts the stored-contract deploy over JSON-RPC directly with
  `pycspr`; no shell-out to `casper-client` and no Node.js in the execution
  path.
- **CSPR.cloud** via credential-gated adapters; without credentials the
  adapter reports `not_configured` instead of pretending to be live.
- **MCP bridge** for read-only judge auditing (node status is a real JSON-RPC
  read; external MCP calls require explicitly configured server URLs and are
  labelled mock otherwise).
- **x402 payment rails** — the supplemental [SafePay Lite](safepay-lite.md)
  native-CSPR rail and the [Official x402](official-x402.md) WCSPR facilitator
  integration. Both are finals work in progress; see each page for its exact
  proof status (`PENDING_PROOF` until live evidence is captured).
- **IPFS evidence pinning** via a Concordia-hosted Kubo node with a public
  gateway route.

## Trust boundary summary

- Advisory models may explain and suggest; they cannot execute.
- Deterministic policy owns state transitions and executable envelopes.
- The multisig approval gate binds a nonce to the exact action hash.
- Locke refuses any mismatch against the approved envelope.
- The final receipt is sealed only after the Casper execution path returns a
  transaction result.
