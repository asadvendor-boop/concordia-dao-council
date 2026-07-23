# Agent & Role Taxonomy

Concordia's authority model is the whole point of the system, so its roles are
named precisely. There are six personas, but they do **not** carry equal
authority, and only some of them reason with a model.

## The canonical taxonomy

- **Four deliberative agents — Rowan, Mercer, Verity, Alden.** These reason over
  a proposal. Their model output is purely **advisory**: they classify, analyze,
  challenge, and draft. Nothing they say can authorize or execute anything.
- **Locke — an authorization-bound execution role.** Locke is *model-involved*
  but is **not a fifth deliberative agent**. It is a narrow echo: it can submit
  the exact envelope the deterministic core has already authorized, and nothing
  else. Its authority is deliberately minimal.
- **Concordia Core — deterministic infrastructure, not a persona and not a
  model.** Core seals cards, owns every state transition, validates nonces, and
  enforces exact-envelope binding. It is the authority.
- **Wells — a non-reasoning archival/presentation persona.** Wells *presents*
  the sealed record for review. It does **not** reason, summarize, decide, close
  the session, or produce the archive. The deterministic governance archive is
  produced by Locke/Core.

| Persona | Role | Nature | Authority |
|---|---|---|---|
| **Rowan** | Proposal Sentinel | Deliberative agent (advisory) | None — advises only |
| **Mercer** | Treasury Intelligence Agent | Deliberative agent (advisory) | None — advises only |
| **Verity** | Risk & Legal Agent | Deliberative agent (advisory) | None — advises only |
| **Alden** | Protocol Strategy Agent | Deliberative agent (advisory) | None — advises only |
| **Locke** | Casper Execution Role | Model-involved execution role (not deliberative) | Submit only the pre-authorized envelope |
| **Wells** | Governance Archivist persona | Non-reasoning archival/presentation persona | None — presents the record |
| **Concordia Core** | Deterministic Evidence Core | Deterministic code (not a persona) | Owns state, policy, nonces, exact-envelope binding |

## Readiness gate

The Gateway's live-readiness gate covers five model-involved roles reported by
the public `/ready` endpoint: `triage`, `diagnosis`, `safety_reviewer`, and
`commander` (the four deliberative agents) plus `operator` (Locke's execution
role). Wells's `scribe` role is intentionally **not** gated — its archive is
deterministic code, not model reasoning.

## Why this separation matters

Most "AI-run DAO" designs let a language model summarize, recommend — and then
quietly act. Concordia refuses that shape. The reasoning layer is provider-
agnostic and advisory; policy checks, nonce binding, exact-envelope validation,
quorum gating, and Casper execution are enforced by deterministic code. A model
can be wrong, adversarial, or swapped out, and the guarantees still hold.

See [Architecture & Trust Boundaries](architecture.md) for how these roles map
onto the Council Chamber, the Gateway/Core, and the on-chain anchor.
