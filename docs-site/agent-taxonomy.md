# Agent and Role Taxonomy

Concordia names roles by responsibility rather than by model provider.

| Role | Responsibility | Authority limit |
| --- | --- | --- |
| Rowan — Proposal Sentinel | Normalize and route the proposal | Cannot approve or execute |
| Mercer — Treasury Intelligence | Analyze allocation, liquidity, and evidence | Advisory only |
| Verity — Constitutional Risk | Challenge policy violations and preserve dissent | Cannot mutate the plan |
| Alden — Governance Strategist | Produce a bounded response plan | Plan requires deterministic checks |
| Locke — Casper Execution | Prepare the exact approved action | Cannot bypass human approval or hash binding |
| Wells — Governance Archivist | Summarize and publish evidence references | Cannot declare failed evidence valid |
| Concordia Core | Policy, integrity, approval, and state transitions | Deterministic code, not an agent persona |

## Card chain

Each role emits typed cards into a proposal-scoped chain. The chain records
sequence number, prior-card identity, typed content, and publication state.
Public views must preserve dissent and superseded evidence rather than silently
rewriting the decision history.

## Model boundary

Agents may suggest text or analysis. They do not own allocation arithmetic,
approval validity, nonce consumption, proof verification, or transaction
success. If a model answer contradicts deterministic policy, deterministic
policy wins.

## V1.5 boundary

This taxonomy describes the V1 council. Governance v3 is excluded from V1.5;
historical parser names in the verifier do not add agents or runtime roles.
