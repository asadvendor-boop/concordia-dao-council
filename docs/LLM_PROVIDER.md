# LLM Provider Policy

Concordia is provider-agnostic. The deterministic Gateway holds all authority:
models are advisory and interchangeable, while policy checks, nonce binding,
exact-envelope validation, quorum gating, and Casper execution are enforced by
code.

Canonical role taxonomy (used consistently across all judge-facing copy):

- **Four deliberative agents** — Rowan, Mercer, Verity, and Alden — reason over
  the proposal. Their model output is purely advisory.
- **Locke** is an **authorization-bound, model-involved execution role**, not a
  fifth deliberative agent. It is model-involved only as a narrow echo: it can
  submit the exact envelope the deterministic core has already authorized.
- **Concordia Core** is deterministic infrastructure, not a model.
- **Wells** is a **non-reasoning archival/presentation persona**. The
  deterministic governance archive is produced by Locke/Core; Wells presents the
  record and performs no model reasoning.

The system uses OpenAI-compatible environment variables. The values below are
example values for any OpenAI-compatible provider, not a statement that the
hosted walkthrough uses a specific vendor:

```bash
LLM_API_KEY=
LLM_BASE_URL=https://api.openai.com/v1
LLM_ROWAN_MODEL=gpt-4o-mini
LLM_MERCER_MODEL=gpt-4o
LLM_VERITY_MODEL=gpt-4o
LLM_ALDEN_MODEL=gpt-4o
LLM_LOCKE_MODEL=gpt-4o-mini
LLM_SCRIBE_MODEL=gpt-4o-mini
```

## Deployed model assignment (hosted walkthrough)

The hosted walkthrough assigns models by **tier**, matched to what each role
actually needs. The specific provider and model identifiers used by the current
hosted deployment are release-derived facts recorded in the deployment
configuration, not fixed here.

| Persona | Internal role | Model tier | Why |
|---|---|---|---|
| Mercer | `diagnosis` | Deep-reasoning tier | Deep treasury and risk analysis needs reasoning depth. |
| Verity | `safety_reviewer` | Deep-reasoning tier | Challenge and dissent quality is the product. |
| Alden | `commander` | Deep-reasoning tier | Plan synthesis and DAO Mandate drafting require stronger reasoning. |
| Rowan | `triage` | Low-latency tier | High-frequency routing favors low latency. |
| Locke | `operator` | Low-latency tier | Narrow execution echo is deliberately low-authority. |
| Wells | `scribe` | Configured metadata label only | Non-reasoning archival/presentation persona: archiving and governance publication are deterministic code paths, and Wells performs no model reasoning in the judge path. Not one of the model-involved live-required roles. |

The Gateway's live-readiness gate covers five model-involved roles reported by
the public `/ready` endpoint: `triage`, `diagnosis`, `safety_reviewer`, and
`commander` (the four deliberative agents) plus `operator` (Locke's execution
role). Wells's `scribe` role is intentionally not gated — its archive is
deterministic code, not model reasoning.

You do not need to swap models to qualify. The important point is to keep the
LLM layer advisory. The deterministic Gateway and exact-envelope checker remain
the authority for state transitions, approval, and execution.

For the final recorded and hosted judging demo, require live model configuration:

```bash
APP_ENV=production
CONCORDIA_REQUIRE_LIVE_LLM=1
```

`CONCORDIA_TEST_MODE=1` and `CONCORDIA_DISABLE_LLM_REASONING=1` are local
development controls only. They must not be enabled for the final judge-facing
workflow.

The runtime still accepts older role-based model variables as backwards-compatible
aliases, but judge-facing documentation and hosted configuration should prefer
the persona-named variables above.
