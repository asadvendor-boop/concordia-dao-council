# LLM Provider Policy

Concordia is provider-agnostic. The deterministic Gateway holds all authority:
models are advisory and interchangeable, while policy checks, nonce binding,
exact-envelope validation, quorum gating, and Casper execution are enforced by
code.

The system uses OpenAI-compatible environment variables. The values below are
example values for any OpenAI-compatible provider, not a statement that the
hosted walkthrough uses OpenAI:

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

The hosted Concordia walkthrough uses Qwen models with role-specific depth:

| Persona | Internal role | Deployed model | Why |
|---|---|---|---|
| Mercer | `diagnosis` | `qwen3.7-plus` | Deep treasury and risk analysis needs reasoning depth. |
| Verity | `safety_reviewer` | `qwen3.7-plus` | Challenge and dissent quality is the product. |
| Alden | `commander` | `qwen3.7-plus` | Plan synthesis and DAO Mandate drafting require stronger reasoning. |
| Rowan | `triage` | `qwen3.6-flash` | High-frequency routing favors low latency. |
| Locke | `operator` | `qwen3.6-flash` | Narrow execution echo is deliberately low-authority. |
| Wells | `scribe` | `qwen3.6-flash` via `LLM_SCRIBE_MODEL`, archival metadata label | Archiving and governance publication are deterministic code paths; Wells is not one of the five live-required advisory roles. |

The Gateway's live-readiness gate covers exactly five advisory roles: `triage`,
`diagnosis`, `safety_reviewer`, `commander`, and `operator`. These are the same
five roles reported by the public `/ready` endpoint. Wells's archival pipeline is
deterministic by design.

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
