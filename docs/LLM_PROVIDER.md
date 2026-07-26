# LLM Provider Policy

Concordia is provider-agnostic. The system uses OpenAI-compatible environment variables:

```bash
LLM_API_KEY=
LLM_BASE_URL=https://api.openai.com/v1
LLM_ROWAN_MODEL=gpt-4o-mini
LLM_MERCER_MODEL=gpt-4o
LLM_VERITY_MODEL=gpt-4o
LLM_ALDEN_MODEL=gpt-4o
LLM_LOCKE_MODEL=gpt-4o-mini
```

You do not need to swap models to qualify. The important point is to remove vendor-specific branding and keep the LLM layer advisory. The deterministic Gateway and exact-envelope checker must remain the authority for state transitions, approval, and execution.

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
