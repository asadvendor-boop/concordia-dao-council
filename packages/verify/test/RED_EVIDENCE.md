# WP8 TDD RED evidence

- Frozen base: `b24c0409023e6c4b56287d4fddc17bdb42d9b1ac`
- Observed at: `2026-07-22T20:06:24Z`
- Command: `npm test`
- Result: exit `1`; `0` passed, `7` failed.
- Expected cause: the tests require the not-yet-implemented
  `dist/index.js` and `dist/cli.js` entry points. Node reported
  `ERR_MODULE_NOT_FOUND` / `MODULE_NOT_FOUND`; the CLI assertions observed the
  placeholder process exit `1` instead of the frozen verifier exit codes.

No production implementation existed when this failure was recorded.

## Independent-review RED evidence

- Observed at: `2026-07-22T20:25Z`.
- Command: `npm test` after adding the reviewer's regression cases and before
  changing production code.
- Result: exit `1`; `24` passed, `4` failed.
- Failures reproduced all three review classes: `__proto__` changed the parsed
  object's prototype; common/native/x402 validators accepted frozen-semantic
  mutations; and the distributable API/documentation contract was incomplete.
- After the production fixes, the expanded suite passes `29/29`, including
  byte-identity checks for all 21 vectors copied into the packed artifact.
