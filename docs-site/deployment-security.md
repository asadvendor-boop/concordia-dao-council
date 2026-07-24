# Deployment & Security

This page summarizes Concordia's deployment shape and security posture for
reviewers. The authoritative, always-current security policy — including the
dismissed-findings register — is the repository's
[`SECURITY.md`](https://github.com/asadvendor-boop/concordia-dao-council/blob/main/.github/SECURITY.md).

!!! warning "Finals-sprint posture — release-derived, not a present guarantee"
    The completeness statements below are the **target** posture for the finals.
    Each is confirmed only by inspecting the final hosted configuration and by the
    final CodeQL/Dependabot gate. Until that release evidence exists, treat them
    as `PENDING_PROOF`, not as current guarantees.

## Deployment shape

- Finals-facing public URLs use the owned-domain map in [Links](links.md): the
  main application is `https://concordiadao.xyz`, `www` redirects to it,
  SafePay v2 is `https://safepay.concordiadao.xyz`, official WCSPR x402 is
  `https://x402.concordiadao.xyz`, and the documentation portal is
  `https://docs.concordiadao.xyz`.
- HTTPS/publication evidence and the published verifier package remain separate
  `PENDING_PROOF` release gates.
- Historical URLs inside immutable proof artifacts are never rewritten.

## Deterministic authority

Models advise. The deterministic Concordia Core owns off-chain policy checks,
nonce binding, exact-envelope authorization, and the trusted execution boundary;
the Casper contract independently owns the on-chain quorum gate. The v3 contract
adds on-chain exact-envelope authorization only when its separately versioned
live proof passes. A human keeps the final no. See
[Agent & Role Taxonomy](agent-taxonomy.md) and
[Architecture & Trust Boundaries](architecture.md).

## Approval boundary

Human approval passes a coordinated reverse-proxy + gateway boundary: Basic
Auth, a server-side proxy secret that overwrites anything a caller supplies,
bcrypt credential verification, an approver allowlist, CSRF protection, and a
one-time nonce. `PENDING_PROOF`: hosted approval-boundary adversarial tests.

## Judge-demo capability

Judge-triggered demo runs use a short-lived, scenario-scoped, single-use signed
capability: the operator token never reaches the browser, the public reset
endpoint is removed, and every demo-created record carries its own run ID so
cleanup can never touch canonical history. `PENDING_PROOF`: hosted
demo-capability adversarial tests.

## Secrets hygiene (target)

The intended posture is that runtime secrets load only via `_FILE` indirection
from `/run/secrets`, with no secret values in the repository, images, logs, or
error responses, and facilitator/operator tokens never echoed back. Confirmation
that every production secret meets this bar is a release-derived fact
(`PENDING_PROOF`).

## Automated scanning

GitHub CodeQL code scanning and Dependabot alerts are enabled; high-severity
findings are tracked and either remediated or dismissed with a public
justification register. A statement that scanning and remediation are *complete*
is valid only after the final gate runs against the integrated tree
(`PENDING_PROOF`).
