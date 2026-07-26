# Deployment and Security

The V1.5 public evidence is Casper Testnet-only. Mainnet has not been executed,
and no Mainnet key or fund claim belongs in this release.

## Runtime boundaries

- The gateway owns deterministic policy, approval, and evidence routes.
- The dashboard is a reviewer/operator surface and does not bypass the gateway.
- SafePay Lite is a recorded proof under the apex, not a separate promoted
  provider domain.
- Shared Caddy and neighboring judged applications are outside the Concordia
  deployment boundary.
- Secrets, keys, databases, caches, generated output, and nested repositories
  are excluded from the public source tree.

## Publication boundaries

GitHub Pages builds the curated `docs-site/` tree. A manual candidate dispatch
may build and upload a Pages artifact, but only `refs/heads/main` can run the
deploy job.

The npm verifier has no publish script. Publication is a manual trusted
workflow bound to the exact public `main` tip, an npm OIDC trusted publisher,
the `npm-production` environment, and post-publish provenance verification.

## Security scanning

CodeQL uses GitHub default setup; the repository intentionally does not contain
a custom `codeql.yml`. Dependabot alerts remain enabled through repository
settings. The dismissed-findings register and reporting instructions live in
the repository security policy.

## Threat boundary

- LLM output is untrusted input.
- Approval tokens are single-use and hash-bound.
- Paths, JSON, remote URLs, response sizes, and timeouts are bounded.
- Missing or contradictory evidence fails closed.
- Casper-native x402 v2 implements an HTTP 402 payment request, payment intent,
  and native-transfer verification on Testnet. A later official facilitator
  service and successful external-provider settlement are not shipped or
  claimed.
- Governance v3 is excluded from V1.5.

Report vulnerabilities privately through the repository Security tab.
