# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Concordia DAO Council, please report
it privately rather than opening a public issue.

- Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  ("Report a vulnerability" under the repository's **Security** tab), or
- Contact the maintainers directly.

Please include steps to reproduce and the potential impact. We aim to
acknowledge reports promptly and will keep you informed of remediation progress.

!!! warning "Finals-sprint posture — release-derived, not yet a present guarantee"
    This document describes the **target** security posture for the Casper
    buildathon finals. The completeness statements below — every production
    secret loaded via `_FILE`, the new finals services being in supported scope,
    and scanning/remediation being complete — are **release-derived facts** that
    hold only after the WP3 approval-boundary and WP5 official-x402 integrations
    land, the production configuration is inspected, and the final
    CodeQL/Dependabot gate passes. Until that release evidence exists, treat each
    such statement as `PENDING_PROOF`, not as a current guarantee.

## Supported Scope

The judged application and its automated `pycspr` release signer run on Casper
**Testnet**. A separately versioned Mainnet canary is preparation-only until its
own live gate passes; the Mainnet browser-wallet account is not mounted into,
or available to, unattended automation. The security-relevant surfaces are:

- the governance gateway API (`gateway/`), including the human-approval
  boundary and the judge-demo capability endpoints,
- the Casper contract packages (`contracts/`),
- the proof/evidence runtime (`shared/proof_runtime.py`),
- the SafePay Lite payment provider (`x402_provider/`), and
- the official x402 settlement service (`services/x402-official/`, a finals
  service that enters supported scope **on integration** — `PENDING_PROOF`
  until the WP5 corrected commit lands).

## Secrets Handling (finals-sprint target)

The intended production posture is that runtime secrets are loaded only via
`_FILE` indirection from `/run/secrets` (for example
`*_FILE=/run/secrets/<name>`), with no direct-value secret environment
variables, and that no secret values appear in the repository, container images,
logs, or error responses, and facilitator or operator tokens are never echoed
back in response bodies or diagnostics. Confirmation that **every** production
secret meets this bar is a release-derived fact produced by inspecting the final
hosted configuration during the WP3/WP5 integration — `PENDING_PROOF` until then.

## Automated Scanning

This repository has GitHub CodeQL code scanning and Dependabot alerts enabled.
High-severity findings are tracked, and the intent is that they are remediated
or dismissed with justification. A statement that scanning and remediation are
**complete** is only valid after the final CodeQL/Dependabot gate runs against
the integrated finals tree — `PENDING_PROOF` until that gate result exists.
Non-applicable findings (for example, timing side-channels that require local
co-residency, or build-time-only dependencies with no runtime untrusted-input
path) are documented and dismissed with justification.

## Remediated Findings (July 2026 review — pending final-gate confirmation)

The following remediations were applied in code during the July 2026 review.
They are confirmed as *complete for the release* only when the final
CodeQL/Dependabot gate re-runs against the integrated tree (`PENDING_PROOF`):

- **11 High CodeQL alerts addressed in code**: path-traversal hardening via a
  basename-sanitize + `normpath`/`startswith` containment guard
  (`gateway/app.py::_safe_data_path`), an anchored regex for the insecure-URL
  audit check, and bounded regex quantifiers plus an input cap for the
  allocation parser (`shared/proof_runtime.py`).
- **High dependency advisories addressed by upgrade**: `langsmith` → 0.10.0
  (SSRF, GHSA in TracingMiddleware), `starlette` → 1.3.1 (form-limits
  bypass; SSRF/UNC credential theft), and `click` → 8.3.3
  (`GHSA-47fr-3ffg-hgmw` / `CVE-2026-7246`), verified against the test suite
  at the time of each fix. Concordia does not call the vulnerable
  `click.edit()` API, but the compatible patched release is pinned anyway.

## Dismissed Findings Register

The following advisories are dismissed **with justification** because no
installable fix exists. Each is revisited when its upstream constraint lifts.

| Advisory | Package | Severity | Why it cannot be fixed today | Risk assessment |
|---|---|---|---|---|
| GHSA-rc23-xxgq-x27g | `wee_alloc` (Rust, contract build) | Critical (unmaintained) | No patched release exists. It is a build-time WASM allocator; swapping it changes the compiled WASM and would invalidate the deployed testnet contract package hash currently under judging. | No runtime untrusted-input path; build-time only. Replace before any mainnet build. |
| GHSA-537c-gmf6-5ccf | `cryptography` | High | Transitive via `pycspr==1.2.0` — the latest Casper Python SDK — which pins `cryptography>=42.0.2,<43.0.0`; the fixed 48.0.1 is resolver-incompatible with that cap. | The affected path requires an attacker-controlled DER primitive larger than 2 GiB. Concordia's release key loaders cap trusted operator PEM files at 64 KiB, and x402 uses fixed-size raw keys/signatures rather than DER. |
| GHSA-r6ph-v2qm-q3c2 | `cryptography` | High | Same `pycspr` cap; the fixed 46.0.5+ cannot be installed with `pycspr==1.2.0`. | The affected APIs require SECT curves or generic DER/PEM public-key loading. Concordia's payment path uses raw Ed25519 or SECP256K1 keys and no SECT curve. |
| GHSA-m959-cc7f-wv43, GHSA-79v4-65xg-pq4g, GHSA-h4gh-qq45-vh27 | `cryptography` | High/Medium | The available fixes begin above the `<43.0.0` cap imposed by `pycspr==1.2.0`. | These findings concern X.509 verification, TLS raw-public-key processing, or OpenSSL expected-name checks. Concordia does not expose those APIs in its agent, release, or payment paths. |
| GHSA-wj6h-64fc-37mp | `ecdsa` (Minerva) | High | No upstream fix has shipped; `ecdsa` is transitive via `pycspr`. | The advisory concerns P-256 signing; `pycspr` hardcodes deterministic SECP256K1 signing. |
| GHSA-9f5j-8jwj-x28g | `ecdsa` | High | The fixed 0.19.2 is resolver-incompatible with `pycspr==1.2.0`, which pins `ecdsa>=0.18.0,<0.19.0`. | The relevant malformed-DER path is bypassed by the finals release loaders, which accept bounded trusted PEM input through `cryptography` and pass a raw 32-byte secret to `pycspr`. The legacy fallback is operator-secret-only, not network input. |

Medium/low advisories on the same capped dependencies inherit the same
constraint and are tracked in the repository's Security tab. These waivers are
re-evaluated when the Casper Python SDK lifts its dependency caps; they are not
claims that the packages themselves are vulnerability-free.
