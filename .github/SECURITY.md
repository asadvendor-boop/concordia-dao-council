# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Concordia DAO Council, please report
it privately rather than opening a public issue.

- Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  ("Report a vulnerability" under the repository's **Security** tab), or
- Contact the maintainers directly.

Please include steps to reproduce and the potential impact. We aim to
acknowledge reports promptly and will keep you informed of remediation progress.

## Supported Scope

This is a hackathon submission running on the Casper **Testnet**. No mainnet
funds are at risk. The security-relevant surfaces are:

- the governance gateway API (`gateway/`),
- the Casper contract package (`contracts/`), and
- the proof/evidence runtime (`shared/proof_runtime.py`).

## Automated Scanning

This repository has GitHub CodeQL code scanning and Dependabot alerts enabled.
High-severity findings are tracked and remediated; non-applicable findings
(for example, timing side-channels that require local co-residency, or
build-time-only dependencies with no runtime untrusted-input path) are
documented and dismissed with justification.

## Remediated Findings (July 2026 review)

- **All 11 High CodeQL alerts fixed in code**: path-traversal hardening via a
  basename-sanitize + `normpath`/`startswith` containment guard
  (`gateway/app.py::_safe_data_path`), an anchored regex for the insecure-URL
  audit check, and bounded regex quantifiers plus an input cap for the
  allocation parser (`shared/proof_runtime.py`).
- **3 High dependency advisories fixed by upgrade**: `langsmith` → 0.10.0
  (SSRF, GHSA in TracingMiddleware) and `starlette` → 1.3.1 (form-limits
  bypass; SSRF/UNC credential theft), verified against the full test suite.

## Dismissed Findings Register

The following advisories are dismissed **with justification** because no
installable fix exists. Each is revisited when its upstream constraint lifts.

| Advisory | Package | Severity | Why it cannot be fixed today | Risk assessment |
|---|---|---|---|---|
| GHSA-rc23-xxgq-x27g | `wee_alloc` (Rust, contract build) | Critical (unmaintained) | No patched release exists. It is a build-time WASM allocator; swapping it changes the compiled WASM and would invalidate the deployed testnet contract package hash currently under judging. | No runtime untrusted-input path; build-time only. Replace before any mainnet build. |
| GHSA-537c-gmf6-5ccf | `cryptography` | High | Transitive via `pycspr==1.2.0` — the **latest** Casper Python SDK — which pins `cryptography>=42.0.2,<43.0.0`; the fixed 48.0.1 is uninstallable (verified: dependency resolution fails on the constraint). | Testnet-only deployment; no mainnet keys or funds. Revisit when pycspr lifts its cap. |
| GHSA-r6ph-v2qm-q3c2 | `cryptography` | High | Same `pycspr` cap; fixed 46.0.5+ uninstallable. | Same as above. |
| GHSA-wj6h-64fc-37mp | `ecdsa` (Minerva) | High | No upstream fix has ever shipped; transitive via `pycspr`. | The Minerva attack requires a local timing side channel on P-256 signing — outside this testnet proof system's threat model. Revisit if a patched release ships. |

Medium/low advisories on the same capped dependencies inherit the same
constraint and are tracked in the repository's Security tab.
