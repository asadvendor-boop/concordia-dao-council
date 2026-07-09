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
