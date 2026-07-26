# Concordia DAO Council

Concordia V1.5 is a policy-governed council for AI-assisted DAO decisions on
Casper Testnet. Its Dissent Receipts preserve objections instead of smoothing
them away. Advisory agents can analyze and challenge a proposal, but a
deterministic core owns state transitions, approval checks, evidence sealing,
and Casper receipt preparation. The exact approved hash and browser-wallet quorum
are bound at the execution boundary, and human approval remains required.

The release is deliberately evidence-first: reviewers can inspect the council
transcript, deterministic policy result, dissent, approval record, downloadable
proof pack, and recorded Casper receipts without trusting a marketing summary.

## V1.5 release scope

Shipped in the V1.5 source and recorded evidence:

- the V1 Council, Timeline, Metrics, Raw Cards, proposal, approval, evidence,
  proof, replay, judge, JSON, PDF, CSV, certificate, IPFS, and CSPR.live
  surfaces;
- deterministic policy enforcement with an 800-basis-point single-allocation
  cap and fail-closed human approval;
- a recorded pre-quorum rejection followed by a 2-of-3 quorum acceptance;
- V1 governance receipts and preserved contract lineage; and
- SafePay Lite as recorded native-CSPR evidence under the Concordia apex.

Release boundaries are explicit:

- **Official x402 is not shipped.** SafePay Lite is not an official x402
  facilitator, escrow, refund contract, or marketplace.
- **Mainnet has not been executed.** All cited deploys are Casper Testnet
  evidence.
- **Governance v3 is excluded from V1.5.** V2/V3 names retained by the npm
  verifier are compatibility parser and refusal surfaces, not shipped V1.5
  product claims.

See the [release-scope documentation](https://docs.concordiadao.xyz/release-scope/)
for the same boundary in reviewer form.

## Canonical proof map

| Evidence | Recorded identity |
| --- | --- |
| Canonical proposal | `DAO-PROP-6CB25C` |
| Canonical reviewer receipt | [`e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852`](https://testnet.cspr.live/deploy/e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852) |
| V1 GovernanceReceipt contract | [`hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1`](https://testnet.cspr.live/contract/a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1) |
| V1 contract package | `hash-992b3a457eedf67f1b50c29f7971199b757d9576dcbaa51e0d52fda3a0fa4c4a` |
| Pre-quorum rejection | [`6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431`](https://testnet.cspr.live/deploy/6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431), `User error: 8` / `QuorumNotMet`, block 8,349,116 |
| Quorum acceptance | [`9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928`](https://testnet.cspr.live/deploy/9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928), block 8,350,034 |
| Browser-wallet receipt | [`56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf`](https://testnet.cspr.live/deploy/56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf) |
| Supplemental dynamic receipt | [`DAO-PROP-DYN-002 → 68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0`](https://testnet.cspr.live/deploy/68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0) |
| Supplemental RWA receipt | [`DAO-PROP-RWA-001 → 3803a5bb561a84a8c103e3c4e8eea99b3a1c893c63644c56ed38daa1986825cc`](https://testnet.cspr.live/deploy/3803a5bb561a84a8c103e3c4e8eea99b3a1c893c63644c56ed38daa1986825cc) |
| SafePay Lite recorded native-CSPR payment | [`dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c`](https://testnet.cspr.live/deploy/dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c) |
| IPFS archive CID | `bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq` |

The quorum-enabled package is a later **contract generation** in the recorded V1
story, not a Concordia V2 product release. The canonical V1 receipt remains
`e926…d852`; the quorum exercise adds the independently inspectable rejection
and acceptance sequence.

## Reviewer path

Use read-only routes:

1. Open the [Judge Walkthrough](https://concordiadao.xyz/dashboard/judge).
2. Inspect the [Proof Center](https://concordiadao.xyz/dashboard/proof?proposal=DAO-PROP-6CB25C).
3. Open the [evidence chain](https://concordiadao.xyz/evidence/DAO-PROP-6CB25C)
   and [proof pack](https://concordiadao.xyz/proof-pack/DAO-PROP-6CB25C).
4. Read the [technical jury note](https://concordiadao.xyz/technical-jury-note)
   for the frozen identities and scope boundary.
5. Compare the receipt and quorum hashes above with CSPR.live.
6. Open the [SafePay Lite record](https://concordiadao.xyz/safepay-lite/DAO-PROP-6CB25C)
   and verify that it is labelled as a historical native-CSPR payment.
7. Download the
   [governance archive](https://concordiadao.xyz/proof-pack/DAO-PROP-6CB25C/download),
   [HTML certificate](https://concordiadao.xyz/certificate/DAO-PROP-6CB25C),
   or [PDF certificate](https://concordiadao.xyz/certificate/DAO-PROP-6CB25C/pdf).

These routes expose recorded evidence. They do not authorize a new transaction.

## Trust model

```text
Proposal
  -> advisory council cards
  -> deterministic policy and dissent
  -> exact plan/action hashes
  -> human approval and nonce checks
  -> receipt preparation
  -> Casper Testnet record
  -> transcript, proof pack, and verifier
```

The core rules are:

- LLM output is advisory and cannot directly mutate governance state.
- Policy evaluation and allocation arithmetic are deterministic.
- High-risk or Casper execution actions require human approval.
- An approval nonce is bound to proposal, plan revision, and action hash; it is
  consumed once.
- Any mismatch, missing evidence, unknown state, or unavailable observation
  fails closed.
- Historical evidence and current runtime claims are kept separate.

## Components

| Path | Responsibility |
| --- | --- |
| `agents/` | Named advisory council roles |
| `gateway/` | FastAPI governance API and read-only evidence routes |
| `shared/` | Policy, approval, integrity, proof, Casper, and SafePay Lite logic |
| `dashboard/` | V1 reviewer and operator interface |
| `contracts/` | Casper Testnet receipt contract source retained by the clean release |
| `artifacts/` | Recorded public evidence shipped with the V1 baseline |
| `packages/verify/` | Read-only, fail-closed npm verifier |
| `docs-site/` | Curated GitHub Pages source |

## Local development

Requirements:

- Python 3.12
- `uv` 0.10.12 or compatible
- Node.js 22 for dashboard and verifier work

Install and run the Python tests:

```bash
uv sync --frozen
uv run --frozen pytest -q
```

Run the gateway locally:

```bash
uv run uvicorn gateway.app:app --host 127.0.0.1 --port 8000
```

Build the curated docs:

```bash
uv run python scripts/check_public_docs_links.py
uv run mkdocs build --strict
```

Build and test the verifier:

```bash
cd packages/verify
npm ci
npm run build
npm test
npm run lint
npm audit --audit-level=high
node scripts/check-package-files.mjs
```

The verifier package has no signer, wallet, secret loader, settlement, or
mutation capability.

## npm verifier 0.1.2

`@concordia-dao/verify` 0.1.2 is prepared as a V1-first compatibility superset
of 0.1.1. All 0.1.1 public exports, parsers, adapters, outcome codes, and
fail-closed refusals remain. Historical V2/V3 parsers remain available only so
existing evidence consumers do not regress.

Publication is manual and gated. The trusted GitHub workflow must check the
exact public `main` tip, rebuild and test the tarball, install it into a clean
consumer, publish through npm OIDC with provenance, and verify the registry
copy with the shared read-only release verifier. Source presence alone is not
proof that 0.1.2 was published.

- Package target:
  [@concordia-dao/verify 0.1.2](https://www.npmjs.com/package/@concordia-dao/verify/v/0.1.2)
- Package-specific documentation:
  [packages/verify/README.md](packages/verify/README.md)

## Security and community

Please use GitHub private vulnerability reporting rather than a public issue for
security defects. The repository keeps its dismissed-findings register in
[`.github/SECURITY.md`](.github/SECURITY.md). CodeQL uses GitHub default setup;
there is intentionally no checked-in `codeql.yml`.

Contributions are welcome through issues and pull requests. Please keep claims
bound to reproducible artifacts, add tests for behavior changes, and preserve
the human-approval and fail-closed boundaries.

## Public links

- App: <https://concordiadao.xyz>
- Documentation: <https://docs.concordiadao.xyz>
- Source: <https://github.com/asadvendor-boop/concordia-dao-council>
- npm target:
  <https://www.npmjs.com/package/@concordia-dao/verify/v/0.1.2>
- X: <https://x.com/ConcordiaDAO>

## License

MIT. See [LICENSE](LICENSE).
