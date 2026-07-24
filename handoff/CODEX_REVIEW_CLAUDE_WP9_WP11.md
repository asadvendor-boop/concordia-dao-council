# Codex integration review — Claude WP9 / WP11

Reviewed commits:

- WP9: `abd46d1feb680c2093edc0a42e77813d93abf2f5`
- WP11: `f19906223d4981b5a0920e4d25186351873827e6`

Verdict: **NO-GO for cherry-pick or publication.** The MkDocs foundation is
well structured and its strict, hash-locked build passes, but the published
content currently gets ahead of both the deployed system and the independent
verification surface. WP11 is only a partial copy pass and cannot be treated
as the committed BUIDL/video/release-copy work package.

## What passed

- `docs_dir` is isolated to the curated `docs-site/` tree.
- Navigation is explicit and the Pages workflow is least-privilege and
  SHA-pinned.
- A fresh temporary environment installed
  `docs/requirements-docs.txt` with `--require-hashes` successfully.
- `mkdocs build --strict` completed without warnings.
- The curated site does not contain the known forbidden competitor/model
  contamination terms.
- Historical v1/v2, pending v3, SafePay v2, and official-x402 sections attempt
  to distinguish their proof status rather than silently rewriting history.

## Release-blocking corrections

### P0 — public claims must follow released proof state

1. `mkdocs.yml` currently says that only the exact approved envelope can
   execute on-chain. That sentence is not publishable until the v3 contract,
   exact-envelope proof, and governed executor proof all pass live gates. Use
   a deployment-derived release manifest or an explicit historical/current/
   pending qualifier; never describe an unreleased implementation as the live
   system.
2. `docs-site/safepay-lite.md` describes the unmerged WP2 design as the current
   implementation. WP2 is independently NO-GO. Until its corrected commit is
   integrated and a fresh payment artifact passes, label the entire v2 model
   as implementation-in-progress and keep every guarantee pending-proof.
3. `docs-site/official-x402.md` says the local service implements the standard
   surface. WP5 is independently NO-GO. Keep this as a design/implementation-
   in-progress page until corrected local and live gates pass. A `/supported`
   or `/verify` response is not settlement evidence.
4. `.github/SECURITY.md` claims all production secrets use `_FILE`, the new
   services are in supported scope, and scanning/remediation is complete.
   Those statements must be regenerated only after WP3/WP5 integration,
   production configuration inspection, and the final CodeQL/Dependabot gate.
   A planned posture is not a present security guarantee.

### P0 — independent-verifier copy is false for the cited Python script

`docs-site/proof-verification.md` and `docs-site/judge-walkthrough.md` say
`scripts/verify_concordia_receipt.py` independently recomputes the evidence
chain and, with `--live-chain`, queries Casper and compares exact on-chain
arguments. The current script accepts artifact booleans/optional fields and
does not independently reconstruct the exact stored card preimages. Replace
these instructions with the completed `@concordia-dao/verify` CLI only after
WP8 passes its card, historical receipt, v3, treasury, SafePay, official-x402,
freshness, provenance, and safe live-observer gates. Until then, state the
narrow artifact/transcript scope and link directly to public deploys.

The published verifier output must expose `verification_scope` and
`observation_sources`; offline verification must never be described as a
current-chain observation. Live mode must use only explicitly trusted HTTPS
RPC endpoints, never artifact-controlled URLs.

### P0 — role taxonomy and archive attribution are still incorrect

The approved taxonomy is:

- four deliberative agents: Rowan, Mercer, Verity, Alden;
- Locke: an authorization-bound, model-involved execution role, not a fifth
  advisory/deliberative agent;
- Concordia Core: deterministic evidence and state-transition authority;
- Wells: non-reasoning archival/presentation persona only.

The deterministic archive is produced by Locke/Core. Wells does not summarize,
close the session, produce the archive, record the sealed trail, or run a
governance-archive pipeline. Correct `docs-site/index.md`,
`docs-site/architecture.md`, and `docs/LLM_PROVIDER.md`, including the phrases
"five advisory roles", "five reasoning agents", "Wells produces", and "Wells
closes". Historical sealed labels may be explained but not rewritten.

### P0 — generated release facts, not hand-maintained proof constants

The final site must consume a generated, schema-validated release-data file for
all current v3/SafePay/x402/native-transfer identifiers, hashes, block heights,
URLs, and statuses. Those values are written only after Codex's live capture
passes. Hand-maintained values may remain solely for frozen historical proof
and must be labelled historical. Unknown/unavailable data never renders as
verified or green.

### P1 — complete the actual WP11 scope

WP11 currently changes only `docs/LLM_PROVIDER.md` and
`.github/SECURITY.md`. It still owes:

- `docs/DORAHACKS_SUBMISSION_TEXT.md` and the external BUIDL draft;
- the constitutional-execution-firewall lead;
- precise DeFi/treasury-risk and RWA/machine-economy language;
- honest council-depth comparison without false agent counts;
- no-fixture-mode wording supported by the final hosted configuration;
- Final Round updates and verify-from-your-own-tools sections;
- domain/docs/npm launch links only after publication gates pass;
- the final video script, with every beat bound to a verified artifact;
- the historical-vs-current SafePay and v1/v2-vs-v3 distinctions.

Every unreleased statement in a draft must carry a machine-searchable
`PENDING_PROOF` marker. Final publication strips a marker only when the release
manifest proves the corresponding gate.

### P1 — publication and site acceptance gates

- Re-run the strict hash-locked dependency install and `mkdocs build --strict`
  after content correction.
- Add an internal-link/anchor crawl over the built site.
- Run the forbidden-term, secret, absolute-local-path, placeholder, and stale-
  hash scans over source and built output.
- Enable GitHub Pages, then configure `docs.concordiadao.xyz`, publish DNS in
  the approved order, wait for certificate issuance, enforce HTTPS, and verify
  every page and asset from the public domain.
- Keep all sslip submission links unchanged.
- Do not publish or update DoraHacks until Codex has approved the exact
  integration commit and live release manifest.

## Re-review evidence required

Return a new WP9/WP11 commit plus:

1. exact file list and diff summary;
2. strict docs install/build command and clean output;
3. built-site link/anchor/secret/placeholder scan output;
4. a claim-to-proof table mapping every judge-facing current claim to a release
   manifest field or marking it `PENDING_PROOF`;
5. explicit confirmation that no live/DNS/Pages/DoraHacks mutation occurred;
6. the final list of remaining proof-dependent placeholders.

Codex remains the sole cherry-picker, merger, publisher, DNS operator, and
release approver.
