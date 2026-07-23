# Concordia DAO Council

**Concordia DAO Council** is the Casper governance firewall for AI-run DAOs: Dissent Receipts preserve Verity's objection, Locke is bound to the exact approved hash, and browser-wallet quorum is proven on-chain when execution is reverted before quorum and accepted after quorum.

The core innovation is not agent deliberation alone. Concordia makes disagreement auditable and execution narrow: specialist agents deliberate, but unsafe proposals produce structured Dissent Receipts, revised plans are bound to policy hashes, and Locke can only execute the approved DAO Mandate.

Demo hook: a malicious AI tries to push an unsafe 30% treasury allocation. Concordia catches the violation, Verity challenges it with Dissent Receipts, the DAO Mandate caps it to 8%, Locke can execute only the exact approved hash, and browser-wallet quorum proves the same action is reverted before quorum and accepted after quorum.

## Canonical proof hierarchy

Use these values for public review. Older receipts may remain only as clearly labeled historical or superseded proof.

| Proof item | Canonical value |
|---|---|
| Proposal | `DAO-PROP-6CB25C` |
| Canonical reviewer receipt | `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852` |
| Canonical contract | `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1` |
| Quorum pre-quorum rejection proof | `6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431` (User error: 8 / QuorumNotMet, block 8,349,116) |
| Quorum acceptance proof (block 8,350,034) | `9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928` |
| Supplemental dynamic lifecycle proof | `DAO-PROP-DYN-002` -> `68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0` |
| Supplemental RWA receipt | `DAO-PROP-RWA-001` -> `3803a5bb561a84a8c103e3c4e8eea99b3a1c893c63644c56ed38daa1986825cc` |
| Browser wallet receipt | `56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf` |
| x402 SafePay Lite payment | `dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c` |
| IPFS archive CID | `bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq` |

Contract lineage note: the v1 GovernanceReceipt receipt anchor, deployed Jun 29, is contract `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1` under package `hash-992b3a457eedf67f1b50c29f7971199b757d9576dcbaa51e0d52fda3a0fa4c4a`; canonical `e926...`, browser-wallet `56b6...`, and supplemental dynamic `68fd...` receipts write there. The v2 quorum-enabled GovernanceReceipt package, deployed Jun 30, is `hash-1d324e319701e4adcfa9476efcde3d047462d35e79d2cd8c7326c0c384c87d96`; quorum proof `9d631...` writes through that package after the 2-of-3 gate passes. When linking the v1 contract in CSPR.live, use `/contract/a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1`.

Reviewer links:

- Dashboard: <https://concordia.47.84.232.193.sslip.io/dashboard>
- Proof Center: <https://concordia.47.84.232.193.sslip.io/dashboard/proof>
- Judge Walkthrough: <https://concordia.47.84.232.193.sslip.io/dashboard/judge>
- Evidence chain: <https://concordia.47.84.232.193.sslip.io/evidence/DAO-PROP-6CB25C>
- Proof pack: <https://concordia.47.84.232.193.sslip.io/proof-pack/DAO-PROP-6CB25C>
- Technical jury note: <https://concordia.47.84.232.193.sslip.io/technical-jury-note>
- HTML certificate: <https://concordia.47.84.232.193.sslip.io/certificate/DAO-PROP-6CB25C>
- PDF certificate: <https://concordia.47.84.232.193.sslip.io/certificate/DAO-PROP-6CB25C/pdf>
- Launch roadmap: [docs/LAUNCH_ROADMAP.md](docs/LAUNCH_ROADMAP.md)
- Social launch kit: [docs/SOCIAL_LAUNCH.md](docs/SOCIAL_LAUNCH.md)
- Demo video: <https://www.youtube.com/watch?v=GU01V83Jrko>
- MCP judge tool: [docs/MCP_JUDGE_TOOL.md](docs/MCP_JUDGE_TOOL.md)

## What is new for the Buildathon

| Buildathon addition | Status |
|---|---|
| Concordia DAO Council framing and Casper-specific council personas | Implemented |
| DAO Constitution with 30% request capped to 8% | Implemented |
| Verity dissent receipt and deterministic governance archive (presented by Wells) | Implemented |
| Native Python Casper deploy construction with typed CLValues | Implemented |
| Odra `GovernanceReceipt` canonical receipt proof | Implemented |
| Supplemental Odra quorum proof with browser-wallet approval | Implemented |
| Supplemental dynamic proposal lifecycle proof (`DAO-PROP-DYN-002`) | Implemented with processed backend-signed Testnet receipt `68fd77bc...4040e0`; canonical `DAO-PROP-6CB25C` remains unchanged |
| Supplemental RWA invoice-pool receipt (`DAO-PROP-RWA-001`) | Implemented with processed backend-signed Testnet receipt `3803a5bb...25cc`; canonical `DAO-PROP-6CB25C` remains unchanged |
| SafePay Lite x402 paid specialist-report proof | Implemented |
| IPFS/Kubo evidence archive and public gateway | Implemented |
| Proof Center, Judge Walkthrough, certificate, CSV exports, trace API | Implemented |
| Dynamic preview for non-canonical proposals | Implemented as preview only; non-canonical proposals are not claimed executed until separately signed and anchored |
| Independent auxiliary Odra module Testnet calls | Implemented as supplemental topology genesis: CouncilRegistry has a representative `register_agent` call, TreasuryPolicy has a `validate_allocation` call, and CardIndexLedger has a `seal_card_root` call recorded in `artifacts/live/odra-topology-genesis-proof.json` |

## What is real in the core demo

The required proof path is intentionally narrow and verifiable:

```text
DAO proposal
  -> Rowan, Proposal Sentinel
  -> Mercer, Treasury Intelligence Agent
  -> Verity, Risk & Legal Agent
  -> Alden, Protocol Strategy Agent
  -> Multisig Approval Gate
  -> Locke, Casper Execution Agent
  -> Casper Testnet governance receipt transaction
  -> Wells, Governance Archivist
```

Concordia keeps deliberation off-chain for speed, explainability, and traceability. Every council decision is sealed into a SHA-256 evidence chain. The final approved card hash and plan hash are committed to Casper Testnet through the governance receipt contract.

## Integration truth table

| Layer | Submission status | Repository location |
|---|---|---|
| Casper Testnet receipt anchoring | **Required production proof.** Locke must return a real Testnet transaction hash in `CASPER_EXECUTION_MODE=real`. | `shared/casper_executor.py`, `contracts/governance-receipt/` |
| Python-native Casper JSON-RPC execution | **Required runtime path.** Builds, signs, serializes, and broadcasts the stored-contract deploy with `pycspr` and `httpx`; no backend container needs `casper-client`, Node.js, or shell subprocess execution for Locke's proof transaction. | `shared/casper_executor.py` |
| Governance receipt smart contract | **Required contract proof.** Minimal Wasm contract stores the approved decision root and evidence hashes with typed Casper CLValues: `ByteArray(32)` for roots and `U32` for numeric risk/allocation fields. | `contracts/governance-receipt/` |
| DAO Constitution / policy-as-code | **Required demo guardrail.** Verity blocks a 30% treasury allocation, records dissent, and Alden revises to the 8% policy cap. | `config/dao_constitution.cas.json`, `shared/dao_policy.py` |
| Casper Node API via CSPR.cloud/direct node | **Live read available.** MCP bridge includes `casper_node_status`, a real JSON-RPC `info_get_status` read, and `casper_public_status`, a public HTTPS GET probe. | `shared/cspr_cloud.py`, `shared/casper_mcp.py`, `integrations/mcp/` |
| CSPR.cloud REST / Streaming | **Credential-gated optional reads.** Real mode requires `CSPR_CLOUD_ACCESS_TOKEN`; otherwise the adapter reports `not_configured` instead of pretending. | `shared/cspr_cloud.py`, `integrations/cspr-cloud/` |
| Casper MCP / CSPR.trade MCP | **Optional external MCP bridge.** Live external calls require `CASPER_MCP_URL` or `CSPR_TRADE_MCP_URL`; local rehearsal mode is labelled mock. | `shared/casper_mcp.py`, `integrations/mcp/` |
| x402 payment rail | **Implemented with a separate Concordia Risk Oracle provider.** `X402_SETTLEMENT_MODE=real` verifies Casper transfer hashes with bounded indexer-lag retry; the hosted proof configures `X402_PROVIDER_URL` so Concordia redeems paid reports from `x402-provider.47.84.232.193.sslip.io` instead of short-circuiting to itself. | `shared/x402_payments.py`, `x402_provider/` |
| IPFS evidence pinning | **Implemented with Concordia-hosted Kubo and optional Pinata.** The hosted deployment can add the governance archive to an internal Kubo node and expose the CID through `/api/ipfs/{cid}`; Pinata remains an optional external pinner. Web3.Storage/NFT.Storage adapters are legacy/experimental unless their current auth flows are configured. | `shared/ipfs_client.py`, `/ipfs/evidence/{proposal_id}`, `/api/ipfs/{cid}` |
| Odra | **Live Odra receipt proof, live quorum exercise, and supplemental topology genesis.** The canonical judging proof uses the deployed v1 Odra `GovernanceReceipt.store_governance_receipt` path at `e926...d852`. A supplemental quorum exercise uses the Jun 30 v2 quorum-enabled package and is live-complete with configure/propose/pre-quorum failure/server approval/browser-wallet approval/final receipt hashes recorded in `artifacts/live/odra-quorum-exercise-plan.json`. `CouncilRegistry` was exercised through a representative `register_agent` call, while `TreasuryPolicy` and `CardIndexLedger` were independently called through `validate_allocation` and `seal_card_root`; hashes are recorded in `artifacts/live/odra-topology-genesis-proof.json`. This proves the auxiliary modules execute; it does not replace the canonical receipt or claim a fully productized four-contract DAO suite. | `contracts/odra-governance-receipt/`, `artifacts/live/odra-module-exercise-plan.json`, `artifacts/live/odra-quorum-exercise-plan.json`, `artifacts/live/odra-topology-genesis-proof.json` |
| Casper Wallet custody path | **Browser-wallet signing verified.** The live proof uses the configured Testnet signer for the canonical receipt, and the browser-wallet custody path produced receipt `56b6...12bf`, quorum approval `7ee7...75da`, and final quorum receipt `9d63...2928`. The compatibility-named `/cspr-click/unsigned-receipt/{proposal_id}`, `/cspr-click/quorum-approval/{proposal_id}`, and `/cspr-click/quorum-receipt/{proposal_id}` routes package wallet-ready typed deploys; the dashboard signs with the active Casper Wallet account directly. | `integrations/cspr-click/`, dashboard Proof Center |
| Proof Center and audit packet | **Implemented judge-facing proof layer.** Shows compact proof table, policy leash meter, blocked rogue action, outcome gallery, reputation preview, and downloadable archive. | `shared/proof_pack.py`, `/proof-center/{proposal_id}`, `/proof-pack/{proposal_id}` |

This repository does not claim that every optional ecosystem adapter is production-complete. The submission-critical path is the Casper Testnet governance receipt transaction.

DAO-PROP-6CB25C is the canonical executed reviewer proof. Non-canonical proposals use the dynamic preview path unless they are separately signed and anchored on Casper; `DAO-PROP-DYN-002` is the supplemental processed dynamic lifecycle proof.

Technical jury note: Concordia freezes the canonical proof for reproducibility. Dynamic proposals are preview/execution-ready unless fully evidenced; the Odra topology genesis proves auxiliary modules independently; and full cross-contract production enforcement is roadmap, not overclaimed. See [docs/TECHNICAL_JURY_NOTE.md](docs/TECHNICAL_JURY_NOTE.md).

## Council personas

| Persona | Public role | Responsibility |
|---|---|---|
| **Rowan** | Proposal Sentinel | Classifies incoming DAO proposals and opens the Council Chamber. |
| **Mercer** | Treasury Intelligence Agent | Reviews treasury exposure, liquidity context, RWA impact, and Casper ecosystem signals. |
| **Verity** | Risk & Legal Agent | Challenges unsafe proposals and flags treasury, compliance, or policy violations. |
| **Alden** | Protocol Strategy Agent | Converts the deliberation into an exact governance execution envelope. |
| **Locke** | Casper Execution Agent | Authorization-bound, model-involved execution role (not a deliberative agent): executes only the approved envelope and anchors the receipt to Casper Testnet. |
| **Wells** | Governance Archivist | Non-reasoning archival/presentation persona: presents the sealed evidence trail; the deterministic archive is produced by Locke/Core. |
| **Concordia Core** | Deterministic Evidence Core | Seals cards, owns state transitions, validates nonces, and enforces exact-envelope execution. |

## Evidence model

Every decision is a typed card:

```text
ProposalCard
TriageDecision
Assessment
Verdict
ResponsePlan
StructuredApproval
PolicyAuthorization
CasperExecutionReceipt
GovernanceSummary
```

Each card contains:

```text
sequence_number
previous_card_hash
card_hash
```

Changing any historical card breaks the evidence chain. The `/evidence/{proposal_id}` endpoint recomputes the chain and reports verification status.

## Local quick start

The production container uses Python 3.12. For a fresh local install, Python
3.12 is the recommended runtime for the full backend dependency graph. The
standalone proof verifier is dependency-free and can be run with plain
`python3 scripts/verify_concordia_receipt.py ...` from the source archive.
When network access is available, add `--live-chain` to query Casper
Testnet/CSPR.live and diff the live deploy, contract hash, entry point, and
typed runtime arguments against the proof pack.

```bash
cp .env.example .env
uv sync
make gateway
```

In another terminal:

```bash
make simulator
```

Start the agents in separate terminals:

```bash
uv run python -m agents.rowan
uv run python -m agents.mercer
uv run python -m agents.verity
uv run python -m agents.alden
uv run python -m agents.locke
uv run python -m agents.recorder.heartbeat
uv run python -m agents.wells  # optional governance summary
```

The Concordia-native module names (`agents.rowan`, `agents.mercer`,
`agents.verity`, `agents.alden`, `agents.locke`, `agents.wells`) are the
supported public entry points and hold the active implementations. Earlier
engineering package names remain only as small compatibility shims so older
scripts, environment variables, and tests continue to resolve during the
buildathon review window.

Start the dashboard:

```bash
cd dashboard
npm install
npm run dev
```

Open:

```text
http://localhost:3000
```

## Real Casper Testnet mode

Use mock mode only for local rehearsal:

```bash
CASPER_EXECUTION_MODE=mock
```

Use real mode for the final proof:

```bash
CASPER_EXECUTION_MODE=real
CASPER_SECRET_KEY_PATH=/absolute/path/to/secret_key.pem
CASPER_RECEIPT_CONTRACT_HASH=hash-your-64-hex-testnet-contract
CASPER_NODE_ADDRESS=https://node.testnet.casper.network
CSPR_NODE_RPC_URL=https://node.testnet.casper.network/rpc
CASPER_CHAIN_NAME=casper-test
CASPER_PAYMENT_AMOUNT=5000000000
CASPER_ENTRY_POINT=store_governance_receipt
```

Before recording the demo:

```bash
make casper-preflight
```

Run one complete proposal flow and save:

```text
Casper Testnet contract hash
Casper transaction hash
proposal ID
evidence URL
demo video URL: https://www.youtube.com/watch?v=GU01V83Jrko
repository URL: https://github.com/asadvendor-boop/concordia-dao-council
```

See `docs/SUBMISSION_ASSETS_STATUS.md` for the current split between verified technical assets and user-owned publication assets, and `docs/DORAHACKS_SUBMISSION_TEXT.md` for ready-to-paste DoraHacks text.

## Demo scenario

**Policy-governed DeFi treasury reallocation**

1. A DAO proposal requests moving 30% of treasury into a high-yield liquidity strategy.
2. Rowan routes it into the Council Chamber.
3. Mercer analyzes treasury exposure, policy state, and Casper Testnet node status.
4. Verity challenges the proposal because it exceeds the 8% DAO Constitution cap.
5. Alden revises the plan to an 8% capped allocation with guardrails.
6. A multisig approver approves the exact execution envelope.
7. Locke anchors the approved governance receipt and dissent hash to Casper Testnet.
8. The deterministic core seals the final governance archive; Wells presents it for review.

## LLM model policy

The LLM is advisory, but the final submission run requires live model configuration. Deterministic Concordia code owns state transitions, exact-envelope approval, nonce binding, card sealing, policy checks, and Casper execution. Local unit tests may disable live LLM calls by setting:

```bash
CONCORDIA_TEST_MODE=1
CONCORDIA_DISABLE_LLM_REASONING=1
```

For the recorded and hosted walkthrough, configure a live OpenAI-compatible model endpoint through `LLM_BASE_URL`, `LLM_API_KEY`, and the per-agent model variables. The hosted walkthrough uses the provider-agnostic, role-tiered model assignment documented in [docs/LLM_PROVIDER.md](docs/LLM_PROVIDER.md). In production mode the Gateway refuses to trigger the workflow when live LLM readiness fails.

## Safety boundaries

- Advisory models may explain and suggest.
- Deterministic policy owns state transitions and executable envelopes.
- The multisig approval gate binds a nonce to the exact action hash.
- Locke refuses any target, parameter, action count, or hash mismatch.
- The final receipt is sealed only after the Casper execution path returns a transaction result.

## Submission assets

See:

```text
docs/SUBMISSION_PACKET.md
docs/CASPER_DEPLOYMENT.md
docs/CASPER_TOOLING_MAP.md
docs/LLM_PROVIDER.md
docs/PRE_SUBMISSION_VERIFICATION.md
```

Demo video: <https://www.youtube.com/watch?v=GU01V83Jrko>

## License

MIT
