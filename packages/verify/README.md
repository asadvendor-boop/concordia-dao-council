# `@concordia-dao/verify`

Read-only, fail-closed verification primitives and a deterministic CLI for
Concordia proof registries and typed exact-envelope v3 data.

The verifier distinguishes four outcomes:

| Status | Exit code | Meaning |
| --- | ---: | --- |
| `verified` | `0` | Every frozen structural and required observed check passed, and referenced artifact bytes matched their SHA-256. |
| `invalid` | `2` | Evidence was present but malformed, contradictory, tampered, or failed a required check. |
| `unavailable` | `3` | Required evidence or a read-only observation could not be obtained. |
| `unknown` | `4` | The proposal or proof exists, but no terminal observation establishes the claim. |
| usage error | `64` | CLI arguments were invalid. |

`invalid`, `unavailable`, and `unknown` are intentionally different. None is
silently promoted to success.

## Install

```bash
npm install @concordia-dao/verify
```

Node.js 20 or newer is required.

### Release authentication

The first `0.1.0` release is intentionally a manual, local, interactive public
publish performed by the package owner with npm 2FA/security-key approval. It
does not claim npm build provenance, and package metadata does not force the
`--provenance` flag. After the package exists, configure npm trusted publishing
for a pinned GitHub Actions workflow; future releases may then publish from
that reviewed workflow with npm provenance. This repository does not create or
run an automatic publishing workflow for the first release.

## CLI

```bash
# Verify a local proof-registry document and repository-relative artifacts.
concordia-verify local ./registry.json

# Fetch a proof registry and its typed HTTPS artifact/download links.
concordia-verify url https://concordiadao.xyz/proof-registry/v1/DAO-PROP-EXAMPLE

# Resolve the frozen public endpoint from a proposal and deployment base URL.
concordia-verify proposal DAO-PROP-EXAMPLE \
  --base-url https://concordiadao.xyz

# Re-query every supported embedded Casper observation through two
# address-distinct, explicitly trusted public RPC endpoints. The endpoints must
# resolve to disjoint public addresses and return identical results.
concordia-verify live DAO-PROP-EXAMPLE \
  --base-url https://concordiadao.xyz \
  --rpc-endpoint https://node-a.example/rpc \
  --rpc-endpoint https://node-b.example/rpc
```

All CLI results are stable, pretty-printed JSON on stdout. URL and proposal
registry/artifact modes use bounded `GET` requests. Live mode sends `POST`
requests only for an explicit allowlist of read-only Casper JSON-RPC methods.
All modes reject embedded URL credentials, network redirects are not followed,
and no mode submits a transaction or invokes a mutation RPC method.

## Library

```js
import {
  encodeEnvelopeHeader,
  verifyGoldenVector,
  verifyProofRegistry,
  verifyLive,
} from "@concordia-dao/verify";

const result = verifyProofRegistry(registry, {
  artifacts: {
    "artifacts/proof.json": artifactBytes,
  },
});

const canonicalHeaderBytes = encodeEnvelopeHeader(typedHeaderFields);

if (result.status !== "verified") {
  process.exitCode = result.exitCode;
}
```

The registry verifier has dedicated strict adapters for
`historical_odra_receipt_v2`, `exact_envelope_v3`, and
`native_treasury_execution_v1`. It reparses raw Casper transcripts, recomputes
typed identities, verifies signed deploy bytes and approvals, checks exact
execution/state transcript consistency, and binds a treasury execution to
exactly one matching v3 finalization. The required order is
`snapshot < v3 finalization = transfer-scan start < native execution`.
Supplying a treasury artifact without that independently verified v3 item is
invalid.

Historical combined-receipt verification is generation-specific. The
currently publishable v1 evidence must use `StoredContractByHash`, the frozen
v1 NamedArg order, and the canonical v1 card root. The v2 accepted receipt used
`StoredVersionedContractByHash` at package version 1 and signed a different
card root, so it remains unavailable as a combined artifact until its own exact
card chain is independently exported. The historical adapter reports preserved
source-to-deployed-Wasm equivalence as `unproven`.

Offline artifacts establish cryptographic deploy/signature validity and
internal transcript consistency; an unauthenticated JSON snapshot alone does
not prove canonical-chain membership. `verifyLive` can upgrade the result to
`live_casper_rpc_corroborated` only after replaying every supported embedded
read-only observation against two to four explicitly trusted RPC endpoints.
Endpoint disagreement, artifact disagreement, an incomplete observation set,
or an unavailable endpoint fails closed. Library callers may instead supply a
raw-bundle observer callback; the package still runs its strict adapters and
never trusts boolean summaries.

The package ships no default RPC endpoints and never accepts RPC credentials.
Distinct hostnames and disjoint IP addresses provide transport-level
corroboration; they do not by themselves prove that two endpoints have
independent administrators. Any stronger operator-independence claim belongs
in the external release manifest, where the endpoint operators can be reviewed
and named. Offline artifact verification remains available when a trusted live
endpoint set is not.

## What is recomputed

- Canonical typed scalar, header, native-transfer, official-x402, evidence,
  metadata, and execution-argument encodings.
- BLAKE2b-256 envelope, action, transfer, manifest, and subordinate binding
  hashes from the frozen v3 domains.
- Every one of the 21 shared Rust/Python/JavaScript golden vectors, including
  invalid cases and cross-proposal/action relationships. The published package
  includes the exact frozen vector documents under `dist/vectors/`; their URL
  is exported as `FROZEN_VECTOR_DIRECTORY_URL` for independent replay.
- Proof-registry shape, exact required-check cardinality, typed provenance,
  allowed outcomes, artifact SHA-256, and proposal binding.
- The packaged v3 release identity (Wasm, generated schema, source, lockfile,
  and historical-contract inventory), locked install deploy, seven-step
  refusal/acceptance choreography, and state-root-pinned contract readback.
- Native treasury signed-deploy bytes, exact transfer arguments, two-node
  finality agreement, pre/post balances, and the bounded no-second-transfer
  scan.
- Historical v1 receipt deploy/body/signatures, generation-specific 17-argument
  NamedArg bytes and digest, exact card preimages/root, execution/block/state
  transcript consistency, and frozen package/contract/Wasm identities. The
  packaged lineage inventory is byte-bound and caller replacement is rejected.

SafePay provider-ledger rows, approval/demo/room-boundary proofs, historical-v2
combined receipts, and official-facilitator settlement facts do not yet have a
passing dedicated adapter in this package. Their registry items therefore
remain `unavailable` even if asserted checks say they passed. Future adapters
must verify their raw, content-addressed evidence before those proof types can
become green.

## Boolean trust boundary

Artifact summary fields such as `passed`, `chain_valid`, `verified`, and
`duplicate_proof_rejected` are assertions, not evidence. They are ignored and
reported in `ignoredAssertions`. A proof becomes verified only through the
frozen registry predicate, unique required observations, and recomputed
artifact bytes. Missing evidence cannot pass vacuously.

## Security and reproducibility

- JSON is parsed with duplicate-key rejection.
- Unknown registry fields and unsafe repository paths fail closed.
- Remote mode requires HTTPS, disables redirects, enforces response-size and
  timeout bounds, rejects credentials and private/reserved destinations,
  re-resolves each artifact host, pins the validated address for the default
  HTTPS transport, requires same-origin artifacts, and sends no authorization
  header. A caller-supplied `fetchImpl` is an explicit trusted test/transport
  seam; supply `dnsLookup` as well when the caller wants the package to enforce
  destination-address policy for that custom transport.
- Stock live mode additionally requires two to four credential-free public RPC
  origins with distinct hostnames and disjoint resolved addresses, pins each
  validated address for transport, applies one overall deadline, and rejects
  any cross-endpoint or artifact-result disagreement. This is a transport
  separation check, not an assertion of independent administration.
- Local mode bounds registries to 8 MiB and artifacts to 64 MiB, confines
  artifact real paths to the registry directory, and verifies the opened file
  identity before reading.
- The package has no wallet, signer, secret-loader, settlement, or mutation
  capability.
- Dependencies are exactly pinned in `package-lock.json`.

For the frozen interface, see `handoff/G1_INTERFACE_SPEC.md` in the Concordia
source repository.
