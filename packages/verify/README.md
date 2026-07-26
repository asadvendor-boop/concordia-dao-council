# `@concordia-dao/verify`

Read-only, fail-closed verification for Concordia V1 receipts, proof registries,
and historical compatibility artifacts.

Version 0.1.4 is V1-first and remains an API/parser/refusal superset of 0.1.3.
It does not sign, broadcast, settle, or mutate.

## V1.5 truth boundary

The default documentation uses canonical V1 proposal `DAO-PROP-6CB25C`,
receipt
`e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852`,
and the recorded quorum sequence.

- Casper-native x402 v2 exposes a live HTTP 402 challenge; the package does not
  claim or verify an external facilitator service.
- Mainnet has not been executed.
- Governance v3 is excluded from V1.5.
- SafePay Lite is recorded native-CSPR settlement evidence, not an external
  facilitator claim.

Historical V2/V3 names below are compatibility schema identifiers. Retaining
them prevents consumer regression; it does not make them V1.5 product claims.

## Outcomes

| Status | Exit code | Meaning |
| --- | ---: | --- |
| `verified` | `0` | Every required supported check passed |
| `invalid` | `2` | Evidence was malformed, contradictory, tampered, or failed a required check |
| `unavailable` | `3` | Required evidence or a read-only observation could not be obtained |
| `unknown` | `4` | No supported terminal observation establishes the claim |
| usage error | `64` | CLI arguments were invalid |

Only `verified` is success. Summary booleans never override recomputed facts.

## Install

```bash
npm install @concordia-dao/verify@0.1.4
```

Node.js 20 or newer is required.

## V1-first CLI example

Export a V1 proof-registry document and all relative artifacts into one
directory:

```bash
concordia-verify local ./v1-proof-registry.json
```

The canonical V1 proposal ID is `DAO-PROP-6CB25C`.

The `proposal` mode remains available for 0.1.1 API compatibility, but it
requires a deployment that actually serves the proof-registry contract. The
Concordia V1 apex does not advertise `/proof-registry/v1/`, so this README does
not send users to that broken outbound route.

```bash
concordia-verify proposal DAO-PROP-6CB25C \
  --base-url https://your-proof-registry.example
```

URL and proposal registry/artifact modes use bounded `GET` requests. Live mode sends `POST` requests only for an explicit allowlist of read-only Casper JSON-RPC methods. Redirects are disabled and embedded credentials are rejected.

## Library

```js
import {
  verifyLocal,
  verifyProofRegistry,
} from "@concordia-dao/verify";

const local = await verifyLocal("./v1-proof-registry.json");
if (local.status !== "verified") {
  process.exitCode = local.exitCode;
}

const result = verifyProofRegistry(registry, {
  artifacts: {
    "artifacts/proof.json": artifactBytes,
  },
});
```

## Compatibility retained from 0.1.1

Every 0.1.1 public export remains. Strict registry support and refusal behavior
remain for:

- `historical_odra_receipt_v2`
- `exact_envelope_v3`
- `native_treasury_execution_v1`
- `safepay_v2`
- `official_x402_settlement_v1`
- `approval_boundary_v1`
- `demo_capability_v1`
- `room_identity_v1`
- `snapshot`

The package continues to expose canonical encoders, golden-vector verification,
signed-deploy and finality adapters, state and transfer adapters, registry
verification, local/URL/proposal/live modes, and the same distinct exit codes.

### Historical receipt behavior

The historical receipt adapter preserves generation-specific call target,
NamedArg order, card-chain binding, deploy/signature checks, execution/block
transcripts, and preserved lineage inventory. Historical fixture bytes remain
test-only and off public product promotion.

### Exact-envelope and native treasury behavior

The exact-envelope and native-treasury adapters remain available for consumers
of 0.1.1 evidence. They recompute typed identities and fail closed on missing or
contradictory transcript material. Their presence is compatibility, not a
claim that governance v3 shipped in V1.5.

### SafePay and official-x402 refusals

The payment envelope adapters can bind strict artifact identity fields. They do
not claim to verify provider persistence, quote/fulfillment/replay semantics,
EIP-712 authorization, official-facilitator behavior, WCSPR execution,
settlement finality, or protected-resource release. Unsupported semantics are
listed in `unsupportedCapabilities` and cannot produce `green: true`.

## Live corroboration

Offline artifacts can establish byte identity, signature validity, and internal
transcript consistency. They do not alone prove canonical-chain membership.

`verifyLive` can upgrade supported observations only after replaying embedded
read-only Casper requests against two to four explicitly trusted public RPC
endpoints. Endpoint disagreement, incomplete observations, artifact mismatch,
or timeout fails closed. Distinct hostnames and addresses are transport
separation, not proof of independent administration.

The package ships no default RPC endpoints and accepts no RPC credentials.

## Release authentication

`0.1.0` was operator-published without an npm provenance attestation and is
deprecated. `0.1.1`, `0.1.2`, and `0.1.3` remain supported historical releases.

`0.1.4` is the provenance-strengthened V1.5 package version. Source metadata
alone does not prove it is published. The pinned
`.github/workflows/publish-verifier.yml` workflow must:

1. be dispatched manually with an exact commit and version;
2. require that commit to equal the current public `main` tip;
3. run clean build, tests, lint, audit, pack, and consumer checks;
4. embed the authorized public `main` SHA as `gitHead`, then use
   `npm publish --provenance --access public` through the
   OIDC trusted publisher and `npm-production` environment; and
5. run the shared `scripts/verify_published_release.mjs` provenance verifier.

No long-lived npm publish token is stored in GitHub. Package metadata has no
`publish` script, and no checkout, push, pull request, or release event can
publish by itself.

## Security

- Strict JSON parsing rejects duplicate keys.
- Registry and artifact sizes, counts, paths, redirects, destinations, and
  deadlines are bounded.
- Local artifact reads stay inside the registry directory and verify opened
  file identity.
- Live mode permits only read-only Casper RPC methods.
- The package has no wallet, signer, secret loader, settlement, or mutation
  capability.
- Dependencies are exactly pinned in `package-lock.json`.

Report security issues through the repository's private vulnerability-reporting
channel.
