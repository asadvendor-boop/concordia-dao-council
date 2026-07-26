# Verifier SDK and CLI

`@concordia-dao/verify` is a read-only, fail-closed package. Version 0.1.2 is
V1-first while preserving every 0.1.1 public export, parser, adapter, outcome,
and refusal behavior.

## Install

```bash
npm install @concordia-dao/verify@0.1.2
```

Publication is accepted only after npm registry provenance and clean-consumer
verification succeed. A repository version alone is not proof of publication.

## V1-first local use

Export a proof registry and referenced artifacts into one directory, then run:

```bash
concordia-verify local ./v1-proof-registry.json
```

The canonical V1 proposal is `DAO-PROP-6CB25C`. Concordia V1 does not advertise
the historical proposal-mode `/proof-registry/v1/` route because the apex does
not serve that registry contract. The `proposal` API remains for compatible
deployments that actually provide it; no broken Concordia outbound URL is
presented as a reviewer step.

## Library

```js
import {
  verifyLocal,
  verifyProofRegistry,
} from "@concordia-dao/verify";

const result = await verifyLocal("./v1-proof-registry.json");
if (result.status !== "verified") {
  process.exitCode = result.exitCode;
}
```

## Compatibility surface

0.1.2 retains strict adapters and refusals for:

- `historical_odra_receipt_v2`
- `exact_envelope_v3`
- `native_treasury_execution_v1`
- `safepay_v2`
- `official_x402_settlement_v1`
- `approval_boundary_v1`
- `demo_capability_v1`
- `room_identity_v1`
- `snapshot`

These are schema/API identifiers. They do not claim that official x402,
Mainnet, or governance v3 shipped in Concordia V1.5.

## Network behavior

Registry and artifact URL modes use bounded credential-free HTTPS `GET`
requests. Live mode permits only an allowlist of read-only Casper JSON-RPC
methods and requires explicitly trusted endpoints. Redirects, embedded
credentials, private destinations, malformed JSON, missing evidence, and
cross-endpoint disagreement fail closed.

The package never signs, broadcasts, settles, or mutates.
