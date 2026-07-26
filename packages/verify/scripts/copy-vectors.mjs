import { cp, mkdir } from "node:fs/promises";

const source = new URL("../../../tests/golden/envelope_v3/", import.meta.url);
const destination = new URL("../dist/vectors/", import.meta.url);

await mkdir(destination, { recursive: true });
await cp(source, destination, { recursive: true, force: true });

const releaseRoot = new URL("../../../contracts/odra-governance-receipt-v3/", import.meta.url);
const releaseDestination = new URL("../dist/release/v3/", import.meta.url);
await mkdir(new URL("source/", releaseDestination), { recursive: true });
await mkdir(new URL("wasm/", releaseDestination), { recursive: true });
await mkdir(new URL("schema/", releaseDestination), { recursive: true });
await cp(new URL("deployment.manifest.json", releaseRoot), new URL("deployment.manifest.json", releaseDestination));
await cp(new URL("wasm/GovernanceReceiptV3.wasm", releaseRoot), new URL("wasm/GovernanceReceiptV3.wasm", releaseDestination));
await cp(
  new URL("resources/casper_contract_schemas/governance_receiptv3_schema.json", releaseRoot),
  new URL("schema/governance_receiptv3_schema.json", releaseDestination),
);
await cp(new URL("src/lib.rs", releaseRoot), new URL("source/lib.rs", releaseDestination));
await cp(new URL("src/encoding.rs", releaseRoot), new URL("source/encoding.rs", releaseDestination));
await cp(new URL("Cargo.lock", releaseRoot), new URL("source/Cargo.lock", releaseDestination));
await cp(
  new URL("../../../handoff/HISTORICAL_ODRA_SHA256.txt", import.meta.url),
  new URL("source/HISTORICAL_ODRA_SHA256.txt", releaseDestination),
);

const historicalDestination = new URL("../dist/release/historical/", import.meta.url);
await mkdir(historicalDestination, { recursive: true });
await cp(
  new URL("../../../handoff/HISTORICAL_ODRA_RECEIPTS_V1.json", import.meta.url),
  new URL("HISTORICAL_ODRA_RECEIPTS_V1.json", historicalDestination),
);
