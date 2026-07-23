/**
 * Production entrypoint.
 *
 * Listens on 0.0.0.0:${X402_OFFICIAL_PORT} (frozen 8787). The chain
 * transport observes the pinned public Casper Testnet RPC directly. CSPR.cloud
 * is used only as a bounded candidate index for lost-response recovery; every
 * candidate is independently verified through Casper RPC before adoption.
 * Any unavailable, malformed, ambiguous, or drifting observation fails closed.
 */

import { loadConfig, loadSecrets } from "./config.js";
import { FulfillmentLedger } from "./ledger.js";
import { HttpFacilitatorTransport, createLocalVerifier } from "./facilitator.js";
import { HttpRegistryTransport } from "./registry.js";
import { CasperRpcChainTransport } from "./rpc-chain.js";
import {
  reconcileLedgerOnStartup,
  probePackageHealthOnStartup,
  isSettlementReady,
  type PipelineDeps,
} from "./pipeline.js";
import { createService } from "./server.js";

async function main(): Promise<void> {
  const config = loadConfig(process.env);
  const secrets = loadSecrets(process.env);
  const ledger = new FulfillmentLedger(config.ledgerPath);
  const chainName = config.network.includes(":")
    ? (config.network.split(":")[1] as string)
    : config.network;
  const deps: PipelineDeps = {
    config,
    ledger,
    facilitator: new HttpFacilitatorTransport(
      config.facilitatorUrl,
      secrets.csprCloudToken,
    ),
    registry: new HttpRegistryTransport(
      config.gatewayInternalUrl,
      secrets.gatewayToken,
    ),
    chain: new CasperRpcChainTransport({
      csprCloudToken: secrets.csprCloudToken,
    }),
    localVerifier: createLocalVerifier(config.network, chainName),
  };
  const reconciliation = await reconcileLedgerOnStartup(deps);
  // Startup readiness probe: current package drift/unavailability must never
  // leave the operational settlement state green (§11, WP5-6).
  const packageHealthy = await probePackageHealthOnStartup(deps);
  console.log(
    JSON.stringify({
      event: "startup",
      settlement_state: ledger.getSettlementState(),
      settlement_ready: isSettlementReady(deps),
      package_healthy: packageHealthy,
      reconciled_finalized: reconciliation.finalized,
      reconciled_failed: reconciliation.failed,
      reconciliation_pending: reconciliation.pending,
      signer_secret_configured: secrets.signerAvailable(),
      resources: config.resources.length,
    }),
  );
  const server = createService(deps);
  server.listen(config.port, "0.0.0.0", () => {
    console.log(JSON.stringify({ event: "listening", port: config.port }));
  });
  const shutdown = (): void => {
    server.close(() => {
      ledger.close();
      process.exit(0);
    });
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main().catch((error: unknown) => {
  // Startup failures log only the stable code (ConfigError message is a code).
  const code = error instanceof Error ? error.message : "startup_failed";
  console.error(JSON.stringify({ event: "startup_failed", code }));
  process.exit(1);
});
