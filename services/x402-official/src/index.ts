/**
 * Production entrypoint.
 *
 * Listens on 0.0.0.0:${X402_OFFICIAL_PORT} (frozen 8787). The chain
 * transport defaults to fail-closed: until Codex wires a live Casper RPC
 * observer for the canary, every drift guard refuses and no credentialed
 * facilitator call can be made. This is the §11 blocked_fail_closed start
 * state, enforced structurally.
 */

import { loadConfig, loadSecrets } from "./config.js";
import { FulfillmentLedger } from "./ledger.js";
import { HttpFacilitatorTransport, createLocalVerifier } from "./facilitator.js";
import { HttpRegistryTransport } from "./registry.js";
import { FailClosedChainTransport } from "./chain.js";
import { reconcileLedgerOnStartup, type PipelineDeps } from "./pipeline.js";
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
    chain: new FailClosedChainTransport(),
    localVerifier: createLocalVerifier(config.network, chainName),
  };
  const reconciliation = await reconcileLedgerOnStartup(deps);
  console.log(
    JSON.stringify({
      event: "startup",
      settlement_state: ledger.getSettlementState(),
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
