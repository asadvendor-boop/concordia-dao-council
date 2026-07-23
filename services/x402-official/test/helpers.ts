/**
 * Shared test fixtures: frozen config, official-library payload signing,
 * mock transports, and a registry-record builder. The REAL facilitator is
 * never touched — every upstream is an injected mock (or a 127.0.0.1
 * loopback stub where header bytes themselves are under test).
 */

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import casperSdk from "casper-js-sdk";
import {
  CASPER_DOMAIN_TYPES,
  buildDomain,
  hashTypedData,
} from "@casper-ecosystem/casper-eip-712";

import type { ServiceConfig } from "../src/config.js";
import { FulfillmentLedger } from "../src/ledger.js";
import { createLocalVerifier } from "../src/facilitator.js";
import { reportHash, resourceUrlHash } from "../src/hashes.js";
import type { PipelineDeps } from "../src/pipeline.js";
import type {
  AuthorizationLocatorQuery,
  ChainTransport,
  ConfiguredResource,
  FacilitatorTransport,
  FinalizedObservationBoundary,
  PackageState,
  PaymentPayloadWire,
  PaymentRequirementsWire,
  ReadbackArg,
  RegistryLookupResult,
  RegistryTransport,
  SettlementLocator,
  TransactionReadback,
  ValidatedPayment,
} from "../src/types.js";
import { validateVerifySettleRequest } from "../src/validation.js";
import { EXACT_ENVELOPE_V3_REQUIRED_CHECKS } from "../src/registry.js";
import { TRANSFER_WITH_AUTHORIZATION_ARGS } from "../src/chain.js";

export const FROZEN = {
  network: "casper:casper-test",
  packageHash: "3d80df21ba4ee4d66a2a1f60c32570dd5685e4b279f6538162a5fd1314847c1e",
  contractHash: "032706aeae170fafb6403ce3bec58062f1c4288710838fe1df98ce4ff6c35f4a",
  contractVersion: 8,
  tokenName: "Wrapped CSPR",
  tokenSymbol: "WCSPR",
  tokenDecimals: 9,
  tokenDomainVersion: "1",
} as const;

export const REPORT_BYTES = Buffer.from(
  '{"schema":"concordia-x402-report-v1","ok":true}',
  "utf8",
);

export const RESOURCE_URL =
  "https://x402.concordiadao.xyz/resource/finals-report-001";
export const RESOURCE_DESCRIPTION = "Concordia finals protected report";
export const RESOURCE_MIME = "application/json";
export const PAYEE = `00${"ab".repeat(32)}`;
export const AMOUNT = "1000000000";

export function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "x402-official-test-"));
}

export function makeResource(): ConfiguredResource {
  return {
    id: "finals-report-001",
    url: RESOURCE_URL,
    description: RESOURCE_DESCRIPTION,
    mimeType: RESOURCE_MIME,
    amount: AMOUNT,
    payTo: PAYEE,
    maxTimeoutSeconds: 600,
    reportBytes: REPORT_BYTES,
    reportHashHex: reportHash(REPORT_BYTES).toString("hex"),
    resourceUrlHashHex: resourceUrlHash(RESOURCE_URL).toString("hex"),
  };
}

export function makeConfig(overrides: Partial<ServiceConfig> = {}): ServiceConfig {
  return {
    port: 8787,
    facilitatorUrl: "https://facilitator.invalid",
    network: FROZEN.network,
    scheme: "exact",
    wcsprPackageHash: FROZEN.packageHash,
    wcsprContractHash: FROZEN.contractHash,
    wcsprContractVersion: FROZEN.contractVersion,
    tokenName: FROZEN.tokenName,
    tokenSymbol: FROZEN.tokenSymbol,
    tokenDecimals: FROZEN.tokenDecimals,
    tokenDomainVersion: FROZEN.tokenDomainVersion,
    ledgerPath: ":memory:",
    gatewayInternalUrl: "http://gateway.invalid:8000",
    resources: [makeResource()],
    ...overrides,
  };
}

export function requirementsFor(config: ServiceConfig): PaymentRequirementsWire {
  return {
    scheme: "exact",
    network: config.network,
    asset: config.wcsprPackageHash,
    amount: AMOUNT,
    payTo: PAYEE,
    maxTimeoutSeconds: 600,
    extra: {
      name: config.tokenName,
      version: config.tokenDomainVersion,
      decimals: String(config.tokenDecimals),
      symbol: config.tokenSymbol,
    },
  };
}

const TRANSFER_WITH_AUTHORIZATION_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};

export interface SignerHandle {
  privateKey: InstanceType<(typeof casperSdk)["PrivateKey"]>;
  publicKeyHex: string;
  accountAddress: string;
}

export async function generateSigner(): Promise<SignerHandle> {
  const privateKey = await casperSdk.PrivateKey.generate(
    casperSdk.KeyAlgorithm.ED25519,
  );
  const publicKeyHex = privateKey.publicKey.toHex();
  const accountAddress = `00${privateKey.publicKey.accountHash().toHex()}`;
  return { privateKey, publicKeyHex, accountAddress };
}

export interface SignOptions {
  validAfter?: number;
  validBefore?: number;
  nonceHex?: string;
  fromOverride?: string;
}

/**
 * Sign a TransferWithAuthorization exactly the way the pinned official
 * client scheme does (same domain, types, message encoding), with a
 * controllable window and nonce for negative tests.
 */
export async function signPayload(
  signer: SignerHandle,
  requirements: PaymentRequirementsWire,
  options: SignOptions = {},
): Promise<PaymentPayloadWire> {
  const now = Math.floor(Date.now() / 1000);
  const validAfter = options.validAfter ?? now - 600;
  const validBefore = options.validBefore ?? now + requirements.maxTimeoutSeconds;
  const nonceHex =
    options.nonceHex ??
    Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex");
  const from = options.fromOverride ?? signer.accountAddress;
  const domain = buildDomain(
    requirements.extra["name"] as string,
    requirements.extra["version"] as string,
    requirements.network,
    `0x${requirements.asset}`,
  );
  const digest = hashTypedData(
    domain,
    TRANSFER_WITH_AUTHORIZATION_TYPES,
    "TransferWithAuthorization",
    {
      from: `0x${from}`,
      to: `0x${requirements.payTo}`,
      value: BigInt(requirements.amount),
      validAfter: BigInt(validAfter),
      validBefore: BigInt(validBefore),
      nonce: `0x${nonceHex}`,
    },
    { domainTypes: CASPER_DOMAIN_TYPES },
  );
  const rawSignature = await signer.privateKey.sign(Buffer.from(digest));
  const raw64 =
    rawSignature.length === 65 ? rawSignature.slice(1) : rawSignature;
  const signature = Buffer.concat([Buffer.from([0x01]), Buffer.from(raw64)]);
  return {
    x402Version: 2,
    resource: {
      url: RESOURCE_URL,
      description: RESOURCE_DESCRIPTION,
      mimeType: RESOURCE_MIME,
    },
    accepted: requirements,
    payload: {
      signature: signature.toString("hex"),
      publicKey: signer.publicKeyHex,
      authorization: {
        from,
        to: requirements.payTo,
        value: requirements.amount,
        validAfter: String(validAfter),
        validBefore: String(validBefore),
        nonce: nonceHex,
      },
    },
  };
}

export async function makeSignedRequest(
  config: ServiceConfig,
  options: SignOptions = {},
  signer?: SignerHandle,
): Promise<{
  request: Record<string, unknown>;
  signer: SignerHandle;
  payment: ValidatedPayment;
}> {
  const s = signer ?? (await generateSigner());
  const requirements = requirementsFor(config);
  const paymentPayload = await signPayload(s, requirements, options);
  // Independent deep copies: accepted and the outer requirements must be
  // equal by value, never the same object, so tests can drift one of them.
  paymentPayload.accepted = structuredClone(requirements);
  const request = {
    x402Version: 2,
    paymentPayload,
    paymentRequirements: structuredClone(requirements),
  };
  const payment = validateVerifySettleRequest(request, config);
  return { request, signer: s, payment };
}

/** Build a fully verified internal proof-registry record for this payment. */
export function buildRegistryRecord(
  payment: ValidatedPayment,
  config: ServiceConfig,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const observedAt = "2026-07-22T20:00:00Z";
  return {
    schema_version: 1,
    proposal_id: "FINALS-X402-001",
    proposal_hash: "11".repeat(32),
    proposal_nonce: "22".repeat(32),
    action_id: "33".repeat(32),
    action_kind: "OfficialX402SettlementV1",
    action_version: 1,
    envelope_hash: "44".repeat(32),
    deployment_domain: "55".repeat(32),
    network: config.network,
    package_hash: config.wcsprPackageHash,
    contract_hash: config.wcsprContractHash,
    v3_finalized_exact: true,
    finalization_transaction: "66".repeat(32),
    finalized_at: observedAt,
    resource_url_hash: payment.resource.resourceUrlHashHex,
    report_hash: payment.resource.reportHashHex,
    payment_requirements_hash: payment.paymentRequirementsHashHex,
    signed_payment_payload_hash: payment.signedPaymentPayloadHashHex,
    verification_status: "verified",
    observed_at: observedAt,
    checks: EXACT_ENVELOPE_V3_REQUIRED_CHECKS.map((name) => ({
      name,
      required: true,
      passed: true,
      source: "artifacts/live/exact-envelope-v3.json",
      observed_at: observedAt,
    })),
    ...overrides,
  };
}

export class MockFacilitator implements FacilitatorTransport {
  verifyCalls: unknown[] = [];
  settleCalls: unknown[] = [];
  supportedCalls = 0;
  supportedResponse: unknown = {
    kinds: [{ x402Version: 2, scheme: "exact", network: FROZEN.network }],
    extensions: {},
    signers: [],
  };
  verifyResponse: unknown = { isValid: true };
  settleResponse: unknown = {
    success: true,
    transaction: "cc".repeat(32),
    network: FROZEN.network,
  };
  verifyError: Error | undefined;
  settleError: Error | undefined;

  async supported(): Promise<unknown> {
    this.supportedCalls += 1;
    return this.supportedResponse;
  }

  async verify(body: unknown): Promise<unknown> {
    this.verifyCalls.push(body);
    if (this.verifyError) throw this.verifyError;
    return this.verifyResponse;
  }

  async settle(body: unknown): Promise<unknown> {
    this.settleCalls.push(body);
    if (this.settleError) throw this.settleError;
    return this.settleResponse;
  }
}

export class MockRegistry implements RegistryTransport {
  calls: string[] = [];
  result: RegistryLookupResult = { outcome: "not_found" };

  async getBySignedPaymentPayloadHash(hashHex: string): Promise<RegistryLookupResult> {
    this.calls.push(hashHex);
    return this.result;
  }
}

/**
 * A negative locator result carrying a well-formed finalized observation
 * boundary. Even this strongest negative shape proves ONLY "the nonce was not
 * consumed as of that finalized snapshot" — NEVER that the original `/settle`
 * submission didn't happen — so the pipeline must keep the row pending with
 * ZERO additional facilitator calls. Its only affirmative use is expiry
 * terminalization: with `blockTimestamp` strictly after the authorization's
 * `valid_before` (and the window passed on the local clock), the contract can
 * no longer accept the original transaction.
 */
export function unconsumedAtFinalizedBoundary(
  overrides: Partial<FinalizedObservationBoundary> = {},
): SettlementLocator {
  return {
    found: false,
    observed: {
      finalized: true,
      blockHeight: 424242,
      stateRootHash: "ee".repeat(32),
      blockTimestamp: new Date().toISOString(),
      ...overrides,
    },
  };
}

export function goodPackageState(): PackageState {
  return {
    lockStatus: "Unlocked",
    enabledVersion: FROZEN.contractVersion,
    enabledContractHash: FROZEN.contractHash,
  };
}

/** The eight exact typed readback args for a validated payment (§11, WP5-1). */
export function readbackArgsFor(
  payment: ValidatedPayment,
): Record<string, ReadbackArg> {
  return {
    from: {
      clType: "Key",
      value: `account-hash-${payment.payerAccountHash.toString("hex")}`,
    },
    to: {
      clType: "Key",
      value: `account-hash-${payment.payeeAccountHash.toString("hex")}`,
    },
    value: { clType: "U256", value: payment.valueAtomic.toString(10) },
    valid_after: { clType: "U64", value: payment.validAfter.toString(10) },
    valid_before: { clType: "U64", value: payment.validBefore.toString(10) },
    nonce: { clType: "List<U8>", value: payment.nonce.toString("hex") },
    public_key: { clType: "PublicKey", value: payment.publicKeyBytes.toString("hex") },
    signature: { clType: "List<U8>", value: payment.signature.toString("hex") },
  };
}

/** A fully valid finalized readback bound to `payment` and the deploy hash. */
export function readbackFor(
  payment: ValidatedPayment,
  txHashHex: string,
  overrides: Partial<TransactionReadback> = {},
): TransactionReadback {
  return {
    transactionHash: txHashHex,
    finalized: true,
    executionSuccess: true,
    targetContractHash: FROZEN.contractHash,
    contractVersion: FROZEN.contractVersion,
    entryPoint: "transfer_with_authorization",
    argNames: [...TRANSFER_WITH_AUTHORIZATION_ARGS],
    args: readbackArgsFor(payment),
    ...overrides,
  };
}

export class MockChain implements ChainTransport {
  resolveCalls = 0;
  txCalls: string[] = [];
  locateCalls: AuthorizationLocatorQuery[] = [];
  /** Queue of per-call package states; the last entry repeats. */
  packageStates: (PackageState | Error)[] = [goodPackageState()];
  transactions = new Map<string, TransactionReadback | Error>();
  /** Lost-response recovery: keyed by authorization nonce hex. */
  locators = new Map<string, SettlementLocator | Error>();

  async resolveActivePackage(): Promise<PackageState> {
    this.resolveCalls += 1;
    const index = Math.min(this.resolveCalls - 1, this.packageStates.length - 1);
    const state = this.packageStates[index];
    if (state instanceof Error) throw state;
    if (state === undefined) throw new Error("no_package_state");
    return state;
  }

  async getFinalizedTransaction(txHashHex: string): Promise<TransactionReadback> {
    this.txCalls.push(txHashHex);
    const entry = this.transactions.get(txHashHex);
    if (entry === undefined) throw new Error("unknown_transaction");
    if (entry instanceof Error) throw entry;
    return entry;
  }

  async locateSettlementByAuthorization(
    query: AuthorizationLocatorQuery,
  ): Promise<SettlementLocator> {
    this.locateCalls.push(query);
    const entry = this.locators.get(query.authorizationNonceHex);
    // Default: the observer cannot determine the outcome (unavailable).
    if (entry === undefined) throw new Error("locator_unavailable");
    if (entry instanceof Error) throw entry;
    return entry;
  }
}

export interface TestHarness {
  deps: PipelineDeps;
  config: ServiceConfig;
  ledger: FulfillmentLedger;
  facilitator: MockFacilitator;
  registry: MockRegistry;
  chain: MockChain;
}

export function makeDeps(
  configOverrides: Partial<ServiceConfig> = {},
  ledgerPath = ":memory:",
): TestHarness {
  const config = makeConfig(configOverrides);
  const ledger = new FulfillmentLedger(ledgerPath);
  const facilitator = new MockFacilitator();
  const registry = new MockRegistry();
  const chain = new MockChain();
  const deps: PipelineDeps = {
    config,
    ledger,
    facilitator,
    registry,
    chain,
    localVerifier: createLocalVerifier(config.network, "casper-test"),
  };
  return { deps, config, ledger, facilitator, registry, chain };
}

export function writeTempSecret(dir: string, name: string, value: string): string {
  const path = join(dir, name);
  writeFileSync(path, value, { mode: 0o600 });
  return path;
}
