import { isRecord, parseUnsigned } from "../encoders.js";
import {
  verifySignedNativeTransferDeploy,
  type SignedNativeTransferExpectation,
  type SignedNativeTransferFacts,
} from "./native-deploy.js";

const HEX32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;

export type NativeFinalityInput = Readonly<{
  requestedDeployHash: string;
  rpcPayload: unknown;
  canonicalBlockPayload: unknown;
  signedDeploy: SignedNativeTransferExpectation;
  corroboratingRpcPayloads?: readonly unknown[];
}>;

export type FinalizedNativeTransferFacts = Readonly<{
  requestedDeployHash: string;
  deployHash: string;
  blockHash: string;
  blockHeight: number;
  stateRootHash: string;
  rpcMethod: "info_get_deploy" | "info_get_transaction";
  executionResultKind: string;
  gasMotes: string;
  blockInclusionPath: string;
  corroborationCount: number;
  signedDeploy: SignedNativeTransferFacts;
}>;

type RpcObservation = {
  deployHash: string;
  blockHash: string;
  blockHeight: number | null;
  rpcMethod: "info_get_deploy" | "info_get_transaction";
  executionResultKind: string;
  gasMotes: string;
};

function record(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${label} is malformed`);
  return value;
}

function own(value: Record<string, unknown>, key: string): unknown {
  return Object.hasOwn(value, key) ? value[key] : undefined;
}

function nonempty(value: Record<string, unknown>, label: string): Record<string, unknown> {
  if (Object.keys(value).length === 0) throw new Error(`${label} is malformed`);
  return value;
}

function lowerHash(value: unknown, label: string): string {
  if (typeof value !== "string" || !HEX32.test(value)) {
    throw new Error(`${label} must be lowercase 32-byte hex`);
  }
  return value;
}

function height(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return value;
}

function unwrapResult(payload: unknown, label: string): Record<string, unknown> {
  const body = record(payload, `${label} payload`);
  if (own(body, "error") !== undefined && own(body, "error") !== null) {
    throw new Error(`${label} payload contains error`);
  }
  const result = nonempty(record(own(body, "result"), `${label} result`), `${label} result`);
  if (Object.hasOwn(result, "value") || Object.hasOwn(result, "name")) {
    return nonempty(record(own(result, "value"), `${label} result`), `${label} result`);
  }
  return result;
}

function returnedDeploy(value: Record<string, unknown>): {
  method: "info_get_deploy" | "info_get_transaction";
  hash: string;
} {
  const hasDeploy = Object.hasOwn(value, "deploy") && own(value, "deploy") !== null;
  const hasTransaction = Object.hasOwn(value, "transaction") && own(value, "transaction") !== null;
  if (hasDeploy === hasTransaction) throw new Error("RPC result must contain exactly one deploy or transaction");
  if (hasDeploy) {
    const deploy = record(own(value, "deploy"), "returned deploy");
    return { method: "info_get_deploy", hash: lowerHash(own(deploy, "hash"), "returned deploy hash") };
  }
  const transaction = record(own(value, "transaction"), "returned transaction");
  const variants = ["Deploy", "Version1"].filter((name) => Object.hasOwn(transaction, name));
  if (variants.length !== 1 || Object.keys(transaction).length !== 1) {
    throw new Error("returned transaction is malformed");
  }
  const body = record(own(transaction, variants[0] as string), "returned transaction");
  return {
    method: "info_get_transaction",
    hash: lowerHash(own(body, "hash"), "returned transaction hash"),
  };
}

function hasFailureMarker(value: unknown): boolean {
  if (Array.isArray(value)) return value.some((entry) => hasFailureMarker(entry));
  if (!isRecord(value)) return false;
  for (const [key, child] of Object.entries(value)) {
    if (key === "Failure" || key === "failure") return true;
    if ((key === "error_message" || key === "errorMessage") && child !== null && child !== "") return true;
    if (hasFailureMarker(child)) return true;
  }
  return false;
}

function executionCost(value: Record<string, unknown>): string {
  const costKeys = Object.keys(value).filter((key) => key.toLowerCase() === "cost");
  if (costKeys.length !== 1 || costKeys[0] !== "cost") throw new Error("execution cost is required and unambiguous");
  const raw = own(value, "cost");
  let text: string;
  if (typeof raw === "number" && Number.isSafeInteger(raw) && raw >= 0) text = String(raw);
  else if (typeof raw === "string" && DECIMAL.test(raw)) text = raw;
  else throw new Error("execution cost must be canonical non-negative U512 decimal");
  parseUnsigned(text, 512);
  return text;
}

function executionSuccess(value: unknown): { kind: string; gasMotes: string } {
  const result = nonempty(record(value, "processed execution result"), "processed execution result");
  const success = Object.hasOwn(result, "Success");
  const failure = Object.hasOwn(result, "Failure") || Object.hasOwn(result, "failure");
  if (success && failure) throw new Error("execution result is conflicting");
  if (failure) throw new Error("execution failed");
  if (success) {
    const body = record(own(result, "Success"), "processed execution result");
    if (hasFailureMarker(body)) throw new Error("execution failed");
    return { kind: "Success", gasMotes: executionCost(body) };
  }

  const variants = ["Version1", "Version2"].filter((name) => Object.hasOwn(result, name));
  if (variants.length !== 1 || Object.keys(result).length !== 1) {
    throw new Error("execution result has no explicit success form");
  }
  const variant = variants[0] as "Version1" | "Version2";
  const body = record(own(result, variant), "processed execution result");
  if (variant === "Version1") {
    const nested = executionSuccess(body);
    return { kind: `Version1.${nested.kind}`, gasMotes: nested.gasMotes };
  }
  if (hasFailureMarker(body)) throw new Error("execution failed");
  if (!Object.hasOwn(body, "error_message") && !Object.hasOwn(body, "errorMessage")) {
    throw new Error("execution result has no explicit success form");
  }
  return { kind: "Version2", gasMotes: executionCost(body) };
}

function parseRpcObservation(payload: unknown): RpcObservation {
  const value = unwrapResult(payload, "RPC");
  const returned = returnedDeploy(value);
  const infoKeys = ["execution_info", "executionInfo"].filter((key) => Object.hasOwn(value, key));
  const resultsKeys = ["execution_results", "executionResults"].filter((key) => Object.hasOwn(value, key));
  if (infoKeys.length > 1 || resultsKeys.length > 1 || (infoKeys.length > 0) === (resultsKeys.length > 0)) {
    throw new Error("execution evidence is ambiguous or missing");
  }

  if (infoKeys.length === 1) {
    const info = nonempty(record(own(value, infoKeys[0] as string), "execution info"), "execution info");
    const execution = executionSuccess(
      Object.hasOwn(info, "execution_result") ? own(info, "execution_result") : own(info, "executionResult"),
    );
    return {
      deployHash: returned.hash,
      blockHash: lowerHash(
        Object.hasOwn(info, "block_hash") ? own(info, "block_hash") : own(info, "blockHash"),
        "execution block hash",
      ),
      blockHeight: height(
        Object.hasOwn(info, "block_height") ? own(info, "block_height") : own(info, "blockHeight"),
        "execution block height",
      ),
      rpcMethod: returned.method,
      executionResultKind: execution.kind,
      gasMotes: execution.gasMotes,
    };
  }

  const results = own(value, resultsKeys[0] as string);
  if (!Array.isArray(results) || results.length !== 1) throw new Error("exactly one execution result is required");
  const item = record(results[0], "processed execution result");
  const execution = executionSuccess(
    Object.hasOwn(item, "result") ? own(item, "result") : own(item, "execution_result"),
  );
  const rawHeight = Object.hasOwn(item, "block_height") ? own(item, "block_height") : own(item, "blockHeight");
  return {
    deployHash: returned.hash,
    blockHash: lowerHash(
      Object.hasOwn(item, "block_hash") ? own(item, "block_hash") : own(item, "blockHash"),
      "execution block hash",
    ),
    blockHeight: rawHeight === undefined || rawHeight === null ? null : height(rawHeight, "execution block height"),
    rpcMethod: returned.method,
    executionResultKind: execution.kind,
    gasMotes: execution.gasMotes,
  };
}

function parseCanonicalBlock(payload: unknown, deployHash: string): {
  blockHash: string;
  blockHeight: number;
  stateRootHash: string;
  inclusionPath: string;
} {
  const value = unwrapResult(payload, "canonical block");
  let wrapped: Record<string, unknown>;
  if (Object.hasOwn(value, "block_with_signatures")) {
    wrapped = record(own(record(own(value, "block_with_signatures"), "canonical block wrapper"), "block"), "canonical block");
  } else if (Object.hasOwn(value, "block")) {
    wrapped = record(own(value, "block"), "canonical block");
  } else {
    throw new Error("canonical block result is malformed");
  }

  const versions = ["Version1", "Version2"].filter((name) => Object.hasOwn(wrapped, name));
  let version: "Legacy" | "Version1" | "Version2" = "Legacy";
  let block = wrapped;
  if (versions.length > 0) {
    if (versions.length !== 1 || Object.keys(wrapped).length !== 1) throw new Error("canonical block result is malformed");
    version = versions[0] as "Version1" | "Version2";
    block = record(own(wrapped, version), "canonical block");
  }
  const blockHash = lowerHash(own(block, "hash"), "canonical block hash");
  const header = record(own(block, "header"), "canonical block header");
  const blockHeight = height(own(header, "height"), "canonical block height");
  const stateRootHash = lowerHash(
    Object.hasOwn(header, "state_root_hash") ? own(header, "state_root_hash") : own(header, "stateRootHash"),
    "canonical state root hash",
  );
  const body = record(own(block, "body"), "canonical block body");
  const paths: string[] = [];
  if (version === "Legacy" || version === "Version1") {
    if (!Object.hasOwn(body, "deploy_hashes") && !Object.hasOwn(body, "transfer_hashes")) {
      throw new Error("canonical block result is malformed");
    }
    for (const name of ["deploy_hashes", "transfer_hashes"] as const) {
      const raw = own(body, name);
      const values = raw === undefined || raw === null ? [] : raw;
      if (!Array.isArray(values)) throw new Error("canonical block result is malformed");
      for (const value of values) if (lowerHash(value, `canonical block ${name} entry`) === deployHash) paths.push(name);
    }
  } else {
    const transactions = record(own(body, "transactions"), "canonical block transactions");
    for (const [lane, rawItems] of Object.entries(transactions)) {
      if (!Array.isArray(rawItems)) throw new Error("canonical block result is malformed");
      for (const rawItem of rawItems) {
        const item = record(rawItem, "canonical block transaction");
        const variants = ["Deploy", "Version1"].filter((name) => Object.hasOwn(item, name));
        if (variants.length !== 1 || Object.keys(item).length !== 1) throw new Error("canonical block result is malformed");
        if (lowerHash(own(item, variants[0] as string), "canonical block transaction hash") === deployHash) {
          paths.push(`transactions.${lane}`);
        }
      }
    }
  }
  if (paths.length === 0) throw new Error("requested deploy is absent from canonical block");
  if (paths.length !== 1) throw new Error("requested deploy appears multiple times in canonical block");
  return { blockHash, blockHeight, stateRootHash, inclusionPath: paths[0] as string };
}

export function verifyFinalizedNativeTransfer(
  input: NativeFinalityInput,
): FinalizedNativeTransferFacts {
  for (const field of [
    "requestedDeployHash",
    "rpcPayload",
    "canonicalBlockPayload",
    "signedDeploy",
  ] as const) {
    if (!Object.hasOwn(input, field)) throw new Error(`required own finality field ${field} is missing`);
  }
  const requested = lowerHash(input.requestedDeployHash, "requested deploy hash");
  const observation = parseRpcObservation(input.rpcPayload);
  if (observation.deployHash !== requested) throw new Error("returned deploy hash does not match requested hash");
  const block = parseCanonicalBlock(input.canonicalBlockPayload, requested);
  if (block.blockHash !== observation.blockHash) throw new Error("canonical block hash does not match execution block");
  if (observation.blockHeight !== null && block.blockHeight !== observation.blockHeight) {
    throw new Error("execution block height does not match canonical block");
  }
  const signedDeploy = verifySignedNativeTransferDeploy(input.signedDeploy);
  if (signedDeploy.deployHash !== requested) throw new Error("signed deploy hash does not match requested hash");

  const corroborations = input.corroboratingRpcPayloads ?? [];
  for (const raw of corroborations) {
    const corroboration = parseRpcObservation(raw);
    if (
      corroboration.deployHash !== requested ||
      corroboration.blockHash !== block.blockHash ||
      corroboration.gasMotes !== observation.gasMotes ||
      (corroboration.blockHeight !== null && corroboration.blockHeight !== block.blockHeight)
    ) {
      throw new Error("corroborating RPC evidence conflicts");
    }
  }

  return Object.freeze({
    requestedDeployHash: requested,
    deployHash: signedDeploy.deployHash,
    blockHash: block.blockHash,
    blockHeight: block.blockHeight,
    stateRootHash: block.stateRootHash,
    rpcMethod: observation.rpcMethod,
    executionResultKind: observation.executionResultKind,
    gasMotes: observation.gasMotes,
    blockInclusionPath: block.inclusionPath,
    corroborationCount: corroborations.length,
    signedDeploy,
  });
}
