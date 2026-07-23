import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { before, test } from "node:test";

import {
  CasperLiveError,
  canonicalTranscriptJson,
  corroborateCasperBundleObservations,
  corroborateCasperTestnetBundle,
  parseJsonStrict,
  verifyExactEnvelopeV3Artifact,
  verifyLive,
} from "../dist/index.js";

const REPOSITORY = fileURLToPath(new URL("../../../", import.meta.url));
const OBSERVED_AT = "2026-07-23T01:00:00Z";
const ENDPOINTS = ["https://rpc-a.example.com/rpc", "https://rpc-b.example.com/rpc"];
const READ_ONLY = new Set([
  "info_get_deploy", "chain_get_block", "chain_get_state_root_hash", "query_global_state",
  "state_get_dictionary_item", "query_balance", "query_balance_details", "chain_get_block_transfers",
]);
const PAIRS = [
  ["request", "response"], ["transaction_request", "transaction_response"],
  ["canonical_block_request", "canonical_block_response"], ["block_request", "block_response"],
  ["block_request", "block"], ["balance_request", "balance_response"],
  ["transfers_request", "transfers_response"], ["state_root_request", "state_root_response"],
];

let bundle;
let responses;

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function unwrap(value) {
  if (value && typeof value === "object" && !Array.isArray(value) &&
      Object.keys(value).length === 2 && Object.hasOwn(value, "name") && Object.hasOwn(value, "value")) {
    return value.value;
  }
  return value;
}

function responseKey(method, params) {
  return canonicalTranscriptJson({ method, params }, "live test RPC key");
}

function collectResponses(value, result = new Map(), seen = new Set()) {
  if (!value || typeof value !== "object" || seen.has(value)) return result;
  seen.add(value);
  if (Array.isArray(value)) {
    for (const item of value) collectResponses(item, result, seen);
    return result;
  }
  for (const [requestField, responseField] of PAIRS) {
    const request = value[requestField];
    const response = value[responseField];
    if (request && response && READ_ONLY.has(request.method) && Object.hasOwn(response, "result")) {
      result.set(responseKey(request.method, request.params), unwrap(response.result));
    }
  }
  for (const child of Object.values(value)) collectResponses(child, result, seen);
  return result;
}

const CHECKS = [
  "source_tree_sha256_matches_release_manifest",
  "wasm_sha256_matches_release_manifest",
  "generated_schema_sha256_matches_release_manifest",
  "envelope_hash_recomputed_from_typed_fields",
  "proposal_commitment_matches_envelope_hash",
  "signer_set_and_threshold_match_deployment",
  "pre_quorum_finalize_reverted_with_code_8",
  "post_quorum_mutated_envelope_reverted_with_code_10",
  "exact_envelope_finalization_accepted",
  "repeat_finalization_reverted_with_code_12",
  "finalization_deploy_processed_without_execution_error",
  "contract_readback_marks_proposal_finalized",
  "contract_readback_marks_action_authorized",
  "package_contract_and_deployment_domain_match_manifest",
];

before(() => {
  const script = [
    "import json",
    "from tests.test_clvalue_roundtrip import _bound_v3_proof",
    "proof, _, _ = _bound_v3_proof()",
    "print(json.dumps(proof, sort_keys=True, separators=(',', ':')))",
  ].join("\n");
  const text = execFileSync("uv", ["run", "--frozen", "--python", "python3.12", "python", "-c", script], {
    cwd: REPOSITORY,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  const artifact = parseJsonStrict(text);
  const facts = verifyExactEnvelopeV3Artifact(artifact);
  const bytes = Buffer.from(text, "utf8");
  responses = collectResponses(artifact);
  const item = {
    proof_id: "exact_envelope_v3",
    proof_type: "exact_envelope_v3",
    generation: "v3",
    lineage: "supplemental",
    observation_mode: "live",
    temporal_scope: "current",
    verification_status: "verified",
    execution_outcome: "accepted",
    claim_scope: "Exact v3 live-test fixture.",
    enforcement_scope: "Casper Testnet exact-envelope proof.",
    proposal_id: facts.proposalId,
    action_id: facts.actionId,
    envelope_hash: facts.envelopeHash,
    artifact_path: "exact-v3.json",
    artifact_sha256: sha256(bytes),
    source_commit: facts.sourceCommit,
    deployment_commit: facts.deploymentCommit,
    network: facts.network,
    package_hash: facts.packageHash,
    contract_hash: facts.contractHash,
    deployment_domain: facts.deploymentDomain,
    schema_version: "concordia.v3-proof.v1",
    captured_at: OBSERVED_AT,
    payment_requirements_hash: null,
    signed_payment_payload_hash: null,
    report_hash: null,
    settlement_transaction: null,
    checks: CHECKS.map((name) => ({
      name, required: true, passed: true, source: "exact-v3.json", observed_at: OBSERVED_AT,
    })),
    links: [{
      rel: "artifact", label: "Exact v3 artifact", href: "https://proofs.example/exact-v3.json", kind: "artifact",
    }],
  };
  bundle = {
    registry: { schema_version: 1, generated_at: OBSERVED_AT, proposal_id: facts.proposalId, items: [item] },
    artifacts: { "exact-v3.json": bytes },
  };
});

function dnsLookup(hostname) {
  return Promise.resolve([hostname.startsWith("rpc-a") ? "8.8.8.8" : "1.1.1.1"]);
}

function transportWith(mutator) {
  return async (endpoint, body) => {
    const request = JSON.parse(body);
    let result;
    if (request.method === "info_get_status") {
      result = { api_version: "2.0.0", chainspec_name: "casper-test" };
    } else {
      const recorded = responses.get(responseKey(request.method, request.params));
      if (recorded === undefined) {
        throw new Error(`missing test response for ${request.method} ${JSON.stringify(request.params)}`);
      }
      result = structuredClone(recorded);
    }
    if (mutator) result = mutator({ endpoint, request, result });
    const bodyText = canonicalTranscriptJson(
      { jsonrpc: "2.0", id: request.id, result },
      "live test response",
    );
    return new Response(bodyText, { status: 200, headers: { "content-type": "application/json" } });
  };
}

function historicalOnlyBundle({ omit } = {}) {
  const pair = (id, method, params, result) => ({
    request: { jsonrpc: "2.0", id, method, params },
    response: { jsonrpc: "2.0", id, result },
  });
  const blockHash = "ab".repeat(32);
  const stateRoot = "cd".repeat(32);
  const rawRpc = {
    deploy: pair(1, "info_get_deploy", { deploy_hash: "ef".repeat(32) }, {
      deploy: { hash: "ef".repeat(32) },
      execution_info: { block_hash: blockHash, block_height: 8_340_490 },
    }),
    canonical_block: pair(2, "chain_get_block", { block_identifier: { Hash: blockHash } }, {
      block_with_signatures: {
        block: { Version2: { hash: blockHash, header: { state_root_hash: stateRoot, height: 8_340_490 } } },
      },
    }),
    state_root: pair(3, "chain_get_state_root_hash", { block_identifier: { Hash: blockHash } }, {
      state_root_hash: stateRoot,
    }),
    package: pair(4, "query_global_state", {
      state_identifier: { StateRootHash: stateRoot }, key: `hash-${"92".repeat(32)}`, path: [],
    }, { stored_value: { ContractPackage: { marker: "package" } } }),
    contract: pair(5, "query_global_state", {
      state_identifier: { StateRootHash: stateRoot }, key: `hash-${"a8".repeat(32)}`, path: [],
    }, { stored_value: { Contract: { marker: "contract" } } }),
  };
  if (omit) delete rawRpc[omit];
  const artifact = {
    schema_version: "concordia.historical_odra_receipt.v1",
    source_url: "https://must-not-be-fetched.example/proof-artifacts/v1/DAO-PROP-6CB25C/historical-odra-receipt",
    raw_rpc: rawRpc,
  };
  const path = "historical-odra.json";
  return {
    bundle: {
      registry: {
        schema_version: 1,
        proposal_id: "DAO-PROP-6CB25C",
        items: [{ proof_type: "historical_odra_receipt_v2", artifact_path: path }],
      },
      artifacts: { [path]: JSON.stringify(artifact) },
    },
    responses: collectResponses(artifact),
  };
}

function historicalTransport(recorded, mutator) {
  return async (endpoint, body) => {
    const request = JSON.parse(body);
    let result;
    if (request.method === "info_get_status") {
      result = { api_version: "2.0.0", chainspec_name: "casper-test" };
    } else {
      const stored = recorded.get(responseKey(request.method, request.params));
      if (stored === undefined) throw new Error(`missing historical response for ${request.method}`);
      result = structuredClone(stored);
    }
    if (mutator) result = mutator({ endpoint, request, result });
    return Response.json({ jsonrpc: "2.0", id: request.id, result });
  };
}

test("live corroboration replays deploy, block and state observations against two trusted RPC hosts", async () => {
  const result = await corroborateCasperTestnetBundle(bundle, {
    rpcEndpoints: ENDPOINTS,
    dnsLookup,
    transport: transportWith(),
    now: OBSERVED_AT,
  });
  assert.equal(result.verificationScope, "live_casper_rpc_corroborated");
  assert.deepEqual(result.observationSources, ENDPOINTS);
  assert.ok(result.rpcObservationCount >= 6);
});

test("historical-only observations corroborate through two trusted RPCs without fetching artifact source URLs", async () => {
  const fixture = historicalOnlyBundle();
  let accidentalFetches = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    accidentalFetches += 1;
    throw new Error("historical source_url must not be fetched");
  };
  try {
    const result = await corroborateCasperBundleObservations(fixture.bundle, {
      rpcEndpoints: ENDPOINTS,
      dnsLookup,
      transport: historicalTransport(fixture.responses),
      now: OBSERVED_AT,
    });
    assert.equal(result.verificationScope, "live_casper_rpc_corroborated");
    assert.deepEqual(result.observationSources, ENDPOINTS);
    assert.equal(result.rpcObservationCount, 10);
    assert.equal(accidentalFetches, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("historical-only live corroboration fails closed on endpoint disagreement", async () => {
  const fixture = historicalOnlyBundle();
  await assert.rejects(
    corroborateCasperBundleObservations(fixture.bundle, {
      rpcEndpoints: ENDPOINTS,
      dnsLookup,
      transport: historicalTransport(fixture.responses, ({ endpoint, request, result }) => {
        if (
          endpoint.hostname.startsWith("rpc-b") &&
          request.method === "query_global_state" &&
          request.params.key === `hash-${"a8".repeat(32)}`
        ) {
          return { ...result, stored_value: { Contract: { marker: "competing-contract" } } };
        }
        return result;
      }),
      now: OBSERVED_AT,
    }),
    (error) => error instanceof CasperLiveError && error.code === "live_rpc_disagreement",
  );
});

test("historical-only live corroboration requires all five frozen RPC observation kinds", async () => {
  const fixture = historicalOnlyBundle({ omit: "contract" });
  await assert.rejects(
    corroborateCasperBundleObservations(fixture.bundle, {
      rpcEndpoints: ENDPOINTS,
      dnsLookup,
      transport: historicalTransport(fixture.responses),
      now: OBSERVED_AT,
    }),
    (error) => error instanceof CasperLiveError && error.code === "incomplete_historical_live_observation_set",
  );
});

test("verifyLive retains the exact remote bundle and upgrades scope only after RPC corroboration", async () => {
  const fetchImpl = async (input) => {
    const url = new URL(String(input));
    if (url.pathname.endsWith("/exact-v3.json")) {
      return new Response(bundle.artifacts["exact-v3.json"], { status: 200 });
    }
    return Response.json(bundle.registry);
  };
  const result = await verifyLive(
    bundle.registry.proposal_id,
    "https://proofs.example",
    {
      fetchImpl,
      dnsLookup,
      trustedRpcEndpoints: ENDPOINTS,
      rpcDnsLookup: dnsLookup,
      rpcTransport: transportWith(),
      now: OBSERVED_AT,
    },
  );
  assert.equal(result.status, "verified");
  assert.equal(result.verificationScope, "live_casper_rpc_corroborated");
  assert.deepEqual(result.observationSources, ENDPOINTS);
  assert.equal(result.live.source, "trusted-casper-rpc-quorum");
  assert.ok(result.live.rpcObservationCount >= 6);
});

test("live corroboration rejects RPC disagreement and artifact mismatch", async () => {
  await assert.rejects(
    corroborateCasperTestnetBundle(bundle, {
      rpcEndpoints: ENDPOINTS,
      dnsLookup,
      transport: transportWith(({ endpoint, request, result }) => {
        if (endpoint.hostname.startsWith("rpc-b") && request.method === "chain_get_block") {
          const changed = structuredClone(result);
          changed.block_with_signatures.block.Version2.header.height += 1;
          return changed;
        }
        return result;
      }),
      now: OBSERVED_AT,
    }),
    (error) => error instanceof CasperLiveError && error.code === "live_rpc_disagreement",
  );

  await assert.rejects(
    corroborateCasperTestnetBundle(bundle, {
      rpcEndpoints: ENDPOINTS,
      dnsLookup,
      transport: transportWith(({ request, result }) => {
        if (request.method !== "chain_get_block") return result;
        const changed = structuredClone(result);
        changed.block_with_signatures.block.Version2.header.height += 1;
        return changed;
      }),
      now: OBSERVED_AT,
    }),
    (error) => error instanceof CasperLiveError && error.code === "live_rpc_artifact_mismatch",
  );
});

test("live corroboration rejects unsafe endpoints and redirects", async () => {
  await assert.rejects(
    corroborateCasperTestnetBundle(bundle, {
      rpcEndpoints: ["https://127.0.0.1/rpc", ENDPOINTS[1]],
      dnsLookup,
      transport: transportWith(),
      now: OBSERVED_AT,
    }),
    (error) => error instanceof CasperLiveError && error.code === "unsafe_live_rpc_host",
  );
  await assert.rejects(
    corroborateCasperTestnetBundle(bundle, {
      rpcEndpoints: ENDPOINTS,
      dnsLookup,
      transport: async () => new Response(null, { status: 302, headers: { location: "https://elsewhere.example/rpc" } }),
      now: OBSERVED_AT,
    }),
    (error) => error instanceof CasperLiveError && error.code === "live_rpc_redirect_rejected",
  );
});

test("live corroboration rejects malformed JSON-RPC, unsupported networks and timeouts", async () => {
  await assert.rejects(
    corroborateCasperTestnetBundle(bundle, {
      rpcEndpoints: ENDPOINTS,
      dnsLookup,
      transport: async () => new Response('{"jsonrpc":"2.0","id":"x","result":{},"result":{}}'),
      now: OBSERVED_AT,
    }),
    (error) => error instanceof CasperLiveError && error.code === "malformed_live_rpc_json",
  );
  await assert.rejects(
    corroborateCasperTestnetBundle(bundle, {
      rpcEndpoints: ENDPOINTS,
      dnsLookup,
      transport: transportWith(({ request, result }) => request.method === "info_get_status"
        ? { ...result, chainspec_name: "casper" }
        : result),
      now: OBSERVED_AT,
    }),
    (error) => error instanceof CasperLiveError && error.code === "unsupported_live_network",
  );
  await assert.rejects(
    corroborateCasperTestnetBundle(bundle, {
      rpcEndpoints: ENDPOINTS,
      dnsLookup,
      transport: async () => new Promise(() => {}),
      timeoutMs: 5,
      overallTimeoutMs: 20,
      now: OBSERVED_AT,
    }),
    (error) => error instanceof CasperLiveError && error.code === "live_rpc_fetch_failed",
  );

  await assert.rejects(
    corroborateCasperTestnetBundle(bundle, {
      rpcEndpoints: ENDPOINTS,
      dnsLookup: async () => new Promise(() => {}),
      transport: transportWith(),
      overallTimeoutMs: 5,
      now: OBSERVED_AT,
    }),
    (error) => error instanceof CasperLiveError && error.code === "live_rpc_timeout",
  );

  await assert.rejects(
    corroborateCasperTestnetBundle(bundle, {
      rpcEndpoints: ENDPOINTS,
      dnsLookup,
      transport: async () => new Response(new ReadableStream({
        pull: async () => new Promise(() => {}),
      })),
      timeoutMs: 5,
      overallTimeoutMs: 20,
      now: OBSERVED_AT,
    }),
    (error) => error instanceof CasperLiveError && error.code === "live_rpc_read_failed",
  );
});
