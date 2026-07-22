import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";

import { verifyLive, verifyProposal, verifyUrl } from "../dist/index.js";

const PACKAGE_ROOT = fileURLToPath(new URL("../", import.meta.url));
const CLI = path.join(PACKAGE_ROOT, "dist/cli.js");
const CAPTURED_AT = "2026-07-23T00:00:00Z";
const GENERATED_AT = "2026-07-23T00:01:00Z";
const PUBLIC_DNS = async () => ["93.184.216.34"];
let fixtureDir;
let registryPath;
let artifactPath;
let remoteArtifact;
let remoteRegistry;

function run(...args) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: fixtureDir,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
  });
}

test("first public release requires interactive 2FA and does not force an unsupported provenance claim", async () => {
  const metadata = JSON.parse(await readFile(path.join(PACKAGE_ROOT, "package.json"), "utf8"));
  assert.deepEqual(metadata.publishConfig, { access: "public" });
  assert.equal(Object.hasOwn(metadata.publishConfig, "provenance"), false);
  assert.equal(Object.hasOwn(metadata.scripts, "publish"), false);
});

before(async () => {
  fixtureDir = await mkdtemp(path.join(os.tmpdir(), "concordia-verify-test-"));
  artifactPath = path.join(fixtureDir, "artifact.json");
  registryPath = path.join(fixtureDir, "registry.json");
  remoteArtifact = Buffer.from('{"proof":"observed"}\n', "utf8");
  await writeFile(artifactPath, remoteArtifact);
  const sha = createHash("sha256").update(remoteArtifact).digest("hex");
  const checks = [
    "artifact_sha256_recomputed",
    "capture_time_present",
    "source_https_url_present",
    "staleness_check_passed",
  ].map((name) => ({
    name,
    required: true,
    passed: true,
    source: "artifact.json",
    observed_at: CAPTURED_AT,
  }));
  const registry = {
    schema_version: 1,
    generated_at: GENERATED_AT,
    proposal_id: "DAO-PROP-VERIFY-CLI",
    items: [
      {
        proof_id: "cli_snapshot",
        proof_type: "snapshot",
        generation: "none",
        lineage: "supplemental",
        observation_mode: "snapshot",
        temporal_scope: "current",
        verification_status: "verified",
        execution_outcome: "not_applicable",
        claim_scope: "CLI fixture.",
        enforcement_scope: "Read-only local verification.",
        proposal_id: "DAO-PROP-VERIFY-CLI",
        action_id: null,
        envelope_hash: null,
        artifact_path: "artifact.json",
        artifact_sha256: sha,
        source_commit: "1".repeat(40),
        deployment_commit: "2".repeat(40),
        network: "casper:casper-test",
        package_hash: null,
        contract_hash: null,
        deployment_domain: null,
        schema_version: "snapshot-v1",
        captured_at: CAPTURED_AT,
        payment_requirements_hash: null,
        signed_payment_payload_hash: null,
        report_hash: null,
        settlement_transaction: null,
        checks,
        links: [
          {
            rel: "source",
            label: "Frozen source",
            href: "https://example.invalid/artifact.json",
            kind: "source",
          },
        ],
      },
    ],
  };
  remoteRegistry = structuredClone(registry);
  remoteRegistry.items[0].links.push({
    rel: "artifact",
    label: "Content-addressed artifact",
    href: "https://proofs.example.invalid/artifact.json",
    kind: "artifact",
  });
  await writeFile(registryPath, `${JSON.stringify(registry, null, 2)}\n`);
});

after(async () => {
  await rm(fixtureDir, { recursive: true, force: true });
});

test("local mode emits deterministic JSON and exits zero for verified proof", () => {
  const first = run("local", registryPath, "--now", GENERATED_AT);
  const second = run("local", registryPath, "--now", GENERATED_AT);
  assert.equal(first.status, 0, first.stderr);
  assert.equal(first.stderr, "");
  assert.equal(first.stdout, second.stdout);
  const result = JSON.parse(first.stdout);
  assert.equal(result.mode, "local");
  assert.equal(result.status, "verified");
  assert.equal(result.valid, true);
  assert.equal(result.exitCode, 0);
  assert.equal(result.verificationScope, "artifact_transcript_consistency");
  assert.deepEqual(result.observationSources, []);
});

test("tampered local artifact is invalid with a distinct exit code", async () => {
  const original = await readFile(artifactPath);
  await writeFile(artifactPath, '{"proof":"tampered"}\n');
  const result = run("local", registryPath, "--now", GENERATED_AT);
  await writeFile(artifactPath, original);
  assert.equal(result.status, 2, result.stderr);
  assert.equal(JSON.parse(result.stdout).status, "invalid");
});

test("missing local input is unavailable rather than invalid", () => {
  const result = run("local", path.join(fixtureDir, "missing.json"));
  assert.equal(result.status, 3);
  const body = JSON.parse(result.stdout);
  assert.equal(body.status, "unavailable");
  assert.equal(body.valid, false);
});

test("known proposal with no proofs is unknown rather than verified", async () => {
  const emptyPath = path.join(fixtureDir, "empty.json");
  await writeFile(
    emptyPath,
    `${JSON.stringify({
      schema_version: 1,
      generated_at: GENERATED_AT,
      proposal_id: "DAO-PROP-VERIFY-EMPTY",
      items: [],
    })}\n`,
  );
  const result = run("local", emptyPath, "--now", GENERATED_AT);
  assert.equal(result.status, 4);
  assert.equal(JSON.parse(result.stdout).status, "unknown");
});

test("duplicate JSON keys are rejected instead of silently taking the last value", async () => {
  const duplicatePath = path.join(fixtureDir, "duplicate.json");
  await writeFile(
    duplicatePath,
    '{"schema_version":1,"generated_at":"2026-07-23T00:01:00Z","proposal_id":"DAO-PROP-DUP","items":[],"schema_version":1}\n',
  );
  const result = run("local", duplicatePath);
  assert.equal(result.status, 2);
  const body = JSON.parse(result.stdout);
  assert.equal(body.error.code, "duplicate_json_key");
});

test("CLI usage errors have a stable non-verification exit code", () => {
  const result = run("not-a-mode");
  assert.equal(result.status, 64);
  const body = JSON.parse(result.stdout);
  assert.equal(body.status, "invalid");
  assert.equal(body.error.code, "usage_error");
});

test("stock CLI live mode requires two explicit trusted RPC endpoints", () => {
  const none = run(
    "live",
    "DAO-PROP-VERIFY-CLI",
    "--base-url",
    "https://proofs.example.invalid",
  );
  assert.equal(none.status, 64);
  assert.equal(JSON.parse(none.stdout).error.code, "usage_error");

  const one = run(
    "live",
    "DAO-PROP-VERIFY-CLI",
    "--base-url",
    "https://proofs.example.invalid",
    "--rpc-endpoint",
    "https://rpc-a.example.invalid/rpc",
  );
  assert.equal(one.status, 64);
  assert.equal(JSON.parse(one.stdout).error.code, "usage_error");
});

function fakeRemoteFetch(calls) {
  return async (input, init = {}) => {
    const url = String(input);
    calls.push({ url, init });
    const parsed = new URL(url);
    if (parsed.pathname === "/artifact.json") {
      return new Response(remoteArtifact, { status: 200 });
    }
    if (url.endsWith("/proof-registry/v1/DAO-PROP-VERIFY-CLI") || url.endsWith("/registry.json")) {
      const registry = structuredClone(remoteRegistry);
      const artifactLink = registry.items[0].links.find(({ kind }) => kind === "artifact");
      artifactLink.href = new URL("/artifact.json", parsed.origin).toString();
      return Response.json(registry);
    }
    return Response.json({ error: "proposal_not_found" }, { status: 404 });
  };
}

test("URL mode uses bounded read-only HTTPS fetches and verifies downloaded artifact bytes", async () => {
  const calls = [];
  const result = await verifyUrl("https://proofs.example.invalid/registry.json", {
    fetchImpl: fakeRemoteFetch(calls),
    dnsLookup: PUBLIC_DNS,
    now: GENERATED_AT,
  });
  assert.equal(result.status, "verified");
  assert.equal(result.mode, "url");
  assert.deepEqual(calls.map(({ url }) => url), [
    "https://proofs.example.invalid/registry.json",
    "https://proofs.example.invalid/artifact.json",
  ]);
  for (const { init } of calls) {
    assert.equal(init.method, "GET");
    assert.equal(init.redirect, "error");
    assert.equal(Object.hasOwn(init.headers, "authorization"), false);
  }
});

test("URL mode validates registry links before attempting artifact fetches", async () => {
  const calls = [];
  const malformed = structuredClone(remoteRegistry);
  malformed.items[0].links[0].href = "https://user:password@proofs.example.invalid/artifact.json";
  const result = await verifyUrl("https://proofs.example.invalid/registry.json", {
    fetchImpl: async (input, init = {}) => {
      calls.push({ url: String(input), init });
      return Response.json(malformed);
    },
    dnsLookup: PUBLIC_DNS,
    now: GENERATED_AT,
  });
  assert.equal(result.status, "invalid");
  assert.equal(result.exitCode, 2);
  assert.equal(calls.length, 1);
});

test("proposal mode resolves the exact frozen public endpoint", async () => {
  const calls = [];
  const result = await verifyProposal(
    "DAO-PROP-VERIFY-CLI",
    "https://concordiadao.xyz/dashboard",
    { fetchImpl: fakeRemoteFetch(calls), dnsLookup: PUBLIC_DNS, now: GENERATED_AT },
  );
  assert.equal(result.status, "verified");
  assert.equal(result.mode, "proposal");
  assert.equal(calls[0].url, "https://concordiadao.xyz/proof-registry/v1/DAO-PROP-VERIFY-CLI");
});

test("live mode preserves verified registry context when no observer is configured", async () => {
  const result = await verifyLive(
    "DAO-PROP-VERIFY-CLI",
    "https://concordiadao.xyz",
    { fetchImpl: fakeRemoteFetch([]), dnsLookup: PUBLIC_DNS, now: GENERATED_AT },
  );
  assert.equal(result.status, "unavailable");
  assert.equal(result.mode, "live");
  assert.equal(result.proposalId, "DAO-PROP-VERIFY-CLI");
  assert.equal(result.summary.verified, 1);
  assert.equal(result.error.code, "live_observer_unavailable");
});

test("live mode refuses boolean-only observations even when every assertion says passed", async () => {
  const result = await verifyLive(
    "DAO-PROP-VERIFY-CLI",
    "https://concordiadao.xyz",
    {
      fetchImpl: fakeRemoteFetch([]),
      dnsLookup: PUBLIC_DNS,
      now: GENERATED_AT,
      liveObserver: async () => ({
        status: "verified",
        checks: [
          {
            name: "deploy_finalized_without_execution_error",
            passed: true,
            source: "https://node.testnet.casper.network/rpc",
            observedAt: GENERATED_AT,
          },
        ],
      }),
    },
  );
  assert.equal(result.status, "invalid");
  assert.equal(result.mode, "live");
  assert.equal(result.error.code, "live_raw_evidence_required");
});

test("live mode independently verifies a raw observer registry and exact artifact bytes", async () => {
  const result = await verifyLive(
    "DAO-PROP-VERIFY-CLI",
    "https://concordiadao.xyz",
    {
      fetchImpl: fakeRemoteFetch([]),
      dnsLookup: PUBLIC_DNS,
      now: GENERATED_AT,
      liveObserver: async () => ({
        source: "https://node.testnet.casper.network/rpc",
        observedAt: GENERATED_AT,
        registry: structuredClone(remoteRegistry),
        artifacts: { "artifact.json": remoteArtifact },
      }),
    },
  );
  assert.equal(result.status, "verified");
  assert.equal(result.mode, "live");
  assert.equal(result.valid, true);
  assert.equal(result.live.status, "verified");
  assert.equal(result.live.proposalId, "DAO-PROP-VERIFY-CLI");
  assert.equal(result.verificationScope, "artifact_transcript_consistency");
});

test("live mode rejects lookalike sources and impossible observation times", async () => {
  const result = await verifyLive(
    "DAO-PROP-VERIFY-CLI",
    "https://concordiadao.xyz",
    {
      fetchImpl: fakeRemoteFetch([]),
      dnsLookup: PUBLIC_DNS,
      now: GENERATED_AT,
      liveObserver: async () => ({
        status: "verified",
        checks: [
          {
            name: "deploy_finalized_without_execution_error",
            passed: true,
            source: "https://",
            observedAt: "2026-02-31T00:00:00Z",
          },
        ],
      }),
    },
  );
  assert.equal(result.status, "invalid");
  assert.equal(result.valid, false);
  assert.equal(result.exitCode, 2);
});
