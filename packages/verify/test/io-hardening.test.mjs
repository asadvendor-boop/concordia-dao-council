import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  rm,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";

import { verifyLocal, verifyUrl } from "../dist/index.js";

const MAX_REGISTRY_BYTES = 8 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 64 * 1024 * 1024;
const MAX_REGISTRY_ITEMS = 128;
const MAX_UNIQUE_ARTIFACTS = 128;
const MAX_TOTAL_ARTIFACT_BYTES = 128 * 1024 * 1024;
const CAPTURED_AT = "2026-07-23T00:00:00Z";
const GENERATED_AT = "2026-07-23T00:01:00Z";
const REMOTE_ORIGIN = "https://proofs.example.invalid";
const SAFE_DNS_LOOKUP = async () => ["93.184.216.34"];

let fixtureRoot;

before(async () => {
  fixtureRoot = await mkdtemp(path.join(os.tmpdir(), "concordia-verify-io-"));
});

after(async () => {
  await rm(fixtureRoot, { recursive: true, force: true });
});

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function emptyRegistry() {
  return {
    schema_version: 1,
    generated_at: GENERATED_AT,
    proposal_id: "DAO-PROP-IO-HARDENING",
    items: [],
  };
}

function snapshotRegistry({
  artifactPath = "artifact.bin",
  artifactSha256,
  artifactHref,
} = {}) {
  const links = [
    {
      rel: "source",
      label: "Frozen source",
      href: `${REMOTE_ORIGIN}/source`,
      kind: "source",
    },
  ];
  if (artifactHref !== undefined) {
    links.push({
      rel: "artifact",
      label: "Proof artifact",
      href: artifactHref,
      kind: "artifact",
    });
  }
  return {
    schema_version: 1,
    generated_at: GENERATED_AT,
    proposal_id: "DAO-PROP-IO-HARDENING",
    items: [
      {
        proof_id: "io_snapshot",
        proof_type: "snapshot",
        generation: "none",
        lineage: "supplemental",
        observation_mode: "snapshot",
        temporal_scope: "current",
        verification_status: "verified",
        execution_outcome: "not_applicable",
        claim_scope: "I/O hardening fixture.",
        enforcement_scope: "Read-only verification.",
        proposal_id: "DAO-PROP-IO-HARDENING",
        action_id: null,
        envelope_hash: null,
        artifact_path: artifactPath,
        artifact_sha256: artifactSha256 ?? "0".repeat(64),
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
        checks: [
          "artifact_sha256_recomputed",
          "capture_time_present",
          "source_https_url_present",
          "staleness_check_passed",
        ].map((name) => ({
          name,
          required: true,
          passed: true,
          source: artifactPath,
          observed_at: CAPTURED_AT,
        })),
        links,
      },
    ],
  };
}

function repeatSnapshotItems(registry, count, {
  artifactPath = () => "artifact.bin",
  artifactHref = () => `${REMOTE_ORIGIN}/artifact.bin`,
} = {}) {
  const template = registry.items[0];
  registry.items = Array.from({ length: count }, (_, index) => {
    const pathValue = artifactPath(index);
    const hrefValue = artifactHref(index);
    const item = structuredClone(template);
    item.proof_id = `io_snapshot_${String(index).padStart(3, "0")}`;
    item.artifact_path = pathValue;
    for (const check of item.checks) check.source = pathValue;
    const artifactLink = item.links.find((link) => link.kind === "artifact");
    if (artifactLink) artifactLink.href = hrefValue;
    return item;
  });
  return registry;
}

async function writeRegistry(directory, registry, name = "registry.json") {
  const registryPath = path.join(directory, name);
  await writeFile(registryPath, `${JSON.stringify(registry)}\n`);
  return registryPath;
}

function streamResponse(chunks, { headers, onCancel } = {}) {
  let index = 0;
  const body = new ReadableStream({
    pull(controller) {
      if (index === chunks.length) {
        controller.close();
        return;
      }
      controller.enqueue(chunks[index]);
      index += 1;
    },
    cancel() {
      onCancel?.();
    },
  });
  const response = new Response(body, { status: 200, headers });
  Object.defineProperty(response, "arrayBuffer", {
    value: async () => {
      throw new Error("unbounded arrayBuffer() was used");
    },
  });
  return response;
}

test("local mode accepts the exact 8 MiB registry boundary", async () => {
  const directory = path.join(fixtureRoot, "registry-boundary");
  await mkdir(directory);
  const encoded = JSON.stringify(emptyRegistry());
  const registryPath = path.join(directory, "registry.json");
  await writeFile(registryPath, `${encoded}${" ".repeat(MAX_REGISTRY_BYTES - Buffer.byteLength(encoded))}`);

  const result = await verifyLocal(registryPath, { now: GENERATED_AT });

  assert.equal(result.status, "unknown");
  assert.equal(result.error, undefined);
});

test("local mode rejects registries above 8 MiB with an invalid size outcome", async () => {
  const directory = path.join(fixtureRoot, "registry-too-large");
  await mkdir(directory);
  const registryPath = path.join(directory, "registry.json");
  await writeFile(registryPath, "");
  await truncate(registryPath, MAX_REGISTRY_BYTES + 1);

  const result = await verifyLocal(registryPath);

  assert.equal(result.status, "invalid");
  assert.equal(result.error?.code, "registry_too_large");
});

test("local mode accepts proof artifacts above the obsolete 16 MiB ceiling", async () => {
  const directory = path.join(fixtureRoot, "artifact-expanded-limit");
  await mkdir(directory);
  const bytes = Buffer.alloc(16 * 1024 * 1024 + 1, 0x61);
  await writeFile(path.join(directory, "artifact.bin"), bytes);
  const registryPath = await writeRegistry(
    directory,
    snapshotRegistry({ artifactSha256: sha256(bytes) }),
  );

  const result = await verifyLocal(registryPath, { now: GENERATED_AT });

  assert.equal(result.status, "verified");
});

test("local mode rejects proof artifacts above 64 MiB before hashing them", async () => {
  const directory = path.join(fixtureRoot, "artifact-too-large");
  await mkdir(directory);
  const artifactPath = path.join(directory, "artifact.bin");
  await writeFile(artifactPath, "");
  await truncate(artifactPath, MAX_ARTIFACT_BYTES + 1);
  const registryPath = await writeRegistry(directory, snapshotRegistry());

  const result = await verifyLocal(registryPath, { now: GENERATED_AT });

  assert.equal(result.status, "invalid");
  assert.equal(result.error?.code, "artifact_too_large");
});

test("local mode rejects an artifact symlink that escapes the registry directory", async () => {
  const directory = path.join(fixtureRoot, "symlink-escape");
  const registryDirectory = path.join(directory, "registry");
  await mkdir(registryDirectory, { recursive: true });
  const bytes = Buffer.from("outside proof\n");
  const outside = path.join(directory, "outside.bin");
  await writeFile(outside, bytes);
  await symlink(outside, path.join(registryDirectory, "artifact.bin"));
  const registryPath = await writeRegistry(
    registryDirectory,
    snapshotRegistry({ artifactSha256: sha256(bytes) }),
  );

  const result = await verifyLocal(registryPath, { now: GENERATED_AT });

  assert.equal(result.status, "invalid");
  assert.equal(result.error?.code, "unsafe_artifact_path");
});

test("local mode permits an artifact symlink whose real target remains in-tree", async () => {
  const directory = path.join(fixtureRoot, "symlink-in-tree");
  await mkdir(directory);
  const bytes = Buffer.from("in-tree proof\n");
  await writeFile(path.join(directory, "target.bin"), bytes);
  await symlink("target.bin", path.join(directory, "artifact.bin"));
  const registryPath = await writeRegistry(
    directory,
    snapshotRegistry({ artifactSha256: sha256(bytes) }),
  );

  const result = await verifyLocal(registryPath, { now: GENERATED_AT });

  assert.equal(result.status, "verified");
});

test("local confinement does not reject a safe filename that merely starts with dots", async () => {
  const directory = path.join(fixtureRoot, "dot-prefixed-artifact");
  await mkdir(directory);
  const bytes = Buffer.from("dot-prefixed proof\n");
  await writeFile(path.join(directory, "..proof.bin"), bytes);
  const registryPath = await writeRegistry(
    directory,
    snapshotRegistry({
      artifactPath: "..proof.bin",
      artifactSha256: sha256(bytes),
    }),
  );

  const result = await verifyLocal(registryPath, { now: GENERATED_AT });

  assert.equal(result.status, "verified");
});

test("local mode safely loads an artifact whose filename is an Object prototype key", async () => {
  const directory = path.join(fixtureRoot, "prototype-key-artifact");
  await mkdir(directory);
  const bytes = Buffer.from("prototype-key proof\n");
  await writeFile(path.join(directory, "__proto__"), bytes);
  const registryPath = await writeRegistry(
    directory,
    snapshotRegistry({
      artifactPath: "__proto__",
      artifactSha256: sha256(bytes),
    }),
  );

  const result = await verifyLocal(registryPath, { now: GENERATED_AT });

  assert.equal(result.status, "verified");
});

test("local mode rejects non-regular artifact paths explicitly", async () => {
  const directory = path.join(fixtureRoot, "artifact-directory");
  await mkdir(path.join(directory, "artifact.bin"), { recursive: true });
  const registryPath = await writeRegistry(directory, snapshotRegistry());

  const result = await verifyLocal(registryPath, { now: GENERATED_AT });

  assert.equal(result.status, "invalid");
  assert.equal(result.error?.code, "artifact_not_regular_file");
});

test("local mode keeps an absent proof artifact unavailable", async () => {
  const directory = path.join(fixtureRoot, "artifact-missing");
  await mkdir(directory);
  const registryPath = await writeRegistry(directory, snapshotRegistry());

  const result = await verifyLocal(registryPath, { now: GENERATED_AT });

  assert.equal(result.status, "unavailable");
  assert.equal(result.error, undefined);
  assert.match(result.items[0].reasons.join("\n"), /artifact bytes unavailable/);
});

test("local mode rejects registries above the 128-item ceiling", async () => {
  const directory = path.join(fixtureRoot, "local-item-limit");
  await mkdir(directory);
  const registry = repeatSnapshotItems(
    snapshotRegistry(),
    MAX_REGISTRY_ITEMS + 1,
  );
  const registryPath = await writeRegistry(directory, registry);

  const result = await verifyLocal(registryPath, { now: GENERATED_AT });

  assert.equal(result.status, "invalid");
  assert.equal(result.error?.code, "too_many_items");
});

test("local mode rejects registries above the 128-unique-artifact ceiling", async () => {
  const directory = path.join(fixtureRoot, "local-artifact-count-limit");
  await mkdir(directory);
  const registry = repeatSnapshotItems(
    snapshotRegistry(),
    MAX_UNIQUE_ARTIFACTS + 1,
    { artifactPath: (index) => `artifact-${index}.bin` },
  );
  const registryPath = await writeRegistry(directory, registry);

  const result = await verifyLocal(registryPath, { now: GENERATED_AT });

  assert.equal(result.status, "invalid");
  assert.equal(result.error?.code, "artifact_count_exceeded");
});

test("local mode rejects aggregate artifact bytes above 128 MiB", async () => {
  const directory = path.join(fixtureRoot, "local-artifact-aggregate-limit");
  await mkdir(directory);
  const artifactPaths = ["artifact-0.bin", "artifact-1.bin", "artifact-2.bin"];
  for (const artifactPath of artifactPaths) {
    const absolute = path.join(directory, artifactPath);
    await writeFile(absolute, "");
    await truncate(absolute, 45 * 1024 * 1024);
  }
  const registry = repeatSnapshotItems(
    snapshotRegistry(),
    artifactPaths.length,
    { artifactPath: (index) => artifactPaths[index] },
  );
  const registryPath = await writeRegistry(directory, registry);

  const result = await verifyLocal(registryPath, { now: GENERATED_AT });

  assert.equal(result.status, "invalid");
  assert.equal(result.error?.code, "artifact_aggregate_too_large");
});

test("local mode permits repeated references to one artifact without double-counting it", async () => {
  const directory = path.join(fixtureRoot, "local-artifact-deduplication");
  await mkdir(directory);
  const bytes = Buffer.from("one shared local proof\n");
  await writeFile(path.join(directory, "artifact.bin"), bytes);
  const registry = repeatSnapshotItems(
    snapshotRegistry({ artifactSha256: sha256(bytes) }),
    3,
  );
  const registryPath = await writeRegistry(directory, registry);

  const result = await verifyLocal(registryPath, { now: GENERATED_AT });

  assert.equal(result.status, "verified");
});

test("URL mode consumes registry bodies as streams without arrayBuffer", async () => {
  const bytes = Buffer.from(JSON.stringify(emptyRegistry()));
  const response = streamResponse([bytes.subarray(0, 7), bytes.subarray(7)]);

  const result = await verifyUrl(`${REMOTE_ORIGIN}/registry.json`, {
    fetchImpl: async () => response,
    dnsLookup: SAFE_DNS_LOOKUP,
    now: GENERATED_AT,
  });

  assert.equal(result.status, "unknown");
  assert.equal(result.error, undefined);
});

test("URL mode cancels and aborts a streamed registry as soon as it crosses 8 MiB", async () => {
  const chunk = new Uint8Array(1024 * 1024);
  let cancelled = false;
  let requestSignal;
  const response = streamResponse(Array.from({ length: 10 }, () => chunk), {
    onCancel: () => {
      cancelled = true;
    },
  });

  const result = await verifyUrl(`${REMOTE_ORIGIN}/registry.json`, {
    fetchImpl: async (_input, init) => {
      requestSignal = init?.signal;
      return response;
    },
    dnsLookup: SAFE_DNS_LOOKUP,
  });

  assert.equal(result.status, "invalid");
  assert.equal(result.error?.code, "registry_too_large");
  assert.equal(cancelled, true);
  assert.equal(requestSignal?.aborted, true);
});

test("URL mode enforces the registry Content-Length limit before reading", async () => {
  const result = await verifyUrl(`${REMOTE_ORIGIN}/registry.json`, {
    fetchImpl: async () =>
      new Response("{}", {
        status: 200,
        headers: { "content-length": String(MAX_REGISTRY_BYTES + 1) },
      }),
    dnsLookup: SAFE_DNS_LOOKUP,
  });

  assert.equal(result.status, "invalid");
  assert.equal(result.error?.code, "registry_too_large");
});

test("URL mode accepts a streamed proof artifact above 16 MiB and below 64 MiB", async () => {
  const artifact = Buffer.alloc(16 * 1024 * 1024 + 1, 0x62);
  const registry = snapshotRegistry({
    artifactSha256: sha256(artifact),
    artifactHref: `${REMOTE_ORIGIN}/artifact.bin`,
  });
  const calls = [];

  const result = await verifyUrl(`${REMOTE_ORIGIN}/registry.json`, {
    fetchImpl: async (input) => {
      const url = String(input);
      calls.push(url);
      return url.endsWith("/artifact.bin")
        ? new Response(artifact)
        : Response.json(registry);
    },
    dnsLookup: SAFE_DNS_LOOKUP,
    now: GENERATED_AT,
  });

  assert.equal(result.status, "verified");
  assert.equal(calls.length, 2);
});

test("URL mode rejects a proof artifact above 64 MiB with an artifact-specific outcome", async () => {
  const registry = snapshotRegistry({
    artifactHref: `${REMOTE_ORIGIN}/artifact.bin`,
  });

  const result = await verifyUrl(`${REMOTE_ORIGIN}/registry.json`, {
    fetchImpl: async (input) =>
      String(input).endsWith("/artifact.bin")
        ? new Response(null, {
            status: 200,
            headers: { "content-length": String(MAX_ARTIFACT_BYTES + 1) },
          })
        : Response.json(registry),
    dnsLookup: SAFE_DNS_LOOKUP,
    now: GENERATED_AT,
  });

  assert.equal(result.status, "invalid");
  assert.equal(result.error?.code, "artifact_too_large");
});

test("URL mode rejects cross-origin artifact links without sending the second request", async () => {
  const artifact = Buffer.from("unrelated-host proof\n");
  const registry = snapshotRegistry({
    artifactSha256: sha256(artifact),
    artifactHref: "https://unrelated.example.invalid/artifact.bin",
  });
  const calls = [];

  const result = await verifyUrl(`${REMOTE_ORIGIN}/registry.json`, {
    fetchImpl: async (input) => {
      calls.push(String(input));
      return calls.length === 1 ? Response.json(registry) : new Response(artifact);
    },
    dnsLookup: SAFE_DNS_LOOKUP,
    now: GENERATED_AT,
  });

  assert.equal(result.status, "invalid");
  assert.equal(result.error?.code, "artifact_origin_mismatch");
  assert.deepEqual(calls, [`${REMOTE_ORIGIN}/registry.json`]);
});

test("URL mode rejects redirects as unavailable rather than following them", async () => {
  const result = await verifyUrl(`${REMOTE_ORIGIN}/registry.json`, {
    fetchImpl: async () =>
      new Response(null, {
        status: 302,
        headers: { location: `${REMOTE_ORIGIN}/other.json` },
      }),
    dnsLookup: SAFE_DNS_LOOKUP,
  });

  assert.equal(result.status, "unavailable");
  assert.equal(result.error?.code, "registry_redirect_rejected");
});

test("URL mode rejects schemes and every form of URL userinfo before fetch", async () => {
  const invalidUrls = [
    "http://proofs.example.com/registry.json",
    "https://user:password@proofs.example.com/registry.json",
    "https://@proofs.example.com/registry.json",
    "https://:@proofs.example.com/registry.json",
  ];
  let calls = 0;

  for (const url of invalidUrls) {
    const result = await verifyUrl(url, {
      fetchImpl: async () => {
        calls += 1;
        return Response.json(emptyRegistry());
      },
    });
    assert.equal(result.status, "invalid", url);
    assert.equal(result.error?.code, "invalid_url", url);
  }
  assert.equal(calls, 0);
});

test("URL mode rejects unsafe literal hosts before invoking fetch", async () => {
  const unsafeUrls = [
    "https://127.0.0.1/registry.json",
    "https://127.1/registry.json",
    "https://2130706433/registry.json",
    "https://0x7f000001/registry.json",
    "https://10.0.0.1/registry.json",
    "https://100.64.0.1/registry.json",
    "https://169.254.169.254/latest/meta-data",
    "https://192.0.2.1/registry.json",
    "https://198.18.0.1/registry.json",
    "https://224.0.0.1/registry.json",
    "https://240.0.0.1/registry.json",
    "https://[::1]/registry.json",
    "https://[fc00::1]/registry.json",
    "https://[fe80::1]/registry.json",
    "https://[ff02::1]/registry.json",
    "https://[2001:db8::1]/registry.json",
    "https://[::ffff:127.0.0.1]/registry.json",
  ];
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return Response.json(emptyRegistry());
  };

  for (const url of unsafeUrls) {
    const result = await verifyUrl(url, { fetchImpl });
    assert.equal(result.status, "invalid", url);
    assert.equal(result.error?.code, "unsafe_remote_host", url);
  }
  assert.equal(calls, 0);
});

test("URL mode rejects any private DNS answer before invoking an injectable fetch", async () => {
  let calls = 0;
  const result = await verifyUrl("https://proofs.example.com/registry.json", {
    fetchImpl: async () => {
      calls += 1;
      return Response.json(emptyRegistry());
    },
    dnsLookup: async () => ["93.184.216.34", "10.0.0.7"],
  });

  assert.equal(result.status, "invalid");
  assert.equal(result.error?.code, "unsafe_remote_host");
  assert.equal(calls, 0);
});

test("URL mode reports DNS lookup failures as unavailable without invoking fetch", async () => {
  let calls = 0;
  const result = await verifyUrl("https://proofs.example.com/registry.json", {
    fetchImpl: async () => {
      calls += 1;
      return Response.json(emptyRegistry());
    },
    dnsLookup: async () => {
      const error = new Error("host not found");
      error.code = "ENOTFOUND";
      throw error;
    },
  });

  assert.equal(result.status, "unavailable");
  assert.equal(result.error?.code, "registry_dns_failed");
  assert.equal(calls, 0);
});

test("URL mode rechecks DNS before same-origin artifact fetches", async () => {
  const artifact = Buffer.from("dns-rebinding proof\n");
  const registry = snapshotRegistry({
    artifactSha256: sha256(artifact),
    artifactHref: "https://proofs.example.com/artifact.bin",
  });
  const answers = [["93.184.216.34"], ["127.0.0.1"]];
  const calls = [];

  const result = await verifyUrl("https://proofs.example.com/registry.json", {
    fetchImpl: async (input) => {
      calls.push(String(input));
      return calls.length === 1 ? Response.json(registry) : new Response(artifact);
    },
    dnsLookup: async () => answers.shift(),
    now: GENERATED_AT,
  });

  assert.equal(result.status, "invalid");
  assert.equal(result.error?.code, "unsafe_remote_host");
  assert.deepEqual(calls, ["https://proofs.example.com/registry.json"]);
});

test("URL mode rejects a custom fetch when no DNS resolver is supplied", async () => {
  let calls = 0;
  const result = await verifyUrl(`${REMOTE_ORIGIN}/registry.json`, {
    fetchImpl: async () => {
      calls += 1;
      return Response.json(emptyRegistry());
    },
  });

  assert.equal(result.status, "invalid");
  assert.equal(result.error?.code, "custom_fetch_dns_required");
  assert.equal(calls, 0);
});

test("URL mode rejects registries above the 128-item ceiling before artifact fetches", async () => {
  const registry = repeatSnapshotItems(
    snapshotRegistry({ artifactHref: `${REMOTE_ORIGIN}/artifact.bin` }),
    MAX_REGISTRY_ITEMS + 1,
  );
  let calls = 0;

  const result = await verifyUrl(`${REMOTE_ORIGIN}/registry.json`, {
    fetchImpl: async () => {
      calls += 1;
      return Response.json(registry);
    },
    dnsLookup: SAFE_DNS_LOOKUP,
    now: GENERATED_AT,
  });

  assert.equal(result.status, "invalid");
  assert.equal(result.error?.code, "too_many_items");
  assert.equal(calls, 1);
});

test("URL mode rejects registries above the 128-unique-artifact ceiling before artifact fetches", async () => {
  const registry = repeatSnapshotItems(
    snapshotRegistry({ artifactHref: `${REMOTE_ORIGIN}/artifact-0.bin` }),
    MAX_UNIQUE_ARTIFACTS + 1,
    {
      artifactPath: (index) => `artifact-${index}.bin`,
      artifactHref: (index) => `${REMOTE_ORIGIN}/artifact-${index}.bin`,
    },
  );
  let calls = 0;

  const result = await verifyUrl(`${REMOTE_ORIGIN}/registry.json`, {
    fetchImpl: async () => {
      calls += 1;
      return Response.json(registry);
    },
    dnsLookup: SAFE_DNS_LOOKUP,
    now: GENERATED_AT,
  });

  assert.equal(result.status, "invalid");
  assert.equal(result.error?.code, "artifact_count_exceeded");
  assert.equal(calls, 1);
});

test("URL mode fetches a shared artifact path only once", async () => {
  const artifact = Buffer.from("one shared remote proof\n");
  const registry = repeatSnapshotItems(
    snapshotRegistry({
      artifactSha256: sha256(artifact),
      artifactHref: `${REMOTE_ORIGIN}/artifact.bin`,
    }),
    3,
  );
  const calls = [];

  const result = await verifyUrl(`${REMOTE_ORIGIN}/registry.json`, {
    fetchImpl: async (input) => {
      calls.push(String(input));
      return calls.length === 1 ? Response.json(registry) : new Response(artifact);
    },
    dnsLookup: SAFE_DNS_LOOKUP,
    now: GENERATED_AT,
  });

  assert.equal(result.status, "verified");
  assert.deepEqual(calls, [
    `${REMOTE_ORIGIN}/registry.json`,
    `${REMOTE_ORIGIN}/artifact.bin`,
  ]);
});

test("URL mode rejects conflicting URLs for one artifact path before artifact fetches", async () => {
  const registry = repeatSnapshotItems(
    snapshotRegistry({ artifactHref: `${REMOTE_ORIGIN}/artifact-a.bin` }),
    2,
    {
      artifactHref: (index) => `${REMOTE_ORIGIN}/artifact-${index}.bin`,
    },
  );
  let calls = 0;

  const result = await verifyUrl(`${REMOTE_ORIGIN}/registry.json`, {
    fetchImpl: async () => {
      calls += 1;
      return Response.json(registry);
    },
    dnsLookup: SAFE_DNS_LOOKUP,
    now: GENERATED_AT,
  });

  assert.equal(result.status, "invalid");
  assert.equal(result.error?.code, "artifact_link_conflict");
  assert.equal(calls, 1);
});

test("URL mode rejects aggregate artifact bytes above 128 MiB", async () => {
  const artifactSize = 45 * 1024 * 1024;
  const artifact = Buffer.alloc(artifactSize, 0x63);
  const registry = repeatSnapshotItems(
    snapshotRegistry({
      artifactSha256: sha256(artifact),
      artifactHref: `${REMOTE_ORIGIN}/artifact-0.bin`,
    }),
    3,
    {
      artifactPath: (index) => `artifact-${index}.bin`,
      artifactHref: (index) => `${REMOTE_ORIGIN}/artifact-${index}.bin`,
    },
  );
  let calls = 0;

  const result = await verifyUrl(`${REMOTE_ORIGIN}/registry.json`, {
    fetchImpl: async () => {
      calls += 1;
      return calls === 1 ? Response.json(registry) : new Response(artifact);
    },
    dnsLookup: SAFE_DNS_LOOKUP,
    now: GENERATED_AT,
  });

  assert.equal(result.status, "invalid");
  assert.equal(result.error?.code, "artifact_aggregate_too_large");
  assert.equal(calls, 4);
});

test("URL mode applies one overall deadline across registry and artifact requests", async () => {
  const artifact = Buffer.from("deadline proof\n");
  const registry = snapshotRegistry({
    artifactSha256: sha256(artifact),
    artifactHref: `${REMOTE_ORIGIN}/artifact.bin`,
  });
  let calls = 0;
  const startedAt = Date.now();

  const result = await verifyUrl(`${REMOTE_ORIGIN}/registry.json`, {
    fetchImpl: async () => {
      calls += 1;
      await new Promise((resolve) => setTimeout(resolve, 70));
      return calls === 1 ? Response.json(registry) : new Response(artifact);
    },
    dnsLookup: SAFE_DNS_LOOKUP,
    timeoutMs: 100,
    now: GENERATED_AT,
  });

  assert.equal(result.status, "unavailable");
  assert.equal(result.error?.code, "artifact_fetch_failed");
  assert.equal(calls, 2);
  assert.ok(Date.now() - startedAt < 180);
});

test("URL mode cancels a stalled response body when its request deadline expires", async () => {
  let cancelled = false;
  let requestSignal;
  const response = new Response(
    new ReadableStream({
      pull() {
        return new Promise(() => {});
      },
      cancel() {
        cancelled = true;
      },
    }),
  );

  const result = await verifyUrl(`${REMOTE_ORIGIN}/registry.json`, {
    fetchImpl: async (_input, init) => {
      requestSignal = init?.signal;
      return response;
    },
    dnsLookup: SAFE_DNS_LOOKUP,
    timeoutMs: 10,
  });

  assert.equal(result.status, "unavailable");
  assert.equal(result.error?.code, "registry_read_failed");
  assert.equal(requestSignal?.aborted, true);
  assert.equal(cancelled, true);
});

test("URL mode keeps a missing same-origin artifact unavailable", async () => {
  const registry = snapshotRegistry({
    artifactHref: `${REMOTE_ORIGIN}/missing.bin`,
  });
  const calls = [];

  const result = await verifyUrl(`${REMOTE_ORIGIN}/registry.json`, {
    fetchImpl: async (input) => {
      calls.push(String(input));
      return calls.length === 1
        ? Response.json(registry)
        : new Response(null, { status: 404 });
    },
    dnsLookup: SAFE_DNS_LOOKUP,
    now: GENERATED_AT,
  });

  assert.equal(result.status, "unavailable");
  assert.equal(result.error, undefined);
  assert.match(result.items[0].reasons.join("\n"), /artifact bytes unavailable/);
  assert.equal(calls.length, 2);
});
