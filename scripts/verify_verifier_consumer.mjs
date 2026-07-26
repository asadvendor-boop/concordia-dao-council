#!/usr/bin/env node
/**
 * Verify an @concordia-dao/verify package spec or exact tarball in a clean
 * consumer. The smoke proof is a local, test-only V1 registry fixture: it does
 * not contact Concordia infrastructure or promote a historical compatibility
 * endpoint.
 *
 *   node scripts/verify_verifier_consumer.mjs <package-spec-or-tarball>
 *   node scripts/verify_verifier_consumer.mjs <published-package-spec> --audit-signatures
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const args = process.argv.slice(2);
const auditSignatures = args.includes("--audit-signatures");
const positional = args.filter((argument) => argument !== "--audit-signatures");

if (positional.length !== 1 || !positional[0]) {
  console.error(
    "usage: verify_verifier_consumer.mjs <package-spec-or-tarball> [--audit-signatures]",
  );
  process.exit(64);
}

const requestedSpec = positional[0];
const packageSpec = existsSync(requestedSpec) ? realpathSync(requestedSpec) : requestedSpec;
const consumer = mkdtempSync(path.join(tmpdir(), "concordia-verify-consumer-"));
const checks = {
  cleanConsumerInstall: false,
  publicApiImport: false,
  cliHelp: false,
  v1LocalFixture: false,
  npmAuditSignatures: null,
};

try {
  writeFileSync(
    path.join(consumer, "package.json"),
    `${JSON.stringify({
      name: "concordia-verify-consumer",
      private: true,
      type: "module",
      version: "0.0.0",
    })}\n`,
  );

  execFileSync(
    "npm",
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--package-lock=false",
      packageSpec,
    ],
    { cwd: consumer, stdio: "pipe" },
  );
  checks.cleanConsumerInstall = true;

  execFileSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      [
        "const m = await import('@concordia-dao/verify');",
        "if (typeof m.verifyProofRegistry !== 'function') process.exit(1);",
        "if (Object.hasOwn(m, 'verifyRegistry')) process.exit(1);",
      ].join(" "),
    ],
    { cwd: consumer, stdio: "pipe" },
  );
  checks.publicApiImport = true;

  const cli = path.join(consumer, "node_modules/.bin/concordia-verify");
  execFileSync(cli, ["--help"], { cwd: consumer, stdio: "pipe" });
  checks.cliHelp = true;

  const capturedAt = "2026-07-23T00:00:00Z";
  const generatedAt = "2026-07-23T00:01:00Z";
  const artifact = Buffer.from(
    `${JSON.stringify({
      fixture_scope: "test-only-consumer-smoke",
      proof: "v1-local-registry-smoke",
    })}\n`,
    "utf8",
  );
  const artifactPath = path.join(consumer, "artifact.json");
  const registryPath = path.join(consumer, "registry.json");
  writeFileSync(artifactPath, artifact);

  const checksRequired = [
    "artifact_sha256_recomputed",
    "capture_time_present",
    "source_https_url_present",
    "staleness_check_passed",
  ].map((name) => ({
    name,
    required: true,
    passed: true,
    source: "test-only-consumer-smoke",
    observed_at: capturedAt,
  }));
  const registry = {
    schema_version: 1,
    generated_at: generatedAt,
    proposal_id: "DAO-PROP-6CB25C",
    items: [
      {
        proof_id: "consumer_v1_snapshot",
        proof_type: "snapshot",
        generation: "none",
        lineage: "supplemental",
        observation_mode: "snapshot",
        temporal_scope: "current",
        verification_status: "verified",
        execution_outcome: "not_applicable",
        claim_scope: "Test-only V1 clean-consumer fixture.",
        enforcement_scope: "Read-only local verification.",
        proposal_id: "DAO-PROP-6CB25C",
        action_id: null,
        envelope_hash: null,
        artifact_path: "artifact.json",
        artifact_sha256: createHash("sha256").update(artifact).digest("hex"),
        source_commit: "1".repeat(40),
        deployment_commit: "2".repeat(40),
        network: "casper:casper-test",
        package_hash: null,
        contract_hash: null,
        deployment_domain: null,
        schema_version: "snapshot-v1",
        captured_at: capturedAt,
        payment_requirements_hash: null,
        signed_payment_payload_hash: null,
        report_hash: null,
        settlement_transaction: null,
        checks: checksRequired,
        links: [
          {
            rel: "source",
            label: "Reserved test-only source",
            href: "https://example.invalid/concordia-v1-consumer-smoke",
            kind: "source",
          },
        ],
      },
    ],
  };
  writeFileSync(registryPath, `${JSON.stringify(registry, null, 2)}\n`);

  const cliOutput = execFileSync(cli, ["local", registryPath, "--now", generatedAt], {
    cwd: consumer,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
  });
  const result = JSON.parse(cliOutput);
  if (
    result.mode !== "local"
    || result.status !== "verified"
    || result.valid !== true
    || result.exitCode !== 0
    || result.proposalId !== "DAO-PROP-6CB25C"
  ) {
    throw new Error(`unexpected V1 local fixture result: ${cliOutput}`);
  }
  checks.v1LocalFixture = true;

  if (auditSignatures) {
    execFileSync("npm", ["audit", "signatures"], { cwd: consumer, stdio: "pipe" });
    checks.npmAuditSignatures = true;
  }

  process.stdout.write(
    `${JSON.stringify({
      packageSpec: requestedSpec,
      checks,
      fixture: {
        proposalId: "DAO-PROP-6CB25C",
        proofType: "snapshot",
        network: "casper:casper-test",
        scope: "test-only",
      },
    })}\n`,
  );
} finally {
  // The package, fixture, and npm cache metadata are only clean-room evidence.
  rmSync(consumer, { recursive: true, force: true });
}
