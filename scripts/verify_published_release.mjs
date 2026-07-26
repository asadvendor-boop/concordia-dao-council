#!/usr/bin/env node
/**
 * Read-only verification of an ALREADY-PUBLISHED @concordia-dao/verify release.
 *
 * Publication and verification are separate concerns: this needs no NPM_TOKEN
 * and no publish permission, so it can re-prove a release at any time without
 * the ability to create one.
 *
 * The source commit is bound through the SLSA provenance
 * (predicate.buildDefinition.resolvedDependencies[].digest.gitCommit), NOT
 * through registry `gitHead` — npm does not populate gitHead for tarball
 * publication, and asserting it left a genuinely successful publish reporting
 * red.
 *
 *   node scripts/verify_published_release.mjs <version> <40-hex-commit>
 */
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const PACKAGE = "@concordia-dao/verify";
const REPOSITORY = "https://github.com/asadvendor-boop/concordia-dao-council";
const WORKFLOW_PATH = ".github/workflows/publish-verifier.yml";
const WORKFLOW_REF = "refs/heads/main";
const SOURCE_URI =
  "git+https://github.com/asadvendor-boop/concordia-dao-council@refs/heads/main";
const BUILDER = "https://github.com/actions/runner/github-hosted";
const INVOCATION =
  /^https:\/\/github\.com\/asadvendor-boop\/concordia-dao-council\/actions\/runs\/[1-9][0-9]*\/attempts\/[1-9][0-9]*$/;
const CONSUMER_VERIFIER = fileURLToPath(
  new URL("./verify_verifier_consumer.mjs", import.meta.url),
);

const [version, commit] = process.argv.slice(2);
if (!/^\d+\.\d+\.\d+$/.test(version ?? "") || !/^[0-9a-f]{40}$/.test(commit ?? "")) {
  console.error("usage: verify_published_release.mjs <version> <40-hex-commit>");
  process.exit(64);
}

const checks = [];
const record = (name, ok, detail = "") => {
  checks.push({ name, ok, detail });
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${detail ? `  ${detail}` : ""}`);
};

const spec = `${PACKAGE}@${version}`;
const metadata = JSON.parse(
  execFileSync("npm", ["view", spec, "name", "version", "dist", "repository", "--json"], {
    encoding: "utf8",
  }),
);

record("registry name", metadata.name === PACKAGE, metadata.name);
record("registry version", metadata.version === version, metadata.version);

const attestations = metadata.dist?.attestations;
record(
  "attestation advertised",
  attestations?.provenance?.predicateType === "https://slsa.dev/provenance/v1"
    && typeof attestations?.url === "string",
);

const url = new URL(attestations.url);
const expectedPath = `/-/npm/v1/attestations/${PACKAGE}@${version}`;
record(
  "attestation url is registry-hosted and exact",
  url.protocol === "https:"
    && url.hostname === "registry.npmjs.org"
    && decodeURIComponent(url.pathname) === expectedPath,
);

const document = await (await fetch(attestations.url)).json();
const provenance = document.attestations?.find(
  (item) => item?.predicateType === "https://slsa.dev/provenance/v1",
);
record("provenance present in bundle", Boolean(provenance?.bundle?.dsseEnvelope?.payload));

const statement = JSON.parse(
  Buffer.from(provenance.bundle.dsseEnvelope.payload, "base64").toString("utf8"),
);
record("in-toto statement v1", statement._type === "https://in-toto.io/Statement/v1");

const expectedDigest = Buffer.from(
  metadata.dist.integrity.slice("sha512-".length),
  "base64",
).toString("hex");
const subject = statement.subject;
record(
  "subject binds package and tarball sha512",
  Array.isArray(subject)
    && subject.length === 1
    && subject[0]?.name === `pkg:npm/%40concordia-dao/verify@${version}`
    && subject[0]?.digest?.sha512 === expectedDigest,
);

const build = statement.predicate?.buildDefinition;
const workflow = build?.externalParameters?.workflow;
record("provenance repository", workflow?.repository === REPOSITORY, workflow?.repository);
record("provenance workflow path", workflow?.path === WORKFLOW_PATH, workflow?.path);
record("provenance ref", workflow?.ref === WORKFLOW_REF, workflow?.ref);

const resolved = build?.resolvedDependencies;
const sourceDependencies = Array.isArray(resolved)
  ? resolved.filter((item) => item?.uri === SOURCE_URI)
  : [];
record(
  "exactly one repository dependency binds source commit",
  sourceDependencies.length === 1
    && sourceDependencies[0]?.digest?.gitCommit === commit,
  commit,
);

const details = statement.predicate?.runDetails;
record("github-hosted builder", details?.builder?.id === BUILDER);
record(
  "invocation id is a real run",
  typeof details?.metadata?.invocationId === "string"
    && INVOCATION.test(details.metadata.invocationId),
  details?.metadata?.invocationId,
);

const consumer = JSON.parse(
  execFileSync(
    process.execPath,
    [CONSUMER_VERIFIER, spec, "--audit-signatures"],
    { encoding: "utf8" },
  ),
);
record("clean-consumer install", consumer.checks?.cleanConsumerInstall === true);
record("public API import", consumer.checks?.publicApiImport === true);
record("CLI --help", consumer.checks?.cliHelp === true);
record(
  "canonical V1 local fixture",
  consumer.checks?.v1LocalFixture === true
    && consumer.fixture?.proposalId === "DAO-PROP-6CB25C"
    && consumer.fixture?.scope === "test-only",
);
record("npm audit signatures", consumer.checks?.npmAuditSignatures === true);

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
if (failed.length) process.exit(1);
console.log(`VERIFIED: ${spec} built by ${WORKFLOW_PATH} from ${commit}`);
