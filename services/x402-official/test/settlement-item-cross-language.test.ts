/**
 * Cross-language acceptance + schema-drift suite (reviewer P1: schema drift).
 *
 * The builder's contract must be validated against the ACTUAL consumers, not
 * against WP5's own constants:
 *
 *  (a) Python — ONE real builder output is piped (as JSON, over stdin) through
 *      `shared.proof_registry.normalize_proof_item`, the public-item error
 *      validator, and `proof_item_is_green`, spawned from the repo root with
 *      the registry package on sys.path. Zero errors, verification_status
 *      stays "verified", and the item is green.
 *  (b) Dashboard — the same item is passed to the dashboard's pure validation
 *      module (dashboard/app/_components/provenance-pure.js, imported AS-IS by
 *      relative path; the renderer provenance.js re-exports it):
 *      `registryItemErrors(item)` must be empty and
 *      `itemGreenVerified(item)` must accept it.
 *
 * Plus drift pins: the builder's 22-name required-check list and 29-name
 * public-field list must equal, name for name and in order, both the Python
 * registry's and the dashboard's constants.
 *
 * Plus adversarial mutations (renamed check / dropped field / forbidden
 * evidence on an emitted check / wrong network / short commit / duplicate /
 * failed check / camel-case name / late observation): each must fail the
 * builder AND, where the public-item validators cover that dimension, be
 * rejected by Python and the dashboard identically — proving the three
 * implementations agree.
 *
 * NOTE (worktree state): this branch does not yet carry
 * shared/proof_registry.py. The suite prefers the in-tree file when present
 * (post-merge state) and otherwise materializes the EXPLICITLY PINNED
 * accepted registry commit (PINNED_ACCEPTED_REGISTRY_COMMIT below) from the
 * git object store into a temp package — never "the newest commit on any
 * ref", so unrelated or rejected branches can never control the test
 * authority. Only the read-only `git show` command is used.
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  buildSettlementRegistryItem,
  OFFICIAL_X402_SETTLEMENT_NETWORK,
  OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS,
  OFFICIAL_X402_SETTLEMENT_SCHEMA_VERSION,
  PUBLIC_ITEM_REQUIRED_FIELDS,
  SettlementItemError,
  type SettlementRegistryItem,
} from "../src/settlement-item.js";
import { validChecks, validInput } from "./settlement-item-fixture.js";

// The dashboard's pure validation module, imported AS-IS (another lane owns
// it; it is read, never modified). provenance-pure.js is JSX-free and
// dependency-free by contract, so this suite runs in a checkout where ONLY
// services/x402-official has installed dependencies — no dashboard
// node_modules, no NODE_PATH, no esbuild transform. The dashboard renderer
// (provenance.js) re-exports these same symbols, so this pins the exact logic
// the dashboard executes.
import {
  itemGreenVerified,
  registryItemErrors,
  PUBLIC_ITEM_REQUIRED_FIELDS as DASHBOARD_PUBLIC_ITEM_REQUIRED_FIELDS,
  REQUIRED_CHECKS_BY_PROOF_TYPE as DASHBOARD_REQUIRED_CHECKS_BY_PROOF_TYPE,
  // eslint-disable-next-line import/no-relative-packages
} from "../../../dashboard/app/_components/provenance-pure.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, "..", "..", "..");

interface PythonVerdict {
  errors: string[];
  verification_status: string;
  green: boolean;
  required_checks: string[];
  public_fields: string[];
}

const PYTHON_PROGRAM = `
import json, sys
sys.path.insert(0, sys.argv[1])
from shared.proof_registry import (
    REQUIRED_CHECKS_BY_PROOF_TYPE,
    PUBLIC_ITEM_REQUIRED_FIELDS,
    _public_item_errors,
    normalize_proof_item,
    proof_item_is_green,
)
item = json.load(sys.stdin)
print(json.dumps({
    "errors": _public_item_errors(item),
    "verification_status": normalize_proof_item(item)["verification_status"],
    "green": proof_item_is_green(item),
    "required_checks": list(
        REQUIRED_CHECKS_BY_PROOF_TYPE["official_x402_settlement_v1"]
    ),
    "public_fields": list(PUBLIC_ITEM_REQUIRED_FIELDS),
}))
`;

let registryRoot = REPO_ROOT;
let registrySource = "worktree shared/proof_registry.py";
let materializedRoot: string | null = null;

// Reviewer finding (test-authority nondeterminism): the previous fallback ran
// `git log --all` and let the NEWEST commit on ANY ref — including unrelated,
// experimental, or rejected branches — control which registry this suite
// validated against. The authority is now either the in-tree accepted registry
// (post-merge state) or this EXPLICITLY PINNED accepted commit, nothing else.
// Pin provenance: codex/finals-integration-preview `fix: derive public proof
// truth fail closed` — the accepted WP4 registry lineage this suite's 22-check
// and 29-field constants were verified against. Advancing the pin is a
// deliberate reviewed change, never an accident of ref state.
const PINNED_ACCEPTED_REGISTRY_COMMIT =
  "7170c873fd20c1ff2e9e3115ec1523b9b1ea2c9b";

beforeAll(() => {
  if (existsSync(path.join(REPO_ROOT, "shared", "proof_registry.py"))) {
    return; // post-merge state: the in-tree registry is the authority.
  }
  let content: string;
  try {
    content = execFileSync(
      "git",
      [
        "-C",
        REPO_ROOT,
        "show",
        `${PINNED_ACCEPTED_REGISTRY_COMMIT}:shared/proof_registry.py`,
      ],
      { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 },
    );
  } catch (error) {
    throw new Error(
      "shared/proof_registry.py is not in the worktree and the pinned " +
        `accepted registry commit ${PINNED_ACCEPTED_REGISTRY_COMMIT} is not ` +
        "available in this repository — cannot run cross-language " +
        `validation (${String(error)})`,
    );
  }
  materializedRoot = mkdtempSync(path.join(tmpdir(), "x402-proof-registry-"));
  mkdirSync(path.join(materializedRoot, "shared"));
  // Empty package init: proof_registry.py itself imports only the stdlib.
  writeFileSync(path.join(materializedRoot, "shared", "__init__.py"), "");
  writeFileSync(path.join(materializedRoot, "shared", "proof_registry.py"), content);
  registryRoot = materializedRoot;
  registrySource = `git object store, pinned accepted registry commit ${PINNED_ACCEPTED_REGISTRY_COMMIT.slice(0, 12)}`;
});

afterAll(() => {
  if (materializedRoot !== null) {
    rmSync(materializedRoot, { recursive: true, force: true });
  }
});

function pythonVerdict(item: unknown): PythonVerdict {
  const stdout = execFileSync("python3", ["-c", PYTHON_PROGRAM, registryRoot], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    input: JSON.stringify(item),
    maxBuffer: 4 * 1024 * 1024,
  });
  return JSON.parse(stdout) as PythonVerdict;
}

/** One real builder output, JSON round-tripped exactly as a consumer sees it. */
function realEmittedItem(): SettlementRegistryItem {
  return JSON.parse(
    JSON.stringify(buildSettlementRegistryItem(validInput())),
  ) as SettlementRegistryItem;
}

function builderCode(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    if (error instanceof SettlementItemError) return error.message;
    throw error;
  }
  throw new Error("expected a SettlementItemError");
}

describe("cross-language acceptance: one real builder output", () => {
  it("Python normalize_proof_item accepts it verbatim (zero errors, stays verified, green)", () => {
    const verdict = pythonVerdict(realEmittedItem());
    expect(verdict.errors).toEqual([]);
    expect(verdict.verification_status).toBe("verified");
    expect(verdict.green).toBe(true);
  });

  it("dashboard registryItemErrors is empty and itemGreenVerified accepts it", () => {
    const item = realEmittedItem();
    expect(registryItemErrors(item)).toEqual([]);
    expect(itemGreenVerified(item)).toBe(true);
  });

  it("emits exactly the 29 public fields in registry order, 22 checks, and the exact schema/network literals", () => {
    const item = realEmittedItem();
    expect(Object.keys(item)).toEqual([...PUBLIC_ITEM_REQUIRED_FIELDS]);
    expect(Object.keys(item)).toHaveLength(29);
    expect(item.checks).toHaveLength(22);
    expect(item.network).toBe("casper:casper-test");
    expect(item.schema_version).toBe("concordia.official_x402_settlement.v1");
    expect(item.claim_scope.length).toBeGreaterThan(0);
    expect(item.enforcement_scope.length).toBeGreaterThan(0);
    expect(Array.isArray(item.links)).toBe(true);
    for (const link of item.links) {
      expect(Object.keys(link).sort()).toEqual(["href", "kind", "label", "rel"]);
      expect(["artifact", "chain", "source", "ui", "download"]).toContain(link.kind);
    }
  });

  it("emitted checks carry ONLY {name, required, passed, source, observed_at, detail_code?} — evidence is stripped", () => {
    const allowed = new Set(["name", "required", "passed", "source", "observed_at", "detail_code"]);
    const item = realEmittedItem();
    for (const check of item.checks) {
      const keys = Object.keys(check);
      expect(keys).not.toContain("evidence");
      for (const key of keys) expect(allowed.has(key)).toBe(true);
      expect(check.required).toBe(true);
      expect(check.passed).toBe(true);
    }
    // The caller-side receipts DID carry evidence — proving the strip happened
    // on emission, not by weakening the input contract.
    expect(validChecks()[0]).toHaveProperty("evidence");
  });

  it("carries an optional detail_code through when the receipt supplies one", () => {
    const checks = validChecks().map((check, index) =>
      index === 0 ? { ...check, detail_code: "expected_ok" } : check,
    );
    const item = JSON.parse(
      JSON.stringify(buildSettlementRegistryItem(validInput({ checks }))),
    ) as SettlementRegistryItem;
    expect(item.checks[0]?.detail_code).toBe("expected_ok");
    const verdict = pythonVerdict(item);
    expect(verdict.errors).toEqual([]);
    expect(verdict.verification_status).toBe("verified");
    expect(registryItemErrors(item)).toEqual([]);
    expect(itemGreenVerified(item)).toBe(true);
  });
});

describe("schema-drift pins: builder constants equal the consumers' constants", () => {
  it("the 22 required check names match Python REQUIRED_CHECKS_BY_PROOF_TYPE exactly (name and order)", () => {
    const verdict = pythonVerdict(realEmittedItem());
    expect(OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS).toHaveLength(22);
    expect([...OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS]).toEqual(verdict.required_checks);
  });

  it("the 29 public field names match Python PUBLIC_ITEM_REQUIRED_FIELDS exactly (name and order)", () => {
    const verdict = pythonVerdict(realEmittedItem());
    expect(PUBLIC_ITEM_REQUIRED_FIELDS).toHaveLength(29);
    expect([...PUBLIC_ITEM_REQUIRED_FIELDS]).toEqual(verdict.public_fields);
  });

  it("the 22 required check names match the dashboard's list exactly", () => {
    expect([...OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS]).toEqual(
      DASHBOARD_REQUIRED_CHECKS_BY_PROOF_TYPE.official_x402_settlement_v1,
    );
  });

  it("the 29 public field names match the dashboard's list exactly", () => {
    expect([...PUBLIC_ITEM_REQUIRED_FIELDS]).toEqual(
      DASHBOARD_PUBLIC_ITEM_REQUIRED_FIELDS,
    );
  });

  it("uses the post-freeze snake-case facilitator names, never the frozen camel-case literal", () => {
    expect(OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS).toContain(
      "facilitator_verify_returned_is_valid_true",
    );
    expect(OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS).toContain(
      "facilitator_settlement_response_success_true",
    );
    expect(OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS.join(",")).not.toMatch(/isValid/);
  });
});

describe("schema-drift mutations: builder, Python, and dashboard reject identically", () => {
  it("a renamed check (obsolete WP5 name) fails the builder, Python, and the dashboard", () => {
    // Builder input side: the obsolete 15-check-era name is not in the set.
    const checks = validChecks();
    checks[0] = { ...checks[0]!, name: "requirements_hash_matches_registry" };
    expect(builderCode(() => buildSettlementRegistryItem(validInput({ checks })))).toBe(
      "unexpected_check",
    );
    // Emitted side: rename one check after the fact.
    const item = realEmittedItem();
    item.checks[0]!.name = "requirements_hash_matches_registry";
    const verdict = pythonVerdict(item);
    expect(verdict.errors).toContain(
      "required_check_missing:exact_envelope_v3_verified_for_registry_record_returned_by_signed_payload_hash",
    );
    expect(verdict.verification_status).toBe("invalid");
    expect(verdict.green).toBe(false);
    expect(registryItemErrors(item)).toContain(
      "required_check_missing:exact_envelope_v3_verified_for_registry_record_returned_by_signed_payload_hash",
    );
    expect(itemGreenVerified(item)).toBe(false);
  });

  it("a camel-case check name violates the shared grammar in all three implementations", () => {
    const checks = validChecks();
    checks[12] = { ...checks[12]!, name: "facilitator_verify_returned_isValid_true" };
    expect(builderCode(() => buildSettlementRegistryItem(validInput({ checks })))).toBe(
      "invalid_check_name",
    );
    const item = realEmittedItem();
    item.checks[12]!.name = "facilitator_verify_returned_isValid_true";
    const verdict = pythonVerdict(item);
    expect(verdict.errors).toContain("check_name_invalid");
    expect(verdict.verification_status).toBe("invalid");
    expect(registryItemErrors(item)).toContain("check_name_invalid");
    expect(itemGreenVerified(item)).toBe(false);
  });

  it("a dropped mandatory field (claim_scope / enforcement_scope / links) is rejected everywhere", () => {
    // Builder input side.
    expect(
      builderCode(() =>
        buildSettlementRegistryItem(validInput({ claimScope: "" })),
      ),
    ).toBe("invalid_claim_scope");
    expect(
      builderCode(() =>
        buildSettlementRegistryItem(
          validInput({ enforcementScope: undefined as unknown as string }),
        ),
      ),
    ).toBe("invalid_enforcement_scope");
    expect(
      builderCode(() =>
        buildSettlementRegistryItem(
          validInput({ links: undefined as unknown as [] }),
        ),
      ),
    ).toBe("invalid_links");
    // Emitted side: delete each mandatory field.
    for (const field of ["claim_scope", "enforcement_scope", "links"] as const) {
      const item = realEmittedItem() as unknown as Record<string, unknown>;
      delete item[field];
      const verdict = pythonVerdict(item);
      expect(verdict.errors).toContain(`field_missing:${field}`);
      expect(verdict.verification_status).toBe("invalid");
      expect(registryItemErrors(item)).toContain(`field_missing:${field}`);
      expect(itemGreenVerified(item)).toBe(false);
    }
  });

  it("an evidence field on an EMITTED check is forbidden by Python and the dashboard, and the builder cannot produce it", () => {
    const item = realEmittedItem();
    (item.checks[3] as unknown as Record<string, unknown>)["evidence"] =
      "smuggled evidence payload";
    const verdict = pythonVerdict(item);
    expect(verdict.errors).toContain("check_unknown_fields");
    expect(verdict.verification_status).toBe("invalid");
    expect(registryItemErrors(item)).toContain("check_unknown_fields");
    expect(itemGreenVerified(item)).toBe(false);
    // Builder side: an unknown receipt field never reaches emission either.
    const checks = validChecks();
    checks[3] = {
      ...checks[3]!,
      observation_url: "https://node.example/status",
    } as unknown as (typeof checks)[number];
    expect(builderCode(() => buildSettlementRegistryItem(validInput({ checks })))).toBe(
      "unexpected_check_field",
    );
  });

  it("a wrong network fails the builder (exact casper:casper-test); value equality is builder/internal-record scope, not the public validators'", () => {
    expect(
      builderCode(() =>
        buildSettlementRegistryItem(validInput({ network: "casper:mainnet" })),
      ),
    ).toBe("invalid_network");
    expect(OFFICIAL_X402_SETTLEMENT_NETWORK).toBe("casper:casper-test");
    // The PUBLIC validators require network non-null for a verified x402 item
    // but do not pin its value (that lives in the internal-record validator
    // and here in the builder). Prove the null-rejection agreement instead.
    const item = realEmittedItem() as unknown as Record<string, unknown>;
    item["network"] = null;
    const verdict = pythonVerdict(item);
    expect(verdict.errors).toContain("execution_identity_missing:network");
    expect(verdict.verification_status).toBe("invalid");
    expect(registryItemErrors(item)).toContain("execution_identity_missing:network");
    expect(itemGreenVerified(item)).toBe(false);
  });

  it("a short (non-SHA-40) commit fails the builder, Python, and the dashboard", () => {
    expect(
      builderCode(() =>
        buildSettlementRegistryItem(validInput({ sourceCommit: "abcdef1" })),
      ),
    ).toBe("invalid_source_commit");
    expect(
      builderCode(() =>
        buildSettlementRegistryItem(validInput({ deploymentCommit: "77".repeat(32) })),
      ),
    ).toBe("invalid_deployment_commit");
    const item = realEmittedItem() as unknown as Record<string, unknown>;
    item["source_commit"] = "abcdef1";
    const verdict = pythonVerdict(item);
    expect(verdict.errors).toContain("source_commit_invalid");
    expect(verdict.verification_status).toBe("invalid");
    expect(registryItemErrors(item)).toContain("source_commit_invalid");
    expect(itemGreenVerified(item)).toBe(false);
  });

  it("a duplicated check name invalidates the item everywhere", () => {
    const checks = [...validChecks(), validChecks()[0]!];
    expect(builderCode(() => buildSettlementRegistryItem(validInput({ checks })))).toBe(
      "duplicate_check_observation",
    );
    const item = realEmittedItem();
    item.checks.push({ ...item.checks[0]! });
    const verdict = pythonVerdict(item);
    expect(verdict.errors).toContain("duplicate_check_name");
    expect(verdict.verification_status).toBe("invalid");
    expect(registryItemErrors(item)).toContain("duplicate_check_name");
    expect(itemGreenVerified(item)).toBe(false);
  });

  it("a failed required check refuses to build, and a tampered passed:false is never verified/green downstream", () => {
    const checks = validChecks();
    checks[15] = { ...checks[15]!, passed: false };
    expect(builderCode(() => buildSettlementRegistryItem(validInput({ checks })))).toBe(
      "check_not_passed",
    );
    const item = realEmittedItem();
    (item.checks[15] as unknown as Record<string, unknown>)["passed"] = false;
    const verdict = pythonVerdict(item);
    // Shape-wise legal, but normalize_proof_item demotes verified -> invalid.
    expect(verdict.verification_status).toBe("invalid");
    expect(verdict.green).toBe(false);
    expect(itemGreenVerified(item)).toBe(false);
  });

  it("a check observed after captured_at is rejected everywhere", () => {
    const checks = validChecks("2026-07-22T20:10:00Z");
    expect(
      builderCode(() =>
        buildSettlementRegistryItem(
          validInput({ checks, capturedAt: "2026-07-22T20:05:00Z" }),
        ),
      ),
    ).toBe("check_observed_after_capture");
    const item = realEmittedItem();
    item.checks[0]!.observed_at = "2026-07-22T20:10:00Z";
    const verdict = pythonVerdict(item);
    expect(verdict.errors).toContain("check_observed_after_capture");
    expect(verdict.verification_status).toBe("invalid");
    expect(registryItemErrors(item)).toContain("check_observed_after_capture");
    expect(itemGreenVerified(item)).toBe(false);
  });

  it("dropping one required check observation refuses to build, and its absence invalidates the item everywhere", () => {
    const dropped = OFFICIAL_X402_SETTLEMENT_REQUIRED_CHECKS[21]!;
    const checks = validChecks().filter((check) => check.name !== dropped);
    expect(builderCode(() => buildSettlementRegistryItem(validInput({ checks })))).toBe(
      "missing_check_observation",
    );
    const item = realEmittedItem();
    item.checks = item.checks.filter((check) => check.name !== dropped);
    const verdict = pythonVerdict(item);
    expect(verdict.errors).toContain(`required_check_missing:${dropped}`);
    expect(verdict.verification_status).toBe("invalid");
    expect(registryItemErrors(item)).toContain(`required_check_missing:${dropped}`);
    expect(itemGreenVerified(item)).toBe(false);
  });

  it(`registry module source is honest about where it came from`, () => {
    // Documented in the suite output: the in-tree registry wins when present;
    // otherwise the newest registry commit in the object store is used.
    expect(registrySource.length).toBeGreaterThan(0);
    expect(
      registrySource.startsWith("worktree ") || registrySource.startsWith("git object store"),
    ).toBe(true);
  });
});

describe("validator boundary agreement: Python and the dashboard draw the SAME lines", () => {
  // Reviewer finding: the dashboard's check-name limit (128) and timestamp
  // parsing (Date.parse rollover) were WEAKER than Python's (96 chars,
  // fromisoformat). These pins prove both validators now agree at the exact
  // boundary — a name/timestamp accepted or rejected by one is treated
  // identically by the other.
  const NAME_96 = `a${"x".repeat(95)}`; // exactly 96 chars — the maximum
  const NAME_97 = `a${"x".repeat(96)}`; // one over — must be rejected

  it("a 96-character check name is within the shared grammar for BOTH validators", () => {
    const item = realEmittedItem();
    item.checks[0]!.name = NAME_96;
    // Renaming a required check makes the item incomplete on both sides —
    // but the NAME ITSELF must be grammatical on both (no check_name_invalid).
    const verdict = pythonVerdict(item);
    expect(verdict.errors).not.toContain("check_name_invalid");
    expect(verdict.errors).toContain(
      "required_check_missing:exact_envelope_v3_verified_for_registry_record_returned_by_signed_payload_hash",
    );
    const dashboardErrors = registryItemErrors(item);
    expect(dashboardErrors).not.toContain("check_name_invalid");
    expect(dashboardErrors).toContain(
      "required_check_missing:exact_envelope_v3_verified_for_registry_record_returned_by_signed_payload_hash",
    );
  });

  it("a 97-character check name is rejected by BOTH validators (Python caps at 96)", () => {
    const item = realEmittedItem();
    item.checks[0]!.name = NAME_97;
    const verdict = pythonVerdict(item);
    expect(verdict.errors).toContain("check_name_invalid");
    expect(verdict.verification_status).toBe("invalid");
    expect(verdict.green).toBe(false);
    expect(registryItemErrors(item)).toContain("check_name_invalid");
    expect(itemGreenVerified(item)).toBe(false);
  });

  it("an impossible calendar date (February 30) is rejected by BOTH validators", () => {
    // Date.parse silently rolls 2026-02-30 over to March 2; Python's
    // fromisoformat raises. Both must refuse it as a timestamp.
    const item = realEmittedItem();
    item.checks[0]!.observed_at = "2026-02-30T12:00:00Z";
    const verdict = pythonVerdict(item);
    expect(verdict.errors).toContain("check_observed_at_invalid");
    expect(verdict.verification_status).toBe("invalid");
    expect(verdict.green).toBe(false);
    expect(registryItemErrors(item)).toContain("check_observed_at_invalid");
    expect(itemGreenVerified(item)).toBe(false);
  });

  it("an impossible captured_at (February 30) is rejected by BOTH validators", () => {
    const item = realEmittedItem();
    (item as { captured_at: string }).captured_at = "2026-02-30T12:00:00Z";
    const verdict = pythonVerdict(item);
    expect(verdict.errors).toContain("captured_at_invalid");
    expect(verdict.green).toBe(false);
    expect(registryItemErrors(item)).toContain("captured_at_invalid");
    expect(itemGreenVerified(item)).toBe(false);
  });

  it("a real leap-day timestamp (2024-02-29) is accepted by BOTH validators", () => {
    // Positive control for the round-trip guard: a valid but calendar-tricky
    // date must NOT be over-rejected by either side.
    const item = realEmittedItem();
    item.checks[0]!.observed_at = "2024-02-29T00:00:00Z";
    const verdict = pythonVerdict(item);
    expect(verdict.errors).toEqual([]);
    expect(verdict.verification_status).toBe("verified");
    expect(verdict.green).toBe(true);
    expect(registryItemErrors(item)).toEqual([]);
    expect(itemGreenVerified(item)).toBe(true);
  });

  it("year 0000 is rejected by BOTH validators (Python's calendar starts at 0001)", () => {
    // Date.parse happily represents year 0; datetime.fromisoformat raises
    // `year 0 is out of range`. Both sides must refuse it.
    const item = realEmittedItem();
    (item as { captured_at: string }).captured_at = "0000-01-01T00:00:00Z";
    const verdict = pythonVerdict(item);
    expect(verdict.errors).toContain("captured_at_invalid");
    expect(verdict.green).toBe(false);
    expect(registryItemErrors(item)).toContain("captured_at_invalid");
    expect(itemGreenVerified(item)).toBe(false);
  });

  it("Python-valid low years (0001 and 0099) are accepted by BOTH validators", () => {
    // Positive controls bracketing the year-0000 rejection: these are real
    // fromisoformat-valid instants and chronology (observed <= captured)
    // still holds, so neither validator may over-reject them.
    for (const ancient of ["0001-01-01T00:00:00Z", "0099-12-31T23:59:59Z"]) {
      const item = realEmittedItem();
      item.checks[0]!.observed_at = ancient;
      const verdict = pythonVerdict(item);
      expect(verdict.errors).toEqual([]);
      expect(verdict.green).toBe(true);
      expect(registryItemErrors(item)).toEqual([]);
      expect(itemGreenVerified(item)).toBe(true);
    }
  });

  it("microsecond chronology is compared exactly by BOTH validators (no millisecond collapse)", () => {
    // Python compares full-microsecond datetimes; collapsing the fraction to
    // Date's milliseconds would make .000999Z equal to .000001Z and silently
    // drop the observed-after-capture violation on the dashboard side.
    const item = realEmittedItem();
    (item as { captured_at: string }).captured_at = "2026-07-22T20:05:00.000001Z";
    item.checks[0]!.observed_at = "2026-07-22T20:05:00.000999Z";
    const verdict = pythonVerdict(item);
    expect(verdict.errors).toContain("check_observed_after_capture");
    expect(verdict.green).toBe(false);
    expect(registryItemErrors(item)).toContain("check_observed_after_capture");
    expect(itemGreenVerified(item)).toBe(false);

    // Inverse positive control: observed one microsecond BEFORE capture is
    // fine on both sides — the exact comparison must not over-reject either.
    const ordered = realEmittedItem();
    (ordered as { captured_at: string }).captured_at = "2026-07-22T20:05:00.000999Z";
    ordered.checks[0]!.observed_at = "2026-07-22T20:05:00.000001Z";
    const orderedVerdict = pythonVerdict(ordered);
    expect(orderedVerdict.errors).toEqual([]);
    expect(orderedVerdict.green).toBe(true);
    expect(registryItemErrors(ordered)).toEqual([]);
    expect(itemGreenVerified(ordered)).toBe(true);
  });

  it("prototype-key proof types fail closed as invalid on BOTH validators (never a crash)", () => {
    // `proofType in REQUIRED_CHECKS_BY_PROOF_TYPE` reaches the prototype
    // chain: "toString"/"__proto__" would resolve to Object.prototype members
    // and crash the check walker. Python dict membership never had this
    // hazard; the dashboard must degrade identically to proof_type_invalid.
    for (const hostile of ["toString", "__proto__", "hasOwnProperty", "constructor"]) {
      const item = realEmittedItem();
      (item as { proof_type: string }).proof_type = hostile;
      const verdict = pythonVerdict(item);
      expect(verdict.errors).toContain("proof_type_invalid");
      expect(verdict.green).toBe(false);
      const dashboardErrors = registryItemErrors(item); // must not throw
      expect(dashboardErrors).toContain("proof_type_invalid");
      expect(itemGreenVerified(item)).toBe(false);
    }
  });

  // Sol's rejection of 7137674: microsecond ordinals were `number`s, so past
  // Number.MAX_SAFE_INTEGER (9007199254740991 µs — about 285 years either
  // side of 1970) two adjacent microseconds landed on ONE double. These pins
  // drive the collapse through the REAL item validators, not just the
  // parsers: at each boundary year an observation one microsecond AFTER
  // capture must be caught, and one microsecond BEFORE must stay green.
  const BOUNDARY_YEARS: readonly (readonly [string, string, string])[] = [
    ["far future (year 9999)", "9999-12-31T23:59:59.000001Z", "9999-12-31T23:59:59.000002Z"],
    ["just past the safe-integer boundary (2256)", "2256-01-01T00:00:00.000001Z", "2256-01-01T00:00:00.000002Z"],
    ["at the safe-integer boundary (2255)", "2255-06-05T23:47:34.000001Z", "2255-06-05T23:47:34.000002Z"],
    ["ancient (year 0001, negative ordinal)", "0001-01-01T00:00:00.000001Z", "0001-01-01T00:00:00.000002Z"],
  ];

  for (const [label, earlier, later] of BOUNDARY_YEARS) {
    it(`adjacent-microsecond chronology is enforced by BOTH validators — ${label}`, () => {
      // Every check moves to the boundary year, so the ONLY difference
      // between the two items below is a single microsecond on checks[0].
      // (Leaving the other checks at their fixture dates would make an
      // ancient captured_at fail for an unrelated reason.)
      const violating = realEmittedItem();
      (violating as { captured_at: string }).captured_at = earlier;
      for (const check of violating.checks) check.observed_at = earlier;
      violating.checks[0]!.observed_at = later; // one microsecond AFTER capture
      const verdict = pythonVerdict(violating);
      expect(verdict.errors).toContain("check_observed_after_capture");
      expect(verdict.green).toBe(false);
      expect(registryItemErrors(violating)).toContain("check_observed_after_capture");
      expect(itemGreenVerified(violating)).toBe(false);

      // Inverse control: one microsecond BEFORE capture stays green on both,
      // so the exact comparison cannot be passing by over-rejecting.
      const ordered = realEmittedItem();
      (ordered as { captured_at: string }).captured_at = later;
      for (const check of ordered.checks) check.observed_at = earlier;
      const orderedVerdict = pythonVerdict(ordered);
      expect(orderedVerdict.errors).toEqual([]);
      expect(orderedVerdict.green).toBe(true);
      expect(registryItemErrors(ordered)).toEqual([]);
      expect(itemGreenVerified(ordered)).toBe(true);
    });
  }

  it("validator output stays JSON-serializable (no BigInt ordinal escapes)", () => {
    // The dashboard ordinal is a BigInt; JSON.stringify throws on one. These
    // validators run inside a React render path, so a leaked ordinal would
    // break serialization at runtime rather than in a type check.
    const item = realEmittedItem();
    (item as { captured_at: string }).captured_at = "9999-12-31T23:59:59.000001Z";
    item.checks[0]!.observed_at = "9999-12-31T23:59:59.000002Z";
    expect(() => JSON.stringify(registryItemErrors(item))).not.toThrow();
    expect(() => JSON.stringify(itemGreenVerified(item))).not.toThrow();
    expect(() => JSON.stringify(registryItemErrors(realEmittedItem()))).not.toThrow();
  });
});
