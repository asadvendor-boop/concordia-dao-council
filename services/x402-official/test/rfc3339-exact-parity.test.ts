/**
 * Exact RFC3339 UTC chronology: three-way parity (x402 ⇄ dashboard ⇄ Python).
 *
 * Sol's audit rejected 7137674 because BOTH JavaScript parsers lost exact
 * microsecond ordering:
 *
 *  1. dashboard/app/_components/provenance-pure.js returned microseconds as a
 *     `number`. Past Number.MAX_SAFE_INTEGER (9007199254740991 µs — reached
 *     inside year 2255) adjacent microseconds collapse onto one double:
 *     9999-12-31T23:59:59.000001Z and .000002Z both became
 *     253402300799000000, so `observed_at > captured_at` could not see a
 *     violation Python reports.
 *
 *  2. services/x402-official/src/time.ts was millisecond-based
 *     (`Math.round(Number(frac) * 1000)` maps .000001 AND .000002 to 0) and
 *     built its instant with `Date.UTC(year, …)`, which remaps years 0–99 to
 *     1900+year — so Python-valid years 0001–0099 were rejected outright.
 *
 * This suite pins the repaired contract against the ONE authority that
 * matters — a live `python3` — over the shared boundary table in
 * ./rfc3339-vectors.ts. Every ordinal is compared as a BigInt, and the
 * decimal strings that cross the process boundary keep the fixtures
 * JSON-serializable (a BigInt cannot be stringified).
 */

import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";

import { parseRfc3339Utc, rfc3339UtcOrdinal } from "../src/time.js";
import {
  ACCEPTED_VECTORS,
  ADJACENT_PAIRS,
  REJECTED_VECTORS,
} from "./rfc3339-vectors.js";
// The dashboard's pure validator, imported AS-IS (another lane owns it; it is
// read, never modified) — the same module the browser executes.
// eslint-disable-next-line import/no-relative-packages
import { parseRfc3339Utc as dashboardParse } from "../../../dashboard/app/_components/provenance-pure.js";

/**
 * Ask Python for the exact microsecond ordinal of every value. Returns null
 * for anything `datetime.fromisoformat` refuses. Python is the authority: the
 * JavaScript parsers are asserted against THIS, never against each other
 * alone (two implementations can agree on the same wrong answer).
 */
const PYTHON_PROGRAM = `
import json, sys
from datetime import datetime, timedelta, timezone

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
out = {}
for value in json.load(sys.stdin):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        out[value] = None
        continue
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        out[value] = None
        continue
    out[value] = str((parsed - EPOCH) // timedelta(microseconds=1))
json.dump(out, sys.stdout)
`;

function pythonOrdinals(values: readonly string[]): Record<string, string | null> {
  const stdout = execFileSync("python3", ["-c", PYTHON_PROGRAM], {
    input: JSON.stringify(values),
    encoding: "utf8",
  });
  return JSON.parse(stdout) as Record<string, string | null>;
}

const ALL_VALUES = [
  ...ACCEPTED_VECTORS.map((v) => v.value),
  ...REJECTED_VECTORS.map((v) => v.value),
];
const PYTHON = pythonOrdinals(ALL_VALUES);

describe("RFC3339 exact chronology — the pinned table matches live Python", () => {
  it("every accepted vector's pinned ordinal is what Python actually computes", () => {
    for (const vector of ACCEPTED_VECTORS) {
      expect(
        PYTHON[vector.value],
        `pinned ordinal drifted from Python for ${vector.value} (${vector.note})`,
      ).toBe(vector.micros);
    }
  });

  it("every rejected vector is genuinely refused by Python", () => {
    for (const rejection of REJECTED_VECTORS) {
      expect(
        PYTHON[rejection.value],
        `expected Python to reject ${rejection.value} (${rejection.note})`,
      ).toBeNull();
    }
  });
});

describe("official-x402 parser (src/time.ts) is exact to the microsecond", () => {
  it("returns Python's exact BigInt ordinal for every accepted vector", () => {
    for (const vector of ACCEPTED_VECTORS) {
      expect(
        rfc3339UtcOrdinal(vector.value),
        `x402 ordinal mismatch for ${vector.value} (${vector.note})`,
      ).toBe(BigInt(vector.micros));
    }
  });

  it("refuses every value Python refuses", () => {
    for (const rejection of REJECTED_VECTORS) {
      expect(
        rfc3339UtcOrdinal(rejection.value),
        `x402 accepted ${rejection.value}, which Python refuses (${rejection.note})`,
      ).toBeNull();
      expect(parseRfc3339Utc(rejection.value)).toBeNull();
    }
  });

  it("keeps adjacent microseconds strictly ordered at every boundary year", () => {
    for (const [earlier, later] of ADJACENT_PAIRS) {
      const a = rfc3339UtcOrdinal(earlier);
      const b = rfc3339UtcOrdinal(later);
      expect(a).not.toBeNull();
      expect(b).not.toBeNull();
      expect(a).not.toBe(b);
      expect((a as bigint) < (b as bigint)).toBe(true);
    }
  });

  it("preserves its public epoch-millisecond API for the expiry path", () => {
    // pipeline.ts compares this against validBeforeEpochMs (U64 seconds ×
    // 1000), so this function must stay millisecond-valued. Milliseconds for
    // years 0001–9999 fit exactly in a double (|ms| < 2.6e14), so no
    // precision is lost at THIS granularity.
    expect(parseRfc3339Utc("1970-01-01T00:00:00Z")).toBe(0);
    expect(parseRfc3339Utc("2026-07-22T20:05:00Z")).toBe(1784750700000);
    expect(parseRfc3339Utc("0001-01-01T00:00:00Z")).toBe(-62135596800000);
    expect(typeof parseRfc3339Utc("2026-07-22T20:05:00Z")).toBe("number");
  });

  it("truncates sub-millisecond precision downward, never upward", () => {
    // Rounding .000999 UP to 1 ms would place an observation later than it
    // occurred — and this value gates expiry terminalization, so an upward
    // round could push a boundary past an expiry it never actually crossed.
    expect(parseRfc3339Utc("2026-07-22T20:05:00.000999Z")).toBe(1784750700000);
    expect(parseRfc3339Utc("2026-07-22T20:05:00.001999Z")).toBe(1784750700001);
  });
});

describe("dashboard parser (provenance-pure.js) is exact to the microsecond", () => {
  it("returns Python's exact BigInt ordinal for every accepted vector", () => {
    for (const vector of ACCEPTED_VECTORS) {
      expect(
        dashboardParse(vector.value),
        `dashboard ordinal mismatch for ${vector.value} (${vector.note})`,
      ).toBe(BigInt(vector.micros));
    }
  });

  it("refuses every value Python refuses", () => {
    for (const rejection of REJECTED_VECTORS) {
      expect(
        dashboardParse(rejection.value),
        `dashboard accepted ${rejection.value}, which Python refuses (${rejection.note})`,
      ).toBeNull();
    }
  });

  it("keeps adjacent microseconds strictly ordered at every boundary year", () => {
    for (const [earlier, later] of ADJACENT_PAIRS) {
      const a = dashboardParse(earlier) as bigint | null;
      const b = dashboardParse(later) as bigint | null;
      expect(a).not.toBeNull();
      expect(b).not.toBeNull();
      expect(a).not.toBe(b);
      expect((a as bigint) < (b as bigint)).toBe(true);
    }
  });
});

describe("the two JavaScript parsers agree with each other exactly", () => {
  it("produces identical ordinals across every accepted vector", () => {
    for (const vector of ACCEPTED_VECTORS) {
      expect(
        rfc3339UtcOrdinal(vector.value),
        `x402 and dashboard disagree on ${vector.value}`,
      ).toBe(dashboardParse(vector.value));
    }
  });

  it("agrees on every rejection", () => {
    for (const rejection of REJECTED_VECTORS) {
      expect(rfc3339UtcOrdinal(rejection.value)).toBeNull();
      expect(dashboardParse(rejection.value)).toBeNull();
    }
  });
});

describe("sub-microsecond precision is refused, never silently truncated", () => {
  // Found by differential fuzzing against Python: the x402 grammar used to
  // allow 1–9 fractional digits and truncate to six, so .1234567Z and
  // .1234568Z produced ONE ordinal — the same collapse this module exists to
  // prevent, just at a different digit. Python truncates here; we refuse,
  // because a parser must never map two distinct instants onto one value.
  const SUB_MICROSECOND = [
    "2026-07-22T20:05:00.1234567Z",
    "2026-07-22T20:05:00.12345678Z",
    "2026-07-22T20:05:00.123456789Z",
  ];

  it("both JavaScript parsers refuse more than six fractional digits", () => {
    for (const value of SUB_MICROSECOND) {
      expect(rfc3339UtcOrdinal(value), `x402 accepted ${value}`).toBeNull();
      expect(parseRfc3339Utc(value)).toBeNull();
      expect(dashboardParse(value), `dashboard accepted ${value}`).toBeNull();
    }
  });

  it("exactly six fractional digits remain accepted", () => {
    expect(rfc3339UtcOrdinal("2026-07-22T20:05:00.123456Z")).toBe(1784750700123456n);
    expect(dashboardParse("2026-07-22T20:05:00.123456Z")).toBe(1784750700123456n);
  });
});

describe("deliberate strictness: narrower than Python, always fail-closed", () => {
  // Python's fromisoformat accepts these; the repository contract is RFC3339
  // UTC-Z ONLY. Rejecting is the safe direction (an evidence timestamp is
  // refused rather than silently reinterpreted), and BOTH JavaScript parsers
  // must reject identically. Pinned so nobody "fixes" them into acceptance.
  const NARROWER_THAN_PYTHON = [
    ["2026-07-22t20:05:00Z", "lowercase 't' separator"],
    ["2026-07-22T20:05:00+00:00", "numeric zero offset instead of literal Z"],
    ["2026-07-22T20:05:00-00:00", "negative zero offset"],
    ["2026-07-22 20:05:00Z", "space separator instead of 'T'"],
    ["2026-07-22T20:05:00.Z", "empty fraction after the decimal point"],
    ["2026-07-22T20:05:00\u0000Z", "embedded NUL byte — Python accepts this one"],
  ] as const;

  for (const [value, why] of NARROWER_THAN_PYTHON) {
    it(`rejects ${why} on both parsers`, () => {
      expect(rfc3339UtcOrdinal(value)).toBeNull();
      expect(dashboardParse(value)).toBeNull();
    });
  }
});

describe("BigInt ordinals never reach a JSON boundary", () => {
  it("stringifying an ordinal directly throws — proof the guard is needed", () => {
    const ordinal = rfc3339UtcOrdinal("2026-07-22T20:05:00.000001Z");
    expect(typeof ordinal).toBe("bigint");
    expect(() => JSON.stringify({ ordinal })).toThrow(TypeError);
  });

  it("the shared vector table itself stays JSON-serializable", () => {
    // Vectors cross a process boundary to Python, so they must survive
    // JSON.stringify — which is exactly why `micros` is a decimal string.
    expect(() => JSON.stringify(ACCEPTED_VECTORS)).not.toThrow();
    expect(() => JSON.stringify(REJECTED_VECTORS)).not.toThrow();
  });
});
