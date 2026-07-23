/**
 * Shared RFC3339 UTC boundary vectors (WP5/WP7 timestamp contract).
 *
 * ONE table drives every timestamp-parity assertion in this repository:
 *
 *  - the official-x402 parser  (services/x402-official/src/time.ts)
 *  - the dashboard parser      (dashboard/app/_components/provenance-pure.js)
 *  - Python                    (datetime.fromisoformat — the authority)
 *
 * Why exact microseconds, and why a STRING:
 *
 * Python compares full-microsecond datetimes. A JavaScript `number` cannot
 * hold microseconds-since-epoch exactly past `Number.MAX_SAFE_INTEGER`
 * (9007199254740991 µs — reached inside year 2255). Two distinct failures
 * follow, and the vectors below distinguish them:
 *
 *   - Just past 2^53 the ordinal becomes INEXACT: 9025257600000001 silently
 *     stores as 9025257600000000. Adjacent values may still differ, but the
 *     instant itself is already wrong.
 *   - Further out the double spacing exceeds one microsecond and adjacent
 *     instants COLLAPSE outright: at year 9999 (spacing 32 µs) and at year
 *     0001 (spacing 8 µs, magnitude ~6.2e16) two neighbours become one
 *     value, so a chronology violation Python reports cannot be seen.
 *
 * Note the second case is symmetric about 1970 — ancient timestamps are as
 * broken as far-future ones. The exact ordinal is therefore a BigInt
 * everywhere it is compared.
 *
 * The table stores each ordinal as a DECIMAL STRING, never a BigInt literal:
 * a BigInt cannot be JSON-serialized (`JSON.stringify(1n)` throws), and these
 * vectors are piped verbatim to Python over stdin. Callers convert at the
 * boundary with `BigInt(vector.micros)`.
 *
 * Every `micros` value below was computed by Python, not by hand:
 *   (datetime.fromisoformat(v) - EPOCH) // timedelta(microseconds=1)
 * and each is re-verified against a live `python3` at test time, so a drift in
 * either direction fails the suite rather than rotting into a stale pin.
 */

export interface Rfc3339Vector {
  /** The RFC3339 UTC-Z literal under test. */
  readonly value: string;
  /** Exact microseconds since the Unix epoch, as a decimal string. */
  readonly micros: string;
  /** Why this vector exists — keeps the boundary intent reviewable. */
  readonly note: string;
}

export interface Rfc3339Rejection {
  readonly value: string;
  readonly note: string;
}

/**
 * Instants Python accepts. Both JavaScript parsers must accept each one AND
 * report the identical exact microsecond ordinal.
 */
export const ACCEPTED_VECTORS: readonly Rfc3339Vector[] = [
  {
    value: "0001-01-01T00:00:00Z",
    micros: "-62135596800000000",
    note: "earliest year Python represents; Date.UTC(1,…) would remap it to 1901",
  },
  {
    value: "0001-01-01T00:00:00.000001Z",
    micros: "-62135596799999999",
    note: "adjacent microsecond at the minimum year; |value| ~6.2e16 puts double spacing at 8 µs, so as Numbers this and the next vector BOTH became -62135596800000000 — a real collapse, verified",
  },
  {
    value: "0001-01-01T00:00:00.000002Z",
    micros: "-62135596799999998",
    note: "its neighbour — collapsed onto the previous vector before the fix; proves the defect is not far-future-only",
  },
  {
    value: "0099-12-31T23:59:59.999999Z",
    micros: "-59011459200000001",
    note: "last instant of the two-digit-year window Date.UTC remaps",
  },
  {
    value: "0100-01-01T00:00:00Z",
    micros: "-59011459200000000",
    note: "first instant past the remap window — exactly 1 µs after the previous",
  },
  {
    value: "1969-12-31T23:59:59.999999Z",
    micros: "-1",
    note: "one microsecond before the epoch (negative ordinal boundary)",
  },
  {
    value: "1970-01-01T00:00:00Z",
    micros: "0",
    note: "the epoch itself",
  },
  {
    value: "2026-07-22T20:05:00.000001Z",
    micros: "1784750700000001",
    note: "present-era adjacency (safe-integer range — must still be exact)",
  },
  {
    value: "2026-07-22T20:05:00.000002Z",
    micros: "1784750700000002",
    note: "its neighbour in the present era",
  },
  {
    value: "2255-06-05T23:47:34.000001Z",
    micros: "9007199254000001",
    note: "just BELOW Number.MAX_SAFE_INTEGER (9007199254740991) — still exact as a double, so this pair is a control, not a collapse",
  },
  {
    value: "2255-06-05T23:47:34.000002Z",
    micros: "9007199254000002",
    note: "its neighbour, also still exact — the last year where a Number ordinal is trustworthy",
  },
  {
    value: "2256-01-01T00:00:00.000001Z",
    micros: "9025257600000001",
    note: "just PAST 2^53: no longer exactly representable — as a Number it silently becomes 9025257600000000, a WRONG instant (adjacent values here happen to stay distinct; the value itself is already corrupt)",
  },
  {
    value: "2256-01-01T00:00:00.000002Z",
    micros: "9025257600000002",
    note: "its neighbour, still exactly representable — which is why only the first of this pair is corrupted",
  },
  {
    value: "9999-12-31T23:59:59.000001Z",
    micros: "253402300799000001",
    note: "far-future adjacency: both collapsed to 253402300799000000 as Numbers",
  },
  {
    value: "9999-12-31T23:59:59.000002Z",
    micros: "253402300799000002",
    note: "its neighbour — the exact case named in the rejection of 7137674",
  },
  {
    value: "9999-12-31T23:59:59.999999Z",
    micros: "253402300799999999",
    note: "the maximum instant a four-digit RFC3339 year can express",
  },
  {
    value: "2024-02-29T00:00:00Z",
    micros: "1709164800000000",
    note: "real leap day — positive control, must not be over-rejected",
  },
  {
    value: "2000-02-29T00:00:00Z",
    micros: "951782400000000",
    note: "century leap day (divisible by 400) — proleptic Gregorian agreement",
  },
];

/**
 * Values Python REJECTS. Both JavaScript parsers must reject each one too —
 * an over-accepting parser lets an impossible instant into an evidence chain.
 */
export const REJECTED_VECTORS: readonly Rfc3339Rejection[] = [
  { value: "1900-02-29T00:00:00Z", note: "1900 is NOT a leap year (divisible by 100, not 400)" },
  { value: "2023-02-29T00:00:00Z", note: "non-leap February 29" },
  { value: "2026-02-30T12:00:00Z", note: "February 30 never exists; Date silently rolls it to March" },
  { value: "2026-04-31T00:00:00Z", note: "April has 30 days; Date rolls it to May 1" },
  { value: "2026-13-01T00:00:00Z", note: "month 13" },
  { value: "2026-00-10T00:00:00Z", note: "month 0" },
  { value: "2026-01-00T00:00:00Z", note: "day 0" },
  { value: "0000-01-01T00:00:00Z", note: "year 0 — Python's proleptic calendar starts at 0001" },
  { value: "2026-01-01T24:00:00Z", note: "hour 24" },
  {
    value: "2026-01-01T00:00:60Z",
    note: "leap second 60 — Python raises 'second must be in 0..59'; a parser that clamps it to :59 invents an instant that never existed",
  },
];

/** Adjacent-microsecond pairs that MUST remain strictly ordered, by year. */
export const ADJACENT_PAIRS: readonly (readonly [string, string])[] = [
  ["0001-01-01T00:00:00.000001Z", "0001-01-01T00:00:00.000002Z"],
  ["2026-07-22T20:05:00.000001Z", "2026-07-22T20:05:00.000002Z"],
  ["2255-06-05T23:47:34.000001Z", "2255-06-05T23:47:34.000002Z"],
  ["2256-01-01T00:00:00.000001Z", "2256-01-01T00:00:00.000002Z"],
  ["9999-12-31T23:59:59.000001Z", "9999-12-31T23:59:59.000002Z"],
  ["0099-12-31T23:59:59.999999Z", "0100-01-01T00:00:00Z"],
];
