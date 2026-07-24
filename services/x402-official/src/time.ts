/**
 * Strict RFC3339 UTC timestamp parsing (§13, WP5-6).
 *
 * Governance records and settlement registry items are only trusted when every
 * timestamp is an explicit UTC-Z instant — never a bare string, a local time,
 * or an arbitrary offset. Chronology is then enforced against the parsed
 * instant, so forged or out-of-order timestamps fail closed.
 *
 * Two accessors, deliberately distinct:
 *
 *  - `rfc3339UtcOrdinal` returns EXACT microseconds since the epoch as a
 *    BigInt. Every chronology comparison must use it. Python compares
 *    full-microsecond datetimes, and microseconds-since-epoch exceed
 *    `Number.MAX_SAFE_INTEGER` (9007199254740991 µs) once |instant| passes
 *    ~285 years from 1970 — so in any year before ~1684 or after ~2255 a
 *    `number` collapses adjacent microseconds onto one double and silently
 *    drops a violation Python reports.
 *
 *  - `parseRfc3339Utc` returns epoch MILLISECONDS as a number, unchanged in
 *    contract and units. It exists for the expiry path in pipeline.ts, which
 *    compares block timestamps against `validBefore` (canonical U64 epoch
 *    seconds × 1000). Milliseconds for years 0001–9999 stay under 2.6e14 and
 *    are therefore exact in a double; only the sub-millisecond remainder is
 *    dropped, and it is dropped DOWNWARD (see below).
 *
 * Both agree exactly with `datetime.fromisoformat` on what is a valid
 * instant — same proleptic Gregorian calendar, same year floor of 0001, same
 * refusal of leap second :60 and of dates `Date` would silently roll over.
 */

// YYYY-MM-DDTHH:MM:SS(.fraction)?Z — uppercase 'T' and 'Z' only, no offset.
//
// At most SIX fractional digits. Python would accept 7–9 and truncate, but
// truncating is precisely the defect this module exists to prevent: it maps
// .1234567Z and .1234568Z onto ONE ordinal, so two distinct instants compare
// equal. Refusing sub-microsecond precision is fail-closed, keeps this parser
// byte-identical in behaviour to the dashboard's (which also caps at six),
// and matches the registry grammar in settlement-item.ts.
const RFC3339_UTC_RE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,6})?Z$/;

const MICROS_PER_MILLISECOND = 1000n;

interface ExactInstant {
  /** Epoch milliseconds truncated to the second — always a multiple of 1000. */
  readonly epochMsAtSecond: number;
  /** Sub-second remainder in microseconds, 0–999999. */
  readonly micros: number;
}

/**
 * Shared exact parse. Returns null for anything `datetime.fromisoformat`
 * would refuse, so every caller inherits identical accept/reject behaviour.
 */
function parseExact(value: unknown): ExactInstant | null {
  if (typeof value !== "string") return null;
  const m = RFC3339_UTC_RE.exec(value);
  if (m === null) return null;
  const [, y, mo, d, h, mi, s, frac] = m;
  const year = Number(y);
  const month = Number(mo);
  const day = Number(d);
  const hour = Number(h);
  const minute = Number(mi);
  const second = Number(s);
  // Python's proleptic Gregorian calendar starts at 0001 ("year 0 is out of
  // range") and has no leap second ("second must be in 0..59"). Clamping :60
  // to :59 — as this parser previously did — invents an instant that never
  // existed and that Python refuses outright.
  if (year < 1) return null;
  if (month < 1 || month > 12) return null;
  if (day < 1 || day > 31) return null;
  if (hour > 23 || minute > 59 || second > 59) return null;
  // Date.UTC maps years 0–99 onto 1900+year (Date.UTC(1, 0, 1) is 1901), so
  // Python-valid years 0001–0099 were remapped and then rejected by the
  // round-trip guard below. setUTCFullYear restores the literal year.
  const instant = new Date(
    Date.UTC(year, month - 1, day, hour, minute, second, 0),
  );
  if (year < 100) instant.setUTCFullYear(year);
  const epochMsAtSecond = instant.getTime();
  if (Number.isNaN(epochMsAtSecond)) return null;
  // Reject values Date silently rolled over (February 30, April 31, a
  // non-leap February 29) — fromisoformat raises instead of normalizing.
  if (
    instant.getUTCFullYear() !== year ||
    instant.getUTCMonth() !== month - 1 ||
    instant.getUTCDate() !== day
  ) {
    return null;
  }
  // The grammar caps the fraction at six digits, so padding is exact — no
  // truncation, and therefore no two inputs can share one ordinal.
  const micros = frac === undefined ? 0 : Number(frac.slice(1).padEnd(6, "0"));
  return { epochMsAtSecond, micros };
}

/**
 * Exact microseconds since the Unix epoch, or null. This is the ONLY
 * representation safe for chronology: it is lossless at every representable
 * year, so `a > b` means exactly what Python's `a > b` means.
 *
 * The result is a BigInt and therefore NOT JSON-serializable — keep it inside
 * comparison logic and never place it on a response, a fixture, or a prop.
 */
export function rfc3339UtcOrdinal(value: unknown): bigint | null {
  const parsed = parseExact(value);
  if (parsed === null) return null;
  return (
    BigInt(parsed.epochMsAtSecond) * MICROS_PER_MILLISECOND +
    BigInt(parsed.micros)
  );
}

/**
 * Parse a strict RFC3339 UTC timestamp to epoch milliseconds, or null.
 *
 * Sub-millisecond precision is truncated toward the past, never rounded up:
 * this value gates expiry terminalization, and rounding an observation
 * upward could place it beyond an expiry boundary it never actually crossed.
 * Use `rfc3339UtcOrdinal` for any comparison that must match Python exactly.
 */
export function parseRfc3339Utc(value: unknown): number | null {
  const parsed = parseExact(value);
  if (parsed === null) return null;
  return parsed.epochMsAtSecond + Math.floor(parsed.micros / 1000);
}

export function isRfc3339Utc(value: unknown): boolean {
  return parseExact(value) !== null;
}
