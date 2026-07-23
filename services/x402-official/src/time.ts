/**
 * Strict RFC3339 UTC timestamp parsing (§13, WP5-6).
 *
 * Governance records and settlement registry items are only trusted when every
 * timestamp is an explicit UTC-Z instant — never a bare string, a local time,
 * or an arbitrary offset. Chronology is then enforced numerically against the
 * parsed epoch milliseconds, so forged or out-of-order timestamps fail closed.
 */

// YYYY-MM-DDTHH:MM:SS(.fraction)?Z — uppercase 'T' and 'Z' only, no offset.
const RFC3339_UTC_RE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?Z$/;

/**
 * Parse a strict RFC3339 UTC timestamp to epoch milliseconds. Returns null for
 * any non-conforming, non-UTC, or calendar-invalid value (e.g. month 13, an
 * offset like +00:00, or a value Date silently normalizes).
 */
export function parseRfc3339Utc(value: unknown): number | null {
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
  if (month < 1 || month > 12) return null;
  if (day < 1 || day > 31) return null;
  if (hour > 23 || minute > 59 || second > 60) return null; // allow leap second 60
  const ms = frac === undefined ? 0 : Math.round(Number(frac) * 1000);
  const secClamped = second === 60 ? 59 : second;
  const epoch = Date.UTC(year, month - 1, day, hour, minute, secClamped, ms);
  if (Number.isNaN(epoch)) return null;
  // Reject values Date silently rolled over (e.g. day 31 in a 30-day month).
  const back = new Date(epoch);
  if (
    back.getUTCFullYear() !== year ||
    back.getUTCMonth() !== month - 1 ||
    back.getUTCDate() !== day
  ) {
    return null;
  }
  return epoch;
}

export function isRfc3339Utc(value: unknown): boolean {
  return parseRfc3339Utc(value) !== null;
}
