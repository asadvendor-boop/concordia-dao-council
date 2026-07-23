/**
 * Bounded response reading for credentialed upstream fetches (WP5-4).
 *
 * A credentialed request must never buffer an unbounded response body: a hostile
 * or compromised upstream could stream gigabytes (resource exhaustion) or embed
 * reflected credentials. `readBoundedJson` enforces a hard byte ceiling using
 * both the advertised `content-length` (fast reject) and a streaming cap
 * (authoritative), then parses JSON from the capped bytes.
 */

/** Thrown when the response exceeds the byte cap or is otherwise unreadable. */
export class BoundedResponseError extends Error {
  constructor(code: string) {
    super(code);
    this.name = "BoundedResponseError";
  }
}

/**
 * Bounded RAW text read. Split out from `readBoundedJson` so the settle path
 * can journal the exact received bytes BEFORE parsing them — the journal
 * records what the upstream actually sent, not our interpretation of it.
 */
export async function readBoundedText(
  response: Response,
  maxBytes: number,
): Promise<string> {
  const advertised = response.headers.get("content-length");
  if (advertised !== null) {
    const declared = Number(advertised);
    if (Number.isFinite(declared) && declared > maxBytes) {
      // Cancel without buffering; the body may reflect the credential.
      try {
        await response.body?.cancel();
      } catch {
        /* discarded */
      }
      throw new BoundedResponseError("response_too_large");
    }
  }

  const body = response.body;
  if (body === null) {
    // No stream: fall back to a bounded text read.
    const text = await response.text();
    if (Buffer.byteLength(text, "utf8") > maxBytes) {
      throw new BoundedResponseError("response_too_large");
    }
    return text;
  }

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value !== undefined) {
        total += value.byteLength;
        if (total > maxBytes) {
          try {
            await reader.cancel();
          } catch {
            /* discarded */
          }
          throw new BoundedResponseError("response_too_large");
        }
        chunks.push(value);
      }
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf8");
}

export async function readBoundedJson(
  response: Response,
  maxBytes: number,
): Promise<unknown> {
  return JSON.parse(await readBoundedText(response, maxBytes)) as unknown;
}
