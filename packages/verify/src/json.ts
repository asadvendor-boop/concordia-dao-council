export class StrictJsonError extends SyntaxError {
  readonly code: "duplicate_json_key" | "invalid_json";

  constructor(code: "duplicate_json_key" | "invalid_json", message: string) {
    super(message);
    this.name = "StrictJsonError";
    this.code = code;
  }
}

export function parseJsonStrict(source: string): unknown {
  let offset = 0;
  let depth = 0;

  function fail(message: string): never {
    throw new StrictJsonError("invalid_json", `${message} at byte ${offset}`);
  }

  function whitespace(): void {
    while (offset < source.length && /[\t\n\r ]/.test(source[offset] ?? "")) offset += 1;
  }

  function value(): unknown {
    whitespace();
    if (depth >= 128) fail("JSON nesting exceeds 128 levels");
    const character = source[offset];
    if (character === "{") return object();
    if (character === "[") return array();
    if (character === '"') return string();
    if (character === "t" && source.slice(offset, offset + 4) === "true") {
      offset += 4;
      return true;
    }
    if (character === "f" && source.slice(offset, offset + 5) === "false") {
      offset += 5;
      return false;
    }
    if (character === "n" && source.slice(offset, offset + 4) === "null") {
      offset += 4;
      return null;
    }
    return number();
  }

  function object(): Record<string, unknown> {
    offset += 1;
    depth += 1;
    // A JSON key is data, never an instruction to mutate an object's
    // prototype. In particular, assigning `__proto__` on a normal object
    // invokes Object.prototype's legacy setter and can make absent validation
    // fields appear inherited. Null-prototype records preserve every parsed
    // key as an own data property.
    const result = Object.create(null) as Record<string, unknown>;
    const seen = new Set<string>();
    whitespace();
    if (source[offset] === "}") {
      offset += 1;
      depth -= 1;
      return result;
    }
    while (offset < source.length) {
      whitespace();
      if (source[offset] !== '"') fail("object key must be a string");
      const key = string();
      if (seen.has(key)) {
        throw new StrictJsonError("duplicate_json_key", `duplicate JSON key ${JSON.stringify(key)}`);
      }
      seen.add(key);
      whitespace();
      if (source[offset] !== ":") fail("expected colon after object key");
      offset += 1;
      result[key] = value();
      whitespace();
      if (source[offset] === "}") {
        offset += 1;
        depth -= 1;
        return result;
      }
      if (source[offset] !== ",") fail("expected comma between object fields");
      offset += 1;
    }
    fail("unterminated object");
  }

  function array(): unknown[] {
    offset += 1;
    depth += 1;
    const result: unknown[] = [];
    whitespace();
    if (source[offset] === "]") {
      offset += 1;
      depth -= 1;
      return result;
    }
    while (offset < source.length) {
      result.push(value());
      whitespace();
      if (source[offset] === "]") {
        offset += 1;
        depth -= 1;
        return result;
      }
      if (source[offset] !== ",") fail("expected comma between array elements");
      offset += 1;
    }
    fail("unterminated array");
  }

  function string(): string {
    const start = offset;
    offset += 1;
    while (offset < source.length) {
      const character = source[offset];
      if (character === '"') {
        offset += 1;
        try {
          return JSON.parse(source.slice(start, offset)) as string;
        } catch {
          fail("invalid JSON string");
        }
      }
      if (character === "\\") {
        offset += 1;
        const escaped = source[offset];
        if (escaped === "u") {
          const hex = source.slice(offset + 1, offset + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("invalid Unicode escape");
          offset += 5;
          continue;
        }
        if (!escaped || !'"\\/bfnrt'.includes(escaped)) fail("invalid string escape");
        offset += 1;
        continue;
      }
      if (character === undefined || character.charCodeAt(0) < 0x20) fail("control character in string");
      offset += 1;
    }
    fail("unterminated string");
  }

  function number(): number | bigint {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(source.slice(offset));
    if (!match) fail("invalid JSON value");
    offset += match[0].length;
    if (!/[.eE]/.test(match[0])) {
      const exact = BigInt(match[0]);
      if (exact > BigInt(Number.MAX_SAFE_INTEGER) || exact < BigInt(Number.MIN_SAFE_INTEGER)) {
        // Casper JSON-RPC serializes some u64 values as JSON numbers. Keeping
        // one as Number would silently round it before exact verification.
        return exact;
      }
    }
    const parsed = Number(match[0]);
    if (!Number.isFinite(parsed)) fail("non-finite JSON number");
    return parsed;
  }

  const result = value();
  whitespace();
  if (offset !== source.length) fail("trailing data after JSON value");
  return result;
}
