import { randomBytes } from "crypto";
import { readFileSync } from "fs";

/**
 * Shared helpers for the demo-capability proxy routes (demo capability v1).
 *
 * The dashboard is a THIN same-origin proxy: it manages only the ephemeral
 * `__Host-concordia-demo-client` cookie and forwards requests to the internal
 * Gateway endpoints with `X-Concordia-Dashboard-Token`. It never holds the
 * operator token or the capability HMAC secret.
 */

export const CLIENT_COOKIE_NAME = "__Host-concordia-demo-client";
export const CLIENT_NONCE_HEADER = "X-Concordia-Demo-Client";
export const DASHBOARD_TOKEN_HEADER = "X-Concordia-Dashboard-Token";

const DASHBOARD_TOKEN_FILE_DEFAULT = "/run/secrets/dashboard_demo_gateway_token";
const COOKIE_MAX_AGE_SECONDS = 600;

// Unpadded base64url of exactly 32 bytes -> always 43 characters.
const CLIENT_NONCE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export function gatewayUrl() {
  return process.env.GATEWAY_URL || "http://127.0.0.1:8000";
}

export function liveDemoDisabledResponse(NextResponse) {
  if (process.env.CONCORDIA_LIVE_DEMO !== "1") {
    return NextResponse.json(
      { error: "Live demo actions are disabled for this deployment." },
      { status: 403 }
    );
  }
  return null;
}

export function readDashboardToken() {
  const filePath =
    process.env.DASHBOARD_DEMO_GATEWAY_TOKEN_FILE || DASHBOARD_TOKEN_FILE_DEFAULT;
  try {
    return readFileSync(filePath, "utf8").trim();
  } catch {
    return "";
  }
}

export function clientNonceFromCookie(request) {
  let value = "";
  const cookie = request.cookies?.get?.(CLIENT_COOKIE_NAME);
  if (cookie?.value) {
    value = cookie.value;
  } else {
    const header = request.headers.get("cookie") || "";
    for (const part of header.split(";")) {
      const [name, ...rest] = part.trim().split("=");
      if (name === CLIENT_COOKIE_NAME) {
        value = rest.join("=");
        break;
      }
    }
  }
  return CLIENT_NONCE_PATTERN.test(value) ? value : "";
}

export function mintClientNonce() {
  // Server-generated random 32 bytes, unpadded base64url on the wire.
  return randomBytes(32)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function setClientCookie(response, value) {
  // __Host- prefix requirements: Secure, Path=/, no Domain.
  response.headers.set(
    "Set-Cookie",
    `${CLIENT_COOKIE_NAME}=${value}; Path=/; Max-Age=${COOKIE_MAX_AGE_SECONDS}; Secure; HttpOnly; SameSite=Strict`
  );
  return response;
}

export async function readGatewayResponse(response) {
  const text = await response.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { error: "Gateway returned an invalid response" };
  }
}
