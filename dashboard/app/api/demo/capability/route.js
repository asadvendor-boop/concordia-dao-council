import { NextResponse } from "next/server";

import {
  CLIENT_NONCE_HEADER,
  DASHBOARD_TOKEN_HEADER,
  clientNonceFromCookie,
  gatewayUrl,
  liveDemoDisabledResponse,
  mintClientNonce,
  readDashboardToken,
  readGatewayResponse,
  setClientCookie,
} from "../_shared";

/**
 * Thin same-origin proxy: request a demo capability from the Gateway
 * (demo capability v1). Manages only the ephemeral client-binding cookie;
 * the Gateway is the sole issuer and HMAC validator. No operator token.
 */
export async function POST(request) {
  const disabled = liveDemoDisabledResponse(NextResponse);
  if (disabled) return disabled;

  let scenarioId = "";
  try {
    const body = await request.json();
    scenarioId = String(body?.scenario_id || "").trim();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }
  if (!scenarioId) {
    return NextResponse.json({ error: "scenario_id is required" }, { status: 400 });
  }

  const dashboardToken = readDashboardToken();
  if (!dashboardToken) {
    return NextResponse.json(
      { error: "DASHBOARD_DEMO_GATEWAY_TOKEN is not configured." },
      { status: 503 }
    );
  }

  // Server-generated random 32-byte client nonce (cookie ⇄ header binding).
  let clientNonce = clientNonceFromCookie(request);
  if (!clientNonce) {
    clientNonce = mintClientNonce();
  }

  try {
    const response = await fetch(`${gatewayUrl()}/internal/demo/capability`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        [DASHBOARD_TOKEN_HEADER]: dashboardToken,
        [CLIENT_NONCE_HEADER]: clientNonce,
      },
      body: JSON.stringify({ scenario_id: scenarioId }),
      cache: "no-store",
    });
    const data = await readGatewayResponse(response);
    const proxied = NextResponse.json(data, { status: response.status });
    // Always refresh the ephemeral binding cookie (Max-Age 600).
    return setClientCookie(proxied, clientNonce);
  } catch {
    return NextResponse.json(
      { error: "Failed to reach the Concordia DAO Council Gateway" },
      { status: 502 }
    );
  }
}
