import { NextResponse } from "next/server";

import {
  CLIENT_NONCE_HEADER,
  DASHBOARD_TOKEN_HEADER,
  clientNonceFromCookie,
  gatewayUrl,
  liveDemoDisabledResponse,
  readDashboardToken,
  readGatewayResponse,
  setClientCookie,
} from "../_shared";

/**
 * Thin same-origin proxy: activate a previously issued demo capability
 * (demo capability v1). The browser presents only the opaque capability and
 * its binding cookie; the Gateway validates and runs the scenario. The
 * dashboard never holds the operator token or the capability HMAC secret,
 * and there is no public reset path.
 */
export async function POST(request) {
  const disabled = liveDemoDisabledResponse(NextResponse);
  if (disabled) return disabled;

  let capability = "";
  let scenarioId = "";
  try {
    const body = await request.json();
    capability = String(body?.capability || "").trim();
    scenarioId = String(body?.scenario_id || "").trim();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }
  if (!capability || !scenarioId) {
    return NextResponse.json(
      { error: "capability and scenario_id are required" },
      { status: 400 }
    );
  }

  const dashboardToken = readDashboardToken();
  if (!dashboardToken) {
    return NextResponse.json(
      { error: "DASHBOARD_DEMO_GATEWAY_TOKEN is not configured." },
      { status: 503 }
    );
  }

  const clientNonce = clientNonceFromCookie(request);
  if (!clientNonce) {
    // Without the binding cookie the capability can never validate.
    return NextResponse.json(
      { error: "Demo client is not initialized — request a capability first." },
      { status: 400 }
    );
  }

  try {
    const response = await fetch(`${gatewayUrl()}/internal/demo/activate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        [DASHBOARD_TOKEN_HEADER]: dashboardToken,
        [CLIENT_NONCE_HEADER]: clientNonce,
      },
      body: JSON.stringify({ capability, scenario_id: scenarioId }),
      cache: "no-store",
    });
    const data = await readGatewayResponse(response);
    const proxied = NextResponse.json(data, { status: response.status });
    return setClientCookie(proxied, clientNonce);
  } catch {
    return NextResponse.json(
      { error: "Failed to reach the Concordia DAO Council Gateway" },
      { status: 502 }
    );
  }
}
