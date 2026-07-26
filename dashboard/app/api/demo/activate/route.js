import { readFileSync } from "fs";
import { NextResponse } from "next/server";

const OPERATOR_TOKEN_FILE = "/run/secrets/concordia_operator_token";
const TRUE_VALUES = new Set(["1", "true", "yes", "on"]);

/**
 * Server-side proxy for controlled demo scenarios. Every non-reset scenario
 * goes through Gateway so it creates a Council Chamber, seals a ProposalCard, and
 * starts the complete agent pipeline. The browser never calls the proposal simulator.
 */
const SCENARIO_TYPES = new Set([
  "treasury",
  "defi-treasury",
  "oracle",
  "yield",
  "exposure",
  "policy",
  "credential",
  "rwa-onboarding",
  "reset",
]);

async function readGatewayResponse(response) {
  const text = await response.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { error: "Gateway returned an invalid response" };
  }
}

function operatorTokenFrom(request) {
  const authorization = request.headers.get("authorization") || "";
  if (authorization.toLowerCase().startsWith("bearer ")) {
    return authorization.slice(7);
  }
  return request.headers.get("x-operator-token") || "";
}

function browserTokenRequired() {
  return TRUE_VALUES.has(String(process.env.CONCORDIA_REQUIRE_BROWSER_TOKEN || "").toLowerCase());
}

function secretFromEnvOrFile(name) {
  const direct = process.env[name] || "";
  if (direct) return direct;

  const filePath = process.env[`${name}_FILE`] || OPERATOR_TOKEN_FILE;
  if (filePath !== OPERATOR_TOKEN_FILE) return "";

  try {
    return readFileSync(OPERATOR_TOKEN_FILE, "utf8").trim();
  } catch {
    return "";
  }
}

export async function POST(request) {
  const gatewayUrl = process.env.GATEWAY_URL || "http://127.0.0.1:8000";

  try {
    const body = await request.json();
    const scenarioType = String(body?.scenario_type || "").trim().toLowerCase();
    if (!SCENARIO_TYPES.has(scenarioType)) {
      return NextResponse.json(
        {
          error: `Unknown scenario_type: ${scenarioType || "(missing)"}. Allowed: ${Array.from(SCENARIO_TYPES).join(", ")}`,
        },
        { status: 400 }
      );
    }

    if (process.env.CONCORDIA_LIVE_DEMO !== "1") {
      return NextResponse.json(
        { error: "Live demo actions are disabled for this deployment." },
        { status: 403 }
      );
    }

    const operatorToken = secretFromEnvOrFile("CONCORDIA_OPERATOR_TOKEN");
    if (!operatorToken) {
      return NextResponse.json(
        { error: "CONCORDIA_OPERATOR_TOKEN is not configured." },
        { status: 503 }
      );
    }
    if (browserTokenRequired() && operatorTokenFrom(request) !== operatorToken) {
      return NextResponse.json(
        { error: "A valid governance admin token is required." },
        { status: 401 }
      );
    }

    const endpoint = scenarioType === "reset" ? "/demo/reset" : "/demo/trigger";
    const gatewayBody = scenarioType === "reset" ? {} : { scenario_type: scenarioType };
    const response = await fetch(`${gatewayUrl}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Operator-Token": operatorToken },
      body: JSON.stringify(gatewayBody),
      cache: "no-store",
    });
    const data = await readGatewayResponse(response);
    return NextResponse.json(data, { status: response.status });
  } catch {
    return NextResponse.json(
      { error: "Failed to reach the Concordia DAO Council Gateway" },
      { status: 502 }
    );
  }
}
