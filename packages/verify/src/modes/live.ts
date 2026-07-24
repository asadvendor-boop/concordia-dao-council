import { isRecord } from "../encoders.js";
import { EXIT_CODES, verifyProofRegistry } from "../registry.js";
import type { ModeResult } from "./common.js";
import { verifyProposal } from "./proposal.js";
import {
  getRawProofBundle,
  type DnsLookupLike,
  type UrlVerificationOptions,
} from "./url.js";
import {
  CasperLiveError,
  corroborateCasperTestnetBundle,
  type CasperRpcTransport,
} from "./casper-live.js";

export type LiveObservation = {
  source: string;
  observedAt: string;
  registry: unknown;
  artifacts: Readonly<Record<string, Uint8Array | string>>;
};

export type LiveObserver = (proposalId: string) => Promise<LiveObservation>;

export type LiveVerificationOptions = Omit<UrlVerificationOptions, "mode"> & {
  liveObserver?: LiveObserver;
  trustedRpcEndpoints?: readonly string[];
  rpcDnsLookup?: DnsLookupLike;
  rpcTransport?: CasperRpcTransport;
  rpcTimeoutMs?: number;
  rpcOverallTimeoutMs?: number;
  rpcMaxResponseBytes?: number;
};

export async function verifyLive(
  proposalId: string,
  baseUrl: string,
  options: LiveVerificationOptions = {},
): Promise<ModeResult> {
  const {
    liveObserver,
    trustedRpcEndpoints,
    rpcDnsLookup,
    rpcTransport,
    rpcTimeoutMs,
    rpcOverallTimeoutMs,
    rpcMaxResponseBytes,
    ...proposalOptions
  } = options;
  const registry = await verifyProposal(proposalId, baseUrl, proposalOptions);
  if (registry.status !== "verified") return { ...registry, mode: "live" };
  if (trustedRpcEndpoints !== undefined && liveObserver !== undefined) {
    return {
      ...registry,
      mode: "live",
      status: "invalid",
      valid: false,
      exitCode: EXIT_CODES.INVALID,
      error: {
        code: "ambiguous_live_observer",
        message: "choose trusted RPC corroboration or a custom raw-bundle observer, not both",
      },
    };
  }
  if (trustedRpcEndpoints !== undefined) {
    const bundle = getRawProofBundle(registry);
    if (bundle === undefined) {
      return {
        ...registry,
        mode: "live",
        status: "unavailable",
        valid: false,
        exitCode: EXIT_CODES.UNAVAILABLE,
        error: {
          code: "live_bundle_unavailable",
          message: "live mode could not retain the exact remotely verified proof bundle",
        },
      };
    }
    try {
      const corroboration = await corroborateCasperTestnetBundle(bundle, {
        rpcEndpoints: trustedRpcEndpoints,
        ...(rpcDnsLookup === undefined ? {} : { dnsLookup: rpcDnsLookup }),
        ...(rpcTransport === undefined ? {} : { transport: rpcTransport }),
        ...(rpcTimeoutMs === undefined ? {} : { timeoutMs: rpcTimeoutMs }),
        ...(rpcOverallTimeoutMs === undefined ? {} : { overallTimeoutMs: rpcOverallTimeoutMs }),
        ...(rpcMaxResponseBytes === undefined ? {} : { maxResponseBytes: rpcMaxResponseBytes }),
        ...(options.now === undefined ? {} : { now: options.now }),
      });
      return {
        ...registry,
        mode: "live",
        verificationScope: corroboration.verificationScope,
        observationSources: corroboration.observationSources,
        live: {
          status: "verified",
          source: "trusted-casper-rpc-quorum",
          observedAt: corroboration.observedAt,
          proposalId: registry.proposalId,
          summary: registry.summary,
          observationSources: corroboration.observationSources,
          rpcObservationCount: corroboration.rpcObservationCount,
        },
      };
    } catch (error) {
      const liveError = error instanceof CasperLiveError
        ? error
        : new CasperLiveError("unavailable", "live_rpc_failed", "trusted RPC corroboration failed");
      return {
        ...registry,
        mode: "live",
        status: liveError.status,
        valid: false,
        exitCode: liveError.status === "invalid" ? EXIT_CODES.INVALID : EXIT_CODES.UNAVAILABLE,
        error: { code: liveError.code, message: liveError.message },
      };
    }
  }
  if (!liveObserver) {
    return {
      ...registry,
      mode: "live",
      status: "unavailable",
      valid: false,
      exitCode: EXIT_CODES.UNAVAILABLE,
      error: {
        code: "live_observer_unavailable",
        message: "live mode requires an explicit read-only chain observer",
      },
    };
  }
  try {
    const observation = await liveObserver(proposalId);
    if (!isLiveEvidenceBundle(observation)) {
      return {
        ...registry,
        mode: "live",
        status: "invalid",
        valid: false,
        exitCode: EXIT_CODES.INVALID,
        error: {
          code: "live_raw_evidence_required",
          message: "live observer must return a raw proof registry and its exact artifact bytes",
        },
      };
    }
    const referenceTime = options.now ?? new Date().toISOString();
    if (Date.parse(observation.observedAt) > Date.parse(referenceTime)) {
      return {
        ...registry,
        mode: "live",
        status: "invalid",
        valid: false,
        exitCode: EXIT_CODES.INVALID,
        error: {
          code: "future_live_observation",
          message: "live observation cannot be in the verifier's future",
        },
      };
    }
    const liveResult = verifyProofRegistry(observation.registry, {
      artifacts: observation.artifacts,
      now: referenceTime,
    });
    const live = {
      status: liveResult.status,
      source: observation.source,
      observedAt: observation.observedAt,
      proposalId: liveResult.proposalId,
      summary: liveResult.summary,
    } as const;
    if (liveResult.proposalId !== proposalId) {
      return {
        ...liveResult,
        mode: "live",
        status: "invalid",
        valid: false,
        exitCode: EXIT_CODES.INVALID,
        live,
        error: {
          code: "live_proposal_mismatch",
          message: "live evidence is bound to another proposal",
        },
      };
    }
    if (liveResult.status !== "verified") {
      return {
        ...liveResult,
        mode: "live",
        live,
        error: liveResult.error ?? {
          code: `live_evidence_${liveResult.status}`,
          message: `raw live evidence is ${liveResult.status}`,
        },
      };
    }
    return {
      ...liveResult,
      mode: "live",
      live,
    };
  } catch {
    return {
      ...registry,
      mode: "live",
      status: "unavailable",
      valid: false,
      exitCode: EXIT_CODES.UNAVAILABLE,
      error: {
        code: "live_observation_failed",
        message: "live observation callback failed",
      },
    };
  }
}

function isLiveEvidenceBundle(value: unknown): value is LiveObservation {
  if (!isRecord(value)) return false;
  const expected = ["source", "observedAt", "registry", "artifacts"];
  const actual = Object.keys(value).sort();
  if (
    actual.length !== expected.length ||
    expected.sort().some((name, index) => actual[index] !== name || !Object.hasOwn(value, name))
  ) {
    return false;
  }
  return (
    typeof value.source === "string" &&
    isHttpsSource(value.source) &&
    typeof value.observedAt === "string" &&
    isRfc3339Utc(value.observedAt) &&
    isRecord(value.artifacts)
  );
}

function isHttpsSource(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.username === "" && url.password === "";
  } catch {
    return false;
  }
}

function isRfc3339Utc(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z$/.exec(value);
  if (!match) return false;
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] = match;
  if (!yearText || !monthText || !dayText || !hourText || !minuteText || !secondText) return false;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return false;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const monthLengths = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day >= 1 && day <= (monthLengths[month - 1] ?? 0);
}
