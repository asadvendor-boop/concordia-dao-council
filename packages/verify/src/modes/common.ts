import {
  EXIT_CODES,
  type RegistryVerificationResult,
  type ResultStatus,
} from "../registry.js";

export type VerificationMode = "local" | "url" | "proposal" | "live";

export type ModeResult = RegistryVerificationResult & {
  mode: VerificationMode;
  live?: {
    status: ResultStatus;
    source: string;
    observedAt: string;
    proposalId: string | null;
    summary: RegistryVerificationResult["summary"];
    observationSources?: string[];
    rpcObservationCount?: number;
  };
};

export function withMode(
  result: RegistryVerificationResult,
  mode: VerificationMode,
): ModeResult {
  return { ...result, mode };
}

export function modeFailure(
  mode: VerificationMode,
  status: Exclude<ResultStatus, "verified">,
  code: string,
  message: string,
): ModeResult {
  const exitCode =
    status === "invalid"
      ? EXIT_CODES.INVALID
      : status === "unavailable"
        ? EXIT_CODES.UNAVAILABLE
        : EXIT_CODES.UNKNOWN;
  return {
    schemaVersion: 1,
    tool: "@concordia-dao/verify",
    mode,
    status,
    valid: false,
    exitCode,
    proposalId: null,
    verificationScope: "none",
    observationSources: [],
    summary: { total: 0, verified: 0, invalid: 0, unavailable: 0, unknown: 0 },
    items: [],
    error: { code, message },
  };
}
