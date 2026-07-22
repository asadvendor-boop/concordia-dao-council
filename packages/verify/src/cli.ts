#!/usr/bin/env node

import { EXIT_CODES } from "./registry.js";
import { verifyLive } from "./modes/live.js";
import { verifyLocal } from "./modes/local.js";
import { verifyProposal } from "./modes/proposal.js";
import { verifyUrl } from "./modes/url.js";
import { modeFailure, type ModeResult } from "./modes/common.js";

async function main(arguments_: string[]): Promise<ModeResult> {
  const [mode, subject, ...rest] = arguments_;
  const now = option(rest, "--now");
  if (mode === "local" && subject && onlyOptions(rest, ["--now"])) {
    return verifyLocal(subject, now ? { now } : {});
  }
  if (mode === "url" && subject && onlyOptions(rest, ["--now"])) {
    return verifyUrl(subject, now ? { now } : {});
  }
  if ((mode === "proposal" || mode === "live") && subject) {
    const baseUrl = option(rest, "--base-url");
    const allowed = mode === "live"
      ? ["--base-url", "--now", "--rpc-endpoint"]
      : ["--base-url", "--now"];
    if (!baseUrl || !onlyOptions(rest, allowed)) return usage(mode);
    if (mode === "proposal") return verifyProposal(subject, baseUrl, now ? { now } : {});
    const rpcEndpoints = options(rest, "--rpc-endpoint");
    if (rpcEndpoints.length < 2) return usage(mode);
    return verifyLive(subject, baseUrl, {
      trustedRpcEndpoints: rpcEndpoints,
      ...(now ? { now } : {}),
    });
  }
  return usage(typeof mode === "string" ? mode : "local");
}

function options(arguments_: string[], name: string): string[] {
  const values: string[] = [];
  for (let index = 0; index < arguments_.length; index += 2) {
    if (arguments_[index] === name && arguments_[index + 1] !== undefined) {
      values.push(arguments_[index + 1] as string);
    }
  }
  return values;
}

function option(arguments_: string[], name: string): string | undefined {
  const index = arguments_.indexOf(name);
  if (index === -1) return undefined;
  return arguments_[index + 1];
}

function onlyOptions(arguments_: string[], allowed: readonly string[]): boolean {
  let index = 0;
  while (index < arguments_.length) {
    const name = arguments_[index];
    if (!name || !allowed.includes(name) || arguments_[index + 1] === undefined) return false;
    index += 2;
  }
  return true;
}

function usage(mode: string): ModeResult {
  const failure = modeFailure(
    mode === "url" || mode === "proposal" || mode === "live" ? mode : "local",
    "invalid",
    "usage_error",
    "usage: concordia-verify local <file> | url <https-url> | proposal <id> --base-url <https-url> | live <id> --base-url <https-url> --rpc-endpoint <https-rpc> --rpc-endpoint <https-rpc>",
  );
  return { ...failure, exitCode: EXIT_CODES.USAGE };
}

const result = await main(process.argv.slice(2));
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
process.exitCode = result.exitCode;
