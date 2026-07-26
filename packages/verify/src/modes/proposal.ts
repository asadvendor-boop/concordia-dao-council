import { modeFailure, type ModeResult } from "./common.js";
import { verifyUrl, type UrlVerificationOptions } from "./url.js";

const PROPOSAL_ID = /^[A-Z0-9-]{1,64}$/;

export async function verifyProposal(
  proposalId: string,
  baseUrl: string,
  options: Omit<UrlVerificationOptions, "mode"> = {},
): Promise<ModeResult> {
  if (!PROPOSAL_ID.test(proposalId)) {
    return modeFailure("proposal", "invalid", "invalid_proposal_id", "proposal ID is not canonical");
  }
  let url: URL;
  try {
    const base = new URL(baseUrl);
    if (base.protocol !== "https:" || base.username !== "" || base.password !== "") throw new Error();
    url = new URL(`/proof-registry/v1/${encodeURIComponent(proposalId)}`, base);
  } catch {
    return modeFailure("proposal", "invalid", "invalid_base_url", "base URL must use HTTPS");
  }
  return verifyUrl(url.toString(), { ...options, mode: "proposal" });
}
