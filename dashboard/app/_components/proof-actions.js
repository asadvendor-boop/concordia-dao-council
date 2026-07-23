// Single proof-action registry: every judge-facing proof shortcut resolves
// through here and renders with a stable `proof-action-<id>` test id.
import {
  DEFAULT_CASPER_EXPLORER_URL,
  DEFAULT_IPFS_GATEWAY_URL,
  DEFAULT_QUORUM_ACCEPTED_URL,
  DEFAULT_QUORUM_REJECTED_URL,
  DEFAULT_REVIEW_PROPOSAL_ID,
  DEFAULT_SUPPLEMENTAL_DYNAMIC_HASH,
  DEFAULT_WALLET_RECEIPT_HASH,
  cx,
  navHref,
} from "./lib";
import { PrimaryButton } from "./primitives";

export const PROOF_ACTION_REGISTRY = {
  evidence_chain: {
    id: "evidence_chain",
    label: "Evidence Chain",
    icon: "evidence",
    status: "secondary",
    tooltip: "Open the sealed Concordia evidence chain for the selected proof run.",
    href: (proposalId) => navHref("/evidence", proposalId),
  },
  canonical_receipt: {
    id: "canonical_receipt",
    label: "Canonical CSPR.live Receipt",
    icon: "external",
    status: "primary",
    tooltip: "Open the canonical reviewer receipt on Casper Testnet.",
    href: () => DEFAULT_CASPER_EXPLORER_URL,
    external: true,
  },
  quorum_failure: {
    id: "quorum_failure",
    label: "Pre-quorum Rejection",
    icon: "lock",
    status: "secondary",
    tooltip: "Open the supplemental proof showing execution blocked before quorum.",
    href: () => DEFAULT_QUORUM_REJECTED_URL,
    external: true,
  },
  quorum_success: {
    id: "quorum_success",
    label: "Quorum Receipt",
    icon: "external",
    status: "secondary",
    tooltip: "Open the supplemental final quorum receipt.",
    href: () => DEFAULT_QUORUM_ACCEPTED_URL,
    external: true,
  },
  wallet_receipt: {
    id: "wallet_receipt",
    label: "Browser Wallet Receipt",
    icon: "external",
    status: "secondary",
    tooltip: "Open the recorded browser-wallet receipt.",
    href: () => `https://testnet.cspr.live/deploy/${DEFAULT_WALLET_RECEIPT_HASH}`,
    external: true,
  },
  supplemental_dynamic_receipt: {
    id: "supplemental_dynamic_receipt",
    label: "Supplemental Dynamic Receipt",
    icon: "external",
    status: "secondary",
    tooltip: "Open the supplemental dynamic execution proof.",
    href: () => `https://testnet.cspr.live/deploy/${DEFAULT_SUPPLEMENTAL_DYNAMIC_HASH}`,
    external: true,
  },
  ipfs_archive: {
    id: "ipfs_archive",
    label: "IPFS Archive",
    icon: "link",
    status: "secondary",
    tooltip: "Open the pinned governance archive CID through the Concordia gateway.",
    href: () => DEFAULT_IPFS_GATEWAY_URL,
    external: true,
  },
  proof_pack_json: {
    id: "proof_pack_json",
    label: "Proof Pack JSON",
    icon: "code",
    status: "secondary",
    tooltip: "Open the raw public proof pack.",
    href: (proposalId) => `/proof-pack/${encodeURIComponent(proposalId || DEFAULT_REVIEW_PROPOSAL_ID)}`,
  },
  certificate_html: {
    id: "certificate_html",
    label: "Certificate",
    icon: "evidence",
    status: "secondary",
    tooltip: "Open the printable HTML governance certificate.",
    href: (proposalId) => `/certificate/${encodeURIComponent(proposalId || DEFAULT_REVIEW_PROPOSAL_ID)}`,
  },
  certificate_pdf: {
    id: "certificate_pdf",
    label: "PDF Certificate",
    icon: "download",
    status: "download",
    tooltip: "Download the PDF governance certificate.",
    href: (proposalId) => `/certificate/${encodeURIComponent(proposalId || DEFAULT_REVIEW_PROPOSAL_ID)}/pdf`,
  },
  audit_packet: {
    id: "audit_packet",
    label: "Audit Packet",
    icon: "download",
    status: "download",
    tooltip: "Download the reviewer audit packet.",
    href: (proposalId) => `/proof-pack/${encodeURIComponent(proposalId || DEFAULT_REVIEW_PROPOSAL_ID)}/download`,
  },
  x402_risk_report: {
    id: "x402_risk_report",
    label: "SafePay Lite Proof (native CSPR)",
    icon: "activity",
    status: "secondary",
    tooltip: "Open the SafePay Lite (native CSPR) proof bundle. Distinct from the official x402 WCSPR settlement.",
    href: (proposalId) => `/safepay-lite/${encodeURIComponent(proposalId || DEFAULT_REVIEW_PROPOSAL_ID)}`,
  },
  trace_api: {
    id: "trace_api",
    label: "Trace API",
    icon: "activity",
    status: "secondary",
    tooltip: "Open the redacted public trace API.",
    href: (proposalId) => `/api/runs/${encodeURIComponent(proposalId || DEFAULT_REVIEW_PROPOSAL_ID)}/trace`,
  },
  wallet_intent: {
    id: "wallet_intent",
    label: "Wallet Intent",
    icon: "lock",
    status: "requires_wallet",
    tooltip: "Advanced testnet action. Not required for reviewing canonical proof.",
    disabledReason: "Connect a Casper Wallet on casper-test to build an optional testnet intent.",
    href: null,
  },
  technical_jury_note: {
    id: "technical_jury_note",
    label: "Technical Jury Note",
    icon: "evidence",
    status: "secondary",
    tooltip: "Open the scoped technical jury note.",
    href: () => "/technical-jury-note",
  },
};

export function resolveProofAction(actionId, proposalId = DEFAULT_REVIEW_PROPOSAL_ID, overrides = {}) {
  const action = { ...(PROOF_ACTION_REGISTRY[actionId] || {}), ...overrides };
  const href = typeof action.href === "function" ? action.href(proposalId) : action.href;
  const disabled = action.status === "disabled" || Boolean(action.disabled);
  return {
    ...action,
    id: action.id || actionId,
    href,
    disabled,
    disabledReason: action.disabledReason || (disabled ? "This action is not available for the selected proof." : ""),
    dataTestId: action.testId || `proof-action-${action.id || actionId}`,
  };
}

export function proofActionTone(status) {
  if (status === "primary") return "primary";
  if (status === "advanced" || status === "requires_wallet") return "ghost";
  return "secondary";
}

export function ProofActionButton({ actionId, proposalId = DEFAULT_REVIEW_PROPOSAL_ID, overrides }) {
  const action = resolveProofAction(actionId, proposalId, overrides);
  return <PrimaryButton
    icon={action.icon}
    href={action.href}
    onClick={action.onClick}
    tone={action.tone || proofActionTone(action.status)}
    disabled={action.disabled || action.status === "requires_wallet" && !action.onClick && !action.href}
    dataTestId={action.dataTestId}
    title={action.disabled ? action.disabledReason : action.tooltip}
  >
    {action.label}
  </PrimaryButton>;
}

export function ProofActionBar({ actionIds = [], proposalId = DEFAULT_REVIEW_PROPOSAL_ID, className = "", compact = false, overridesById = {} }) {
  return <div className={cx("proof-action-bar", compact && "compact", className)}>{actionIds.map((actionId) => <ProofActionButton key={actionId} actionId={actionId} proposalId={proposalId} overrides={overridesById[actionId]} />)}</div>;
}
