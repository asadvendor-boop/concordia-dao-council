// Provenance-aware proof registry rendering (G1_INTERFACE_SPEC.md section 13).
//
// Truth rules implemented here:
// - A green verification cue renders ONLY when verification_status=verified,
//   every mapped required check occurs exactly once with required=true and
//   passed=true, every extra required check passes, observation is available,
//   and execution_outcome is accepted / expected_rejection / not_applicable.
// - expected_rejection renders as POSITIVE proof (e.g. QuorumNotMet), never as
//   a failure.
// - unknown / missing / stale / pending / unavailable / invalid never render
//   green. Top-level asserted booleans never become green on their own.
//
// The validation logic itself (registryItemErrors, itemGreenVerified, the
// required-check and public-field tables) lives in provenance-pure.js — a
// JSX-free, dependency-free module also consumed by the x402 settlement
// service's cross-language schema-drift suite. This file re-exports it so
// every dashboard consumer keeps importing from "./provenance" unchanged.
import { cx, shortHash, titleCaseAction } from "./lib";
import { Icon, PendingNote, StatusPill } from "./primitives";
import {
  itemGreenVerified,
  normalizeRegistryItem,
  registryItemErrors,
  PUBLIC_ITEM_REQUIRED_FIELDS,
  REQUIRED_CHECKS_BY_PROOF_TYPE,
} from "./provenance-pure";

export {
  itemGreenVerified,
  normalizeRegistryItem,
  registryItemErrors,
  PUBLIC_ITEM_REQUIRED_FIELDS,
  REQUIRED_CHECKS_BY_PROOF_TYPE,
};

export function findRegistryItems(registry, proofType) {
  if (!registry || !Array.isArray(registry.items)) return [];
  const reference = new Date().toISOString();
  return registry.items
    .filter((item) => item?.proof_type === proofType)
    .map((item) => normalizeRegistryItem(item, registry, reference));
}
export function findRegistryItem(registry, proofType) {
  return findRegistryItems(registry, proofType)[0] || null;
}
// Exact-id registry lookup for claim rows that reference a specific proof item.
// The result passes through the same cross-field normalization, so a
// mismatched/late/malformed item is stamped invalid and can never render green.
export function findRegistryItemByProofId(registry, proofId) {
  if (!registry || !Array.isArray(registry.items) || !proofId) return null;
  const match = registry.items.find((item) => item?.proof_id === proofId);
  return match ? normalizeRegistryItem(match, registry, new Date().toISOString()) : null;
}

const STATUS_META = {
  verified: { label: "Verified", tone: "success" },
  pending: { label: "Pending", tone: "warning" },
  stale: { label: "Stale", tone: "warning" },
  unavailable: { label: "Unavailable", tone: "muted" },
  invalid: { label: "Invalid", tone: "danger" },
};
const OUTCOME_META = {
  accepted: { label: "Accepted" },
  expected_rejection: { label: "Expected rejection · proof" },
  not_applicable: { label: "Not applicable" },
  unexpected_rejection: { label: "Unexpected rejection" },
  not_attempted: { label: "Not attempted" },
  unknown: { label: "Unknown" },
};

// Provenance badge: renders the separate registry dimensions without ever
// collapsing them into one status string, and applies the green cue only via
// itemGreenVerified.
export function ProvenanceBadge({ item, compact = false }) {
  if (!item) {
    return <span className="prov-badge prov-unavailable"><Icon name="clock" size={13} />Provenance unavailable</span>;
  }
  const green = itemGreenVerified(item);
  const status = STATUS_META[item.verification_status] || { label: titleCaseAction(item.verification_status || "unknown"), tone: "muted" };
  const outcome = OUTCOME_META[item.execution_outcome] || { label: titleCaseAction(item.execution_outcome || "unknown") };
  const expectedRejectionProof = green && item.execution_outcome === "expected_rejection";
  return <span className={cx("prov-badge", `prov-${item.verification_status || "unknown"}`, green && "prov-verified", compact && "prov-compact")}>
    <Icon name={green ? "check" : status.tone === "danger" ? "signal" : "clock"} size={13} />
    <strong>{status.label}</strong>
    <em className={cx("prov-outcome", expectedRejectionProof && "prov-outcome-proof")}>{outcome.label}</em>
    <small>{item.lineage || "—"} · {item.temporal_scope || "—"} · {item.observation_mode || "—"}</small>
  </span>;
}

function checksSummary(item) {
  const checks = Array.isArray(item?.checks) ? item.checks : [];
  const required = checks.filter((check) => check?.required === true);
  const passed = required.filter((check) => check?.passed === true);
  return { total: checks.length, required: required.length, passed: passed.length };
}

// Full registry listing panel. Renders each item with its provenance badge and
// per-check detail; honest pending state when the registry is not yet served.
export function ProofRegistryPanel({ registry, registryError }) {
  if (!registry) {
    return <div className="registry-pending" data-testid="proof-registry-pending">
      <PendingNote>
        The provenance-aware proof registry (<code>/proof-registry/v1</code>) is not
        available from the gateway yet{registryError ? ` (${registryError})` : ""}. No
        provenance claims are asserted while it is unavailable.
      </PendingNote>
    </div>;
  }
  const rawItems = Array.isArray(registry.items) ? registry.items : [];
  if (!rawItems.length) {
    return <div className="registry-pending" data-testid="proof-registry-empty">
      <PendingNote>The proof registry returned no items for this proposal. Nothing is asserted.</PendingNote>
    </div>;
  }
  const reference = new Date().toISOString();
  const items = rawItems.map((item) => normalizeRegistryItem(item, registry, reference));
  return <div className="registry-list" data-testid="proof-registry-list">
    {items.map((item) => {
      const green = itemGreenVerified(item);
      const summary = checksSummary(item);
      return <article key={item.proof_id} className={cx("registry-item", green && "registry-item-verified")} data-proof-type={item.proof_type}>
        <header>
          <div>
            <strong>{titleCaseAction(item.proof_type)}</strong>
            <small className="mono">{item.proof_id}</small>
          </div>
          <ProvenanceBadge item={item} />
        </header>
        <div className="registry-item-grid">
          <div><span>Generation</span><strong>{item.generation || "—"}</strong></div>
          <div><span>Claim scope</span><strong>{item.claim_scope || "—"}</strong></div>
          <div><span>Enforcement scope</span><strong>{item.enforcement_scope || "—"}</strong></div>
          <div><span>Required checks</span><strong>{summary.required ? `${summary.passed} / ${summary.required} passed` : "none recorded"}</strong></div>
          {item.artifact_sha256 && <div><span>Artifact SHA-256</span><strong className="mono">{shortHash(item.artifact_sha256, 12, 8)}</strong></div>}
          {item.envelope_hash && <div><span>Envelope hash</span><strong className="mono">{shortHash(item.envelope_hash, 12, 8)}</strong></div>}
          {item.captured_at && <div><span>Captured</span><strong>{item.captured_at}</strong></div>}
          {item.source_commit && <div><span>Source commit</span><strong className="mono">{shortHash(item.source_commit, 10, 0)}</strong></div>}
        </div>
        {!green && <p className="registry-item-note">
          {item.verification_status === "verified"
            ? "Marked verified but its required checks do not all pass — rendered without a success cue."
            : "Not verified — rendered without any success cue."}
        </p>}
      </article>;
    })}
  </div>;
}

export function registryStatusPill(item) {
  if (!item) return <StatusPill tone="muted" compact>unavailable</StatusPill>;
  const green = itemGreenVerified(item);
  const meta = STATUS_META[item.verification_status] || { label: item.verification_status || "unknown", tone: "muted" };
  return <StatusPill tone={green ? "success" : meta.tone === "success" ? "info" : meta.tone} compact>{meta.label}</StatusPill>;
}
