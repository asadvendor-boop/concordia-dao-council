// The TWO payment proofs, rendered as two permanently distinct panels:
//
//   1. SafePay Lite — supplemental paid specialist-report settlement in NATIVE
//      CSPR (spec section 12, safepay-v2).
//   2. Official x402 — WCSPR (CEP-18) settlement through the official
//      facilitator (spec section 12, official x402 local service v1).
//
// They are never merged, and WCSPR is never described as native CSPR. Neither
// panel renders a success cue unless its registry item passes the section-13
// green predicate. The official x402 gate starts fail-closed and renders
// "pending live verification" until real evidence exists.
import { HISTORICAL_SAFEPAY_PAYMENT_HASH, shortHash } from "./lib";
import { itemGreenVerified } from "./provenance";
import { HashChip, Icon, Panel, PendingNote, StatusPill } from "./primitives";

function findCheck(item, name) {
  return (Array.isArray(item?.checks) ? item.checks : []).find((check) => check?.name === name) || null;
}

// The three redemption dispositions from spec section 12 (SafePay v2), each
// bound to the registry check that records it.
const SAFEPAY_DISPOSITIONS = [
  {
    id: "first_consumption",
    check: "provider_consumption_row_matches_payment_and_binding",
    label: "First consumption",
    detail: "Payment atomically claimed once; fulfillment persisted with its response hash.",
  },
  {
    id: "idempotent_replay",
    check: "exact_retry_returned_same_fulfillment_hash_without_second_consumption",
    label: "Idempotent replay",
    detail: "Exact same-quote retry returned the identical stored fulfillment — no second consumption.",
  },
  {
    id: "cross_binding_rejected",
    check: "cross_binding_reuse_returned_terminal_409",
    label: "Cross-binding rejected (409)",
    detail: "Reusing the payment for a different quote/resource returned terminal HTTP 409.",
  },
];

export function SafePayPanel({ item, legacy }) {
  const green = itemGreenVerified(item);
  const paymentHash = item?.settlement_transaction || null;
  const reportHash = item?.report_hash || null;
  return <Panel
    className="payment-panel safepay-panel"
    title="SafePay Lite · native CSPR"
    eyebrow="Supplemental paid report settlement — distinct from official x402 (WCSPR)"
    action={item
      ? <StatusPill tone={green ? "success" : "warning"} compact>{green ? "verified" : item.verification_status || "pending"}</StatusPill>
      : <StatusPill tone="muted" compact>unavailable</StatusPill>}
  >
    <div className="payment-panel-body" data-testid="safepay-panel">
      {item ? <>
        <div className="payment-hash-row">
          {paymentHash && <HashChip label="Payment deploy" value={paymentHash} tone={green ? "success" : "info"} />}
          {reportHash && <HashChip label="Report SHA-256" value={reportHash} />}
        </div>
        <div className="disposition-list">
          {SAFEPAY_DISPOSITIONS.map((disposition) => {
            const check = findCheck(item, disposition.check);
            const proven = green && check?.passed === true;
            const recorded = !green && check?.passed === true;
            return <div key={disposition.id} className={proven ? "disposition disposition-proof" : recorded ? "disposition disposition-recorded" : "disposition disposition-pending"} data-disposition={disposition.id}>
              <span><Icon name={proven ? "check" : "clock"} size={15} /></span>
              <div>
                <strong>{disposition.label}</strong>
                <small>{disposition.detail}</small>
              </div>
              {proven && <StatusPill tone="success" compact>proof</StatusPill>}
              {recorded && <StatusPill tone="warning" compact>recorded · not verified</StatusPill>}
              {!check && <StatusPill tone="muted" compact>not observed</StatusPill>}
              {check && check.passed !== true && <StatusPill tone="danger" compact>failed</StatusPill>}
            </div>;
          })}
        </div>
      </> : <>
        <PendingNote>
          SafePay v2 consumption evidence is unavailable. No settlement,
          replay-safety, or duplicate-rejection claim is made without recorded
          ledger observations.
        </PendingNote>
        {legacy?.payment_hash && legacy.payment_hash !== HISTORICAL_SAFEPAY_PAYMENT_HASH && <div className="payment-hash-row">
          <HashChip label="Reported payment" value={legacy.payment_hash} />
        </div>}
        <div className="payment-historical-line">
          <Icon name="clock" size={14} />
          <span>Historical native-CSPR payment <code className="mono">{shortHash(HISTORICAL_SAFEPAY_PAYMENT_HASH, 10, 6)}</code> (recorded 2026-06-29) remains a historical artifact only — it backs no replay-safety claim.</span>
        </div>
      </>}
      <p className="payment-footnote">Settled in native CSPR. The single consumption authority is the provider ledger — the UI asserts nothing the ledger has not recorded.</p>
    </div>
  </Panel>;
}

export function OfficialX402Panel({ item }) {
  const green = itemGreenVerified(item);
  return <Panel
    className="payment-panel x402-panel"
    title="Official x402 · WCSPR (CEP-18)"
    eyebrow="Official facilitator settlement — distinct from SafePay Lite (native CSPR)"
    action={item && green
      ? <StatusPill tone="success" compact>verified</StatusPill>
      : <StatusPill tone="warning" compact>pending live verification</StatusPill>}
  >
    <div className="payment-panel-body" data-testid="official-x402-panel">
      {item && green ? <>
        <div className="payment-hash-row">
          {item.settlement_transaction && <HashChip label="Settlement" value={item.settlement_transaction} tone="success" />}
          {item.payment_requirements_hash && <HashChip label="Requirements hash" value={item.payment_requirements_hash} />}
          {item.signed_payment_payload_hash && <HashChip label="Signed payload hash" value={item.signed_payment_payload_hash} />}
        </div>
        <p className="payment-footnote">Wrapped CSPR (WCSPR) token settlement, verified against the governance-bound registry record — never conflated with native CSPR.</p>
      </> : <>
        <div className="x402-gate-state" data-testid="official-x402-blocked">
          <Icon name="lock" size={18} />
          <div>
            <strong>Settlement gate is fail-closed</strong>
            <p>
              The official x402 settlement service starts blocked and only opens
              after a governance-verified v3 registry binding plus a live
              facilitator settlement with <code>success=true</code> and a finalized
              WCSPR transfer. No settlement is claimed until that proof is
              recorded{item ? ` (registry status: ${item.verification_status || "unknown"})` : ""}.
            </p>
          </div>
        </div>
        <p className="payment-footnote">Pays in Wrapped CSPR (WCSPR · CEP-18) via the official facilitator — a separate payment path from SafePay Lite&apos;s native CSPR.</p>
      </>}
    </div>
  </Panel>;
}
