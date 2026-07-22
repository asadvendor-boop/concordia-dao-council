// The four-outcome exact-envelope v3 sequence, rendered exclusively from data
// (proof-registry item checks or an equivalent payload block). Expected
// rejections render as POSITIVE proof; nothing renders green unless the
// registry item satisfies the section-13 green predicate. With no data, an
// honest pending state renders — no outcome is ever asserted from literals.
import { cx } from "./lib";
import { itemGreenVerified } from "./provenance";
import { Icon, Panel, PendingNote, StatusPill } from "./primitives";

// Check-name -> outcome metadata, per the section-6 pinned error table:
// 8 QuorumNotMet · 10 EnvelopeHashMismatch · 12 AlreadyFinalized ·
// 13 ActionAlreadyAuthorized.
export const V3_OUTCOME_STEPS = [
  { check: "pre_quorum_finalize_reverted_with_code_8", code: 8, errorName: "QuorumNotMet", label: "Finalize before quorum", kind: "expected_rejection" },
  { check: "post_quorum_mutated_envelope_reverted_with_code_10", code: 10, errorName: "EnvelopeHashMismatch", label: "Mutated envelope after quorum", kind: "expected_rejection" },
  { check: "exact_envelope_finalization_accepted", code: null, errorName: null, label: "Exact envelope finalization", kind: "accepted" },
  { check: "repeat_finalization_reverted_with_code_12", code: 12, errorName: "AlreadyFinalized", label: "Repeat finalization", kind: "expected_rejection" },
  { check: "repeat_authorization_reverted_with_code_13", code: 13, errorName: "ActionAlreadyAuthorized", label: "Repeat authorization", kind: "expected_rejection", optional: true },
];

export function V3Sequence({ item }) {
  const checks = Array.isArray(item?.checks) ? item.checks : [];
  const byName = new Map(checks.map((check) => [check?.name, check]));
  const green = itemGreenVerified(item);
  const hasSequenceData = V3_OUTCOME_STEPS.some((step) => byName.has(step.check));
  return <Panel
    className="v3-sequence-panel"
    title="Exact-envelope v3 sequence"
    eyebrow="Four outcomes · enforced on-chain, rendered from data"
    action={item
      ? <StatusPill tone={green ? "success" : "warning"} compact>{green ? "verified" : item.verification_status || "pending"}</StatusPill>
      : <StatusPill tone="muted" compact>pending</StatusPill>}
  >
    {!item || !hasSequenceData ? (
      <div className="v3-pending" data-testid="v3-sequence-pending">
        <PendingNote>
          The v3 sequence is pending live verification. The four outcomes
          (pre-quorum revert, mutated-envelope revert, exact acceptance, repeat
          revert) will render here from recorded registry checks — no outcome is
          asserted until the proof registry publishes them.
        </PendingNote>
      </div>
    ) : (
      <div className="v3-sequence" data-testid="v3-sequence">
        {V3_OUTCOME_STEPS.map((step) => {
          const check = byName.get(step.check);
          if (!check && step.optional) return null;
          if (!check) {
            return <article key={step.check} className="v3-outcome v3-outcome-pending">
              <span className="v3-outcome-index"><Icon name="clock" size={15} /></span>
              <div>
                <strong>{step.label}</strong>
                <p>Not yet observed — no result asserted.</p>
              </div>
              <StatusPill tone="muted" compact>pending</StatusPill>
            </article>;
          }
          const passed = check.passed === true;
          const positive = passed && green;
          const recordedNotVerified = passed && !green;
          const failureLabel = step.kind === "accepted" ? "check failed" : "unexpected result";
          return <article
            key={step.check}
            className={cx(
              "v3-outcome",
              positive && (step.kind === "accepted" ? "v3-outcome-accepted" : "v3-outcome-proof"),
              recordedNotVerified && "v3-outcome-recorded",
              !passed && "v3-outcome-failed",
            )}
            data-outcome-code={step.code ?? "accepted"}
          >
            <span className="v3-outcome-index">{positive ? <Icon name={step.kind === "accepted" ? "check" : "lock"} size={15} /> : <Icon name={passed ? "clock" : "signal"} size={15} />}</span>
            <div>
              <strong>{step.label}</strong>
              <p>
                {step.kind === "accepted"
                  ? "Accepted · anchored with the exact approved envelope hash"
                  : <>Reverted · error {step.code} — <span className="v3-error-name">{step.errorName}</span></>}
              </p>
              {check.detail_code && <small className="mono">{check.detail_code}</small>}
            </div>
            {positive && step.kind === "expected_rejection" && <StatusPill tone="success" compact>Expected rejection · proof</StatusPill>}
            {positive && step.kind === "accepted" && <StatusPill tone="success" compact>Accepted</StatusPill>}
            {recordedNotVerified && <StatusPill tone="warning" compact>recorded · not verified</StatusPill>}
            {!passed && <StatusPill tone="danger" compact>{failureLabel}</StatusPill>}
          </article>;
        })}
        <p className="v3-sequence-note">Every outcome above derives from a recorded registry check. An expected rejection is proof the chain enforced the rule — it is never a failure.</p>
      </div>
    )}
  </Panel>;
}
