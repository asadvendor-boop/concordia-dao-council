// Approvals: exact action envelope review and the human authorization boundary.
import { useEffect, useState } from "react";
import {
  CARD_LABELS,
  CARD_ROLE,
  CONCORDIA_MODE,
  actionEnvelopeText,
  alteredEnvelope,
  api,
  cardBadge,
  cardSummary,
  cardTone,
  cx,
  deriveProposalFacts,
  getCard,
  getCardData,
  getProfile,
  governancePlaybook,
  isAuthorizedApproval,
  isDeniedApproval,
  isReceiptVerified,
  navHref,
  publicJson,
  shortHash,
  stateLabel,
  stateTone,
  statusTone,
  titleCaseAction,
} from "../lib";
import { Avatar, EmptyState, Icon, PageHeader, Panel, PrimaryButton, RichText, StatusPill } from "../primitives";
import { ProposalSelector } from "../shared";

export function ApprovalPage({ data }) {
  const proposal = data.selectedProposal;
  const cards = data.evidence?.cards || [];
  const facts = deriveProposalFacts(proposal, data.evidence);
  const planCard = getCard(cards, "ResponsePlan", true);
  const plan = getCardData(planCard);
  const envelopes = plan.envelopes || [];
  const approvalCard = getCard(cards, "StructuredApproval", true) || getCard(cards, "PolicyAuthorization", true);
  const receipt = getCard(cards, "CasperExecutionReceipt", true);
  const firstEnvelope = envelopes[0];
  const altered = alteredEnvelope(firstEnvelope);
  // Authorization is NEVER inferred from card presence. The shared fail-closed
  // predicate (lib.js isAuthorizedApproval) requires an affirmative decision
  // bound to THIS proposal and the exact sealed plan hash — a missing
  // proposal_id or plan hash is NOT a match, and no card type (including
  // PolicyAuthorization) is exempt. One-time consumption additionally requires
  // a positively verified Casper receipt.
  const approvalRejected = Boolean(approvalCard) && isDeniedApproval(approvalCard);
  const approvalAuthorized = isAuthorizedApproval(approvalCard, proposal?.proposal_id, planCard);
  const approvalConsumedOnce = approvalAuthorized && isReceiptVerified(receipt);
  // Observed refusal evidence for the deterministic guard preview. The
  // "Blocked before execution" outcome renders ONLY when the gateway reports a
  // genuine recorded refusal artifact (adversarial safety demo with an explicit
  // blocked status); an envelope's mere existence proves nothing was blocked.
  const [refusalArtifact, setRefusalArtifact] = useState(null);
  const refusalProposalId = proposal?.proposal_id || "";
  useEffect(() => {
    setRefusalArtifact(null);
    if (!refusalProposalId) return undefined;
    let cancelled = false;
    api(`/adversarial-safety-demo/${encodeURIComponent(refusalProposalId)}`)
      .then((value) => { if (!cancelled) setRefusalArtifact(value); })
      .catch(() => { if (!cancelled) setRefusalArtifact(null); });
    return () => { cancelled = true; };
  }, [refusalProposalId]);
  const refusalObserved = refusalArtifact?.status === "blocked";
  const approvalHistoryCards = cards.filter((card) => ["Assessment", "Verdict", "ResponsePlan", "StructuredApproval", "PolicyAuthorization", "CasperExecutionReceipt"].includes(card.card_type));
  return <>
    <PageHeader title="Review Exact Governance execution" subtitle={proposal ? `${facts.title} · ${proposal.proposal_id}` : "Human authorization is bound to an exact typed action envelope."} meta={proposal && <div className="page-meta-pills"><StatusPill tone={statusTone(facts.severity, "danger")} compact>{String(facts.severity).toUpperCase()}</StatusPill><StatusPill tone={stateTone(proposal.state)} compact>{stateLabel(proposal.state)}</StatusPill></div>} actions={<ProposalSelector proposals={data.proposals} selectedId={data.selectedId} onSelect={data.selectProposal} />} />
    {!proposal ? <Panel><EmptyState title="No proposal selected" icon="approval" /></Panel> : !planCard ? <Panel><EmptyState title="No response plan is ready" description="Open the Council Chamber to watch the investigation and safety review complete before human approval." icon="approval" action={<PrimaryButton href={navHref("/proposals", proposal.proposal_id)}>Open Proposal Workspace</PrimaryButton>} /></Panel> : <div className="approval-layout">
      <div className="approval-left-column">
      <Panel className="envelope-panel" title="Exact Action Envelope" eyebrow="Human-reviewed execution scope" action={<StatusPill tone="info" icon="shield">Sealed plan</StatusPill>}><div className="envelope-intro"><Icon name="lock" size={24} /><div><strong>The Casper Execution Agent may execute only the action below.</strong><p>Target, parameters, revision and action count are verified again immediately before execution.</p></div></div><div className="envelope-list">{envelopes.map((envelope, index) => <div className="envelope-card" key={`${envelope.action_id}-${index}`}><span className="envelope-number">{index + 1}</span><div className="envelope-fields"><div><span>Action</span><strong>{titleCaseAction(envelope.action_id)}</strong></div><div><span>Target</span><strong>{envelope.target || "—"}</strong></div><div className="wide envelope-parameters-field"><span>Parameters</span><details className="envelope-parameters"><summary>View parameters</summary><pre>{Object.keys(envelope.parameters || {}).length ? publicJson(envelope.parameters, 2) : "{}"}</pre></details></div><div><span>Timeout</span><strong>{envelope.timeout_seconds ? `${envelope.timeout_seconds}s` : "—"}</strong></div><div><span>Fallback action</span><strong>{(envelope.fallback_action || envelope.reversal_action) ? titleCaseAction(envelope.fallback_action || envelope.reversal_action) : "Defined by policy"}</strong></div></div></div>)}</div><div className="plan-integrity-grid"><div><span>Governance playbook</span><strong>{governancePlaybook(plan.governance_playbook || plan.policy_path || plan.runbook)}</strong></div><div><span>Risk level</span><strong>{String(plan.risk_level || facts.severity).toUpperCase()}</strong></div><div><span>Plan revision</span><strong>{plan.revision || 1}</strong></div><div><span>Sealed plan hash</span><strong className="mono">{shortHash(planCard.hash, 12, 8)}</strong></div></div><div className="control-checks"><div><Icon name="check" size={16} /><span><strong>Evidence reviewed</strong><small>Treasury intelligence and safety verdict are sealed</small></span></div><div><Icon name="check" size={16} /><span><strong>Exact parameter binding</strong><small>Any deviation is refused before side effects</small></span></div><div><Icon name="check" size={16} /><span><strong>Exactly-once execution</strong><small>Duplicate and partial plans cannot certify</small></span></div><div><Icon name="shield" size={16} /><span><strong>Receipt gate</strong><small>No receipt without Casper transaction verification</small></span></div></div></Panel>
      <Panel className="approval-history-panel" title="Decision history" eyebrow="Sealed review trail"><div className="approval-history">{approvalHistoryCards.map((card) => { const profile = getProfile(CARD_ROLE[card.card_type]); return <div key={`${card.sequence}-${card.card_type}`}><Avatar profile={profile} size="xs" /><span><strong>{profile.name}</strong><small>{CARD_LABELS[card.card_type]}</small></span><p><RichText value={cardSummary(card)} hashChips /></p><StatusPill tone={cardTone(card)} compact>{cardBadge(card)}</StatusPill></div>; })}</div></Panel>
      </div>
      <div className="approval-right-column"><Panel title="Multisig decision" eyebrow={approvalAuthorized ? (approvalConsumedOnce ? "Authorization consumed once" : "Authorization recorded") : approvalRejected ? "Authorization rejected" : "Action required"}><div className="decision-panel"><div className={cx("decision-icon", approvalAuthorized ? "approved" : approvalRejected ? "rejected" : "pending")}><Icon name={approvalAuthorized ? "check" : approvalRejected ? "signal" : "human"} size={28} /></div><h3>{approvalAuthorized ? "Exact action authorized" : approvalRejected ? "Authorization rejected" : "Authorization boundary visible"}</h3><p>{approvalAuthorized
        ? (approvalConsumedOnce
          ? "The sealed approval is bound to this proposal and the exact plan/action hash, and a verified receipt proves it was consumed exactly once."
          : "The sealed approval is bound to this proposal and the exact plan/action hash. One-time consumption is confirmed only from a positively verified receipt.")
        : approvalRejected
          ? "The recorded decision did not authorize execution. No exact action is authorized for this proposal."
          : CONCORDIA_MODE === "reviewer"
            ? "The mutating approval form is protected behind Caddy and Basic Auth. This public view exposes the exact envelope judges need to inspect without exposing signing controls."
            : "Open the protected approval page to inspect, approve or reject the exact action."}</p>{approvalAuthorized
        ? <StatusPill tone={approvalConsumedOnce ? "success" : "warning"} icon={approvalConsumedOnce ? "check" : "clock"}>{approvalConsumedOnce ? "Authorization verified and consumed" : "Authorization recorded · execution unconfirmed"}</StatusPill>
        : approvalRejected
          ? <StatusPill tone="danger" icon="signal">Not authorized</StatusPill>
          : (CONCORDIA_MODE === "reviewer" ? <StatusPill tone="warning" icon="lock">Protected form disabled</StatusPill> : <PrimaryButton icon="external" href={`/approve/${proposal.proposal_id}`}>Open Secure Approval</PrimaryButton>)}<div className="decision-warning"><Icon name="signal" size={17} />Approval applies only to this action, target and exact parameters.</div></div></Panel><Panel title="Deterministic guard preview" eyebrow="Why exact authorization matters">{firstEnvelope ? <div className="tamper-preview"><div className="tamper-row exact"><span>Approved exact request</span><code>{actionEnvelopeText(firstEnvelope)}</code></div><div className="tamper-row altered"><span>Any altered request</span><code>{actionEnvelopeText(altered)}</code></div>{refusalObserved
        ? <div className="tamper-result"><Icon name="lock" size={18} /><div><strong>Blocked before execution</strong><small>{refusalArtifact.locke_result === "refused_to_sign" ? "Recorded refusal artifact · Locke refused to sign the altered envelope · no side effect occurred" : "Recorded refusal artifact · canonical envelope mismatch · no side effect occurred"}</small></div></div>
        : <div className="tamper-result tamper-unavailable" data-testid="tamper-refusal-unavailable"><Icon name="clock" size={18} /><div><strong>Refusal artifact unavailable</strong><small>No blocked-tamper outcome is asserted until the gateway reports a recorded refusal artifact for this proposal.</small></div></div>}</div> : <EmptyState title="No envelope available" icon="lock" />}</Panel><Panel title="Execution status" eyebrow="Certified workflow"><div className="execution-status-line">{[{ label: "Planned", done: Boolean(planCard) }, { label: "Authorized", done: approvalAuthorized }, { label: "Executed", done: isReceiptVerified(receipt) }, { label: "Receipt", done: facts.receiptVerified }].map((item, index, list) => <div key={item.label} className={cx("execution-status-step", item.done && "done")}><span>{item.done ? <Icon name="check" size={13} /> : null}</span><small>{item.label}</small>{index < list.length - 1 && <i />}</div>)}</div><div className="execution-note"><Icon name="info" size={16} />Execution starts only after the Gateway validates the consumed authorization. The Receipt step completes only on a positively verified receipt.</div></Panel></div>
    </div>}
  </>;
}
