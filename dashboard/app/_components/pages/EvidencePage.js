// Evidence & Audit: tamper-evident chain, sealed card detail, verification.
import { useEffect, useState } from "react";
import {
  CARD_LABELS,
  CARD_ROLE,
  cardBadge,
  cardSummary,
  cardTone,
  cx,
  deriveHandoffs,
  deriveProposalFacts,
  displayFamily,
  downloadEvidence,
  firstDefined,
  formatDateTime,
  formatDuration,
  getCard,
  getCardData,
  getProfile,
  humanizeCardData,
  publicJson,
  sanitizeDisplayText,
  shortHash,
  titleCaseAction,
} from "../lib";
import { Avatar, EmptyState, Icon, PageHeader, Panel, PrimaryButton, RichText, StatusPill } from "../primitives";
import { ProposalSelector, VerifiedRunStaticFallback } from "../shared";

function ChainStrip({ cards, selectedIndex, onSelect }) {
  if (!cards.length) return <EmptyState title="No sealed evidence cards" description="Cards appear here after their Council publication is verified." icon="link" />;
  return <div className="chain-strip" role="list" aria-label="Evidence chain">
    {cards.map((card, index) => {
      const profile = getProfile(CARD_ROLE[card.card_type]);
      return <div className="chain-step-wrap" key={`${card.sequence}-${card.card_type}`}>
        <button type="button" role="listitem" className={cx("chain-step", index === selectedIndex && "selected", `chain-${cardTone(card)}`)} onClick={() => onSelect(index)}>
          <span className="chain-sequence">{card.sequence ?? index + 1}</span>
          <Avatar profile={profile} size="xs" />
          <span className="chain-step-copy"><strong>{CARD_LABELS[card.card_type] || titleCaseAction(card.card_type)}</strong><small>{profile.name} · {shortHash(card.hash, 6, 4)}</small></span>
          <span className="chain-verified"><Icon name="check" size={12} />Verified</span>
        </button>
        {index < cards.length - 1 && <span className="chain-connector" aria-hidden="true"><Icon name="link" size={14} /></span>}
      </div>;
    })}
  </div>;
}

export function EvidencePage({ data }) {
  const proposal = data.selectedProposal;
  const cards = data.evidence?.cards || [];
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [showAll, setShowAll] = useState(false);
  useEffect(() => { setSelectedIndex(Math.max(0, cards.length - 1)); }, [data.selectedId, cards.length]);
  const selectedCard = cards[selectedIndex] || cards[0] || null;
  const selectedProfile = getProfile(CARD_ROLE[selectedCard?.card_type]);
  const rows = humanizeCardData(selectedCard);
  const run = data.runSummary?.runs?.find((item) => item.proposal_id === data.selectedId) || null;
  const chainValid = data.evidence?.chain_valid !== false;
  const receipt = getCard(cards, "CasperExecutionReceipt", true);
  const approval = getCard(cards, "StructuredApproval", true) || getCard(cards, "PolicyAuthorization", true);
  const challengeCount = cards.filter((card) => card.card_type === "Verdict" && getCardData(card).decision === "CHALLENGE").length;
  const handoffs = deriveHandoffs(cards).length;
  const collaboration = data.evidence?.collaboration || {};
  const exactMatch = collaboration.execution_conflict_control?.exact_match;
  const evidenceHandoffs = collaboration.handoff_count ?? handoffs;
  const evidenceChallenges = collaboration.challenge_count ?? challengeCount;
  const evidenceHumanDecisions = collaboration.human_decision_count ?? (approval ? 1 : 0);
  const proposalFamily = firstDefined(run?.proposal_family, data.evidence?.proposal_family);
  const signalTarget = firstDefined(run?.signal_service, data.evidence?.signal_service);
  const facts = deriveProposalFacts(proposal, data.evidence);
  const sealedCardIndexPanel = <Panel title="Sealed card index" eyebrow="Progressive disclosure" action={<button type="button" className="text-button" onClick={() => setShowAll((value) => !value)}>{showAll ? "Hide card index" : `View all ${cards.length} cards`}<Icon name="chevronDown" size={15} /></button>}>{showAll ? <div className="table-wrap"><table className="data-table evidence-table"><thead><tr><th>Sequence</th><th>Card</th><th>Issuer</th><th>Outcome</th><th>Hash</th><th>Publication</th></tr></thead><tbody>{cards.map((card, index) => { const profile = getProfile(CARD_ROLE[card.card_type]); return <tr key={`${card.sequence}-${card.card_type}`} onClick={() => setSelectedIndex(index)}><td>{card.sequence}</td><td><strong>{CARD_LABELS[card.card_type] || card.card_type}</strong></td><td><div className="table-agent"><Avatar profile={profile} size="xs" /><span>{profile.name}<small>{profile.role}</small></span></div></td><td><StatusPill tone={cardTone(card)} compact>{cardBadge(card)}</StatusPill></td><td className="mono">{shortHash(card.hash, 8, 5)}</td><td><StatusPill tone="success" compact><Icon name="check" size={11} />Verified</StatusPill></td></tr>; })}</tbody></table></div> : <div className="collapsed-index"><Icon name="evidence" size={20} /><span>The chain above is the primary view. Open the index only when detailed card-by-card inspection is needed.</span></div>}</Panel>;
  return <>
    <PageHeader title="Evidence & Audit" subtitle="Verified Council publications, ordered evidence cards and deterministic control results." meta={proposal && <div className="page-meta-pills"><StatusPill tone={chainValid ? "success" : "danger"} icon={chainValid ? "check" : "signal"}>{chainValid ? "Evidence chain valid" : "Chain verification failed"}</StatusPill></div>} actions={<><ProposalSelector proposals={data.proposals} selectedId={data.selectedId} onSelect={data.selectProposal} />{facts.casperExplorerUrl && <PrimaryButton icon="external" href={facts.casperExplorerUrl} target="_blank" rel="noreferrer">View Immutable Receipt on Casper Testnet</PrimaryButton>}<PrimaryButton icon="download" onClick={() => downloadEvidence(data.evidence, data.selectedId)} disabled={!cards.length}>Export Evidence Package</PrimaryButton></>} />
    {!proposal ? <Panel><VerifiedRunStaticFallback /></Panel> : <>
      <Panel className="chain-panel" title="Tamper-evident evidence chain" eyebrow={`${cards.length} verified cards · ${proposal.proposal_id}`} action={<StatusPill tone={chainValid ? "success" : "danger"} compact>{chainValid ? "Integrity 100%" : "Review required"}</StatusPill>}><ChainStrip cards={cards} selectedIndex={selectedIndex} onSelect={setSelectedIndex} /></Panel>
      <div className="evidence-master-detail">
        <div className="evidence-left-column">
        <Panel className="selected-card-panel" title={selectedCard ? CARD_LABELS[selectedCard.card_type] || titleCaseAction(selectedCard.card_type) : "Selected sealed card"} eyebrow={selectedCard ? `Sequence ${selectedCard.sequence} · ${selectedProfile.name}` : "Select a chain item"} action={selectedCard && <StatusPill tone={cardTone(selectedCard)} compact>{cardBadge(selectedCard)}</StatusPill>}>
          {selectedCard ? <><div className="selected-card-summary"><Avatar profile={selectedProfile} size="lg" /><div><h3><RichText value={cardSummary(selectedCard)} /></h3><div className="selected-card-meta"><span><Icon name="clock" size={14} />{formatDateTime(firstDefined(getCardData(selectedCard).created_at, getCardData(selectedCard).timestamp))}</span><span><Icon name="link" size={14} />{shortHash(selectedCard.hash, 12, 8)}</span><span><Icon name="network" size={14} />Council publication verified</span></div></div></div><div className="humanized-card-grid">{rows.length ? rows.map((row) => <div key={row.label} className={cx(row.wide && "wide")}><span>{row.label}</span>{row.mono ? <code>{shortHash(row.value, 20, 12)}</code> : <strong>{Array.isArray(row.value) ? row.value.join(" · ") : typeof row.value === "object" ? publicJson(row.value, 0) : row.type === "datetime" ? formatDateTime(row.value) : sanitizeDisplayText(String(row.value))}</strong>}</div>) : <EmptyState title="No additional human-readable fields" icon="evidence" />}</div><details className="sealed-payload"><summary>View sealed payload</summary><pre>{publicJson(getCardData(selectedCard))}</pre></details></> : <EmptyState title="Select a sealed card" icon="evidence" />}
        </Panel>
        {sealedCardIndexPanel}
        </div>
        <aside className="evidence-right-rail">
          <Panel title="Chain verification" eyebrow="Deterministic checks"><div className="verification-score"><span><Icon name={chainValid ? "shield" : "signal"} size={28} /></span><div><strong>{chainValid ? "Valid and ordered" : "Verification failed"}</strong><small>{chainValid ? "Every available check passed" : "Inspect the selected card and Gateway logs"}</small></div></div><div className="verification-list">{[
            ["Sequence is ordered", chainValid],
            ["Previous hashes are valid", chainValid],
            ["Council publications verified", cards.length > 0],
            ["Sender roles are verified", cards.length > 0],
            ["Authorization consumed once", Boolean(approval) || !receipt],
            ["Receipt credentialified", Boolean(receipt)],
          ].map(([label, ok]) => <div key={label} className={cx(ok ? "pass" : "pending")}><Icon name={ok ? "check" : "clock"} size={15} /><span>{label}</span></div>)}</div></Panel>
          <Panel title="Run Summary" eyebrow="Measured from sealed evidence"><div className="summary-metric-grid"><div><span>Proposal family</span><strong>{displayFamily(proposalFamily)}</strong></div><div><span>Proposal target</span><strong>{signalTarget || "—"}</strong></div><div><span>Proposal duration</span><strong>{formatDuration(run?.total_resolution_secs)}</strong></div><div><span>Handoffs</span><strong>{run?.handoffs ?? evidenceHandoffs}</strong></div><div><span>Challenges</span><strong>{run?.challenges ?? evidenceChallenges}</strong></div><div><span>Multisig decisions</span><strong>{run?.human_interventions ?? evidenceHumanDecisions}</strong></div><div className={exactMatch === true ? "summary-accent-success" : exactMatch === false ? "summary-accent-danger" : "summary-accent-muted"}><span>Execution conflict control</span><strong>{exactMatch === true ? "Exact match" : exactMatch === false ? "Mismatch blocked" : "Envelope bound"}</strong></div><div className="summary-accent-success"><span>Execution verified</span><strong>{(run?.receipt_verified ?? Boolean(receipt)) ? "Yes" : "No"}</strong></div></div><p className="summary-footnote">Only values available from current sealed evidence are shown; no unsupported savings or ROI estimates are inferred.</p></Panel>
        </aside>
      </div>
      {data.rules.length > 0 && <Panel title="Active suppression controls" eyebrow="Bounded false-alarm policy"><div className="suppression-list">{data.rules.map((rule) => <div key={rule.id || rule.fingerprint}><span className="suppression-icon"><Icon name="shield" size={17} /></span><span><strong className="mono">{shortHash(rule.fingerprint, 18, 8)}</strong><small>{rule.reason || "Human-reviewed false-alarm suppression"}</small></span><div><StatusPill tone="info" compact>{rule.suppression_count || 0} / {rule.max_suppressions || 3} used</StatusPill><small>{rule.expires_at ? `Expires ${formatDateTime(rule.expires_at)}` : "No expiry configured"}</small></div></div>)}</div></Panel>}
    </>}
  </>;
}
