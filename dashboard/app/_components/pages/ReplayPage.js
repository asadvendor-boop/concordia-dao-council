// Runs & Verified Replay, including the recording-mode cinema view.
import { useEffect, useState } from "react";
import {
  CARD_LABELS,
  CARD_ROLE,
  CONCORDIA_MODE,
  DEFAULT_REVIEW_PROPOSAL_ID,
  TERMINAL_STATES,
  cardBadge,
  cardTone,
  cardSummary,
  cx,
  deriveHandoffs,
  deriveProposalFacts,
  displayFamily,
  downloadEvidence,
  firstDefined,
  formatDateTime,
  formatDuration,
  formatPercent,
  getCardData,
  getProfile,
  humanizeCardData,
  isReceiptVerified,
  publicJson,
  replayEventTitle,
  replayStageLabel,
  sanitizeDisplayText,
  titleCaseAction,
} from "../lib";
import { Avatar, HashChip, Icon, PageHeader, Panel, PrimaryButton, RichText, StatusPill, useRecordingMode, EmptyState } from "../primitives";
import { ProofActionBar } from "../proof-actions";
import { ProposalSelector, VerifiedRunStaticFallback } from "../shared";

function DaoScoreboard({ summary }) {
  const speedup = summary?.speedup_factor;
  const baseline = summary?.manual_baseline_secs;
  const avgTotal = summary?.avg_total_resolution_secs;
  const disagreementEvents = summary?.disagreement_events ?? summary?.total_challenges_issued;
  const disagreementDetail = summary?.disagreement_events != null
    ? `Challenges ${summary?.total_challenges_issued ?? 0} · rejections ${summary?.total_human_rejections ?? 0}`
    : "Risk & Legal Agent challenges and human revisions";
  const cards = [
    { label: "Role handoffs", value: summary?.total_handoffs ?? "—", detail: "Task division across published card owners", icon: "network", tone: "blue" },
    { label: "Disagreement events", value: disagreementEvents ?? "—", detail: disagreementDetail, icon: "shield", tone: "purple" },
    { label: "Multisig decisions", value: summary?.human_interventions ?? "—", detail: "Approve, reject, or false-alarm choices", icon: "human", tone: "amber" },
    { label: "Baseline speedup", value: speedup ? `${speedup}×` : "Configure", detail: baseline && avgTotal ? `${formatDuration(baseline)} single-agent baseline vs ${formatDuration(avgTotal)} same-family Concordia runs` : "Baseline comparison is operator-configurable for same-family proof.", icon: "activity", tone: speedup ? "green" : "muted" },
  ];
  return <Panel title="DAO collaboration scorecard" eyebrow="Task division · negotiation · efficiency"><div className="dao-score-grid">{cards.map((item) => <div key={item.label} className={cx("dao-score-card", `dao-${item.tone}`)}><span><Icon name={item.icon} size={18} /></span><div><strong>{item.value}</strong><small>{item.label}</small><p>{item.detail}</p></div></div>)}</div></Panel>;
}

export function ReplayPage({ data }) {
  const terminalProposals = data.proposals.filter((proposal) => TERMINAL_STATES.has(String(proposal.state || "").toUpperCase()));
  const cards = data.evidence?.cards || [];
  // Only an explicit gateway-reported chain_valid===true is "valid"; missing is
  // unknown (never rendered as a green sealed/verified claim).
  const chainValid = data.evidence?.chain_valid === true;
  // "Verified" labels/tones additionally require the evidence payload to be
  // BOUND to the selected proposal (the gateway stamps proposal_id into the
  // public evidence export). chain_valid alone on an unbound/mismatched
  // payload proves nothing about the proposal on screen.
  const evidenceBound = Boolean(data.selectedId) && data.evidence?.proposal_id === data.selectedId;
  const replayVerified = chainValid && evidenceBound;
  // Payload-derived receipt claim: a receipt chip may only cite a receipt
  // that is positively verified inside THIS bound payload, with a
  // well-formed 64-hex deploy hash — never a static literal.
  const receiptClaimCard = cards.find((card) => card.card_type === "CasperExecutionReceipt");
  const receiptClaimTx = receiptClaimCard ? getCardData(receiptClaimCard).actions_taken?.[0]?.transaction_hash : undefined;
  const boundReceiptHash = replayVerified
    && isReceiptVerified(receiptClaimCard)
    && typeof receiptClaimTx === "string"
    && /^[0-9a-f]{64}$/.test(receiptClaimTx)
    ? receiptClaimTx
    : null;
  const [index, setIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const recordingMode = useRecordingMode();
  useEffect(() => {
    if (!terminalProposals.length) return;
    const selectedIsTerminal = terminalProposals.some((proposal) => proposal.proposal_id === data.selectedId);
    if (!selectedIsTerminal) data.selectProposal(terminalProposals[0].proposal_id);
  }, [terminalProposals, data.selectedId, data.selectProposal]);
  useEffect(() => { setIndex(0); setPlaying(false); }, [data.selectedId]);
  useEffect(() => {
    if (!playing || cards.length < 2) return;
    const timer = setInterval(() => setIndex((current) => {
      if (current >= cards.length - 1) { setPlaying(false); return current; }
      return current + 1;
    }), 2600 / speed);
    return () => clearInterval(timer);
  }, [playing, speed, cards.length]);
  const card = cards[index] || null;
  const profile = getProfile(CARD_ROLE[card?.card_type]);
  const facts = deriveProposalFacts(data.selectedProposal, data.evidence);
  // Execution/anchoring telemetry uses the SAME bound replay predicate as
  // every other verified label: a verified receipt alone (no bound valid
  // evidence chain for the selected proposal) never claims verification.
  const executionVerified = replayVerified && facts.receiptVerified;
  const run = data.runSummary?.runs?.find((item) => item.proposal_id === data.selectedId) || null;
  const proposalFamily = firstDefined(run?.proposal_family, data.evidence?.proposal_family);
  const progress = cards.length > 1 ? (index / (cards.length - 1)) * 100 : 0;
  const rows = humanizeCardData(card).slice(0, 4);
  const safeSelectOptions = terminalProposals.length ? terminalProposals : data.proposals;
  useEffect(() => {
    if (!recordingMode) return undefined;
    const handleKey = (event) => {
      if (event.key === "ArrowRight" || event.key === " ") {
        event.preventDefault();
        setPlaying(false);
        setIndex((current) => Math.min(cards.length - 1, current + 1));
      }
      if (event.key === "ArrowLeft") {
        event.preventDefault();
        setPlaying(false);
        setIndex((current) => Math.max(0, current - 1));
      }
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [recordingMode, cards.length]);
  if (recordingMode && card) {
    return <>
      <PageHeader
        title={replayVerified ? "Verified Run Replay" : "Recorded Run Replay"}
        subtitle={replayVerified
          ? "Cinema mode shows one sealed evidence card at a time for clean demo recording."
          : "Cinema mode shows one recorded evidence card at a time. Verification labels appear only when the gateway reports a valid chain for this proposal."}
        meta={<div className="page-meta-pills"><StatusPill tone={replayVerified ? "success" : "info"} icon="shield">Recording mode</StatusPill><StatusPill tone="info">{index + 1} / {cards.length}</StatusPill></div>}
        actions={<ProofActionBar
          compact
          proposalId={data.selectedId || DEFAULT_REVIEW_PROPOSAL_ID}
          // The receipt shortcut may only cite a receipt verified inside THIS
          // bound payload — the static canonical literal never renders here.
          actionIds={boundReceiptHash ? ["canonical_receipt", "certificate_html"] : ["certificate_html"]}
          overridesById={boundReceiptHash ? { canonical_receipt: { label: "Casper Receipt", tooltip: "Open this recording's verified Casper receipt on Casper Testnet.", href: () => `https://testnet.cspr.live/deploy/${boundReceiptHash}` } } : {}}
        />}
      />
      <section className="recording-story-board replay-recording">
        <div className="recording-progress-rail" aria-label="Replay progress">
          {cards.map((item, cardIndex) => <button key={`${item.sequence}-${item.card_type}`} type="button" className={cx(cardIndex === index && "active", cardIndex < index && "complete")} onClick={() => { setPlaying(false); setIndex(cardIndex); }}>{cardIndex < index ? <Icon name="check" size={13} /> : cardIndex + 1}</button>)}
        </div>
        <Panel className="recording-step-panel" eyebrow={`${replayVerified ? "Sealed" : "Recorded"} card ${card.sequence || index + 1}`} title={replayEventTitle(card)}>
          {/* Historical replay card: the persona authored a recorded sealed card;
              that is not live presence, so no online dot is shown. */}
          <div className="replay-recording-agent"><Avatar profile={profile} size="xl" /><div><strong>{profile.name}</strong><span>{profile.role}</span></div><StatusPill tone={cardTone(card)} compact>{cardBadge(card)}</StatusPill></div>
          <p>{cardSummary(card)}</p>
          {rows.length ? <div className="replay-detail-list">{rows.slice(0, 3).map((row) => <div key={row.label}><span>{row.label}</span><strong>{Array.isArray(row.value) ? row.value.join(" · ") : typeof row.value === "object" ? publicJson(row.value, 0) : sanitizeDisplayText(String(row.value))}</strong></div>)}</div> : null}
          {/* Proof chips are payload-derived only: the evidence-chain chip
              renders the card's own hash (never a default stand-in), and the
              canonical-receipt chip renders ONLY for the verified canonical
              proposal — an unverified or non-canonical replay shows no
              receipt claim at all. */}
          <div className="recording-proof-chips">{card.hash ? <HashChip label="Evidence chain" value={card.hash} /> : null}{boundReceiptHash ? <HashChip label="Casper receipt" value={boundReceiptHash} href={`https://testnet.cspr.live/deploy/${boundReceiptHash}`} tone="success" /> : null}</div>
          <div className="recording-controls">
            <PrimaryButton tone="secondary" icon="previous" onClick={() => setIndex((current) => Math.max(0, current - 1))} disabled={index === 0}>Previous</PrimaryButton>
            <PrimaryButton icon="next" onClick={() => setIndex((current) => Math.min(cards.length - 1, current + 1))} disabled={index >= cards.length - 1}>Next sealed card</PrimaryButton>
          </div>
        </Panel>
      </section>
    </>;
  }
  return <>
    <PageHeader title={replayVerified ? "Runs & Verified Replay" : "Runs & Recorded Replay"} subtitle={replayVerified ? "A public, read-only reconstruction of a verified live proposal run." : "A public, read-only reconstruction of a recorded proposal run. Verification labels appear only when the gateway reports a valid chain for this proposal."} actions={<><ProposalSelector proposals={safeSelectOptions} selectedId={data.selectedId} onSelect={data.selectProposal} terminalOnly={terminalProposals.length > 0} /><PrimaryButton tone="secondary" icon="download" onClick={() => downloadEvidence(data.evidence, data.selectedId)}>Export Read-only Evidence</PrimaryButton></>} />
    <div className="reviewer-banner"><span><Icon name="info" size={23} /></span><div><strong>{CONCORDIA_MODE === "reviewer" ? "Public Review Mode" : replayVerified ? "Verified Run Preview" : "Recorded Run Preview"}</strong><p>{CONCORDIA_MODE === "reviewer" ? "This page replays a sanitized proposal recorded with live LLM model integrations. Paid and mutating actions are disabled during public review." : "Use this view to rehearse the reviewer experience before switching the public deployment to read-only mode."}</p></div><StatusPill tone="info" icon="lock">Read-only</StatusPill></div>
    <DaoScoreboard summary={data.runSummary?.summary} />
    {!data.selectedProposal ? <Panel><VerifiedRunStaticFallback /></Panel> : !cards.length ? <Panel><EmptyState title="This proposal has no replayable evidence yet" description="Select a completed run with a sealed card chain." icon="replay" /></Panel> : <>
      <Panel className="replay-stage-panel" noPadding>
        <div className="replay-workflow"><div className="replay-workflow-track">{cards.map((item, cardIndex) => <button key={`${item.sequence}-${item.card_type}`} type="button" className={cx("replay-stage", cardIndex < index && "complete", cardIndex === index && "current")} onClick={() => { setPlaying(false); setIndex(cardIndex); }}><span>{cardIndex < index ? <Icon name="check" size={12} /> : cardIndex + 1}</span><small>{replayStageLabel(item)}</small></button>)}</div></div>
        <div className="replay-controls"><button type="button" className="button button-primary" onClick={() => setPlaying((value) => !value)}><Icon name={playing ? "pause" : "play"} size={16} />{playing ? "Pause" : index >= cards.length - 1 ? "Replay" : "Play"}</button><button type="button" className="button button-ghost" onClick={() => { setPlaying(false); setIndex(Math.max(0, index - 1)); }} disabled={index === 0}><Icon name="previous" size={16} />Previous</button><button type="button" className="button button-ghost" onClick={() => { setPlaying(false); setIndex(Math.min(cards.length - 1, index + 1)); }} disabled={index >= cards.length - 1}>Next handoff<Icon name="next" size={16} /></button><div className="speed-control"><button className={cx(speed === 1 && "active")} type="button" onClick={() => setSpeed(1)}>1×</button><button className={cx(speed === 2 && "active")} type="button" onClick={() => setSpeed(2)}>2×</button></div><span className="replay-counter">{index + 1} / {cards.length}</span><div className="replay-progress"><span style={{ width: `${progress}%` }} /><i style={{ left: `${progress}%` }} /></div></div>
        <div className="replay-main-grid"><div className="replay-current-event"><div className="replay-agent-column"><Avatar profile={profile} size="xl" /><h2>{profile.name}</h2><p>{profile.role}</p><span>{profile.framework} · {profile.model}</span><StatusPill tone={cardTone(card)} compact>{cardBadge(card)}</StatusPill></div><div className="replay-event-copy">{/* "Verified handoff" only when the observed evidence chain reports
              chain_valid === true AND the payload is bound to the selected
              proposal; otherwise the handoff is honestly recorded. */}<div className="eyebrow">{replayVerified ? "Verified handoff" : "Recorded handoff"} · sequence {card.sequence}</div><h2>{replayEventTitle(card)}</h2><p className="replay-event-summary"><RichText value={cardSummary(card)} /></p>{rows.length ? <div className="replay-detail-list">{rows.map((row) => <div key={row.label}><span>{row.label}</span><strong>{Array.isArray(row.value) ? row.value.join(" · ") : typeof row.value === "object" ? publicJson(row.value, 0) : <RichText value={String(row.value)} hashChips />}</strong></div>)}</div> : null}<div className="replay-integrity-note"><Icon name={replayVerified ? "shield" : "clock"} size={18} /><span><strong>{replayVerified ? "Publication and identity verified" : "Reconstructed from recorded evidence"}</strong><small>{replayVerified ? "This event is reconstructed from sealed Gateway evidence, not a fabricated animation." : "This event is reconstructed from recorded Gateway evidence. Verification is asserted only when the gateway reports a valid chain for this proposal."}</small></span></div></div></div>
        <aside className="replay-right-rail"><div className="replay-rail-card"><span>Current workflow state</span><strong>{CARD_LABELS[card.card_type] || titleCaseAction(card.card_type)}</strong><small>{formatDateTime(firstDefined(getCardData(card).created_at, getCardData(card).timestamp))}</small></div><div className="replay-rail-card"><span>Proposal family</span><strong>{displayFamily(proposalFamily)}</strong><small>Baseline proof uses same-family runs</small></div><div className="replay-rail-card"><span>Proposal duration</span><strong>{formatDuration(run?.total_resolution_secs)}</strong><small>{run?.handoffs ?? deriveHandoffs(cards).length} {replayVerified ? "verified" : "recorded"} handoffs</small></div><div className="replay-rail-card"><span>Evidence-chain status</span><strong className={replayVerified ? "success-text" : ""}>{data.evidence?.chain_valid === false ? "Verification failed" : replayVerified ? "Valid and sealed" : "Validity unavailable"}</strong><small>{cards.length} ordered cards</small></div><div className="replay-rail-card"><span>Execution conflict resolution</span><strong>Exact action only</strong><small>Altered requests are blocked before side effects</small></div></aside></div>
      </Panel>
      <Panel title="Execution telemetry" eyebrow="Before → after · measured during the recorded run"><div className="replay-metrics"><div className={cx("metric-comparison", "danger-to-success", facts.postMetrics.errorRate === undefined && "telemetry-neutral")}><span><Icon name="activity" size={18} />Risk exposure</span><div><strong>{formatPercent(facts.preMetrics.errorRate)}</strong><Icon name="arrowRight" size={18} /><strong>{formatPercent(facts.postMetrics.errorRate)}</strong></div><small>{replayVerified ? "Proposal → anchored" : "Proposal → recorded"}</small></div><div className={cx("metric-comparison", "danger-to-success", facts.postMetrics.volatility === undefined && "telemetry-neutral")}><span><Icon name="clock" size={18} />Treasury volatility</span><div><strong>{facts.preMetrics.volatility !== undefined ? `${facts.preMetrics.volatility} bps` : "—"}</strong><Icon name="arrowRight" size={18} /><strong>{facts.postMetrics.volatility !== undefined ? `${facts.postMetrics.volatility} bps` : "—"}</strong></div><small>risk exposure delta</small></div><div className={cx("metric-comparison", "danger-to-success", facts.postMetrics.uptime === undefined && "telemetry-neutral")}><span><Icon name="shield" size={18} />Policy compliance</span><div><strong>{formatPercent(facts.preMetrics.uptime)}</strong><Icon name="arrowRight" size={18} /><strong>{formatPercent(facts.postMetrics.uptime)}</strong></div><small>{replayVerified ? "Before → verified" : "Before → recorded"}</small></div><div className={cx("receipt-final-card", !executionVerified && "receipt-final-pending")}><Icon name={executionVerified ? "check" : "clock"} size={26} /><span><strong>{executionVerified ? "Execution verified" : facts.receiptVerified ? "Receipt recorded" : "Verification pending"}</strong><small>{executionVerified ? "Casper receipt anchored · evidence chain valid" : facts.receiptVerified ? "A receipt verification is recorded, but the gateway reports no bound valid evidence chain for this proposal in this payload." : "The recorded receipt verification has not positively confirmed recovery in this payload."}</small></span></div></div></Panel>
    </>}
  </>;
}
