// Proposal workspace: Council Chamber transcript, timeline, metrics, raw cards.
import { useState } from "react";
import {
  CARD_LABELS,
  CARD_ROLE,
  PROFILES,
  cardBadge,
  cardSummary,
  cardTone,
  cleanRoomContent,
  cx,
  deriveHandoffs,
  deriveProposalFacts,
  deriveWorkflow,
  displayFamily,
  downloadEvidence,
  formatPercent,
  formatTime,
  getCard,
  getCardData,
  getProfile,
  inferMessageRole,
  messageBadge,
  navHref,
  normalizeRole,
  publicJson,
  bpsToPercent,
  shortHash,
  stateLabel,
  stateTone,
  statusTone,
} from "../lib";
import { Avatar, EmptyState, Icon, PageHeader, Panel, PrimaryButton, RichText, Skeleton, StatusPill } from "../primitives";
import { ProposalSelector, WorkflowStepper } from "../shared";

function ProposalContext({ proposal, facts }) { return <div className="context-list"><div><span>Target</span><strong>{facts.service}</strong></div><div><span>Proposal type</span><strong>{displayFamily(facts.proposalType)}</strong></div><div><span>Environment</span><strong>{facts.environment}</strong></div><div><span>Requested allocation</span><strong className="metric-danger">{bpsToPercent(facts.requestedAllocationBps)}</strong></div><div><span>Approved cap</span><strong className="metric-success">{bpsToPercent(facts.approvedAllocationBps)}</strong></div><div><span>Policy version</span><strong>{facts.policyVersion || "—"}</strong></div><div><span>Dissent hash</span><strong className="mono">{shortHash(facts.dissentHash, 12, 8)}</strong></div><div><span>Evidence strength</span><strong>{facts.evidenceStrength != null ? formatPercent(Number(facts.evidenceStrength) * 100) : "—"}</strong></div><div><span>Proposal ID</span><strong className="mono">{proposal?.proposal_id || "—"}</strong></div></div>; }
function WorkflowVertical({ workflow }) { return <div className="workflow-vertical">{workflow.steps.map((step, index) => <div key={step.id} className={cx("workflow-v-step", step.done && "complete", index === workflow.currentIndex && "current", step.skipped && "skipped", step.tone === "warning" && "challenge")}><span className="workflow-v-node">{step.done ? <Icon name="check" size={13} /> : index === workflow.currentIndex ? <span className="workflow-pulse" /> : null}</span><span>{step.label}</span></div>)}</div>; }
export function MessageCard({ message, index }) {
  const role = inferMessageRole(message); const profile = getProfile(role); const content = cleanRoomContent(message.content); const badge = messageBadge(message); const challenge = badge === "CHALLENGE" || badge === "APPROVAL REQUIRED"; const approval = badge === "APPROVAL"; const tone = challenge ? "warning" : approval ? "success" : role === "core" ? "muted" : "info";
  const displayContent = content.length > 440 ? `${content.slice(0, 440)}…` : content;
  return <article className={cx("message-card", `message-${tone}`)} style={{ "--agent-accent": profile.color }}><div className="message-sequence">{index + 1}</div><Avatar profile={profile} size="md" /><div className="message-body"><div className="message-meta"><strong>{profile.name}</strong><span>{profile.role}</span><StatusPill tone={tone} compact>{badge}</StatusPill><time>{formatTime(message.created_at)}</time></div><p><RichText value={displayContent} /></p></div></article>;
}
function EvidenceTimeline({ cards }) { return <div className="timeline-list">{cards.map((card, index) => { const profile = getProfile(CARD_ROLE[card.card_type]); return <div key={`${card.sequence}-${card.card_type}`} className="timeline-row"><div className="timeline-time">#{card.sequence}</div><div className="timeline-track"><span style={{ background: profile.color }} />{index < cards.length - 1 && <i />}</div><div className="timeline-card"><div><Avatar profile={profile} size="xs" /><strong>{CARD_LABELS[card.card_type] || card.card_type}</strong><StatusPill tone={cardTone(card)} compact>{cardBadge(card)}</StatusPill></div><p><RichText value={cardSummary(card)} /></p><small>{shortHash(card.hash)}</small></div></div>; })}</div>; }
export function MetricsPanel({ facts }) {
  const items = [{ label: "Risk exposure", before: formatPercent(facts.preMetrics.errorRate), after: formatPercent(facts.postMetrics.errorRate), icon: "signal" }, { label: "Treasury volatility", before: facts.preMetrics.volatility != null ? `${facts.preMetrics.volatility} bps` : "—", after: facts.postMetrics.volatility != null ? `${facts.postMetrics.volatility} bps` : "—", icon: "activity" }, { label: "Policy compliance", before: formatPercent(facts.preMetrics.uptime), after: formatPercent(facts.postMetrics.uptime), icon: "clock" }];
  return <div className="metrics-grid">{items.map((item) => <div className="metric-comparison" key={item.label}><div className="metric-comparison-head"><Icon name={item.icon} size={17} /><span>{item.label}</span></div><div className="metric-values"><span><small>Before</small><strong className="metric-danger">{item.before}</strong></span><Icon name="arrowRight" size={19} /><span><small>After</small><strong className="metric-success">{item.after}</strong></span></div></div>)}<div className={cx("metric-comparison", "receipt-card", !facts.receiptVerified && "receipt-card-pending")}><div className="metric-comparison-head"><Icon name="shield" size={17} /><span>Receipt gate</span></div><strong>{facts.receiptVerified ? "Verified" : "Pending verification"}</strong><small>{facts.receiptVerified ? "Recorded receipt verification passed." : "Not verified: the receipt verification event has not positively confirmed recovery."}</small></div></div>;
}
function RawCardsPanel({ cards }) {
  const [expanded, setExpanded] = useState(null);
  return <div className="raw-card-list">{cards.map((card) => <div key={`${card.sequence}-${card.card_type}`} className="raw-card-item"><button type="button" onClick={() => setExpanded(expanded === card.sequence ? null : card.sequence)}><span className="raw-card-seq">#{card.sequence}</span><strong>{card.card_type}</strong><span>{shortHash(card.hash)}</span><StatusPill tone={card.published ? "success" : "warning"} compact>{card.published ? "Published" : "Prepared"}</StatusPill><Icon name={expanded === card.sequence ? "chevronDown" : "chevronRight"} size={16} /></button>{expanded === card.sequence && <pre>{publicJson(card.data || {})}</pre>}</div>)}</div>;
}

export function ProposalWorkspacePage({ data }) {
  const [tab, setTab] = useState("council");
  const proposal = data.selectedProposal;
  const cards = data.evidence?.cards || [];
  const facts = deriveProposalFacts(proposal, data.evidence);
  const workflow = deriveWorkflow(cards, proposal?.state);
  const handoffs = deriveHandoffs(cards);
  const activeHandoff = handoffs[handoffs.length - 1];
  const participants = ["rowan", "mercer", "verity", "alden", "locke", "core"];
  const actions = proposal ? <>{getCard(cards, "ResponsePlan", true) && !getCard(cards, "StructuredApproval", true) && <PrimaryButton icon="approval" href={navHref("/approvals", proposal.proposal_id)}>Review Approval</PrimaryButton>}<PrimaryButton tone="secondary" icon="download" onClick={() => downloadEvidence(data.evidence, proposal.proposal_id)}>Export Evidence</PrimaryButton></> : null;
  return <>
    <PageHeader title={proposal ? facts.title : "Proposal Workspace"} subtitle={proposal ? `${proposal.proposal_id} · ${facts.service} · ${facts.environment}` : "Select a proposal to inspect its Council Chamber."} meta={proposal && <div className="page-meta-pills"><StatusPill tone={statusTone(facts.severity, "danger")} compact>{String(facts.severity).toUpperCase()}</StatusPill><StatusPill tone={stateTone(proposal.state)} compact>{stateLabel(proposal.state)}</StatusPill></div>} actions={actions} />
    <div className="page-toolbar"><ProposalSelector proposals={data.proposals} selectedId={data.selectedId} onSelect={data.selectProposal} /><div className="toolbar-status">{data.roomMeta?.updatedAt ? `Council Chamber updated ${formatTime(data.roomMeta.updatedAt)}` : "Waiting for Council Chamber data"}</div></div>
    {!proposal ? <Panel><EmptyState title="No proposal selected" description="Choose an proposal above or trigger the risky treasury proposal scenario from Overview." icon="proposal" /></Panel> : <div className="proposal-workspace">
      <aside className="proposal-left-rail"><Panel title="Proposal context" eyebrow="Live evidence"><ProposalContext proposal={proposal} facts={facts} /></Panel><Panel title="Workflow stage" eyebrow="Deterministic state"><WorkflowVertical workflow={workflow} /></Panel></aside>
      <Panel className="proposal-room-panel" noPadding><div className="room-header"><div><div className="eyebrow">Council Chamber</div><h2>Collaboration transcript</h2></div><div className="room-header-meta"><span className="status-dot online" /><span>{data.roomMeta?.count ?? data.messages.length} messages</span><span className="read-only-badge"><Icon name="lock" size={13} />Read-only</span></div></div><div className="tab-list" role="tablist">{[{ id: "council", label: "Council", icon: "network" }, { id: "timeline", label: "Timeline", icon: "clock" }, { id: "metrics", label: "Metrics", icon: "activity" }, { id: "raw", label: "Raw Cards", icon: "code" }].map((item) => <button key={item.id} type="button" className={cx("tab-button", tab === item.id && "active")} onClick={() => setTab(item.id)}><Icon name={item.icon} size={16} />{item.label}</button>)}</div><div className="room-content">{data.proposalLoading ? <><Skeleton height={92} /><Skeleton height={92} /><Skeleton height={92} /></> : null}{!data.proposalLoading && tab === "council" && <div className="message-list">{data.roomError && <div className="inline-notice warning"><Icon name="signal" size={17} />{data.roomError}</div>}{data.messages.length ? data.messages.map((message, index) => <MessageCard key={message.id || index} message={message} index={index} />) : cards.length ? cards.map((card, index) => { const profile = getProfile(CARD_ROLE[card.card_type]); return <MessageCard key={`${card.sequence}-${card.card_type}`} index={index} message={{ sender_role: profile.key, content: `${cardBadge(card)}\n${cardSummary(card)}`, created_at: card.data?.created_at || card.data?.timestamp }} />; }) : <EmptyState title="No collaboration events yet" description="Messages will appear as agents publish sealed cards through the Council Chamber." icon="network" />}</div>}{!data.proposalLoading && tab === "timeline" && (cards.length ? <EvidenceTimeline cards={cards} /> : <EmptyState title="No sealed timeline yet" icon="clock" />)}{!data.proposalLoading && tab === "metrics" && <MetricsPanel facts={facts} />}{!data.proposalLoading && tab === "raw" && (cards.length ? <RawCardsPanel cards={cards} /> : <EmptyState title="No cards available" icon="code" />)}</div><div className="working-state"><Avatar profile={activeHandoff ? getProfile(activeHandoff.to) : getProfile("alden")} size="sm" status="online" /><span>{activeHandoff ? `${getProfile(activeHandoff.to).name} received the latest verified handoff.` : "Waiting for the next verified handoff."}</span><span className="typing-dots"><i /><i /><i /></span></div></Panel>
      <aside className="proposal-right-rail"><Panel title="Current participants" eyebrow="Council Chamber"><div className="participant-list">{participants.map((role) => { const profile = getProfile(role); const agent = data.agents.find((item) => normalizeRole(item.agent_role) === role); return <div key={role}><Avatar profile={profile} size="xs" status={agent?.online ? "online" : "offline"} /><span><strong>{profile.name}</strong><small>{profile.role}</small></span><StatusPill tone={agent?.online ? "success" : "muted"} compact>{agent?.online ? "Active" : "Standing by"}</StatusPill></div>; })}<div className="participant-platform"><Avatar profile={PROFILES.wells} size="xs" /><span><strong>Wells</strong><small>Optional governance summary enrichment</small></span><StatusPill tone="purple" compact>LLM</StatusPill></div></div></Panel><Panel title="Active handoff" eyebrow="Current coordination">{activeHandoff ? <div className="handoff-card"><div className="handoff-person"><Avatar profile={getProfile(activeHandoff.from)} size="sm" /><span>{getProfile(activeHandoff.from).name}<small>{getProfile(activeHandoff.from).role}</small></span></div><div className="handoff-line"><span /><Icon name="arrowRight" size={18} /></div><div className="handoff-person"><Avatar profile={getProfile(activeHandoff.to)} size="sm" /><span>{getProfile(activeHandoff.to).name}<small>{getProfile(activeHandoff.to).role}</small></span></div></div> : <EmptyState title="No handoff yet" icon="network" />}</Panel><Panel title="Decision state" eyebrow="Execution boundary"><div className="decision-state"><StatusPill tone={stateTone(proposal.state)}>{stateLabel(proposal.state)}</StatusPill><div><Icon name="lock" size={16} />Only the exact authorized envelope can execute.</div><div><Icon name="shield" size={16} />Casper transaction verification must pass before the receipt is sealed.</div></div></Panel></aside>
    </div>}
  </>;
}
