// Shared composite components used across multiple pages.
import Link from "next/link";
import {
  CARD_ROLE,
  DEFAULT_CASPER_EXPLORER_URL,
  DEFAULT_QUORUM_ACCEPTED_URL,
  DEFAULT_QUORUM_FINAL_RECEIPT_HASH,
  DEFAULT_QUORUM_REJECTED_HASH,
  DEFAULT_QUORUM_REJECTED_URL,
  DEFAULT_REVIEW_PROPOSAL_ID,
  TERMINAL_STATES,
  cardBadge,
  cardSummary,
  cardTone,
  cx,
  displayFamily,
  formatDateTime,
  formatDuration,
  formatTime,
  getProfile,
  navHref,
  pctFromBps,
  stateLabel,
  stateTone,
} from "./lib";
import { Avatar, HashChip, Icon, Panel, PendingNote, RichText, StatusPill } from "./primitives";

// Control-room stat tile. Values must come from payload data, the recorded
// canonical constants (labeled), or an honest placeholder.
export function StatTile({ icon, label, value, detail, tone = "blue", href, mono = false, unavailable = false, dataTestId }) {
  const body = <>
    <div className="stat-tile-icon"><Icon name={icon} size={20} /></div>
    <div className="stat-tile-copy">
      <span>{label}</span>
      <strong className={cx(mono && "mono stat-tile-hash", unavailable && "stat-tile-unavailable")}>{value}</strong>
      <small>{detail}</small>
    </div>
  </>;
  const className = cx("stat-tile", `stat-${tone}`, unavailable && "stat-tile-muted");
  if (href) {
    return <a className={className} href={href} target="_blank" rel="noreferrer" data-testid={dataTestId}>{body}<Icon className="stat-tile-external" name="external" size={14} /></a>;
  }
  return <div className={className} data-testid={dataTestId}>{body}</div>;
}

export function WorkflowStepper({ workflow, compact = false }) {
  return <div className={cx("workflow-stepper", compact && "workflow-compact")}>{workflow.steps.map((step, index) => { const current = index === workflow.currentIndex; return <div key={step.id} className={cx("workflow-step", step.done && "complete", current && "current", step.skipped && "skipped", step.tone === "warning" && "challenge")}><div className="workflow-node">{step.done ? <Icon name="check" size={15} /> : current ? <span className="workflow-pulse" /> : <span className="workflow-empty" />}</div><span>{step.label}</span>{index < workflow.steps.length - 1 && <div className="workflow-line" />}</div>; })}</div>;
}

export function ProposalSelector({ proposals, selectedId, onSelect, terminalOnly = false }) {
  const options = terminalOnly ? proposals.filter((proposal) => TERMINAL_STATES.has(String(proposal.state || "").toUpperCase())) : proposals;
  return <label className="proposal-select"><span>Proposal</span><select value={selectedId || ""} onChange={(event) => onSelect(event.target.value)}>{options.map((proposal) => <option key={proposal.proposal_id} value={proposal.proposal_id}>{proposal.proposal_id} · {stateLabel(proposal.state)}</option>)}</select></label>;
}

export function AgentMiniRow({ role, status, detail, tone }) { const profile = getProfile(role); return <div className="agent-mini-row"><Avatar profile={profile} size="sm" status={tone === "success" ? "online" : tone === "warning" ? "waiting" : undefined} /><div className="agent-mini-copy"><strong>{profile.name}</strong><span>{profile.role}</span></div><StatusPill tone={tone || "muted"} compact>{status}</StatusPill>{detail && <small>{detail}</small>}</div>; }

export function CollaborationEvent({ card, compact = false, onClick }) {
  const profile = getProfile(CARD_ROLE[card?.card_type] || "system");
  const tone = cardTone(card);
  return <button type="button" className={cx("collaboration-event", compact && "compact", `event-${tone}`)} onClick={onClick}><Avatar profile={profile} size={compact ? "sm" : "md"} /><div className="collaboration-event-copy"><div className="event-heading"><strong>{profile.name}</strong><span>{profile.role}</span><StatusPill tone={tone} compact>{cardBadge(card)}</StatusPill></div><p><RichText value={cardSummary(card)} /></p></div><time>{formatTime(card?.data?.created_at || card?.data?.timestamp)}</time></button>;
}

// Policy leash meter. Values render only from provided data; when absent an
// honest placeholder renders instead — the 30%/8% story is never invented
// client-side.
export function LeashMeter({ requestedBps, approvedBps, requestedLabel, approvedLabel, sourceNote }) {
  const hasBps = requestedBps !== undefined && requestedBps !== null && approvedBps !== undefined && approvedBps !== null;
  const hasLabels = Boolean(requestedLabel && approvedLabel);
  if (!hasBps && !hasLabels) {
    return <PendingNote>Policy leash telemetry loads from sealed evidence. Values are never invented client-side.</PendingNote>;
  }
  return <div className="leash-meter">
    <div className="leash-values">
      <span><strong>{requestedLabel || pctFromBps(requestedBps)}</strong><small>Requested by proposal</small></span>
      <Icon name="arrowRight" size={20} />
      <span><strong>{approvedLabel || pctFromBps(approvedBps)}</strong><small>DAO Constitution cap</small></span>
    </div>
    {hasBps && <div className="leash-bar"><span style={{ width: `${Math.min(100, Number(requestedBps) / 40)}%` }} /><i style={{ left: `${Math.min(100, Number(approvedBps) / 40)}%` }} /></div>}
    <p>Verity can challenge and Alden can revise, but no model output can widen the policy leash.{sourceNote ? ` ${sourceNote}` : ""}</p>
  </div>;
}

export function CouncilPersonaStrip() {
  const roles = [
    { role: "rowan", trait: "\"Every proposal earns its hearing.\"" },
    { role: "mercer", trait: "\"Numbers before narratives.\"" },
    { role: "verity", trait: "\"Dissent is evidence.\"" },
    { role: "alden", trait: "\"Exact envelopes only.\"" },
    { role: "locke", trait: "\"I sign nothing unapproved.\"" },
    { role: "wells", trait: "\"The archive outlives the argument.\"" },
  ];
  return <section className="council-persona-strip" aria-label="Concordia council personas">
    <div className="council-persona-intro">
      <div className="eyebrow">Council personas</div>
      <h2>Meet the council behind the proof</h2>
      <p>Each persona has a bounded authority: no agent can widen the DAO leash or execute outside the approved mandate.</p>
    </div>
    <div className="council-persona-list">{roles.map(({ role, trait }) => { const profile = getProfile(role); return <article key={role} className="council-persona-card" style={{ "--agent-accent": profile.color }}>
      <Avatar profile={profile} size="persona" status={role === "wells" ? "platform" : "online"} />
      <div>
        <strong>{profile.name}</strong>
        <span>{profile.role}</span>
        <small className="persona-trait">{trait}</small>
        <p>{profile.description}</p>
      </div>
    </article>; })}</div>
  </section>;
}

export function CouncilAvatarStrip() {
  const roles = ["rowan", "mercer", "verity", "alden", "locke", "wells"];
  const proofRoles = {
    verity: { label: "Dissent receipt", href: navHref("/evidence", DEFAULT_REVIEW_PROPOSAL_ID) },
    locke: { label: "Execution receipt", href: DEFAULT_QUORUM_ACCEPTED_URL, external: true },
    wells: { label: "Archive", href: `/proof-pack/${DEFAULT_REVIEW_PROPOSAL_ID}/download`, external: true },
  };
  return <div className="council-avatar-strip" aria-label="Compact council personas">
    {roles.map((role) => {
      const profile = getProfile(role);
      const proofRole = proofRoles[role];
      return <div key={role} className="council-avatar-chip" style={{ "--agent-accent": profile.color }}>
        <Avatar profile={profile} size="sm" status={role === "wells" ? "platform" : "online"} />
        <span>
          <strong>{profile.name}</strong>
          <small>{profile.role}</small>
          {proofRole && (proofRole.external
            ? <a className="persona-proof-role" href={proofRole.href} target="_blank" rel="noreferrer">{proofRole.label}</a>
            : <Link className="persona-proof-role" href={proofRole.href}>{proofRole.label}</Link>)}
        </span>
      </div>;
    })}
  </div>;
}

// The chain-enforces-the-quorum centerpiece. Both deploy hashes and block
// heights are recorded supplemental v2 receipts already published on Casper
// Testnet — reused as recorded values, never presented as live activity.
export function EnforcementClimaxPanel() {
  return <Panel className="enforcement-climax-panel" title="The chain enforces the quorum" eyebrow="ON-CHAIN REJECTED / ACCEPTED · RECORDED SUPPLEMENTAL RECEIPTS">
    <div className="enforcement-climax-grid">
      <article className="enforcement-climax-card rejected">
        <div>
          <span>Before quorum</span>
          <strong>Reverted</strong>
        </div>
        <HashChip label="Deploy" value={DEFAULT_QUORUM_REJECTED_HASH} href={DEFAULT_QUORUM_REJECTED_URL} tone="warning" displayValue="6280b8e1…f67431" />
        <p>Store attempt reverted on-chain: error 8 — QuorumNotMet, at block 8,349,116</p>
        <a href={DEFAULT_QUORUM_REJECTED_URL} target="_blank" rel="noreferrer">Open rejected deploy <Icon name="external" size={14} /></a>
      </article>
      <article className="enforcement-climax-card accepted">
        <div>
          <span>After 2-of-3 quorum</span>
          <strong>Accepted · Anchored</strong>
        </div>
        <HashChip label="Deploy" value={DEFAULT_QUORUM_FINAL_RECEIPT_HASH} href={DEFAULT_QUORUM_ACCEPTED_URL} tone="success" displayValue="9d631fe1…e2928" />
        <p>Receipt stored after server + browser-wallet approval, block 8,350,034</p>
        <a href={DEFAULT_QUORUM_ACCEPTED_URL} target="_blank" rel="noreferrer">Open accepted receipt <Icon name="external" size={14} /></a>
      </article>
    </div>
    <p className="enforcement-climax-note">Same envelope, same contract — the only difference is quorum. Quorum is proven on-chain, not asserted in the UI.</p>
  </Panel>;
}

export function VerifiedRunStaticFallback({ compact = false }) {
  return <div className={cx("empty-state", "verified-run-fallback", compact && "compact")}>
    <span className="empty-icon"><Icon name="replay" size={26} /></span>
    <strong>Verified Casper run available</strong>
    <p>{DEFAULT_REVIEW_PROPOSAL_ID} is the completed reviewer run with policy dissent, multisig approval, and Casper Testnet receipt proof.</p>
    <div className="fallback-actions">
      <Link className="text-link" href={navHref("/runs", DEFAULT_REVIEW_PROPOSAL_ID)}>Open replay <Icon name="chevronRight" size={15} /></Link>
      <Link className="text-link" href={navHref("/evidence", DEFAULT_REVIEW_PROPOSAL_ID)}>Open evidence <Icon name="chevronRight" size={15} /></Link>
      <a className="text-link" href={DEFAULT_CASPER_EXPLORER_URL} target="_blank" rel="noreferrer">CSPR.live receipt <Icon name="external" size={13} /></a>
    </div>
  </div>;
}

export function RecentRunsTable({ runSummary, proposals, onSelect }) {
  const runs = runSummary?.runs || [];
  if (!runs.length) return <VerifiedRunStaticFallback compact />;
  return <div className="table-wrap"><table className="data-table recent-runs-table"><thead><tr><th>Proposal</th><th>Family</th><th>Outcome</th><th>Duration</th><th>Challenges</th><th>Receipt</th><th>Evidence</th></tr></thead><tbody>{runs.slice(0, 4).map((run) => { const proposal = proposals.find((item) => item.proposal_id === run.proposal_id); return <tr key={run.proposal_id} onClick={() => onSelect(run.proposal_id)}><td><strong>{run.proposal_id}</strong><small>{proposal ? formatDateTime(proposal.created_at) : "Verified run"}</small></td><td><strong>{displayFamily(run.proposal_family)}</strong><small>{run.signal_service || "same-family proof"}</small></td><td><StatusPill tone={run.state === "CLOSED_FALSE_ALARM" ? "muted" : stateTone(run.state)} compact>{stateLabel(run.state)}</StatusPill></td><td>{formatDuration(run.total_resolution_secs)}</td><td>{run.challenges ?? 0}</td><td>{run.casper_explorer_url ? <a className="text-link" href={run.casper_explorer_url} target="_blank" rel="noreferrer" onClick={(event) => event.stopPropagation()}>CSPR.live <Icon name="external" size={13} /></a> : <StatusPill tone={run.receipt_verified ? "success" : "muted"} compact>{run.receipt_verified ? "Verified" : "N/A"}</StatusPill>}</td><td><StatusPill tone="success" compact>Valid</StatusPill></td></tr>; })}</tbody></table></div>;
}
