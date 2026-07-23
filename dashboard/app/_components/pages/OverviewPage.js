// State-first "governance control room" Overview. Live system state renders
// above the fold; the persona gallery is demoted below it. Every stat tile is
// wired to real payload data, a recorded canonical constant (labeled), or an
// honest "unavailable" placeholder — never an invented number.
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import {
  ASSET_BASE,
  CONCORDIA_MODE,
  DEFAULT_CASPER_DEPLOY_HASH,
  DEFAULT_CASPER_EXPLORER_URL,
  DEFAULT_REVIEW_PROPOSAL_ID,
  RECORDED_ONCHAIN_RECEIPTS,
  agentStatusInfo,
  countDissentReceipts,
  cx,
  deriveLifecycle,
  deriveProposalFacts,
  formatDateTime,
  formatPercent,
  getCard,
  isActiveProposal,
  isAuthorizedApproval,
  isDeniedApproval,
  isReceiptVerified,
  navHref,
  shortHash,
  stateLabel,
  stateTone,
  statusTone,
} from "../lib";
import { EmptyState, Icon, Panel, PrimaryButton, StatusPill, useDelayedFlag } from "../primitives";
import {
  AgentMiniRow,
  CollaborationEvent,
  CouncilPersonaStrip,
  LeashMeter,
  RecentRunsTable,
  StatTile,
  VerifiedRunStaticFallback,
  WorkflowStepper,
} from "../shared";

function DemoModal({ open, onClose, data }) {
  const [firing, setFiring] = useState(null);
  const dialogRef = useRef(null);
  const previouslyFocusedRef = useRef(null);
  // Accessible modal: trap focus inside the dialog, close on Escape, and return
  // focus to the control that opened it.
  useEffect(() => {
    if (!open || typeof document === "undefined") return undefined;
    previouslyFocusedRef.current = document.activeElement;
    const focusable = () => Array.from(
      dialogRef.current?.querySelectorAll('a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])') || [],
    ).filter((element) => element.offsetParent !== null || element === document.activeElement);
    focusable()[0]?.focus();
    const onKeyDown = (event) => {
      if (event.key === "Escape") { event.preventDefault(); onClose(); return; }
      if (event.key !== "Tab") return;
      const items = focusable();
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener("keydown", onKeyDown, true);
    return () => {
      document.removeEventListener("keydown", onKeyDown, true);
      if (previouslyFocusedRef.current && typeof previouslyFocusedRef.current.focus === "function") previouslyFocusedRef.current.focus();
    };
  }, [open, onClose]);
  if (!open) return null;
  const scenarios = [
    { id: "defi-treasury", name: "Risky Treasury Move", description: "Golden path · 30% proposal, Verity dissent, Alden 8% cap, Casper receipt", icon: "proposal", primary: true },
    { id: "rwa-onboarding", name: "RWA Invoice Onboarding", description: "RWA template · evidence hash, invoice pool risk, Casper governance receipt", icon: "shield" },
    { id: "oracle", name: "Oracle Signal", description: "Full pipeline · oracle anomaly on the treasury feed", icon: "signal" },
    { id: "yield", name: "Treasury Volatility Spike", description: "Full pipeline · liquidity pool yield anomaly", icon: "activity" },
    { id: "exposure", name: "Treasury Exposure", description: "Full pipeline · allocation exceeds risk budget", icon: "network" },
    { id: "policy", name: "Protocol Drift", description: "Full pipeline · strategy deviates from DAO policy", icon: "activity" },
    { id: "credential", name: "RWA Credential Expiry", description: "Full pipeline · RWA attestation credential nearing expiry", icon: "shield" },
  ];
  // Frozen demo-capability protocol (demo capability v1 / WP3 demo-run-v1): the
  // browser NEVER posts {scenario_type} and never holds an operator token. It
  // (1) requests a short-lived capability bound to this scenario + client
  // cookie, then (2) activates that exact capability. There is no public reset
  // path. The activation contract is the frozen WP3 schema: a fresh run is
  // `status:"started"`, a replay of a consumed capability is
  // `status:"idempotent_replay"` (NEVER presented as a fresh start), a
  // concurrent in-flight retry is a documented 202 `status:"running"`, a stored
  // FAILED terminal replays `status:"failed"` with its honest error, and
  // proposal ids come ONLY from `created_proposal_ids[]` — the API returns no
  // scalar `proposal_id`. Nothing is asserted as started unless the Gateway
  // said so.
  const fire = async (scenarioId) => {
    if (CONCORDIA_MODE === "reviewer") {
      data.setToast({ type: "info", message: "Live mutations are disabled in Public Review Mode. Open Runs & Replay instead." });
      onClose();
      return;
    }
    setFiring(scenarioId);
    try {
      const capabilityResponse = await fetch(`${ASSET_BASE}/api/demo/capability`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scenario_id: scenarioId }) });
      const capability = await capabilityResponse.json().catch(() => ({}));
      if (!capabilityResponse.ok || capability.error || !capability.capability) {
        throw new Error(capability.error || `Capability request returned ${capabilityResponse.status}`);
      }
      const activateResponse = await fetch(`${ASSET_BASE}/api/demo/activate`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ capability: capability.capability, scenario_id: scenarioId }) });
      const result = await activateResponse.json().catch(() => ({}));
      if (activateResponse.status === 202 && result.status === "running") {
        // Documented WP3 202: the same run identity is still in flight. Nothing
        // fresh was started, so no proposal is asserted or selected.
        data.setToast({ type: "info", message: `This scenario is still running${result.demo_run_id ? ` · ${result.demo_run_id}` : ""}. It will appear once the council chain is created.` });
        await data.refreshBase(true);
        onClose();
        return;
      }
      if (result.status === "failed") {
        // Stored FAILED terminal replay — surface the stored honest error.
        throw new Error(result.error || "The recorded demo run for this scenario ended in failure.");
      }
      if (!activateResponse.ok || result.error) throw new Error(result.error || `Activation returned ${activateResponse.status}`);
      // Frozen WP3 contract: the selected proposal derives from
      // created_proposal_ids[0]; there is no scalar proposal id field.
      const createdProposalIds = (Array.isArray(result.created_proposal_ids) ? result.created_proposal_ids : []).filter(Boolean);
      const selectedProposalId = createdProposalIds[0] || null;
      const idempotentReplay = result.status === "idempotent_replay";
      if (result.status !== "started" && !idempotentReplay) {
        // Fail-closed: an unrecognized success body never claims a started run.
        throw new Error("The Gateway did not report a started demo run.");
      }
      data.setToast(idempotentReplay
        ? { type: "info", message: `${selectedProposalId || "This scenario"} is already active — showing the existing run. No new pipeline was started.` }
        : { type: "success", message: `${selectedProposalId || "Proposal"} started · ${result.scenario_id || scenarioId} is entering the full proposal pipeline.` });
      await data.refreshBase(true);
      if (selectedProposalId) data.selectProposal(selectedProposalId);
      onClose();
    } catch (error) {
      data.setToast({ type: "error", message: error?.message ? `The scenario could not be started: ${error.message}` : "The scenario could not be started. Check the Gateway and Council mesh connection." });
    } finally { setFiring(null); }
  };
  return <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
    <div className="modal demo-modal" role="dialog" aria-modal="true" aria-labelledby="demo-title" ref={dialogRef}>
      <header className="modal-header"><div><div className="eyebrow">Controlled full-pipeline scenarios</div><h2 id="demo-title">Trigger a real proposal workflow</h2><p>Every scenario creates a unique Council Chamber and the complete agent chain.</p></div><button type="button" className="icon-button" onClick={onClose} aria-label="Close"><Icon name="close" /></button></header>
      <button className="golden-scenario" type="button" onClick={() => fire("defi-treasury")} disabled={Boolean(firing)}><span className="golden-scenario-icon"><Icon name="proposal" size={28} /></span><span><strong>DAO Constitution Firewall Scenario</strong><small>30% treasury request → Verity dissent → Alden 8% cap → multisig approval → Casper receipt</small></span><span className="golden-scenario-action">{firing === "defi-treasury" ? "Starting…" : CONCORDIA_MODE === "reviewer" ? "View replay" : "Start full pipeline"}<Icon name="arrowRight" size={17} /></span></button>
      <div className="modal-section-heading"><span>Additional proposal types</span><small>Each one activates distinct telemetry and starts the same evidence-bound agent workflow.</small></div>
      <div className="scenario-grid">{scenarios.filter((scenario) => !scenario.primary).map((scenario) => <button key={scenario.id} type="button" className="scenario-card" onClick={() => fire(scenario.id)} disabled={Boolean(firing)}><span><Icon name={scenario.icon} size={20} /></span><strong>{scenario.name}</strong><small>{scenario.description}</small></button>)}</div>
      <footer className="modal-footer"><p className="modal-footer-note"><Icon name="shield" size={15} />Each scenario runs under a short-lived, single-use capability bound to this browser. There is no reset control.</p><button type="button" className="button button-secondary" onClick={onClose}>Cancel</button></footer>
    </div>
  </div>;
}

export function OverviewPage({ data }) {
  const [demoOpen, setDemoOpen] = useState(false);
  const activeCandidate = data.proposals.find(isActiveProposal) || null;
  const activeProposal = activeCandidate || data.selectedProposal || data.proposals[0] || null;
  const proposalEyebrow = activeCandidate ? "Active proposal" : "Verified proposal replay";
  const activeEvidence = activeProposal?.proposal_id === data.selectedId ? data.evidence : null;
  const cards = activeEvidence?.cards || [];
  const facts = deriveProposalFacts(activeProposal, activeEvidence);
  const lifecycle = deriveLifecycle(cards, activeProposal?.proposal_id);
  const eventFeed = cards.slice(-5).reverse();
  const showBaseIssue = useDelayedFlag(Boolean(data.baseError), 10000);
  const showRoomIssue = useDelayedFlag(Boolean(data.roomError), 10000);
  const agentStatus = agentStatusInfo(data.agents, data.loading);
  const dissentCount = countDissentReceipts(activeEvidence);
  const councilRoles = ["rowan", "mercer", "verity", "alden", "locke", "core"];
  return <>
    <section className="control-room-masthead hero-glow">
      <div className="control-room-copy">
        <div className="eyebrow">Governance control room · Casper Testnet</div>
        <h1>Concordia DAO Council</h1>
        <p>Agents may disagree — the chain remembers the dissent, and only the approved envelope executes.</p>
      </div>
      <div className="control-room-actions">
        <PrimaryButton icon="challenge" href={navHref("/judge", DEFAULT_REVIEW_PROPOSAL_ID)} dataTestId="overview-primary-judge">Try to Break the Council</PrimaryButton>
        <PrimaryButton tone="ghost" icon="shield" href={navHref("/proof", DEFAULT_REVIEW_PROPOSAL_ID)} dataTestId="overview-primary-proof">Open Proof Center</PrimaryButton>
        <PrimaryButton tone="secondary" icon="play" onClick={() => setDemoOpen(true)} dataTestId="overview-demo-trigger">Run a live scenario</PrimaryButton>
      </div>
    </section>
    {showBaseIssue && <div className="inline-notice neutral"><Icon name="refresh" size={17} />Reconnecting to the Gateway. The interface will keep retrying automatically.</div>}
    <div className="stat-tile-grid">
      <StatTile
        icon="shield"
        label="Canonical sealed receipt"
        value={shortHash(DEFAULT_CASPER_DEPLOY_HASH, 10, 6)}
        detail={`${DEFAULT_REVIEW_PROPOSAL_ID} · recorded on Casper Testnet · frozen for review`}
        tone="green"
        mono
        href={DEFAULT_CASPER_EXPLORER_URL}
        dataTestId="overview-stat-receipt"
      />
      <StatTile
        icon="link"
        label="Recorded on-chain receipts"
        value={String(RECORDED_ONCHAIN_RECEIPTS.length)}
        detail={RECORDED_ONCHAIN_RECEIPTS.map((receipt) => receipt.label).join(" · ")}
        tone="cyan"
        dataTestId="overview-stat-receipt-count"
      />
      <StatTile
        icon="agents"
        label="Council status"
        value={agentStatus.known ? `${agentStatus.online} / ${agentStatus.total}` : "—"}
        detail={agentStatus.known ? "agents online · reported by the Gateway" : agentStatus.text}
        tone="blue"
        unavailable={!agentStatus.known}
        dataTestId="overview-stat-council"
      />
      <StatTile
        icon="challenge"
        label="Dissent receipts"
        value={dissentCount === null ? "—" : String(dissentCount)}
        detail={dissentCount === null ? "Loads from sealed evidence" : `Recorded CHALLENGE verdicts · ${activeProposal?.proposal_id || DEFAULT_REVIEW_PROPOSAL_ID}`}
        tone="purple"
        unavailable={dissentCount === null}
        dataTestId="overview-stat-dissent"
      />
    </div>
    <div className="overview-layout">
      <Panel className="active-proposal-panel" noPadding>{activeProposal ? <>
        <div className="active-proposal-head"><div><div className="eyebrow">{proposalEyebrow}</div><h2>{facts.title}</h2><div className="proposal-meta-row"><StatusPill tone={statusTone(facts.severity, "danger")} compact><Icon name="signal" size={13} />{String(facts.severity).toUpperCase()}</StatusPill><StatusPill tone="info" compact>{facts.environment}</StatusPill><StatusPill tone={stateTone(activeProposal.state)} compact>{stateLabel(activeProposal.state)}</StatusPill><span>Started {formatDateTime(activeProposal.created_at)}</span>{facts.errorRate != null && <span>Simulated exposure <strong className="metric-muted">{formatPercent(facts.errorRate)}</strong></span>}{facts.targetVersion !== "—" && <span>Guardrail cap <strong className="metric-info">{facts.targetVersion}</strong></span>}</div></div><div className="active-proposal-actions"><PrimaryButton icon="external" href={navHref("/proposals", activeProposal.proposal_id)}>Open Council Chamber</PrimaryButton><PrimaryButton tone="secondary" icon="approval" href={navHref("/approvals", activeProposal.proposal_id)}>Review Approval</PrimaryButton></div></div>
        <div className="active-proposal-workflow" aria-label="Proposal lifecycle"><WorkflowStepper workflow={lifecycle} compact /></div>
        <div className="latest-collaboration"><div className="section-title-row"><div><div className="eyebrow">Council event feed</div><h3>Recorded council events</h3></div><Link href={navHref("/proposals", activeProposal.proposal_id)}>View full chamber <Icon name="chevronRight" size={15} /></Link></div>{eventFeed.length ? eventFeed.map((card) => <CollaborationEvent key={`${card.sequence}-${card.card_type}`} card={card} compact />) : <EmptyState title="Waiting for sealed evidence" description="Recorded council events appear here with their sealed timestamps as agents publish verified work. No synthetic events are shown." icon="network" />}</div>
      </> : <VerifiedRunStaticFallback />}</Panel>
      <div className="overview-rail">
        <Panel title="Policy leash" eyebrow="No model output can widen it">
          <LeashMeter requestedBps={facts.requestedAllocationBps} approvedBps={facts.approvedAllocationBps} lead="An AI requested 30%. Concordia authorized at most 8%." />
        </Panel>
        <Panel title="Council activity" eyebrow="Current roles"><div className="agent-mini-list">{councilRoles.slice(1, 5).map((role) => {
          const verdict = getCard(cards, "Verdict", true);
          const assessment = getCard(cards, "Assessment", true);
          const plan = getCard(cards, "ResponsePlan", true);
          const approval = getCard(cards, "StructuredApproval", true) || getCard(cards, "PolicyAuthorization", true);
          const receipt = getCard(cards, "CasperExecutionReceipt", true);
          // No presence-based success: "Authorized" requires the explicit
          // affirmative + bound approval predicate, and "Execution complete"
          // requires a positively verified receipt. Unknown/rejected/unbound/
          // unverified cards never render a success cue.
          const planAuthorized = isAuthorizedApproval(approval, activeProposal?.proposal_id, plan);
          const approvalRejected = isDeniedApproval(approval);
          const receiptVerified = isReceiptVerified(receipt);
          const byRole = {
            mercer: { status: assessment ? "Assessment ready" : "Standing by", tone: assessment ? "info" : "muted" },
            verity: { status: verdict ? "Review complete" : "Standing by", tone: verdict ? "success" : "muted" },
            alden: {
              status: plan ? (planAuthorized ? "Authorized" : approvalRejected ? "Authorization rejected" : "Awaiting human") : "Standing by",
              tone: plan ? (planAuthorized ? "success" : approvalRejected ? "danger" : "warning") : "muted",
            },
            locke: {
              status: receiptVerified ? "Execution complete" : receipt ? "Receipt recorded · unverified" : "Standing by",
              tone: receiptVerified ? "success" : receipt ? "info" : "muted",
            },
          };
          const entry = byRole[role];
          return entry ? <AgentMiniRow key={role} role={role} status={entry.status} tone={entry.tone} /> : null;
        })}</div></Panel>
        <Panel title="Protocol health" eyebrow="Control plane"><div className="health-list"><div><span className="health-icon"><Icon name="shield" size={17} /></span><span><strong>Gateway</strong><small>Deterministic policy plane</small></span><StatusPill tone={showBaseIssue ? "muted" : "success"} compact>{showBaseIssue ? "Reconnecting" : "Operational"}</StatusPill></div><div><span className="health-icon"><Icon name="network" size={17} /></span><span><strong>Council Chambers</strong><small>Shared collaboration layer</small></span><StatusPill tone={showRoomIssue ? "muted" : "info"} compact>{showRoomIssue ? "Reconnecting" : "Connected"}</StatusPill></div><div><span className="health-icon"><Icon name="activity" size={17} /></span><span><strong>Proposal simulator</strong><small>Synthetic DAO treasury feed</small></span><StatusPill tone={activeProposal && isActiveProposal(activeProposal) ? "warning" : "success"} compact>{activeProposal && isActiveProposal(activeProposal) ? "Proposal active" : "Healthy"}</StatusPill></div>{/* Three-state chain validity: ONLY an explicit chain_valid === true renders
    the green "Valid" cue; an explicit false is "Invalid"; a missing/unknown
    value renders an honest non-green "Unverified". */}<div><span className="health-icon"><Icon name="link" size={17} /></span><span><strong>Evidence chain</strong><small>Sealed and ordered cards</small></span><StatusPill tone={activeEvidence?.chain_valid === true ? "success" : activeEvidence?.chain_valid === false ? "danger" : "muted"} compact>{activeEvidence ? activeEvidence.chain_valid === true ? "Valid" : activeEvidence.chain_valid === false ? "Invalid" : "Unverified" : "Waiting"}</StatusPill></div></div></Panel>
      </div>
    </div>
    <Panel title="Recent verified runs" eyebrow="Measured outcomes" action={<Link className="text-link" href={navHref("/runs", data.selectedId)}>Open replay library <Icon name="chevronRight" size={15} /></Link>}><RecentRunsTable runSummary={data.runSummary} proposals={data.proposals} onSelect={(id) => data.selectProposal(id)} /></Panel>
    <section className="overview-persona-section">
      <CouncilPersonaStrip />
      <div className="capability-chip-row" aria-label="Concordia live capabilities">
        {[
          ["ODRA CONTRACTS", "green"],
          ["ON-CHAIN QUORUM", "cyan"],
          ["DISSENT RECEIPTS", "purple"],
          ["SAFEPAY LITE SETTLEMENT", "amber"],
          ["IPFS ARCHIVE", "blue"],
          ["CASPER TESTNET LIVE", "green"],
        ].map(([label, tone]) => <span key={label} className={cx("chip-outline", `chip-outline-${tone}`)}>{label}</span>)}
      </div>
      <p className="overview-fine-print">Four deliberative agents (Rowan, Mercer, Verity, Alden) plus authorization-bound Locke act under model guidance; Concordia Core is deterministic infrastructure and Wells is a non-reasoning archive persona. Every execution still requires deterministic invariants, quorum approval, and an on-chain receipt.</p>
    </section>
    <DemoModal open={demoOpen} onClose={() => setDemoOpen(false)} data={data} />
  </>;
}
