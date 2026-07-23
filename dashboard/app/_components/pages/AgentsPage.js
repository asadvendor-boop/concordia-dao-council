// Council Chamber: topology, responsibilities, directory, and skills.
// Truthful architecture labeling: seven council ROLES = four deliberative agents
// (Rowan, Mercer, Verity, Alden) + authorization-bound model-involved Locke +
// deterministic Concordia Core + non-reasoning archive persona Wells. Never
// "seven agents", never "five reasoning agents".
import {
  CARD_LABELS,
  cx,
  deriveHandoffs,
  getCard,
  getProfile,
  navHref,
  normalizeRole,
} from "../lib";
import { Avatar, EmptyState, Icon, PageHeader, Panel, PrimaryButton, StatusPill } from "../primitives";
import { ProposalSelector } from "../shared";

function TopologyMap({ agents, cards }) {
  const remoteRoles = ["rowan", "mercer", "verity", "alden", "locke", "core"];
  const handoffs = deriveHandoffs(cards);
  const current = handoffs[handoffs.length - 1];
  const positions = ["top-left", "middle-left", "bottom-left", "top-right", "middle-right", "bottom-right"];
  const lineGeometry = {
    rowan: [380, 210, 135, 78],
    mercer: [380, 210, 135, 210],
    verity: [380, 210, 135, 342],
    alden: [380, 210, 625, 78],
    locke: [380, 210, 625, 210],
    core: [380, 210, 625, 342],
  };
  return <div className="topology-map"><svg className="topology-lines" viewBox="0 0 760 420" preserveAspectRatio="none" aria-hidden="true"><defs>{remoteRoles.map((role) => { const profile = getProfile(role); const [x1, y1, x2, y2] = lineGeometry[role]; return <linearGradient key={role} id={`topology-gradient-${role}`} gradientUnits="userSpaceOnUse" x1={x1} y1={y1} x2={x2} y2={y2}><stop offset="0%" stopColor="#35c5f0" stopOpacity=".18" /><stop offset="58%" stopColor={profile.color} stopOpacity=".78" /><stop offset="100%" stopColor={profile.color} stopOpacity=".96" /></linearGradient>; })}</defs>{remoteRoles.map((role) => { const profile = getProfile(role); const [x1, y1, x2, y2] = lineGeometry[role]; const active = current && (current.from === role || current.to === role); return <line key={role} className={cx("topology-line", active && "active")} style={{ "--agent-accent": profile.color }} stroke={`url(#topology-gradient-${role})`} x1={x1} y1={y1} x2={x2} y2={y2} />; })}</svg><div className="room-hub"><span><Icon name="network" size={28} /></span><strong>Concordia</strong><small>Council Chamber</small></div>{remoteRoles.map((role, index) => { const profile = getProfile(role); const agent = agents.find((item) => normalizeRole(item.agent_role) === role); const active = current && (current.from === role || current.to === role); return <div key={role} className={cx("topology-agent", positions[index], active && "active")} style={{ "--agent-accent": profile.color }}><Avatar profile={profile} size="md" status={agent?.online ? "online" : "offline"} /><span><strong>{profile.name}</strong><small>{profile.role}</small></span>{active && <StatusPill tone="info" compact>Active handoff</StatusPill>}</div>; })}</div>;
}
function AgentCard({ role, agent, currentActivity, lastHandoff }) {
  const profile = getProfile(role); const platform = profile.platform; const online = platform ? false : Boolean(agent?.online);
  return <div className={cx("agent-directory-card", platform && "platform-card")} style={{ "--agent-accent": profile.color }}><div className="agent-card-head"><Avatar profile={profile} size="lg" status={online ? "online" : platform ? "platform" : "offline"} /><div><h3>{profile.name}</h3><p>{profile.role}</p><div className="agent-tags"><span>{profile.framework}</span><span>{profile.model}</span></div></div></div><div className="agent-card-grid"><div><span>Current activity</span><strong>{currentActivity}</strong></div><div><span>Status</span><StatusPill tone={platform ? "purple" : online ? "success" : "muted"} compact>{platform ? "Platform-managed" : online ? "Online" : "Standing by"}</StatusPill></div><div className="wide"><span>Most recent handoff</span><strong>{lastHandoff || "No handoff recorded"}</strong></div></div></div>;
}
function SkillCard({ skill }) {
  const profile = getProfile(skill.role);
  return <article className="skill-card" style={{ "--agent-accent": profile.color }}>
    <header><Avatar profile={profile} size="sm" /><div><strong>{skill.skill_name}</strong><span>{skill.agent_name} · {skill.llm_model}</span></div><StatusPill tone="info" compact>{skill.category}</StatusPill></header>
    <div className="skill-tool-name"><span>MCP-style tool</span><code>{skill.tool_name || skill.skill_id}</code></div>
    <p>{skill.prompt_contract}</p>
    <div className="skill-proof-grid"><div><span>Input contract</span><strong>{skill.input_contract}</strong></div><div><span>Output contract</span><strong>{skill.output_contract}</strong></div><div><span>LLM provider use</span><strong>{skill.llm_cloud_use}</strong></div><div><span>DAO proof</span><strong>{skill.dao_requirement}</strong></div><div><span>Guardrail</span><strong>{skill.deterministic_guardrail}</strong></div><div><span>Evidence artifact</span><strong>{skill.evidence_artifact}</strong></div></div>
    {skill.review_demo_cue && <div className="skill-demo-cue"><Icon name="info" size={15} /><span>{skill.review_demo_cue}</span></div>}
  </article>;
}

export function AgentsPage({ data }) {
  const cards = data.evidence?.cards || [];
  const handoffs = deriveHandoffs(cards);
  const recent = handoffs.slice(-4).reverse();
  const activityByRole = { rowan: getCard(cards, "TriageDecision") ? "Proposal intake complete" : "Monitoring proposal intake", mercer: getCard(cards, "Assessment", true) ? "Evidence analysis complete" : "Ready for evidence analysis", verity: getCard(cards, "Verdict", true) ? "Independent review complete" : "Ready to challenge conclusions", alden: getCard(cards, "ResponsePlan", true) ? (getCard(cards, "StructuredApproval", true) ? "Plan authorized" : "Awaiting human approval") : "Ready to construct a response plan", locke: getCard(cards, "CasperExecutionReceipt", true) ? "Governance execution and receipt complete" : "Ready to execute · blocked until authorized", core: "Recording state and evidence chain", wells: "Presents the governance archive · non-reasoning persona" };
  const lastHandoffFor = (role) => { const item = [...handoffs].reverse().find((handoff) => handoff.from === role || handoff.to === role); return item ? `${getProfile(item.from).name} → ${getProfile(item.to).name}` : null; };
  const skillsEyebrow = data.skills.length ? `${data.skills.length} deterministic MCP-style contracts` : "Deterministic MCP-style contracts";
  return <>
    <PageHeader title="Council Chamber" subtitle="Specialized agents share context and hand off work through one verified Council Chamber." actions={<><PrimaryButton href={navHref("/proposals", data.selectedId)} icon="external">Open Proposal Workspace</PrimaryButton><PrimaryButton href={navHref("/approvals", data.selectedId)} tone="secondary" icon="approval">Review Approval</PrimaryButton></>} />
    <div className="page-toolbar"><ProposalSelector proposals={data.proposals} selectedId={data.selectedId} onSelect={data.selectProposal} /></div>
    <div className="agents-top-layout"><Panel className="topology-panel" title="Council topology" eyebrow="Current proposal"><TopologyMap agents={data.agents} cards={cards} /><div className="topology-caption"><Icon name="network" size={18} /><span>The Council Chamber carries shared context and handoffs. Gateway separately verifies identity, state and exact authorization.</span></div></Panel><div className="agents-right-rail"><Panel title="Recent handoffs" eyebrow="Ordered collaboration"><div className="handoff-list">{recent.length ? recent.map((handoff, index) => <div key={`${handoff.from}-${handoff.to}-${index}`}><Avatar profile={getProfile(handoff.from)} size="xs" /><span><strong>{getProfile(handoff.from).name} → {getProfile(handoff.to).name}</strong><small>{CARD_LABELS[handoff.card.card_type] || handoff.card.card_type}</small></span><time>#{handoff.card.sequence}</time></div>) : <EmptyState title="No handoffs yet" icon="network" />}</div></Panel><Panel title="Architecture responsibilities" eyebrow="Separation of concerns"><div className="responsibility-list"><div><Icon name="network" size={18} /><span><strong>Council Chamber</strong><small>Agent communication, shared context and visible task handoffs</small></span></div><div><Icon name="shield" size={18} /><span><strong>Gateway</strong><small>Identity checks, deterministic state transitions and authorization enforcement</small></span></div><div><Icon name="link" size={18} /><span><strong>Concordia Core</strong><small>Hash-linked evidence cards and publication verification</small></span></div></div></Panel></div></div>
    <Panel title="Agent directory" eyebrow="Seven council roles · Four deliberative agents + authorization-bound Locke + deterministic Core + non-reasoning archive persona"><div className="agent-directory-grid">{["rowan", "mercer", "verity", "alden", "locke", "core"].map((role) => <AgentCard key={role} role={role} agent={data.agents.find((item) => normalizeRole(item.agent_role) === role)} currentActivity={activityByRole[role]} lastHandoff={lastHandoffFor(role)} />)}<AgentCard role="wells" currentActivity={activityByRole.wells} lastHandoff={lastHandoffFor("wells")} /></div></Panel>
    <Panel title="Casper agent skills" eyebrow={skillsEyebrow}><p className="skill-manifest-note"><strong>Casper MCP-compatible review manifest.</strong> These inspectable MCP-style contracts expose stable tool names, schemas, LLM prompt boundaries, guardrails, and evidence artifacts for reviewers.</p><div className="skill-grid">{data.skills.length ? data.skills.map((skill) => <SkillCard key={skill.skill_id} skill={skill} />) : <EmptyState title="Skill registry unavailable" description="The Gateway exposes /agent-skills when the control plane is reachable." icon="shield" />}</div></Panel>
  </>;
}
