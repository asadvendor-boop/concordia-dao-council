import Link from "next/link";

import { PublicLinkList } from "./PublicLinks";
import {
  DEFAULT_REVIEW_PROPOSAL_ID,
  PUBLIC_APP_ORIGIN,
  PUBLIC_LINKS,
  RECORDED_PROOF_ROWS,
  X402_RECORDED_SETTLEMENT_COPY,
  X402_RECORDED_SETTLEMENT_BADGE,
} from "./presentation-config.mjs";

const council = [
  ["rowan", "Rowan", "Proposal Sentinel"],
  ["mercer", "Mercer", "Treasury Intelligence"],
  ["verity", "Verity", "Risk & Legal"],
  ["alden", "Alden", "Protocol Strategy"],
  ["locke", "Locke", "Casper Execution"],
  ["wells", "Wells", "Governance Archivist"],
  ["core", "Core", "Evidence Core"],
];

const proofMetrics = [
  ["CANONICAL RECEIPT", "SEALED", "approved envelope anchored on Casper Testnet", "green"],
  ["ON-CHAIN PROOF TYPES", "6", "distinct recorded Casper artifact classes", "cyan"],
  ["RECORDED COUNCIL", "6 + CORE", "specialists plus the deterministic evidence core", "blue"],
  ["DISSENT RECEIPTS", "2", "policy conflicts preserved, not discarded", "purple"],
];

const decisionPath = [
  ["01", "Proposal", "A treasury action requests a 30% allocation."],
  ["02", "Dissent", "Verity records the policy conflict instead of hiding it."],
  ["03", "Quorum", "Execution is rejected before approval and accepted after quorum."],
  ["04", "Receipt", "Locke anchors the approved result on Casper Testnet."],
];

function short(value) {
  return value.length > 32 ? `${value.slice(0, 16)}…${value.slice(-12)}` : value;
}

export function LandingPage() {
  const docs = PUBLIC_LINKS.find((link) => link.id === "docs");
  const github = PUBLIC_LINKS.find((link) => link.id === "github");
  const npmVerifier = PUBLIC_LINKS.find((link) => link.id === "npm");
  const canonicalReceipt = RECORDED_PROOF_ROWS.find((row) => row.id === "canonical-receipt");
  const footerLinks = PUBLIC_LINKS;
  return <main className="landing-page">
    <div className="landing-grid-texture" aria-hidden="true" />
    <div className="landing-orb landing-orb-one" aria-hidden="true" />
    <div className="landing-orb landing-orb-two" aria-hidden="true" />
    <div className="landing-inner">
      <header className="landing-header">
        <Link className="landing-brand" href="/landing" aria-label="Concordia home">
          <img src="/dashboard/concordia-dao-logo-final.webp" alt="" width="44" height="44" />
          <span><strong>CONCORDIA</strong><small>DAO COUNCIL · V1.5</small></span>
        </Link>
        <nav className="landing-header-nav" aria-label="Landing navigation">
          <a href="#proof">Proof</a>
          <a href="#council">Council</a>
          <a href={docs.href} target="_blank" rel="noopener noreferrer">Docs</a>
          <a href={github.href} target="_blank" rel="noopener noreferrer">GitHub</a>
          <a href={npmVerifier.href} target="_blank" rel="noopener noreferrer">npm {npmVerifier.label}</a>
          <Link className="landing-enter" href="/">Enter dashboard <span aria-hidden="true">→</span></Link>
        </nav>
      </header>

      <section className="landing-hero" aria-labelledby="landing-title">
        <div className="landing-hero-copy">
          <div className="landing-proof-badge"><span />RECORDED ON CASPER TESTNET · VERIFIED AT CAPTURE</div>
          <h1 id="landing-title">Governance that AI cannot overrule.</h1>
          <p>Concordia is the Casper governance firewall for AI-run DAOs. Specialist agents deliberate, deterministic policy blocks unsafe proposals, dissent is preserved as a signed receipt, and human quorum permits only the exact approved action — proven on Casper Testnet.</p>
          <div className="landing-actions">
            <Link className="landing-button landing-button-primary" href={`/judge?proposal=${DEFAULT_REVIEW_PROPOSAL_ID}`}>Start Judge Walkthrough <span aria-hidden="true">→</span></Link>
            <Link className="landing-button landing-button-secondary" href={`/proof?proposal=${DEFAULT_REVIEW_PROPOSAL_ID}`}>Open Proof Center</Link>
          </div>
        </div>
        <div className="landing-hero-visual" aria-label="Recorded authorization sequence">
          <div className="landing-visual-kicker">CONSTITUTIONAL CONTROL PATH</div>
          <div className="landing-sequence-line" aria-hidden="true" />
          {decisionPath.map(([number, title, description], index) => <article key={number} className="landing-sequence-card" style={{ "--sequence-index": index }}>
            <span>{number}</span><div><strong>{title}</strong><p>{description}</p></div>
          </article>)}
          <div className="landing-boundary-seal"><img src="/dashboard/concordia-dao-logo-final.webp" alt="" /><span>BOUNDARY HELD</span><small>exact approved action only</small></div>
        </div>
      </section>

      <section className="landing-metric-grid" aria-label="Recorded V1 proof highlights">
        {proofMetrics.map(([label, value, detail, tone]) => <article key={label} className={`landing-metric landing-metric-${tone}`}><span>{label}</span><strong>{value}</strong><small>{detail}</small></article>)}
      </section>

      <section className="landing-control-grid" aria-label="Deterministic controls">
        <article className="landing-control landing-control-leash">
          <span>POLICY LEASH</span>
          <h3>A model cannot widen its own mandate.</h3>
          <div className="landing-leash-meter" role="img" aria-label="Requested 30 percent reduced to an 8 percent constitutional cap">
            <div className="landing-leash-requested"><small>REQUESTED</small><strong>30.00%</strong></div>
            <div className="landing-leash-arrow" aria-hidden="true">→</div>
            <div className="landing-leash-capped"><small>DAO CAP</small><strong>8.00%</strong></div>
          </div>
          <p>Verity can challenge and Alden can revise, but no model output moves the constitutional cap. The reduction is enforced before execution, not argued after it.</p>
        </article>
        <article className="landing-control landing-control-quorum">
          <span>CHAIN-ENFORCED QUORUM</span>
          <h3>Only the exact approved action executes.</h3>
          <ol className="landing-quorum-steps">
            <li><strong>Rejected before quorum</strong><small>execution refused while approval is incomplete</small></li>
            <li><strong>Multisig approval</strong><small>human signers authorize one exact envelope</small></li>
            <li><strong>Anchored receipt</strong><small>the executed action is recorded on Casper Testnet</small></li>
          </ol>
          {canonicalReceipt ? <a className="landing-quorum-receipt" href={canonicalReceipt.href} target="_blank" rel="noopener noreferrer">Open the canonical receipt <span aria-hidden="true">→</span></a> : null}
        </article>
      </section>

      <section id="proof" className="landing-proof-section" aria-labelledby="landing-proof-heading">
        <header className="landing-section-header"><div><span>PUBLIC EVIDENCE</span><h2 id="landing-proof-heading">The receipt trail, not a promise.</h2></div><p>Each row is a recorded V1 artifact. Explorer links show the captured Testnet result; SafePay Lite remains a recorded proof under the Concordia apex.</p></header>
        <div className="landing-proof-table">
          {RECORDED_PROOF_ROWS.map((row) => <a key={row.id} href={row.href} target="_blank" rel="noopener noreferrer">
            <span>{row.label}</span><code>{short(row.value)}</code><small>{row.status}</small><b aria-hidden="true">↗</b>
          </a>)}
        </div>
        <div className="landing-safepay-note">
          <span>RECORDED V1 NATIVE-CSPR SAFEPAY LITE EVIDENCE</span>
          <p>
            Historical payment and duplicate-proof rejection evidence is available at <a href={`${PUBLIC_APP_ORIGIN}/safepay-lite/${DEFAULT_REVIEW_PROPOSAL_ID}`} target="_blank" rel="noopener noreferrer">the owned Concordia domain</a>. {X402_RECORDED_SETTLEMENT_COPY}
          </p>
          <strong>{X402_RECORDED_SETTLEMENT_BADGE}</strong>
        </div>
      </section>

      <section id="council" className="landing-council-section" aria-labelledby="landing-council-heading">
        <header className="landing-section-header"><div><span>BOUNDED SPECIALISTS</span><h2 id="landing-council-heading">The council behind the proof.</h2></div><p>Six agent roles deliberate. The deterministic evidence core seals the trail. No persona can widen the DAO leash or authorize itself.</p></header>
        <div className="landing-council-grid">{council.map(([id, name, role], index) => <article key={id} style={{ "--council-index": index }}><div className="landing-avatar-ring"><img src={`/dashboard/agents/${id}.webp`} alt={`${name}, ${role}`} /></div><strong>{name}</strong><small>{role}</small></article>)}</div>
      </section>

      <section className="landing-final-cta">
        <div><span>REPRODUCIBLE REVIEW PATH</span><h2>Inspect the refusal. Follow the quorum. Open the receipt.</h2><p>The dashboard preserves every V1 proposal, approval, evidence, replay, transcript, proof, and download surface.</p></div>
        <Link className="landing-button landing-button-primary" href={`/judge?proposal=${DEFAULT_REVIEW_PROPOSAL_ID}`}>Begin the judge path <span aria-hidden="true">→</span></Link>
      </section>

      <footer className="landing-footer"><div><strong>Built in the open</strong><small>Owned launch surface, documentation, source, verifier, and public updates.</small></div><div className="landing-footer-links"><PublicLinkList className="landing-public-links" ids={footerLinks.map((link) => link.id)} /></div></footer>
    </div>
  </main>;
}
