// Proof Center: the reviewer proof cockpit. TRUTH-CORRECTED:
// - "The chain enforces the quorum" before/after centerpiece uses the recorded
//   supplemental v2 receipts (values already published on-chain), never
//   presented as live activity.
// - No fabricated green states: firewall, safety demo, reputation, RWA,
//   integrations and live-read panels render honest pending/unavailable states
//   when their live payload is absent.
// - The provenance registry, v3 sequence, and the two DISTINCT payment panels
//   render exclusively from registry/payload data.
import { useCallback, useEffect, useRef, useState } from "react";
import {
  DEFAULT_CASPER_CONTRACT_HASH,
  DEFAULT_CASPER_DEPLOY_HASH,
  DEFAULT_CASPER_EXPLORER_URL,
  DEFAULT_IPFS_CID,
  DEFAULT_IPFS_GATEWAY_URL,
  DEFAULT_ODRA_PACKAGE_HASH,
  DEFAULT_QUORUM_APPROVAL_HASH,
  DEFAULT_QUORUM_FINAL_RECEIPT_HASH,
  DEFAULT_REVIEW_PROPOSAL_ID,
  DEFAULT_WALLET_RECEIPT_HASH,
  GW,
  HISTORICAL_SAFEPAY_PAYMENT_HASH,
  PROFILES,
  SUPPLEMENTAL_DYNAMIC_ARGUMENT_SOURCE,
  api,
  cx,
  humanizeWalletError,
  isCasperLiveReadComplete,
  isWalletIntentSignable,
  pctFromBps,
  proofTabFromLocation,
  statusTone,
  titleCaseAction,
  unsignedIntentUnavailable,
  walletStatusTone,
} from "../lib";
import { Avatar, CodePreview, EmptyState, HashChip, Icon, PageHeader, Panel, PendingNote, PrimaryButton, StatusPill } from "../primitives";
import { ProofActionBar } from "../proof-actions";
import { EnforcementClimaxPanel, LeashMeter, ProposalSelector } from "../shared";
import { ProofRegistryPanel, findRegistryItem, findRegistryItemByProofId, itemGreenVerified } from "../provenance";
import { V3Sequence } from "../V3Sequence";
import { OfficialX402Panel, SafePayPanel } from "../payments";
import { signWithCasperWalletDirect } from "../wallet";

// Canonical recorded receipt facts (frozen, judged historical values).
// These identify the recorded canonical run; verification claims about them
// still only render from live payloads.
const CANONICAL_RECEIPT_FACTS = {
  decision: "APPROVED_WITH_LIMITS",
  deploy_hash: DEFAULT_CASPER_DEPLOY_HASH,
  transaction_hash: DEFAULT_CASPER_DEPLOY_HASH,
  contract_hash: DEFAULT_CASPER_CONTRACT_HASH,
  contract_package_hash: DEFAULT_ODRA_PACKAGE_HASH,
  entry_point: "store_governance_receipt",
  block_height: 8340490,
  explorer_url: DEFAULT_CASPER_EXPLORER_URL,
  policy_hash: "cae4a845c1edabba79ec77a2266c455e2d2492793bc707fb92639a6e4239f1a6",
  dissent_hash: "53fb4bc558cf2ee3d70d1a61b2462bdc3da92cd6e2ee24594eabff7f7a2055da",
  final_card_hash: "710b406d7b960d03c633e110fb2edda890b12594967b5db9dba533198a25d622",
  plan_hash: "603c61df5efc7c911d6c3cbc9063ba3e7b7ac3d580a61e90c89aa0673ef2ac93",
  approved_allocation_bps: 800,
  risk_score: 72,
  typed_args: {
    policy_hash: { cl_type: { ByteArray: 32 } },
    dissent_hash: { cl_type: { ByteArray: 32 } },
    final_card_hash: { cl_type: { ByteArray: 32 } },
    plan_hash: { cl_type: { ByteArray: 32 } },
    approved_allocation_bps: { cl_type: "U32" },
    risk_score: { cl_type: "U32" },
  },
};

// Canonical recorded policy-leash values (30.00% requested → 8.00% cap) from
// the frozen canonical run — labeled as recorded, not live.
const CANONICAL_POLICY_FACTS = {
  requested_bps: 3000,
  approved_bps: 800,
  requested_label: "30.00%",
  approved_label: "8.00%",
};

// The judge checklist claims. Without a live proof payload these render as
// "recorded" (neutral info tone linking to the recorded evidence), NEVER as
// live-verified green.
const RECORDED_PROOF_CLAIMS = [
  { claim: "Approved receipt anchored on Casper Testnet", status: "recorded", evidence: DEFAULT_CASPER_EXPLORER_URL },
  { claim: "Blocked tamper attempt", status: "recorded", evidence: "recorded deterministic envelope replay — see sealed evidence chain" },
  { claim: "DAO Constitution cap enforced", status: "recorded", evidence: "30.00% request reduced to 8.00% cap in the recorded canonical run" },
  { claim: "Exact action envelope matched", status: "recorded", evidence: "planned action list equals executed action list in sealed evidence" },
];

// Descriptive governance outcome states (design copy about the recorded
// scenario families, not live claims).
const OUTCOME_GALLERY = [
  { outcome: "APPROVED_WITH_LIMITS", tone: "success", description: "Risky treasury move revised from 30% to the 8% DAO Constitution cap." },
  { outcome: "BLOCKED_BY_CONSTITUTION", tone: "danger", description: "Attempts to execute the original 30% allocation are refused by the action firewall." },
  { outcome: "ESCALATED_TO_HUMANS", tone: "warning", description: "High-risk proposals require multisig review before Locke can act." },
  { outcome: "ABSTAINED_UNTIL_EVIDENCE", tone: "muted", description: "RWA onboarding remains non-executable until required evidence hashes are present." },
];

const FIREWALL_CHECK_LABELS = [
  ["approved_envelope_hash_matched", "Approved envelope hash matched"],
  ["policy_hash_sealed", "Policy hash sealed"],
  ["dissent_hash_sealed", "Dissent hash sealed"],
  ["final_card_hash_sealed", "Final card hash sealed"],
  ["multisig_approval_required", "Multisig approval nonce valid"],
  ["casper_receipt_processed", "Casper receipt processed"],
];

export function ProofCenterPage({ data }) {
  const [proof, setProof] = useState(null);
  const [safety, setSafety] = useState(null);
  const [integrations, setIntegrations] = useState(null);
  const [registry, setRegistry] = useState(null);
  const [registryError, setRegistryError] = useState(null);
  const [unsignedIntent, setUnsignedIntent] = useState(null);
  const [proofError, setProofError] = useState(null);
  const [walletStatus, setWalletStatus] = useState("idle");
  const [walletReceiptHash, setWalletReceiptHash] = useState("");
  const [quorumWalletStatus, setQuorumWalletStatus] = useState("idle");
  const [quorumWalletReceiptHash, setQuorumWalletReceiptHash] = useState("");
  const [quorumFinalStatus, setQuorumFinalStatus] = useState("idle");
  const [quorumFinalReceiptHash, setQuorumFinalReceiptHash] = useState("");
  const [activeProofTab, setActiveProofTab] = useState("summary");
  const [showAdvancedSigning, setShowAdvancedSigning] = useState(false);
  const [sandboxBps, setSandboxBps] = useState("3000");
  const [sandboxResult, setSandboxResult] = useState(null);
  const proposalId = data.selectedId || DEFAULT_REVIEW_PROPOSAL_ID;
  const walletSigningAvailable = isWalletIntentSignable(unsignedIntent);
  const quorumDemoEnabled = typeof window !== "undefined" && new URLSearchParams(window.location.search).get("quorum_demo") === "1";
  const quorumSigningAvailable = proposalId === DEFAULT_REVIEW_PROPOSAL_ID || quorumDemoEnabled;
  useEffect(() => {
    setActiveProofTab(proofTabFromLocation());
  }, []);
  useEffect(() => {
    if (!proposalId || typeof window === "undefined") return;
    const storedHash = window.localStorage.getItem(`concordia-wallet-receipt:${proposalId}`) || "";
    setWalletReceiptHash(storedHash || (proposalId === DEFAULT_REVIEW_PROPOSAL_ID ? DEFAULT_WALLET_RECEIPT_HASH : ""));
  }, [proposalId]);
  const rememberWalletReceiptHash = useCallback((hash) => {
    const cleaned = String(hash || "").trim().toLowerCase();
    setWalletReceiptHash(cleaned);
    if (cleaned && typeof window !== "undefined") {
      window.localStorage.setItem(`concordia-wallet-receipt:${proposalId}`, cleaned);
    }
  }, [proposalId]);
  const rememberQuorumWalletReceiptHash = useCallback((hash) => {
    const cleaned = String(hash || "").trim().toLowerCase();
    setQuorumWalletReceiptHash(cleaned);
    if (cleaned && typeof window !== "undefined") {
      window.localStorage.setItem(`concordia-quorum-wallet-approval:${proposalId}`, cleaned);
    }
  }, [proposalId]);
  const rememberQuorumFinalReceiptHash = useCallback((hash) => {
    const cleaned = String(hash || "").trim().toLowerCase();
    setQuorumFinalReceiptHash(cleaned);
    if (cleaned && typeof window !== "undefined") {
      window.localStorage.setItem(`concordia-quorum-final-receipt:${proposalId}`, cleaned);
    }
  }, [proposalId]);
  useEffect(() => {
    if (!proposalId || typeof window === "undefined") return;
    setQuorumWalletReceiptHash(
      window.localStorage.getItem(`concordia-quorum-wallet-approval:${proposalId}`)
      || (proposalId === DEFAULT_REVIEW_PROPOSAL_ID ? DEFAULT_QUORUM_APPROVAL_HASH : "")
    );
    setQuorumFinalReceiptHash(
      window.localStorage.getItem(`concordia-quorum-final-receipt:${proposalId}`)
      || (proposalId === DEFAULT_REVIEW_PROPOSAL_ID ? DEFAULT_QUORUM_FINAL_RECEIPT_HASH : "")
    );
  }, [proposalId]);
  useEffect(() => {
    if (!proposalId) return;
    let cancelled = false;
    const load = async () => {
      setProof(null);
      setSafety(null);
      setRegistry(null);
      setRegistryError(null);
      setUnsignedIntent(null);
      setWalletStatus("idle");
      setProofError(null);
      try {
        const [proofResult, safetyResult, integrationResult, intentResult, registryResult] = await Promise.allSettled([
          api(`/proof-center/${encodeURIComponent(proposalId)}`),
          api(`/adversarial-safety-demo/${encodeURIComponent(proposalId)}`),
          api("/integrations/status"),
          api(`/cspr-click/unsigned-receipt/${encodeURIComponent(proposalId)}`),
          api(`/proof-registry/v1/${encodeURIComponent(proposalId)}`),
        ]);
        if (cancelled) return;
        if (proofResult.status === "fulfilled") setProof(proofResult.value);
        if (safetyResult.status === "fulfilled") setSafety(safetyResult.value);
        if (integrationResult.status === "fulfilled") setIntegrations(integrationResult.value);
        if (registryResult.status === "fulfilled") setRegistry(registryResult.value);
        else setRegistryError("not served yet");
        if (intentResult.status === "fulfilled") {
          setUnsignedIntent(intentResult.value);
        } else {
          setUnsignedIntent(unsignedIntentUnavailable("Suppressed or blocked proposals are evidence-only and do not need a wallet-signed Casper receipt."));
        }
        const failed = [proofResult, safetyResult].filter((item) => item.status === "rejected");
        setProofError(failed.length ? "Proof Center is still loading live evidence." : null);
      } catch {
        if (!cancelled) setProofError("Proof Center is temporarily unavailable.");
      }
    };
    load();
    return () => { cancelled = true; };
  }, [proposalId]);
  const signWithWallet = useCallback(async () => {
    if (!walletSigningAvailable) {
      setWalletStatus("not needed: no Casper receipt payload");
      return;
    }
    try {
      await signWithCasperWalletDirect(proposalId, setWalletStatus, rememberWalletReceiptHash);
    } catch (error) {
      setWalletStatus(humanizeWalletError(error));
    }
  }, [proposalId, rememberWalletReceiptHash, walletSigningAvailable]);
  const signQuorumApprovalWithWallet = useCallback(async () => {
    if (!quorumSigningAvailable) {
      setQuorumWalletStatus(`select ${DEFAULT_REVIEW_PROPOSAL_ID} first`);
      return;
    }
    setQuorumWalletStatus("connecting-casper-wallet");
    try {
      await signWithCasperWalletDirect(
        proposalId,
        setQuorumWalletStatus,
        rememberQuorumWalletReceiptHash,
        "/cspr-click/quorum-approval",
      );
    } catch (error) {
      setQuorumWalletStatus(humanizeWalletError(error));
    }
  }, [proposalId, quorumSigningAvailable, rememberQuorumWalletReceiptHash]);
  const signFinalQuorumReceiptWithWallet = useCallback(async () => {
    if (!quorumSigningAvailable) {
      setQuorumFinalStatus(`select ${DEFAULT_REVIEW_PROPOSAL_ID} first`);
      return;
    }
    setQuorumFinalStatus("connecting-casper-wallet");
    try {
      await signWithCasperWalletDirect(
        proposalId,
        setQuorumFinalStatus,
        rememberQuorumFinalReceiptHash,
        "/cspr-click/quorum-receipt",
      );
    } catch (error) {
      setQuorumFinalStatus(humanizeWalletError(error));
    }
  }, [proposalId, quorumSigningAvailable, rememberQuorumFinalReceiptHash]);

  // WP7 final fail-open kill: CANONICAL_RECEIPT_FACTS is recorded display
  // history and NEVER backs a verified-receipt claim. Only a live/registry
  // proof payload makes receiptIsLive true; when it is false the recorded
  // facts render exclusively under explicit recorded/historical labeling with
  // neutral tone (see the receipts panel below).
  const liveReceipt = proof?.casper_receipt || data.evidence?.casper_receipt || null;
  const receiptIsLive = Boolean(liveReceipt);
  const receipt = liveReceipt || CANONICAL_RECEIPT_FACTS;
  const policy = proof?.policy_leash_meter || CANONICAL_POLICY_FACTS;
  const policyIsLive = Boolean(proof?.policy_leash_meter);
  const firewall = proof?.locke_execution_firewall || null;
  const compactRows = proof?.compact_proof_table?.length ? proof.compact_proof_table : RECORDED_PROOF_CLAIMS;
  // A compact proof-table row can NEVER turn green from status === "verified"
  // alone. Green requires the provenance-aware registry item backing the row
  // (matched by the row's proof_id or proof_type) to pass the strict
  // provenance.js validation with every required check explicitly passed:true.
  // Missing/failed/unknown registry backing renders a non-green row.
  const compactRowGreen = (row) => {
    if (String(row?.status || "").toLowerCase() !== "verified") return false;
    const registryItem = findRegistryItemByProofId(registry, row?.proof_id)
      || (row?.proof_type ? findRegistryItem(registry, row.proof_type) : null);
    return Boolean(registryItem) && itemGreenVerified(registryItem);
  };
  const safetyProof = safety || proof?.adversarial_safety_demo || null;
  const outcomeRows = proof?.outcome_gallery?.length ? proof.outcome_gallery : OUTCOME_GALLERY;
  const reputation = proof?.council_reputation?.length ? proof.council_reputation : null;
  const rwa = proof?.rwa_template || null;
  const liveRead = proof?.mercer_live_casper_read || null;
  // A live-read object is only a "Live data source" when its asserting fields
  // are explicitly present: a block height AND a state root. Object presence
  // alone proves nothing (shared strict predicate in lib.js).
  const liveReadComplete = isCasperLiveReadComplete(liveRead);
  const ipfsEvidence = proof?.ipfs_evidence || data.evidence?.ipfs_evidence || null;
  // "Pinned" requires an explicit, positive pin observation in the payload —
  // a CID alone is never a verified pin.
  const ipfsPinVerified = Boolean(ipfsEvidence?.cid) && (
    ipfsEvidence.pinned === true
    || ipfsEvidence.pin_verified === true
    || String(ipfsEvidence.pin_status || "").toLowerCase() === "pinned"
  );
  const integrationStatus = integrations || null;
  const v3Item = findRegistryItem(registry, "exact_envelope_v3");
  const safepayItem = findRegistryItem(registry, "safepay_v2");
  const x402Item = findRegistryItem(registry, "official_x402_settlement_v1");
  const walletArgumentSource = unsignedIntent?.argument_source || receipt.argument_source || "";
  const walletArgumentSourceLabel = walletArgumentSource === SUPPLEMENTAL_DYNAMIC_ARGUMENT_SOURCE
    ? "Supplemental Dynamic Execution Artifact"
    : walletArgumentSource ? titleCaseAction(walletArgumentSource) : "Sealed Evidence";
  const downloadHref = `${GW}/proof-pack/${encodeURIComponent(proposalId)}/download`;
  const isCanonicalProof = proposalId === DEFAULT_REVIEW_PROPOSAL_ID;
  const selectedState = String(data.selectedProposal?.state || "").toUpperCase();
  const evidenceOnly = !isCanonicalProof && (selectedState === "SUPPRESSED" || !walletSigningAvailable);
  const typedArgsCount = Object.keys(unsignedIntent?.typed_runtime_args || receipt.typed_args || {}).length;
  const proofTabs = [
    { id: "summary", label: "Summary" },
    { id: "safety", label: "Safety" },
    { id: "onchain", label: "On-chain" },
    { id: "data", label: "Data" },
    { id: "exports", label: "Exports" },
  ];
  const tabRefs = useRef({});
  // Selecting a tab keeps the ?tab= deep-link in sync (via history.replaceState
  // so no re-navigation occurs), preserving every other query param and the
  // hash so the tab survives a proposal switch and a page refresh.
  const selectTab = useCallback((tabId) => {
    setActiveProofTab(tabId);
    if (typeof window !== "undefined") {
      try {
        const url = new URL(window.location.href);
        url.searchParams.set("tab", tabId);
        window.history.replaceState(window.history.state, "", url);
      } catch { /* ignore */ }
    }
  }, []);
  const onTabKeyDown = useCallback((event, index) => {
    const order = proofTabs.map((tab) => tab.id);
    let nextIndex = null;
    if (event.key === "ArrowRight" || event.key === "ArrowDown") nextIndex = (index + 1) % order.length;
    else if (event.key === "ArrowLeft" || event.key === "ArrowUp") nextIndex = (index - 1 + order.length) % order.length;
    else if (event.key === "Home") nextIndex = 0;
    else if (event.key === "End") nextIndex = order.length - 1;
    if (nextIndex === null) return;
    event.preventDefault();
    const nextId = order[nextIndex];
    selectTab(nextId);
    tabRefs.current[nextId]?.focus();
  }, [proofTabs, selectTab]);
  const runSandboxPreview = () => {
    const requested = Math.max(0, Number(sandboxBps || 0));
    const approved = Math.min(requested, 800);
    setSandboxResult({
      requested,
      approved,
      blocked: requested > 800,
      typedArgs: {
        proposal_id: DEFAULT_REVIEW_PROPOSAL_ID,
        requested_allocation_bps: requested,
        approved_allocation_bps: approved,
        policy_hash: receipt.policy_hash || CANONICAL_RECEIPT_FACTS.policy_hash,
        decision: requested > 800 ? "APPROVED_WITH_LIMITS" : "APPROVED",
      },
    });
  };
  return <>
    <PageHeader
      title="Proof Center"
      subtitle="Reviewer-first proof cockpit for the canonical Casper receipt, safety controls, live data sources, and audit exports."
      meta={<div className="page-meta-pills"><StatusPill tone={isCanonicalProof ? "success" : "warning"} icon="shield">{isCanonicalProof ? "Canonical reviewer proof" : "Evidence preview"}</StatusPill><StatusPill tone="info" icon="link">{proposalId}</StatusPill></div>}
      actions={<><ProposalSelector proposals={data.proposals} selectedId={data.selectedId} onSelect={data.selectProposal} />{isCanonicalProof ? <ProofActionBar compact proposalId={proposalId} actionIds={["canonical_receipt", "certificate_html", "audit_packet"]} /> : <ProofActionBar compact proposalId={proposalId} actionIds={["evidence_chain"]} />}</>}
    />
    {proofError && <div className="inline-notice warning"><Icon name="signal" size={17} />{proofError}</div>}
    {evidenceOnly && <div className="inline-notice warning"><Icon name="info" size={17} />Evidence-only proposal. This is not the canonical signed proof. Select <strong className="mono">{DEFAULT_REVIEW_PROPOSAL_ID}</strong> to review verified Casper receipts.</div>}
    <div className="section-tabs" role="tablist" aria-label="Proof Center sections">{proofTabs.map((tab, index) => <button key={tab.id} type="button" role="tab" id={`proof-tab-${tab.id}`} aria-selected={activeProofTab === tab.id} aria-controls={`proof-tabpanel-${tab.id}`} tabIndex={activeProofTab === tab.id ? 0 : -1} ref={(element) => { tabRefs.current[tab.id] = element; }} className={cx(activeProofTab === tab.id && "active")} onClick={() => selectTab(tab.id)} onKeyDown={(event) => onTabKeyDown(event, index)}>{tab.label}</button>)}</div>

    {activeProofTab === "summary" && <div role="tabpanel" id="proof-tabpanel-summary" aria-labelledby="proof-tab-summary" tabIndex={0}>
      <EnforcementClimaxPanel />
      <div className="proof-hero-grid">
        <Panel title="Canonical proof table" eyebrow="Judge checklist"><div className="proof-table">{compactRows.map((row) => { const rowStatus = String(row.status || "").toLowerCase(); const rowGreen = compactRowGreen(row); const rowTone = rowGreen ? "success" : rowStatus === "verified" || rowStatus === "recorded" ? "info" : statusTone(row.status, "warning"); const rowLabel = rowStatus === "verified" && !rowGreen ? "unconfirmed" : row.status; return <div key={row.claim}><span><Icon name={rowTone === "success" ? "check" : rowTone === "info" ? "evidence" : "clock"} size={16} /></span><div><strong>{row.claim}</strong><small>{row.evidence || "Inspect evidence chain"}</small></div><StatusPill tone={rowTone} compact>{rowLabel}</StatusPill></div>; })}</div>{!proof?.compact_proof_table?.length && <p className="proof-table-note">Live verification statuses load from the gateway; until then the rows above link to the recorded evidence without asserting live verification.</p>}{proof?.compact_proof_table?.length && compactRows.some((row) => String(row?.status || "").toLowerCase() === "verified" && !compactRowGreen(row)) ? <p className="proof-table-note">Rows the gateway marks verified render green only when the provenance registry independently verifies them (every required check passed). Unconfirmed rows stay neutral.</p> : null}</Panel>
        <Panel title="Policy leash meter" eyebrow={policyIsLive ? "LLM cannot inject numbers" : "Recorded canonical run · LLM cannot inject numbers"}>
          <LeashMeter requestedBps={policy.requested_bps} approvedBps={policy.approved_bps} requestedLabel={policy.requested_label} approvedLabel={policy.approved_label} lead="An AI requested 30%. Concordia authorized at most 8%." />
        </Panel>
        {/* WP7 final: "Verified receipts" (and any success tone) renders ONLY
            when a live/registry receipt payload was observed (receiptIsLive).
            Without it the same recorded hashes render under an explicit
            recorded/historical title with neutral tone — recorded facts are
            never presented as a verified receipt. */}
        <Panel className="receipts-panel" title={receiptIsLive ? "Verified receipts" : "Recorded receipts · historical"} eyebrow={receiptIsLive ? "Completed proof, not pending actions" : "Recorded on Casper Testnet · live verification unavailable"}><div className="verified-receipts"><HashChip label={receiptIsLive ? "Canonical receipt" : "Canonical receipt (recorded)"} value={receipt.deploy_hash || DEFAULT_CASPER_DEPLOY_HASH} href={receipt.explorer_url || DEFAULT_CASPER_EXPLORER_URL} tone={receiptIsLive ? "success" : "info"} /><HashChip label="Wallet receipt" value={DEFAULT_WALLET_RECEIPT_HASH} href={`https://testnet.cspr.live/deploy/${DEFAULT_WALLET_RECEIPT_HASH}`} /><HashChip label="Quorum approval" value={DEFAULT_QUORUM_APPROVAL_HASH} href={`https://testnet.cspr.live/deploy/${DEFAULT_QUORUM_APPROVAL_HASH}`} /><HashChip label="Final quorum receipt" value={DEFAULT_QUORUM_FINAL_RECEIPT_HASH} href={`https://testnet.cspr.live/deploy/${DEFAULT_QUORUM_FINAL_RECEIPT_HASH}`} /><HashChip label="SafePay Lite payment (historical)" value={HISTORICAL_SAFEPAY_PAYMENT_HASH} /></div><p className="technical-note-lede">{receiptIsLive ? "Primary reviewer actions stay in the header. This card only lists completed receipts so a judge never confuses recorded proof with a pending transaction." : "These are recorded historical receipt hashes on Casper Testnet. No live verification is asserted while the live proof payload is unavailable."}</p></Panel>
      </div>
      <V3Sequence item={v3Item} />
      <div className="proof-two-column payments-row">
        <SafePayPanel item={safepayItem} legacy={proof?.safepay_lite || null} />
        <OfficialX402Panel item={x402Item} />
      </div>
    </div>}

    {activeProofTab === "safety" && <div className="proof-two-column" role="tabpanel" id="proof-tabpanel-safety" aria-labelledby="proof-tab-safety" tabIndex={0}>
      <Panel title="Locke Execution Firewall" eyebrow="Chain action gateway">
        {firewall ? <div className="firewall-grid">{FIREWALL_CHECK_LABELS.map(([key, label]) => { const ok = firewall[key] === true; return <div key={key} className={ok ? "pass" : "pending"}><Icon name={ok ? "check" : "clock"} size={15} /><span>{label}</span></div>; })}<div className="firewall-warning"><Icon name="lock" size={17} /><span>AI can suggest, but cannot force unauthorized execution.</span></div></div>
          : <div data-testid="firewall-unavailable"><PendingNote>Firewall check results load from the live proof payload. No checks are asserted while it is unavailable.</PendingNote><div className="firewall-grid firewall-grid-pending">{FIREWALL_CHECK_LABELS.map(([key, label]) => <div key={key} className="pending"><Icon name="clock" size={15} /><span>{label}</span></div>)}</div></div>}
      </Panel>
      <Panel title="Adversarial Safety Demo" eyebrow="Deterministic replay">
        {safetyProof ? <div className="safety-demo-card"><div className="safety-demo-head"><Icon name="lock" size={28} /><div><strong>{safetyProof.status === "blocked" ? "Execution Blocked" : "Safety outcome unavailable"}</strong><p>{safetyProof.summary || "Concordia proves that an altered envelope cannot bypass the deterministic gateway."}</p></div>{safetyProof.status === "blocked"
          ? <StatusPill tone="danger" compact>Rogue action refused</StatusPill>
          : <StatusPill tone="muted" compact>Outcome unavailable</StatusPill>}</div><div className="safety-demo-grid"><div><span>Approved allocation</span><strong>{safetyProof.approved_allocation_label || pctFromBps(safetyProof.approved_allocation_bps)}</strong></div><div><span>Attempted allocation</span><strong>{safetyProof.attempted_allocation_label || pctFromBps(safetyProof.attempted_allocation_bps)}</strong></div><div className="wide"><span>Reason</span><strong>{safetyProof.reason || "—"}</strong></div><div><span>Locke result</span><strong>{safetyProof.locke_result || "—"}</strong></div><div><span>Proof mode</span><strong>{safetyProof.proof_mode || "—"}</strong></div><div><span>Poisoned input</span><strong>{safetyProof.poisoned_input_rejected === true ? "Rejected" : safetyProof.poisoned_input_rejected === false ? "NOT rejected" : "—"}</strong></div></div></div>
          : <div data-testid="safety-demo-unavailable"><PendingNote>The adversarial safety demo result loads from the gateway. No blocked/allowed outcome is asserted while it is unavailable. The recorded deterministic replay remains in the sealed evidence chain.</PendingNote></div>}
      </Panel>
      <Panel title="Outcome Gallery" eyebrow="Governance states">{outcomeRows.length ? <div className="outcome-gallery">{outcomeRows.map((item) => <article key={item.outcome} className={`outcome-${item.tone || "info"}`}><StatusPill tone={item.tone || "info"} compact>{item.outcome}</StatusPill><p>{item.description}</p></article>)}</div> : <EmptyState title="Outcome gallery unavailable" icon="evidence" />}</Panel>
    </div>}

    {activeProofTab === "onchain" && <div className="proof-two-column" role="tabpanel" id="proof-tabpanel-onchain" aria-labelledby="proof-tab-onchain" tabIndex={0}>
      <Panel title="Typed Casper payload" eyebrow={receiptIsLive || unsignedIntent?.typed_runtime_args ? "ByteArray(32) + U32" : "Recorded canonical payload · ByteArray(32) + U32"}><div className="intent-grid"><div><span>Contract</span><HashChip value={receipt.contract_hash || DEFAULT_CASPER_CONTRACT_HASH} /></div><div><span>Entry point</span><strong>{receipt.entry_point || "store_governance_receipt"}</strong></div><div><span>Typed args</span><strong>{typedArgsCount || "—"}</strong></div><div><span>Argument source</span><strong>{walletArgumentSourceLabel}</strong>{walletArgumentSource && <code>{walletArgumentSource}</code>}</div></div><CodePreview summary="Show typed runtime args" value={unsignedIntent?.typed_runtime_args || receipt.typed_args || CANONICAL_RECEIPT_FACTS.typed_args} /></Panel>
      <Panel title="Judge Sandbox" eyebrow="Safe testnet intent preview"><div className="judge-sandbox"><StatusPill tone="info" icon="shield">Preview only</StatusPill><p>No wallet is required. This sandbox never mutates {DEFAULT_REVIEW_PROPOSAL_ID}; it only previews how invariants cap requested allocation before a typed Casper intent is built.</p><label><span>Requested allocation bps</span><input value={sandboxBps} onChange={(event) => setSandboxBps(event.target.value)} inputMode="numeric" /></label><PrimaryButton icon="shield" onClick={runSandboxPreview}>Run invariant preview</PrimaryButton>{sandboxResult && <div className="safety-demo-grid"><div><span>Requested</span><strong>{pctFromBps(sandboxResult.requested)}</strong></div><div><span>Approved</span><strong>{pctFromBps(sandboxResult.approved)}</strong></div><div><span>Invariant</span><strong>{sandboxResult.blocked ? "capped by DAO Constitution" : "within cap"}</strong></div><div><span>Mode</span><strong>preview only</strong></div><div className="wide"><span>Typed args preview</span><CodePreview summary="Show preview args" value={sandboxResult.typedArgs} /></div></div>}</div></Panel>
      <Panel title="Advanced signing demo" eyebrow="Optional testnet actions"><details className="advanced-actions" open={showAdvancedSigning} onToggle={(event) => setShowAdvancedSigning(event.currentTarget.open)}><summary>Advanced: re-run signing demo</summary><div className="inline-notice warning"><Icon name="signal" size={16} />Advanced testnet action — not required for reviewing canonical proof.</div><div className="wallet-action-row"><PrimaryButton tone="secondary" icon="lock" onClick={signWithWallet} disabled={!walletSigningAvailable}>Request Casper Wallet Signature</PrimaryButton><StatusPill tone={walletStatusTone(walletStatus)} compact>{walletStatus}</StatusPill></div><div className="wallet-action-row"><PrimaryButton tone="secondary" icon="lock" onClick={signQuorumApprovalWithWallet} disabled={!quorumSigningAvailable}>Request Quorum Approval</PrimaryButton><StatusPill tone={walletStatusTone(quorumWalletStatus)} compact>{quorumWalletStatus}</StatusPill></div><div className="wallet-action-row"><PrimaryButton tone="secondary" icon="lock" onClick={signFinalQuorumReceiptWithWallet} disabled={!quorumSigningAvailable}>Request Final Quorum Receipt</PrimaryButton><StatusPill tone={walletStatusTone(quorumFinalStatus)} compact>{quorumFinalStatus}</StatusPill></div><div id="csprclick-ui" className="csprclick-ui-host" /></details></Panel>
    </div>}

    {activeProofTab === "data" && <div role="tabpanel" id="proof-tabpanel-data" aria-labelledby="proof-tab-data" tabIndex={0}>
      <Panel title="Provenance registry" eyebrow="Section-13 proof items · green only when verified" className="registry-panel">
        <ProofRegistryPanel registry={registry} registryError={registryError} />
      </Panel>
      <div className="proof-three-column">
        <Panel title="Council reputation" eyebrow="Accountability preview">{reputation ? <div className="reputation-list">{reputation.map((item) => {
          // A row is green only when its own asserting field (the recorded
          // count) is explicitly present and positive. Row presence proves
          // nothing, and a historical reputation row never implies the agent
          // is online.
          const signalPositive = typeof item.value === "number" && item.value > 0;
          return <div key={`${item.agent}-${item.metric}`}><Avatar profile={Object.values(PROFILES).find((profile) => profile.name === item.agent) || PROFILES.system} size="xs" /><span><strong>{item.agent}</strong><small>{item.metric}</small></span><StatusPill tone={signalPositive ? "success" : "muted"} compact>{item.signal || "Unavailable"}</StatusPill></div>;
        })}</div> : <PendingNote>Reputation metrics load from the live proof payload. No counts are shown while it is unavailable.</PendingNote>}</Panel>
        <Panel title="Mercer live Casper read" eyebrow="MCP-style data source">{liveRead ? <div className="source-status-card">{liveReadComplete
          ? <StatusPill tone="success" icon="check">Live data source</StatusPill>
          : <StatusPill tone="muted" icon="clock">Live read incomplete</StatusPill>}<div><span>Network</span><strong>{liveRead.network || "—"}</strong></div><div><span>Block height</span><strong>{Number.isInteger(liveRead.latest_block_height) ? liveRead.latest_block_height : "—"}</strong></div><div><span>State root</span>{liveRead.state_root_hash ? <HashChip value={liveRead.state_root_hash} /> : <strong>—</strong>}</div><small>{liveRead.source || "—"}</small>{!liveReadComplete && <small>Asserted only when the payload carries the frozen Testnet network, an integer block height, a well-formed state root, and observation provenance.</small>}</div> : <PendingNote>The live Casper read loads from the gateway. No block height or state root is shown while it is unavailable.</PendingNote>}</Panel>
        <Panel title="RWA evidence packet" eyebrow="Non-canonical applicability proof">{rwa ? <div className="rwa-template-card"><strong>{rwa.proposal_id || "—"} · {rwa.proposal_type || "—"}</strong><div className="rwa-template-grid"><div><span>Face value</span><strong>{rwa.face_value_usd != null ? `$${Number(rwa.face_value_usd).toLocaleString()}` : "—"}</strong></div><div><span>Maturity</span><strong>{rwa.maturity_days != null ? `${rwa.maturity_days} days` : "—"}</strong></div><div><span>Debtor risk</span><strong>{rwa.debtor_risk_score ?? "—"}</strong></div><div><span>Issuer reputation</span><strong>{rwa.issuer_reputation_score ?? "—"}</strong></div>{rwa.supplemental_receipt_hash && <div className="wide"><span>Supplemental RWA receipt</span><HashChip value={rwa.supplemental_receipt_hash} href={rwa.supplemental_receipt_url} tone="info" /></div>}</div><p>Visible RWA applicability packet; supplemental receipt is separate from the canonical Casper proof.</p></div> : <PendingNote>The RWA packet loads from the live proof payload. No values are shown while it is unavailable.</PendingNote>}</Panel>
        <Panel title="IPFS evidence CID" eyebrow="Governance archive pin">{ipfsEvidence?.cid ? <div className="source-status-card">{ipfsPinVerified
          ? <StatusPill tone="success" icon="check">Pinned</StatusPill>
          : <StatusPill tone="info" icon="link">Pin unverified</StatusPill>}<div><span>Provider</span><strong>{ipfsEvidence.provider || "kubo"}</strong></div><HashChip label="CID" value={ipfsEvidence.cid} href={ipfsEvidence.gateway_url || DEFAULT_IPFS_GATEWAY_URL} />{!ipfsPinVerified && <small>A CID alone does not prove pinning; a verified pin is asserted only from an explicit pin observation in the payload.</small>}</div> : <div className="source-status-card"><StatusPill tone="info" icon="link">Recorded CID</StatusPill><div><span>Live pin status</span><strong>loads from the gateway</strong></div><HashChip label="CID" value={DEFAULT_IPFS_CID} href={DEFAULT_IPFS_GATEWAY_URL} /><small>The recorded archive CID is shown; live pin verification is not asserted while the payload is unavailable.</small></div>}</Panel>
        <Panel title="Integration status" eyebrow="Implemented now vs roadmap">{integrationStatus ? <><div className="integration-list">{Object.entries(integrationStatus).filter(([key]) => key !== "roadmap_only").map(([key, value]) => <div key={key}><span>{titleCaseAction(key)}</span><strong>{typeof value === "object" && value !== null ? (value.status || value.mode || value.provider || "configured") : String(value)}</strong><small>{typeof value === "object" && value !== null ? (value.note || value.message || "") : ""}</small></div>)}</div>{integrationStatus?.roadmap_only?.length ? <div className="roadmap-note"><Icon name="info" size={16} /><span>Roadmap only: {integrationStatus.roadmap_only.join(" · ")}</span></div> : null}</> : <PendingNote>Integration status loads from the gateway. No integration is claimed live while the payload is unavailable.</PendingNote>}</Panel>
      </div>
    </div>}

    {activeProofTab === "exports" && <div className="proof-two-column" role="tabpanel" id="proof-tabpanel-exports" aria-labelledby="proof-tab-exports" tabIndex={0}>
      <Panel title="Reviewer shortcuts" eyebrow="Single action registry"><ProofActionBar proposalId={proposalId} actionIds={["evidence_chain", "canonical_receipt", "quorum_failure", "quorum_success", "wallet_receipt", "supplemental_dynamic_receipt", "ipfs_archive", "proof_pack_json", "technical_jury_note"]} /></Panel>
      <Panel title="Downloads" eyebrow="Audit exports"><div className="proof-action-bar vertical"><PrimaryButton href={`${downloadHref}`} icon="download" dataTestId="proof-action-audit-packet">Download Governance Archive</PrimaryButton><PrimaryButton href={`${GW}/proof-pack/${encodeURIComponent(proposalId)}/exports/cards.csv`} icon="download" dataTestId="proof-action-cards-csv">cards.csv</PrimaryButton><PrimaryButton href={`${GW}/proof-pack/${encodeURIComponent(proposalId)}/exports/outcomes.csv`} icon="download" dataTestId="proof-action-outcomes-csv">outcomes.csv</PrimaryButton><PrimaryButton href={`${GW}/proof-pack/${encodeURIComponent(proposalId)}/exports/proof_table.csv`} icon="download" dataTestId="proof-action-proof-table-csv">proof_table.csv</PrimaryButton><PrimaryButton href={`${GW}/proof-pack/${encodeURIComponent(proposalId)}/exports/reputation.csv`} icon="download" dataTestId="proof-action-reputation-csv">reputation.csv</PrimaryButton><PrimaryButton href={`${GW}/proof-pack/${encodeURIComponent(proposalId)}/exports/casper_receipts.csv`} icon="download" dataTestId="proof-action-casper-receipts-csv">casper_receipts.csv</PrimaryButton><PrimaryButton href={`${GW}/proof-pack/${encodeURIComponent(proposalId)}/exports/x402_settlements.csv`} icon="download" dataTestId="proof-action-x402-csv">x402_settlements.csv</PrimaryButton></div></Panel>
    </div>}
  </>;
}
