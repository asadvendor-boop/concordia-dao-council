// Technical Jury Note: honest reviewer map of canonical vs supplemental vs
// preview vs roadmap. The historical SafePay Lite payment is labeled
// historical native-CSPR; the official x402 WCSPR path is a separate,
// fail-closed pending surface.
import {
  DEFAULT_CASPER_CONTRACT_HASH,
  DEFAULT_CASPER_DEPLOY_HASH,
  DEFAULT_CASPER_EXPLORER_URL,
  DEFAULT_IPFS_CID,
  DEFAULT_IPFS_GATEWAY_URL,
  DEFAULT_QUORUM_FINAL_RECEIPT_HASH,
  DEFAULT_REVIEW_PROPOSAL_ID,
  DEFAULT_SUPPLEMENTAL_DYNAMIC_HASH,
  DEFAULT_WALLET_RECEIPT_HASH,
  HISTORICAL_SAFEPAY_PAYMENT_HASH,
} from "../lib";
import { CodePreview, HashChip, Icon, PageHeader, Panel, StatusPill } from "../primitives";
import { ProofActionBar } from "../proof-actions";

export function TechnicalJuryNotePage({ data }) {
  const proposalId = data.selectedId || DEFAULT_REVIEW_PROPOSAL_ID;
  const proofRows = [
    ["Canonical reviewer proof", DEFAULT_REVIEW_PROPOSAL_ID, DEFAULT_CASPER_DEPLOY_HASH, "Frozen reproducible Casper receipt"],
    ["v1 GovernanceReceipt contract", "Jun 29", DEFAULT_CASPER_CONTRACT_HASH, "Receipt anchor used by canonical reviewer proof"],
    ["Browser wallet receipt", DEFAULT_REVIEW_PROPOSAL_ID, DEFAULT_WALLET_RECEIPT_HASH, "Recorded Casper Wallet custody path"],
    ["Quorum-enabled v2 proof", DEFAULT_REVIEW_PROPOSAL_ID, DEFAULT_QUORUM_FINAL_RECEIPT_HASH, "Supplemental receipt after quorum approval"],
    ["Supplemental dynamic execution", "DAO-PROP-DYN-002", DEFAULT_SUPPLEMENTAL_DYNAMIC_HASH, "Reusable engine proof, not canonical"],
    ["SafePay Lite (native CSPR · historical)", DEFAULT_REVIEW_PROPOSAL_ID, HISTORICAL_SAFEPAY_PAYMENT_HASH, "Historical Jun-29 paid specialist-report settlement in native CSPR"],
    ["IPFS archive", DEFAULT_REVIEW_PROPOSAL_ID, DEFAULT_IPFS_CID, "Pinned governance archive CID"],
  ];
  return <>
    <PageHeader
      title="Technical Jury Note"
      subtitle="An honest reviewer map for what is canonical, what is supplemental, what is preview-only, and what remains roadmap."
      meta={<div className="page-meta-pills"><StatusPill tone="success" icon="shield">Reviewer-safe scope</StatusPill><StatusPill tone="info" icon="link">{DEFAULT_REVIEW_PROPOSAL_ID}</StatusPill></div>}
      actions={<ProofActionBar compact proposalId={proposalId} actionIds={["canonical_receipt", "proof_pack_json", "certificate_html"]} />}
    />
    <div className="technical-note-grid">
      <Panel title="Canonical proof" eyebrow="Frozen for reproducibility">
        <p className="technical-note-lede">The canonical reviewer proof is <strong>{DEFAULT_REVIEW_PROPOSAL_ID}</strong>. It remains fixed so judges can verify the same evidence chain, Casper receipt, IPFS archive, SafePay proof, and certificate without the proof hierarchy shifting during review.</p>
        <div className="verified-receipts">
          <HashChip label="Canonical receipt" value={DEFAULT_CASPER_DEPLOY_HASH} href={DEFAULT_CASPER_EXPLORER_URL} tone="success" />
          <HashChip label="Canonical contract" value={DEFAULT_CASPER_CONTRACT_HASH} href="https://testnet.cspr.live/contract/a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1" />
          <HashChip label="IPFS CID" value={DEFAULT_IPFS_CID} href={DEFAULT_IPFS_GATEWAY_URL} />
        </div>
      </Panel>
      <Panel title="Supplemental proofs" eyebrow="Additional evidence, not replacement">
        <div className="technical-boundary-list">
          <div><StatusPill tone="info" compact>Quorum</StatusPill><span>v2 quorum-enabled contract proves pre-quorum rejection, wallet approval, and final post-quorum receipt.</span></div>
          <div><StatusPill tone="info" compact>Wallet</StatusPill><span>Recorded browser wallet receipt demonstrates custody path without making the demo depend on a judge wallet.</span></div>
          <div><StatusPill tone="info" compact>Dynamic</StatusPill><span>Supplemental dynamic proposal proves reusable receipt execution while the canonical proof stays frozen.</span></div>
          <div><StatusPill tone="info" compact>SafePay Lite</StatusPill><span>Native-CSPR paid specialist-report settlement (historical Jun-29 payment). Distinct from the official x402 WCSPR settlement, which remains fail-closed until its live proof is recorded. Not claimed as a full escrow marketplace.</span></div>
        </div>
      </Panel>
    </div>
    <Panel title="Smart contract proof table" eyebrow="Two real GovernanceReceipt iterations plus supplemental topology">
      <div className="table-wrap">
        <table className="data-table technical-proof-table">
          <thead><tr><th>Surface</th><th>Proposal / date</th><th>Proof hash</th><th>Reviewer meaning</th></tr></thead>
          <tbody>
            {proofRows.map(([surface, id, hash, meaning]) => <tr key={`${surface}-${hash}`}>
              <td><strong>{surface}</strong></td>
              <td>{id}</td>
              <td><HashChip value={hash} /></td>
              <td>{meaning}</td>
            </tr>)}
          </tbody>
        </table>
      </div>
    </Panel>
    <div className="technical-note-grid">
      <Panel title="Dynamic preview boundary" eyebrow="Reusable engine, controlled execution">
        <p className="technical-note-lede">Non-canonical proposals can build dynamic preview artifacts and testnet intent previews when evidence exists. They are not automatically advertised as canonical executed proofs unless a processed Casper transaction is captured and listed in the proof table.</p>
        <div className="inline-notice"><Icon name="info" size={17} />This avoids fake success states while still showing how the verifier, invariant runner, DAO Mandate builder, and wallet intent packager generalize.</div>
      </Panel>
      <Panel title="Live vs roadmap" eyebrow="No overclaiming">
        <div className="technical-boundary-list">
          <div><StatusPill tone="success" compact>Live</StatusPill><span>Canonical receipt, Proof Center, Judge Walkthrough, browser wallet receipt, quorum proof, SafePay Lite (native CSPR), IPFS archive, PDF/HTML certificate, verifier artifacts.</span></div>
          <div><StatusPill tone="warning" compact>Supplemental</StatusPill><span>Odra topology genesis and dynamic proposal receipts are supporting proofs, not replacements for the canonical reviewer proof.</span></div>
          <div><StatusPill tone="warning" compact>Pending</StatusPill><span>Official x402 WCSPR settlement is fail-closed until its live proof is recorded and verified.</span></div>
          <div><StatusPill tone="muted" compact>Roadmap</StatusPill><span>Full cross-contract production enforcement, enterprise IAM/durable queues, and SSE finality pipeline remain launch-plan work.</span></div>
        </div>
      </Panel>
    </div>
    <Panel title="Verifier commands" eyebrow="One-command reviewer checks">
      <CodePreview summary="Show local verification commands" value={`uv run pytest -q tests/ -q\nuv run python scripts/verify_concordia_receipt.py artifacts/live/casper-final-receipt-proof.json\nuv run python scripts/check_canonical_consistency.py\nuv run python scripts/redaction_check.py`} />
      <ProofActionBar proposalId={proposalId} actionIds={["technical_jury_note", "proof_pack_json", "trace_api", "audit_packet"]} />
    </Panel>
  </>;
}
