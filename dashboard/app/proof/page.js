import ConcordiaApp from "../_components/ConcordiaApp";

const staticProof = {
  proposalId: "DAO-PROP-6CB25C",
  canonicalReceipt:
    "e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852",
  canonicalContract:
    "hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1",
  walletReceipt:
    "56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf",
  preQuorumBlocked:
    "6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431",
  quorumApproval:
    "7ee77b11b8373fa55976b047e5613d391dd2ece5b6c2f0671c7232183cc875da",
  finalQuorumReceipt:
    "9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928",
  dynamicLifecycleReceipt:
    "68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0",
  dynamicArgumentSource: "supplemental_dynamic_execution_artifact",
  x402Payment:
    "dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c",
  ipfsCid: "bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq",
  technicalJuryNote: "https://concordia.47.84.232.193.sslip.io/technical-jury-note",
};

export default function ProofPage() {
  return (
    <>
      <section
        aria-label="Static proof summary"
        style={{
          position: "absolute",
          width: 1,
          height: 1,
          overflow: "hidden",
          clipPath: "inset(50%)",
          whiteSpace: "nowrap",
        }}
      >
        <h1>Concordia static proof summary</h1>
        <p>Proposal {staticProof.proposalId}</p>
        <p>Canonical Odra GovernanceReceipt deploy {staticProof.canonicalReceipt}</p>
        <p>Canonical contract {staticProof.canonicalContract}</p>
        <p>Browser wallet receipt {staticProof.walletReceipt}</p>
        <p>Pre-quorum blocked deploy {staticProof.preQuorumBlocked}</p>
        <p>Browser wallet quorum approval {staticProof.quorumApproval}</p>
        <p>Final quorum receipt {staticProof.finalQuorumReceipt}</p>
        <p>Supplemental dynamic lifecycle receipt DAO-PROP-DYN-002 {staticProof.dynamicLifecycleReceipt}</p>
        <p>Supplemental dynamic argument source {staticProof.dynamicArgumentSource}</p>
        <p>x402 SafePay Lite payment {staticProof.x402Payment}</p>
        <p>IPFS evidence CID {staticProof.ipfsCid}</p>
        <p>Technical jury note {staticProof.technicalJuryNote}</p>
        <p>Concordia DAO Council is the Casper governance firewall for AI-run DAOs: Dissent Receipts preserve Verity&apos;s objection, Locke is bound to the exact approved hash, and browser-wallet quorum is proven on-chain when execution is reverted before quorum and accepted after quorum.</p>
        <p>Canonical proof is frozen for reproducibility; dynamic proposals are preview/execution-ready unless fully evidenced and signed; full cross-contract production enforcement is roadmap, not overclaimed.</p>
        <p>IPFS status verified through Concordia-hosted Kubo.</p>
        <p>Policy leash meter: requested 30 percent, approved 8 percent.</p>
      </section>
      <ConcordiaApp view="proof" />
    </>
  );
}
