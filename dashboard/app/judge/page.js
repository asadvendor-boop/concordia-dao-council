import ConcordiaApp from "../_components/ConcordiaApp";

const staticJudgeProof = {
  proposalId: "DAO-PROP-6CB25C",
  canonicalReceipt:
    "e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852",
  canonicalContract:
    "hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1",
  quorumReceipt:
    "9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928",
  dynamicLifecycleReceipt:
    "68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0",
  dynamicArgumentSource: "supplemental_dynamic_execution_artifact",
  walletReceipt:
    "56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf",
  x402Payment:
    "dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c",
  ipfsCid: "bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq",
  technicalJuryNote: "https://concordia.47.84.232.193.sslip.io/technical-jury-note",
};

export default function JudgePage() {
  return (
    <>
      <section
        aria-label="Static judge proof summary"
        style={{
          position: "absolute",
          width: 1,
          height: 1,
          overflow: "hidden",
          clipPath: "inset(50%)",
          whiteSpace: "nowrap",
        }}
      >
        <h1>Concordia Judge Walkthrough</h1>
        <p>Proposal {staticJudgeProof.proposalId}</p>
        <p>Canonical reviewer receipt {staticJudgeProof.canonicalReceipt}</p>
        <p>Canonical contract {staticJudgeProof.canonicalContract}</p>
        <p>Quorum proof {staticJudgeProof.quorumReceipt}</p>
        <p>Supplemental dynamic lifecycle proof DAO-PROP-DYN-002 {staticJudgeProof.dynamicLifecycleReceipt}</p>
        <p>Supplemental dynamic argument source {staticJudgeProof.dynamicArgumentSource}</p>
        <p>Browser wallet receipt {staticJudgeProof.walletReceipt}</p>
        <p>x402 payment {staticJudgeProof.x402Payment}</p>
        <p>IPFS CID {staticJudgeProof.ipfsCid}</p>
        <p>Technical jury note {staticJudgeProof.technicalJuryNote}</p>
        <p>Canonical proof is frozen for reproducibility; dynamic proposals are preview/execution-ready unless fully evidenced and signed; full cross-contract production enforcement is roadmap, not overclaimed.</p>
        <p>
          Concordia DAO Council is the Casper governance firewall for AI-run
          DAOs: Dissent Receipts preserve Verity&apos;s objection, Locke is bound
          to the exact approved hash, and browser-wallet quorum is proven
          on-chain when execution is reverted before quorum and accepted after
          quorum.
        </p>
      </section>
      <ConcordiaApp view="judge" />
    </>
  );
}
