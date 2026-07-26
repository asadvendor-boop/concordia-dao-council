export const PUBLIC_APP_ORIGIN = "https://concordiadao.xyz";
export const DEFAULT_REVIEW_PROPOSAL_ID = "DAO-PROP-6CB25C";

export const NAV_GROUPS = [
  {
    label: "MONITOR",
    items: [
      { id: "overview", label: "Overview", href: "/", icon: "overview" },
      { id: "agents", label: "Council Chamber", href: "/agents", icon: "agents" },
      { id: "proposals", label: "Proposals", href: "/proposals", icon: "proposal" },
    ],
  },
  {
    label: "GOVERN",
    items: [
      { id: "approvals", label: "Approvals", href: "/approvals", icon: "approval" },
      { id: "evidence", label: "Evidence Chain", href: "/evidence", icon: "evidence" },
    ],
  },
  {
    label: "PROVE",
    items: [
      { id: "proof", label: "Proof Center", href: "/proof", icon: "shield" },
      { id: "judge", label: "Judge Walkthrough", href: "/judge", icon: "check" },
      { id: "runs", label: "Run Replay", href: "/runs", icon: "replay" },
    ],
  },
];

export const PUBLIC_LINKS = [
  { id: "website", label: "Website", href: PUBLIC_APP_ORIGIN },
  { id: "docs", label: "Docs", href: "https://docs.concordiadao.xyz" },
  { id: "github", label: "GitHub", href: "https://github.com/asadvendor-boop/concordia-dao-council" },
  { id: "npm", label: "Verifier 0.1.2", href: "https://www.npmjs.com/package/@concordia-dao/verify/v/0.1.2" },
  { id: "x", label: "X / Twitter", href: "https://x.com/ConcordiaDAO" },
];

export const RECORDED_PROOF_ROWS = [
  {
    id: "canonical-receipt",
    label: "Canonical reviewer receipt",
    value: "e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852",
    status: "verified at capture",
    href: "https://testnet.cspr.live/deploy/e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852",
  },
  {
    id: "pre-quorum",
    label: "Pre-quorum execution",
    value: "6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431",
    status: "reverted as expected",
    href: "https://testnet.cspr.live/deploy/6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431",
  },
  {
    id: "final-quorum",
    label: "Final quorum receipt",
    value: "9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928",
    status: "accepted on Testnet",
    href: "https://testnet.cspr.live/deploy/9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928",
  },
  {
    id: "safepay-lite",
    label: "Recorded V1 native-CSPR SafePay Lite evidence",
    value: "dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c",
    status: "recorded V1 proof",
    href: `${PUBLIC_APP_ORIGIN}/safepay-lite/${DEFAULT_REVIEW_PROPOSAL_ID}`,
  },
  {
    id: "ipfs-archive",
    label: "Governance archive",
    value: "bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq",
    status: "pinned at capture",
    href: `${PUBLIC_APP_ORIGIN}/api/ipfs/bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq`,
  },
];
