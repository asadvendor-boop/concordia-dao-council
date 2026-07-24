"use client";

// Concordia dashboard root. The former 2600-line monolith is decomposed into
// focused modules under app/_components/; this file keeps the stable
// `<ConcordiaApp view=... />` contract used by every route wrapper.
import { AppShell } from "./AppShell";
import { useConcordiaData } from "./useConcordiaData";
import { OverviewPage } from "./pages/OverviewPage";
import { ProposalWorkspacePage } from "./pages/ProposalWorkspacePage";
import { ApprovalPage } from "./pages/ApprovalPage";
import { AgentsPage } from "./pages/AgentsPage";
import { EvidencePage } from "./pages/EvidencePage";
import { ProofCenterPage } from "./pages/ProofCenterPage";
import { JudgeWalkthroughPage } from "./pages/JudgeWalkthroughPage";
import { ReplayPage } from "./pages/ReplayPage";
import { TechnicalJuryNotePage } from "./pages/TechnicalJuryNotePage";

export default function ConcordiaApp({ view = "overview" }) {
  const data = useConcordiaData();
  const pages = {
    overview: <OverviewPage data={data} />,
    proposals: <ProposalWorkspacePage data={data} />,
    approvals: <ApprovalPage data={data} />,
    agents: <AgentsPage data={data} />,
    evidence: <EvidencePage data={data} />,
    proof: <ProofCenterPage data={data} />,
    judge: <JudgeWalkthroughPage data={data} />,
    runs: <ReplayPage data={data} />,
    technical: <TechnicalJuryNotePage data={data} />,
  };
  return <AppShell view={view} data={data}>{pages[view] || pages.overview}</AppShell>;
}
