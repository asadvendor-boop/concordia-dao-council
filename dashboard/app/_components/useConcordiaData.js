// Central gateway data hook. All reads fail soft: an unreachable gateway
// yields honest "unavailable" UI states, never fabricated data.
import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { DEFAULT_REVIEW_PROPOSAL_ID, TERMINAL_STATES, api, isActiveProposal } from "./lib";

export function useConcordiaData() {
  const pathname = usePathname();
  const router = useRouter();
  const [stats, setStats] = useState(null);
  const [agents, setAgents] = useState([]);
  const [skills, setSkills] = useState([]);
  const [proposals, setProposals] = useState([]);
  const [rules, setRules] = useState([]);
  const [runSummary, setRunSummary] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [proposalDetail, setProposalDetail] = useState(null);
  const [evidence, setEvidence] = useState(null);
  const [messages, setMessages] = useState([]);
  const [roomMeta, setRoomMeta] = useState(null);
  const [loading, setLoading] = useState(true);
  const [proposalLoading, setProposalLoading] = useState(false);
  const [lastUpdate, setLastUpdate] = useState(null);
  const [baseError, setBaseError] = useState(null);
  const [roomError, setRoomError] = useState(null);
  const [toast, setToast] = useState(null);
  const initialSelectionResolved = useRef(false);

  const refreshBase = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    const results = await Promise.allSettled([api("/stats"), api("/agent-status"), api("/agent-skills"), api("/proposals"), api("/suppression-rules"), api("/stats/runsummary")]);
    const [statsResult, agentsResult, skillsResult, proposalsResult, rulesResult, runResult] = results;
    if (statsResult.status === "fulfilled") setStats(statsResult.value);
    if (agentsResult.status === "fulfilled") setAgents(Array.isArray(agentsResult.value) ? agentsResult.value : []);
    if (skillsResult.status === "fulfilled") setSkills(Array.isArray(skillsResult.value?.skills) ? skillsResult.value.skills : []);
    if (proposalsResult.status === "fulfilled") setProposals(Array.isArray(proposalsResult.value) ? proposalsResult.value : []);
    if (rulesResult.status === "fulfilled") setRules(Array.isArray(rulesResult.value) ? rulesResult.value : []);
    if (runResult.status === "fulfilled") setRunSummary(runResult.value);
    const failed = results.filter((result) => result.status === "rejected");
    setBaseError(failed.length ? `${failed.length} live data source${failed.length === 1 ? "" : "s"} unavailable` : null);
    setLastUpdate(new Date());
    setLoading(false);
  }, []);

  const fetchMessages = useCallback(async (proposalId, quiet = false) => {
    if (!proposalId) return;
    try {
      const result = await api(`/room-messages/${encodeURIComponent(proposalId)}`);
      setMessages(result.messages || []);
      setRoomMeta({ roomId: result.room_id || null, count: result.message_count || 0, updatedAt: new Date() });
      setRoomError(null);
    } catch {
      if (!quiet) setRoomError("Council Chamber is temporarily unavailable. Sealed evidence remains available.");
    }
  }, []);

  const refreshProposal = useCallback(async (proposalId, quiet = false) => {
    if (!proposalId) return;
    if (!quiet) setProposalLoading(true);
    const results = await Promise.allSettled([api(`/proposals/${encodeURIComponent(proposalId)}`), api(`/evidence/${encodeURIComponent(proposalId)}`), api(`/room-messages/${encodeURIComponent(proposalId)}`)]);
    if (results[0].status === "fulfilled") setProposalDetail(results[0].value);
    if (results[1].status === "fulfilled") setEvidence(results[1].value);
    if (results[2].status === "fulfilled") {
      const result = results[2].value;
      setMessages(result.messages || []);
      setRoomMeta({ roomId: result.room_id || null, count: result.message_count || 0, updatedAt: new Date() });
      setRoomError(null);
    } else setRoomError("Council Chamber is temporarily unavailable. Sealed evidence remains available.");
    setProposalLoading(false);
  }, []);

  const selectProposal = useCallback((proposalId, updateUrl = true) => {
    if (!proposalId) return;
    setSelectedId(proposalId);
    try { window.localStorage.setItem("concordia:selectedProposal", proposalId); } catch {}
    if (updateUrl && pathname) router.replace(`${pathname}?proposal=${encodeURIComponent(proposalId)}`, { scroll: false });
  }, [pathname, router]);

  useEffect(() => { refreshBase(false); const timer = setInterval(() => refreshBase(true), 30000); return () => clearInterval(timer); }, [refreshBase]);
  useEffect(() => {
    if (!proposals.length || initialSelectionResolved.current) return;
    initialSelectionResolved.current = true;
    let requested = null;
    let explicitQuorumDemo = false;
    try {
      const params = new URLSearchParams(window.location.search);
      requested = params.get("proposal");
      explicitQuorumDemo = params.get("quorum_demo") === "1";
    } catch {}
    const requestedExists = requested && proposals.some((proposal) => proposal.proposal_id === requested);
    const canonical = proposals.find((proposal) => proposal.proposal_id === DEFAULT_REVIEW_PROPOSAL_ID);
    const active = proposals.find(isActiveProposal);
    const terminal = proposals.find((proposal) => TERMINAL_STATES.has(String(proposal.state || "").toUpperCase()));
    const selected = requested && (requestedExists || explicitQuorumDemo) ? requested : (canonical || active || terminal || proposals[0])?.proposal_id;
    if (selected) setSelectedId(selected);
  }, [pathname, proposals]);
  useEffect(() => {
    if (!selectedId) return;
    refreshProposal(selectedId, false);
    const roomTimer = setInterval(() => fetchMessages(selectedId, true), 30000);
    const proposalTimer = setInterval(() => refreshProposal(selectedId, true), 30000);
    return () => { clearInterval(roomTimer); clearInterval(proposalTimer); };
  }, [selectedId, refreshProposal, fetchMessages]);

  const selectedProposal = useMemo(() => proposalDetail?.proposal?.proposal_id === selectedId ? proposalDetail.proposal : proposals.find((proposal) => proposal.proposal_id === selectedId) || null, [proposalDetail, proposals, selectedId]);
  const allAgents = useMemo(() => [...agents, { agent_role: "wells", agent_id: "wells-archive", framework: "LLM provider", model: "GovernanceSummary writer", online: false, _platform: true }], [agents]);
  return { stats, agents, allAgents, skills, proposals, rules, runSummary, selectedId, selectedProposal, proposalDetail, evidence, messages, roomMeta, loading, proposalLoading, lastUpdate, baseError, roomError, toast, setToast, refreshBase, refreshProposal, selectProposal };
}
