import ConcordiaApp from "../_components/ConcordiaApp";

// The former screen-reader "static proof summary" block was removed: it injected
// a SECOND <h1> on this route and hardcoded stale proposal IDs, receipt/contract
// hashes, block heights, and a fixed "requested 30 / approved 8" claim as proof.
// The single accessible page heading and every proof value now come from the
// validated selected-proposal proof data rendered inside the app
// (ProofCenterPage / provenance registry), never from literals here.
export default function ProofPage() {
  return <ConcordiaApp view="proof" />;
}
