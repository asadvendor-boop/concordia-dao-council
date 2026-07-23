import ConcordiaApp from "../_components/ConcordiaApp";

// The former screen-reader "static judge proof summary" block was removed: it
// injected a SECOND <h1> on this route and hardcoded stale proposal IDs,
// receipt hashes, and block claims as proof. The single accessible page heading
// and all proof values now come from the validated selected-proposal proof data
// rendered inside the app (JudgeWalkthroughPage), never from literals here.
export default function JudgePage() {
  return <ConcordiaApp view="judge" />;
}
