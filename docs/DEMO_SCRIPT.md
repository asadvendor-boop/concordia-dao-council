# Concordia Finals Demo Script — v3 Cut

Target length: **2:45 (hard cap 3:00)**. Every second has either motion or a
receipt on screen. This script replaces the qualification-round cut: it narrates
the final implemented system — the typed exact-envelope GovernanceReceipt v3,
the three cleanly separated payment claims, the proof cockpit dashboard, and the
independent verifier — and it never narrates a pending item as done.

**Publish precondition (G13).** The published video is itself a gated claim:
`PENDING_PROOF`: G13 new finals video — incognito-verified public URL showing
all four v3 outcomes and all three payment claims. Do not record a shot whose
gate below is still pending — use its fallback shot instead — and do not
publish while any shot in the final edit depends on an unflipped gate.

## One-line submission pitch

Concordia DAO Council is the constitutional execution firewall for AI-run DAOs
on Casper: four deliberative agents advise, a deterministic core owns every
state transition and binds execution to the exact approved envelope, dissent is
preserved in the evidence chain whose hash is anchored by the on-chain receipt,
and the chain itself refuses anything that is not byte-exactly what quorum
approved.

## Who is on screen — the truthful taxonomy

Narration must always match this. It is the frozen taxonomy in
`shared/personas.py` and the submission copy.

- **Four deliberative agents — Rowan, Mercer, Verity, Alden** — reason over the
  proposal. Their model output is purely advisory.
- **Locke** is an authorization-bound, model-involved execution role — not a
  fifth deliberative agent. It submits only the exact envelope the
  deterministic core has authorized.
- **Concordia Core** is deterministic infrastructure, not a model. It owns
  every policy check, nonce, quorum gate, exact-envelope binding, and Casper
  execution.
- **Wells** is a non-reasoning archival/presentation persona. The deterministic
  archive is produced by Locke/Core; Wells presents the record and performs no
  model reasoning.

Banned narration (never say, never caption): any count of "reasoning agents"
above four; any phrasing that credits Wells with producing, sealing, or
summarizing evidence; any suggestion that a model executes or authorizes.

## Shot list — 13 shots, 2:45

Each shot: timecode, on-screen target, the narration line, and the gate it
depends on. **LIVE** = verified today and safe to record now. **PENDING** = do
not record until the named gate flips; use the fallback table below.

### Shot 1 — Cold open: the council (0:00–0:10)

- **On screen:** Overview page of the proof cockpit dashboard
  (`/dashboard`) — hero, judge-first CTA row, slow half-scroll to the persona
  wall (Rowan, Mercer, Verity, Alden, Locke, Wells portraits). Hold on the wall.
- **Narration:** "Concordia DAO Council — the constitutional execution firewall
  for AI-run DAOs on Casper. Four deliberative agents advise; deterministic
  code decides; a human keeps the final no."
- **Gate:** LIVE (current dashboard). Cockpit layout: `PENDING_PROOF`: WP10
  hosted release — proof cockpit dashboard deployed to the live origin.

### Shot 2 — The threat, and the deterministic block (0:10–0:24)

- **On screen:** Judge Walkthrough (`/dashboard/judge`, recording mode). Hold
  the demo-hook panel stating the 30%-vs-8% setup, then the adversarial-replay
  **result grid only**: BLOCKED pill, ATTEMPTED ALLOCATION 30.00%, ALLOWED CAP
  8.00%, LOCKE RESULT "Refused To Sign", CHAIN ACTION "Not triggered". Keep the
  adversarial input textarea out of frame (see hard rules — behavior, not
  payload strings).
- **Narration:** "A malicious proposal asks for thirty percent of the treasury;
  the DAO Constitution caps it at eight. Rowan, Mercer, Verity, and Alden
  deliberate in the open — and the deterministic replay blocks the violation
  every single time."
- **Gate:** LIVE.

### Shot 3 — Dissent is a receipt, not a footnote (0:24–0:38)

- **On screen:** Proposal Workspace transcript
  (`/dashboard/proposals?proposal=DAO-PROP-6CB25C`): Verity's CHALLENGE
  message, then the context rail — REQUESTED 30% (red), APPROVED CAP 8%
  (green), DISSENT HASH row — then Alden's RESPONSE PLAN, pausing half a beat
  on the human APPROVAL message (#9, Authorized DAO Approver).
- **Narration:** "Verity's objection is not smoothed away — it is sealed as a
  Dissent Receipt and anchored to Casper. Alden converts the safe
  eight-percent action into a DAO Mandate, and a named human approver signs
  inside the chamber."
- **Gate:** LIVE.

### Shot 4 — v3 outcome 1: before quorum, the chain says no (0:38–0:48)

- **On screen:** CSPR.live deploy page of the v3 pre-quorum finalize attempt
  showing `User error: 8`. Secondary: the cockpit's v3 four-outcome panel row.
  Dwell 3–4 s on the error line.
- **Narration:** "Now the finals contract — GovernanceReceipt v3, typed
  envelopes on-chain. The same envelope, finalized before quorum: the contract
  itself reverts it. Error code eight — QuorumNotMet."
- **Gate:** PENDING — `PENDING_PROOF`: G7a v3 install (package/contract hash +
  install deploy) and G7a v3 four-outcome live proof.

### Shot 5 — v3 outcome 2: the mutated envelope (0:48–0:58)

- **On screen:** CSPR.live deploy page of the post-quorum **mutated** envelope
  (3000 bps submitted vs approved 800 bps) showing `User error: 10`. Dwell.
- **Narration:** "After quorum, we submit a mutated envelope — thirty percent
  instead of the approved eight. The contract rejects anything that is not
  byte-exact. Error code ten — EnvelopeHashMismatch."
- **Gate:** PENDING — `PENDING_PROOF`: G7a v3 four-outcome live proof.

### Shot 6 — v3 outcome 3: the exact envelope finalizes (0:58–1:08)

- **On screen:** CSPR.live deploy page of the exact-envelope acceptance, then
  the `action_authorized=true` contract-state readback (cockpit readback panel
  or explorer state view). Dwell on `true`.
- **Narration:** "The exact approved envelope finalizes — and the contract
  state now reads action-authorized: true. Authorization lives on-chain, not in
  a model."
- **Gate:** PENDING — `PENDING_PROOF`: G7a v3 four-outcome live proof.

### Shot 7 — v3 outcome 4: never twice (1:08–1:16)

- **On screen:** CSPR.live deploy page of the repeat finalization attempt
  showing `User error: 12`. Dwell.
- **Narration:** "Submit the same envelope again? Error code twelve —
  AlreadyFinalized. One approval, one finalization — ever."
- **Gate:** PENDING — `PENDING_PROOF`: G7a v3 four-outcome live proof.

### Shot 8 — Real value: the quorum-authorized treasury transfer (1:16–1:30)

- **On screen:** CSPR.live deploy page of the finalized native transfer — 50
  CSPR, the transfer ID visibly bound to the authorized envelope — with the
  execution-journal artifact beside it (cockpit panel or artifact view).
- **Narration:** "That authorization moves real value: from a
  six-hundred-twenty-five CSPR treasury snapshot, a fifty CSPR native
  transfer, its transfer ID bound to the authorized envelope — executed
  exactly once, through the executor's durable journal."
- **Gate:** PENDING — `PENDING_PROOF`: G7a treasury execution (finalized
  native-transfer deploy + execution artifact).

### Shot 9 — SafePay v2: paid evidence, consumed exactly once (1:30–1:48)

- **On screen:** Three beats on one surface (cockpit SafePay v2 panel, or a
  clean terminal showing the two redemption responses side by side): (1) first
  consumption — `replay_disposition: first_consumption`; (2) the exact
  same-resource retry — identical stored fulfillment and identical
  `response_hash`, `replay_disposition: idempotent_replay`; (3) the
  cross-binding replay — terminal HTTP 409, `cross_binding_rejected`. No
  secrets, tokens, or headers in frame.
- **Narration:** "When the council buys specialist evidence, SafePay verifies
  the Casper payment before anything becomes proof. Retry the exact same
  payment — the identical stored response comes back; nothing is consumed
  twice. Rebind that payment to a different resource — terminal four-oh-nine,
  forever."
- **Gate:** PENDING — `PENDING_PROOF`: G6 SafePay Lite v2 replay-safe live
  artifact (idempotent retry + terminal cross-binding rejection, both
  surviving provider restart). The historical native-CSPR settlement
  `dcb35f42…` (block 8,339,447) is LIVE and is the fallback baseline.

### Shot 10 — The separate official x402 claim: WCSPR settlement (1:48–2:02)

- **On screen:** The official x402 settlement moment: facilitator `/settle`
  response with `success: true` and the transaction hash (response body only —
  never a request with credentials), then the finalized WCSPR
  `transfer_with_authorization` on CSPR.live, then the post-settlement
  on-chain readback. Dwell on `success: true` and the explorer page.
- **Narration:** "Separately — a different protocol, a different asset —
  Concordia settles the official x402 protocol: a signed WCSPR
  transfer-with-authorization, verified and settled through the official
  CSPR-dot-cloud facilitator. The service is fail-closed, and settlement is
  gated behind the on-chain v3 finalization you just watched."
- **Gate:** PENDING — `PENDING_PROOF`: G7b official x402 settlement
  (facilitator `success:true` + finalized WCSPR transfer + post-settle
  readback).

### Shot 11 — Verify from your own machine (2:02–2:16)

- **On screen:** Clean terminal: `npm install @concordia-dao/verify`, then
  `concordia-verify` pointed at the hosted deployment, ending on its green
  recompute summary. Jump-cut the install; dwell on the final output.
- **Narration:** "Don't take the dashboard's word for it. Install
  at-concordia-dao slash verify from npm, point it at the hosted deployment,
  and it recomputes every card and evidence hash from scratch — it never
  trusts an artifact's own booleans."
- **Gate:** PENDING — `PENDING_PROOF`: G9n npm publish + clean-room install +
  independent recompute against hosted evidence.

### Shot 12 — Everything public: certificate, registry, docs, domain (2:16–2:30)

- **On screen:** Certificate page (`/certificate/DAO-PROP-6CB25C`) — slow
  scroll across the labeled QR cards — then a beat on the proof-registry view
  in the cockpit (per-item status dimensions visible), closing on the browser
  address bar at `concordiadao.xyz` and `docs.concordiadao.xyz`.
- **Narration:** "Every claim ends in a public receipt. The certificate links
  each hash to CSPR-dot-live and IPFS, the proof registry declares each
  item's own verification status — pending stays pending — and the docs are
  public at docs-dot-concordiadao-dot-xyz."
- **Gate:** Certificate LIVE. Registry view: `PENDING_PROOF`: WP10 hosted
  release. Domain: `PENDING_PROOF`: G10 production domain live. Docs:
  `PENDING_PROOF`: G9d docs site live over HTTPS.

### Shot 13 — Close (2:30–2:45)

- **On screen:** Back to the Overview persona wall. End on the tagline
  "Agents may disagree — the chain remembers the dissent." Hold still.
- **Narration:** "Concordia DAO Council. Agents advise. The deterministic core
  decides. The chain holds the record — and a human keeps the final no. Built
  on Casper for the Agentic Buildathon."
- **Gate:** LIVE.

## Fallback-shot table

Check every gate against the release manifest immediately before recording. A
pending gate means: record the fallback, keep the `PENDING_PROOF` marker in
this file, and adjust narration to the fallback line — never the pending line.

| Pending gate | Shots affected | Fallback shot (what to record instead) | Fallback narration constraint |
|---|---|---|---|
| G7a v3 install + v3 four-outcome | 4, 5, 6, 7 | The LIVE historical v2 pair: CSPR.live `6280b8e1…` (`User error: 8` / QuorumNotMet, block 8,349,116) then `9d631fe1…` (accepted, block 8,350,034) — two shots, 3–4 s dwell each | Narrate as the historical v2 quorum proof: "the same envelope, before and after quorum — only the quorum differs." Do NOT mention codes 10/12, `action_authorized`, or on-chain envelope binding; say envelope binding was enforced off-chain by the deterministic core in this run |
| G7a treasury execution | 8 | Cut the shot. Optionally substitute the LIVE historical browser-wallet approval receipt `56b6ea6c…` with 3–4 s dwell | If substituting, narrate only what it proves: "a real browser-wallet signature inside the quorum." Never say "treasury transfer", never mention 625/50 CSPR |
| G6 SafePay v2 | 9 | The LIVE historical SafePay Lite settlement `dcb35f42…` on CSPR.live (2.5 CSPR, verified block 8,339,447) plus the judge-page SafePay panel | Narrate as historical verified payment-before-proof only. No "consumed exactly once", no idempotent-retry or 409 claims |
| G7b official x402 | 10 | Cut the shot entirely; reallocate the 14 s as extra dwell on shots 4–7 (or the v2 fallback pair) | Never show the service or narrate WCSPR/facilitator settlement as done; do not describe it in voiceover at all |
| G9n npm verifier | 11 | LIVE consistency checker on camera: `python3 scripts/verify_concordia_receipt.py --base-url https://concordia.47.84.232.193.sslip.io --proposal-id DAO-PROP-6CB25C` | Use scope-honest words: "a consistency check of the hosted artifacts against the chain" — never "independent recompute", never mention npm |
| G10 domain / G9d docs | 12 | Same shot with the sslip URLs in the address bar; skip the docs beat | Do not say or show `concordiadao.xyz` or `docs.concordiadao.xyz` |
| WP10 hosted release (proof cockpit deployed) | 1, 2, 12 | Record on the current live dashboard surfaces at the sslip origin (Overview, Judge Walkthrough, Proof Center, certificate) | Do not narrate cockpit-only features (registry status dimensions) unless they are on screen |

Rule of thumb: the LIVE spine (shots 1, 2, 3, plus the v2 fallback pair, plus
the consistency checker, plus 12's certificate and 13) is a complete, honest
2-minute video on its own. Pending gates only ever add shots; their absence
never breaks the cut.

## Pre-flight checklist (do not skip)

Services and data:

- [ ] All judged sslip routes return 200 (run the automated link sweep; zero
      broken links).
- [ ] Dashboard, gateway, SafePay provider, and the official x402 service
      health endpoints are green; Caddy TLS valid.
- [ ] Release-manifest check: for each shot 4–12, confirm whether its gate has
      flipped. Print the fallback table and mark each shot RECORD-AS-WRITTEN or
      RECORD-FALLBACK before opening the recorder.
- [ ] Proposal selected: `DAO-PROP-6CB25C` preloaded on the Judge Walkthrough;
      the Proposal Workspace transcript renders the CHALLENGE, VERDICT,
      RESPONSE PLAN, and human APPROVAL messages.
- [ ] Every CSPR.live deploy page for the planned cut is pre-loaded in its own
      tab and fully rendered (no skeletons on camera).

Wallet:

- [ ] Casper Wallet unlocked, Testnet network selected, correct approver
      account — only if a live approval beat is planned; the default cut uses
      already-finalized deploys and needs no on-camera signing.
- [ ] Wallet extension popups tested off-camera; no pending notification
      badges visible.

Recording mode and viewport:

- [ ] Use the recording path: `/dashboard/judge?recording=1` (chrome
      suppression) and `/dashboard/record` where applicable.
- [ ] Clean browser profile: no bookmarks bar, no extra extensions, no
      unplanned tabs; macOS Focus mode on, notifications off.
- [ ] Full-screen browser, dock and menu bar hidden. Record at 1920×1080,
      100% zoom; verify CSPR.live error lines are legible at final export size.
- [ ] Microphone check; script rehearsed aloud once; ~140 wpm.

## Hard rules while recording

- **Show behavior, never payloads.** Production lesson (learned the hard way):
  raw injection/attack strings on camera trip content classifiers and prove
  nothing. Never frame the adversarial input textarea or any attack payload
  text — show only the refusal evidence: BLOCKED grids, revert codes, 409
  responses, journal entries. If a surface unavoidably shows payload text,
  crop or scroll it out of frame before rolling.
- **Never narrate a claim that isn't on screen at that moment.** Every
  sentence must be provable by the pixels under it. Juries pause videos.
- **Never conflate the three payment claims.** SafePay = native CSPR,
  supplemental. Official x402 = WCSPR via the CSPR.cloud facilitator. Treasury
  execution = quorum-authorized native transfer. Each gets its own shot and
  its own words.
- **Never present a v1/v2 historical receipt as a v3 property.** The v2 pair
  proves on-chain quorum; only v3 deploys prove on-chain envelope binding.
- **Taxonomy discipline:** four deliberative agents; Locke is an
  authorization-bound execution role; Concordia Core is deterministic
  infrastructure; Wells presents the record. No other counting.
- No secrets, tokens, `Authorization` headers, or facilitator credentials on
  screen — response bodies only, and never a 401 body.
- Dwell rule: every CSPR.live page stays on screen 3–4 full seconds minimum.
- Pronunciation: x402 = "ex-four-oh-two", CSPR.live = "Casper-dot-live",
  WCSPR = "wrapped Casper", QuorumNotMet = "quorum not met",
  EnvelopeHashMismatch = "envelope hash mismatch".
- No competitor names, no "only project" claims — let the receipts carry it.
- If any page stalls, stop and re-record the segment; no spinners on film.

## Canonical live values (verified — do not edit)

| Proof item | Canonical value |
|---|---|
| Proposal | `DAO-PROP-6CB25C` |
| Canonical reviewer receipt | `e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852` |
| Canonical v1 contract | `hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1` |
| v2 pre-quorum revert (historical) | `6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431` (`User error: 8` / QuorumNotMet, block 8,349,116) |
| v2 quorum-accepted (historical) | `9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928` (block 8,350,034) |
| Browser wallet receipt (historical) | `56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf` |
| SafePay Lite settlement (historical, native CSPR) | `dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c` (block 8,339,447) |
| IPFS archive CID | `bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq` |

Contract lineage: v1 = Jun 29 typed receipt anchor (package
`hash-992b3a45…4c4a`); v2 = Jun 30 quorum-enabled package
(`hash-1d324e31…7d96`), exact-envelope enforcement off-chain in that run; v3 =
the finals exact-envelope upgrade, values pending below.

## Pending values — fill from the release manifest before recording

Do not invent, reuse, or approximate these. Each stays blank until its gate
flips; a blank row means the corresponding shot records its fallback.

| Pending value | Gate | Fills shots |
|---|---|---|
| v3 package hash / contract hash / install deploy | G7a v3 install | 4–7 |
| v3 pre-quorum revert deploy + block (code 8) | G7a v3 four-outcome | 4 |
| v3 mutated-envelope revert deploy + block (code 10) | G7a v3 four-outcome | 5 |
| v3 exact-acceptance deploy + block + `action_authorized=true` readback | G7a v3 four-outcome | 6 |
| v3 repeat-finalization revert deploy + block (code 12) | G7a v3 four-outcome | 7 |
| Treasury native-transfer deploy + bound transfer ID + journal artifact | G7a treasury | 8 |
| SafePay v2 live artifact (first consumption / idempotent retry / 409) | G6 | 9 |
| Official x402 settlement transaction + readback artifact | G7b | 10 |
| `@concordia-dao/verify` published version | G9n | 11 |
| `concordiadao.xyz` + `docs.concordiadao.xyz` live over HTTPS | G10 / G9d | 12 |

## Links to open during recording

- Overview (persona wall): <https://concordia.47.84.232.193.sslip.io/dashboard>
- Judge Walkthrough (recording mode): <https://concordia.47.84.232.193.sslip.io/dashboard/judge?recording=1>
- Proposal Workspace (transcript): <https://concordia.47.84.232.193.sslip.io/dashboard/proposals?proposal=DAO-PROP-6CB25C>
- Proof Center: <https://concordia.47.84.232.193.sslip.io/dashboard/proof>
- HTML certificate: <https://concordia.47.84.232.193.sslip.io/certificate/DAO-PROP-6CB25C>
- v2 pre-quorum revert deploy: <https://testnet.cspr.live/deploy/6280b8e1964fb341dc82f7bf82213631591a8113abe1df47528de864bcf67431>
- v2 quorum-accepted deploy: <https://testnet.cspr.live/deploy/9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928>
- SafePay Lite historical settlement: <https://testnet.cspr.live/deploy/dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c>
- Evidence chain (backup tab): <https://concordia.47.84.232.193.sslip.io/evidence/DAO-PROP-6CB25C>
- Proof pack (backup tab): <https://concordia.47.84.232.193.sslip.io/proof-pack/DAO-PROP-6CB25C>
- v3 deploy tabs, treasury deploy tab, x402 settlement tab: add from the
  pending-values table once their gates flip.

## Upload checklist

- Visibility: **Public** (not unlisted — eligibility requirement).
- Title: `Concordia DAO Council — The Chain Says No, Four Times | Casper
  Agentic Buildathon 2026`
- Description: one-line pitch + live app URL + GitHub URL + the quorum deploy
  links + certificate URL + (once live) the v3 deploy links.
- Captions on; watch the processed upload end-to-end once at full resolution.

## Incognito / public verification checklist (before pasting the URL anywhere)

- [ ] Open the video URL in a **logged-out incognito/private window**: it
      loads, plays start to finish, and shows the correct title/description.
- [ ] Confirm visibility reads Public — not Unlisted, not Private, no
      "scheduled" state still counting down.
- [ ] Check from a second network or device (e.g., mobile data) to rule out
      account- or network-scoped access.
- [ ] Verify resolution options include the recorded quality and the CSPR.live
      error lines are legible at 1080p.
- [ ] No age-restriction, region-block, or copyright interstitial appears.
- [ ] Only after all boxes: replace the video link in the BUIDL page and the
      submission text, then re-open **that** published page in incognito and
      click through to the video once more.
