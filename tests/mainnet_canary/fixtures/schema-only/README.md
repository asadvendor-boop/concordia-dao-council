# Schema-only fixtures — Mainnet canary preparation lane

These documents describe the exact shapes of the future operator inputs and
future live artifacts.  They are deliberately **fixture-free**: every
evidence field is `null` and every claim field is
`"BLOCKED_PENDING_LIVE_PROOF"`.  They contain **no** invented hashes,
receipts, block heights, proposal IDs, deploy hashes, or `verified` booleans.

Real values may only ever be produced by Codex's future live gate and land
under `artifacts/mainnet-canary/v3/<canary-id>/**` with
`provenance=mainnet_supplemental`.  The preparation branch never creates
those artifacts.
