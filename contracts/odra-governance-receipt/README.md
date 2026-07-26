# Odra Multi-Contract Governance Migration

This is the Wasm-build-checked Odra-oriented migration package for Concordia. The canonical live proof uses the deployed Odra `GovernanceReceipt` contract, and this package also splits production governance state into separate Casper contract domains.

Modules included:

- `CouncilRegistry`: council agent credential registry.
- `CardIndexLedger`: tamper-evident card-root index by proposal and sequence.
- `TreasuryPolicy`: allocation caps and deterministic policy checks.
- `GovernanceReceipt`: typed final receipt anchoring.

The `GovernanceReceipt` API is the live proof path. Numeric governance values such as `risk_score` and `approved_allocation_bps` are native `u32` fields instead of strings.

Verification:

```bash
python scripts/verify_odra_migration.py
cd contracts/odra-governance-receipt && cargo +nightly check
cd contracts/odra-governance-receipt && RUSTFLAGS='-C link-arg=--allow-undefined' cargo +nightly build --target wasm32-unknown-unknown --release --bin concordia_odra_governance_receipt_build_contract
```

The `RUSTFLAGS` line allows the normal Casper host imports that Odra/Casper contracts resolve at runtime. Generated `target/` files are intentionally excluded from clean source archives; the manifest records the local SHA-256 values for reproducibility. The qualification video should use the deployed Odra `GovernanceReceipt` contract hash and processed Testnet deploy recorded in `migration.manifest.json`. `CouncilRegistry`, `TreasuryPolicy`, and `CardIndexLedger` now also have supplemental independent Testnet install/call hashes recorded in `artifacts/live/odra-topology-genesis-proof.json`; those hashes prove auxiliary module execution but do not replace the canonical reviewer receipt.
