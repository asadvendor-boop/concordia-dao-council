# Casper Deployment Guide

This checklist turns Concordia from rehearsal mode into a real Casper Testnet proof.

## 0. Create and fund a Testnet keypair

Use a dedicated Testnet account for the demo. Do not reuse a mainnet key.

Concordia runtime expects a PEM secret key:

```text
/opt/apps/concordia/secrets/casper_secret_key.pem
```

Create the keypair with your preferred Casper wallet or trusted local Casper tooling, copy the public key hex, fund it from the Casper Testnet faucet, and wait until `state_get_account_info` can see the account.

## 1. Build the receipt contract

```bash
cd contracts/governance-receipt
rustup toolchain install nightly-2025-02-01 --profile minimal
rustup +nightly-2025-02-01 target add wasm32-unknown-unknown
cargo +nightly-2025-02-01 build --release --target wasm32-unknown-unknown
```

The Wasm output is:

```text
contracts/governance-receipt/target/wasm32-unknown-unknown/release/concordia_governance_receipt.wasm
```

## 2. Install the contract on Casper Testnet

On the shared ECS host, after the key is funded:

```bash
cd /opt/apps/concordia/src
uv run python scripts/finalize_casper_shared_host.py
```

The setup script uses Python-native Casper deploy assembly:

```text
Wasm bytes -> pycspr DeployOfModuleBytes -> signed deploy JSON -> HTTPS JSON-RPC account_put_deploy
```

It then polls `state_get_account_info` for the `concordia_governance_receipt` named key, patches `/opt/apps/concordia/shared-host/concordia.env`, restarts Concordia, and reruns `scripts/casper_preflight.py --network`.

The setup script intentionally stops before the final governance receipt transaction. Locke still submits that transaction only after the approved Concordia proposal flow.

## 3. Configure real Locke execution

```bash
CASPER_EXECUTION_MODE=real
CASPER_EXECUTION_DRIVER=pycspr
CONCORDIA_PYCSPR_DRY_RUN=0
CASPER_SECRET_KEY_PATH=/run/secrets/casper_secret_key
CASPER_RECEIPT_CONTRACT_HASH=hash-your-testnet-contract
CASPER_NODE_ADDRESS=https://node.testnet.casper.network
CSPR_NODE_RPC_URL=https://node.testnet.casper.network/rpc
CASPER_CHAIN_NAME=casper-test
CASPER_PAYMENT_AMOUNT=5000000000
CASPER_ENTRY_POINT=store_governance_receipt
```

The hosted backend image does not install or call host Casper CLI binaries or Node.js SDK scripts for Locke's proof transaction. `shared/casper_executor.py` builds typed `pycspr` CLValues, signs the stored-contract deploy in Python, serializes it to Casper JSON, and broadcasts through HTTPS JSON-RPC.

## 4. Run preflight

```bash
make casper-preflight
python scripts/casper_preflight.py --network
```

Preflight fails if the key path is unreadable, `pycspr` is unavailable, or `CASPER_RECEIPT_CONTRACT_HASH` is missing the `hash-` prefix.

## 5. Runtime argument format

The receipt contract expects typed Casper values:

```text
proposal_hash: ByteArray(32)
final_card_hash: ByteArray(32)
plan_hash: ByteArray(32)
policy_hash: ByteArray(32)
dissent_hash: ByteArray(32)
agent_action_hash: ByteArray(32)
risk_score: U32
approved_allocation_bps: U32
```

Human-readable metadata stays as CL `String`; hashes and governance numbers are not flattened into text.

## 6. Final proof artifacts

Save these values after Locke executes the approved envelope:

```text
contract hash
transaction/deploy hash
proposal ID
final card hash
plan hash
policy hash
dissent hash
approved allocation bps
entry point: store_governance_receipt
evidence URL
```

The transaction hash must be visible in the demo and copied into `docs/SUBMISSION_PACKET.md` before publishing the repository.

## 7. Current shared-host deployment status

Current hosted review deployment:

```text
https://concordia.47.84.232.193.sslip.io/dashboard
```

Current state until funding/deployment is completed:

```text
Casper Testnet public read: working
Hosted Locke driver: pycspr native Python JSON-RPC
Testnet public key: 019aeeb6276a9bfe8534a1b51cc7c1e0b72b63cd307566f08d91223bee9e610151
CASPER_EXECUTION_MODE=mock
CASPER_RECEIPT_CONTRACT_HASH=hash-0000000000000000000000000000000000000000000000000000000000000000
```

Do not record the final submission proof until this changes to real execution and Locke returns a processed Casper Testnet transaction hash.

### Discord-Sourced Testnet Troubleshooting Notes

These are non-authoritative operational notes from Casper buildathon support channels and are kept only as troubleshooting hints:

- Buildathon contract proof should target Casper Testnet.
- `casper-client put-transaction` pricing-mode errors on protocol 2.2.x may require `--gas-price-tolerance 1`; Concordia's final receipt path uses Python-native `pycspr` JSON-RPC, so this is only relevant to manual CLI recovery.
- Odra 2.8.2 has been reported by builders to avoid some pricing-mode failures seen with older Odra/client combinations.
- The public faucet is one-time per account lifecycle; create a fresh account for another faucet claim.
- Fresh accounts may need enough testnet CSPR to cover account/purse creation and deploy gas before contract installation.
