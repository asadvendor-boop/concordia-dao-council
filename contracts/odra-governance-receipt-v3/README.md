# Concordia Governance Receipt v3

This sibling Odra contract implements the frozen typed exact-envelope v3 ABI.
It does not modify or upgrade the historical v1/v2 packages, and it does not
transfer or custody assets. A successful finalization is an on-chain
authorization receipt for one exact typed action.

Normative interfaces and encodings are frozen at the repository tag
`concordia-g1-freeze-v2.0-a` in `handoff/G1_INTERFACE_SPEC.md` and
`handoff/G1_FREEZE_MANIFEST.json`.

## Reproducible local gates

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked
ODRA_MODULE=GovernanceReceiptV3 \
  RUSTFLAGS='-C link-arg=--allow-undefined' \
  cargo build --locked --target wasm32-unknown-unknown --release \
  --bin concordia_odra_governance_receipt_v3_build_contract
ODRA_MODULE=GovernanceReceiptV3 \
  cargo run --locked --bin concordia_odra_governance_receipt_v3_build_schema
```

The installation transaction must supply these Odra configuration arguments
exactly:

- `odra_cfg_package_hash_key_name=concordia_governance_receipt_v3`
- `odra_cfg_is_upgradable=false`
- `odra_cfg_allow_key_override=false`
- `odra_cfg_is_upgrade=false`

The package-key name is part of the deployment-domain preimage. A deployment
using a different value is invalid even if the Wasm itself is unchanged.

The flattened constructor ABI represents account identities as `ByteArray(32)`.
It cannot recover whether arbitrary bytes originally came from an account,
contract, or package. Every release install must therefore be assembled by
`scripts/install_governance_receipt_v3.py` (or the Rust
`validated_deployment_init_args` boundary), which proves account provenance,
role separation, threshold, chain, nonce, and all four locked Odra flags before
building the deploy. Hand-written installer arguments are unsupported.

The generated schema's `call.wasm_file_name` is authoritative. The validated
release artifact is `wasm/GovernanceReceiptV3.wasm`; `target/` is a disposable,
ignored cache and must never be staged.

## Release and mixed-custody tooling

Both commands are prepare-only unless `--submit` is present. Preparing creates
the authoritative journal with mode `0600`, fsyncs the exact signed Casper
deploy and immutable intent, and performs no network request. Keep the journal;
`--manifest-out` and `--out` are verified result artifacts, not resumable state.

The installer requires a clean Git tree. `REVIEWED_40_HEX_COMMIT` must contain
the exact release files and `RELEASE_40_HEX_COMMIT` must equal the current HEAD.
Prepare the install:

```sh
uv run python scripts/install_governance_receipt_v3.py \
  --secret-key /run/secrets/v3_installer \
  --key-algorithm ED25519 \
  --roles artifacts/private/v3-roles.json \
  --installation-nonce NONZERO_32_BYTE_LOWERCASE_HEX \
  --wasm contracts/odra-governance-receipt-v3/wasm/GovernanceReceiptV3.wasm \
  --schema contracts/odra-governance-receipt-v3/resources/casper_contract_schemas/governance_receiptv3_schema.json \
  --source-commit REVIEWED_40_HEX_COMMIT \
  --deployment-commit RELEASE_40_HEX_COMMIT \
  --journal artifacts/private/v3-install.journal.json \
  --manifest-out artifacts/private/v3-deployment.json
```

After inspecting the journal, submit or resume the same deploy. The two URLs
must be distinct, canonical public HTTPS `/rpc` endpoints with disjoint public
DNS addresses:

```sh
uv run python scripts/install_governance_receipt_v3.py \
  --secret-key /run/secrets/v3_installer \
  --key-algorithm ED25519 \
  --roles artifacts/private/v3-roles.json \
  --installation-nonce NONZERO_32_BYTE_LOWERCASE_HEX \
  --wasm contracts/odra-governance-receipt-v3/wasm/GovernanceReceiptV3.wasm \
  --schema contracts/odra-governance-receipt-v3/resources/casper_contract_schemas/governance_receiptv3_schema.json \
  --source-commit REVIEWED_40_HEX_COMMIT \
  --deployment-commit RELEASE_40_HEX_COMMIT \
  --journal artifacts/private/v3-install.journal.json \
  --manifest-out artifacts/private/v3-deployment.json \
  --rpc-url https://FIRST-INDEPENDENT-NODE.example/rpc \
  --rpc-url https://SECOND-INDEPENDENT-NODE.example/rpc \
  --submit
```

If the process loses the broadcast response, run that exact submit command
again. It reconciles the saved hash and never rebuilds or rebroadcasts an
ambiguous deploy. Finality requires both nodes to return the deploy and agree
on its hash-pinned canonical block inclusion, height, state root, and block
timestamp. An expired deploy becomes terminal only when both nodes return the
exact not-found error.

Do not put browser-wallet private keys in that role file. A browser role uses
only `{ "custody": "browser", "public_key": "..." }`; a server role names a
mounted key path and algorithm. The live runner stops before every browser
step and atomically writes a sealed checkpoint containing:

- the exact unsigned deploy;
- the signer role and public key;
- network, package, contract, entry point, and argument digest;
- the completed finalized-step prefix; and
- a raw, hash-pinned block/contract/package state readback.

Prepare the first live-proof deploy without network access:

```sh
uv run python scripts/run_v3_live_proof.py artifacts/private/native-input.json \
  --roles artifacts/private/v3-role-custody.json \
  --package-hash EXACT_PACKAGE_HASH \
  --contract-hash EXACT_CONTRACT_HASH \
  --journal artifacts/private/v3-run.journal.json \
  --out artifacts/private/v3-run.json
```

Submit or reconcile the authoritative journal:

```sh
uv run python scripts/run_v3_live_proof.py artifacts/private/native-input.json \
  --roles artifacts/private/v3-role-custody.json \
  --package-hash EXACT_PACKAGE_HASH \
  --contract-hash EXACT_CONTRACT_HASH \
  --journal artifacts/private/v3-run.journal.json \
  --out artifacts/private/v3-run.json \
  --resume-checkpoint artifacts/private/v3-run.journal.json \
  --rpc-url https://FIRST-INDEPENDENT-NODE.example/rpc \
  --rpc-url https://SECOND-INDEPENDENT-NODE.example/rpc \
  --submit
```

Sign only the checkpoint's `run.steps[next_step_index].deploy` in the named
wallet, export the resulting raw signed deploy JSON, then resume while updating
the same checkpoint path:

```sh
uv run python scripts/run_v3_live_proof.py artifacts/private/native-input.json \
  --roles artifacts/private/v3-role-custody.json \
  --package-hash EXACT_PACKAGE_HASH \
  --contract-hash EXACT_CONTRACT_HASH \
  --resume-checkpoint artifacts/private/v3-run.journal.json \
  --signed-deploy artifacts/private/browser-signed-deploy.json \
  --journal artifacts/private/v3-run.journal.json \
  --out artifacts/private/v3-run.json \
  --rpc-url https://FIRST-INDEPENDENT-NODE.example/rpc \
  --rpc-url https://SECOND-INDEPENDENT-NODE.example/rpc \
  --submit
```

An imported deploy is single-use. Wrong or stale checkpoints, changed roles,
network aliases, package/contract drift, changed entry points or arguments,
invalid signatures, and duplicate imports fail before broadcast. The runner
persists the staged signed deploy before broadcasting it, so a restart can
resume from the checkpoint without requesting or accepting a second import.
Repeat the submit/resume command at each custody boundary. The final
`v3-run.json` is written only after all seven steps and the state readback have
verified.

Assemble the self-contained proof only from those verified artifacts, then run
the offline verifier:

```sh
jq -n \
  --slurpfile deployment artifacts/private/v3-deployment.json \
  --slurpfile input artifacts/private/native-input.json \
  --slurpfile run artifacts/private/v3-run.json \
  '{schema_id:"concordia.v3-proof.v1",deployment:$deployment[0],input:$input[0],prepared:$run[0].prepared,run:$run[0],readback:$run[0].readback}' \
  > artifacts/private/v3-proof.json

uv run python scripts/verify_v3_proof.py artifacts/private/v3-proof.json
```

The threshold is exactly `2`. The negative finalization always changes
`approved_allocation_bps` to `3000`, except an approved value of `3000` changes
to `2999`. Every durable step carries two-node block evidence with
`block_timestamp == finalized_at`; `observed_at` is a separate local UTC time
recorded after corroboration.
