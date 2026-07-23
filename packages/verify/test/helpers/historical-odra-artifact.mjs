import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const REPOSITORY = fileURLToPath(new URL("../../../../", import.meta.url));
const PROPOSAL_ID = "DAO-PROP-6CB25C";
const PACKAGE_HASH = "92".repeat(32);
const CONTRACT_HASH = "a8".repeat(32);
const WASM_HASH = "24".repeat(32);
const BLOCK_HASH = "ab".repeat(32);
const STATE_ROOT_HASH = "cd".repeat(32);
const BLOCK_HEIGHT = 8_340_490;
const V1_ARGUMENT_ORDER = [
  "proposal_id",
  "proposal_type",
  "proposal_hash",
  "final_card_hash",
  "plan_hash",
  "decision",
  "risk_level",
  "risk_score",
  "treasury_action",
  "policy_hash",
  "policy_version",
  "dissent_hash",
  "approved_allocation_bps",
  "casper_network",
  "agent_council_version",
  "evidence_uri",
  "agent_action_hash",
];
const V2_ARGUMENT_ORDER = [
  "proposal_id",
  "proposal_type",
  "proposal_hash",
  "policy_hash",
  "dissent_hash",
  "final_card_hash",
  "plan_hash",
  "agent_action_hash",
  "approved_allocation_bps",
  "risk_score",
  "risk_level",
  "decision",
  "treasury_action",
  "policy_version",
  "casper_network",
  "agent_council_version",
  "evidence_uri",
];
const ARGUMENT_TYPES = {
  proposal_id: "String",
  proposal_type: "String",
  proposal_hash: "ByteArray(32)",
  policy_hash: "ByteArray(32)",
  dissent_hash: "ByteArray(32)",
  final_card_hash: "ByteArray(32)",
  plan_hash: "ByteArray(32)",
  agent_action_hash: "ByteArray(32)",
  approved_allocation_bps: "U32",
  risk_score: "U32",
  risk_level: "String",
  decision: "String",
  treasury_action: "String",
  policy_version: "String",
  casper_network: "String",
  agent_council_version: "String",
  evidence_uri: "String",
};

function sha256Utf8(value) {
  return createHash("sha256").update(Buffer.from(value, "utf8")).digest("hex");
}

function cardChain() {
  const first = JSON.stringify({
    card_type: "ProposalCard",
    previous_card_hash: null,
    sequence_number: 1,
    signal_id: PROPOSAL_ID,
    summary: "An AI requested 30%.",
  });
  const firstHash = sha256Utf8(first);
  const second = JSON.stringify({
    card_type: "ConstitutionalDecision",
    previous_card_hash: firstHash,
    proposal_id: PROPOSAL_ID,
    sequence_number: 2,
    approved_allocation_bps: 800,
  });
  const secondHash = sha256Utf8(second);
  const third = JSON.stringify({
    card_type: "CasperExecutionReceipt",
    previous_card_hash: secondHash,
    proposal_id: PROPOSAL_ID,
    sequence_number: 3,
    status: "accepted",
  });
  const thirdHash = sha256Utf8(third);
  return {
    schema_version: "concordia.card_chain.v1",
    proposal_id: PROPOSAL_ID,
    captured_at: "2026-07-23T01:00:00Z",
    source_url: `https://concordia.example/proof-artifacts/v1/${PROPOSAL_ID}/card-chain`,
    cards: [
      { sequence_number: 1, card_type: "ProposalCard", card_hash: firstHash, canonical_card_json: first, published_at: "2026-06-01T10:00:00Z" },
      { sequence_number: 2, card_type: "ConstitutionalDecision", card_hash: secondHash, canonical_card_json: second, published_at: "2026-06-01T10:01:00Z" },
      { sequence_number: 3, card_type: "CasperExecutionReceipt", card_hash: thirdHash, canonical_card_json: third, published_at: null },
    ],
  };
}

function rpc(id, method, params, result) {
  return {
    request: { jsonrpc: "2.0", id, method, params },
    response: { jsonrpc: "2.0", id, result: { name: `${method}_result`, value: result } },
  };
}

export function buildSignedHistoricalReceiptDeploy(finalCardHash, generation = "v1") {
  const script = String.raw`
import hashlib, json, sys
from pycspr import serializer
from pycspr.factory.accounts import parse_private_key_bytes
from pycspr.types.crypto import KeyAlgorithm
from shared.casper_executor import (
    _assemble_generic_contract_call_deploy,
    _assemble_pycspr_deploy,
    build_receipt_request,
    typed_runtime_args_preview,
)

proposal_id, final_card_hash, target_hash, generation = sys.argv[1:]
private = parse_private_key_bytes(bytes([9]) * 32, KeyAlgorithm.ED25519)
request = build_receipt_request(
    proposal_id=proposal_id,
    action_hash="11" * 32,
    final_card_hash=final_card_hash,
    plan_hash="22" * 32,
    parameters={
        "proposal_type": "DEFI_TREASURY_REALLOCATION",
        "decision": "APPROVED",
        "risk_level": "high",
        "risk_score": "84",
        "treasury_action": "record_governance_decision",
        "policy_hash": "33" * 32,
        "policy_version": "2026.06.cas-v1",
        "dissent_hash": "44" * 32,
        "approved_allocation_bps": "800",
        "casper_network": "casper-test",
        "agent_council_version": "concordia-dao-council-2026.06",
        "evidence_uri": "https://concordia.example/evidence/DAO-PROP-6CB25C",
    },
)
if generation == "v1":
    deploy = _assemble_pycspr_deploy(
        request,
        account=private,
        contract_hash="hash-" + target_hash,
        entry_point="store_governance_receipt",
        chain_name="casper-test",
        payment_amount=5_000_000_000,
        ttl="30m",
    )
else:
    order = [
        "proposal_id", "proposal_type", "proposal_hash", "policy_hash",
        "dissent_hash", "final_card_hash", "plan_hash", "agent_action_hash",
        "approved_allocation_bps", "risk_score", "risk_level", "decision",
        "treasury_action", "policy_version", "casper_network",
        "agent_council_version", "evidence_uri",
    ]
    preview = typed_runtime_args_preview(request)
    deploy = _assemble_generic_contract_call_deploy(
        account=private,
        contract_hash="package-" + target_hash,
        entry_point="store_governance_receipt",
        argument_specs={name: preview[name] for name in order},
        chain_name="casper-test",
        payment_amount=5_000_000_000,
        ttl="30m",
        call_target="package",
        contract_version=1,
    )
deploy.approve(private)
arguments = deploy.session.arguments
preimage = len(arguments).to_bytes(4, "little") + b"".join(
    serializer.to_bytes(argument) for argument in arguments
)
print(json.dumps({
    "deploy": serializer.to_json(deploy),
    "argument_digest": hashlib.sha256(preimage).hexdigest(),
}, sort_keys=True, separators=(",", ":")))
`;
  const target = generation === "v1" ? CONTRACT_HASH : PACKAGE_HASH;
  return JSON.parse(execFileSync(
    "uv",
    ["run", "--frozen", "--python", "python3.12", "python", "-c", script, PROPOSAL_ID, finalCardHash, target, generation],
    { cwd: REPOSITORY, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 },
  ));
}

export async function buildHistoricalOdraArtifact() {
  const cards = cardChain();
  const finalCardHash = cards.cards.at(-1).card_hash;
  const signed = buildSignedHistoricalReceiptDeploy(finalCardHash, "v1");
  const deploy = signed.deploy;
  const deployHash = deploy.hash.toLowerCase();
  const inventoryObject = {
    schema_version: "concordia.historical_odra_inventory.v1",
    network: "casper-test",
    receipt_argument_types: ARGUMENT_TYPES,
    chain_identity: {
      v1: {
        package_hash: PACKAGE_HASH,
        contract_hash: CONTRACT_HASH,
        contract_wasm_state_hash: WASM_HASH,
        contract_version: 1,
        protocol_version_major: 2,
        install_deploy_hash: "31".repeat(32),
        install_block_height: BLOCK_HEIGHT - 100,
        entry_point: "store_governance_receipt",
        accepted_session: {
          variant: "StoredContractByHash",
          target_kind: "contract",
          target_hash: CONTRACT_HASH,
          version: null,
          final_card_hash: finalCardHash,
          card_chain_binding: "canonical_export_required",
          argument_order: V1_ARGUMENT_ORDER,
        },
        receipt_deploys: { canonical_accepted: deployHash },
      },
      v2: {
        package_hash: "1d".repeat(32),
        contract_hash: "fd".repeat(32),
        contract_wasm_state_hash: "42".repeat(32),
        contract_version: 1,
        protocol_version_major: 2,
        install_deploy_hash: "62".repeat(32),
        install_block_height: BLOCK_HEIGHT + 100,
        entry_point: "store_governance_receipt",
        accepted_session: {
          variant: "StoredVersionedContractByHash",
          target_kind: "package",
          target_hash: "1d".repeat(32),
          version: 1,
          final_card_hash: "71".repeat(32),
          card_chain_binding: "separate_export_required",
          argument_order: V2_ARGUMENT_ORDER,
        },
        receipt_deploys: {
          pre_quorum_expected_rejection: "62".repeat(32),
          post_quorum_accepted: "9d".repeat(32),
        },
      },
    },
    preserved_repo_source: {
      baseline_commit: "b".repeat(40),
      manifest_path: "handoff/HISTORICAL_ODRA_SHA256.txt",
      manifest_sha256: "b0".repeat(32),
      governance_receipt_wasm_path: "contracts/odra-governance-receipt/wasm/GovernanceReceipt.wasm",
      governance_receipt_wasm_sha256: "07".repeat(32),
      source_deployment_equivalence: "unproven",
    },
  };
  const inventoryText = `${JSON.stringify(inventoryObject, null, 2)}\n`;
  const inventoryBytes = Buffer.from(inventoryText, "utf8");
  const inventorySha256 = sha256Utf8(inventoryText);
  const executionResult = {
    Version2: {
      initiator: { PublicKey: deploy.header.account },
      error_message: null,
      current_price: 1,
      limit: "5000000000",
      consumed: "100000000",
      cost: "100000000",
      refund: "0",
      transfers: [],
      size_estimate: 512,
      effects: [],
    },
  };
  const artifact = {
    schema_version: "concordia.historical_odra_receipt.v1",
    proposal_id: PROPOSAL_ID,
    generation: "v1",
    captured_at: "2026-07-23T01:00:00Z",
    source_commit: "1".repeat(40),
    deployment_commit: "2".repeat(40),
    source_url: `https://concordia.example/proof-artifacts/v1/${PROPOSAL_ID}/historical-odra-receipt`,
    network: "casper-test",
    lineage_inventory: {
      schema_version: "concordia.historical_odra_inventory.v1",
      sha256: inventorySha256,
      canonical_json: inventoryText,
    },
    contract_identity: {
      package_hash: PACKAGE_HASH,
      contract_hash: CONTRACT_HASH,
      contract_wasm_state_hash: WASM_HASH,
      contract_version: 1,
      protocol_version_major: 2,
      entry_point: "store_governance_receipt",
      session_variant: "StoredContractByHash",
      session_target_kind: "contract",
      session_target_hash: CONTRACT_HASH,
      session_version: null,
    },
    card_chain: cards,
    raw_rpc: {
      deploy: rpc(1, "info_get_deploy", { deploy_hash: deployHash }, {
        api_version: "2.0.0",
        deploy,
        execution_info: {
          block_hash: BLOCK_HASH,
          block_height: BLOCK_HEIGHT,
          execution_result: executionResult,
        },
      }),
      canonical_block: rpc(2, "chain_get_block", { block_identifier: { Hash: BLOCK_HASH } }, {
        api_version: "2.0.0",
        block_with_signatures: {
          block: {
            Version2: {
              hash: BLOCK_HASH,
              header: { height: BLOCK_HEIGHT, state_root_hash: STATE_ROOT_HASH, parent_hash: "aa".repeat(32) },
              body: { transactions: { "0": [{ Deploy: deployHash }] } },
            },
          },
          proofs: [],
        },
      }),
      state_root: rpc(3, "chain_get_state_root_hash", { block_identifier: { Hash: BLOCK_HASH } }, {
        api_version: "2.0.0",
        state_root_hash: STATE_ROOT_HASH,
      }),
      package: rpc(4, "query_global_state", {
        state_identifier: { StateRootHash: STATE_ROOT_HASH },
        key: `hash-${PACKAGE_HASH}`,
        path: [],
      }, {
        api_version: "2.0.0",
        stored_value: {
          ContractPackage: {
            access_key: `uref-${"ef".repeat(32)}-007`,
            versions: [{ protocol_version_major: 2, contract_version: 1, contract_hash: `contract-${CONTRACT_HASH}` }],
            disabled_versions: [],
            groups: [],
            lock_status: "Locked",
          },
        },
        merkle_proof: "00",
      }),
      contract: rpc(5, "query_global_state", {
        state_identifier: { StateRootHash: STATE_ROOT_HASH },
        key: `hash-${CONTRACT_HASH}`,
        path: [],
      }, {
        api_version: "2.0.0",
        stored_value: {
          Contract: {
            contract_package_hash: `contract-package-${PACKAGE_HASH}`,
            contract_wasm_hash: `contract-wasm-${WASM_HASH}`,
            named_keys: [],
            entry_points: [{ name: "store_governance_receipt" }],
            protocol_version: "2.0.0",
          },
        },
        merkle_proof: "00",
      }),
    },
  };
  return {
    artifact,
    inventoryBytes,
    inventorySha256,
    pythonArgumentDigest: signed.argument_digest,
  };
}
