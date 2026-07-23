"""Pinned constants for the Concordia Mainnet canary preparation lane.

Nothing here asserts that anything is deployed or verified on Mainnet.
Live-proof fields elsewhere must remain ``BLOCKED_PENDING_LIVE_PROOF`` until
Codex executes the live gate.
"""

from __future__ import annotations

# --- Preparation-lane provenance -------------------------------------------

# Exact head of codex/finals-core-v3 this branch is based on.
PREP_BASE_SHA = "7668fa46629cca02a7eb087b9a9873c0a8479912"

# Marker for every claim that only the future live gate can prove.
BLOCKED_PENDING_LIVE_PROOF = "BLOCKED_PENDING_LIVE_PROOF"

# Endpoint constants that were pinned from in-repo spec/docs without a live
# probe carry this marker instead of a live observation.
UNVERIFIED_OFFLINE = "UNVERIFIED_OFFLINE"

# --- Network identity --------------------------------------------------------

MAINNET_CHAIN_NAME = "casper"
TESTNET_CHAIN_NAME = "casper-test"

# Official Casper Association Mainnet RPC (credential-free HTTPS, path /rpc,
# mirroring the Testnet convention already pinned in deploy/shared-host).
MAINNET_RPC_URL = "https://node.mainnet.casper.network/rpc"

# Read-only, credential-free `info_get_status` observation of the pinned
# endpoint performed during preparation.  This is an observation of the public
# network, not a deployment claim.
MAINNET_RPC_OBSERVATION = {
    "endpoint": MAINNET_RPC_URL,
    "observed_at": "2026-07-23T06:45:02Z",
    "api_version": "2.0.0",
    "chainspec_name": MAINNET_CHAIN_NAME,
    "protocol_version": "2.2.2",
    "authorization_header_sent": False,
}

# A second disjoint-host public endpoint (required by the repo's two-endpoint
# read policy in shared/casper_rpc_transport.py) has deliberately NOT been
# pinned: Codex must nominate it.  Guessing one would violate the pin policy.
MAINNET_SECONDARY_RPC_URL: str | None = None

# --- Frozen v3 contract facts (from the RC base, Testnet build) -------------

PACKAGE_KEY_NAME = "concordia_governance_receipt_v3"
CONTRACT_NAME = "GovernanceReceiptV3"

# SHA-256 of contracts/odra-governance-receipt-v3/wasm/GovernanceReceiptV3.wasm
# at PREP_BASE_SHA.  This is the TESTNET RC build: its embedded constructor
# validation only accepts chain name `casper-test`, so this exact Wasm cannot
# initialise on Mainnet.  See the interface manifest (blocking finding B1).
TESTNET_RC_WASM_SHA256_AT_PREP_BASE = (
    "6605611e9649e513fe343e176d5427b317c5214c41fef340fcbb76180baa5564"
)

# Stable v3 error codes (contracts/odra-governance-receipt-v3/src/lib.rs).
V3_ERROR_CODES = {
    "InvalidSignerSet": 1,
    "InvalidThreshold": 2,
    "InvalidRoleAddress": 3,
    "UnauthorizedProposer": 4,
    "UnauthorizedSigner": 5,
    "UnauthorizedFinalizer": 6,
    "ProposalAlreadyExists": 7,
    "QuorumNotMet": 8,
    "ProposalMissing": 9,
    "EnvelopeHashMismatch": 10,
    "AlreadyApproved": 11,
    "AlreadyFinalized": 12,
    "ActionAlreadyAuthorized": 13,
    "InvalidProposalId": 14,
    "InvalidEnvelopeField": 15,
    "InvalidActionField": 16,
}

# On-wire execution-error rendering used across this repo's frozen readback
# fixtures: `execution_result.Version2.error_message == "User error: <code>"`.
USER_ERROR_PREFIX = "User error: "
EXPECTED_PREQUORUM_ERROR_MESSAGE = (
    f"{USER_ERROR_PREFIX}{V3_ERROR_CODES['QuorumNotMet']}"
)
EXPECTED_POSTQUORUM_MUTATION_ERROR_MESSAGE = (
    f"{USER_ERROR_PREFIX}{V3_ERROR_CODES['EnvelopeHashMismatch']}"
)
EXPECTED_DUPLICATE_FINALIZE_ERROR_MESSAGE = (
    f"{USER_ERROR_PREFIX}{V3_ERROR_CODES['AlreadyFinalized']}"
)

# --- Future mount paths (referenced only; NEVER read by this lane) ----------

# Codex-issued live authorization document (public approval, contains no
# secret).  Its absence is the stable broadcast refusal in this lane.
LIVE_AUTHORIZATION_MOUNT_PATH = (
    "/run/concordia/mainnet_canary/live_authorization.json"
)

# Public half of the dedicated Mainnet key inventory (public keys and account
# hashes only).  Supplied later by Codex/Asad through file mounts.
PUBLIC_KEY_INVENTORY_MOUNT_PATH = (
    "/run/concordia/mainnet_canary/public_key_inventory.json"
)

# Directory that will hold the dedicated Mainnet signing keys for the future
# live lane.  This tooling only ever validates that inventory entries point
# below this prefix; it never opens, lists, or tests anything under it.
SECRET_KEY_MOUNT_PREFIX = "/run/secrets/mainnet_canary/"

# --- Network identity (CAIP-2) ----------------------------------------------

TESTNET_CAIP2_IDENTITY = "casper:casper-test"
MAINNET_CAIP2_IDENTITY = "casper:casper"

# Confirmation depth both RPC providers must independently show beyond a
# block before an economic conclusion is drawn from it (belt-and-suspenders on
# top of Casper 2.x per-block finality signatures).
FINALITY_CONFIRMATION_DEPTH = 8

# OfficialX402SettlementV1 on the Mainnet-native contract profile: pinned
# fail-closed outcome until a live Mainnet `/supported` observation
# independently pins the real asset constants. `InvalidActionField` (16) is
# the contract-level refusal every x402 action hits on that profile.
MAINNET_X402_PINNED_REFUSAL = (
    f"{USER_ERROR_PREFIX}{V3_ERROR_CODES['InvalidActionField']}"
)

# --- Artifact lineage --------------------------------------------------------

# Future live artifacts namespace (never created by the preparation branch).
MAINNET_ARTIFACT_NAMESPACE = "artifacts/mainnet-canary/v3/"
MAINNET_SUPPLEMENTAL_PROVENANCE = "mainnet_supplemental"

# Supplemental output namespace for canary evidence bundles; a path policy
# instance only ever permits in-repo writes below
# `artifacts/mainnet-canary/<canary_id>/` and only with explicit live-capture
# authorization (never granted in the preparation lane).
CANARY_OUTPUT_NAMESPACE = "artifacts/mainnet-canary/"

# Canonical/Testnet evidence namespaces that Mainnet supplemental records may
# never overwrite or re-label.
PROTECTED_CANONICAL_PREFIXES = (
    "artifacts/live/",
    "artifacts/rwa/",
    "handoff/HISTORICAL_",
)

# --- Roles -------------------------------------------------------------------

GOVERNANCE_ROLES = ("proposer", "finalizer", "signer_a", "signer_b", "signer_c")
EXECUTION_ROLES = ("treasury_source", "recipient")
ALL_ROLES = GOVERNANCE_ROLES + EXECUTION_ROLES

# --- Cost model --------------------------------------------------------------

# Fixed, ordered cost line items.  Refusal proofs are never treated as free.
COST_LINE_ITEMS = (
    "contract_install",
    "propose_envelope",
    "approve_envelope_vote_a",
    "approve_envelope_vote_b",
    "prequorum_finalize_refusal",
    "finalize_native_transfer",
    "wrong_envelope_refusal_optional",
    "native_transfer",
    "safety_buffer",
)

# Future Codex-published measured-cost document (exact-equivalent Testnet
# deploys of the v3 RC).  Absent at PREP_BASE_SHA, so every line is UNKNOWN.
MEASURED_TESTNET_COSTS_RELPATH = (
    "artifacts/mainnet-canary/testnet-measured-costs.v1.json"
)

# --- Staleness policy for treasury snapshots --------------------------------

SNAPSHOT_MAX_HEIGHT_LAG = 32
SNAPSHOT_MAX_AGE_SECONDS = 600
