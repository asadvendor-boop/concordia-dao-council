"""Deterministic Mainnet transaction plan (no signing, no network mutation).

``plan`` produces the exact ordered transaction plan for the canary proof
sequence A..K: canonical typed arguments, expected hashes, expected refusal
codes, role/signature requirements, and the dependency graph.  All
identifiers are recomputed by two independent implementations and the frozen
G1 golden vectors are re-proven first (see ``crosscheck``).

The plan requires dedicated Mainnet identities and refuses any account hash
that already appears in the repo's canonical Testnet artifacts, so the funded
Testnet treasury can never become an operational dependency.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from tools.mainnet_canary.constants import (
    BLOCKED_PENDING_LIVE_PROOF,
    MAINNET_CHAIN_NAME,
    MAINNET_RPC_URL,
    PACKAGE_KEY_NAME,
    PREP_BASE_SHA,
    SNAPSHOT_MAX_AGE_SECONDS,
    SNAPSHOT_MAX_HEIGHT_LAG,
)
from tools.mainnet_canary.crosscheck import (
    recompute_native_identifiers,
    run_golden_vector_gate,
)
from tools.mainnet_canary.encoding import (
    DOMAIN_ACTION_ID,
    DOMAIN_TRANSFER_ID,
    NATIVE_BODY_FIELDS,
    NATIVE_CORE_FIELD_NAMES,
    FreshEncodingError,
    blake2b_256,
    derive_deployment_domain,
    encode_scalar,
)
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.keys import (
    load_key_inventory,
    refuse_known_testnet_identity_reuse,
)
from tools.mainnet_canary.rc_gate import validate_rc_gate
from tools.mainnet_canary.secret_guard import refuse_if_secret_material

PLAN_SCHEMA_ID = "concordia.mainnet-canary.plan.v1"
PARAMS_SCHEMA_ID = "concordia.mainnet-canary.parameters.v1"
SNAPSHOT_SCHEMA_ID = "concordia.mainnet-canary.treasury-snapshot-observation.v1"
STATUS_SCHEMA_ID = "concordia.mainnet-canary.chain-status-observation.v1"

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")

_PARAM_FIELDS = {
    "schema_id",
    "proposal_id",
    "proposal_nonce",
    "decision_code",
    "requested_allocation_bps",
    "approved_allocation_bps",
    "action_nonce",
    "installation_nonce",
    "proposal_hash",
    "policy_hash",
    "plan_hash",
    "final_card_hash",
    "dissent_hash",
    "agent_action_hash",
    "preauth_evidence_root",
    "authorized_metadata_root",
    "max_amount_motes",
}

_SNAPSHOT_FIELDS = {
    "schema_id",
    "chain_name",
    "account_hash",
    "balance_motes",
    "block_hash",
    "block_height",
    "state_root_hash",
    "timestamp_unix",
}

_STATUS_FIELDS = {
    "schema_id",
    "chain_name",
    "latest_block_hash",
    "latest_block_height",
    "latest_timestamp_unix",
}

# Exact flattened finalize_native_transfer ABI order (G1 §8).
FINALIZE_NATIVE_ARG_ORDER = (
    "proposal_id",
    "proposal_nonce",
    "decision_code",
    "requested_allocation_bps",
    "approved_allocation_bps",
    "action_kind",
    "action_version",
    "action_id",
    "proposal_hash",
    "policy_hash",
    "plan_hash",
    "final_card_hash",
    "dissent_hash",
    "agent_action_hash",
    "preauth_evidence_root",
    "authorized_metadata_root",
    "asset_kind",
    "source_account",
    "recipient_account",
    "amount_motes",
    "treasury_snapshot_balance_motes",
    "snapshot_block_hash",
    "snapshot_block_height",
    "transfer_id",
    "action_nonce",
    "execution_target",
    "execution_version",
)


def canonical_json(document: dict[str, object]) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def plan_document_hash(document: dict[str, object]) -> str:
    body = {
        key: value
        for key, value in document.items()
        if key != "canary_plan_sha256"
    }
    return hashlib.sha256(canonical_json(body).encode("ascii")).hexdigest()


def _load_strict_json(
    path: Path, *, absent_code: str, context: str
) -> dict[str, object]:
    if not path.is_file():
        raise CanaryRefusal(absent_code, f"{context} file is not present")
    raw = path.read_text(encoding="utf-8")
    refuse_if_secret_material(raw, context=context)
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CanaryRefusal(
            RefusalCode.PLAN_INPUT_INVALID, f"{context} is not valid JSON"
        ) from exc
    if not isinstance(document, dict):
        raise CanaryRefusal(
            RefusalCode.PLAN_INPUT_INVALID, f"{context} must be a JSON object"
        )
    return document


def load_parameters(path: Path) -> dict[str, object]:
    document = _load_strict_json(
        path, absent_code=RefusalCode.PLAN_INPUT_ABSENT, context="canary-parameters"
    )
    if set(document) != _PARAM_FIELDS or document["schema_id"] != PARAMS_SCHEMA_ID:
        raise CanaryRefusal(
            RefusalCode.PLAN_INPUT_INVALID,
            f"parameters must contain exactly {sorted(_PARAM_FIELDS)} with "
            f"schema_id {PARAMS_SCHEMA_ID}",
        )
    return document


def load_snapshot_observation(path: Path) -> dict[str, object]:
    document = _load_strict_json(
        path,
        absent_code=RefusalCode.PLAN_INPUT_ABSENT,
        context="treasury-snapshot-observation",
    )
    if (
        set(document) != _SNAPSHOT_FIELDS
        or document["schema_id"] != SNAPSHOT_SCHEMA_ID
    ):
        raise CanaryRefusal(
            RefusalCode.PLAN_INPUT_INVALID,
            f"snapshot observation must contain exactly {sorted(_SNAPSHOT_FIELDS)}",
        )
    if document["chain_name"] != MAINNET_CHAIN_NAME:
        raise CanaryRefusal(
            RefusalCode.NETWORK_MISMATCH,
            "treasury snapshot was not observed on chain `casper`",
        )
    return document


def load_status_observation(path: Path) -> dict[str, object]:
    document = _load_strict_json(
        path,
        absent_code=RefusalCode.PLAN_INPUT_ABSENT,
        context="chain-status-observation",
    )
    if set(document) != _STATUS_FIELDS or document["schema_id"] != STATUS_SCHEMA_ID:
        raise CanaryRefusal(
            RefusalCode.PLAN_INPUT_INVALID,
            f"status observation must contain exactly {sorted(_STATUS_FIELDS)}",
        )
    if document["chain_name"] != MAINNET_CHAIN_NAME:
        raise CanaryRefusal(
            RefusalCode.NETWORK_MISMATCH,
            "chain status was not observed on chain `casper`",
        )
    return document


def require_fresh_snapshot(
    snapshot: dict[str, object], status: dict[str, object]
) -> None:
    """Stale treasury state roots are refused before staging/planning."""

    height = snapshot["block_height"]
    latest = status["latest_block_height"]
    taken = snapshot["timestamp_unix"]
    now = status["latest_timestamp_unix"]
    if not all(isinstance(value, int) for value in (height, latest, taken, now)):
        raise CanaryRefusal(
            RefusalCode.PLAN_INPUT_INVALID, "snapshot/status heights malformed"
        )
    if latest < height or now < taken:
        raise CanaryRefusal(
            RefusalCode.STATE_ROOT_STALE,
            "snapshot claims to be newer than the observed chain head",
        )
    if latest - height > SNAPSHOT_MAX_HEIGHT_LAG or now - taken > (
        SNAPSHOT_MAX_AGE_SECONDS
    ):
        raise CanaryRefusal(
            RefusalCode.STATE_ROOT_STALE,
            "treasury snapshot is stale relative to the observed chain head",
        )


def collect_known_testnet_account_hashes(repo_root: Path) -> set[str]:
    """Harvest Testnet account hashes from the canonical live artifacts."""

    pattern = re.compile(r"account-hash-([0-9a-f]{64})|\"account_hash\"\s*:\s*\"([0-9a-f]{64})\"")
    found: set[str] = set()
    live_dir = repo_root / "artifacts" / "live"
    if live_dir.is_dir():
        for path in sorted(live_dir.glob("*.json")):
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for match in pattern.finditer(text):
                found.add(match.group(1) or match.group(2))
    return found


def _typed_arg(name: str, type_name: str, value: object) -> dict[str, object]:
    return {"name": name, "type": type_name, "value": value}


def _governance_target_args(
    proposal_id: str, envelope_hash_hex: str
) -> list[dict[str, object]]:
    return [
        _typed_arg("proposal_id", "String", proposal_id),
        _typed_arg("envelope_hash", "ByteArray(32)", envelope_hash_hex),
    ]


def build_plan(
    repo_root: Path,
    *,
    rc_declaration_path: Path,
    key_inventory_path: Path,
    parameters_path: Path,
    snapshot_path: Path,
    status_path: Path,
) -> dict[str, object]:
    """Assemble and validate the full canary plan; refuse on any gap."""

    rc = validate_rc_gate(repo_root, rc_declaration_path)
    inventory = load_key_inventory(key_inventory_path)
    refuse_known_testnet_identity_reuse(
        inventory, collect_known_testnet_account_hashes(repo_root)
    )
    parameters = load_parameters(parameters_path)
    snapshot = load_snapshot_observation(snapshot_path)
    status = load_status_observation(status_path)
    require_fresh_snapshot(snapshot, status)
    golden_gate = run_golden_vector_gate(repo_root)

    source = inventory.roles["treasury_source"]
    recipient = inventory.roles["recipient"]
    if snapshot["account_hash"] != source.account_hash_hex:
        raise CanaryRefusal(
            RefusalCode.PLAN_INPUT_INVALID,
            "treasury snapshot does not belong to the dedicated source account",
        )

    balance_raw = snapshot["balance_motes"]
    if not isinstance(balance_raw, str) or _DECIMAL.match(balance_raw) is None:
        raise CanaryRefusal(
            RefusalCode.PLAN_INPUT_INVALID, "snapshot balance malformed"
        )
    approved_bps = parameters["approved_allocation_bps"]
    if not isinstance(approved_bps, int) or not 0 < approved_bps <= 10_000:
        raise CanaryRefusal(
            RefusalCode.PLAN_INPUT_INVALID, "approved_allocation_bps malformed"
        )
    amount_motes = int(balance_raw) * approved_bps // 10_000
    if amount_motes <= 0:
        raise CanaryRefusal(
            RefusalCode.AMOUNT_MISMATCH, "derived canary amount is zero"
        )
    max_amount = parameters["max_amount_motes"]
    if not isinstance(max_amount, str) or _DECIMAL.match(max_amount) is None:
        raise CanaryRefusal(
            RefusalCode.PLAN_INPUT_INVALID, "max_amount_motes malformed"
        )
    if amount_motes > int(max_amount):
        raise CanaryRefusal(
            RefusalCode.AMOUNT_MISMATCH,
            "derived amount exceeds the deliberately-tiny canary cap",
        )

    installation_nonce = parameters["installation_nonce"]
    deployment_domain = derive_deployment_domain(
        chain_name=MAINNET_CHAIN_NAME,
        package_key_name=PACKAGE_KEY_NAME,
        installation_nonce=installation_nonce,
    )

    header: dict[str, object] = {
        "schema_version": 3,
        "deployment_domain": deployment_domain.hex(),
        "casper_chain_name": MAINNET_CHAIN_NAME,
        "proposal_id": parameters["proposal_id"],
        "proposal_nonce": parameters["proposal_nonce"],
        "decision_code": parameters["decision_code"],
        "requested_allocation_bps": parameters["requested_allocation_bps"],
        "approved_allocation_bps": approved_bps,
        "action_kind": 1,
        "action_version": 1,
        "action_id": "0" * 64,  # replaced after recomputation below
        "proposal_hash": parameters["proposal_hash"],
        "policy_hash": parameters["policy_hash"],
        "plan_hash": parameters["plan_hash"],
        "final_card_hash": parameters["final_card_hash"],
        "dissent_hash": parameters["dissent_hash"],
        "agent_action_hash": parameters["agent_action_hash"],
        "preauth_evidence_root": parameters["preauth_evidence_root"],
        "authorized_metadata_root": parameters["authorized_metadata_root"],
    }
    body: dict[str, object] = {
        "asset_kind": 0,
        "source_account": source.account_hash_hex,
        "recipient_account": recipient.account_hash_hex,
        "amount_motes": str(amount_motes),
        "treasury_snapshot_balance_motes": balance_raw,
        "snapshot_block_hash": snapshot["block_hash"],
        "snapshot_block_height": snapshot["block_height"],
        "transfer_id": "0",  # replaced after recomputation below
        "action_nonce": parameters["action_nonce"],
        "execution_target": "native-transfer",
        "execution_version": 1,
    }

    # Derive the two identifier fields directly per G1 §7, then run the strict
    # dual recomputation over the completed envelope (fresh implementation vs
    # frozen shared primitives), which re-validates every invariant.
    try:
        body_types = dict(NATIVE_BODY_FIELDS)
        core = b"".join(
            encode_scalar(name, body_types[name], body[name])
            for name in NATIVE_CORE_FIELD_NAMES
        )
        action_nonce_bytes = bytes.fromhex(str(parameters["action_nonce"]))
        action_id = blake2b_256(DOMAIN_ACTION_ID + b"\x01" + action_nonce_bytes + core)
        header["action_id"] = action_id.hex()
        proposal_ascii = str(parameters["proposal_id"]).encode("ascii")
        transfer_digest = blake2b_256(
            DOMAIN_TRANSFER_ID
            + len(proposal_ascii).to_bytes(4, "big")
            + proposal_ascii
            + bytes.fromhex(str(parameters["proposal_nonce"]))
            + action_id
        )
        body["transfer_id"] = str(int.from_bytes(transfer_digest[:8], "big"))
    except (FreshEncodingError, ValueError) as exc:
        raise CanaryRefusal(
            RefusalCode.ENVELOPE_INVALID, f"canary envelope invalid: {exc}"
        ) from exc

    material = recompute_native_identifiers(
        header, body, chain_name=MAINNET_CHAIN_NAME
    )

    finalize_args = [
        _typed_arg(
            name,
            _FINALIZE_ARG_TYPES[name],
            header.get(name, body.get(name)),
        )
        for name in FINALIZE_NATIVE_ARG_ORDER
    ]

    votes_required = inventory.threshold
    voters = ["signer_a", "signer_b", "signer_c"][:votes_required]

    steps: list[dict[str, object]] = []

    def add_step(
        step_id: str,
        *,
        kind: str,
        economic: bool,
        role: str | None,
        depends_on: list[str],
        entry_point: str | None = None,
        typed_args: list[dict[str, object]] | None = None,
        expected_outcome: dict[str, object] | None = None,
    ) -> None:
        steps.append(
            {
                "step_id": step_id,
                "kind": kind,
                "economic": economic,
                "signing_role": role,
                "signing_account_hash": (
                    inventory.roles[role].account_hash_hex if role else None
                ),
                "depends_on": depends_on,
                "entry_point": entry_point,
                "typed_args": typed_args or [],
                "expected_outcome": expected_outcome or {},
            }
        )

    add_step(
        "A-network-preflight",
        kind="readonly_rpc_check",
        economic=False,
        role=None,
        depends_on=[],
        expected_outcome={
            "chainspec_name": MAINNET_CHAIN_NAME,
            "endpoint": MAINNET_RPC_URL,
        },
    )
    add_step(
        "B-install-rc-wasm",
        kind="contract_install",
        economic=True,
        role="treasury_source",
        depends_on=["A-network-preflight"],
        entry_point=None,
        typed_args=[
            _typed_arg("proposer", "ByteArray(32)", inventory.roles["proposer"].account_hash_hex),
            _typed_arg("finalizer", "ByteArray(32)", inventory.roles["finalizer"].account_hash_hex),
            _typed_arg("signer_a", "ByteArray(32)", inventory.roles["signer_a"].account_hash_hex),
            _typed_arg("signer_b", "ByteArray(32)", inventory.roles["signer_b"].account_hash_hex),
            _typed_arg("signer_c", "ByteArray(32)", inventory.roles["signer_c"].account_hash_hex),
            _typed_arg("threshold", "U8", votes_required),
            _typed_arg("casper_chain_name", "String", MAINNET_CHAIN_NAME),
            _typed_arg("installation_nonce", "ByteArray(32)", installation_nonce),
        ],
        expected_outcome={
            "execution": "success",
            "session_wasm_sha256": rc.mainnet_wasm_sha256,
        },
    )
    add_step(
        "C-verify-install",
        kind="readonly_rpc_check",
        economic=False,
        role=None,
        depends_on=["B-install-rc-wasm"],
        expected_outcome={
            "schema_version": 3,
            "casper_chain_name": MAINNET_CHAIN_NAME,
            "deployment_domain": deployment_domain.hex(),
            "threshold": votes_required,
        },
    )
    add_step(
        "D-propose-envelope",
        kind="contract_call",
        economic=True,
        role="proposer",
        depends_on=["C-verify-install"],
        entry_point="propose_envelope",
        typed_args=_governance_target_args(
            str(parameters["proposal_id"]), material.envelope_hash_hex
        ),
        expected_outcome={"execution": "success", "event": "EnvelopeProposed"},
    )
    add_step(
        "E-prequorum-finalize-refusal",
        kind="contract_call",
        economic=True,
        role="finalizer",
        depends_on=["D-propose-envelope"],
        entry_point="finalize_native_transfer",
        typed_args=finalize_args,
        expected_outcome={
            "execution": "failure",
            "exact_error_message": rc.expected_prequorum_error_message,
            "error_name": "QuorumNotMet",
        },
    )
    previous = "E-prequorum-finalize-refusal"
    for voter in voters:
        step_id = f"F-approve-{voter.replace('_', '-')}"
        add_step(
            step_id,
            kind="contract_call",
            economic=True,
            role=voter,
            depends_on=[previous],
            entry_point="approve_envelope",
            typed_args=_governance_target_args(
                str(parameters["proposal_id"]), material.envelope_hash_hex
            ),
            expected_outcome={"execution": "success", "event": "EnvelopeApproved"},
        )
        previous = step_id
    add_step(
        "G-finalize-exact-envelope",
        kind="contract_call",
        economic=True,
        role="finalizer",
        depends_on=[previous],
        entry_point="finalize_native_transfer",
        typed_args=finalize_args,
        expected_outcome={
            "execution": "success",
            "event": "EnvelopeFinalized",
            "action_id": material.action_id_hex,
            "envelope_hash": material.envelope_hash_hex,
        },
    )
    add_step(
        "H-no-second-economic-action",
        kind="invariant_assertion",
        economic=False,
        role=None,
        depends_on=["G-finalize-exact-envelope"],
        expected_outcome={
            "assertion": "no additional finalize/transfer is created for "
            "this action_id"
        },
    )
    add_step(
        "I-executor-native-transfer",
        kind="native_transfer",
        economic=True,
        role="treasury_source",
        depends_on=["G-finalize-exact-envelope", "H-no-second-economic-action"],
        entry_point=None,
        typed_args=[
            _typed_arg(
                "target",
                "Key(Account)",
                recipient.account_hash_hex,
            ),
            _typed_arg("amount", "U512", str(amount_motes)),
            _typed_arg(
                "id", "Option<u64>", {"variant": "Some", "value": str(material.transfer_id)}
            ),
        ],
        expected_outcome={
            "execution": "success",
            "source_account": source.account_hash_hex,
            "recipient_account": recipient.account_hash_hex,
            "amount_motes": str(amount_motes),
            "transfer_id": str(material.transfer_id),
        },
    )
    add_step(
        "J-transfer-readback",
        kind="readonly_rpc_check",
        economic=False,
        role=None,
        depends_on=["I-executor-native-transfer"],
        expected_outcome={
            "action_id": material.action_id_hex,
            "transfer_id": str(material.transfer_id),
            "action_authorized": True,
        },
    )
    add_step(
        "K-supplemental-proof-pack",
        kind="artifact_generation",
        economic=False,
        role=None,
        depends_on=["J-transfer-readback"],
        expected_outcome={
            "namespace": "artifacts/mainnet-canary/v3/",
            "provenance": "mainnet_supplemental",
            "available_in_preparation_lane": False,
        },
    )

    document: dict[str, object] = {
        "schema_id": PLAN_SCHEMA_ID,
        "prep_base_sha": PREP_BASE_SHA,
        "rc": {
            "tag": rc.rc_tag,
            "peeled_commit_sha": rc.peeled_commit_sha,
            "testnet_wasm_sha256": rc.testnet_wasm_sha256,
            "mainnet_wasm_sha256": rc.mainnet_wasm_sha256,
        },
        "network": {
            "chain_name": MAINNET_CHAIN_NAME,
            "rpc_url": MAINNET_RPC_URL,
        },
        "identities": {
            role.role: {
                "public_key_hex": role.public_key_hex,
                "account_hash_hex": role.account_hash_hex,
            }
            for role in inventory.roles.values()
        },
        "threshold": votes_required,
        "envelope": {
            "header": header,
            "body": body,
            "derived": {
                "deployment_domain": deployment_domain.hex(),
                "action_id": material.action_id_hex,
                "transfer_id": str(material.transfer_id),
                "envelope_hash": material.envelope_hash_hex,
            },
        },
        "golden_vector_gate": golden_gate,
        "steps": steps,
        "live_proof_status": BLOCKED_PENDING_LIVE_PROOF,
    }
    document["canary_plan_sha256"] = plan_document_hash(document)
    return document


_FINALIZE_ARG_TYPES = {
    "proposal_id": "String",
    "proposal_nonce": "ByteArray(32)",
    "decision_code": "U8",
    "requested_allocation_bps": "U32",
    "approved_allocation_bps": "U32",
    "action_kind": "U8",
    "action_version": "U32",
    "action_id": "ByteArray(32)",
    "proposal_hash": "ByteArray(32)",
    "policy_hash": "ByteArray(32)",
    "plan_hash": "ByteArray(32)",
    "final_card_hash": "ByteArray(32)",
    "dissent_hash": "ByteArray(32)",
    "agent_action_hash": "ByteArray(32)",
    "preauth_evidence_root": "ByteArray(32)",
    "authorized_metadata_root": "ByteArray(32)",
    "asset_kind": "U8",
    "source_account": "ByteArray(32)",
    "recipient_account": "ByteArray(32)",
    "amount_motes": "U512",
    "treasury_snapshot_balance_motes": "U512",
    "snapshot_block_hash": "ByteArray(32)",
    "snapshot_block_height": "U64",
    "transfer_id": "U64",
    "action_nonce": "ByteArray(32)",
    "execution_target": "String",
    "execution_version": "U32",
}
