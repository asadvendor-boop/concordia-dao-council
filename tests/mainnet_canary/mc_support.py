"""Hermetic builders for the Mainnet canary preparation tests.

Every test runs against a throwaway git repository built in ``tmp_path``.
All values below are synthetic test doubles (computed in code, never
presented as live evidence) so the failure-first suite can exercise every
fail-closed gate without any network, key, or live artifact.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from tools.mainnet_canary.keys import derive_account_hash

REAL_REPO_ROOT = Path(__file__).resolve().parents[2]

FAKE_TESTNET_WASM = b"\x00asm-testnet-rc-build"
FAKE_MAINNET_WASM = b"\x00asm-mainnet-rc-build"
TESTNET_WASM_SHA = hashlib.sha256(FAKE_TESTNET_WASM).hexdigest()
MAINNET_WASM_SHA = hashlib.sha256(FAKE_MAINNET_WASM).hexdigest()

ROLE_PUBLIC_KEYS = {
    "proposer": "01" + "aa" * 32,
    "finalizer": "01" + "bb" * 32,
    "signer_a": "01" + "cc" * 32,
    "signer_b": "01" + "dd" * 32,
    "signer_c": "01" + "ee" * 32,
    "treasury_source": "01" + "1a" * 32,
    "recipient": "01" + "2b" * 32,
}


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=canary-test",
            "-c",
            "user.email=canary-test@example.invalid",
            *args,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def build_hermetic_repo(tmp_path: Path) -> Path:
    """A committed throwaway repo with wasm, historical inventory, vectors."""

    repo = tmp_path / "repo"
    wasm_dir = repo / "contracts" / "odra-governance-receipt-v3" / "wasm"
    wasm_dir.mkdir(parents=True)
    (wasm_dir / "GovernanceReceiptV3.wasm").write_bytes(FAKE_TESTNET_WASM)

    historical_dir = repo / "contracts" / "odra-governance-receipt"
    historical_dir.mkdir(parents=True)
    legacy = historical_dir / "legacy-source.txt"
    legacy.write_text("frozen historical v1/v2 bytes\n", encoding="utf-8")
    legacy_sha = hashlib.sha256(legacy.read_bytes()).hexdigest()
    handoff = repo / "handoff"
    handoff.mkdir()
    (handoff / "HISTORICAL_ODRA_SHA256.txt").write_text(
        "# test baseline\n"
        f"{legacy_sha}  contracts/odra-governance-receipt/legacy-source.txt\n",
        encoding="utf-8",
    )

    # Frozen golden vectors are required by the pre-plan self-check gate.
    shutil.copytree(
        REAL_REPO_ROOT / "tests" / "golden" / "envelope_v3",
        repo / "tests" / "golden" / "envelope_v3",
    )

    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "hermetic canary test baseline")
    return repo


def repo_head(repo: Path) -> str:
    return _git(repo, "rev-parse", "HEAD").strip()


def git_commit_all(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)
    return repo_head(repo)


def historical_inventory_sha(repo: Path) -> str:
    return hashlib.sha256(
        (repo / "handoff" / "HISTORICAL_ODRA_SHA256.txt").read_bytes()
    ).hexdigest()


def make_rc_declaration(repo: Path, **overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_id": "concordia.mainnet-canary.rc-declaration.v1",
        "rc_tag": "concordia-testnet-rc-v3.0-test",
        "peeled_commit_sha": repo_head(repo),
        "testnet_wasm_sha256": TESTNET_WASM_SHA,
        "mainnet_wasm_sha256": MAINNET_WASM_SHA,
        "mainnet_wasm_chain_name": "casper",
        "mainnet_chain_name": "casper",
        "mainnet_rpc_url": "https://node.mainnet.casper.network/rpc",
        "historical_odra_inventory_sha256": historical_inventory_sha(repo),
        "expected_prequorum_error_message": "User error: 8",
        "gates": {
            "testnet_gates_green": True,
            "local_gates_green": True,
            "hosted_gates_green": True,
            "historical_manifest_unchanged": True,
            "source_tree_clean_at_tag": True,
        },
    }
    document.update(overrides)
    return document


def write_json(path: Path, document: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")
    return path


def make_key_inventory(**overrides: object) -> dict[str, object]:
    roles = {
        role: {
            "public_key_hex": key,
            "account_hash_hex": derive_account_hash(key),
            "key_file_mount_path": f"/run/secrets/mainnet_canary/{role}.ref",
        }
        for role, key in ROLE_PUBLIC_KEYS.items()
    }
    document: dict[str, object] = {
        "schema_id": "concordia.mainnet-canary.public-key-inventory.v1",
        "network": "casper",
        "threshold": 2,
        "roles": roles,
    }
    document.update(overrides)
    return document


def make_parameters(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_id": "concordia.mainnet-canary.parameters.v1",
        "proposal_id": "MAINNET-CANARY-001",
        "proposal_nonce": "10" * 32,
        "decision_code": 2,
        "requested_allocation_bps": 3000,
        "approved_allocation_bps": 800,
        "action_nonce": "44" * 32,
        "installation_nonce": "a5" * 32,
        "proposal_hash": "31" * 32,
        "policy_hash": "32" * 32,
        "plan_hash": "33" * 32,
        "final_card_hash": "34" * 32,
        "dissent_hash": "35" * 32,
        "agent_action_hash": "36" * 32,
        "preauth_evidence_root": "37" * 32,
        "authorized_metadata_root": "38" * 32,
        "max_amount_motes": "50000000000",
        # v2: the amount is an explicit human authorization, never derived
        # silently.  625000000000 * 800bps / 10000 = 50000000000 is the bound.
        "human_authorized_amount_motes": "50000000000",
    }
    document.update(overrides)
    return document


def make_snapshot(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_id": "concordia.mainnet-canary.treasury-snapshot-observation.v1",
        "chain_name": "casper",
        "account_hash": derive_account_hash(ROLE_PUBLIC_KEYS["treasury_source"]),
        "balance_motes": "625000000000",
        "block_hash": "43" * 32,
        "block_height": 100,
        "state_root_hash": "ab" * 32,
        "timestamp_unix": 1_000_000,
    }
    document.update(overrides)
    return document


def make_status(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_id": "concordia.mainnet-canary.chain-status-observation.v1",
        "chain_name": "casper",
        "latest_block_hash": "4d" * 32,
        "latest_block_height": 110,
        "latest_timestamp_unix": 1_000_300,
    }
    document.update(overrides)
    return document


def make_measured_costs(**overrides: object) -> dict[str, object]:
    measured = {
        "contract_install": "150000000000",
        "propose_envelope": "2500000000",
        "approve_envelope_vote_a": "2500000000",
        "approve_envelope_vote_b": "2500000000",
        "prequorum_finalize_refusal": "5000000000",
        "finalize_native_transfer": "5000000000",
        "native_transfer": "100000000",
    }
    measured.update(overrides)
    return {
        "schema_id": "concordia.mainnet-canary.testnet-measured-costs.v1",
        "measured_motes": measured,
    }


def make_ceiling(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_id": "concordia.mainnet-canary.spend-ceiling.v1",
        "max_total_motes": "1000000000000",
        "approved_by": ["asad-public-approval"],
        "approval_reference": "TEST-CEILING-DOC",
        "wrong_envelope_refusal_approved": False,
    }
    document.update(overrides)
    return document


CLOCK_UNIX = 1_700_000_000


def make_attestation(**overrides: object) -> dict[str, object]:
    """A double-built two-profile attestation backing the RC declaration."""

    def artifact(sha: str, profile: str) -> dict[str, object]:
        return {
            "schema_id": "concordia.mainnet-canary.rc-attestation.v1",
            "tag": "concordia-testnet-rc-v3.0-test",
            "tag_object_sha": "ab" * 20,
            "peeled_commit_sha": "cd" * 20,
            "profile": profile,
            "build_env_delta": {"CONCORDIA_V3_NETWORK_PROFILE": profile},
            "builds": 2,
            "artifact_relpath": "wasm/GovernanceReceiptV3.wasm",
            "wasm_sha256": sha,
            "wasm_size_bytes": 4096,
            "toolchain": {
                "rustc_version": "rustc 1.94.1 (test)",
                "cargo_odra_version": "cargo-odra 0.1.7",
                "cargo_lock_sha256": "ef" * 32,
            },
        }

    document: dict[str, object] = {
        "network_artifacts": {
            "testnet": artifact(TESTNET_WASM_SHA, "testnet"),
            "mainnet-native": artifact(MAINNET_WASM_SHA, "mainnet-native"),
        }
    }
    document.update(overrides)
    return document


def make_calibration(plan: dict[str, object], **overrides: object) -> dict[str, object]:
    """Finalized Testnet calibration receipts for every economic plan step."""

    lines: dict[str, object] = {}
    for step in plan["steps"]:
        if not step["economic"]:
            continue
        lines[str(step["step_id"])] = {
            "payment_motes": "5000000000",
            "receipt": {
                "deploy_hash": "1f" * 32,
                "block_hash": "2e" * 32,
                "finalized": True,
                "chain_name": "casper-test",
            },
        }
    document: dict[str, object] = {
        "schema_id": "concordia.mainnet-canary.testnet-calibration.v1",
        "lines": lines,
    }
    document.update(overrides)
    return document


# A deterministic TEST authorizer keypair. Test-only material: it authorizes
# nothing but hermetic fixtures, and no real key is ever placed in the repo.
_TEST_AUTHORIZER_SEED = bytes(range(32))


def test_authorizer_public_key_hex() -> str:
    """Casper-form (0x01-prefixed) ed25519 public key of the test authorizer."""

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private = ed25519.Ed25519PrivateKey.from_private_bytes(_TEST_AUTHORIZER_SEED)
    raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "01" + raw.hex()


def sign_authorization(document: dict[str, object]) -> dict[str, object]:
    """Attach a REAL detached ed25519 signature over the canonical bytes."""

    from cryptography.hazmat.primitives.asymmetric import ed25519

    from tools.mainnet_canary.economic_manifest import authorization_signing_bytes

    private = ed25519.Ed25519PrivateKey.from_private_bytes(_TEST_AUTHORIZER_SEED)
    unsigned = dict(document)
    unsigned["signature_hex"] = ""
    signature = private.sign(authorization_signing_bytes(unsigned))
    signed = dict(unsigned)
    signed["signature_hex"] = signature.hex()
    return signed


def make_authorization(
    plan: dict[str, object], manifest: dict[str, object], **overrides: object
) -> dict[str, object]:
    """A genuinely signed human authorization binding the manifest exactly."""

    document: dict[str, object] = {
        "schema_id": "concordia.mainnet-canary.human-authorization.v1",
        "plan_hash": plan["canary_plan_sha256"],
        "chain_name": "casper",
        "treasury_source_account_hash": manifest["treasury_source_account_hash"],
        "recipient_account_hash": manifest["recipient_account_hash"],
        "transfer_principal_motes": manifest["transfer_principal_motes"],
        "max_fees_motes": manifest["max_fees_motes"],
        "max_total_outlay_motes": manifest["max_total_outlay_motes"],
        "expiry_unix": CLOCK_UNIX + 3600,
        "nonce": "9d" * 32,
        "authorized_by": ["asad-public-approval"],
        "authorizer_public_key_hex": test_authorizer_public_key_hex(),
        "signature_hex": "",
    }
    document.update(overrides)
    # Sign LAST so any override is covered by the signature — a fixture must
    # never hand the validator a document whose signature omits a mutation.
    return sign_authorization(document)


def make_snapshot_corroboration(snapshot: dict[str, object]) -> dict[str, object]:
    """Two disjoint providers reporting the identical treasury observation."""

    return {
        "schema_id": "concordia.mainnet-canary.treasury-snapshot-corroboration.v1",
        "providers": [
            {
                "provider_id": "provider-a",
                "endpoint_host": "node-a.example",
                "response_sha256": "aa" * 32,
            },
            {
                "provider_id": "provider-b",
                "endpoint_host": "node-b.example",
                "response_sha256": "bb" * 32,
            },
        ],
        "observation": snapshot,
    }


def build_economic_inputs(
    plan: dict[str, object], tmp_path: Path
) -> dict[str, Path]:
    """Attestation + calibration + authorization written to disk for staging."""

    from tools.mainnet_canary.economic_manifest import build_economic_manifest

    calibration = make_calibration(plan)
    manifest = build_economic_manifest(
        plan, calibration=calibration, operator_ceilings={}
    )
    return {
        "attestation": write_json(
            tmp_path / "inputs" / "attestation.json", make_attestation()
        ),
        "calibration": write_json(
            tmp_path / "inputs" / "calibration.json", calibration
        ),
        "authorization": write_json(
            tmp_path / "inputs" / "authorization.json",
            make_authorization(plan, manifest),
        ),
    }


def stage_gate_kwargs(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> dict[str, object]:
    """The hardening gates every ``run_stage`` call must now satisfy.

    Derived from a PRISTINE plan built from the same inputs, so a test that
    deliberately tampers with its plan still reaches ``run_stage``'s own
    plan-hash guard instead of tripping the manifest builder first.
    """

    pristine = build_valid_plan(plan_inputs)
    economic = build_economic_inputs(pristine, tmp_path)
    snapshot = json.loads(plan_inputs["snapshot"].read_text(encoding="utf-8"))
    return {
        "attestation_path": economic["attestation"],
        "calibration_path": economic["calibration"],
        "authorization_path": economic["authorization"],
        "clock_unix": CLOCK_UNIX,
        "snapshot_corroboration_path": write_json(
            tmp_path / "inputs" / "snapshot-corroboration.json",
            make_snapshot_corroboration(snapshot),
        ),
        "pinned_authorizer_keys": frozenset({test_authorizer_public_key_hex()}),
    }


def build_plan_inputs(hermetic_repo: Path, tmp_path: Path) -> dict[str, Path]:
    """All valid plan inputs written to disk for the hermetic repo."""

    return {
        "repo": hermetic_repo,
        "rc": write_json(
            tmp_path / "inputs" / "rc.json", make_rc_declaration(hermetic_repo)
        ),
        "inventory": write_json(
            tmp_path / "inputs" / "inventory.json", make_key_inventory()
        ),
        "parameters": write_json(
            tmp_path / "inputs" / "parameters.json", make_parameters()
        ),
        "snapshot": write_json(
            tmp_path / "inputs" / "snapshot.json", make_snapshot()
        ),
        "status": write_json(tmp_path / "inputs" / "status.json", make_status()),
        "measured": write_json(
            tmp_path / "inputs" / "measured.json", make_measured_costs()
        ),
        "ceiling": write_json(
            tmp_path / "inputs" / "ceiling.json", make_ceiling()
        ),
    }


def build_valid_plan(plan_inputs: dict[str, Path]) -> dict[str, object]:
    from tools.mainnet_canary.plan import build_plan

    return build_plan(
        plan_inputs["repo"],
        rc_declaration_path=plan_inputs["rc"],
        key_inventory_path=plan_inputs["inventory"],
        parameters_path=plan_inputs["parameters"],
        snapshot_path=plan_inputs["snapshot"],
        status_path=plan_inputs["status"],
    )


def make_v2_pair(step_id: str, **overrides: object) -> list[dict[str, object]]:
    """Two agreeing observations from disjoint providers (finality v2).

    ``verify`` now refuses single-source evidence, so every CLI-level
    observation bundle must supply a disjoint pair per economic step.
    """

    pair: list[dict[str, object]] = []
    for provider_id, host in (
        ("provider-a", "node-a.example"),
        ("provider-b", "node-b.example"),
    ):
        document = make_observation(step_id, **overrides)
        document["schema_id"] = "concordia.mainnet-canary.step-observation.v2"
        document["provider"] = {
            "provider_id": provider_id,
            "endpoint_host": host,
            "method": "info_get_deploy",
            "request_sha256": "11" * 32,
            "response_sha256": "22" * 32,
            "retrieved_at_unix": CLOCK_UNIX,
            "api_version": "2.0.0",
            "chainspec_name": "casper",
            "chain_tip_height": 128,
        }
        document.setdefault("state_readback", None)
        pair.append(document)
    return pair


def make_observation(step_id: str, **overrides: object) -> dict[str, object]:
    """A structurally valid finalized success observation (test double)."""

    document: dict[str, object] = {
        "schema_id": "concordia.mainnet-canary.step-observation.v1",
        "step_id": step_id,
        "deploy_hash": "5e" * 32,
        "chain_name_observed": "casper",
        "block": {
            "status": "finalized",
            "block_hash": "6f" * 32,
            "block_height": 120,
            "state_root_hash": "7a" * 32,
            "era_id": 42,
            "block_proofs_present": True,
            "deploy_is_member": True,
        },
        "execution": {
            "success": True,
            "error_message": None,
            "cost_motes": "100000000",
        },
        "target": {
            "package_hash": "8b" * 32,
            "contract_hash": "9c" * 32,
            "entry_point": None,
            "typed_args": None,
            "transfer": None,
        },
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(document.get(key), dict):
            merged = dict(document[key])
            merged.update(value)
            document[key] = merged
        else:
            document[key] = value
    return document
