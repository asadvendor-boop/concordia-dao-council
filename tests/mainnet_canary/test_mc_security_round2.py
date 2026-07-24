"""Round-2 security blockers: failing-first negative tests (SEC1–SEC8).

Each test drives a specific attack the Codex Security audit reproduced and
asserts the exact stable refusal code.  The positive controls live in the
existing suites; these prove the NEW guards actually refuse.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import mc_support
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode


# --- SEC1: build-executable identity must be present and well-formed ---------

def _repo(tmp_path: Path) -> Path:
    return mc_support.build_hermetic_repo(tmp_path)


def _verify_attestation(repo: Path, document: dict[str, object]):
    from tools.mainnet_canary.attestation import verify_attestation_document

    return verify_attestation_document(
        repo,
        document,
        rc_tag="concordia-testnet-rc-v3.0-test",
        rc_peeled_commit_sha=mc_support.repo_head(repo),
        rc_mainnet_wasm_sha256=mc_support.MAINNET_WASM_SHA,
    )


def _redigest(document: dict[str, object]) -> dict[str, object]:
    from tools.mainnet_canary.attestation import attestation_entry_digest

    document["entry_digests"] = {
        profile: attestation_entry_digest(entry)
        for profile, entry in document["network_artifacts"].items()
    }
    return document


def test_sec1_attestation_without_build_executable_refuses(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    document = mc_support.make_attestation(repo)
    del document["network_artifacts"]["mainnet-native"]["build_executable"]
    _redigest(document)
    with pytest.raises(CanaryRefusal) as refusal:
        _verify_attestation(repo, document)
    assert refusal.value.code == RefusalCode.ATTESTATION_NOT_EXECUTED


def test_sec1_attestation_with_malformed_executable_sha_refuses(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    document = mc_support.make_attestation(repo)
    document["network_artifacts"]["testnet"]["build_executable"][
        "path_sha256"
    ] = "short"
    _redigest(document)
    with pytest.raises(CanaryRefusal) as refusal:
        _verify_attestation(repo, document)
    assert refusal.value.code == RefusalCode.ATTESTATION_NOT_EXECUTED


# --- SEC4: two provider labels wrapping one source refuse ---------------------

def test_sec4_two_labels_one_callable_refuses() -> None:
    from tools.mainnet_canary.collector import collect_dual_observations

    shared_call = lambda method, params: {}  # noqa: E731 - one source, two labels
    with pytest.raises(CanaryRefusal) as refusal:
        collect_dual_observations(
            {"provider-a": shared_call, "provider-b": shared_call},
            hosts={"provider-a": "node-a", "provider-b": "node-b"},
            step_id="X",
            deploy_hash="5e" * 32,
            retrieved_at_unix=1,
            target={},
            state_readback=None,
        )
    assert refusal.value.code == RefusalCode.NODE_SET_INVALID


def test_sec4_two_bound_methods_same_instance_refuses() -> None:
    from tools.mainnet_canary.collector import bind_dual_read_calls

    class _T:
        endpoint = "https://a.example/rpc"
        pinned_ip = "203.0.113.1"

        def read(self, method, params):
            return {}

    one = _T()
    with pytest.raises(CanaryRefusal) as refusal:
        bind_dual_read_calls([one, one])
    assert refusal.value.code == RefusalCode.NODE_SET_INVALID


# --- SEC5: signer / recipient / value bindings on the signed deploy ----------

def _transfer_step() -> dict[str, object]:
    from pycspr import crypto as pycspr_crypto

    key = mc_support.harness_source_key()
    return {
        "step_id": "I",
        "kind": "native_transfer",
        "signing_account_hash": pycspr_crypto.get_account_hash(
            key.account_key
        ).hex(),
        "entry_point": None,
        "typed_args": None,
        "expected_outcome": {
            "recipient_account": mc_support.HARNESS_RECIPIENT.hex(),
            "amount_motes": "2500000000",
            "transfer_id": "7",
        },
    }


def test_sec5_wrong_recipient_refuses() -> None:
    from tools.mainnet_canary.submission import validate_signed_step_deploy

    raw = mc_support.signed_transfer_bytes(
        recipient=bytes.fromhex("cc" * 32),  # not the plan's recipient
        amount=2_500_000_000,
        transfer_id=7,
    )
    with pytest.raises(CanaryRefusal) as refusal:
        validate_signed_step_deploy(
            raw, step=_transfer_step(), max_payment_motes=100_000_000
        )
    assert refusal.value.code == RefusalCode.SIGNED_BYTES_INVALID


def test_sec5_wrong_transfer_id_refuses() -> None:
    from tools.mainnet_canary.submission import validate_signed_step_deploy

    raw = mc_support.signed_transfer_bytes(
        recipient=mc_support.HARNESS_RECIPIENT,
        amount=2_500_000_000,
        transfer_id=999,  # not the plan's bound id
    )
    with pytest.raises(CanaryRefusal) as refusal:
        validate_signed_step_deploy(
            raw, step=_transfer_step(), max_payment_motes=100_000_000
        )
    assert refusal.value.code == RefusalCode.SIGNED_BYTES_INVALID


def test_sec5_wrong_signer_refuses() -> None:
    from tools.mainnet_canary.submission import validate_signed_step_deploy

    step = _transfer_step()
    with pytest.raises(CanaryRefusal) as refusal:
        validate_signed_step_deploy(
            mc_support.signed_transfer_bytes(
                recipient=mc_support.HARNESS_RECIPIENT,
                amount=2_500_000_000,
                transfer_id=7,
            ),
            step=step,
            max_payment_motes=100_000_000,
            expected_signer_account_hash="ff" * 32,  # a different pinned role
        )
    assert refusal.value.code == RefusalCode.SIGNED_BYTES_INVALID


# --- SEC8: install must validate against the attested Mainnet Wasm -----------

def test_sec8_install_without_attested_wasm_refuses() -> None:
    from tools.mainnet_canary.submission import validate_signed_step_deploy

    install_step = {
        "step_id": "B",
        "kind": "contract_install",
        "signing_account_hash": None,
        "entry_point": None,
        "typed_args": [],
        "expected_outcome": {"execution": "success"},
    }
    # A transfer deploy stands in as "not a ModuleBytes install"; with no
    # attested hash supplied the install path must refuse before trusting it.
    raw = mc_support.signed_transfer_bytes(
        recipient=mc_support.HARNESS_RECIPIENT, amount=1, transfer_id=1
    )
    with pytest.raises(CanaryRefusal) as refusal:
        validate_signed_step_deploy(
            raw, step=install_step, max_payment_motes=100_000_000
        )
    assert refusal.value.code == RefusalCode.SIGNED_BYTES_INVALID


# --- SEC3: target derived from raw deploy session, not metadata --------------

def _dual_with_session(metadata_entry_point: str, real_entry_point: str):
    """A disjoint pair whose raw deploy session names ``real_entry_point``
    while the observation metadata target claims ``metadata_entry_point``."""

    session = {
        "entry_point": real_entry_point,
        "args": [["installation_nonce", {"cl_type": "String", "parsed": "a5"}]],
        "transfer": None,
    }
    pair = []
    for pid, host in (("provider-a", "node-a"), ("provider-b", "node-b")):
        provider = mc_support.make_raw_provider(
            pid,
            host,
            deploy_hash="5e" * 32,
            block_hash="6f" * 32,
            block_height=120,
            success=True,
            chainspec_name="casper",
            chain_tip_height=200,
            session=session,
        )
        pair.append(
            {
                "schema_id": "concordia.mainnet-canary.step-observation.v3",
                "step_id": "B",
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
                    "entry_point": metadata_entry_point,
                    "typed_args": {"installation_nonce": "a5"},
                    "transfer": None,
                },
                "provider": provider,
                "state_readback": None,
            }
        )
    return pair


def test_sec3_metadata_target_disagreeing_with_raw_session_refuses() -> None:
    from tools.mainnet_canary.finality_v2 import validate_observation_v3

    # Metadata claims a different entry point than the raw deploy session.
    observation = _dual_with_session("propose_envelope", "finalize_native_transfer")[0]
    with pytest.raises(CanaryRefusal) as refusal:
        validate_observation_v3(observation)
    assert refusal.value.code == RefusalCode.RAW_EVIDENCE_MISMATCH


def test_sec3_metadata_target_agreeing_with_raw_session_passes() -> None:
    from tools.mainnet_canary.finality_v2 import validate_observation_v3

    observation = _dual_with_session("finalize_native_transfer", "finalize_native_transfer")[0]
    validate_observation_v3(observation)  # no raise


# --- SEC2: proof bundle refuses a status-only verification entry -------------

def test_sec2_bundle_refuses_status_only_entry(
    plan_inputs: dict[str, Path], tmp_path: Path
) -> None:
    from tools.mainnet_canary.cli import main

    plan = mc_support.build_valid_plan(plan_inputs)
    # Strip the embedded observations → a status-only report.
    report = mc_support.full_verification_report(plan)
    for step in report["steps"]:
        step.pop("observations", None)
    args = mc_support.bundle_cli_args(
        plan, plan_inputs, tmp_path, verification=report
    )
    import io
    import contextlib
    import json

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = main(args)
    output = json.loads(buffer.getvalue())
    assert code == 2
    assert output["refusal"]["code"] == RefusalCode.OBSERVATION_ABSENT
