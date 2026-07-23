from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import scripts.assemble_proof_registry as registry_assembler

from scripts.assemble_proof_registry import (
    AssemblyError,
    _atomic_write_document,
    _ensure_packaged_verifier,
    _validate_output_mode,
    assemble_proof_registry,
)
from shared.proof_registry import (
    ProofRegistryRepository,
    REQUIRED_CHECKS_BY_PROOF_TYPE,
    proof_item_is_green,
)


ROOT = Path(__file__).resolve().parents[1]
VERIFY_CLI = ROOT / "packages/verify/dist/cli.js"


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _node_treasury_fixture() -> dict[str, object]:
    script = """
import { buildNativeTreasuryArtifact } from './packages/verify/test/helpers/native-treasury-artifact.mjs';
import { canonicalTranscriptJson } from './packages/verify/dist/index.js';
const artifact = await buildNativeTreasuryArtifact();
process.stdout.write(canonicalTranscriptJson(artifact, 'registry assembler fixture'));
"""
    result = subprocess.run(
        ["node", "--input-type=module", "--eval", script],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return json.loads(result.stdout)


def _python_exact_fixture() -> dict[str, object]:
    script = """
import json
from pathlib import Path
import tests.test_clvalue_roundtrip as fixtures
core = json.loads(Path('packages/verify/test/fixtures/native-treasury-core.json').read_text())
document = {
    'schema_id': 'concordia.exact-envelope-v3.input.v1',
    'action': 'NativeTransferV1',
    'header': core['authorization']['typed_header'],
    'body': core['authorization']['typed_body'],
}
fixtures._native_document = lambda: document
proof, _, _ = fixtures._bound_v3_proof()
print(json.dumps(proof, sort_keys=True, separators=(',', ':')))
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return json.loads(result.stdout)


def _scan_authorization_block_hash(treasury: dict[str, object]) -> str:
    bounded = treasury["bounded_transfer_scan"]
    assert isinstance(bounded, dict)
    transcript = bounded["transcript"]
    assert isinstance(transcript, dict)
    observations = transcript["block_observations"]
    assert isinstance(observations, list) and observations
    response = observations[0]["block_response"]
    return response["result"]["value"]["block_with_signatures"]["block"]["Version2"][
        "hash"
    ]


def _reseal_exact_timeline(
    proof: dict[str, object],
    *,
    finalization_height: int,
    finalization_hash: str,
) -> None:
    run = proof["run"]
    assert isinstance(run, dict)
    steps = run["steps"]
    assert isinstance(steps, list)
    for step in steps:
        transcript = step["finality_transcript"]
        execution_info = transcript["response"]["result"]["execution_info"]
        execution_info["block_height"] = finalization_height
        execution_info["block_hash"] = finalization_hash
        transcript["canonical_sha256"] = _canonical_sha256(
            {"request": transcript["request"], "response": transcript["response"]}
        )
        evidence = step.get("finality_block_evidence")
        if isinstance(evidence, dict):
            evidence["block_height"] = finalization_height
            evidence["block_hash"] = finalization_hash
            for observation in evidence["node_observations"]:
                observation["deploy_response"]["result"]["execution_info"][
                    "block_height"
                ] = finalization_height
                observation["deploy_response"]["result"]["execution_info"][
                    "block_hash"
                ] = finalization_hash
                observation["block_request"]["params"]["block_identifier"]["Hash"] = (
                    finalization_hash
                )
                versioned = observation["block_response"]["result"][
                    "block_with_signatures"
                ]["block"]["Version2"]
                versioned["hash"] = finalization_hash
                versioned["header"]["height"] = finalization_height

    readback = proof["readback"]
    assert isinstance(readback, dict)
    block = next(
        item for item in readback["transcripts"] if item["method"] == "chain_get_block"
    )
    block["response"]["result"]["block_with_signatures"]["block"]["Version2"]["header"][
        "height"
    ] = finalization_height + 1
    block["canonical_sha256"] = _canonical_sha256(
        {"request": block["request"], "response": block["response"]}
    )
    readback["facts"]["observed_block_height"] = finalization_height + 1
    without_hash = copy.deepcopy(readback)
    without_hash.pop("artifact_sha256")
    readback["artifact_sha256"] = _canonical_sha256(without_hash)
    run["readback"] = copy.deepcopy(readback)


def _add_durable_finality_evidence(
    proof: dict[str, object], *, finalized_at: str, observed_at: str
) -> None:
    run = proof["run"]
    assert isinstance(run, dict)
    steps = run["steps"]
    assert isinstance(steps, list)
    for position, step in enumerate(steps):
        finality = step["finality_transcript"]
        response = finality["response"]
        execution = response["result"]["execution_info"]
        deploy_hash = step["deploy_hash"]
        block_hash = execution["block_hash"]
        block_height = execution["block_height"]
        state_root_hash = f"{position + 1:064x}"
        observations = []
        for node_position, hostname in enumerate(
            ("rpc-a.example", "rpc-b.example"), start=1
        ):
            deploy_request = {
                "jsonrpc": "2.0",
                "id": f"deploy-{position}-{node_position}",
                "method": "info_get_deploy",
                "params": {"deploy_hash": deploy_hash},
            }
            deploy_response = copy.deepcopy(response)
            deploy_response["id"] = deploy_request["id"]
            block_request = {
                "jsonrpc": "2.0",
                "id": f"block-{position}-{node_position}",
                "method": "chain_get_block",
                "params": {"block_identifier": {"Hash": block_hash}},
            }
            block_response = {
                "jsonrpc": "2.0",
                "id": block_request["id"],
                "result": {
                    "api_version": "2.0.0",
                    "block_with_signatures": {
                        "block": {
                            "Version2": {
                                "hash": block_hash,
                                "header": {
                                    "height": block_height,
                                    "state_root_hash": state_root_hash,
                                    "timestamp": finalized_at,
                                },
                                "body": {
                                    "transactions": {"0": [{"Deploy": deploy_hash}]}
                                },
                            }
                        },
                        "proofs": [],
                    },
                },
            }
            observations.append(
                {
                    "node_id": hostname,
                    "node_url": f"https://{hostname}/rpc",
                    "deploy_request": deploy_request,
                    "deploy_response": deploy_response,
                    "block_request": block_request,
                    "block_response": block_response,
                }
            )
        error_code = step["expected_error"]
        step["submission_state"] = "finalized"
        step["finality_block_evidence"] = {
            "status": "finalized",
            "block_hash": block_hash,
            "block_height": block_height,
            "state_root_hash": state_root_hash,
            "block_timestamp": finalized_at,
            "finalized_at": finalized_at,
            "observed_at": observed_at,
            "deploy_hash": deploy_hash,
            "corroboration_count": 2,
            "success": error_code is None,
            "user_error": error_code,
            "node_observations": observations,
            "endpoint_identities": [
                "https://rpc-a.example/rpc",
                "https://rpc-b.example/rpc",
            ],
        }


@pytest.fixture(scope="module")
def matched_bundle(tmp_path_factory: pytest.TempPathFactory) -> dict[str, object]:
    root = tmp_path_factory.mktemp("proof-registry-bundle")
    artifact_root = root / "artifacts"
    artifact_root.mkdir()

    exact = _python_exact_fixture()
    treasury = _node_treasury_fixture()
    deployment = exact["deployment"]
    assert isinstance(deployment, dict)
    treasury["source_commit"] = deployment["source_commit"]
    treasury["deployment_commit"] = deployment["deployment_commit"]
    release = treasury["release_identity"]
    assert isinstance(release, dict)
    release["package_hash"] = deployment["package_hash"]
    release["contract_hash"] = deployment["contract_hash"]
    release["wasm_sha256"] = deployment["build"]["wasm_sha256"]
    release["generated_schema_sha256"] = deployment["build"]["schema_sha256"]

    captured = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=2)
    treasury["captured_at"] = captured.isoformat().replace("+00:00", "Z")
    finalized = captured - timedelta(minutes=5)
    observed = captured - timedelta(minutes=4)
    _add_durable_finality_evidence(
        exact,
        finalized_at=finalized.isoformat().replace("+00:00", "Z"),
        observed_at=observed.isoformat().replace("+00:00", "Z"),
    )
    journal = treasury["executor_journal"]
    assert isinstance(journal, dict)
    journal["created_at"] = (
        (captured - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
    )
    journal["updated_at"] = (
        (captured - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    )

    bounded = treasury["bounded_transfer_scan"]
    assert isinstance(bounded, dict)
    authorization_height = bounded["authorization_block_height"]
    assert isinstance(authorization_height, int)
    _reseal_exact_timeline(
        exact,
        finalization_height=authorization_height,
        finalization_hash=_scan_authorization_block_hash(treasury),
    )

    exact_path = artifact_root / "exact-v3.json"
    treasury_path = artifact_root / "native-treasury.json"
    exact_path.write_bytes(_canonical_bytes(exact))
    treasury_path.write_bytes(_canonical_bytes(treasury))
    return {
        "root": root,
        "exact_path": exact_path,
        "treasury_path": treasury_path,
        "exact": exact,
        "treasury": treasury,
        "generated_at": treasury["captured_at"],
    }


def _assemble(
    bundle: dict[str, object], output: Path | None = None
) -> dict[str, object]:
    root = bundle["root"]
    assert isinstance(root, Path)
    return assemble_proof_registry(
        repository_root=ROOT,
        output_path=output or root / "registry.json",
        exact_v3_path=bundle["exact_path"],
        native_treasury_path=bundle["treasury_path"],
        generated_at=bundle["generated_at"],
    )


def test_assembler_emits_only_independently_verified_available_proofs(
    matched_bundle: dict[str, object],
) -> None:
    document = _assemble(matched_bundle)
    root = matched_bundle["root"]
    assert isinstance(root, Path)

    assert set(document) == {"schema_version", "public_items", "internal_records"}
    assert document["schema_version"] == 1
    public_items = document["public_items"]
    assert isinstance(public_items, list)
    assert [item["proof_type"] for item in public_items] == [
        "exact_envelope_v3",
        "native_treasury_execution_v1",
    ]
    absent_producers = {
        "safepay_v2",
        "official_x402_settlement_v1",
        "approval_boundary_v1",
        "demo_capability_v1",
        "room_identity_v1",
    }
    assert absent_producers.isdisjoint(item["proof_type"] for item in public_items)
    for item in public_items:
        expected = REQUIRED_CHECKS_BY_PROOF_TYPE[item["proof_type"]]
        assert len(item["checks"]) == len(expected)
        assert [check["name"] for check in item["checks"]] == list(expected)
        assert all(
            check["required"] is True and check["passed"] is True
            for check in item["checks"]
        )
        artifact = root / item["artifact_path"]
        assert (
            hashlib.sha256(artifact.read_bytes()).hexdigest() == item["artifact_sha256"]
        )
        assert proof_item_is_green(item) is True

    repository = ProofRegistryRepository(root)
    proposal_id = public_items[0]["proposal_id"]
    public = repository.public_document(
        proposal_id,
        known=True,
        generated_at=matched_bundle["generated_at"],
    )
    assert len(public["items"]) == 2
    assert all(proof_item_is_green(item) for item in public["items"])
    internal = repository.by_action_id(public_items[0]["action_id"])
    assert internal["v3_finalized_exact"] is True
    assert internal["network"] == "casper:casper-test"
    exact_step = next(
        step
        for step in matched_bundle["exact"]["run"]["steps"]
        if step["name"] == "finalize_exact"
    )
    finality = exact_step["finality_block_evidence"]
    exact_item = next(
        item for item in public_items if item["proof_type"] == "exact_envelope_v3"
    )
    assert exact_item["captured_at"] == matched_bundle["generated_at"]
    observed_by_name = {
        check["name"]: check["observed_at"] for check in exact_item["checks"]
    }
    assert observed_by_name["pre_quorum_finalize_reverted_with_code_8"] == next(
        step["finality_block_evidence"]["observed_at"]
        for step in matched_bundle["exact"]["run"]["steps"]
        if step["name"] == "finalize_pre_quorum"
    )
    assert observed_by_name["exact_envelope_finalization_accepted"] == finality[
        "observed_at"
    ]
    assert observed_by_name["source_tree_sha256_matches_release_manifest"] == (
        matched_bundle["generated_at"]
    )
    assert internal["finalized_at"] == finality["finalized_at"]
    assert internal["observed_at"] == matched_bundle["generated_at"]
    assert internal["observed_at"] >= finality["observed_at"]


def test_assembler_rejects_any_step_observed_after_registry_generation(
    matched_bundle: dict[str, object],
) -> None:
    root = matched_bundle["root"]
    assert isinstance(root, Path)
    exact = copy.deepcopy(matched_bundle["exact"])
    exact["run"]["steps"][-1]["finality_block_evidence"]["observed_at"] = (
        "2099-01-01T00:00:00Z"
    )
    path = root / "artifacts/future-step-observation.json"
    path.write_bytes(_canonical_bytes(exact))

    with pytest.raises(AssemblyError, match="later than registry verification"):
        assemble_proof_registry(
            repository_root=ROOT,
            output_path=root / "registry.json",
            exact_v3_path=path,
            native_treasury_path=matched_bundle["treasury_path"],
            generated_at=matched_bundle["generated_at"],
        )


def test_assembled_public_document_passes_packaged_verifier(
    matched_bundle: dict[str, object],
) -> None:
    document = _assemble(matched_bundle)
    root = matched_bundle["root"]
    assert isinstance(root, Path)
    proposal_id = document["public_items"][0]["proposal_id"]
    public = ProofRegistryRepository(root).public_document(
        proposal_id,
        known=True,
        generated_at=matched_bundle["generated_at"],
    )
    public_path = root / "public-verifier-input.json"
    public_path.write_bytes(_canonical_bytes(public))
    try:
        result = subprocess.run(
            [
                "node",
                str(VERIFY_CLI),
                "local",
                str(public_path),
                "--now",
                str(matched_bundle["generated_at"]),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
    finally:
        public_path.unlink(missing_ok=True)
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "verified"
    assert payload["summary"] == {
        "total": 2,
        "verified": 2,
        "invalid": 0,
        "unavailable": 0,
        "unknown": 0,
    }
    assert all(item["green"] is True for item in payload["items"])


def test_assembler_rejects_assertion_smuggling_and_preserves_previous_output(
    matched_bundle: dict[str, object],
) -> None:
    root = matched_bundle["root"]
    exact_path = matched_bundle["exact_path"]
    assert isinstance(root, Path) and isinstance(exact_path, Path)
    forged = copy.deepcopy(matched_bundle["exact"])
    forged["verified"] = True
    forged_path = root / "artifacts/forged-exact.json"
    forged_path.write_bytes(_canonical_bytes(forged))
    output = root / "registry.json"
    output.write_bytes(b'{"existing":"preserved"}\n')
    before = output.read_bytes()

    with pytest.raises(AssemblyError, match="exact-envelope v3"):
        assemble_proof_registry(
            repository_root=ROOT,
            output_path=output,
            exact_v3_path=forged_path,
            native_treasury_path=matched_bundle["treasury_path"],
            generated_at=matched_bundle["generated_at"],
        )

    assert output.read_bytes() == before


def test_assembler_rejects_duplicate_artifacts_and_cross_artifact_mismatch(
    matched_bundle: dict[str, object],
) -> None:
    root = matched_bundle["root"]
    assert isinstance(root, Path)
    with pytest.raises(AssemblyError, match="distinct artifact paths"):
        assemble_proof_registry(
            repository_root=ROOT,
            output_path=root / "registry.json",
            exact_v3_path=matched_bundle["exact_path"],
            native_treasury_path=matched_bundle["exact_path"],
            generated_at=matched_bundle["generated_at"],
        )

    mismatched = copy.deepcopy(matched_bundle["treasury"])
    mismatched["authorization"]["proposal_id"] = "DAO-PROP-OTHER"
    mismatch_path = root / "artifacts/mismatched-treasury.json"
    mismatch_path.write_bytes(_canonical_bytes(mismatched))
    with pytest.raises(AssemblyError, match="proposal"):
        assemble_proof_registry(
            repository_root=ROOT,
            output_path=root / "registry.json",
            exact_v3_path=matched_bundle["exact_path"],
            native_treasury_path=mismatch_path,
            generated_at=matched_bundle["generated_at"],
        )


def test_assembler_rejects_misordered_chain_evidence(
    matched_bundle: dict[str, object],
) -> None:
    root = matched_bundle["root"]
    assert isinstance(root, Path)
    exact = copy.deepcopy(matched_bundle["exact"])
    body = exact["input"]["body"]
    snapshot_height = int(body["snapshot_block_height"])
    _reseal_exact_timeline(
        exact,
        finalization_height=snapshot_height,
        finalization_hash=_scan_authorization_block_hash(matched_bundle["treasury"]),
    )
    path = root / "artifacts/misordered-exact.json"
    path.write_bytes(_canonical_bytes(exact))

    with pytest.raises(AssemblyError, match="packaged verifier|chronology|ordering"):
        assemble_proof_registry(
            repository_root=ROOT,
            output_path=root / "registry.json",
            exact_v3_path=path,
            native_treasury_path=matched_bundle["treasury_path"],
            generated_at=matched_bundle["generated_at"],
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing", "block evidence|finality.*evidence|finalized_at"),
        (
            "forged_block_timestamp",
            "block timestamp|finalized_at|disagrees|v3 artifact",
        ),
        ("reversed", "observation.*before|predates|observed_at|v3 artifact"),
    ],
)
def test_exact_v3_registry_timing_is_derived_from_verified_finality_evidence(
    matched_bundle: dict[str, object], mutation: str, message: str
) -> None:
    root = matched_bundle["root"]
    assert isinstance(root, Path)
    exact = copy.deepcopy(matched_bundle["exact"])
    finalization = next(
        step for step in exact["run"]["steps"] if step["name"] == "finalize_exact"
    )
    evidence = finalization["finality_block_evidence"]
    if mutation == "missing":
        evidence.pop("observed_at")
    elif mutation == "forged_block_timestamp":
        evidence["finalized_at"] = "2026-01-01T00:00:00Z"
    elif mutation == "reversed":
        evidence["observed_at"] = "2026-01-01T00:00:00Z"
    else:  # pragma: no cover - parameter table is closed above
        raise AssertionError(mutation)
    path = root / f"artifacts/timing-{mutation}.json"
    path.write_bytes(_canonical_bytes(exact))

    with pytest.raises(AssemblyError, match=message):
        assemble_proof_registry(
            repository_root=ROOT,
            output_path=root / "registry.json",
            exact_v3_path=path,
            native_treasury_path=matched_bundle["treasury_path"],
            generated_at=matched_bundle["generated_at"],
        )


def test_historical_generation_v2_cannot_be_conflated_with_publishable_v1(
    matched_bundle: dict[str, object],
) -> None:
    root = matched_bundle["root"]
    assert isinstance(root, Path)
    path = root / "artifacts/historical-v2.json"
    path.write_bytes(
        _canonical_bytes(
            {
                "schema_version": "concordia.historical_odra_receipt.v1",
                "generation": "v2",
            }
        )
    )
    with pytest.raises(AssemblyError, match="v2.*unavailable|exactly v1"):
        assemble_proof_registry(
            repository_root=ROOT,
            output_path=root / "registry.json",
            historical_v1_path=path,
            exact_v3_path=matched_bundle["exact_path"],
            native_treasury_path=matched_bundle["treasury_path"],
            generated_at=matched_bundle["generated_at"],
        )


def test_artifacts_must_be_regular_files_confined_below_registry_bundle(
    matched_bundle: dict[str, object], tmp_path: Path
) -> None:
    root = matched_bundle["root"]
    assert isinstance(root, Path)
    outside = tmp_path / "outside.json"
    outside.write_bytes(Path(matched_bundle["exact_path"]).read_bytes())
    with pytest.raises(AssemblyError, match="confined"):
        assemble_proof_registry(
            repository_root=ROOT,
            output_path=root / "registry.json",
            exact_v3_path=outside,
            native_treasury_path=matched_bundle["treasury_path"],
            generated_at=matched_bundle["generated_at"],
        )

    symlink = root / "artifacts/symlink-exact.json"
    try:
        symlink.symlink_to(matched_bundle["exact_path"])
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    with pytest.raises(AssemblyError, match="symlink|regular"):
        assemble_proof_registry(
            repository_root=ROOT,
            output_path=root / "registry.json",
            exact_v3_path=symlink,
            native_treasury_path=matched_bundle["treasury_path"],
            generated_at=matched_bundle["generated_at"],
        )


def test_live_output_requires_release_flag_clean_git_and_historical_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live = tmp_path / "artifacts/live/proof-registry/registry.json"
    with pytest.raises(AssemblyError, match="--release"):
        _validate_output_mode(
            repository_root=tmp_path,
            output_path=live,
            release=False,
            historical_v1_path=tmp_path / "historical.json",
        )

    monkeypatch.setattr(
        "scripts.assemble_proof_registry._git_worktree_is_clean", lambda _root: False
    )
    with pytest.raises(AssemblyError, match="clean Git"):
        _validate_output_mode(
            repository_root=tmp_path,
            output_path=live,
            release=True,
            historical_v1_path=tmp_path / "historical.json",
        )

    monkeypatch.setattr(
        "scripts.assemble_proof_registry._git_worktree_is_clean", lambda _root: True
    )
    with pytest.raises(AssemblyError, match="historical"):
        _validate_output_mode(
            repository_root=tmp_path,
            output_path=live,
            release=True,
            historical_v1_path=None,
        )


def _release_assembly_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    roots_path: Path | None = None,
    verification_hook: Callable[[], None] | None = None,
) -> tuple[dict[str, object], Path, bytes]:
    repository_root = tmp_path / "repository"
    bundle_root = repository_root / "artifacts/live/proof-registry"
    artifact_root = bundle_root / "artifacts"
    artifact_root.mkdir(parents=True)
    output = bundle_root / "registry.json"
    proposal_id = "DAO-PROP-RELEASE-ROOTS"
    generated_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    exact_path = artifact_root / "exact.json"
    treasury_path = artifact_root / "treasury.json"
    historical_path = artifact_root / "historical.json"
    exact_path.write_bytes(b'{"deployment":{"install_block_height":9001}}\n')
    treasury_path.write_bytes(b'{"treasury":true}\n')
    historical_path.write_bytes(b'{"historical":true}\n')
    roots_payload = _canonical_bytes(
        {
            "schema_version": "concordia.card_chain_roots.v1",
            "roots": {proposal_id: "11" * 32},
        }
    )
    canonical_roots = repository_root / "artifacts/live/card-chain-roots-v1.json"
    canonical_roots.parent.mkdir(parents=True, exist_ok=True)
    canonical_roots.write_bytes(roots_payload)
    selected_roots = roots_path or canonical_roots

    exact_item = {
        "proof_id": "exact-release",
        "proposal_id": proposal_id,
        "action_id": "22" * 32,
        "captured_at": generated_at,
        "source_commit": "ab" * 20,
        "deployment_commit": "cd" * 20,
    }
    treasury_item = {
        "proof_id": "treasury-release",
        "proposal_id": proposal_id,
        "captured_at": generated_at,
        "source_commit": "ab" * 20,
        "deployment_commit": "cd" * 20,
    }
    historical_item = {
        "proof_id": "historical-release",
        "proposal_id": proposal_id,
        "captured_at": generated_at,
        "source_commit": "ab" * 20,
        "deployment_commit": "cd" * 20,
    }
    public_items = [historical_item, exact_item, treasury_item]

    monkeypatch.setattr(registry_assembler, "_git_worktree_is_clean", lambda _root: True)
    monkeypatch.setattr(
        registry_assembler,
        "_exact_item",
        lambda _artifact, verification_observed_at: (exact_item, {}),
    )
    monkeypatch.setattr(
        registry_assembler,
        "_treasury_item",
        lambda _artifact: (treasury_item, {}),
    )
    monkeypatch.setattr(
        registry_assembler,
        "_historical_item",
        lambda _artifact: (historical_item, {"blockHeight": 9000}),
    )
    monkeypatch.setattr(registry_assembler, "_same_binding", lambda *_args: None)
    monkeypatch.setattr(
        registry_assembler,
        "derive_card_chain_release_roots",
        lambda _raw: roots_payload,
    )
    monkeypatch.setattr(registry_assembler, "proof_item_is_green", lambda _item: True)
    monkeypatch.setattr(
        registry_assembler,
        "build_public_registry",
        lambda _proposal, items, **_kwargs: {"items": list(items)},
    )

    def verify_packaged(**_kwargs: object) -> None:
        if verification_hook is not None:
            verification_hook()

    monkeypatch.setattr(registry_assembler, "_verify_with_packaged_cli", verify_packaged)
    monkeypatch.setattr(
        registry_assembler,
        "_internal_record",
        lambda _artifact, _item: {"v3_finalized_exact": True},
    )
    monkeypatch.setattr(registry_assembler, "_git_commit_exists", lambda *_args: True)

    class FakeRepository:
        def __init__(self, _root: Path) -> None:
            pass

        def public_document(self, *_args: object, **_kwargs: object) -> dict[str, object]:
            return {"items": public_items}

        def by_action_id(self, _action_id: str) -> dict[str, object]:
            return {"v3_finalized_exact": True}

    monkeypatch.setattr(registry_assembler, "ProofRegistryRepository", FakeRepository)
    document = assemble_proof_registry(
        repository_root=repository_root,
        output_path=output,
        historical_v1_path=historical_path,
        card_chain_roots_path=selected_roots,
        exact_v3_path=exact_path,
        native_treasury_path=treasury_path,
        generated_at=generated_at,
        release=True,
    )
    return document, canonical_roots, roots_payload


def test_release_assembly_rejects_equal_alternate_card_chain_roots_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    alternate = tmp_path / "alternate-card-chain-roots.json"
    alternate.write_bytes(
        _canonical_bytes(
            {
                "schema_version": "concordia.card_chain_roots.v1",
                "roots": {"DAO-PROP-RELEASE-ROOTS": "11" * 32},
            }
        )
    )

    with pytest.raises(AssemblyError, match="canonical.*card-chain roots"):
        _release_assembly_case(tmp_path, monkeypatch, roots_path=alternate)


def test_release_output_binds_canonical_card_chain_roots_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document, canonical_roots, roots_payload = _release_assembly_case(
        tmp_path, monkeypatch
    )

    assert document["card_chain_roots"] == {
        "artifact_path": "artifacts/live/card-chain-roots-v1.json",
        "artifact_sha256": hashlib.sha256(roots_payload).hexdigest(),
    }
    assert canonical_roots.read_bytes() == roots_payload
    loaded = ProofRegistryRepository(canonical_roots.parent / "proof-registry")._documents()
    assert loaded[0]["card_chain_roots"] == document["card_chain_roots"]


def test_release_assembly_rejects_roots_changed_after_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository_root = tmp_path / "repository"
    canonical_roots = repository_root / "artifacts/live/card-chain-roots-v1.json"

    def alter_validated_roots() -> None:
        canonical_roots.write_bytes(b'{"changed":true}\n')

    with pytest.raises(AssemblyError, match="card-chain roots changed during verification"):
        _release_assembly_case(
            tmp_path,
            monkeypatch,
            verification_hook=alter_validated_roots,
        )


def test_clean_checkout_without_npm_dependencies_fails_with_exact_build_gate(
    tmp_path: Path,
) -> None:
    package = tmp_path / "packages/verify"
    package.mkdir(parents=True)

    with pytest.raises(AssemblyError, match=r"npm --prefix packages/verify ci"):
        _ensure_packaged_verifier(tmp_path)


def test_packaged_verifier_build_fails_if_its_inputs_change_mid_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = tmp_path / "packages/verify"
    (package / "node_modules/typescript/bin").mkdir(parents=True)
    (package / "node_modules/typescript/bin/tsc").write_text("", encoding="ascii")
    (package / "dist").mkdir()
    (package / "dist/cli.js").write_text("", encoding="ascii")
    fingerprints = iter(("a" * 64, "b" * 64))
    monkeypatch.setattr(
        "scripts.assemble_proof_registry._verifier_input_fingerprint",
        lambda _root: next(fingerprints),
    )
    monkeypatch.setattr(
        "scripts.assemble_proof_registry.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0),
    )

    with pytest.raises(AssemblyError, match="changed during"):
        _ensure_packaged_verifier(tmp_path)


def test_atomic_writer_fsyncs_temp_and_preserves_old_file_on_rename_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "registry.json"
    output.write_text("old\n", encoding="utf-8")
    real_replace = os.replace

    def fail_replace(_source: object, _target: object) -> None:
        raise OSError("injected rename failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError, match="injected"):
        _atomic_write_document(
            output,
            {"schema_version": 1, "public_items": [], "internal_records": []},
        )
    assert output.read_text(encoding="utf-8") == "old\n"
    assert list(tmp_path.glob(".registry.json.*.tmp")) == []

    monkeypatch.setattr(os, "replace", real_replace)
    _atomic_write_document(
        output,
        {"schema_version": 1, "public_items": [], "internal_records": []},
    )
    assert json.loads(output.read_text(encoding="utf-8"))["schema_version"] == 1
