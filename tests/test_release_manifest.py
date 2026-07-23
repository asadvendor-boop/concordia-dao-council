from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from shared import release_manifest
from shared.release_manifest import (
    ARTIFACT_PATHS,
    COMPOSE_INVENTORY_PATH,
    RELEASE_INPUTS_PATH,
    RELEASE_MANIFEST_PATH,
    TREASURY_CHILD_PATH,
    ReleaseManifestError,
    build_release_manifest,
    write_release_manifest_once,
)


SOURCE_TIME = "2026-07-23T00:00:00Z"
CAPTURED_AT = "2026-07-23T00:10:00Z"
GENERATED_AT = "2026-07-23T00:20:00Z"
BUILD_SCRIPT = Path(__file__).parents[1] / "scripts/build_release_manifest.py"


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _git(repository: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        ["git", *args],
        cwd=repository,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return completed.stdout


def _commit(repository: Path, message: str) -> str:
    _git(repository, "add", "-A")
    _git(repository, "commit", "-m", message)
    return _git(repository, "rev-parse", "HEAD").decode().strip()


def _write(repository: Path, relative: str, value: object) -> None:
    target = repository / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(_canonical(value))


def _artifact_documents(
    source_commit: str, deployment_commit: str
) -> dict[str, dict[str, object]]:
    package_hash = "11" * 32
    contract_hash = "22" * 32
    install_deploy_hash = "33" * 32
    install_block_hash = "44" * 32
    historical = {
        "schema_version": "concordia.historical_odra_receipt.v1",
        "proposal_id": "DAO-PROP-6CB25C",
        "generation": "v1",
        "captured_at": CAPTURED_AT,
        "source_commit": source_commit,
        "deployment_commit": deployment_commit,
        "source_url": "https://concordia.47.84.232.193.sslip.io/proof-artifacts/v1/DAO-PROP-6CB25C/historical-odra-receipt",
        "network": "casper-test",
        "lineage_inventory": {},
        "contract_identity": {},
        "card_chain": {},
        "raw_rpc": {},
    }
    roots = {
        "schema_version": "concordia.card_chain_roots.v1",
        "roots": {"DAO-PROP-6CB25C": "55" * 32},
    }
    exact = {
        "schema_id": "concordia.v3-proof.v1",
        "deployment": {
            "status": "finalized",
            "network": "casper-test",
            "package_hash": package_hash,
            "contract_hash": contract_hash,
            "contract_version": 1,
            "install_deploy_hash": install_deploy_hash,
            "install_block_hash": install_block_hash,
            "install_block_height": 8_400_001,
            "source_commit": source_commit,
            "deployment_commit": deployment_commit,
        },
        "input": {},
        "prepared": {},
        "run": {
            "status": "contract_sequence_verified",
            "steps": [
                {
                    "name": "finalize_exact",
                    "finality_block_evidence": {
                        "status": "finalized",
                        "observed_at": CAPTURED_AT,
                    },
                }
            ],
        },
        "readback": {},
    }
    treasury = {
        "schema_version": "concordia.native_treasury_execution.v1",
        "captured_at": CAPTURED_AT,
        "source_commit": source_commit,
        "deployment_commit": deployment_commit,
        "release_identity": {},
        "authorization": {},
        "executor_journal": {},
        "finality": {"status": "finalized"},
        "balance_evidence": {},
        "bounded_transfer_scan": {},
        "artifact_sha256_scope": "canonical_json_without_release_manifest",
    }
    safepay = {
        "schema_version": "safepay-v2",
        "captured_at": CAPTURED_AT,
        "source_commit": source_commit,
        "deployment_commit": deployment_commit,
        "quote": {},
        "consumption": {},
        "redemption_observations": [],
        "verification": {"deploy_status": "finalized"},
    }
    official = {
        "schema_version": "concordia.official_x402_settlement.v1",
        "captured_at": CAPTURED_AT,
        "source_commit": source_commit,
        "deployment_commit": deployment_commit,
        "status": "verified",
        "governance_binding": {},
        "payment_requirements": {},
        "signed_payment_payload": {},
        "facilitator_verification": {},
        "settlement": {},
        "finality": {"status": "finalized"},
        "protected_report": {},
        "fulfillment": {},
    }
    public_items = []
    for proof_type, schema, artifact_id, artifact in (
        (
            "historical_odra_receipt_v2",
            "concordia.historical_odra_receipt.v1",
            "historical_odra_receipt_v1",
            historical,
        ),
        ("exact_envelope_v3", "concordia.v3-proof.v1", "exact_envelope_v3", exact),
        (
            "native_treasury_execution_v1",
            "concordia.native_treasury_execution.v1",
            "native_treasury_execution_v1",
            treasury,
        ),
        ("safepay_v2", "safepay-v2", "safepay_v2", safepay),
        (
            "official_x402_settlement_v1",
            "concordia.official_x402_settlement.v1",
            "official_x402_settlement_v1",
            official,
        ),
    ):
        public_items.append(
            {
                "proof_id": proof_type,
                "proof_type": proof_type,
                "schema_version": schema,
                "captured_at": CAPTURED_AT,
                "source_commit": source_commit,
                "deployment_commit": deployment_commit,
                "artifact_path": ARTIFACT_PATHS[artifact_id],
                "artifact_sha256": hashlib.sha256(_canonical(artifact)).hexdigest(),
                "verification_status": "verified",
                "observation_mode": "live",
            }
        )
    registry = {
        "schema_version": 1,
        "public_items": public_items,
        "internal_records": [{}],
        "card_chain_roots": {
            "artifact_path": "artifacts/live/card-chain-roots-v1.json",
            "artifact_sha256": hashlib.sha256(_canonical(roots)).hexdigest(),
        },
    }
    return {
        "historical_odra_receipt_v1": historical,
        "card_chain_roots_v1": roots,
        "proof_registry_v1": registry,
        "exact_envelope_v3": exact,
        "native_treasury_execution_v1": treasury,
        "safepay_v2": safepay,
        "official_x402_settlement_v1": official,
    }


def _compose_inventory(source_commit: str, deployment_commit: str) -> dict[str, object]:
    services = [
        {
            "service_id": service,
            "image_reference": f"concordia/{service}:finals",
            "image_digest": "sha256:" + hashlib.sha256(service.encode()).hexdigest(),
        }
        for service in (
            "gateway",
            "x402-provider",
            "simulator",
            "dashboard",
            "rowan",
            "mercer",
            "verity",
            "alden",
            "locke",
            "wells",
            "recorder-heartbeat",
            "ipfs",
            "otel-collector",
            "jaeger",
            "x402-official",
        )
    ]
    return {
        "schema_version": "concordia.rendered_compose_inventory.v1",
        "captured_at": CAPTURED_AT,
        "source_commit": source_commit,
        "deployment_commit": deployment_commit,
        "compose_project": "concordia",
        "compose_semantic_sha256": "77" * 32,
        "services": services,
    }


def _release_inputs(
    source_commit: str,
    deployment_commit: str,
    compose_inventory: dict[str, object],
) -> dict[str, object]:
    services = [
        {
            **service,
            "deployment_commit": deployment_commit,
            "status": "staged",
            "staged_at": CAPTURED_AT,
        }
        for service in compose_inventory["services"]
    ]
    public_urls = [
        {
            "url_id": url_id,
            "url": url,
            "deployment_commit": deployment_commit,
            "status": "available",
            "observed_at": CAPTURED_AT,
        }
        for url_id, url in sorted(release_manifest.PUBLIC_URLS.items())
    ]
    return {
        "schema_version": "concordia.staged_release_inputs.v1",
        "captured_at": CAPTURED_AT,
        "source_commit": source_commit,
        "deployment_commit": deployment_commit,
        "rendered_compose_inventory_path": COMPOSE_INVENTORY_PATH,
        "rendered_compose_inventory_sha256": hashlib.sha256(
            _canonical(compose_inventory)
        ).hexdigest(),
        "compose_semantic_sha256": compose_inventory["compose_semantic_sha256"],
        "caddy_semantic_sha256": "66" * 32,
        "services": services,
        "public_urls": public_urls,
        "docs_pages": {
            "status": "deployed",
            "deployment_commit": deployment_commit,
            "url": "https://docs.concordiadao.xyz/",
            "observed_at": CAPTURED_AT,
        },
        "npm_package": {
            "status": "published",
            "name": "@concordia-dao/verify",
            "version": "1.0.0",
            "tarball_sha256": "88" * 32,
            "integrity": "sha512-" + base64.b64encode(b"\x99" * 64).decode("ascii"),
            "deployment_commit": deployment_commit,
            "observed_at": CAPTURED_AT,
        },
        "rpc_providers": [
            {
                "provider_id": "casper_association",
                "operator_id": "casper_association",
                "endpoint": "https://node.testnet.casper.network/rpc",
                "authentication": "none",
                "status": "reviewed",
                "reviewed_at": CAPTURED_AT,
            },
            {
                "provider_id": "cspr_cloud",
                "operator_id": "cspr_cloud",
                "endpoint": "https://node.testnet.cspr.cloud/rpc",
                "authentication": "raw_authorization_file",
                "status": "reviewed",
                "reviewed_at": CAPTURED_AT,
            },
        ],
    }


@pytest.fixture
def release_repository(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-b", "main")
    _git(repository, "config", "user.name", "Release Test")
    _git(repository, "config", "user.email", "release@example.invalid")
    _write(repository, "source.json", {"created_at": SOURCE_TIME})
    source_commit = _commit(repository, "source")
    _write(repository, "deployment.json", {"source_commit": source_commit})
    deployment_commit = _commit(repository, "deployment")

    documents = _artifact_documents(source_commit, deployment_commit)
    for artifact_id, relative in ARTIFACT_PATHS.items():
        _write(repository, relative, documents[artifact_id])
    compose_inventory = _compose_inventory(source_commit, deployment_commit)
    _write(repository, COMPOSE_INVENTORY_PATH, compose_inventory)
    _write(
        repository,
        RELEASE_INPUTS_PATH,
        _release_inputs(source_commit, deployment_commit, compose_inventory),
    )
    artifacts_commit = _commit(repository, "artifacts and staged identities")
    return repository, {
        "source": source_commit,
        "deployment": deployment_commit,
        "artifacts": artifacts_commit,
    }


def test_build_release_manifest_binds_every_fixed_artifact_and_release_identity(
    release_repository: tuple[Path, dict[str, str]],
) -> None:
    repository, commits = release_repository

    payload = build_release_manifest(repository, generated_at=GENERATED_AT)
    document = json.loads(payload)

    assert payload == _canonical(document)
    assert document["schema_version"] == "concordia.release_manifest.v1"
    assert document["status"] == "ready"
    assert document["generated_at"] == GENERATED_AT
    assert "manifest_commit" not in document
    assert [item["artifact_id"] for item in document["artifacts"]] == sorted(
        ARTIFACT_PATHS
    )
    for item in document["artifacts"]:
        raw = (repository / item["path"]).read_bytes()
        assert item["sha256"] == hashlib.sha256(raw).hexdigest()
        assert item["artifact_commit"] == commits["artifacts"]
        assert item["source_commit"] == commits["source"]
        assert item["deployment_commit"] == commits["deployment"]
    assert document["contract_identity"] == {
        "contract_version": 1,
        "entity_or_contract_hash": "22" * 32,
        "identity_kind": "contract_hash",
        "install_block_hash": "44" * 32,
        "install_block_height": 8_400_001,
        "install_deploy_hash": "33" * 32,
        "network": "casper-test",
        "package_hash": "11" * 32,
    }
    assert {item["service_id"] for item in document["services"]} == {
        item["service_id"]
        for item in _compose_inventory(commits["source"], commits["deployment"])[
            "services"
        ]
    }
    assert {item["url_id"] for item in document["public_urls"]} == set(
        release_manifest.PUBLIC_URLS
    )
    assert document["treasury_child"] is None
    assert document["compose_inventory"]["path"] == COMPOSE_INVENTORY_PATH
    assert document["compose_inventory"]["artifact_commit"] == commits["artifacts"]
    assert document["deployment_surfaces"] == {
        "caddy_semantic_sha256": "66" * 32,
        "compose_semantic_sha256": "77" * 32,
        "docs_pages": {
            "deployment_commit": commits["deployment"],
            "observed_at": CAPTURED_AT,
            "status": "deployed",
            "url": "https://docs.concordiadao.xyz/",
        },
        "npm_package": {
            "deployment_commit": commits["deployment"],
            "integrity": "sha512-" + base64.b64encode(b"\x99" * 64).decode("ascii"),
            "name": "@concordia-dao/verify",
            "observed_at": CAPTURED_AT,
            "status": "published",
            "tarball_sha256": "88" * 32,
            "version": "1.0.0",
        },
        "rpc_providers": [
            {
                "authentication": "none",
                "endpoint": "https://node.testnet.casper.network/rpc",
                "operator_id": "casper_association",
                "provider_id": "casper_association",
                "reviewed_at": CAPTURED_AT,
                "status": "reviewed",
            },
            {
                "authentication": "raw_authorization_file",
                "endpoint": "https://node.testnet.cspr.cloud/rpc",
                "operator_id": "cspr_cloud",
                "provider_id": "cspr_cloud",
                "reviewed_at": CAPTURED_AT,
                "status": "reviewed",
            },
        ],
    }


def test_manifest_uses_git_blob_bytes_and_rejects_untracked_or_modified_artifact(
    release_repository: tuple[Path, dict[str, str]],
) -> None:
    repository, _ = release_repository
    target = repository / ARTIFACT_PATHS["safepay_v2"]
    target.write_bytes(target.read_bytes() + b" ")

    with pytest.raises(
        ReleaseManifestError, match="worktree is not clean|committed bytes"
    ):
        build_release_manifest(repository, generated_at=GENERATED_AT)


def test_manifest_rejects_missing_required_fixed_artifact(
    release_repository: tuple[Path, dict[str, str]],
) -> None:
    repository, _ = release_repository
    (repository / ARTIFACT_PATHS["official_x402_settlement_v1"]).unlink()

    with pytest.raises(
        ReleaseManifestError, match="worktree is not clean|required artifact"
    ):
        build_release_manifest(repository, generated_at=GENERATED_AT)


def test_manifest_rejects_symlink_without_following_it(
    release_repository: tuple[Path, dict[str, str]],
) -> None:
    repository, _ = release_repository
    target = repository / ARTIFACT_PATHS["safepay_v2"]
    outside = repository.parent / "outside.json"
    outside.write_bytes(target.read_bytes())
    target.unlink()
    target.symlink_to(outside)

    with pytest.raises(ReleaseManifestError, match="worktree is not clean|symlink"):
        build_release_manifest(repository, generated_at=GENERATED_AT)


def test_manifest_rejects_duplicate_json_keys_even_when_git_tracked(
    release_repository: tuple[Path, dict[str, str]],
) -> None:
    repository, _ = release_repository
    target = repository / ARTIFACT_PATHS["safepay_v2"]
    target.write_bytes(
        b'{"schema_version":"safepay-v2","schema_version":"safepay-v2"}\n'
    )
    _commit(repository, "duplicate key")

    with pytest.raises(ReleaseManifestError, match="duplicate JSON key"):
        build_release_manifest(repository, generated_at=GENERATED_AT)


def test_manifest_rejects_unknown_fields_and_unavailable_status(
    release_repository: tuple[Path, dict[str, str]],
) -> None:
    repository, _ = release_repository
    staged = json.loads((repository / RELEASE_INPUTS_PATH).read_bytes())
    staged["unknown"] = True
    _write(repository, RELEASE_INPUTS_PATH, staged)
    _commit(repository, "unknown release input")

    with pytest.raises(ReleaseManifestError, match="unknown fields"):
        build_release_manifest(repository, generated_at=GENERATED_AT)

    staged.pop("unknown")
    staged["public_urls"][0]["status"] = "unavailable"
    _write(repository, RELEASE_INPUTS_PATH, staged)
    _commit(repository, "unavailable public URL")
    with pytest.raises(ReleaseManifestError, match="unavailable|available"):
        build_release_manifest(repository, generated_at=GENERATED_AT)


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-07-23T00:20:00+00:00",
        "2026-7-23T00:20:00Z",
        "2026-02-30T00:20:00Z",
        "2026-07-23T00:20:00z",
    ],
)
def test_manifest_rejects_noncanonical_timestamps(
    release_repository: tuple[Path, dict[str, str]], timestamp: str
) -> None:
    repository, _ = release_repository
    with pytest.raises(ReleaseManifestError, match="timestamp|RFC3339"):
        build_release_manifest(repository, generated_at=timestamp)


def test_manifest_rejects_generation_time_in_the_future(
    release_repository: tuple[Path, dict[str, str]],
) -> None:
    repository, _ = release_repository
    with pytest.raises(ReleaseManifestError, match="future"):
        build_release_manifest(repository, generated_at="2999-01-01T00:00:00Z")


def test_manifest_rejects_duplicate_service_or_url_identity(
    release_repository: tuple[Path, dict[str, str]],
) -> None:
    repository, _ = release_repository
    staged = json.loads((repository / RELEASE_INPUTS_PATH).read_bytes())
    staged["services"][1]["service_id"] = staged["services"][0]["service_id"]
    _write(repository, RELEASE_INPUTS_PATH, staged)
    _commit(repository, "duplicate service")

    with pytest.raises(ReleaseManifestError, match="duplicate service identity"):
        build_release_manifest(repository, generated_at=GENERATED_AT)


def test_manifest_requires_exact_dynamic_rendered_compose_inventory(
    release_repository: tuple[Path, dict[str, str]],
) -> None:
    repository, _ = release_repository
    staged = json.loads((repository / RELEASE_INPUTS_PATH).read_bytes())
    staged["services"].pop()
    _write(repository, RELEASE_INPUTS_PATH, staged)
    _commit(repository, "omit one rendered service")

    with pytest.raises(ReleaseManifestError, match="rendered Compose inventory"):
        build_release_manifest(repository, generated_at=GENERATED_AT)


def test_manifest_rejects_compose_or_caddy_digest_and_package_identity_drift(
    release_repository: tuple[Path, dict[str, str]],
) -> None:
    repository, _ = release_repository
    staged = json.loads((repository / RELEASE_INPUTS_PATH).read_bytes())
    staged["compose_semantic_sha256"] = "aa" * 32
    _write(repository, RELEASE_INPUTS_PATH, staged)
    _commit(repository, "compose digest drift")
    with pytest.raises(ReleaseManifestError, match="Compose semantic"):
        build_release_manifest(repository, generated_at=GENERATED_AT)

    staged["compose_semantic_sha256"] = "77" * 32
    staged["npm_package"]["name"] = "@someone-else/verify"
    _write(repository, RELEASE_INPUTS_PATH, staged)
    _commit(repository, "npm identity drift")
    with pytest.raises(ReleaseManifestError, match="npm package identity"):
        build_release_manifest(repository, generated_at=GENERATED_AT)


def test_manifest_rejects_proof_registry_artifact_path_or_hash_drift(
    release_repository: tuple[Path, dict[str, str]],
) -> None:
    repository, _ = release_repository
    registry = json.loads(
        (repository / ARTIFACT_PATHS["proof_registry_v1"]).read_bytes()
    )
    safepay = next(
        item for item in registry["public_items"] if item["proof_type"] == "safepay_v2"
    )
    safepay["artifact_sha256"] = "aa" * 32
    _write(repository, ARTIFACT_PATHS["proof_registry_v1"], registry)
    _commit(repository, "forge registry artifact binding")

    with pytest.raises(ReleaseManifestError, match="registry artifact binding"):
        build_release_manifest(repository, generated_at=GENERATED_AT)


def test_manifest_requires_two_exact_independent_reviewed_rpc_provider_identities(
    release_repository: tuple[Path, dict[str, str]],
) -> None:
    repository, _ = release_repository
    staged = json.loads((repository / RELEASE_INPUTS_PATH).read_bytes())
    staged["rpc_providers"][1]["operator_id"] = "casper_association"
    _write(repository, RELEASE_INPUTS_PATH, staged)
    _commit(repository, "collapse rpc operators")

    with pytest.raises(ReleaseManifestError, match="RPC provider|operator"):
        build_release_manifest(repository, generated_at=GENERATED_AT)


def test_required_negative_evidence_status_is_not_generic_release_unavailability(
    release_repository: tuple[Path, dict[str, str]],
) -> None:
    repository, _ = release_repository
    exact = json.loads((repository / ARTIFACT_PATHS["exact_envelope_v3"]).read_bytes())
    exact["run"]["steps"].insert(
        0,
        {
            "name": "finalize_pre_quorum",
            "status": "failed",
            "expected_error": 8,
            "finality_block_evidence": {
                "status": "finalized",
                "observed_at": CAPTURED_AT,
            },
        },
    )
    _write(repository, ARTIFACT_PATHS["exact_envelope_v3"], exact)
    registry = json.loads(
        (repository / ARTIFACT_PATHS["proof_registry_v1"]).read_bytes()
    )
    exact_item = next(
        item
        for item in registry["public_items"]
        if item["proof_type"] == "exact_envelope_v3"
    )
    exact_item["artifact_sha256"] = hashlib.sha256(_canonical(exact)).hexdigest()
    _write(repository, ARTIFACT_PATHS["proof_registry_v1"], registry)
    _commit(repository, "required negative proof status")

    document = json.loads(build_release_manifest(repository, generated_at=GENERATED_AT))
    assert document["status"] == "ready"


def test_manifest_rejects_secret_material_in_any_bound_input(
    release_repository: tuple[Path, dict[str, str]],
) -> None:
    repository, _ = release_repository
    staged = json.loads((repository / RELEASE_INPUTS_PATH).read_bytes())
    staged["services"][0]["image_reference"] = "Bearer should-never-be-here"
    _write(repository, RELEASE_INPUTS_PATH, staged)
    _commit(repository, "secret material")

    with pytest.raises(ReleaseManifestError, match="secret"):
        build_release_manifest(repository, generated_at=GENERATED_AT)


def test_manifest_rejects_commit_metadata_not_ancestral_to_artifact_commit(
    release_repository: tuple[Path, dict[str, str]],
) -> None:
    repository, _ = release_repository
    orphan = repository.parent / "orphan"
    _git(repository.parent, "clone", str(repository), str(orphan))
    _git(orphan, "checkout", "--orphan", "unrelated")
    for child in orphan.iterdir():
        if child.name != ".git":
            if child.is_dir():
                import shutil

                shutil.rmtree(child)
            else:
                child.unlink()
    _write(orphan, "orphan.json", {"orphan": True})
    unrelated = _commit(orphan, "unrelated")
    _git(repository, "fetch", str(orphan), unrelated)
    staged = json.loads((repository / RELEASE_INPUTS_PATH).read_bytes())
    staged["source_commit"] = unrelated
    _write(repository, RELEASE_INPUTS_PATH, staged)
    _commit(repository, "bad ancestry")

    with pytest.raises(ReleaseManifestError, match="ancestor"):
        build_release_manifest(repository, generated_at=GENERATED_AT)


def test_manifest_consumes_strict_tracked_treasury_child_when_present(
    release_repository: tuple[Path, dict[str, str]],
) -> None:
    repository, commits = release_repository
    treasury_bytes = (
        repository / ARTIFACT_PATHS["native_treasury_execution_v1"]
    ).read_bytes()
    child = {
        "schema_version": "concordia.treasury_release_child.v1",
        "status": "ready",
        "captured_at": CAPTURED_AT,
        "source_commit": commits["source"],
        "deployment_commit": commits["deployment"],
        "artifact_path": ARTIFACT_PATHS["native_treasury_execution_v1"],
        "artifact_sha256": hashlib.sha256(treasury_bytes).hexdigest(),
    }
    _write(repository, TREASURY_CHILD_PATH, child)
    child_commit = _commit(repository, "treasury child")

    document = json.loads(build_release_manifest(repository, generated_at=GENERATED_AT))
    assert document["treasury_child"] == {
        "artifact_commit": child_commit,
        "artifact_path": ARTIFACT_PATHS["native_treasury_execution_v1"],
        "artifact_sha256": hashlib.sha256(treasury_bytes).hexdigest(),
        "captured_at": CAPTURED_AT,
        "deployment_commit": commits["deployment"],
        "path": TREASURY_CHILD_PATH,
        "schema_version": "concordia.treasury_release_child.v1",
        "sha256": hashlib.sha256(_canonical(child)).hexdigest(),
        "source_commit": commits["source"],
        "status": "ready",
    }


def test_treasury_child_rejects_wrong_artifact_hash_or_unknown_field(
    release_repository: tuple[Path, dict[str, str]],
) -> None:
    repository, commits = release_repository
    child = {
        "schema_version": "concordia.treasury_release_child.v1",
        "status": "ready",
        "captured_at": CAPTURED_AT,
        "source_commit": commits["source"],
        "deployment_commit": commits["deployment"],
        "artifact_path": ARTIFACT_PATHS["native_treasury_execution_v1"],
        "artifact_sha256": "00" * 32,
    }
    _write(repository, TREASURY_CHILD_PATH, child)
    _commit(repository, "wrong treasury child")

    with pytest.raises(ReleaseManifestError, match="treasury child.*SHA-256"):
        build_release_manifest(repository, generated_at=GENERATED_AT)


def test_manifest_detects_path_swap_during_assembly(
    release_repository: tuple[Path, dict[str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _ = release_repository
    original = release_manifest._read_bounded_repository_file
    calls = 0

    def swapping_read(root: Path, relative: str, limit: int):
        nonlocal calls
        result = original(root, relative, limit)
        calls += 1
        if calls == len(ARTIFACT_PATHS) + 1:
            target = repository / ARTIFACT_PATHS["safepay_v2"]
            target.write_bytes(target.read_bytes() + b" ")
        return result

    monkeypatch.setattr(
        release_manifest, "_read_bounded_repository_file", swapping_read
    )
    with pytest.raises(ReleaseManifestError, match="changed during assembly|worktree"):
        build_release_manifest(repository, generated_at=GENERATED_AT)


def test_write_manifest_is_atomic_create_once_mode_0600_and_fsyncs_directory(
    release_repository: tuple[Path, dict[str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _ = release_repository
    payload = build_release_manifest(repository, generated_at=GENERATED_AT)
    fsynced_directory = False
    original_fsync = os.fsync

    def recording_fsync(fd: int) -> None:
        nonlocal fsynced_directory
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            fsynced_directory = True
        original_fsync(fd)

    monkeypatch.setattr(os, "fsync", recording_fsync)
    target = write_release_manifest_once(repository, payload)

    assert target == repository / RELEASE_MANIFEST_PATH
    assert target.read_bytes() == payload
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert fsynced_directory is True
    with pytest.raises(ReleaseManifestError, match="already exists"):
        write_release_manifest_once(repository, payload)


def test_write_manifest_rejects_noncanonical_or_nonready_payload(
    release_repository: tuple[Path, dict[str, str]],
) -> None:
    repository, _ = release_repository
    payload = build_release_manifest(repository, generated_at=GENERATED_AT)
    document = json.loads(payload)
    document["status"] = "unavailable"

    with pytest.raises(ReleaseManifestError, match="ready"):
        write_release_manifest_once(repository, _canonical(document))
    with pytest.raises(ReleaseManifestError, match="canonical"):
        write_release_manifest_once(repository, payload[:-1] + b" \n")


def test_cli_has_no_artifact_path_selectors_and_creates_fixed_manifest_once(
    release_repository: tuple[Path, dict[str, str]],
) -> None:
    repository, _ = release_repository
    completed = subprocess.run(
        [
            sys.executable,
            str(BUILD_SCRIPT),
            "--repository-root",
            str(repository),
            "--generated-at",
            GENERATED_AT,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr.decode()
    result = json.loads(completed.stdout)
    assert result["status"] == "ready"
    assert result["path"] == RELEASE_MANIFEST_PATH
    assert (repository / RELEASE_MANIFEST_PATH).is_file()

    repeated = subprocess.run(
        [
            sys.executable,
            str(BUILD_SCRIPT),
            "--repository-root",
            str(repository),
            "--generated-at",
            GENERATED_AT,
            "--output",
            "somewhere-else.json",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert repeated.returncode == 2
    assert b"unrecognized arguments: --output" in repeated.stderr
