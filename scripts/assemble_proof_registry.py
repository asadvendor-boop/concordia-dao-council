#!/usr/bin/env python3
"""Assemble one fail-closed, staging-first Concordia proof registry.

The assembler accepts only raw producer artifacts.  It derives registry facts
by running the Python historical/v3 verifiers and the packaged TypeScript
verifier; it never consumes a producer ``verified`` or ``passed`` summary as
authority.  SafePay, approval/demo/room, and official-x402 items are omitted
until their independent producer adapters exist, which keeps them unavailable
instead of fabricating green placeholders.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping, Sequence

from scripts.verify_v3_proof import ProofVerificationError, verify_v3_proof_document
from scripts.generate_card_chain_release_roots import (
    ReleaseRootsError,
    derive_card_chain_release_roots,
    verify_existing_release_roots,
)
from shared.historical_odra_artifact import (
    HistoricalOdraArtifactError,
    HistoricalOdraArtifactUnavailable,
    verify_historical_odra_artifact,
)
from shared.proof_registry import (
    ProofRegistryRepository,
    REQUIRED_CHECKS_BY_PROOF_TYPE,
    build_public_registry,
    proof_item_is_green,
    validate_internal_record,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STAGING_OUTPUT = Path("artifacts/staging/proof-registry/registry.json")
DEFAULT_RELEASE_OUTPUT = Path("artifacts/live/proof-registry/registry.json")
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_VERIFIER_OUTPUT_BYTES = 2 * 1024 * 1024
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT40_RE = re.compile(r"^[0-9a-f]{40}$")
_RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_BUILT_VERIFIER_OUTPUTS: dict[str, str] = {}
_EXACT_CHECK_STEP = {
    "pre_quorum_finalize_reverted_with_code_8": "finalize_pre_quorum",
    "post_quorum_mutated_envelope_reverted_with_code_10": (
        "finalize_mutated_3000_bps"
    ),
    "exact_envelope_finalization_accepted": "finalize_exact",
    "repeat_finalization_reverted_with_code_12": "finalize_again",
    "finalization_deploy_processed_without_execution_error": "finalize_exact",
}


class AssemblyError(ValueError):
    """A registry cannot be assembled without weakening a proof boundary."""


class _DuplicateJsonKey(ValueError):
    pass


@dataclass(frozen=True)
class _Artifact:
    path: Path
    relative_path: str
    raw: bytes
    document: dict[str, Any]
    sha256: str
    stat_identity: tuple[int, int, int, int, int]


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJsonKey(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _strict_json_bytes(raw: bytes, *, label: str, limit: int) -> dict[str, Any]:
    if len(raw) > limit:
        raise AssemblyError(f"{label} exceeds its size limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AssemblyError(f"{label} is not UTF-8 JSON") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (_DuplicateJsonKey, json.JSONDecodeError, ValueError) as exc:
        raise AssemblyError(f"{label} is not strict JSON: {exc}") from exc
    if type(value) is not dict:
        raise AssemblyError(f"{label} must contain one JSON object")
    return value


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise AssemblyError("registry output is not canonical ASCII JSON") from exc


def _parse_timestamp(value: object, label: str) -> datetime:
    if type(value) is not str or _RFC3339_RE.fullmatch(value) is None:
        raise AssemblyError(f"{label} must be RFC3339 UTC-Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise AssemblyError(f"{label} must be RFC3339 UTC-Z") from exc
    if parsed.utcoffset() != timedelta(0):
        raise AssemblyError(f"{label} must be RFC3339 UTC-Z")
    return parsed


def _hash32(value: object, label: str) -> str:
    if type(value) is not str or _HEX32_RE.fullmatch(value) is None:
        raise AssemblyError(f"{label} must be lowercase 32-byte hexadecimal")
    return value


def _normalized_hash32(value: object, label: str) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
        raise AssemblyError(f"{label} must be 32-byte hexadecimal")
    return value.lower()


def _git40(value: object, label: str) -> str:
    if type(value) is not str or _GIT40_RE.fullmatch(value) is None:
        raise AssemblyError(f"{label} must be a lowercase Git commit")
    return value


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AssemblyError(f"{label} must be an object")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise AssemblyError(f"{label} must be nonempty text")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise AssemblyError(f"{label} must be ASCII") from exc
    return value


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _path_has_symlink(path: Path, root: Path) -> bool:
    try:
        relative = path.absolute().relative_to(root.absolute())
    except ValueError:
        return True
    current = root.absolute()
    for component in relative.parts:
        current = current / component
        if current.is_symlink():
            return True
    return False


def _read_artifact(
    path_value: str | Path, *, bundle_root: Path, label: str
) -> _Artifact:
    path = Path(path_value).absolute()
    root = bundle_root.resolve()
    try:
        resolved = path.resolve(strict=True)
        relative = resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise AssemblyError(
            f"{label} must be confined below the registry bundle"
        ) from exc
    if not relative.parts or relative.parts[0] != "artifacts":
        raise AssemblyError(
            f"{label} must be confined below the registry bundle artifacts directory"
        )
    if _path_has_symlink(path, root):
        raise AssemblyError(f"{label} cannot use a symlink")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AssemblyError(f"{label} is unavailable as a regular file") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise AssemblyError(f"{label} must be a regular file")
        if metadata.st_size > MAX_ARTIFACT_BYTES:
            raise AssemblyError(f"{label} exceeds 64 MiB")
        chunks: list[bytes] = []
        remaining = MAX_ARTIFACT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_ARTIFACT_BYTES:
            raise AssemblyError(f"{label} exceeds 64 MiB")
        after = os.fstat(descriptor)
        if (
            _stat_identity(metadata) != _stat_identity(after)
            or len(raw) != after.st_size
        ):
            raise AssemblyError(f"{label} changed while it was read")
    finally:
        os.close(descriptor)
    document = _strict_json_bytes(raw, label=label, limit=MAX_ARTIFACT_BYTES)
    return _Artifact(
        path=resolved,
        relative_path=relative.as_posix(),
        raw=raw,
        document=document,
        sha256=hashlib.sha256(raw).hexdigest(),
        stat_identity=_stat_identity(metadata),
    )


def _assert_artifact_unchanged(
    artifact: _Artifact, *, bundle_root: Path, label: str
) -> None:
    reread = _read_artifact(artifact.path, bundle_root=bundle_root, label=label)
    if (
        reread.stat_identity != artifact.stat_identity
        or reread.sha256 != artifact.sha256
        or reread.raw != artifact.raw
    ):
        raise AssemblyError(f"{label} changed during verification")


def _checks(proof_type: str, source: str, observed_at: str) -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "required": True,
            "passed": True,
            "source": source,
            "observed_at": observed_at,
        }
        for name in REQUIRED_CHECKS_BY_PROOF_TYPE[proof_type]
    ]


def _links() -> list[dict[str, str]]:
    return [
        {
            "rel": "proof_center",
            "label": "Concordia proof center",
            "href": "/dashboard/proof",
            "kind": "ui",
        }
    ]


def _base_item(
    *,
    proof_id: str,
    proof_type: str,
    generation: str,
    lineage: str,
    temporal_scope: str,
    claim_scope: str,
    enforcement_scope: str,
    proposal_id: str,
    action_id: str | None,
    envelope_hash: str | None,
    artifact: _Artifact,
    source_commit: str,
    deployment_commit: str,
    network: str,
    package_hash: str,
    contract_hash: str,
    deployment_domain: str | None,
    schema_version: str,
    captured_at: str,
) -> dict[str, Any]:
    return {
        "proof_id": proof_id,
        "proof_type": proof_type,
        "generation": generation,
        "lineage": lineage,
        "observation_mode": "snapshot",
        "temporal_scope": temporal_scope,
        "verification_status": "verified",
        "execution_outcome": "accepted",
        "claim_scope": claim_scope,
        "enforcement_scope": enforcement_scope,
        "proposal_id": proposal_id,
        "action_id": action_id,
        "envelope_hash": envelope_hash,
        "artifact_path": artifact.relative_path,
        "artifact_sha256": artifact.sha256,
        "source_commit": source_commit,
        "deployment_commit": deployment_commit,
        "network": network,
        "package_hash": package_hash,
        "contract_hash": contract_hash,
        "deployment_domain": deployment_domain,
        "schema_version": schema_version,
        "captured_at": captured_at,
        "payment_requirements_hash": None,
        "signed_payment_payload_hash": None,
        "report_hash": None,
        "settlement_transaction": None,
        "checks": _checks(proof_type, artifact.relative_path, captured_at),
        "links": _links(),
    }


def _historical_item(artifact: _Artifact) -> tuple[dict[str, Any], dict[str, object]]:
    if artifact.document.get("generation") == "v2":
        raise AssemblyError(
            "historical generation v2 combined proof is unavailable; release requires exactly v1"
        )
    try:
        facts = verify_historical_odra_artifact(artifact.raw)
    except HistoricalOdraArtifactUnavailable as exc:
        raise AssemblyError(f"historical v1 artifact is unavailable: {exc}") from exc
    except HistoricalOdraArtifactError as exc:
        raise AssemblyError(f"historical v1 artifact is invalid: {exc}") from exc
    if facts.get("generation") != "v1":
        raise AssemblyError(
            "historical combined artifact must be exactly generation v1"
        )
    item = _base_item(
        proof_id="historical_odra_receipt_v1",
        proof_type="historical_odra_receipt_v2",
        generation="v1",
        lineage="canonical",
        temporal_scope="historical",
        claim_scope=(
            "The preserved v1 receipt, exact card preimages, signed deploy, and "
            "embedded state transcripts are internally consistent."
        ),
        enforcement_scope=(
            "Historical quorum-gated receipt storage only; no retroactive v3, "
            "canonical-finality, custody, or source-to-Wasm equivalence claim."
        ),
        proposal_id=_text(facts.get("proposalId"), "historical proposal_id"),
        action_id=None,
        envelope_hash=None,
        artifact=artifact,
        source_commit=_git40(facts.get("sourceCommit"), "historical source_commit"),
        deployment_commit=_git40(
            facts.get("deploymentCommit"), "historical deployment_commit"
        ),
        network="casper-test",
        package_hash=_hash32(facts.get("packageHash"), "historical package hash"),
        contract_hash=_hash32(facts.get("contractHash"), "historical contract hash"),
        deployment_domain=None,
        schema_version="concordia.historical_odra_receipt.v1",
        captured_at=_text(facts.get("capturedAt"), "historical captured_at"),
    )
    return item, facts


def _exact_finality_timing(
    document: Mapping[str, Any],
) -> tuple[str, str]:
    run = _mapping(document.get("run"), "v3 run")
    steps = run.get("steps")
    if not isinstance(steps, Sequence) or isinstance(steps, (str, bytes)):
        raise AssemblyError("v3 run steps are invalid")
    finalizations = [
        step
        for step in steps
        if isinstance(step, Mapping) and step.get("name") == "finalize_exact"
    ]
    if len(finalizations) != 1:
        raise AssemblyError("v3 proof must contain exactly one finalize_exact step")
    evidence = _mapping(
        finalizations[0].get("finality_block_evidence"),
        "v3 finalize_exact finality evidence",
    )
    block_timestamp = _text(
        evidence.get("block_timestamp"), "v3 canonical block timestamp"
    )
    finalized_at = _text(evidence.get("finalized_at"), "v3 finalized_at")
    observed_at = _text(evidence.get("observed_at"), "v3 observed_at")
    finalized_time = _parse_timestamp(finalized_at, "v3 finalized_at")
    observed_time = _parse_timestamp(observed_at, "v3 observed_at")
    _parse_timestamp(block_timestamp, "v3 canonical block timestamp")
    if block_timestamp != finalized_at:
        raise AssemblyError(
            "v3 finalized_at must equal the verified canonical block timestamp"
        )
    if observed_time < finalized_time:
        raise AssemblyError("v3 finality observation predates canonical finalization")
    return finalized_at, observed_at


def _exact_check_timing(
    facts: Mapping[str, Any], *, verification_observed_at: str
) -> tuple[list[dict[str, Any]], str]:
    verification_time = _parse_timestamp(
        verification_observed_at, "v3 verification observed_at"
    )
    outcomes = _mapping(
        facts.get("contract_step_outcomes"), "v3 contract step outcomes"
    )
    required_steps = {
        "propose_exact",
        "finalize_pre_quorum",
        "approve_a",
        "approve_b",
        "finalize_mutated_3000_bps",
        "finalize_exact",
        "finalize_again",
    }
    if set(outcomes) != required_steps:
        raise AssemblyError("v3 contract step timing set is incomplete")
    observed_by_step: dict[str, str] = {}
    for name in sorted(required_steps):
        outcome = _mapping(outcomes[name], f"v3 {name} outcome")
        observed_at = _text(outcome.get("observed_at"), f"v3 {name} observed_at")
        if _parse_timestamp(observed_at, f"v3 {name} observed_at") > verification_time:
            raise AssemblyError(
                f"v3 {name} observation is later than registry verification"
            )
        observed_by_step[name] = observed_at
    checks: list[dict[str, Any]] = []
    check_times: list[tuple[datetime, str]] = []
    for check_name in REQUIRED_CHECKS_BY_PROOF_TYPE["exact_envelope_v3"]:
        step_name = _EXACT_CHECK_STEP.get(check_name)
        observed_at = (
            observed_by_step[step_name]
            if step_name is not None
            else verification_observed_at
        )
        check_times.append(
            (_parse_timestamp(observed_at, f"v3 {check_name} observed_at"), observed_at)
        )
        checks.append(
            {
                "name": check_name,
                "required": True,
                "passed": True,
                "source": "exact-v3-derived",
                "observed_at": observed_at,
            }
        )
    captured_at = max(check_times, key=lambda item: item[0])[1]
    return checks, captured_at


def _exact_item(
    artifact: _Artifact, *, verification_observed_at: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        facts = verify_v3_proof_document(artifact.document)
    except (ProofVerificationError, ValueError, KeyError, TypeError) as exc:
        raise AssemblyError(f"exact-envelope v3 artifact is invalid: {exc}") from exc
    deployment = _mapping(artifact.document.get("deployment"), "v3 deployment")
    header = _mapping(
        _mapping(artifact.document.get("input"), "v3 input").get("header"),
        "v3 typed header",
    )
    domain = _hash32(header.get("deployment_domain"), "v3 deployment domain")
    _exact_finality_timing(artifact.document)
    checks, captured_at = _exact_check_timing(
        facts, verification_observed_at=verification_observed_at
    )
    item = _base_item(
        proof_id="exact_envelope_v3",
        proof_type="exact_envelope_v3",
        generation="v3",
        lineage="supplemental",
        temporal_scope="current",
        claim_scope=(
            "The typed NativeTransferV1 envelope and seven-step Testnet proof "
            "recompute to the finalized action and envelope identities."
        ),
        enforcement_scope=(
            "Exact-envelope authorization by the named v3 package, contract, and "
            "deployment domain; no treasury custody claim."
        ),
        proposal_id=_text(facts.get("proposal_id"), "v3 proposal_id"),
        action_id=_hash32(facts.get("action_id"), "v3 action_id"),
        envelope_hash=_hash32(facts.get("envelope_hash"), "v3 envelope_hash"),
        artifact=artifact,
        source_commit=_git40(deployment.get("source_commit"), "v3 source_commit"),
        deployment_commit=_git40(
            deployment.get("deployment_commit"), "v3 deployment_commit"
        ),
        network=_text(facts.get("network"), "v3 network"),
        package_hash=_hash32(facts.get("package_hash"), "v3 package hash"),
        contract_hash=_hash32(facts.get("contract_hash"), "v3 contract hash"),
        deployment_domain=domain,
        schema_version="concordia.v3-proof.v1",
        captured_at=captured_at,
    )
    item["checks"] = [
        {**check, "source": artifact.relative_path} for check in checks
    ]
    return item, facts


def _treasury_item(artifact: _Artifact) -> tuple[dict[str, Any], dict[str, Any]]:
    # These are tentative claims only.  The packaged native-treasury adapter
    # below must independently reproduce every field before anything is emitted.
    document = artifact.document
    if document.get("schema_version") != "concordia.native_treasury_execution.v1":
        raise AssemblyError("native treasury artifact schema is invalid")
    release = _mapping(document.get("release_identity"), "treasury release identity")
    authorization = _mapping(document.get("authorization"), "treasury authorization")
    captured_at = _text(document.get("captured_at"), "treasury captured_at")
    _parse_timestamp(captured_at, "treasury captured_at")
    facts = {
        "proposal_id": _text(authorization.get("proposal_id"), "treasury proposal_id"),
        "action_id": _hash32(authorization.get("action_id"), "treasury action_id"),
        "envelope_hash": _hash32(
            authorization.get("envelope_hash"), "treasury envelope_hash"
        ),
        "source_commit": _git40(
            document.get("source_commit"), "treasury source_commit"
        ),
        "deployment_commit": _git40(
            document.get("deployment_commit"), "treasury deployment_commit"
        ),
        "network": _text(release.get("network"), "treasury network"),
        "package_hash": _hash32(release.get("package_hash"), "treasury package hash"),
        "contract_hash": _hash32(
            release.get("contract_hash"), "treasury contract hash"
        ),
        "deployment_domain": _hash32(
            release.get("deployment_domain"), "treasury deployment domain"
        ),
        "wasm_sha256": _hash32(release.get("wasm_sha256"), "treasury Wasm SHA-256"),
        "generated_schema_sha256": _hash32(
            release.get("generated_schema_sha256"),
            "treasury generated-schema SHA-256",
        ),
        "captured_at": captured_at,
    }
    item = _base_item(
        proof_id="native_treasury_execution_v1",
        proof_type="native_treasury_execution_v1",
        generation="v3",
        lineage="supplemental",
        temporal_scope="current",
        claim_scope=(
            "A single native Testnet transfer was authorized by the matched v3 "
            "envelope and is supported by bounded finality, balance, and scan evidence."
        ),
        enforcement_scope=(
            "Off-chain executor submission after exact on-chain authorization; "
            "the contract neither custodied nor directly disbursed treasury funds."
        ),
        proposal_id=facts["proposal_id"],
        action_id=facts["action_id"],
        envelope_hash=facts["envelope_hash"],
        artifact=artifact,
        source_commit=facts["source_commit"],
        deployment_commit=facts["deployment_commit"],
        network=facts["network"],
        package_hash=facts["package_hash"],
        contract_hash=facts["contract_hash"],
        deployment_domain=facts["deployment_domain"],
        schema_version="concordia.native_treasury_execution.v1",
        captured_at=captured_at,
    )
    return item, facts


def _same_binding(
    exact_item: Mapping[str, Any],
    treasury_item: Mapping[str, Any],
    exact_document: Mapping[str, Any],
    treasury_facts: Mapping[str, Any],
) -> None:
    for field, label in (
        ("proposal_id", "proposal"),
        ("action_id", "action"),
        ("envelope_hash", "envelope"),
        ("network", "network"),
        ("package_hash", "package"),
        ("contract_hash", "contract"),
        ("deployment_domain", "deployment domain"),
        ("source_commit", "source commit"),
        ("deployment_commit", "deployment commit"),
    ):
        if exact_item.get(field) != treasury_item.get(field):
            raise AssemblyError(f"exact-v3 and native-treasury {label} bindings differ")
    deployment = _mapping(exact_document.get("deployment"), "v3 deployment")
    build = _mapping(deployment.get("build"), "v3 deployment build")
    if treasury_facts.get("wasm_sha256") != build.get("wasm_sha256"):
        raise AssemblyError(
            "native-treasury Wasm binding differs from exact-v3 release"
        )
    if treasury_facts.get("generated_schema_sha256") != build.get("schema_sha256"):
        raise AssemblyError(
            "native-treasury generated-schema binding differs from exact-v3 release"
        )


def _internal_record(
    exact_artifact: _Artifact,
    exact_item: Mapping[str, Any],
) -> dict[str, Any]:
    input_document = _mapping(exact_artifact.document.get("input"), "v3 input")
    header = _mapping(input_document.get("header"), "v3 typed header")
    if input_document.get("action") != "NativeTransferV1":
        raise AssemblyError(
            "release registry currently requires a NativeTransferV1 exact proof"
        )
    try:
        action_version = int(str(header.get("action_version")))
    except ValueError as exc:
        raise AssemblyError("v3 action_version is invalid") from exc
    run = _mapping(exact_artifact.document.get("run"), "v3 run")
    steps = run.get("steps")
    if not isinstance(steps, Sequence) or isinstance(steps, (str, bytes)):
        raise AssemblyError("v3 run steps are invalid")
    finalizations = [
        step
        for step in steps
        if isinstance(step, Mapping) and step.get("name") == "finalize_exact"
    ]
    if len(finalizations) != 1:
        raise AssemblyError("v3 proof must contain exactly one finalize_exact step")
    finalization_transaction = _normalized_hash32(
        finalizations[0].get("deploy_hash"), "v3 finalization transaction"
    )
    finalized_at, observed_at = _exact_finality_timing(exact_artifact.document)
    record = {
        "schema_version": 1,
        "proposal_id": exact_item["proposal_id"],
        "proposal_hash": _hash32(header.get("proposal_hash"), "v3 proposal_hash"),
        "proposal_nonce": _hash32(header.get("proposal_nonce"), "v3 proposal_nonce"),
        "action_id": exact_item["action_id"],
        "action_kind": "NativeTransferV1",
        "action_version": action_version,
        "envelope_hash": exact_item["envelope_hash"],
        "deployment_domain": exact_item["deployment_domain"],
        "network": "casper:casper-test",
        "package_hash": exact_item["package_hash"],
        "contract_hash": exact_item["contract_hash"],
        # Deliberately false as input: validate_internal_record derives the value.
        "v3_finalized_exact": False,
        "finalization_transaction": finalization_transaction,
        "finalized_at": finalized_at,
        "resource_url_hash": None,
        "report_hash": None,
        "payment_requirements_hash": None,
        "signed_payment_payload_hash": None,
        "verification_status": "verified",
        "observed_at": observed_at,
        "checks": copy.deepcopy(exact_item["checks"]),
    }
    validated = validate_internal_record(record)
    if (
        validated.get("verification_status") != "verified"
        or validated.get("v3_finalized_exact") is not True
        or set(validated) != set(record)
    ):
        raise AssemblyError(
            "derived v3 internal record did not pass the Python registry"
        )
    return validated


def _verify_with_packaged_cli(
    *,
    repository_root: Path,
    bundle_root: Path,
    public_document: Mapping[str, Any],
    generated_at: str,
    expected_proof_ids: Sequence[str],
) -> None:
    _ensure_packaged_verifier(repository_root)
    cli = repository_root / "packages/verify/dist/cli.js"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".registry.verify.", suffix=".json", dir=bundle_root
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical_json_bytes(public_document))
            stream.flush()
            os.fsync(stream.fileno())
        result = subprocess.run(
            [
                "node",
                str(cli),
                "local",
                str(temporary),
                "--now",
                generated_at,
            ],
            cwd=repository_root,
            capture_output=True,
            timeout=180,
        )
        if len(result.stdout) > MAX_VERIFIER_OUTPUT_BYTES:
            raise AssemblyError("packaged verifier output exceeds 2 MiB")
        try:
            payload = _strict_json_bytes(
                result.stdout,
                label="packaged verifier result",
                limit=MAX_VERIFIER_OUTPUT_BYTES,
            )
        except AssemblyError as exc:
            raise AssemblyError("packaged verifier did not return strict JSON") from exc
        items = payload.get("items")
        if (
            result.returncode != 0
            or payload.get("tool") != "@concordia-dao/verify"
            or payload.get("status") != "verified"
            or payload.get("valid") is not True
            or payload.get("exitCode") != 0
            or not isinstance(items, list)
            or len(items) != len(expected_proof_ids)
        ):
            raise AssemblyError(
                "packaged verifier rejected registry bindings or chronology"
            )
        by_id = {
            item.get("proofId"): item for item in items if isinstance(item, Mapping)
        }
        if set(by_id) != set(expected_proof_ids):
            raise AssemblyError(
                "packaged verifier returned an unexpected proof cardinality"
            )
        for proof_id in expected_proof_ids:
            item = by_id[proof_id]
            if (
                item.get("status") != "verified"
                or item.get("green") is not True
                or item.get("ignoredAssertions") != []
            ):
                raise AssemblyError(
                    f"packaged verifier did not independently verify {proof_id}"
                )
    except subprocess.TimeoutExpired as exc:
        raise AssemblyError("packaged verifier timed out") from exc
    finally:
        temporary.unlink(missing_ok=True)


def _verifier_input_fingerprint(repository_root: Path) -> str:
    """Hash every tracked input consumed by the deterministic verifier build."""

    package = repository_root / "packages/verify"
    inputs = [
        package / "package.json",
        package / "package-lock.json",
        package / "tsconfig.json",
        *sorted((package / "src").rglob("*.ts")),
        *sorted((package / "scripts").rglob("*.mjs")),
        *sorted((repository_root / "tests/golden/envelope_v3").rglob("*.json")),
        repository_root
        / "contracts/odra-governance-receipt-v3/deployment.manifest.json",
        repository_root
        / "contracts/odra-governance-receipt-v3/wasm/GovernanceReceiptV3.wasm",
        repository_root
        / "contracts/odra-governance-receipt-v3/resources/casper_contract_schemas/governance_receiptv3_schema.json",
        repository_root / "handoff/HISTORICAL_ODRA_RECEIPTS_V1.json",
        repository_root / "handoff/HISTORICAL_ODRA_SHA256.txt",
    ]
    digest = hashlib.sha256()
    for path in inputs:
        if not path.is_file():
            raise AssemblyError(
                f"packaged verifier build input is unavailable: {path.name}"
            )
        relative = path.relative_to(repository_root).as_posix().encode("utf-8")
        raw = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def _ensure_packaged_verifier(repository_root: Path) -> None:
    """Build current sources and reject stale or subsequently changed output."""

    package = repository_root / "packages/verify"
    if not (package / "node_modules/typescript/bin/tsc").is_file():
        raise AssemblyError(
            "packaged verifier dependencies are unavailable; run "
            "`npm --prefix packages/verify ci` before registry assembly"
        )
    fingerprint = _verifier_input_fingerprint(repository_root)
    dist = package / "dist"
    expected_output = _BUILT_VERIFIER_OUTPUTS.get(fingerprint)
    if expected_output is not None and dist.is_dir():
        if _directory_fingerprint(dist) == expected_output:
            return
    try:
        result = subprocess.run(
            ["npm", "--prefix", str(package), "run", "build"],
            cwd=repository_root,
            capture_output=True,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AssemblyError("packaged verifier deterministic build failed") from exc
    if result.returncode != 0:
        raise AssemblyError(
            "packaged verifier deterministic build failed; run its build gate separately"
        )
    cli = package / "dist/cli.js"
    if not cli.is_file():
        raise AssemblyError("packaged verifier build did not produce dist/cli.js")
    if _verifier_input_fingerprint(repository_root) != fingerprint:
        raise AssemblyError("packaged verifier inputs changed during its build")
    _BUILT_VERIFIER_OUTPUTS[fingerprint] = _directory_fingerprint(dist)


def _directory_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(path for path in root.rglob("*") if path.is_file())
    if not files:
        raise AssemblyError("packaged verifier build output is empty")
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        raw = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest()


def _git_worktree_is_clean(repository_root: Path) -> bool:
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repository_root),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            capture_output=True,
            check=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.stdout == b""


def _git_commit_exists(repository_root: Path, commit: str) -> bool:
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repository_root),
                "cat-file",
                "-e",
                f"{commit}^{{commit}}",
            ],
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _validate_output_mode(
    *,
    repository_root: str | Path,
    output_path: str | Path,
    release: bool,
    historical_v1_path: str | Path | None,
) -> None:
    root = Path(repository_root).resolve()
    output = Path(output_path).absolute()
    live_root = root / "artifacts/live"
    in_live = _is_within(output, live_root)
    if in_live and not release:
        raise AssemblyError("writing below artifacts/live requires explicit --release")
    if release and not in_live:
        raise AssemblyError("--release output must be confined below artifacts/live")
    if release and historical_v1_path is None:
        raise AssemblyError(
            "release assembly requires the verified historical v1 artifact"
        )
    if release and not _git_worktree_is_clean(root):
        raise AssemblyError("release assembly requires a clean Git worktree")


def _validate_bundle_layout(output_path: Path) -> Path:
    if output_path.name != "registry.json":
        raise AssemblyError("registry output filename must be exactly registry.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    bundle_root = output_path.parent.resolve()
    if output_path.is_symlink():
        raise AssemblyError("registry output cannot be a symlink")
    siblings = [
        path
        for path in bundle_root.glob("*.json")
        if path.name != output_path.name
        and not path.name.startswith(".registry.verify.")
    ]
    if siblings:
        raise AssemblyError(
            "registry bundle root cannot contain unrelated JSON documents"
        )
    return bundle_root


def _atomic_write_document(path: str | Path, document: Mapping[str, Any]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_symlink():
        raise AssemblyError("registry output cannot be a symlink")
    payload = _canonical_json_bytes(document)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, output)
        directory_fd = os.open(output.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def assemble_proof_registry(
    *,
    repository_root: str | Path,
    output_path: str | Path,
    exact_v3_path: str | Path,
    native_treasury_path: str | Path,
    historical_v1_path: str | Path | None = None,
    card_chain_roots_path: str | Path | None = None,
    generated_at: str | None = None,
    release: bool = False,
) -> dict[str, Any]:
    """Verify producer artifacts and atomically write one strict registry."""

    root = Path(repository_root).resolve()
    output = Path(output_path).absolute()
    _validate_output_mode(
        repository_root=root,
        output_path=output,
        release=release,
        historical_v1_path=historical_v1_path,
    )
    bundle_root = _validate_bundle_layout(output)
    if generated_at is None:
        generated_at = (
            datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        )
    generated_time = _parse_timestamp(generated_at, "generated_at")
    now = datetime.now(UTC)
    if generated_time > now:
        raise AssemblyError("generated_at cannot be in the future")
    if release and now - generated_time > timedelta(minutes=5):
        raise AssemblyError(
            "release generated_at must be captured within the last five minutes"
        )

    exact = _read_artifact(
        exact_v3_path, bundle_root=bundle_root, label="exact-envelope v3 artifact"
    )
    treasury = _read_artifact(
        native_treasury_path,
        bundle_root=bundle_root,
        label="native treasury artifact",
    )
    historical = (
        _read_artifact(
            historical_v1_path,
            bundle_root=bundle_root,
            label="historical v1 artifact",
        )
        if historical_v1_path is not None
        else None
    )
    release_roots: _Artifact | None = None
    if release and card_chain_roots_path is None:
        raise AssemblyError(
            "release requires verifier-derived card-chain roots"
        )
    if release:
        canonical_roots_path = root / "artifacts/live/card-chain-roots-v1.json"
        provided_roots_path = Path(card_chain_roots_path).absolute()
        try:
            canonical_resolved = canonical_roots_path.resolve(strict=True)
            provided_resolved = provided_roots_path.resolve(strict=True)
        except OSError as exc:
            raise AssemblyError(
                "release canonical card-chain roots are unavailable"
            ) from exc
        if provided_resolved != canonical_resolved:
            raise AssemblyError(
                "release requires the canonical card-chain roots path"
            )
        release_roots = _read_artifact(
            provided_roots_path,
            bundle_root=root,
            label="card-chain roots",
        )
    artifacts = [artifact for artifact in (historical, exact, treasury) if artifact]
    if len({artifact.path for artifact in artifacts}) != len(artifacts):
        raise AssemblyError("producer inputs must use distinct artifact paths")
    if len({artifact.sha256 for artifact in artifacts}) != len(artifacts):
        raise AssemblyError(
            "producer inputs must have distinct artifact SHA-256 values"
        )

    exact_item, exact_facts = _exact_item(
        exact, verification_observed_at=generated_at
    )
    treasury_item, treasury_facts = _treasury_item(treasury)
    _same_binding(exact_item, treasury_item, exact.document, treasury_facts)
    public_items: list[dict[str, Any]] = []
    historical_facts: dict[str, object] | None = None
    if historical is not None:
        historical_item, historical_facts = _historical_item(historical)
        try:
            expected_roots = derive_card_chain_release_roots(historical.raw)
            if release_roots is not None:
                if release_roots.raw != expected_roots:
                    raise ReleaseRootsError(
                        "card-chain release roots does not equal verified historical receipt"
                    )
            elif card_chain_roots_path is not None:
                verify_existing_release_roots(
                    Path(card_chain_roots_path), expected_roots
                )
        except ReleaseRootsError as exc:
            raise AssemblyError(
                "card-chain roots are not derived from the verified historical receipt"
            ) from exc
        if historical_item["proposal_id"] != exact_item["proposal_id"]:
            raise AssemblyError("historical and v3 proposal bindings differ")
        install_height = _mapping(
            exact.document.get("deployment"), "v3 deployment"
        ).get("install_block_height")
        historical_height = historical_facts.get("blockHeight")
        if (
            type(install_height) is not int
            or type(historical_height) is not int
            or historical_height >= install_height
        ):
            raise AssemblyError(
                "historical receipt chronology does not precede v3 installation"
            )
        public_items.append(historical_item)
    public_items.extend([exact_item, treasury_item])

    for item in public_items:
        captured = _parse_timestamp(
            item["captured_at"], f"{item['proof_id']} captured_at"
        )
        if captured > generated_time:
            raise AssemblyError(
                f"{item['proof_id']} was captured after registry generation"
            )
        if not proof_item_is_green(item):
            raise AssemblyError(f"Python proof registry rejected {item['proof_id']}")

    proposal_id = exact_item["proposal_id"]
    public_document = build_public_registry(
        proposal_id,
        public_items,
        generated_at=generated_at,
        reference_time=generated_at,
    )
    if any(not proof_item_is_green(item) for item in public_document["items"]):
        raise AssemblyError("Python public registry normalization rejected an item")
    _verify_with_packaged_cli(
        repository_root=root,
        bundle_root=bundle_root,
        public_document=public_document,
        generated_at=generated_at,
        expected_proof_ids=[item["proof_id"] for item in public_items],
    )

    internal = _internal_record(exact, exact_item)
    if release:
        commits = {
            value
            for item in public_items
            for value in (item["source_commit"], item["deployment_commit"])
            if isinstance(value, str)
        }
        if any(not _git_commit_exists(root, commit) for commit in commits):
            raise AssemblyError("release artifact references an unavailable Git commit")

    unchanged_checks: list[tuple[_Artifact, Path, str]] = [
        (exact, bundle_root, "exact-envelope v3 artifact"),
        (treasury, bundle_root, "native treasury artifact"),
    ]
    if historical is not None:
        unchanged_checks.append((historical, bundle_root, "historical v1 artifact"))
    if release_roots is not None:
        unchanged_checks.append((release_roots, root, "card-chain roots"))
    for artifact, artifact_root, label in unchanged_checks:
        _assert_artifact_unchanged(
            artifact, bundle_root=artifact_root, label=label
        )

    document = {
        "schema_version": 1,
        "public_items": public_items,
        "internal_records": [internal],
    }
    if release_roots is not None:
        document["card_chain_roots"] = {
            "artifact_path": release_roots.relative_path,
            "artifact_sha256": release_roots.sha256,
        }
    _atomic_write_document(output, document)

    # Exercise the same strict loader used by Gateway routes before returning.
    repository = ProofRegistryRepository(bundle_root)
    loaded = repository.public_document(
        proposal_id, known=True, generated_at=generated_at
    )
    if len(loaded["items"]) != len(public_items) or any(
        not proof_item_is_green(item) for item in loaded["items"]
    ):
        raise AssemblyError("emitted registry failed repository reload")
    bound = repository.by_action_id(exact_item["action_id"])
    if bound.get("v3_finalized_exact") is not True:
        raise AssemblyError("emitted internal record failed action lookup")
    return document


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--historical-v1", type=Path)
    parser.add_argument("--card-chain-roots", type=Path)
    parser.add_argument("--exact-v3", type=Path, required=True)
    parser.add_argument("--native-treasury", type=Path, required=True)
    parser.add_argument("--generated-at")
    parser.add_argument("--release", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    repository_root = args.repository_root.resolve()
    output = args.output
    if output is None:
        output = repository_root / (
            DEFAULT_RELEASE_OUTPUT if args.release else DEFAULT_STAGING_OUTPUT
        )
    try:
        document = assemble_proof_registry(
            repository_root=repository_root,
            output_path=output,
            historical_v1_path=args.historical_v1,
            card_chain_roots_path=args.card_chain_roots,
            exact_v3_path=args.exact_v3,
            native_treasury_path=args.native_treasury,
            generated_at=args.generated_at,
            release=args.release,
        )
    except (AssemblyError, OSError) as exc:
        print(json.dumps({"status": "invalid", "error": str(exc)}, sort_keys=True))
        return 2
    print(
        json.dumps(
            {
                "status": "assembled",
                "output": str(Path(output)),
                "public_item_count": len(document["public_items"]),
                "internal_record_count": len(document["internal_records"]),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
