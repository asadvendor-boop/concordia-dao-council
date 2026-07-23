#!/usr/bin/env python3
"""Assemble one fail-closed, staging-first Concordia proof registry.

The assembler accepts only raw producer artifacts.  It derives registry facts
by running the Python historical/v3 verifiers and the packaged TypeScript
verifier; it never consumes a producer ``verified`` or ``passed`` summary as
authority. Release mode additionally requires the independent SafePay v2 and
official-x402 raw-artifact adapters and emits the exact frozen five-public /
two-internal release registry.
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
from shared import release_proof_adapters
from shared.proof_registry import (
    ProofRegistryRepository,
    REQUIRED_CHECKS_BY_PROOF_TYPE,
    build_public_registry,
    proof_item_is_green,
    validate_internal_record,
    validate_release_registry_document,
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
_RELEASE_ARTIFACT_PATHS = {
    "historical_v1": "artifacts/live/historical-odra-receipt-v2.json",
    "exact_v3": (
        "artifacts/live/odra-governance-receipt-v3-exact-envelope-proof.json"
    ),
    "native_treasury": "artifacts/live/treasury-execution-v3.json",
    "safepay_v2": "artifacts/live/safepay-lite-replaysafe-v2.json",
    "official_x402": "artifacts/live/official-x402-settlement-v1.json",
}
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
    package_hash: str | None,
    contract_hash: str | None,
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


def _adapter_checks(
    result: Mapping[str, Any],
    *,
    proof_type: str,
    artifact: _Artifact,
    captured_at: str,
) -> list[dict[str, Any]]:
    if (
        result.get("proof_type") != proof_type
        or result.get("artifact_sha256") != artifact.sha256
    ):
        raise AssemblyError(
            f"{proof_type} adapter result differs from the raw artifact identity"
        )
    adapter_checks = result.get("checks")
    required_names = REQUIRED_CHECKS_BY_PROOF_TYPE[proof_type]
    if not isinstance(adapter_checks, list) or len(adapter_checks) != len(
        required_names
    ):
        raise AssemblyError(f"{proof_type} adapter check cardinality is invalid")
    captured_time = _parse_timestamp(captured_at, f"{proof_type} captured_at")
    checks: list[dict[str, Any]] = []
    for expected_name, check_value in zip(
        required_names, adapter_checks, strict=True
    ):
        check = _mapping(check_value, f"{proof_type} adapter check")
        observed_at = _text(
            check.get("observed_at"), f"{proof_type} {expected_name} observed_at"
        )
        if (
            check.get("name") != expected_name
            or check.get("passed") is not True
            or check.get("source") != artifact.relative_path
            or _parse_timestamp(
                observed_at, f"{proof_type} {expected_name} observed_at"
            )
            > captured_time
        ):
            raise AssemblyError(
                f"{proof_type} adapter check {expected_name} is not independently valid"
            )
        checks.append(
            {
                "name": expected_name,
                "required": True,
                "passed": True,
                "source": artifact.relative_path,
                "observed_at": observed_at,
            }
        )
    return checks


def _safepay_item(artifact: _Artifact) -> dict[str, Any]:
    try:
        result = release_proof_adapters.verify_safepay_v2_artifact(
            artifact.document, artifact.raw
        )
    except release_proof_adapters.ReleaseProofAdapterError as exc:
        raise AssemblyError(f"SafePay v2 raw artifact was rejected: {exc}") from exc
    facts = _mapping(result.get("derived_facts"), "SafePay v2 derived facts")
    captured_at = _text(facts.get("captured_at"), "SafePay v2 captured_at")
    item = _base_item(
        proof_id="safepay_v2",
        proof_type="safepay_v2",
        generation="v2",
        lineage="supplemental",
        temporal_scope="current",
        claim_scope=(
            "One exact native Testnet payment consumed one immutable SafePay quote; "
            "an exact retry returned the stored fulfillment and cross-binding reuse "
            "was rejected before a second consumption."
        ),
        enforcement_scope=(
            "SafePay Lite provider consumption and report-release binding; this is "
            "separate from the official WCSPR x402 facilitator flow."
        ),
        proposal_id=_text(facts.get("proposal_id"), "SafePay v2 proposal_id"),
        action_id=None,
        envelope_hash=None,
        artifact=artifact,
        source_commit=_git40(
            facts.get("source_commit"), "SafePay v2 source_commit"
        ),
        deployment_commit=_git40(
            facts.get("deployment_commit"), "SafePay v2 deployment_commit"
        ),
        network=_text(facts.get("network"), "SafePay v2 network"),
        package_hash=None,
        contract_hash=None,
        deployment_domain=None,
        schema_version=_text(
            artifact.document.get("schema_version"), "SafePay v2 schema_version"
        ),
        captured_at=captured_at,
    )
    item["observation_mode"] = "live"
    item["report_hash"] = _hash32(
        facts.get("report_hash"), "SafePay v2 report_hash"
    )
    item["settlement_transaction"] = _hash32(
        facts.get("payment_hash"), "SafePay v2 payment_hash"
    )
    item["checks"] = _adapter_checks(
        result,
        proof_type="safepay_v2",
        artifact=artifact,
        captured_at=captured_at,
    )
    return item


def _official_item_and_internal(
    artifact: _Artifact,
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        result = release_proof_adapters.verify_official_x402_artifact(
            artifact.document, artifact.raw
        )
    except release_proof_adapters.ReleaseProofAdapterError as exc:
        raise AssemblyError(
            f"official x402 raw artifact was rejected: {exc}"
        ) from exc
    facts = _mapping(result.get("derived_facts"), "official x402 derived facts")
    captured_at = _text(facts.get("captured_at"), "official x402 captured_at")
    item = _base_item(
        proof_id="official_x402_settlement_v1",
        proof_type="official_x402_settlement_v1",
        generation="v3",
        lineage="supplemental",
        temporal_scope="current",
        claim_scope=(
            "The official WCSPR x402 authorization, facilitator verification and "
            "settlement, finalized chain receipt, and paid report release are bound "
            "to one exact v3 envelope."
        ),
        enforcement_scope=(
            "Official WCSPR facilitator settlement after exact-envelope v3 "
            "finalization; it does not relabel SafePay Lite as official x402."
        ),
        proposal_id=_text(facts.get("proposal_id"), "official x402 proposal_id"),
        action_id=_hash32(facts.get("action_id"), "official x402 action_id"),
        envelope_hash=_hash32(
            facts.get("envelope_hash"), "official x402 envelope_hash"
        ),
        artifact=artifact,
        source_commit=_git40(
            facts.get("source_commit"), "official x402 source_commit"
        ),
        deployment_commit=_git40(
            facts.get("deployment_commit"), "official x402 deployment_commit"
        ),
        network=_text(facts.get("network"), "official x402 network"),
        package_hash=_hash32(
            facts.get("package_hash"), "official x402 package_hash"
        ),
        contract_hash=_hash32(
            facts.get("contract_hash"), "official x402 contract_hash"
        ),
        deployment_domain=_hash32(
            facts.get("deployment_domain"), "official x402 deployment_domain"
        ),
        schema_version=_text(
            artifact.document.get("schema_version"),
            "official x402 schema_version",
        ),
        captured_at=captured_at,
    )
    item["observation_mode"] = "live"
    for field in (
        "payment_requirements_hash",
        "signed_payment_payload_hash",
        "report_hash",
        "settlement_transaction",
    ):
        item[field] = _hash32(facts.get(field), f"official x402 {field}")
    item["checks"] = _adapter_checks(
        result,
        proof_type="official_x402_settlement_v1",
        artifact=artifact,
        captured_at=captured_at,
    )
    raw_internal = _mapping(
        result.get("internal_record"), "official x402 internal record"
    )
    internal = validate_internal_record(copy.deepcopy(raw_internal))
    if (
        internal != raw_internal
        or internal.get("verification_status") != "verified"
        or internal.get("v3_finalized_exact") is not True
    ):
        raise AssemblyError(
            "official x402 adapter internal record failed registry validation"
        )
    return item, internal


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
    finalized_at, finality_observed_at = _exact_finality_timing(
        exact_artifact.document
    )
    observed_at = _text(
        exact_item.get("captured_at"), "v3 registry verification observed_at"
    )
    if _parse_timestamp(
        observed_at, "v3 registry verification observed_at"
    ) < _parse_timestamp(finality_observed_at, "v3 finality observed_at"):
        raise AssemblyError(
            "v3 registry verification predates the canonical finality observation"
        )
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
    expected_unsupported_capabilities: Mapping[str, str] | None = None,
) -> None:
    _ensure_packaged_verifier(repository_root)
    cli = repository_root / "packages/verify/dist/cli.js"
    unsupported = dict(expected_unsupported_capabilities or {})
    if not set(unsupported).issubset(expected_proof_ids):
        raise AssemblyError("packaged verifier unsupported proof inventory is invalid")
    artifact_paths = [
        item.get("artifact_path")
        for item in public_document.get("items", [])
        if isinstance(item, Mapping) and isinstance(item.get("artifact_path"), str)
    ]
    candidate_roots = [
        root
        for root in (repository_root, bundle_root)
        if all((root / relative).is_file() for relative in artifact_paths)
    ]
    if artifact_paths and not candidate_roots:
        raise AssemblyError(
            "packaged verifier artifact paths do not share one verification root"
        )
    verification_root = candidate_roots[0] if candidate_roots else repository_root
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".registry.verify.", suffix=".json", dir=verification_root
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
        expected_exit = 3 if unsupported else 0
        expected_status = "unavailable" if unsupported else "verified"
        expected_valid = not unsupported
        if (
            result.returncode != expected_exit
            or payload.get("tool") != "@concordia-dao/verify"
            or payload.get("status") != expected_status
            or payload.get("valid") is not expected_valid
            or payload.get("exitCode") != expected_exit
            or payload.get("proposalId") != public_document.get("proposal_id")
            or payload.get("summary")
            != {
                "total": len(expected_proof_ids),
                "verified": len(expected_proof_ids) - len(unsupported),
                "invalid": 0,
                "unavailable": len(unsupported),
                "unknown": 0,
            }
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
            if item.get("ignoredAssertions") != []:
                raise AssemblyError(
                    f"packaged verifier did not independently verify {proof_id}"
                )
            if proof_id in unsupported:
                if (
                    item.get("status") != "unavailable"
                    or item.get("green") is not False
                    or set(item.get("verifiedAspects", []))
                    != {
                        "artifact_identity_envelope",
                        "artifact_sha256",
                        "proposal_binding",
                    }
                    or item.get("unsupportedCapabilities")
                    != [unsupported[proof_id]]
                ):
                    raise AssemblyError(
                        "packaged verifier misstated unsupported payment semantics: "
                        f"{proof_id}"
                    )
                continue
            if (
                item.get("status") != "verified"
                or item.get("green") is not True
                or set(item.get("verifiedAspects", []))
                != {
                    "artifact_identity_envelope",
                    "artifact_sha256",
                    "proposal_binding",
                    "proof_semantics",
                }
                or item.get("unsupportedCapabilities") != []
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
    safepay_v2_path: str | Path | None = None,
    official_x402_path: str | Path | None = None,
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
    if release and safepay_v2_path is None:
        raise AssemblyError("release assembly requires the raw SafePay v2 artifact")
    if release and official_x402_path is None:
        raise AssemblyError(
            "release assembly requires the raw official x402 artifact"
        )


def _artifact_input(
    path_value: str | Path,
    *,
    repository_root: Path,
    bundle_root: Path,
    release: bool,
    release_key: str,
    label: str,
) -> tuple[_Artifact, Path]:
    artifact_root = bundle_root
    path = Path(path_value)
    if release:
        canonical = repository_root / _RELEASE_ARTIFACT_PATHS[release_key]
        provided = path if path.is_absolute() else repository_root / path
        try:
            canonical_resolved = canonical.resolve(strict=True)
            provided_resolved = provided.resolve(strict=True)
        except OSError as exc:
            raise AssemblyError(
                f"release canonical {label} is unavailable"
            ) from exc
        if provided_resolved != canonical_resolved:
            raise AssemblyError(f"release requires the canonical {label} path")
        path = provided_resolved
        artifact_root = repository_root
    return (
        _read_artifact(path, bundle_root=artifact_root, label=label),
        artifact_root,
    )


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
    safepay_v2_path: str | Path | None = None,
    official_x402_path: str | Path | None = None,
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
        safepay_v2_path=safepay_v2_path,
        official_x402_path=official_x402_path,
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

    exact, exact_root = _artifact_input(
        exact_v3_path,
        repository_root=root,
        bundle_root=bundle_root,
        release=release,
        release_key="exact_v3",
        label="exact-envelope v3 artifact",
    )
    treasury, treasury_root = _artifact_input(
        native_treasury_path,
        repository_root=root,
        bundle_root=bundle_root,
        release=release,
        release_key="native_treasury",
        label="native treasury artifact",
    )
    historical_result = (
        _artifact_input(
            historical_v1_path,
            repository_root=root,
            bundle_root=bundle_root,
            release=release,
            release_key="historical_v1",
            label="historical v1 artifact",
        )
        if historical_v1_path is not None
        else None
    )
    historical = historical_result[0] if historical_result is not None else None
    historical_root = (
        historical_result[1] if historical_result is not None else bundle_root
    )
    safepay_result = (
        _artifact_input(
            safepay_v2_path,
            repository_root=root,
            bundle_root=bundle_root,
            release=release,
            release_key="safepay_v2",
            label="SafePay v2 artifact",
        )
        if safepay_v2_path is not None
        else None
    )
    safepay = safepay_result[0] if safepay_result is not None else None
    safepay_root = safepay_result[1] if safepay_result is not None else bundle_root
    official_result = (
        _artifact_input(
            official_x402_path,
            repository_root=root,
            bundle_root=bundle_root,
            release=release,
            release_key="official_x402",
            label="official x402 artifact",
        )
        if official_x402_path is not None
        else None
    )
    official = official_result[0] if official_result is not None else None
    official_root = (
        official_result[1] if official_result is not None else bundle_root
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
    artifacts = [
        artifact
        for artifact in (historical, exact, treasury, safepay, official)
        if artifact
    ]
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
    official_internal: dict[str, Any] | None = None
    if safepay is not None:
        safepay_item = _safepay_item(safepay)
        if safepay_item["proposal_id"] != exact_item["proposal_id"]:
            raise AssemblyError("SafePay and v3 proposal bindings differ")
        public_items.append(safepay_item)
    if official is not None:
        official_item, official_internal = _official_item_and_internal(official)
        if official_item["proposal_id"] == exact_item["proposal_id"]:
            raise AssemblyError(
                "official x402 requires a distinct proposal from the native-transfer "
                "v3 action"
            )
        for field, label in (
            ("network", "network"),
            ("package_hash", "package"),
            ("contract_hash", "contract"),
            ("deployment_domain", "deployment domain"),
        ):
            if official_item.get(field) != exact_item.get(field):
                raise AssemblyError(
                    f"official x402 and native-transfer v3 {label} bindings differ"
                )
        if official_item.get("action_id") == exact_item.get("action_id"):
            raise AssemblyError("official x402 and native-transfer action IDs collide")
        if official_item.get("envelope_hash") == exact_item.get("envelope_hash"):
            raise AssemblyError("official x402 and native-transfer envelopes collide")
        public_items.append(official_item)

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
    proposal_ids = sorted({str(item["proposal_id"]) for item in public_items})
    expected_public_counts: dict[str, int] = {}
    for selected_proposal_id in proposal_ids:
        selected_items = [
            item
            for item in public_items
            if item["proposal_id"] == selected_proposal_id
        ]
        public_document = build_public_registry(
            selected_proposal_id,
            selected_items,
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
            expected_proof_ids=[item["proof_id"] for item in selected_items],
            expected_unsupported_capabilities={
                item["proof_id"]: (
                    "safepay_v2_semantics"
                    if item["proof_type"] == "safepay_v2"
                    else "official_x402_settlement_v1_semantics"
                )
                for item in selected_items
                if item["proof_type"]
                in {"safepay_v2", "official_x402_settlement_v1"}
            },
        )
        expected_public_counts[selected_proposal_id] = len(selected_items)

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
        (exact, exact_root, "exact-envelope v3 artifact"),
        (treasury, treasury_root, "native treasury artifact"),
    ]
    if historical is not None:
        unchanged_checks.append(
            (historical, historical_root, "historical v1 artifact")
        )
    if safepay is not None:
        unchanged_checks.append((safepay, safepay_root, "SafePay v2 artifact"))
    if official is not None:
        unchanged_checks.append((official, official_root, "official x402 artifact"))
    if release_roots is not None:
        unchanged_checks.append((release_roots, root, "card-chain roots"))
    for artifact, artifact_root, label in unchanged_checks:
        _assert_artifact_unchanged(
            artifact, bundle_root=artifact_root, label=label
        )

    document = {
        "schema_version": 1,
        "public_items": public_items,
        "internal_records": [
            record for record in (internal, official_internal) if record is not None
        ],
    }
    if release_roots is not None:
        document["card_chain_roots"] = {
            "artifact_path": release_roots.relative_path,
            "artifact_sha256": release_roots.sha256,
        }
    if release:
        try:
            validated_release = validate_release_registry_document(document)
        except ValueError as exc:
            raise AssemblyError(f"release proof registry is incomplete: {exc}") from exc
        if validated_release != document:
            raise AssemblyError("release proof registry validation changed its content")
    _atomic_write_document(output, document)

    # Exercise the same strict loader used by Gateway routes before returning.
    repository = ProofRegistryRepository(bundle_root)
    for selected_proposal_id, expected_count in expected_public_counts.items():
        loaded = repository.public_document(
            selected_proposal_id, known=True, generated_at=generated_at
        )
        if len(loaded["items"]) != expected_count or any(
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
    parser.add_argument("--safepay-v2", type=Path)
    parser.add_argument("--official-x402", type=Path)
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
            safepay_v2_path=args.safepay_v2,
            official_x402_path=args.official_x402,
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
