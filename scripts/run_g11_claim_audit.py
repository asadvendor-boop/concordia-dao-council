#!/usr/bin/env python3
"""Run G11 or verify the exact claim-to-artifact map without writing files."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from scripts.release_gate_runner import GateRunError, run_gate
from shared import g11_claim_policy_authority
from shared.proof_registry import (
    REQUIRED_CHECKS_BY_PROOF_TYPE,
    proof_item_is_green,
    validate_internal_record,
)


ROOT = Path(__file__).resolve().parents[1]
CLAIM_MAP_PATH = "docs/CLAIM_TO_ARTIFACT_MAP.json"
CLAIM_POLICY_PATH = "handoff/G11_CLAIM_POLICY.json"
REGISTRY_PATH = "artifacts/live/proof-registry/registry.json"
AUDITED_DOCUMENT_PATHS = (
    "README.md",
    "docs/POLICY_TEMPLATES.md",
    "docs/TECHNICAL_JURY_NOTE.md",
    "docs/DEMO_SCRIPT.md",
    "docs/DORAHACKS_SUBMISSION_TEXT.md",
)
_MAX_FILE_BYTES = 64 * 1024 * 1024
_HEX32 = re.compile(r"^[0-9a-f]{64}$")
_CLAIM_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
_CLAIM_CLASSES = frozenset(
    {"verified_current", "verified_historical", "limitation", "roadmap"}
)


class ClaimAuditError(ValueError):
    """The claim map does not prove its document and artifact bindings."""


def _canonical_json(value: object) -> bytes:
    try:
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
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ClaimAuditError("claim audit input is not canonical JSON") from exc


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ClaimAuditError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strict_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ClaimAuditError(f"invalid JSON constant: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ClaimAuditError(f"{label} is not strict UTF-8 JSON") from exc
    if type(value) is not dict:
        raise ClaimAuditError(f"{label} must be a JSON object")
    if raw != _canonical_json(value):
        raise ClaimAuditError(f"{label} is not canonical JSON")
    return value


def _relative_parts(relative: str) -> tuple[str, ...]:
    path = PurePosixPath(relative)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in relative
    ):
        raise ClaimAuditError(f"claim artifact path is unsafe: {relative}")
    return path.parts


def _read_regular(repository_root: Path, relative: str) -> bytes:
    parts = _relative_parts(relative)
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(repository_root, directory_flags)
    try:
        for part in parts[:-1]:
            next_descriptor = os.open(part, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        try:
            file_descriptor = os.open(
                parts[-1],
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
        except OSError as exc:
            raise ClaimAuditError(
                f"required claim artifact is missing: {relative}"
            ) from exc
        try:
            before = os.fstat(file_descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_FILE_BYTES:
                raise ClaimAuditError(
                    f"claim artifact is not a bounded regular file: {relative}"
                )
            chunks: list[bytes] = []
            remaining = _MAX_FILE_BYTES + 1
            while remaining:
                chunk = os.read(file_descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(file_descriptor)
            if (
                len(raw) != before.st_size
                or len(raw) > _MAX_FILE_BYTES
                or (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                )
                != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                )
            ):
                raise ClaimAuditError(f"claim artifact changed while read: {relative}")
            return raw
        finally:
            os.close(file_descriptor)
    except ClaimAuditError:
        raise
    except OSError as exc:
        raise ClaimAuditError(
            f"claim artifact cannot be read without symlinks: {relative}"
        ) from exc
    finally:
        os.close(descriptor)


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or _HEX32.fullmatch(value) is None:
        raise ClaimAuditError(f"{label} must be a lowercase SHA-256")
    return value


def _mapping(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ClaimAuditError(f"{label} must be an object")
    return value


def _sequence(value: object, label: str) -> list[Any]:
    if type(value) is not list:
        raise ClaimAuditError(f"{label} must be an array")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value.strip():
        raise ClaimAuditError(f"{label} must be nonempty text")
    return value


def _load_registry(repository_root: Path) -> tuple[dict[str, dict[str, Any]], int]:
    registry_raw = _read_regular(repository_root, REGISTRY_PATH)
    registry = _strict_json(registry_raw, "proof registry")
    allowed = {"schema_version", "public_items", "internal_records"}
    if set(registry) not in {
        frozenset(allowed),
        frozenset(allowed | {"card_chain_roots"}),
    }:
        raise ClaimAuditError("proof registry schema is not exact")
    if registry.get("schema_version") != 1:
        raise ClaimAuditError("proof registry version differs")

    by_id: dict[str, dict[str, Any]] = {}
    for raw_item in _sequence(registry.get("public_items"), "public proof items"):
        item = _mapping(raw_item, "public proof item")
        proof_id = _text(item.get("proof_id"), "public proof id")
        if proof_id in by_id:
            raise ClaimAuditError("proof registry contains duplicate proof ids")
        if not proof_item_is_green(item):
            raise ClaimAuditError(f"proof registry item is not green: {proof_id}")
        artifact_path = _text(item.get("artifact_path"), f"{proof_id} artifact path")
        artifact_raw = _read_regular(repository_root, artifact_path)
        expected = _sha256(item.get("artifact_sha256"), f"{proof_id} artifact SHA-256")
        if hashlib.sha256(artifact_raw).hexdigest() != expected:
            raise ClaimAuditError(f"{proof_id} artifact digest differs")
        by_id[proof_id] = item
    if not by_id:
        raise ClaimAuditError("proof registry has no public proof items")

    action_ids: set[str] = set()
    internal_records = _sequence(
        registry.get("internal_records"), "internal proof records"
    )
    for raw_record in internal_records:
        record = _mapping(raw_record, "internal proof record")
        action_id = _text(record.get("action_id"), "internal action id")
        if action_id in action_ids:
            raise ClaimAuditError("proof registry contains duplicate action ids")
        action_ids.add(action_id)
        validated = validate_internal_record(record)
        if (
            validated.get("verification_status") != "verified"
            or validated.get("v3_finalized_exact") is not True
        ):
            raise ClaimAuditError("proof registry contains an invalid internal record")

    if "card_chain_roots" in registry:
        roots = _mapping(registry["card_chain_roots"], "card-chain roots binding")
        if set(roots) != {"artifact_path", "artifact_sha256"}:
            raise ClaimAuditError("card-chain roots binding schema differs")
        relative = _text(roots.get("artifact_path"), "card-chain roots path")
        raw = _read_regular(repository_root, relative)
        expected = _sha256(roots.get("artifact_sha256"), "card-chain roots SHA-256")
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ClaimAuditError("card-chain roots digest differs")
    return by_id, len(internal_records)


def _document_inventory(
    root: Path,
) -> tuple[dict[str, str], dict[str, str]]:
    texts: dict[str, str] = {}
    digests: dict[str, str] = {}
    for relative in AUDITED_DOCUMENT_PATHS:
        raw = _read_regular(root, relative)
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ClaimAuditError(f"{relative} is not UTF-8") from exc
        if "\r" in text:
            raise ClaimAuditError(f"{relative} is not LF-normalized")
        texts[relative] = text
        digests[relative] = hashlib.sha256(raw).hexdigest()
    return texts, digests


def _policy_document_inventory(value: object) -> dict[str, str]:
    observed: dict[str, str] = {}
    for raw_document in _sequence(value, "policy audited documents"):
        document = _mapping(raw_document, "policy audited document")
        if set(document) != {"path", "sha256"}:
            raise ClaimAuditError("policy audited document schema is not exact")
        relative = _text(document.get("path"), "policy audited document path")
        if relative in observed:
            raise ClaimAuditError("policy audited document is duplicated")
        observed[relative] = _sha256(
            document.get("sha256"), f"{relative} policy SHA-256"
        )
    if set(observed) != set(AUDITED_DOCUMENT_PATHS):
        raise ClaimAuditError("policy audited document path inventory differs")
    return observed


def _validate_policy_profile(
    value: object,
    *,
    claim_id: str,
    claim_class: str,
) -> dict[str, Any]:
    profile = _mapping(value, f"{claim_id} allowed proof profile")
    if set(profile) != {
        "proof_type",
        "verification_scope",
        "provenance_class",
        "temporal_scope",
        "outcome_kind",
        "required_checks",
    }:
        raise ClaimAuditError(f"{claim_id} allowed proof profile schema is not exact")
    proof_type = _text(profile.get("proof_type"), f"{claim_id} proof type")
    if proof_type not in REQUIRED_CHECKS_BY_PROOF_TYPE:
        raise ClaimAuditError(f"{claim_id} proof type is not frozen in the registry")
    required_checks = [
        _text(item, f"{claim_id} required check")
        for item in _sequence(profile.get("required_checks"), "required checks")
    ]
    if tuple(required_checks) != REQUIRED_CHECKS_BY_PROOF_TYPE[proof_type]:
        raise ClaimAuditError(
            f"{claim_id} required checks differ from the frozen registry set"
        )
    scope = _mapping(profile.get("verification_scope"), "verification scope")
    if set(scope) != {"claim_scope", "enforcement_scope"}:
        raise ClaimAuditError(f"{claim_id} verification scope schema differs")
    _text(scope.get("claim_scope"), f"{claim_id} claim scope")
    _text(scope.get("enforcement_scope"), f"{claim_id} enforcement scope")
    provenance = _mapping(profile.get("provenance_class"), "provenance class")
    if set(provenance) != {"generation", "lineage", "observation_mode"}:
        raise ClaimAuditError(f"{claim_id} provenance class schema differs")
    for key in ("generation", "lineage", "observation_mode"):
        _text(provenance.get(key), f"{claim_id} {key}")
    temporal_scope = _text(profile.get("temporal_scope"), f"{claim_id} temporal scope")
    expected_temporal = "current" if claim_class == "verified_current" else "historical"
    if temporal_scope != expected_temporal:
        raise ClaimAuditError(f"{claim_id} temporal scope differs from its class")
    _text(profile.get("outcome_kind"), f"{claim_id} outcome kind")
    return profile


def _profile_matches(item: Mapping[str, Any], profile: Mapping[str, Any]) -> bool:
    scope = _mapping(profile["verification_scope"], "verification scope")
    provenance = _mapping(profile["provenance_class"], "provenance class")
    expected_checks = set(_sequence(profile["required_checks"], "required checks"))
    actual_checks = {
        check.get("name")
        for check in _sequence(item.get("checks"), "registry checks")
        if type(check) is dict
        and check.get("required") is True
        and check.get("passed") is True
    }
    return (
        item.get("proof_type") == profile.get("proof_type")
        and item.get("verification_status") == "verified"
        and item.get("temporal_scope") == profile.get("temporal_scope")
        and item.get("execution_outcome") == profile.get("outcome_kind")
        and item.get("claim_scope") == scope.get("claim_scope")
        and item.get("enforcement_scope") == scope.get("enforcement_scope")
        and item.get("generation") == provenance.get("generation")
        and item.get("lineage") == provenance.get("lineage")
        and item.get("observation_mode") == provenance.get("observation_mode")
        and actual_checks == expected_checks
    )


def verify_claim_artifacts(repository_root: str | Path) -> dict[str, object]:
    """Verify the independently pinned exhaustive claim policy and exact map."""

    root = Path(repository_root).resolve(strict=True)
    try:
        approved_policy_digest = g11_claim_policy_authority.approved_policy_sha256()
    except ValueError as exc:
        raise ClaimAuditError(str(exc)) from exc
    policy_raw = _read_regular(root, CLAIM_POLICY_PATH)
    if hashlib.sha256(policy_raw).hexdigest() != approved_policy_digest:
        raise ClaimAuditError("G11 claim policy digest is not independently approved")
    policy = _strict_json(policy_raw, "G11 claim policy")
    if set(policy) != {"schema_version", "audited_documents", "claims"}:
        raise ClaimAuditError("G11 claim policy schema is not exact")
    if policy.get("schema_version") != "concordia.g11_claim_policy.v1":
        raise ClaimAuditError("G11 claim policy version differs")

    document_text, document_hashes = _document_inventory(root)
    policy_documents = _policy_document_inventory(policy.get("audited_documents"))
    if policy_documents != document_hashes:
        raise ClaimAuditError("audited document digest differs from approved policy")

    claim_map = _strict_json(
        _read_regular(root, CLAIM_MAP_PATH), "claim-to-artifact map"
    )
    if set(claim_map) != {"schema_version", "audited_documents", "claims"}:
        raise ClaimAuditError("claim-to-artifact map schema is not exact")
    if claim_map.get("schema_version") != "concordia.claim_to_artifact_map.v1":
        raise ClaimAuditError("claim-to-artifact map version differs")
    if claim_map.get("audited_documents") != policy.get("audited_documents"):
        raise ClaimAuditError("claim map document inventory differs from policy")

    policy_claims = _sequence(policy.get("claims"), "policy material claims")
    map_claims = _sequence(claim_map.get("claims"), "mapped material claims")
    if not policy_claims or len(map_claims) != len(policy_claims):
        raise ClaimAuditError("claim map inventory differs from approved policy")

    registry, _ = _load_registry(root)
    seen_claim_ids: set[str] = set()
    mapped_proofs: set[str] = set()
    mapped_documents: set[str] = set()
    artifact_paths: set[str] = set()
    for raw_policy_claim, raw_map_claim in zip(policy_claims, map_claims, strict=True):
        policy_claim = _mapping(raw_policy_claim, "policy material claim")
        if set(policy_claim) != {
            "claim_id",
            "exact_text",
            "sources",
            "claim_class",
            "allowed_proof_profiles",
        }:
            raise ClaimAuditError("policy material claim schema is not exact")
        claim_id = _text(policy_claim.get("claim_id"), "policy claim id")
        if _CLAIM_ID.fullmatch(claim_id) is None or claim_id in seen_claim_ids:
            raise ClaimAuditError("policy claim id is invalid or duplicated")
        seen_claim_ids.add(claim_id)
        exact_text = _text(policy_claim.get("exact_text"), f"{claim_id} exact text")
        claim_class = _text(policy_claim.get("claim_class"), f"{claim_id} claim class")
        if claim_class not in _CLAIM_CLASSES:
            raise ClaimAuditError(f"{claim_id} claim class is not allowed")

        sources = _sequence(policy_claim.get("sources"), f"{claim_id} sources")
        if not sources:
            raise ClaimAuditError(f"{claim_id} has no approved source occurrence")
        seen_sources: set[tuple[str, int]] = set()
        for raw_source in sources:
            source = _mapping(raw_source, f"{claim_id} source")
            if set(source) != {"path", "exact_text", "occurrence"}:
                raise ClaimAuditError(f"{claim_id} source schema is not exact")
            relative = _text(source.get("path"), f"{claim_id} source path")
            source_text = _text(source.get("exact_text"), f"{claim_id} source text")
            occurrence = source.get("occurrence")
            if type(occurrence) is not int or occurrence < 1:
                raise ClaimAuditError(f"{claim_id} source occurrence is invalid")
            source_key = (relative, occurrence)
            if (
                relative not in document_text
                or source_text != exact_text
                or source_key in seen_sources
                or document_text[relative].count(exact_text) < occurrence
            ):
                raise ClaimAuditError(
                    f"{claim_id} approved source occurrence is absent or duplicated"
                )
            seen_sources.add(source_key)
            mapped_documents.add(relative)
        expected_sources = {
            (relative, occurrence)
            for relative, text in document_text.items()
            for occurrence in range(1, text.count(exact_text) + 1)
        }
        if seen_sources != expected_sources:
            raise ClaimAuditError(
                f"{claim_id} source occurrence inventory is not exhaustive"
            )

        raw_profiles = _sequence(
            policy_claim.get("allowed_proof_profiles"),
            f"{claim_id} allowed proof profiles",
        )
        if claim_class in {"limitation", "roadmap"}:
            if raw_profiles:
                raise ClaimAuditError(
                    f"{claim_id} non-verified class cannot imply green proof"
                )
            profiles: list[dict[str, Any]] = []
        else:
            if not raw_profiles:
                raise ClaimAuditError(
                    f"{claim_id} verified class has no allowed proof profile"
                )
            profiles = [
                _validate_policy_profile(
                    profile,
                    claim_id=claim_id,
                    claim_class=claim_class,
                )
                for profile in raw_profiles
            ]
            profile_digests = {
                hashlib.sha256(_canonical_json(profile)).hexdigest()
                for profile in profiles
            }
            if len(profile_digests) != len(profiles):
                raise ClaimAuditError(
                    f"{claim_id} has a duplicate allowed proof profile"
                )

        map_claim = _mapping(raw_map_claim, "mapped material claim")
        if set(map_claim) != {"claim_id", "claim_text", "sources", "artifacts"}:
            raise ClaimAuditError("mapped material claim schema is not exact")
        if (
            map_claim.get("claim_id") != claim_id
            or map_claim.get("claim_text") != exact_text
            or map_claim.get("sources") != sources
        ):
            raise ClaimAuditError(f"{claim_id} map identity differs from policy")

        artifacts = _sequence(map_claim.get("artifacts"), f"{claim_id} artifacts")
        if claim_class in {"limitation", "roadmap"}:
            if artifacts:
                raise ClaimAuditError(
                    f"{claim_id} non-verified class cannot bind green artifacts"
                )
            continue
        if not artifacts:
            raise ClaimAuditError(f"{claim_id} verified claim has no artifact")
        claim_proofs: set[str] = set()
        for raw_artifact in artifacts:
            artifact = _mapping(raw_artifact, f"{claim_id} artifact")
            if set(artifact) != {"proof_id", "path", "sha256"}:
                raise ClaimAuditError(f"{claim_id} artifact schema is not exact")
            proof_id = _text(artifact.get("proof_id"), f"{claim_id} proof id")
            if proof_id in claim_proofs or proof_id not in registry:
                raise ClaimAuditError(
                    f"{claim_id} proof binding is unknown or duplicated"
                )
            claim_proofs.add(proof_id)
            item = registry[proof_id]
            if not any(_profile_matches(item, profile) for profile in profiles):
                raise ClaimAuditError(
                    f"{claim_id} proof is not compatible with approved policy"
                )
            relative = _text(artifact.get("path"), f"{claim_id} artifact path")
            digest = _sha256(artifact.get("sha256"), f"{claim_id} artifact SHA-256")
            if (
                relative != item.get("artifact_path")
                or digest != item.get("artifact_sha256")
                or hashlib.sha256(_read_regular(root, relative)).hexdigest() != digest
            ):
                raise ClaimAuditError(
                    f"{claim_id} artifact binding differs from registry"
                )
            mapped_proofs.add(proof_id)
            artifact_paths.add(relative)

    if mapped_documents != set(AUDITED_DOCUMENT_PATHS):
        raise ClaimAuditError("not every audited document has an approved claim source")
    if mapped_proofs != set(registry):
        raise ClaimAuditError(
            "not every public registry proof supports an approved claim"
        )
    return {
        "artifact_count": len(artifact_paths),
        "claim_count": len(policy_claims),
        "document_count": len(document_text),
        "proof_count": len(registry),
        "status": "verified",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    repository_root = args.repository_root.resolve()
    try:
        if args.verify_only:
            result: Mapping[str, object] = verify_claim_artifacts(repository_root)
        else:
            gate = run_gate("G11", repository_root=repository_root)
            result = {
                "gate_id": gate.gate_id,
                "receipt_path": gate.receipt_path,
                "receipt_sha256": gate.receipt_sha256,
                "status": "verified",
            }
    except (ClaimAuditError, GateRunError, OSError) as exc:
        print(json.dumps({"error": str(exc), "status": "invalid"}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
