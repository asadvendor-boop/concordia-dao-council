"""Canonical public artifact for a fully proven v3 native treasury execution.

The artifact is evidence, not a verdict.  It contains exact typed inputs and
raw observations so independent verifiers can derive checks themselves.  No
caller-supplied ``passed`` or ``verified`` boolean is serialized.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import timedelta, datetime
from typing import Any

from shared.casper_state_proof import (
    CasperStateProofError,
    VerifiedAccountBalance,
    verify_account_balance_at_block,
)
from shared.native_transfer_deploy import (
    NativeTransferDeployError,
    validate_signed_native_transfer_deploy,
)
from shared.native_transfer_finality import (
    NativeTransferFinalityError,
    require_verified_finalized_native_transfer,
    verify_finalized_native_transfer,
)
from shared.native_transfer_scan import (
    NativeTransferScanError,
    require_verified_no_duplicate_native_transfer,
    verify_no_duplicate_native_transfer_transcript,
)
from shared.post_transfer_proof import (
    PostTransferProofError,
    require_verified_post_transfer_balance,
    verify_post_transfer_balance,
)
from shared.treasury_executor import ExecutionState, JournalEntry
from shared.v3_authorization import (
    V3AuthorizationError,
    validate_verified_authorization,
)


SCHEMA_VERSION = "concordia.native_treasury_execution.v1"
ARTIFACT_SHA256_SCOPE = "canonical_json_without_release_manifest"
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_RFC3339_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$"
)
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


class TreasuryExecutionArtifactError(ValueError):
    """The journal entry cannot be represented as verified public evidence."""


def _canonical_json(value: object, label: str) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise TreasuryExecutionArtifactError(f"{label} is not canonical JSON") from exc
    if len(encoded) > _MAX_ARTIFACT_BYTES:
        raise TreasuryExecutionArtifactError(f"{label} exceeds artifact size limit")
    return encoded


def _parse_canonical_json(value: object, label: str) -> Any:
    if type(value) is not str:
        raise TreasuryExecutionArtifactError(f"{label} is missing")
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as exc:
        raise TreasuryExecutionArtifactError(f"{label} is invalid JSON") from exc
    if _canonical_json(decoded, label).decode("ascii") != value:
        raise TreasuryExecutionArtifactError(f"{label} is not canonical JSON")
    return decoded


def _release_value(value: object, label: str) -> str:
    if type(value) is not str or _COMMIT_RE.fullmatch(value) is None:
        raise TreasuryExecutionArtifactError(
            f"{label} must be a lowercase 40-character Git commit"
        )
    return value


def _captured_at(value: object) -> str:
    if type(value) is not str or _RFC3339_UTC_RE.fullmatch(value) is None:
        raise TreasuryExecutionArtifactError("captured_at must be RFC3339 UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise TreasuryExecutionArtifactError("captured_at must be RFC3339 UTC") from exc
    if parsed.utcoffset() != timedelta(0):
        raise TreasuryExecutionArtifactError("captured_at must be RFC3339 UTC")
    return value


def _journal_timestamp(value: object) -> datetime:
    if type(value) is not str or _RFC3339_UTC_RE.fullmatch(value) is None:
        raise TreasuryExecutionArtifactError("journal timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise TreasuryExecutionArtifactError("journal timestamp is invalid") from exc
    if parsed.utcoffset() != timedelta(0):
        raise TreasuryExecutionArtifactError("journal timestamp must be UTC")
    return parsed


_BALANCE_TRANSCRIPT_FIELDS = {
    "status_request",
    "status",
    "block_request",
    "block",
    "balance_request",
    "balance_response",
}


def _reparse_balance_bundle(
    value: object,
    *,
    account_hash: bytes,
    block_hash: bytes,
    block_height: int,
    state_root_hash: bytes,
    expected_balance_motes: int | None = None,
) -> VerifiedAccountBalance:
    if type(value) is not dict or set(value) != _BALANCE_TRANSCRIPT_FIELDS:
        raise TreasuryExecutionArtifactError("balance transcript fields are not exact")
    try:
        return verify_account_balance_at_block(
            chain_status_request=value["status_request"],
            chain_status_payload=value["status"],
            canonical_block_request=value["block_request"],
            canonical_block_payload=value["block"],
            balance_request=value["balance_request"],
            balance_response=value["balance_response"],
            expected_account_hash=account_hash,
            expected_block_hash=block_hash,
            expected_block_height=block_height,
            expected_state_root_hash=state_root_hash,
            expected_balance_motes=expected_balance_motes,
        )
    except CasperStateProofError as exc:
        raise TreasuryExecutionArtifactError("balance transcript is invalid") from exc


def _reparse_emitted_evidence(
    value: JournalEntry,
    *,
    authorization: object,
    finality: object,
    post: object,
    scan: object,
) -> None:
    try:
        node_observations = _parse_canonical_json(
            value.finality_node_observations_json,
            "finality node observations",
        )
        if type(node_observations) is not list or any(
            type(item) is not dict for item in node_observations
        ):
            raise TreasuryExecutionArtifactError(
                "finality node observations must be a list of objects"
            )
        reparsed_finality = verify_finalized_native_transfer(
            requested_deploy_hash=value.deploy_hash,
            node_observations=tuple(node_observations),
            signed_deploy_bytes=value.signed_bytes,
            expected_source_account_hash=authorization.source_account,
            expected_recipient_account_hash=authorization.recipient_account,
            expected_amount_motes=authorization.amount_motes,
            expected_transfer_id=authorization.transfer_id,
            expected_payment_amount_motes=value.payment_amount_motes,
            max_payment_amount_motes=value.payment_amount_motes,
        )
    except (NativeTransferFinalityError, TreasuryExecutionArtifactError) as exc:
        raise TreasuryExecutionArtifactError(
            "emitted finality transcript is invalid"
        ) from exc
    if reparsed_finality != finality:
        raise TreasuryExecutionArtifactError(
            "emitted finality transcript does not match sealed proof"
        )

    balance_bundle = _parse_canonical_json(
        value.post_balance_evidence_json,
        "balance evidence",
    )
    if type(balance_bundle) is not dict or set(balance_bundle) != {
        "pre_source",
        "pre_recipient",
        "post_source",
        "post_recipient",
    }:
        raise TreasuryExecutionArtifactError("balance evidence fields are not exact")
    try:
        pre_source = _reparse_balance_bundle(
            balance_bundle["pre_source"],
            account_hash=authorization.source_account,
            block_hash=authorization.snapshot_block_hash,
            block_height=authorization.snapshot_block_height,
            state_root_hash=authorization.snapshot_state_root_hash,
            expected_balance_motes=authorization.treasury_snapshot_balance_motes,
        )
        pre_recipient = _reparse_balance_bundle(
            balance_bundle["pre_recipient"],
            account_hash=authorization.recipient_account,
            block_hash=authorization.snapshot_block_hash,
            block_height=authorization.snapshot_block_height,
            state_root_hash=authorization.snapshot_state_root_hash,
        )
        finality_block_hash = bytes.fromhex(reparsed_finality.block_hash)
        finality_state_root_hash = bytes.fromhex(reparsed_finality.state_root_hash)
        post_source = _reparse_balance_bundle(
            balance_bundle["post_source"],
            account_hash=authorization.source_account,
            block_hash=finality_block_hash,
            block_height=reparsed_finality.block_height,
            state_root_hash=finality_state_root_hash,
        )
        post_recipient = _reparse_balance_bundle(
            balance_bundle["post_recipient"],
            account_hash=authorization.recipient_account,
            block_hash=finality_block_hash,
            block_height=reparsed_finality.block_height,
            state_root_hash=finality_state_root_hash,
        )
        reparsed_post = verify_post_transfer_balance(
            pre_source_balance=pre_source,
            pre_recipient_balance=pre_recipient,
            post_source_balance=post_source,
            post_recipient_balance=post_recipient,
            finality_proof=reparsed_finality,
            expected_source_account_hash=authorization.source_account,
            expected_recipient_account_hash=authorization.recipient_account,
            expected_amount_motes=authorization.amount_motes,
        )
    except (CasperStateProofError, PostTransferProofError) as exc:
        raise TreasuryExecutionArtifactError(
            "emitted balance transcript is invalid"
        ) from exc
    if reparsed_post != post:
        raise TreasuryExecutionArtifactError(
            "emitted balance transcript does not match sealed proof"
        )

    try:
        reparsed_scan = verify_no_duplicate_native_transfer_transcript(
            value.no_duplicate_scan_json,
            finality_proof=reparsed_finality,
        )
    except NativeTransferScanError as exc:
        raise TreasuryExecutionArtifactError(
            "emitted scan transcript is invalid"
        ) from exc
    if (
        reparsed_scan != scan
        or reparsed_scan.authorization_block_height
        != authorization.finalization_block_height
    ):
        raise TreasuryExecutionArtifactError(
            "emitted scan transcript does not match sealed proof"
        )


def _validate_entry(value: object) -> JournalEntry:
    if type(value) is not JournalEntry:
        raise TreasuryExecutionArtifactError("a parser-validated journal entry is required")
    if value.state is not ExecutionState.PROVEN:
        raise TreasuryExecutionArtifactError("journal entry must be PROVEN")
    if value.broadcast_attempts != 1:
        raise TreasuryExecutionArtifactError(
            "public finals artifact requires exactly one broadcast attempt"
        )
    if (
        value.signed_bytes is None
        or value.signed_bytes_sha256 is None
        or value.deploy_hash is None
        or value.finality_proof is None
        or value.post_transfer_proof is None
        or value.no_duplicate_proof is None
        or value.post_balance_evidence_json is None
        or value.no_duplicate_scan_json is None
        or value.execution_proof_sha256 is None
        or value.finality_node_observations_json is None
    ):
        raise TreasuryExecutionArtifactError("PROVEN journal evidence is incomplete")
    try:
        authorization = validate_verified_authorization(value.authorization)
        finality = require_verified_finalized_native_transfer(value.finality_proof)
        post = require_verified_post_transfer_balance(value.post_transfer_proof)
        scan = require_verified_no_duplicate_native_transfer(value.no_duplicate_proof)
        deploy = validate_signed_native_transfer_deploy(
            value.signed_bytes,
            expected_source_account_hash=authorization.source_account,
            expected_recipient_account_hash=authorization.recipient_account,
            expected_amount_motes=authorization.amount_motes,
            expected_transfer_id=authorization.transfer_id,
            expected_payment_amount_motes=value.payment_amount_motes,
            max_payment_amount_motes=value.payment_amount_motes,
        )
    except (
        V3AuthorizationError,
        NativeTransferDeployError,
        NativeTransferFinalityError,
        PostTransferProofError,
        NativeTransferScanError,
    ) as exc:
        raise TreasuryExecutionArtifactError("journal parser evidence is invalid") from exc
    if (
        hashlib.sha256(value.signed_bytes).hexdigest() != value.signed_bytes_sha256
        or deploy.deploy_hash_hex != value.deploy_hash
        or finality.deploy_hash != value.deploy_hash
        or post.deploy_hash != value.deploy_hash
        or scan.deploy_hash != value.deploy_hash
    ):
        raise TreasuryExecutionArtifactError("journal deploy identity does not match evidence")
    if value.last_detail_code != "execution_proven":
        raise TreasuryExecutionArtifactError(
            "PROVEN journal must carry execution_proven detail code"
        )
    created = _journal_timestamp(value.created_at)
    updated = _journal_timestamp(value.updated_at)
    if updated < created:
        raise TreasuryExecutionArtifactError("updated timestamp precedes created timestamp")
    _reparse_emitted_evidence(
        value,
        authorization=authorization,
        finality=finality,
        post=post,
        scan=scan,
    )
    digest_material = {
        "post_balance_evidence_sha256": hashlib.sha256(
            value.post_balance_evidence_json.encode("ascii")
        ).hexdigest(),
        "no_duplicate_scan_sha256": hashlib.sha256(
            value.no_duplicate_scan_json.encode("ascii")
        ).hexdigest(),
        "deploy_hash": value.deploy_hash,
    }
    expected_execution_digest = hashlib.sha256(
        _canonical_json(digest_material, "execution proof digest")
    ).hexdigest()
    if value.execution_proof_sha256 != expected_execution_digest:
        raise TreasuryExecutionArtifactError("execution proof digest does not match")
    return value


def build_native_treasury_execution_artifact(
    entry: object,
    *,
    source_commit: str,
    deployment_commit: str,
    captured_at: str,
) -> bytes:
    """Serialize one strict ``native_treasury_execution_v1`` artifact."""

    journal = _validate_entry(entry)
    authorization = journal.authorization
    finality = journal.finality_proof
    scan = journal.no_duplicate_proof
    assert finality is not None
    assert scan is not None
    source_commit = _release_value(source_commit, "source_commit")
    deployment_commit = _release_value(deployment_commit, "deployment_commit")
    captured_at = _captured_at(captured_at)

    typed_header = _parse_canonical_json(
        authorization.typed_header_json, "typed header"
    )
    typed_body = _parse_canonical_json(authorization.typed_body_json, "typed body")
    readback = _parse_canonical_json(
        authorization.readback_artifact_json, "v3 readback"
    )
    snapshot = {
        "status_request": _parse_canonical_json(
            authorization.snapshot_status_request_json, "snapshot status request"
        ),
        "status": _parse_canonical_json(
            authorization.snapshot_status_json, "snapshot status"
        ),
        "block_request": _parse_canonical_json(
            authorization.snapshot_block_request_json, "snapshot block request"
        ),
        "block": _parse_canonical_json(
            authorization.snapshot_block_json, "snapshot block"
        ),
        "balance_request": _parse_canonical_json(
            authorization.snapshot_balance_request_json, "snapshot balance request"
        ),
        "balance_response": _parse_canonical_json(
            authorization.snapshot_balance_response_json, "snapshot balance response"
        ),
    }
    finality_evidence = {
        "facts": {
            "deploy_hash": finality.deploy_hash,
            "block_hash": finality.block_hash,
            "block_height": finality.block_height,
            "state_root_hash": finality.state_root_hash,
            "execution_result_kind": finality.execution_result_kind,
            "gas_motes": str(finality.gas_motes),
            "corroboration_count": finality.corroboration_count,
        },
        "node_observations": _parse_canonical_json(
            journal.finality_node_observations_json,
            "finality node observations",
        ),
        "verification_scope": finality.verification_scope,
    }
    balance_evidence = _parse_canonical_json(
        journal.post_balance_evidence_json, "balance evidence"
    )
    scan_transcript = _parse_canonical_json(
        journal.no_duplicate_scan_json, "bounded transfer scan"
    )

    artifact = {
        "schema_version": SCHEMA_VERSION,
        "captured_at": captured_at,
        "source_commit": source_commit,
        "deployment_commit": deployment_commit,
        "release_identity": {
            "network": authorization.network,
            "package_hash": authorization.package_hash.hex(),
            "contract_hash": authorization.contract_hash.hex(),
            "deployment_domain": authorization.deployment_domain.hex(),
            "source_sha256": authorization.source_sha256.hex(),
            "wasm_sha256": authorization.wasm_sha256.hex(),
            "generated_schema_sha256": authorization.schema_sha256.hex(),
        },
        "authorization": {
            "proposal_id": authorization.proposal_id,
            "action_id": authorization.action_id.hex(),
            "envelope_hash": authorization.envelope_hash.hex(),
            "typed_header": typed_header,
            "typed_body": typed_body,
            "header_bytes_hex": authorization.header_bytes.hex(),
            "body_bytes_hex": authorization.body_bytes.hex(),
            "action_core_bytes_hex": authorization.action_core_bytes.hex(),
            "v3_readback": readback,
            "snapshot": snapshot,
        },
        "executor_journal": {
            "state": journal.state.value,
            "signed_deploy_bytes_hex": journal.signed_bytes.hex(),
            "signed_deploy_sha256": journal.signed_bytes_sha256,
            "deploy_hash": journal.deploy_hash,
            "broadcast_attempts": journal.broadcast_attempts,
            "last_detail_code": journal.last_detail_code,
            "payment_amount_motes": str(journal.payment_amount_motes),
            "created_at": journal.created_at,
            "updated_at": journal.updated_at,
            "execution_proof_sha256": journal.execution_proof_sha256,
        },
        "finality": finality_evidence,
        "balance_evidence": balance_evidence,
        "bounded_transfer_scan": {
            "authorization_block_height": scan.authorization_block_height,
            "observed_through_block_height": scan.observed_through_block_height,
            "observed_through_block_hash": scan.observed_through_block_hash,
            "scanned_block_count": scan.scanned_block_count,
            "matched_transfer_count": scan.matched_transfer_count,
            "transcript": scan_transcript,
        },
        "artifact_sha256_scope": ARTIFACT_SHA256_SCOPE,
    }
    return _canonical_json(artifact, "native treasury execution artifact")


__all__ = [
    "ARTIFACT_SHA256_SCOPE",
    "SCHEMA_VERSION",
    "TreasuryExecutionArtifactError",
    "build_native_treasury_execution_artifact",
]
