"""Fail-closed provenance registry for Concordia proof artifacts.

The registry deliberately keeps provenance, observation, verification, and
execution outcome as independent dimensions.  In particular, no convenience
boolean from an artifact can make an item verified or green.
"""
from __future__ import annotations

import copy
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REQUIRED_CHECKS_BY_PROOF_TYPE: dict[str, tuple[str, ...]] = {
    "historical_odra_receipt_v2": (
        "artifact_hash_recomputed",
        "historical_card_chain_recomputed",
        "deploy_processed_without_execution_error",
        "receipt_arguments_match_historical_artifact",
        "package_and_contract_match_historical_manifest",
        "historical_lineage_matches_frozen_inventory",
    ),
    "exact_envelope_v3": (
        "source_tree_sha256_matches_release_manifest",
        "wasm_sha256_matches_release_manifest",
        "generated_schema_sha256_matches_release_manifest",
        "envelope_hash_recomputed_from_typed_fields",
        "proposal_commitment_matches_envelope_hash",
        "signer_set_and_threshold_match_deployment",
        "pre_quorum_finalize_reverted_with_code_8",
        "post_quorum_mutated_envelope_reverted_with_code_10",
        "exact_envelope_finalization_accepted",
        "repeat_finalization_reverted_with_code_12",
        "finalization_deploy_processed_without_execution_error",
        "contract_readback_marks_proposal_finalized",
        "contract_readback_marks_action_authorized",
        "package_contract_and_deployment_domain_match_manifest",
    ),
    "native_treasury_execution_v1": (
        "exact_envelope_v3_verified",
        "executor_journal_signed_bytes_hash_matches",
        "single_broadcast_or_reconciled_by_deploy_hash",
        "snapshot_block_hash_height_and_state_root_observed_from_casper_rpc",
        "source_balance_observed_at_snapshot_root_equals_treasury_snapshot_balance_motes",
        "snapshot_precedes_v3_finalization_and_native_execution",
        "transfer_source_exact",
        "transfer_recipient_exact",
        "transfer_amount_exact",
        "transfer_id_exact",
        "successful_inclusion_observed_by_two_named_casper_rpc_nodes",
        "post_execution_source_and_recipient_balances_observed",
        "no_second_native_transaction_observed_through_block",
    ),
    "safepay_v2": (
        "quote_hash_recomputed",
        "issued_quote_row_matches_and_survives_restart",
        "per_quote_correlation_id_recomputed_and_equals_native_transfer_id",
        "payment_deploy_finalized_without_execution_error",
        "single_native_transfer_exact",
        "payee_amount_and_transfer_id_exact",
        "proposal_resource_and_correlation_exact",
        "report_hash_recomputed_and_matches_quote",
        "provider_consumption_row_matches_payment_and_binding",
        "exact_retry_returned_same_fulfillment_hash_without_second_consumption",
        "cross_binding_reuse_returned_terminal_409",
    ),
    "official_x402_settlement_v1": (
        "exact_envelope_v3_verified_for_registry_record_returned_by_signed_payload_hash",
        "resource_object_equals_configured_resource",
        "accepted_equals_current_payment_requirements",
        "payment_requirements_argument_equals_accepted",
        "eip712_signature_verified",
        "public_key_account_hash_equals_payer",
        "authorization_equals_envelope_payer_payee_value_nonce_and_window",
        "resource_url_hash_matches_envelope",
        "report_hash_matches_envelope",
        "payment_requirements_hash_matches_envelope",
        "signed_payment_payload_hash_matches_envelope",
        "active_wcspr_v8_pre_verify_drift_guard_passed",
        "facilitator_verify_returned_is_valid_true",
        "active_wcspr_v8_pre_settle_drift_guard_passed",
        "facilitator_settlement_response_success_true",
        "settlement_transaction_finalized_without_execution_error",
        "active_wcspr_v8_post_settle_target_and_args_readback_passed",
        "fulfillment_authorization_nonce_unique_binding_matches",
        "fulfillment_restart_reconciliation_passed",
        "exact_retry_returned_stored_fulfillment_without_second_settlement",
        "cross_binding_or_authorization_reuse_returned_terminal_409_before_submission",
        "protected_report_released_only_after_finalized_state",
    ),
    "approval_boundary_v1": (
        "caddy_basic_auth_observed",
        "proxy_secret_header_overwritten_by_caddy",
        "gateway_bcrypt_check_passed",
        "approver_allowlist_check_passed",
        "csrf_check_passed",
        "nonce_consumed_exactly_once",
        "trusted_human_message_origin_matches_approval_boundary",
    ),
    "demo_capability_v1": (
        "capability_signature_valid",
        "scenario_and_client_binding_exact",
        "capability_unexpired_at_first_consumption",
        "capability_consumed_atomically",
        "demo_run_provenance_present_on_all_created_records",
        "cleanup_scope_exact_demo_run_id",
        "canonical_ids_excluded_from_cleanup",
    ),
    "room_identity_v1": (
        "sender_identity_derived_from_authenticated_key",
        "sender_role_derived_from_authenticated_key",
        "agent_sender_type_is_agent",
        "room_membership_enforced",
        "role_operation_matrix_enforced",
        "gateway_secret_fallback_not_used",
    ),
    "snapshot": (
        "artifact_sha256_recomputed",
        "capture_time_present",
        "source_https_url_present",
        "staleness_check_passed",
    ),
}


class AmbiguousGovernanceBinding(Exception):
    pass


class RegistryNotFound(Exception):
    pass


_PROOF_TYPES = frozenset(REQUIRED_CHECKS_BY_PROOF_TYPE)
_GENERATIONS = frozenset({"v1", "v2", "v3", "none"})
_LINEAGES = frozenset({"canonical", "supplemental"})
_OBSERVATION_MODES = frozenset({"live", "snapshot", "unavailable"})
_TEMPORAL_SCOPES = frozenset({"current", "historical"})
_VERIFICATION_STATUSES = frozenset({"verified", "pending", "stale", "unavailable", "invalid"})
_EXECUTION_OUTCOMES = frozenset(
    {
        "accepted",
        "expected_rejection",
        "not_applicable",
        "unexpected_rejection",
        "not_attempted",
        "unknown",
    }
)
_GREEN_OUTCOMES = frozenset({"accepted", "expected_rejection", "not_applicable"})

# A proof type is not merely a label for a checklist.  Its provenance fields
# define the exact claim that the checklist is allowed to support.  Keeping
# this mapping explicit prevents a current v3 proof from being relabelled as
# canonical/historical (or vice versa) while retaining a green status.
_PROVENANCE_BY_PROOF_TYPE: dict[str, dict[str, frozenset[str]]] = {
    "historical_odra_receipt_v2": {
        "generation": frozenset({"v1", "v2"}),
        "lineage": frozenset({"canonical", "supplemental"}),
        "observation_mode": frozenset({"live", "snapshot"}),
        "temporal_scope": frozenset({"historical"}),
        "execution_outcome": frozenset({"accepted", "expected_rejection"}),
    },
    "exact_envelope_v3": {
        "generation": frozenset({"v3"}),
        "lineage": frozenset({"supplemental"}),
        "observation_mode": frozenset({"live", "snapshot"}),
        "temporal_scope": frozenset({"current"}),
        "execution_outcome": frozenset({"accepted"}),
    },
    "native_treasury_execution_v1": {
        "generation": frozenset({"v3"}),
        "lineage": frozenset({"supplemental"}),
        "observation_mode": frozenset({"live", "snapshot"}),
        "temporal_scope": frozenset({"current"}),
        "execution_outcome": frozenset({"accepted"}),
    },
    "safepay_v2": {
        "generation": frozenset({"v2"}),
        "lineage": frozenset({"supplemental"}),
        "observation_mode": frozenset({"live", "snapshot"}),
        "temporal_scope": frozenset({"current"}),
        "execution_outcome": frozenset({"accepted"}),
    },
    "official_x402_settlement_v1": {
        "generation": frozenset({"v3"}),
        "lineage": frozenset({"supplemental"}),
        "observation_mode": frozenset({"live", "snapshot"}),
        "temporal_scope": frozenset({"current"}),
        "execution_outcome": frozenset({"accepted"}),
    },
    "approval_boundary_v1": {
        "generation": frozenset({"v1"}),
        "lineage": frozenset({"supplemental"}),
        "observation_mode": frozenset({"live", "snapshot"}),
        "temporal_scope": frozenset({"current"}),
        "execution_outcome": frozenset({"accepted"}),
    },
    "demo_capability_v1": {
        "generation": frozenset({"v1"}),
        "lineage": frozenset({"supplemental"}),
        "observation_mode": frozenset({"live", "snapshot"}),
        "temporal_scope": frozenset({"current"}),
        "execution_outcome": frozenset({"accepted"}),
    },
    "room_identity_v1": {
        "generation": frozenset({"v1"}),
        "lineage": frozenset({"supplemental"}),
        "observation_mode": frozenset({"live", "snapshot"}),
        "temporal_scope": frozenset({"current"}),
        "execution_outcome": frozenset({"accepted"}),
    },
    "snapshot": {
        "generation": frozenset({"none"}),
        "lineage": frozenset({"supplemental"}),
        "observation_mode": frozenset({"snapshot"}),
        "temporal_scope": frozenset({"current", "historical"}),
        "execution_outcome": frozenset({"not_applicable"}),
    },
}
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_PROPOSAL_RE = re.compile(r"^[A-Z0-9-]{1,64}$")
_IDENTIFIER_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
_CHECK_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
_RFC3339_UTC_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)

PUBLIC_ITEM_REQUIRED_FIELDS = (
    "proof_id",
    "proof_type",
    "generation",
    "lineage",
    "observation_mode",
    "temporal_scope",
    "verification_status",
    "execution_outcome",
    "claim_scope",
    "enforcement_scope",
    "proposal_id",
    "action_id",
    "envelope_hash",
    "artifact_path",
    "artifact_sha256",
    "source_commit",
    "deployment_commit",
    "network",
    "package_hash",
    "contract_hash",
    "deployment_domain",
    "schema_version",
    "captured_at",
    "payment_requirements_hash",
    "signed_payment_payload_hash",
    "report_hash",
    "settlement_transaction",
    "checks",
    "links",
)

INTERNAL_REQUIRED_FIELDS = (
    "schema_version",
    "proposal_id",
    "proposal_hash",
    "proposal_nonce",
    "action_id",
    "action_kind",
    "action_version",
    "envelope_hash",
    "deployment_domain",
    "network",
    "package_hash",
    "contract_hash",
    "v3_finalized_exact",
    "finalization_transaction",
    "finalized_at",
    "resource_url_hash",
    "report_hash",
    "payment_requirements_hash",
    "signed_payment_payload_hash",
    "verification_status",
    "observed_at",
    "checks",
)


def _is_hex32(value: Any) -> bool:
    return isinstance(value, str) and _HEX32_RE.fullmatch(value) is not None


def _parse_rfc3339_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or _RFC3339_UTC_RE.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        return None
    return parsed


def _is_rfc3339_utc(value: Any) -> bool:
    return _parse_rfc3339_utc(value) is not None


def _safe_repository_path(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and value
        and "://" not in value
        and not Path(value).is_absolute()
        and ".." not in Path(value).parts
        and "\\" not in value
    )


def _safe_check_source(value: Any) -> bool:
    return isinstance(value, str) and (
        value.startswith("https://") or _safe_repository_path(value)
    )


def _safe_link_href(value: Any) -> bool:
    return isinstance(value, str) and bool(
        value.startswith("https://") or (value.startswith("/") and not value.startswith("//"))
    )


def _check_errors(checks: Any, required_names: tuple[str, ...]) -> list[str]:
    if not isinstance(checks, list):
        return ["checks_not_array"]
    errors: list[str] = []
    names: list[str] = []
    for check in checks:
        if not isinstance(check, dict):
            errors.append("check_not_object")
            continue
        required_fields = {"name", "required", "passed", "source", "observed_at"}
        if not required_fields <= set(check):
            errors.append("check_fields_missing")
            continue
        if set(check) - (required_fields | {"detail_code"}):
            errors.append("check_unknown_fields")
        name = check.get("name")
        if not isinstance(name, str) or _CHECK_NAME_RE.fullmatch(name) is None:
            errors.append("check_name_invalid")
            continue
        names.append(name)
        if not isinstance(check.get("required"), bool) or not isinstance(check.get("passed"), bool):
            errors.append("check_boolean_invalid")
        if not _safe_check_source(check.get("source")):
            errors.append("check_source_invalid")
        if not _is_rfc3339_utc(check.get("observed_at")):
            errors.append("check_observed_at_invalid")
    if len(names) != len(set(names)):
        errors.append("duplicate_check_name")
    by_name = {check.get("name"): check for check in checks if isinstance(check, dict)}
    for name in required_names:
        check = by_name.get(name)
        if check is None:
            errors.append(f"required_check_missing:{name}")
        elif check.get("required") is not True:
            errors.append(f"required_check_demoted:{name}")
    return errors


def _public_item_errors(item: Any) -> list[str]:
    if not isinstance(item, dict):
        return ["item_not_object"]
    errors: list[str] = []
    for field in PUBLIC_ITEM_REQUIRED_FIELDS:
        if field not in item:
            errors.append(f"field_missing:{field}")
    proof_type = item.get("proof_type")
    if proof_type not in _PROOF_TYPES:
        errors.append("proof_type_invalid")
        required_checks: tuple[str, ...] = ()
    else:
        required_checks = REQUIRED_CHECKS_BY_PROOF_TYPE[proof_type]
    if not isinstance(item.get("proof_id"), str) or _IDENTIFIER_RE.fullmatch(item.get("proof_id", "")) is None:
        errors.append("proof_id_invalid")
    proposal_id = item.get("proposal_id")
    if proposal_id is not None and (
        not isinstance(proposal_id, str) or _PROPOSAL_RE.fullmatch(proposal_id) is None
    ):
        errors.append("proposal_id_invalid")
    for field, allowed in (
        ("generation", _GENERATIONS),
        ("lineage", _LINEAGES),
        ("observation_mode", _OBSERVATION_MODES),
        ("temporal_scope", _TEMPORAL_SCOPES),
        ("verification_status", _VERIFICATION_STATUSES),
        ("execution_outcome", _EXECUTION_OUTCOMES),
    ):
        if item.get(field) not in allowed:
            errors.append(f"{field}_invalid")
    provenance = _PROVENANCE_BY_PROOF_TYPE.get(proof_type)
    if provenance is not None:
        for field, allowed in provenance.items():
            if item.get(field) not in allowed:
                errors.append(f"provenance_invalid:{field}")
    for field in ("claim_scope", "enforcement_scope"):
        if not isinstance(item.get(field), str) or not item[field].strip():
            errors.append(f"{field}_invalid")
    artifact_path = item.get("artifact_path")
    if artifact_path is not None and not _safe_repository_path(artifact_path):
        errors.append("artifact_path_invalid")
    for field in (
        "action_id",
        "envelope_hash",
        "artifact_sha256",
        "package_hash",
        "contract_hash",
        "deployment_domain",
        "payment_requirements_hash",
        "signed_payment_payload_hash",
        "report_hash",
        "settlement_transaction",
    ):
        if item.get(field) is not None and not _is_hex32(item[field]):
            errors.append(f"{field}_invalid")
    for field in ("source_commit", "deployment_commit"):
        value = item.get(field)
        if value is not None and (not isinstance(value, str) or _GIT_SHA_RE.fullmatch(value) is None):
            errors.append(f"{field}_invalid")
    if item.get("captured_at") is not None and not _is_rfc3339_utc(item["captured_at"]):
        errors.append("captured_at_invalid")
    errors.extend(_check_errors(item.get("checks"), required_checks))
    captured_at = _parse_rfc3339_utc(item.get("captured_at"))
    if captured_at is not None and isinstance(item.get("checks"), list):
        for check in item["checks"]:
            if not isinstance(check, dict):
                continue
            observed_at = _parse_rfc3339_utc(check.get("observed_at"))
            if observed_at is not None and observed_at > captured_at:
                errors.append("check_observed_after_capture")
    if not isinstance(item.get("links"), list):
        errors.append("links_not_array")
    else:
        for link in item["links"]:
            if not isinstance(link, dict) or set(link) != {"rel", "label", "href", "kind"}:
                errors.append("link_invalid")
                continue
            if link.get("kind") not in {"artifact", "chain", "source", "ui", "download"}:
                errors.append("link_kind_invalid")
            if not _safe_link_href(link.get("href")):
                errors.append("link_href_invalid")
    if item.get("verification_status") == "verified":
        for field in ("artifact_path", "artifact_sha256", "source_commit", "schema_version", "captured_at"):
            if item.get(field) is None:
                errors.append(f"verified_field_missing:{field}")
        if item.get("observation_mode") == "live" and item.get("temporal_scope") == "current":
            if item.get("deployment_commit") is None:
                errors.append("verified_live_deployment_commit_missing")
        if proof_type in {
            "exact_envelope_v3",
            "native_treasury_execution_v1",
            "official_x402_settlement_v1",
        }:
            for field in (
                "proposal_id",
                "action_id",
                "envelope_hash",
                "network",
                "package_hash",
                "contract_hash",
                "deployment_domain",
            ):
                if item.get(field) is None:
                    errors.append(f"execution_identity_missing:{field}")
        if proof_type == "official_x402_settlement_v1":
            for field in (
                "payment_requirements_hash",
                "signed_payment_payload_hash",
                "report_hash",
                "settlement_transaction",
            ):
                if item.get(field) is None:
                    errors.append(f"x402_identity_missing:{field}")
    if proof_type == "snapshot" and item.get("captured_at") is None:
        errors.append("snapshot_capture_missing")
    return errors


def proof_item_is_green(item: dict[str, Any]) -> bool:
    if _public_item_errors(item):
        return False
    if item.get("verification_status") != "verified":
        return False
    if item.get("observation_mode") == "unavailable":
        return False
    if item.get("execution_outcome") not in _GREEN_OUTCOMES:
        return False
    return _required_checks_pass(item)


def _required_checks_pass(item: dict[str, Any]) -> bool:
    proof_type = item.get("proof_type")
    if proof_type not in REQUIRED_CHECKS_BY_PROOF_TYPE:
        return False
    checks = item.get("checks")
    if not isinstance(checks, list):
        return False
    checks = item["checks"]
    by_name = {
        check.get("name"): check
        for check in checks
        if isinstance(check, dict) and isinstance(check.get("name"), str)
    }
    required_names = REQUIRED_CHECKS_BY_PROOF_TYPE[proof_type]
    if any(
        by_name.get(name, {}).get("required") is not True
        or by_name.get(name, {}).get("passed") is not True
        for name in required_names
    ):
        return False
    return all(
        check.get("passed") is True
        for check in checks
        if isinstance(check, dict) and check.get("required") is True
    )


def normalize_proof_item(item: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(item)
    errors = _public_item_errors(normalized)
    if errors or (
        normalized.get("verification_status") == "verified"
        and not _required_checks_pass(normalized)
    ):
        normalized["verification_status"] = "invalid"
    return normalized


def build_public_registry(
    proposal_id: str,
    items: list[dict[str, Any]],
    *,
    generated_at: str | None = None,
    reference_time: str | None = None,
) -> dict[str, Any]:
    if _PROPOSAL_RE.fullmatch(proposal_id) is None:
        raise ValueError("invalid proposal_id")
    now = datetime.now(UTC)
    if generated_at is None:
        generated_at = now.isoformat().replace("+00:00", "Z")
    generated_time = _parse_rfc3339_utc(generated_at)
    if generated_time is None:
        raise ValueError("generated_at must be RFC3339 UTC")
    if reference_time is None:
        reference_time = now.isoformat().replace("+00:00", "Z")
    reference = _parse_rfc3339_utc(reference_time)
    if reference is None:
        raise ValueError("reference_time must be RFC3339 UTC")
    if generated_time > reference:
        raise ValueError("generated_at cannot be after reference_time")
    proof_ids = [
        item.get("proof_id")
        for item in items
        if isinstance(item, dict) and isinstance(item.get("proof_id"), str)
    ]
    if len(proof_ids) != len(set(proof_ids)):
        raise ValueError("duplicate proof_id")
    normalized = [normalize_proof_item(item) for item in items]
    for item in normalized:
        if item.get("proposal_id") not in {None, proposal_id}:
            item["verification_status"] = "invalid"
        captured_at = _parse_rfc3339_utc(item.get("captured_at"))
        if captured_at is not None and captured_at > generated_time:
            item["verification_status"] = "invalid"
    return {
        "schema_version": 1,
        "generated_at": generated_at,
        "proposal_id": proposal_id,
        "items": normalized,
    }


def _internal_record_errors(record: Any) -> list[str]:
    if not isinstance(record, dict):
        return ["record_not_object"]
    errors: list[str] = []
    unknown_fields = set(record) - set(INTERNAL_REQUIRED_FIELDS)
    if unknown_fields:
        errors.append("unknown_fields")
    for field in INTERNAL_REQUIRED_FIELDS:
        if field not in record:
            errors.append(f"field_missing:{field}")
    if record.get("schema_version") != 1:
        errors.append("schema_version_invalid")
    if not isinstance(record.get("proposal_id"), str) or _PROPOSAL_RE.fullmatch(record.get("proposal_id", "")) is None:
        errors.append("proposal_id_invalid")
    for field in (
        "proposal_hash",
        "proposal_nonce",
        "action_id",
        "envelope_hash",
        "deployment_domain",
        "package_hash",
        "contract_hash",
    ):
        if not _is_hex32(record.get(field)):
            errors.append(f"{field}_invalid")
    for field in (
        "finalization_transaction",
        "resource_url_hash",
        "report_hash",
        "payment_requirements_hash",
        "signed_payment_payload_hash",
    ):
        if record.get(field) is not None and not _is_hex32(record[field]):
            errors.append(f"{field}_invalid")
    if record.get("action_kind") not in {"NativeTransferV1", "OfficialX402SettlementV1"}:
        errors.append("action_kind_invalid")
    if not isinstance(record.get("action_version"), int) or isinstance(record.get("action_version"), bool):
        errors.append("action_version_invalid")
    if record.get("network") != "casper:casper-test":
        errors.append("network_invalid")
    if record.get("verification_status") not in _VERIFICATION_STATUSES:
        errors.append("verification_status_invalid")
    if not _is_rfc3339_utc(record.get("observed_at")):
        errors.append("observed_at_invalid")
    if record.get("finalized_at") is not None and not _is_rfc3339_utc(record["finalized_at"]):
        errors.append("finalized_at_invalid")
    errors.extend(_check_errors(record.get("checks"), REQUIRED_CHECKS_BY_PROOF_TYPE["exact_envelope_v3"]))
    if record.get("action_kind") == "OfficialX402SettlementV1":
        for field in (
            "resource_url_hash",
            "report_hash",
            "payment_requirements_hash",
            "signed_payment_payload_hash",
        ):
            if record.get(field) is None:
                errors.append(f"x402_field_missing:{field}")
    elif record.get("action_kind") == "NativeTransferV1":
        for field in (
            "resource_url_hash",
            "report_hash",
            "payment_requirements_hash",
            "signed_payment_payload_hash",
        ):
            if record.get(field) is not None:
                errors.append(f"native_x402_field_present:{field}")
    return errors


def validate_internal_record(record: dict[str, Any]) -> dict[str, Any]:
    validated = copy.deepcopy(record)
    errors = _internal_record_errors(validated)
    checks = validated.get("checks") if isinstance(validated.get("checks"), list) else []
    required_names = REQUIRED_CHECKS_BY_PROOF_TYPE["exact_envelope_v3"]
    by_name = {
        check.get("name"): check
        for check in checks
        if isinstance(check, dict) and isinstance(check.get("name"), str)
    }
    all_required_pass = not errors and all(
        by_name.get(name, {}).get("required") is True and by_name.get(name, {}).get("passed") is True
        for name in required_names
    ) and all(
        check.get("passed") is True
        for check in checks
        if isinstance(check, dict) and check.get("required") is True
    )
    verified = validated.get("verification_status") == "verified" and all_required_pass
    if errors or (validated.get("verification_status") == "verified" and not all_required_pass):
        validated["verification_status"] = "invalid"
    validated["v3_finalized_exact"] = bool(
        verified
        and validated.get("finalization_transaction")
        and validated.get("finalized_at")
    )
    return validated


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strict_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError(f"proof registry artifact too large: {path.name}")
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(value, dict):
        raise ValueError(f"proof registry artifact must be an object: {path.name}")
    required_fields = {"schema_version", "public_items", "internal_records"}
    if set(value) not in {frozenset(required_fields), frozenset(required_fields | {"card_chain_roots"})}:
        raise ValueError(f"proof registry artifact has unknown or missing fields: {path.name}")
    if value["schema_version"] != 1:
        raise ValueError(f"proof registry artifact schema mismatch: {path.name}")
    if not isinstance(value["public_items"], list) or not isinstance(value["internal_records"], list):
        raise ValueError(f"proof registry artifact arrays invalid: {path.name}")
    if "card_chain_roots" in value:
        roots = value["card_chain_roots"]
        if (
            not isinstance(roots, dict)
            or set(roots) != {"artifact_path", "artifact_sha256"}
            or roots.get("artifact_path")
            != "artifacts/live/card-chain-roots-v1.json"
            or not _is_hex32(roots.get("artifact_sha256"))
        ):
            raise ValueError(
                f"proof registry card-chain roots identity invalid: {path.name}"
            )
    return value


class ProofRegistryRepository:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    def _documents(self) -> list[dict[str, Any]]:
        if not self.root.exists():
            return []
        if not self.root.is_dir():
            raise ValueError("proof registry root must be a directory")
        return [_strict_json(path) for path in sorted(self.root.glob("*.json"))]

    def _public_items(self) -> list[dict[str, Any]]:
        return [item for document in self._documents() for item in document["public_items"]]

    def _internal_records(self) -> list[dict[str, Any]]:
        return [record for document in self._documents() for record in document["internal_records"]]

    def has_public_proposal(self, proposal_id: str) -> bool:
        return any(item.get("proposal_id") == proposal_id for item in self._public_items() if isinstance(item, dict))

    def public_document(
        self,
        proposal_id: str,
        *,
        known: bool,
        generated_at: str | None = None,
    ) -> dict[str, Any]:
        items = [
            item
            for item in self._public_items()
            if isinstance(item, dict) and item.get("proposal_id") == proposal_id
        ]
        if not known and not items:
            raise RegistryNotFound(proposal_id)
        return build_public_registry(proposal_id, items, generated_at=generated_at)

    def unique_green_public_item(
        self,
        proposal_id: str,
        proof_type: str,
        *,
        temporal_scope: str | None = None,
        artifact_path: str | None = None,
    ) -> dict[str, Any] | None:
        document = self.public_document(proposal_id, known=True)
        matches = [
            item
            for item in document["items"]
            if item.get("proof_type") == proof_type
            and (
                temporal_scope is None
                or item.get("temporal_scope") == temporal_scope
            )
            and (
                artifact_path is None
                or item.get("artifact_path") == artifact_path
            )
            and proof_item_is_green(item)
        ]
        if len(matches) != 1:
            return None
        return copy.deepcopy(matches[0])

    def by_action_id(self, value: str) -> dict[str, Any]:
        if not _is_hex32(value):
            raise RegistryNotFound(value)
        matches = [
            validate_internal_record(record)
            for record in self._internal_records()
            if isinstance(record, dict) and record.get("action_id") == value
        ]
        if not matches:
            raise RegistryNotFound(value)
        if len(matches) > 1:
            raise AmbiguousGovernanceBinding(value)
        return matches[0]

    def by_signed_payment_payload_hash(self, value: str) -> dict[str, Any]:
        if not _is_hex32(value):
            raise RegistryNotFound(value)
        matches = []
        for record in self._internal_records():
            if not isinstance(record, dict):
                continue
            if record.get("action_kind") != "OfficialX402SettlementV1":
                continue
            if record.get("signed_payment_payload_hash") != value:
                continue
            validated = validate_internal_record(record)
            if validated.get("verification_status") == "verified" and validated.get("v3_finalized_exact") is True:
                matches.append(validated)
        if not matches:
            raise RegistryNotFound(value)
        if len(matches) > 1:
            raise AmbiguousGovernanceBinding(value)
        return matches[0]
