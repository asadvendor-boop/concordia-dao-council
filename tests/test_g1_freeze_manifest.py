from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HANDOFF = ROOT / "handoff"
MANIFEST_PATH = HANDOFF / "G1_FREEZE_MANIFEST.json"
SPEC_PATH = HANDOFF / "G1_INTERFACE_SPEC.md"
CROSS_LANE_PATH = HANDOFF / "G1_CROSS_LANE_SCHEMAS.json"
READBACK_PATH = HANDOFF / "WCSPR_FACILITATOR_READBACK.json"
ODRA_HASHES_PATH = HANDOFF / "HISTORICAL_ODRA_SHA256.txt"
LIVE_HASHES_PATH = HANDOFF / "HISTORICAL_LIVE_ARTIFACTS_SHA256.txt"
GENERATOR_PATH = ROOT / "scripts" / "generate_g1_vectors.py"
G0R_EVIDENCE_PATH = HANDOFF / "G0R_FALLBACK_EVIDENCE.json"
G0R_RUNBOOK_PATH = HANDOFF / "G0R_RESTORE_RUNBOOK.md"

BASELINE_COMMIT = "b79b42c974daa6ba4b8d904573f6c321ecef1a98"
BASELINE_TREE = "c82655a79882ab3fcd596e388b07aebfd0bc1701"
TAG = "concordia-g1-freeze-v2.0-a"

HEADER_FIELDS = [
    "schema_version:u32:injected",
    "deployment_domain:Bytes32:injected",
    "casper_chain_name:String:injected",
    "proposal_id:String",
    "proposal_nonce:Bytes32",
    "decision_code:u8",
    "requested_allocation_bps:u32",
    "approved_allocation_bps:u32",
    "action_kind:u8",
    "action_version:u32",
    "action_id:Bytes32",
    "proposal_hash:Bytes32",
    "policy_hash:Bytes32",
    "plan_hash:Bytes32",
    "final_card_hash:Bytes32",
    "dissent_hash:Bytes32",
    "agent_action_hash:Bytes32",
    "preauth_evidence_root:Bytes32",
    "authorized_metadata_root:Bytes32",
]

NATIVE_BODY = [
    "asset_kind:u8",
    "source_account:AccountHash",
    "recipient_account:AccountHash",
    "amount_motes:U512",
    "treasury_snapshot_balance_motes:U512",
    "snapshot_block_hash:Bytes32",
    "snapshot_block_height:u64",
    "transfer_id:u64",
    "action_nonce:Bytes32",
    "execution_target:String",
    "execution_version:u32",
]

NATIVE_CORE = [
    "asset_kind",
    "source_account",
    "recipient_account",
    "amount_motes",
    "treasury_snapshot_balance_motes",
    "snapshot_block_hash",
    "snapshot_block_height",
    "execution_target",
    "execution_version",
]

X402_BODY = [
    "x402_version:u32",
    "scheme:String",
    "caip2_network:String",
    "wcspr_package:Bytes32",
    "wcspr_contract:Bytes32",
    "token_name:String",
    "token_symbol:String",
    "eip712_domain_version:String",
    "token_decimals:u8",
    "payer:AccountHash",
    "payee:AccountHash",
    "value:U256",
    "resource_url_hash:Bytes32",
    "report_hash:Bytes32",
    "payment_requirements_hash:Bytes32",
    "signed_payment_payload_hash:Bytes32",
    "eip712_auth_nonce:Bytes32",
    "valid_after:u64",
    "valid_before:u64",
    "action_nonce:Bytes32",
    "settlement_target:String",
    "settlement_version:u32",
]

X402_CORE = [field.split(":", 1)[0] for field in X402_BODY if not field.startswith("action_nonce:")]

FINALIZER_HEADER_ARGS = [
    "proposal_id:String",
    "proposal_nonce:ByteArray(32)",
    "decision_code:U8",
    "requested_allocation_bps:U32",
    "approved_allocation_bps:U32",
    "action_kind:U8",
    "action_version:U32",
    "action_id:ByteArray(32)",
    "proposal_hash:ByteArray(32)",
    "policy_hash:ByteArray(32)",
    "plan_hash:ByteArray(32)",
    "final_card_hash:ByteArray(32)",
    "dissent_hash:ByteArray(32)",
    "agent_action_hash:ByteArray(32)",
    "preauth_evidence_root:ByteArray(32)",
    "authorized_metadata_root:ByteArray(32)",
]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strict_json_loads(value: str | bytes) -> object:
    return json.loads(value, object_pairs_hook=_reject_duplicate_json_keys)


def _json(path: Path) -> dict:
    value = _strict_json_loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict), path
    return value


def _manifest() -> dict:
    return _json(MANIFEST_PATH)


def _cross_lane() -> dict:
    return _json(CROSS_LANE_PATH)


def _inventory_entries(path: Path) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        expected, relative = line.split(maxsplit=1)
        result.append((expected, relative))
    return result


def test_g1_manifest_is_ready_and_binds_every_normative_artifact() -> None:
    manifest = _manifest()
    authority = manifest["authority"]
    assert manifest["status"] == "ready"
    assert manifest["tag"] == TAG
    assert manifest["baseline"] == {
        "commit": BASELINE_COMMIT,
        "tree": BASELINE_TREE,
        "branch": "main",
        "origin_matches": True,
    }
    assert authority["normative_spec_sha256"] == _sha256(SPEC_PATH)
    for key, path in (
        ("cross_lane_schema", CROSS_LANE_PATH),
        ("wcspr_facilitator_readback", READBACK_PATH),
        ("historical_odra_inventory", ODRA_HASHES_PATH),
        ("historical_live_artifact_inventory", LIVE_HASHES_PATH),
        ("golden_vector_generator", GENERATOR_PATH),
        ("g0r_fallback_evidence", G0R_EVIDENCE_PATH),
        ("g0r_restore_runbook", G0R_RUNBOOK_PATH),
    ):
        assert authority[key]["path"] == path.relative_to(ROOT).as_posix()
        assert authority[key]["sha256"] == _sha256(path)
    for visual in authority["g0r_visual_baselines"]:
        path = ROOT / visual["path"]
        assert path.is_file()
        assert visual["sha256"] == _sha256(path)
    buidl_backup = authority["g0r_live_buidl_backup"]
    assert Path(buidl_backup["path"]).is_absolute()
    assert len(buidl_backup["sha256"]) == 64
    if os.getenv("CONCORDIA_VERIFY_EXTERNAL_G0R") == "1":
        buidl_path = Path(buidl_backup["path"])
        assert buidl_path.is_file()
        assert buidl_backup["sha256"] == _sha256(buidl_path)


def test_canonical_encoding_and_domain_separators_are_exact() -> None:
    canonical = _manifest()["canonical_encoding"]
    assert canonical["hash"] == {
        "name": "BLAKE2b-256",
        "standard": "RFC 7693",
        "digest_size_bytes": 32,
        "key_hex": "",
        "salt_hex": "",
        "personalization_hex": "",
        "truncate_blake2b_512": False,
    }
    assert canonical["byte_order"] == "big-endian"
    assert canonical["type_tags"] == {
        "bool": 1,
        "u8": 2,
        "u32": 3,
        "u64": 4,
        "U256": 5,
        "U512": 6,
        "Bytes32": 7,
        "AccountHash": 8,
        "Key": 9,
        "String": 10,
        "Bytes": 11,
        "List<Key>": 12,
        "PublicKey": 13,
        "Option<u64>": 14,
    }
    expected_separators = {
        "deployment_domain": "434f4e434f524449415f444f4d41494e5f563300",
        "envelope": "434f4e434f524449415f474f5645524e414e43455f454e56454c4f50455f563300",
        "action_id": "434f4e434f524449415f414354494f4e5f49445f563300",
        "transfer_id": "434f4e434f524449415f5452414e534645525f49445f563300",
        "resource_url": "434f4e434f524449415f5245534f555243455f55524c5f563100",
        "preauth_evidence": "434f4e434f524449415f505245415554485f45564944454e43455f563100",
        "authorized_metadata": "434f4e434f524449415f415554484f52495a45445f4d455441444154415f563100",
        "execution_args": "434f4e434f524449415f455845435f415247535f563100",
        "payment_requirements": "434f4e434f524449415f5041594d454e545f524551554952454d454e54535f563100",
        "signed_payment_payload": "434f4e434f524449415f5349474e45445f5041594d454e545f5041594c4f41445f563100",
        "x402_report": "434f4e434f524449415f583430325f5245504f52545f563100",
        "safepay_correlation": "434f4e434f524449415f534146455041595f51554f54455f563200",
        "safepay_quote_hash": "434f4e434f524449415f534146455041595f51554f54455f484153485f563200",
    }
    assert {key: value["hex"] for key, value in canonical["domain_separators"].items()} == expected_separators
    for separator in canonical["domain_separators"].values():
        raw = bytes.fromhex(separator["hex"])
        assert len(raw) == separator["bytes"]
        assert raw.endswith(b"\0")
        assert not raw.endswith(b"\\0")
        assert raw[:-1].isascii()


def test_envelope_field_orders_cores_and_invariants_are_exact() -> None:
    envelope = _manifest()["envelope"]
    native = envelope["native_transfer_v1"]
    x402 = envelope["official_x402_settlement_v1"]
    assert envelope["header_fields"] == HEADER_FIELDS
    assert native["body_fields"] == NATIVE_BODY
    assert native["action_core_fields"] == NATIVE_CORE
    assert native["excluded_from_action_core"] == ["action_id", "action_nonce", "transfer_id"]
    assert x402["body_fields"] == X402_BODY
    assert x402["action_core_fields"] == X402_CORE
    assert x402["excluded_from_action_core"] == ["action_id", "action_nonce"]
    assert envelope["action_id"]["action_nonce_occurrences"] == 1
    assert envelope["action_id"]["proposal_independent"] is True
    assert envelope["transfer_id"]["proposal_bound"] is True
    compatibility = envelope["decision_action_compatibility"]
    assert compatibility["executable_decisions"] == [1, 2]
    assert compatibility["non_executable_decisions"] == [0, 3, 4]
    assert native["invariants"]["finals_example"]["amount_motes"] == "50000000000"
    assert x402["invariants"]["value_nonzero"] is True
    assert x402["invariants"]["wcspr_contract"] == _manifest()["wcspr_live_readback"]["active_contract_hash"]


def test_contract_abi_has_no_placeholders_and_matches_frozen_fields() -> None:
    abi = _manifest()["contract_abi"]
    assert abi["constructor"] == [
        "proposer:ByteArray(32)",
        "finalizer:ByteArray(32)",
        "signer_a:ByteArray(32)",
        "signer_b:ByteArray(32)",
        "signer_c:ByteArray(32)",
        "threshold:u8",
        "casper_chain_name:String",
        "installation_nonce:ByteArray(32)",
    ]
    native_args = abi["entry_points"]["finalize_native_transfer"]["args"]
    x402_args = abi["entry_points"]["finalize_official_x402"]["args"]
    expected_native_body_args = [
        "asset_kind:U8",
        "source_account:ByteArray(32)",
        "recipient_account:ByteArray(32)",
        "amount_motes:U512",
        "treasury_snapshot_balance_motes:U512",
        "snapshot_block_hash:ByteArray(32)",
        "snapshot_block_height:U64",
        "transfer_id:U64",
        "action_nonce:ByteArray(32)",
        "execution_target:String",
        "execution_version:U32",
    ]
    expected_x402_body_args = [
        field.replace(":u32", ":U32")
        .replace(":u8", ":U8")
        .replace(":u64", ":U64")
        .replace(":Bytes32", ":ByteArray(32)")
        .replace(":AccountHash", ":ByteArray(32)")
        for field in X402_BODY
    ]
    assert native_args == FINALIZER_HEADER_ARGS + expected_native_body_args
    assert x402_args == FINALIZER_HEADER_ARGS + expected_x402_body_args
    assert abi["entry_points"]["propose_envelope"]["return"] == "Unit"
    assert abi["entry_points"]["approve_envelope"]["return"] == "Unit"
    assert abi["queries"] == {
        "schema_version": {"args": [], "return": "U32"},
        "deployment_domain": {"args": [], "return": "ByteArray(32)"},
        "casper_chain_name": {"args": [], "return": "String"},
        "proposer": {"args": [], "return": "ByteArray(32)"},
        "finalizer": {"args": [], "return": "ByteArray(32)"},
        "signer_a": {"args": [], "return": "ByteArray(32)"},
        "signer_b": {"args": [], "return": "ByteArray(32)"},
        "signer_c": {"args": [], "return": "ByteArray(32)"},
        "threshold": {"args": [], "return": "U8"},
        "proposed_envelope": {"args": ["proposal_id:String"], "return": "Option<ByteArray(32)>"},
        "approval_count": {"args": ["proposal_id:String"], "return": "U8"},
        "has_approved": {"args": ["proposal_id:String", "signer:ByteArray(32)"], "return": "Bool"},
        "quorum_met": {"args": ["proposal_id:String"], "return": "Bool"},
        "finalized": {"args": ["proposal_id:String"], "return": "Bool"},
        "finalized_envelope": {"args": ["proposal_id:String"], "return": "Option<ByteArray(32)>"},
        "action_authorized": {"args": ["action_id:ByteArray(32)"], "return": "Bool"},
    }
    assert list(abi["events"]) == [
        "V3Initialized",
        "EnvelopeProposed",
        "EnvelopeApproved",
        "EnvelopeFinalized",
    ]
    assert abi["events"]["EnvelopeFinalized"][-1] == "action_kind:U8"
    assert abi["errors"] == {
        "1": "InvalidSignerSet",
        "2": "InvalidThreshold",
        "3": "InvalidRoleAddress",
        "4": "UnauthorizedProposer",
        "5": "UnauthorizedSigner",
        "6": "UnauthorizedFinalizer",
        "7": "ProposalAlreadyExists",
        "8": "QuorumNotMet",
        "9": "ProposalMissing",
        "10": "EnvelopeHashMismatch",
        "11": "AlreadyApproved",
        "12": "AlreadyFinalized",
        "13": "ActionAlreadyAuthorized",
        "14": "InvalidProposalId",
        "15": "InvalidEnvelopeField",
        "16": "InvalidActionField",
    }
    assert abi["finalize_precedence"][-5:] == [
        "EnvelopeHashMismatch",
        "InvalidEnvelopeField_decision_or_allocation_semantics",
        "InvalidActionField_cross_field_action_semantics",
        "ActionAlreadyAuthorized",
        "atomic_success",
    ]
    assert "typed_header" not in json.dumps(abi)
    assert "typed_native_body" not in json.dumps(abi)
    assert "typed_x402_body" not in json.dumps(abi)


def test_wcspr_readback_and_official_hosted_gate_are_fail_closed() -> None:
    manifest = _manifest()
    readback = _json(READBACK_PATH)
    wcspr = manifest["wcspr_live_readback"]
    facilitator = manifest["facilitator"]
    assert readback["observed_at"] != readback["observation"]["block_timestamp"]
    assert wcspr["artifact_sha256"] == _sha256(READBACK_PATH)
    assert wcspr["package_lock_status"] == "Unlocked"
    assert wcspr["active_contract_version"] == 8
    assert wcspr["transfer_with_authorization"] == [
        "from:Key",
        "to:Key",
        "value:U256",
        "valid_after:U64",
        "valid_before:U64",
        "nonce:List<U8>",
        "public_key:PublicKey",
        "signature:List<U8>",
        "return:Unit",
    ]
    assert facilitator["authorization_header"] == "raw_token_no_bearer"
    gate = facilitator["settlement_gate"]
    assert gate["status"] == "blocked_fail_closed"
    assert gate["success_status"] == "official_hosted_verified_live"
    assert gate["self_hosted_satisfies_official_deliverable"] is False
    assert gate["verify_is_not_settle"] is True
    assert gate["automatic_amount_value_fallback_forbidden"] is True


def test_golden_vectors_exist_match_hashes_and_regenerate_deterministically() -> None:
    manifest = _manifest()
    paths = manifest["mandatory_golden_vector_paths"]
    hashes = manifest["golden_vector_sha256"]
    assert len(paths) == 21
    assert set(paths) == set(hashes)
    for relative in paths:
        path = ROOT / relative
        assert path.is_file(), relative
        assert _sha256(path) == hashes[relative], relative
        assert isinstance(_strict_json_loads(path.read_text(encoding="utf-8")), dict)
    subprocess.run(
        ["python3", str(GENERATOR_PATH), "--check"],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    x402 = _json(ROOT / "tests/golden/envelope_v3/x402_settlement/GV-X4-01.json")
    account_binding = x402["x402_binding_projection"]["public_key_account_binding"]
    assert account_binding["equals_typed_payer"] is True
    assert account_binding["derived_account_hash"] == (
        "5e4de9c4290a76042658e8e0d127d3e0d4ba7b99a11ad17da88d0bed2e15ec5c"
    )
    assert x402["live_or_facilitator_success_claimed"] is False
    assert set(x402["x402_binding_projection"]["preimages"]) == {
        "resource_url_hash",
        "report_hash",
        "payment_requirements_hash",
        "signed_payment_payload_hash",
    }


def test_every_normative_json_document_has_unique_object_keys() -> None:
    normative_paths = [
        MANIFEST_PATH,
        CROSS_LANE_PATH,
        READBACK_PATH,
        G0R_EVIDENCE_PATH,
        *sorted((ROOT / "tests/golden/envelope_v3").rglob("*.json")),
    ]
    assert len(normative_paths) == 25
    for path in normative_paths:
        assert isinstance(_strict_json_loads(path.read_text(encoding="utf-8")), dict), path


def test_historical_odra_and_live_artifact_trees_match_frozen_inventories() -> None:
    for inventory, expected_count in ((ODRA_HASHES_PATH, 18), (LIVE_HASHES_PATH, 65)):
        entries = _inventory_entries(inventory)
        assert len(entries) == expected_count
        assert len({relative for _, relative in entries}) == expected_count
        scope = (
            "contracts/odra-governance-receipt"
            if inventory == ODRA_HASHES_PATH
            else "artifacts/live"
        )
        baseline_paths = set(
            subprocess.check_output(
                ["git", "ls-tree", "-r", "--name-only", BASELINE_COMMIT, "--", scope],
                cwd=ROOT,
                text=True,
            ).splitlines()
        )
        assert {relative for _, relative in entries} == baseline_paths
        if inventory == ODRA_HASHES_PATH:
            current_tracked = set(
                subprocess.check_output(["git", "ls-files", "--", scope], cwd=ROOT, text=True).splitlines()
            )
            assert current_tracked == baseline_paths
            porcelain = subprocess.check_output(
                ["git", "status", "--porcelain", "--untracked-files=all", "--", scope],
                cwd=ROOT,
                text=True,
            ).strip()
            assert porcelain == ""
        for expected, relative in entries:
            path = ROOT / relative
            assert path.is_file(), relative
            assert _sha256(path) == expected, relative
            baseline_bytes = subprocess.check_output(
                ["git", "show", f"{BASELINE_COMMIT}:{relative}"], cwd=ROOT
            )
            assert hashlib.sha256(baseline_bytes).hexdigest() == expected, relative


def test_safepay_cross_lane_contract_is_authentic_atomic_and_replay_safe() -> None:
    safepay = _cross_lane()["safepay_v2"]
    assert safepay["canonical_network"] == "casper:casper-test"
    assert safepay["provider_is_only_consumption_authority"] is True
    assert safepay["gateway_consumption_ledger_forbidden"] is True
    wire = safepay["wire_contract"]
    assert wire["quote_issue"]["method"] == "POST"
    assert wire["quote_issue"]["path"] == "/x402/v2/quotes"
    assert wire["quote_issue"]["success_http_status"] == 402
    assert wire["quote_issue"]["response_literals"] == {"schema_version": "safepay-v2"}
    assert wire["quote_issue"]["error_object"] == {
        "code": "payment_required",
        "retryable": False,
    }
    assert wire["redemption"]["path"] == "/x402/v2/redemptions"
    assert wire["redemption"]["request_required_fields_in_order"] == [
        "schema_version", "quote", "payment_hash"
    ]
    assert wire["redemption"]["payment_header_forbidden"] is True
    assert wire["gateway_mapping"]["provider_quote_must_not_be_reconstructed_by_gateway"] is True
    assert wire["legacy_v1_route_not_valid_for_new_v2_evidence"] is True
    abuse = safepay["issuance_abuse_controls"]
    assert abuse["quote_ttl_seconds"] == 900
    assert abuse["per_client_limit"] > 0
    assert abuse["global_limit"] >= abuse["per_client_limit"]
    assert abuse["maximum_outstanding_unconsumed_quotes"] > 0
    assert abuse["maximum_retained_unconsumed_quotes_including_expired"] == 20000
    assert abuse["maximum_content_addressed_report_decoded_bytes"] == 67108864
    assert "expires_at_strictly_greater_than_now" in abuse["outstanding_definition"]
    assert abuse["algorithm"] == "durable_SQLite_fixed_window"
    assert abuse["client_identity"]["caddy_operation"].startswith("remove_any_caller_supplied_value")
    assert abuse["client_identity"]["hmac_configuration"]["runtime_file"] == (
        "/run/secrets/safepay_client_key_hmac_secret"
    )
    assert abuse["client_identity"]["proxy_attestation_configuration"]["runtime_file"] == (
        "/run/secrets/safepay_proxy_secret"
    )
    assert abuse["maximum_inflight_quote_reservations"] == 32
    assert abuse["reservation_ttl_seconds"] == 60
    assert abuse["report_resolution_timeout_seconds"] == 10
    assert abuse["issued_at_rule"] == (
        "provider_samples_one_integer_UTC_Unix_second_once_at_the_start_of_the_"
        "final_issue_transaction_after_report_resolution"
    )
    assert abuse["preflight_attempt_transaction"][0] == "BEGIN_IMMEDIATE"
    assert abuse["preflight_attempt_transaction"][-1] == "COMMIT_before_report_resolution"
    assert abuse["final_issue_transaction"][0] == "BEGIN_IMMEDIATE"
    assert abuse["final_issue_transaction"][-1] == "COMMIT_before_returning_HTTP_402"
    assert "without_future_refund" in " ".join(abuse["preflight_attempt_transaction"])
    assert "outside_any_SQLite_write_transaction" in abuse["report_resolution_order"]
    assert abuse["expired_unconsumed_gc"]["consumed_quotes_must_never_be_deleted_by_this_gc"] is True
    assert safepay["identifier_encoding"]["domain_separator"] == "CONCORDIA_SAFEPAY_QUOTE_V2\0"
    assert safepay["identifier_encoding"]["correlation_id_formula"] == (
        "first_8_digest_bytes_interpreted_as_unsigned_big_endian_u64"
    )
    quote_fields = [item["name"] for item in safepay["immutable_quote"]["fields_in_order"]]
    assert "transfer_id" not in quote_fields
    assert "correlation_id" in quote_fields
    quote_store = safepay["quote_ledger_row"]
    assert quote_store["caller_computable_unkeyed_quote_hash_is_not_authentication"] is True
    assert quote_store["transaction_mode"] == "BEGIN IMMEDIATE"
    assert safepay["storage"]["database_path"] == "/data/safepay.db"
    response = safepay["success_response"]
    assert response["schema_version_literal"] == "safepay-v2"
    assert response["required_fields_in_order"] == ["schema_version", "fulfillment", "delivery"]
    assert "response_hash" in response["fulfillment_required_fields_in_order"]
    assert response["idempotent_retry_rule"].startswith("fulfillment_and_response_hash_are_identical")
    assert safepay["retry_semantics"]["same_payment_different_quote_or_resource_result"].startswith("http_409")
    assert safepay["error_responses"]["cross_binding_replay"]["gateway_retry_allowed"] is False
    assert safepay["fulfillment_hash"]["dynamic_replay_disposition_included"] is False
    assert safepay["report"]["maximum_decoded_content_bytes"] == 262144
    assert "report_hash TEXT NOT NULL REFERENCES safepay_reports(report_hash)" in (
        safepay["quote_ledger_row"]["required_columns"]
    )
    assert "report_bytes BLOB NOT NULL CHECK(length(report_bytes) <= 262144)" in (
        safepay["report_ledger_row"]["required_columns"]
    )
    assert "PRAGMA foreign_keys=ON" in safepay["storage"]["required_pragmas"]
    assert "PRAGMA synchronous=FULL" in safepay["storage"]["required_pragmas"]
    error_wire = safepay["error_wire_contract"]
    assert error_wire["error_required_fields_in_order"] == ["code", "retryable"]
    assert safepay["error_responses"]["invalid_request"]["http_status"] == 400
    assert safepay["error_responses"]["expired_quote"]["gateway_retry_allowed"] is False
    assert "503:payment_observer_unavailable" in safepay["endpoint_outcomes"]["POST_/x402/v2/redemptions"]
    assert "503:provider_unavailable" in safepay["endpoint_outcomes"]["POST_/x402/v2/quotes"]
    assert "503:provider_unavailable" in safepay["endpoint_outcomes"]["POST_/x402/v2/redemptions"]
    assert "never_include_exception_text" in error_wire["exception_handler"]


def test_wp3_security_interfaces_freeze_dedicated_secrets_and_server_identity() -> None:
    schemas = _cross_lane()
    approval = schemas["approval_boundary_v1"]
    demo = schemas["demo_capability_v1"]
    rooms = schemas["room_identity_v1"]
    assert approval["caddy_contract"]["proxy_header_operation"] == "overwrite"
    assert approval["caddy_contract"]["caller_supplied_proxy_header_forwarded"] is False
    assert all(item["file_environment_name"].endswith("_FILE") for item in approval["runtime_configuration"])
    assert demo["public_endpoints"]["reset"] is None
    assert demo["capability_payload"]["format"].startswith("unpadded_base64url(typed_payload_bytes)")
    assert demo["signing_secret"]["runtime_file"] == "/run/secrets/demo_capability_hmac_secret"
    assert demo["client_binding"]["ip_address_or_user_agent_in_binding_forbidden"] is True
    assert rooms["principal_shape"]["authoritative_source"] == "server_side_authenticated_key_mapping"
    assert rooms["production_gateway_secret_fallback_for_agent_traffic"] is False
    assert rooms["human_approval"]["agent_key_can_emit_user"] is False


def test_official_x402_service_has_exact_wire_interlock_and_recovery_contract() -> None:
    schemas = _cross_lane()
    service = schemas["official_x402_service_v1"]
    registry = schemas["internal_proof_registry_v1"]
    assert service["service"]["container_port"] == 8787
    assert service["service"]["ledger_database_path"] == "/data/x402-official.db"
    assert service["dependencies"] == {
        "@make-software/casper-x402": "1.0.0",
        "@x402/core": "2.15.0",
        "casper-js-sdk": "5.0.12",
        "@casper-ecosystem/casper-eip-712": "1.2.1",
        "source_audit_commit": "14c364bb30838003302074423b7500b4360df889",
        "lockfile_required": True,
        "version_ranges_forbidden": True,
    }
    env = {item["name"]: item["value"] for item in service["environment"]}
    assert env["X402_FACILITATOR_URL"] == "https://x402-facilitator.cspr.cloud"
    assert env["X402_WCSPR_CONTRACT_VERSION"] == "8"
    secret_files = {item["environment_name"]: item["runtime_file"] for item in service["secret_files"]}
    assert secret_files["X402_GATEWAY_TOKEN_FILE"] == "/run/secrets/x402_official_gateway_token"
    assert service["payment_requirements"]["amount_minimum"] == "1"
    assert service["payment_requirements"]["maxTimeoutSeconds_type"] == "integer_1_through_4294967295"
    assert service["payment_payload"]["extensions_rule"] == "absent_or_empty_object_only"
    assert set(service["hash_encodings"]) == {
        "hash",
        "length_prefix",
        "resource_url_hash",
        "report_hash",
        "payment_requirements_hash",
        "signed_payment_payload_hash",
        "casper_account_hash_from_public_key",
    }
    ledger = service["ledger"]
    assert ledger["authorization_unique_key"] == [
        "network",
        "wcspr_contract",
        "payer_account_hash",
        "authorization_nonce",
    ]
    assert ledger["state_machine"][-1] == "failed_terminal"
    assert "never issue a blind second settlement" in ledger["reconciliation_rule"]
    assert service["governance_interlock"]["verification_status_required"] == "verified"
    assert registry["endpoints"] == {
        "by_action_id": "GET /internal/proof-registry/v1/actions/{action_id_hex}",
        "by_signed_payment_payload_hash": "GET /internal/proof-registry/v1/x402/{signed_payment_payload_hash}",
    }
    assert registry["ambiguous_x402_response"]["http_status"] == 409


def test_public_proof_registry_never_vacuously_verifies_unknown_data() -> None:
    registry = _cross_lane()["public_proof_registry_v1"]
    assert registry["transport"]["endpoint"] == "GET /proof-registry/v1/{proposal_id}"
    assert registry["transport"]["required_top_level_fields"] == [
        "schema_version",
        "generated_at",
        "proposal_id",
        "items",
    ]
    assert set(registry["proof_type_enum"]) == set(registry["required_checks_by_proof_type"])
    assert all(registry["required_checks_by_proof_type"].values())
    assert registry["green_visual_predicate"].startswith("verification_status_equals_verified")
    assert "execution_outcome_is_one_of_accepted_expected_rejection_not_applicable" in registry["green_visual_predicate"]
    assert registry["top_level_asserted_boolean_can_verify"] is False
    assert registry["initial_state_for_new_unobserved_proof"] == {
        "lineage": "supplemental",
        "observation_mode": "unavailable",
        "temporal_scope": "current",
        "verification_status": "unavailable",
        "execution_outcome": "not_attempted",
        "checks": [],
    }
    required_item_fields = set(registry["item_required_fields"])
    assert required_item_fields == set(registry["item_field_types"])
    assert registry["observed_check"]["required_fields"] == [
        "name",
        "required",
        "passed",
        "source",
        "observed_at",
    ]
    assert registry["observed_check"]["name_unique_within_item"] is True
    assert registry["observed_check"]["duplicate_name_behavior"] == "item_is_invalid"
    checks = registry["required_checks_by_proof_type"]
    assert {
        "pre_quorum_finalize_reverted_with_code_8",
        "post_quorum_mutated_envelope_reverted_with_code_10",
        "exact_envelope_finalization_accepted",
        "repeat_finalization_reverted_with_code_12",
    } <= set(checks["exact_envelope_v3"])
    assert "no_second_native_transaction_for_action_id" in checks["native_treasury_execution_v1"]
    assert {
        "active_wcspr_v8_pre_verify_drift_guard_passed",
        "active_wcspr_v8_pre_settle_drift_guard_passed",
        "active_wcspr_v8_post_settle_target_and_args_readback_passed",
    } <= set(checks["official_x402_settlement_v1"])


def test_ownership_and_literal_path_inventories_are_collision_safe() -> None:
    manifest = _manifest()
    codex = set(manifest["ownership"]["codex"]["exclusive_paths"])
    claude = set(manifest["ownership"]["claude"]["exclusive_paths"])
    assert not codex & claude
    assert "shared/proposal_room.py" in codex
    assert "gateway/auth.py" in codex
    assert "gateway/database.py" in codex
    assert "tests/test_concordia_core.py" in codex
    assert "docs/LLM_PROVIDER.md" in claude
    assert ".github/SECURITY.md" in claude
    for key in ("mandatory_golden_vector_paths", "mandatory_test_paths"):
        paths = manifest[key]
        assert len(paths) == len(set(paths))
        for path in paths:
            assert all(token not in path for token in ("*", "…", "{", "}", "TODO", "TBD"))


def test_runtime_secret_inventory_contains_every_new_boundary_secret() -> None:
    secrets = _manifest()["secrets"]
    assert secrets["repository_secret_values_allowed"] is False
    assert set(secrets["runtime_files"]) >= {
        "/run/secrets/x402_official_cspr_cloud_token",
        "/run/secrets/x402_official_signer",
        "/run/secrets/x402_official_gateway_token",
        "/run/secrets/demo_capability_hmac_secret",
        "/run/secrets/dashboard_demo_gateway_token",
        "/run/secrets/approval_proxy_secret",
        "/run/secrets/approval_ui_user",
        "/run/secrets/approval_ui_approver_id",
        "/run/secrets/approval_ui_bcrypt_hash",
        "/run/secrets/approval_ui_csrf_secret",
        "/run/secrets/safepay_client_key_hmac_secret",
        "/run/secrets/safepay_proxy_secret",
    }
    assert secrets["forbidden_repository_path"] == "services/x402-official/secrets/"
    assert secrets["facilitator_error_bodies_must_not_be_logged"] is True


def test_branch_protocol_and_claim_state_are_fail_closed() -> None:
    manifest = _manifest()
    protocol = manifest["branch_protocol"]
    assert protocol["required_root"] == f"refs/tags/{TAG}^{{}}"
    assert protocol["main_writes_forbidden"] is True
    assert protocol["untagged_or_partial_branching_forbidden"] is True
    requirements = set(protocol["claude_start_requirements"])
    assert {
        "resolve the annotated tag to its peeled commit",
        "read this manifest from that commit",
        "require status exactly ready",
        "verify every path and SHA-256 under manifest.authority",
        "run python3 scripts/generate_g1_vectors.py --check",
        "run pytest -q tests/test_g1_freeze_manifest.py against the tagged tree",
        "create claude/finals-product-security from the peeled commit",
        "work only in Claude-owned paths",
    } == requirements
    assert manifest["baseline_gates"]["release_green_claim"] is False
    assert manifest["g1_acceptance"]["implementation_complete"] is False
    assert manifest["g1_acceptance"]["live_proof_complete"] is False
    g0r = _json(G0R_EVIDENCE_PATH)
    assert g0r["status"] == "pass"
    assert all(g0r["pass_predicate"].values())
    assert g0r["route_crawl"]["final_200_count"] == 16
    routes = g0r["route_crawl"]["routes"]
    assert len(routes) == 16
    assert all(item["status"] == 200 for item in routes)
    assert all(item["requested_url"].startswith("https://") for item in routes)
    jury = next(
        item for item in routes
        if item["requested_url"] == "https://concordia.47.84.232.193.sslip.io/technical-jury-note"
    )
    assert jury["effective_url"].endswith("/dashboard/technical-jury-note")
    assert jury["redirect_chain"] == [{"status": 307, "location": "/dashboard/technical-jury-note"}]
    assert g0r["anchor_audit"]["broken_targets"] == 0
    targets = g0r["anchor_audit"]["targets"]
    assert len(targets) == 32
    assert all(item["status"] == 200 for item in targets)
    assert all(item["effective_url"] == item["requested_url"] for item in targets)
    assert all(item["redirect_chain"] == [] for item in targets)
    assert len({item["requested_url"] for item in targets}) == 32
    buidl_links = g0r["live_buidl_backup"]["link_audit"]
    assert buidl_links["unique_targets"] == 13
    assert buidl_links["broken_targets"] == 0
    assert len(buidl_links["targets"]) == 13
    assert all(item["status"] == 200 for item in buidl_links["targets"])
    assert g0r["vm_backup"]["docker_image_inventory"]["locally_available"] == 77
    assert g0r["ecs_snapshot"]["completed"] is True
    execution_state = (HANDOFF / "EXECUTION_STATE.md").read_text(encoding="utf-8")
    assert "| G0-R fallback verification | PASS |" in execution_state
    assert "| G1 interface freeze | PASS |" in execution_state
    assert "`concordia-g1-freeze-v2.0-a` peels to `b24c040`" in execution_state


def test_annotated_tag_if_required_or_present_is_self_consistent() -> None:
    require_tag = os.getenv("CONCORDIA_REQUIRE_G1_TAG") == "1"
    exists = subprocess.run(
        ["git", "show-ref", "--verify", "--quiet", f"refs/tags/{TAG}"],
        cwd=ROOT,
    ).returncode == 0
    if not exists:
        assert not require_tag, f"required annotated tag {TAG} does not exist"
        return
    tag_type = subprocess.check_output(["git", "cat-file", "-t", TAG], cwd=ROOT, text=True).strip()
    peeled = subprocess.check_output(["git", "rev-parse", f"{TAG}^{{}}"], cwd=ROOT, text=True).strip()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    assert tag_type == "tag"
    if require_tag:
        assert peeled == head
    parent = subprocess.check_output(["git", "rev-parse", f"{peeled}^"], cwd=ROOT, text=True).strip()
    assert parent == BASELINE_COMMIT

    def tagged_bytes(relative: str) -> bytes:
        return subprocess.check_output(["git", "show", f"{TAG}:{relative}"], cwd=ROOT)

    tagged_manifest = _strict_json_loads(tagged_bytes("handoff/G1_FREEZE_MANIFEST.json"))
    assert isinstance(tagged_manifest, dict)
    assert tagged_manifest["status"] == "ready"
    for key in (
        "cross_lane_schema",
        "wcspr_facilitator_readback",
        "historical_odra_inventory",
        "historical_live_artifact_inventory",
        "golden_vector_generator",
        "g0r_fallback_evidence",
        "g0r_restore_runbook",
    ):
        authority = tagged_manifest["authority"][key]
        assert hashlib.sha256(tagged_bytes(authority["path"])).hexdigest() == authority["sha256"]
    for visual in tagged_manifest["authority"]["g0r_visual_baselines"]:
        assert hashlib.sha256(tagged_bytes(visual["path"])).hexdigest() == visual["sha256"]
    assert hashlib.sha256(tagged_bytes(tagged_manifest["authority"]["normative_spec"])).hexdigest() == (
        tagged_manifest["authority"]["normative_spec_sha256"]
    )
    for relative, expected in tagged_manifest["golden_vector_sha256"].items():
        assert hashlib.sha256(tagged_bytes(relative)).hexdigest() == expected
