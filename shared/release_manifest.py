"""Code-collected, commit-bound finals release receipts and manifest.

This module deliberately separates two operator actions:

``capture``
    Observes fixed local and public release surfaces, projects them through
    strict non-secret schemas, reruns every fixed proof verifier, and creates
    immutable receipts.  It accepts no operator-authored status document.

``assemble``
    Requires those exact receipts to be committed, reruns every proof verifier,
    performs a second observation of mutable surfaces, checks freshness and
    stability, and atomically creates the one fixed release manifest.

Raw Caddy, Compose, HTTP, RPC, registry, and secret-bearing data is held only in
memory.  The persistent receipts contain canonical public projections and
digests, never raw response bodies, headers, environment values, or secrets.
"""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import http.client
import ipaddress
import io
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import stat
import tarfile
import tempfile
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import urljoin, urlsplit

import bcrypt

from shared import release_proof_adapters
from shared.bound_command import (
    BoundCommandError,
    BoundCommandResult,
    HostToolchainAuthority,
    accepted_tool_authority_from_receipt,
    build_host_toolchain_receipt_candidate,
    run_bound_command,
)
from shared.proof_registry import validate_release_registry_document
from shared.live_collector_provenance import (
    LIVE_COLLECTOR_ARTIFACT_PATHS,
    LIVE_COLLECTOR_RAW_PATHS,
    LIVE_COLLECTOR_RECEIPT_PATHS,
)
from shared.release_gate_contract import (
    BOUND_GIT_CONFIG_OVERRIDES,
    BOUND_HOST_TOOLCHAIN_RECEIPT_PATH,
    BOUND_HOST_TOOLCHAIN_RECEIPT_SCHEMA_VERSION,
    COMMAND_GATE_COMMANDS,
    COMMAND_GATE_EXECUTABLE_CHAIN_SCHEMA_VERSION,
    COMMAND_GATE_EXPECTED_RUNTIME_VERSIONS,
    COMMAND_GATE_FRESH_OUTPUT_PATHS,
    COMMAND_GATE_IDENTITY_PATHS,
    COMMAND_GATE_INPUT_ARTIFACT_PATHS,
    COMMAND_GATE_NORMALIZATION,
    COMMAND_GATE_PRODUCED_ARTIFACT_PATHS,
    COMMAND_GATE_RECEIPT_PATHS,
    COMMAND_GATE_RECEIPT_SCHEMA_VERSION,
    COMMAND_GATE_REQUIRED_RUNTIMES,
    COMMAND_GATE_RUNNER_PATHS as COMMAND_GATE_RUNNER_PATHS,
    G1_FREEZE_COMMIT,
    G1_FREEZE_TAG,
    G1_FREEZE_TAG_OBJECT,
)
from shared.secret_variants import normalize_sensitive_key, secret_variants


SCHEMA_VERSION = "concordia.release_manifest.v5"
OBSERVATION_SCHEMA_VERSION = "concordia.release_observation_receipt.v1"
PROOF_RECEIPT_SCHEMA_VERSION = "concordia.proof_verifier_receipt.v1"
RELEASE_MANIFEST_PATH = "release/RELEASE_MANIFEST.json"
COMPOSE_FILE_PATH = "deploy/shared-host/compose.prod.yml"
NPM_CAPTURE_PATH = "release/captures/concordia-dao-verify.tgz"
CAPTURE_JOURNAL_PATH = ".concordia-release-capture-journal.json"
CAPTURE_JOURNAL_SCHEMA_VERSION = "concordia.capture_publication_journal.v1"
POST_FREEZE_CORRECTION_SCHEMA_VERSION = "concordia.post_freeze_correction.v1"
POST_FREEZE_CORRECTIONS_SCHEMA_VERSION = "concordia.post_freeze_corrections.v1"
_G1_POST_FREEZE_CORRECTIONS_PATH = "handoff/G1_POST_FREEZE_CORRECTIONS.json"
_G1_POST_FREEZE_CORRECTIONS_SCHEMA_ID = (
    "concordia.g1-post-freeze-corrections.v1"
)
_G1_POST_FREEZE_CORRECTION_IDS = (
    "G1-C6-v3-temporal-order",
    "G1-C7-proof-registry-deployment-domain",
    "G1-C8-v3-canonical-block-order",
    "G1-C9-treasury-authorization-block-hash",
    "G1-C10-independent-card-chain-artifact",
    "G1-C11-proof-type-provenance-binding",
    "G1-C12-proof-observation-chronology",
    "G1-C13-independent-historical-odra-artifact",
    "G1-C14-official-x402-separate-proposal-and-governance-identity",
)
# The shared host serves another judged application. Bind its complete /mcp
# route projection without carrying that application's identity into Concordia's
# submission corpus.
_SHARED_COHOST_MCP_ROUTE_SHA256 = (
    "ea66f8b9c78be3bbbb459f908181c6ad80e9527c1162c057c499311cf464df1b"
)

_SAFEPAY_GATEWAY_CORRECTION = {
    "schema_version": POST_FREEZE_CORRECTION_SCHEMA_VERSION,
    "correction_id": "safepay_gateway_wallet_intent_capability_v1",
    "g1_disposition": "post_freeze_non_mutating_security_correction",
    "reviewed_source_candidate_commit": "65b2474f4c10d47766aba026a654eb1b4486ac53",
    "client_interface_version": "safepay-gateway-wallet-intent-capability-v1",
    "endpoint": "/x402/v2/payment-intent",
    "request_schema": "safepay-wallet-intent-request-v2",
    "response_schema": "safepay-wallet-intent-v2",
    "request_capability_field": "quote_capability",
    "quote_response_capability_header": ("X-Concordia-SafePay-Quote-Capability"),
    "capability_format_prefix": "sqc1",
    "deployment_prerequisite": {
        "environment_key": "SAFEPAY_QUOTE_TOKEN_SECRET_FILE",
        "runtime_path": "/run/secrets/safepay_quote_token_secret",
        "consumer": "gateway",
        "minimum_bytes": 32,
    },
}
_SAFEPAY_GATEWAY_CORRECTION_PATHS = (
    "gateway/app.py",
    "shared/x402_payments.py",
    COMPOSE_FILE_PATH,
    "tests/test_safepay_gateway_v2.py",
    "tests/test_compose_secret_scope.py",
)

ARTIFACT_PATHS: dict[str, str] = {
    "card_chain_roots_v1": "artifacts/live/card-chain-roots-v1.json",
    "exact_envelope_v3": "artifacts/live/odra-governance-receipt-v3-exact-envelope-proof.json",
    "historical_odra_receipt_v1": "artifacts/live/historical-odra-receipt-v2.json",
    "native_treasury_execution_v1": "artifacts/live/treasury-execution-v3.json",
    "official_x402_settlement_v1": "artifacts/live/official-x402-settlement-v1.json",
    "proof_registry_v1": "artifacts/live/proof-registry/registry.json",
    "safepay_v2": "artifacts/live/safepay-lite-replaysafe-v2.json",
}

RECEIPT_PATHS: dict[str, str] = {
    "compose": "release/receipts/compose.json",
    "runtime": "release/receipts/runtime.json",
    "caddy": "release/receipts/caddy.json",
    "public_probes": "release/receipts/public-probes.json",
    "pages": "release/receipts/pages.json",
    "npm": "release/receipts/npm.json",
    "rpc": "release/receipts/rpc.json",
}
PROOF_RECEIPT_PATHS: dict[str, str] = {
    artifact_id: f"release/receipts/proofs/proof-{artifact_id}.json"
    for artifact_id in ARTIFACT_PATHS
}

# Compatibility name used by the existing release-manifest tests and gate map.
# The authoritative inventory lives in the shared immutable gate contract.
COMMAND_GATE_ARTIFACT_PATHS = COMMAND_GATE_PRODUCED_ARTIFACT_PATHS

G13_SUBMISSION_RECEIPT_SCHEMA_VERSION = "concordia.g13_submission_receipt.v3"
G13_SUBMISSION_RECEIPT_PATH = "release/G13_SUBMISSION_RECEIPT.json"
G13_RUNNER_PATH = "scripts/run_g13_submission_gate.mjs"
G13_BROWSER_RECEIPT_SCHEMA_VERSION = "concordia.g13_browser_receipt.v1"
G13_BROWSER_RECEIPT_PATH = "release/g13/BROWSER_RECEIPT.json"
G13_BROWSER_TRACE_SCHEMA_VERSION = "concordia.g13_browser_probe_result.v1"
G13_BROWSER_TRACE_PATH = "release/g13/BROWSER_TRACE.json"
ORGANIZER_LINK_AUDIT_SCHEMA_VERSION = (
    "concordia.organizer_rendered_link_audit.v2"
)
ORGANIZER_LINK_INVOCATION_SCHEMA_VERSION = (
    "concordia.organizer_rendered_link_invocation.v1"
)
ORGANIZER_LINK_REQUEST_PATH = "handoff/ORGANIZER_LINK_GATE_REQUEST.json"
ORGANIZER_LINK_CORE_PATH = "scripts/organizer-link-gate-core.mjs"
ORGANIZER_LINK_RUNNER_PATH = "scripts/run_organizer_link_gate.mjs"
ORGANIZER_LINK_VERIFIER_PATH = "scripts/verify_organizer_link_audit.mjs"
ORGANIZER_G12_AUDIT_PATH = (
    "release/organizer/G12_RENDERED_LINK_AUDIT.json"
)
ORGANIZER_G13_AUDIT_PATH = (
    "release/g13/ORGANIZER_RENDERED_LINK_AUDIT.json"
)
ORGANIZER_G12_INVOCATION_PATH = (
    "release/organizer/G12_RENDERED_LINK_INVOCATION.json"
)
ORGANIZER_G13_INVOCATION_PATH = (
    "release/g13/ORGANIZER_RENDERED_LINK_INVOCATION.json"
)
_ORGANIZER_DASHBOARD_ROUTE_IDS = (
    "overview",
    "proposals",
    "approvals",
    "council_chamber",
    "evidence",
    "proof_center",
    "judge_walkthrough",
    "judge_recording",
    "runs_replay",
    "record",
    "technical_jury_note",
)
_ORGANIZER_PROOF_TAB_IDS = ("summary", "safety", "onchain", "data", "exports")
_G1_FREEZE_MANIFEST_PATH = "handoff/G1_FREEZE_MANIFEST.json"
_G1_FREEZE_ANNOTATION = "Concordia finals G1 interface freeze v2.0-A\n"

PUBLIC_URLS: dict[str, str] = {
    "custom_apex": "https://concordiadao.xyz/",
    "custom_docs": "https://docs.concordiadao.xyz/",
    "custom_www": "https://www.concordiadao.xyz/",
    "custom_x402": "https://x402.concordiadao.xyz/",
    "sslip_app": "https://concordia.47.84.232.193.sslip.io/",
    "sslip_provider": "https://x402-provider.47.84.232.193.sslip.io/",
}
RPC_PROVIDERS: dict[str, dict[str, str]] = {
    "casper_association": {
        "operator_id": "casper_association",
        "endpoint": "https://node.testnet.casper.network/rpc",
        "authentication": "none",
    },
    "cspr_cloud": {
        "operator_id": "cspr_cloud",
        "endpoint": "https://node.testnet.cspr.cloud/rpc",
        "authentication": "raw_authorization_file",
    },
}

_APP = "https://concordia.47.84.232.193.sslip.io"
_PROVIDER = "https://x402-provider.47.84.232.193.sslip.io"
_PROPOSAL = "DAO-PROP-6CB25C"
_OFFICIAL_X402_PROPOSAL = "DAO-PROP-X402-FINALS-2026"
_APP_TITLE = b"Concordia \xe2\x80\x94 Evidence-Bound DAO Governance Council"


def _probe(
    url: str,
    *,
    status: int = 200,
    effective_url: str | None = None,
    redirects: Sequence[Mapping[str, object]] = (),
    content_type: str = "text/html; charset=utf-8",
    body: bytes = _APP_TITLE,
    marker: bytes | None = None,
    exact_body: bytes | None = None,
    prefix: bytes | None = None,
    semantic: str | None = None,
) -> dict[str, object]:
    return {
        "url": url,
        "effective_url": effective_url or url,
        "redirect_chain": [dict(item) for item in redirects],
        "status": status,
        "content_type": content_type,
        "marker": marker,
        "exact_body": exact_body,
        "prefix": prefix,
        "semantic": semantic,
    }


# Fixed, read-only crawl.  No demo, reset, activation, payment redemption, or
# settlement endpoint is present.  The sixteen baseline URLs are preserved and
# the release-specific health/proof surfaces are additive.
HTTP_PROBE_SPECS: dict[str, dict[str, object]] = {
    "sslip_app_root": _probe(
        _APP + "/",
        effective_url=_APP + "/dashboard",
        redirects=(
            {"status": 302, "location": "/dashboard/"},
            {"status": 308, "location": "/dashboard"},
        ),
        marker=_APP_TITLE,
    ),
    "sslip_provider_root": _probe(
        _PROVIDER + "/",
        content_type="text/plain; charset=utf-8",
        body=b"Concordia x402 Risk Oracle Provider",
        exact_body=b"Concordia x402 Risk Oracle Provider",
    ),
    "custom_apex_root": _probe(
        "https://concordiadao.xyz/",
        effective_url="https://concordiadao.xyz/dashboard",
        redirects=(
            {"status": 302, "location": "/dashboard/"},
            {"status": 308, "location": "/dashboard"},
        ),
        marker=_APP_TITLE,
    ),
    "custom_www_root": _probe(
        "https://www.concordiadao.xyz/",
        effective_url="https://concordiadao.xyz/dashboard",
        redirects=(
            {"status": 308, "location": "https://concordiadao.xyz/"},
            {"status": 302, "location": "/dashboard/"},
            {"status": 308, "location": "/dashboard"},
        ),
        marker=_APP_TITLE,
    ),
    "custom_docs_root": _probe(
        "https://docs.concordiadao.xyz/",
        body=b"<title>Concordia documentation</title><meta name=release-stamp content=deployed>",
        marker=b"Concordia",
    ),
    "custom_x402_root": _probe(
        "https://x402.concordiadao.xyz/",
        effective_url="https://x402.concordiadao.xyz/supported",
        redirects=({"status": 308, "location": "/supported"},),
        content_type="application/json",
        semantic="official_supported",
    ),
    "custom_x402_health": _probe(
        "https://x402.concordiadao.xyz/health",
        content_type="application/json",
        semantic="official_health",
    ),
}

for _route_id, _route in (
    ("dashboard", "/dashboard"),
    ("dashboard_judge", "/dashboard/judge"),
    ("dashboard_proof", "/dashboard/proof"),
    ("dashboard_agents", "/dashboard/agents"),
    ("dashboard_proposals", f"/dashboard/proposals?proposal={_PROPOSAL}"),
    ("dashboard_approvals", "/dashboard/approvals"),
    ("dashboard_evidence", "/dashboard/evidence"),
    ("dashboard_runs", "/dashboard/runs"),
    ("dashboard_record", "/dashboard/record"),
    ("dashboard_technical_note", "/dashboard/technical-jury-note"),
):
    HTTP_PROBE_SPECS[_route_id] = _probe(_APP + _route, marker=_APP_TITLE)

HTTP_PROBE_SPECS.update(
    {
        "evidence": _probe(
            f"{_APP}/evidence/{_PROPOSAL}",
            content_type="application/json",
            body=(f'{{"proposal_id":"{_PROPOSAL}","cards":[]}}').encode(),
            semantic="evidence",
        ),
        "proof_pack": _probe(
            f"{_APP}/proof-pack/{_PROPOSAL}",
            content_type="application/json",
            body=(f'{{"proposal_id":"{_PROPOSAL}","redaction":"passed"}}').encode(),
            semantic="proof_pack",
        ),
        "technical_note": _probe(
            f"{_APP}/technical-jury-note",
            effective_url=f"{_APP}/dashboard/technical-jury-note",
            redirects=({"status": 307, "location": "/dashboard/technical-jury-note"},),
            marker=_APP_TITLE,
        ),
        "certificate_html": _probe(
            f"{_APP}/certificate/{_PROPOSAL}",
            body=b"Concordia certificate DAO-PROP-6CB25C",
            marker=_PROPOSAL.encode(),
        ),
        "certificate_pdf": _probe(
            f"{_APP}/certificate/{_PROPOSAL}/pdf",
            content_type="application/pdf",
            body=b"%PDF-1.7\nConcordia DAO-PROP-6CB25C certificate\n%%EOF",
            marker=_PROPOSAL.encode(),
            prefix=b"%PDF-",
            semantic="pdf_certificate",
        ),
        "safepay": _probe(
            f"{_APP}/safepay-lite/{_PROPOSAL}",
            content_type="application/json",
            body=b'{"schema_version":"safepay-v2","replay_safety":"no_double_consumption"}',
            semantic="safepay",
        ),
        "gateway_health": _probe(
            f"{_APP}/health",
            content_type="application/json",
            body=b'{"service":"concordia-gateway","status":"ok"}',
            exact_body=b'{"service":"concordia-gateway","status":"ok"}',
        ),
        "gateway_ready": _probe(
            f"{_APP}/ready",
            content_type="application/json",
            body=b'{"endpoint":"redacted","errors":[],"llm":{"ready":true,"required":true},"service":"concordia-gateway","status":"ok"}',
            exact_body=b'{"endpoint":"redacted","errors":[],"llm":{"ready":true,"required":true},"service":"concordia-gateway","status":"ok"}',
        ),
        "canonical_consistency": _probe(
            f"{_APP}/canonical-proof/consistency",
            content_type="application/json",
            body=b'{"findings":[],"status":"passed"}',
            exact_body=b'{"findings":[],"status":"passed"}',
        ),
        "redaction_check": _probe(
            f"{_APP}/proof-pack/{_PROPOSAL}/redaction-check",
            content_type="application/json",
            body=b'{"findings":[],"status":"passed"}',
            exact_body=b'{"findings":[],"status":"passed"}',
        ),
        "provider_health": _probe(
            f"{_PROVIDER}/health",
            content_type="application/json",
            body=b'{"service":"concordia-x402-provider","status":"ok"}',
            exact_body=b'{"service":"concordia-x402-provider","status":"ok"}',
        ),
        "provider_openapi": _probe(
            f"{_PROVIDER}/openapi.json",
            content_type="application/json",
            marker=b"/x402/v2/redemptions",
            semantic="provider_openapi",
        ),
        "proof_registry": _probe(
            f"{_APP}/proof-registry/v1/{_PROPOSAL}",
            content_type="application/json",
            marker=_PROPOSAL.encode(),
            semantic="proof_registry",
        ),
        "proof_registry_official": _probe(
            f"{_APP}/proof-registry/v1/{_OFFICIAL_X402_PROPOSAL}",
            content_type="application/json",
            marker=_OFFICIAL_X402_PROPOSAL.encode(),
            semantic="proof_registry",
        ),
        "card_chain": _probe(
            f"{_APP}/proof-artifacts/v1/{_PROPOSAL}/card-chain",
            content_type="application/json",
            marker=_PROPOSAL.encode(),
            semantic="card_chain",
        ),
        "trace": _probe(
            f"{_APP}/api/runs/{_PROPOSAL}/trace",
            content_type="application/json",
            marker=_PROPOSAL.encode(),
            semantic="trace",
        ),
        "ipfs_archive": {
            **_probe(
                f"{_APP}/api/ipfs/bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq",
                content_type="application/json",
                semantic="ipfs_cid",
            ),
            "cid": "bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq",
        },
        "governance_archive": _probe(
            f"{_APP}/proof-pack/{_PROPOSAL}/download",
            content_type="application/json",
            marker=_PROPOSAL.encode(),
            semantic="governance_archive",
        ),
    }
)

_CSV_HEADERS = {
    "cards.csv": "sequence,card_type,issuer,hash",
    "outcomes.csv": "outcome,tone,description",
    "proof_table.csv": "claim,status,evidence",
    "reputation.csv": "agent,metric,value,signal",
    "casper_receipts.csv": "kind,deploy_hash,status,block_hash,block_height,explorer_url",
    "x402_settlements.csv": "payment_hash,resource,status,target_account_hash,amount_motes,explorer_url",
}
for _csv_name, _csv_header in _CSV_HEADERS.items():
    HTTP_PROBE_SPECS["csv_" + _csv_name.removesuffix(".csv")] = {
        **_probe(
            f"{_APP}/proof-pack/{_PROPOSAL}/exports/{_csv_name}",
            content_type="text/csv; charset=utf-8",
            semantic="csv",
        ),
        "csv_header": _csv_header,
    }


_ARTIFACT_LIMIT = 64 * 1024 * 1024
_CONTROL_LIMIT = 4 * 1024 * 1024
_NPM_LIMIT = 16 * 1024 * 1024
_HTTP_LIMIT = 16 * 1024 * 1024
_GIT_OUTPUT_LIMIT = 70 * 1024 * 1024
_VERIFIER_ARCHIVE_LIMIT = 256 * 1024 * 1024
_RECEIPT_MAX_AGE = timedelta(minutes=15)
_MIN_RECHECK_INTERVAL = timedelta(seconds=20)
_GIT40 = re.compile(r"^[0-9a-f]{40}$")
_HEX32 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$"
)
_SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_SECRET_TEXT_PATTERNS = (
    re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(rb"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(rb"\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{12,}\b"),
    re.compile(rb"\bnpm_[A-Za-z0-9]{24,}\b"),
    re.compile(rb"\bsk-[A-Za-z0-9_-]{16,}\b"),
)
_COMMAND_LOG_SECRET_PATTERNS = (
    *_SECRET_TEXT_PATTERNS,
    re.compile(
        rb"(?i)\b(?:authorization|credential|password|private[_ -]?key|secret|token)"
        rb"\s*[:=]\s*[^\s]{4,}"
    ),
)
_COMMAND_LOG_TEMP_PATH = re.compile(
    rb"(?:/private)?/tmp(?:/[^\s]*)?|(?:/private)?/var/folders(?:/[^\s]*)?"
)
_COMMAND_LOG_USER_PATH = re.compile(
    rb"(?:file://)?/(?:Users|home)/[^\s/]+(?:/[^\s]*)?"
    rb"|(?:file:///)?[A-Za-z]:[\\/](?:Users|Documents and Settings)[\\/][^\s\\/]+"
)
_SENSITIVE_KEY_PARTS = frozenset(
    {
        "token",
        "authorization",
        "credential",
        "password",
        "privatekey",
        "apikey",
        "secret",
    }
)
_SAFE_SEMANTIC_KEYS = frozenset(
    {
        "$concordia_secret_sha256",
        "account_home_token",
        "authentication_mode",
        "auth_algorithm",
        "auth_account_count",
        "bcrypt_secret_file_match",
        "payment_secret_target_names",
        "proxy_secret_sha256",
        "repository_root_token",
        "temporary_root_token",
        "username_sha256",
    }
)
_SECRET_FILE_MATRIX: dict[str, tuple[str, frozenset[str]]] = {
    "LLM_API_KEY_FILE": (
        "llm_api_key",
        frozenset(
            {
                "gateway",
                "x402-provider",
                "rowan",
                "mercer",
                "verity",
                "alden",
                "locke",
                "wells",
            }
        ),
    ),
    "GATEWAY_SECRET_FILE": ("gateway_secret", frozenset({"gateway"})),
    "RECORDER_SUBMISSION_KEY_FILE": (
        "recorder_submission_key",
        frozenset({"gateway", "recorder-heartbeat"}),
    ),
    "TRIAGE_SUBMISSION_KEY_FILE": (
        "triage_submission_key",
        frozenset({"gateway", "rowan"}),
    ),
    "DIAGNOSIS_SUBMISSION_KEY_FILE": (
        "diagnosis_submission_key",
        frozenset({"gateway", "mercer"}),
    ),
    "SAFETY_REVIEWER_SUBMISSION_KEY_FILE": (
        "safety_reviewer_submission_key",
        frozenset({"gateway", "verity"}),
    ),
    "COMMANDER_SUBMISSION_KEY_FILE": (
        "commander_submission_key",
        frozenset({"gateway", "alden"}),
    ),
    "OPERATOR_SUBMISSION_KEY_FILE": (
        "operator_submission_key",
        frozenset({"gateway", "locke"}),
    ),
    "PROPOSAL_ROOM_API_KEY_FILE": (
        "proposal_room_api_key",
        frozenset({"gateway", "wells"}),
    ),
    "APPROVAL_PROXY_SECRET_FILE": ("approval_proxy_secret", frozenset({"gateway"})),
    "APPROVAL_UI_USER_FILE": ("approval_ui_user", frozenset({"gateway"})),
    "APPROVAL_UI_APPROVER_ID_FILE": (
        "approval_ui_approver_id",
        frozenset({"gateway"}),
    ),
    "APPROVAL_UI_BCRYPT_HASH_FILE": (
        "approval_ui_bcrypt_hash",
        frozenset({"gateway"}),
    ),
    "APPROVAL_UI_CSRF_SECRET_FILE": (
        "approval_ui_csrf_secret",
        frozenset({"gateway"}),
    ),
    "CONCORDIA_OPERATOR_TOKEN_FILE": (
        "concordia_operator_token",
        frozenset({"gateway"}),
    ),
    "CASPER_SECRET_KEY_PATH": (
        "casper_secret_key",
        frozenset({"gateway", "locke"}),
    ),
    "DEMO_CAPABILITY_HMAC_SECRET_FILE": (
        "demo_capability_hmac_secret",
        frozenset({"gateway"}),
    ),
    "DASHBOARD_DEMO_GATEWAY_TOKEN_FILE": (
        "dashboard_demo_gateway_token",
        frozenset({"gateway", "dashboard"}),
    ),
    "CSPR_CLOUD_ACCESS_TOKEN_FILE": (
        "cspr_cloud_access_token",
        frozenset({"mercer"}),
    ),
    "X402_CSPR_CLOUD_TOKEN_FILE": (
        "x402_official_cspr_cloud_token",
        frozenset({"x402-official"}),
    ),
    "X402_SIGNER_FILE": ("x402_official_signer", frozenset({"x402-official"})),
    "X402_GATEWAY_TOKEN_FILE": (
        "x402_official_gateway_token",
        frozenset({"gateway", "x402-official"}),
    ),
    "SAFEPAY_PROXY_SECRET_FILE": (
        "safepay_proxy_secret",
        frozenset({"gateway", "x402-provider"}),
    ),
    "SAFEPAY_QUOTE_TOKEN_SECRET_FILE": (
        "safepay_quote_token_secret",
        frozenset({"gateway"}),
    ),
    "SAFEPAY_CLIENT_KEY_HMAC_SECRET_FILE": (
        "safepay_client_key_hmac_secret",
        frozenset({"x402-provider"}),
    ),
}
_PAYMENT_SECRET_POLICY = {
    key: services for key, (_, services) in _SECRET_FILE_MATRIX.items()
}
_EXACT_SECRET_FILE_TARGETS = {
    key: f"/run/secrets/{target}" for key, (target, _) in _SECRET_FILE_MATRIX.items()
}
_SECRET_HOST_BASENAMES = {
    target: "casper_secret_key.pem" if target == "casper_secret_key" else target
    for target, _ in _SECRET_FILE_MATRIX.values()
}
_LEGACY_PAYMENT_SECRET_KEYS = frozenset(
    {
        "X402_FACILITATOR_TOKEN",
        "X402_PROVIDER_TOKEN",
        "CSPR_CLOUD_ACCESS_TOKEN",
        "X402_CSPR_CLOUD_TOKEN",
        "X402_GATEWAY_TOKEN",
        "SAFEPAY_CLIENT_KEY_HMAC_SECRET",
        "SAFEPAY_PROXY_SECRET",
        "SAFEPAY_QUOTE_TOKEN_SECRET",
        "X402_SIGNER",
        "APPROVAL_PROXY_SECRET",
        "APPROVAL_UI_USER",
        "APPROVAL_UI_APPROVER_ID",
        "APPROVAL_UI_BCRYPT_HASH",
        "APPROVAL_UI_CSRF_SECRET",
        "CONCORDIA_OPERATOR_TOKEN",
        "DEMO_CAPABILITY_HMAC_SECRET",
        "DASHBOARD_DEMO_GATEWAY_TOKEN",
    }
)
_FIXED_VM_IP = "47.84.232.193"
_FIXED_DNS_EXPECTATIONS: dict[str, dict[str, tuple[str, ...] | None]] = {
    "concordiadao.xyz": {"addresses": (_FIXED_VM_IP,), "cnames": ()},
    "www.concordiadao.xyz": {
        "addresses": (_FIXED_VM_IP,),
        "cnames": ("concordiadao.xyz.",),
    },
    "docs.concordiadao.xyz": {
        "addresses": None,
        "cnames": ("asadvendor-boop.github.io.",),
    },
    "x402.concordiadao.xyz": {"addresses": (_FIXED_VM_IP,), "cnames": ()},
    "concordia.47.84.232.193.sslip.io": {
        "addresses": (_FIXED_VM_IP,),
        "cnames": (),
    },
    "x402-provider.47.84.232.193.sslip.io": {
        "addresses": (_FIXED_VM_IP,),
        "cnames": (),
    },
}
_PUBLIC_ENV_KEYS = frozenset(
    {
        "CASPER_CHAIN_NAME",
        "CASPER_NETWORK",
        "NODE_ENV",
        "X402_NETWORK",
    }
)
_SECRET_CANARY_PATHS = tuple(
    [Path("/run/secrets") / target for target, _ in _SECRET_FILE_MATRIX.values()]
    + [
        Path("/opt/apps/concordia/secrets") / _SECRET_HOST_BASENAMES[target]
        for target, _ in _SECRET_FILE_MATRIX.values()
    ]
)
_APPROVAL_CADDY_SECRET_PATHS = (
    Path("/opt/apps/concordia/secrets/approval_ui_user"),
    Path("/opt/apps/concordia/secrets/approval_ui_bcrypt_hash"),
    Path("/opt/apps/concordia/secrets/approval_proxy_secret"),
)
_APPROVAL_CADDY_PROBE_PASSWORD_PATH = Path(
    "/run/concordia-release/approval_ui_probe_password"
)
_VERIFIER_PATHS = (
    # These closed tracked roots are the complete executable verifier surface.
    # Directory paths deliberately bind transitive local imports and build
    # helpers instead of relying on a hand-maintained leaf-file list.
    "shared",
    "scripts",
    "gateway",
    "x402_provider",
    "services/x402-official",
    "packages/verify",
    "contracts/odra-governance-receipt-v3",
    "pyproject.toml",
    "uv.lock",
    "tests/golden/envelope_v3",
    "handoff/HISTORICAL_ODRA_SHA256.txt",
    "handoff/HISTORICAL_ODRA_RECEIPTS_V1.json",
)


class ReleaseManifestError(ValueError):
    """A release observation, proof, lineage, or write gate failed closed."""


@dataclass(frozen=True)
class RawObservationSnapshot:
    """Ephemeral collector output.  Instances are never serialized directly."""

    observed_at: str
    compose: Mapping[str, object]
    runtime: Sequence[Mapping[str, object]]
    caddy: Mapping[str, object]
    public_probes: Sequence[Mapping[str, object]]
    pages: Mapping[str, object]
    npm: Mapping[str, object]
    rpc: Sequence[Mapping[str, object]]


class _Collector(Protocol):
    def collect(self) -> RawObservationSnapshot: ...


class _ProofVerifier(Protocol):
    def verify(
        self,
        *,
        artifact_id: str,
        artifact_path: str,
        artifact_bytes: bytes,
        artifact_document: dict[str, object],
    ) -> dict[str, object]: ...


@dataclass(frozen=True)
class _RepositoryRead:
    raw: bytes
    fingerprint: tuple[int, int, int, int]


@dataclass(frozen=True)
class _BoundFile:
    path: str
    raw: bytes
    sha256: str
    artifact_commit: str
    fingerprint: tuple[int, int, int, int]


@dataclass(frozen=True)
class _Artifact:
    artifact_id: str
    bound: _BoundFile
    document: dict[str, object]
    canonical: bytes
    schema_version: str
    captured_at: str
    source_commit: str
    deployment_commit: str
    observation_mode: str
    adapter_result: Mapping[str, Any] | None = None


def _utc_now() -> datetime:
    return datetime.now(UTC)


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
        raise ReleaseManifestError("release projection is not canonical JSON") from exc


def _reject_constant(value: str) -> None:
    raise ReleaseManifestError(f"non-finite JSON constant {value!r} is invalid")


def _pairs(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseManifestError("duplicate JSON key in release input")
        result[key] = value
    return result


def _strict_json(raw: bytes, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseManifestError(f"{label} is not strict JSON") from exc
    if type(value) is not dict:
        raise ReleaseManifestError(f"{label} must be a JSON object")
    return value, _canonical_json(value)


def _mapping(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ReleaseManifestError(f"{label} must be an object")
    return value


def _sequence(value: object, label: str) -> list[Any]:
    if type(value) is not list:
        raise ReleaseManifestError(f"{label} must be an array")
    return value


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise ReleaseManifestError(f"{label} must be non-empty text")
    return value


def _git40(value: object, label: str) -> str:
    value = _text(value, label)
    if _GIT40.fullmatch(value) is None:
        raise ReleaseManifestError(f"{label} must be lowercase git40")
    return value


def _hash32(value: object, label: str) -> str:
    value = _text(value, label)
    if _HEX32.fullmatch(value) is None:
        raise ReleaseManifestError(f"{label} must be lowercase SHA-256")
    return value


def _parse_timestamp(value: object, label: str) -> tuple[str, datetime]:
    value = _text(value, label)
    if _TIMESTAMP.fullmatch(value) is None:
        raise ReleaseManifestError(f"{label} must be canonical RFC3339 UTC-Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ReleaseManifestError(f"{label} is not a real UTC timestamp") from exc
    if parsed.utcoffset() != timedelta(0):
        raise ReleaseManifestError(f"{label} must be UTC")
    return value, parsed


def _format_now(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ReleaseManifestError("release clock must be UTC")
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _normalize_semantic_key(value: str) -> str:
    return normalize_sensitive_key(value)


def _assert_no_canary(raw: bytes, canaries: Sequence[bytes], label: str) -> None:
    if any(canary and canary in raw for canary in canaries):
        raise ReleaseManifestError(f"{label} contains reflected secret material")
    if any(pattern.search(raw) for pattern in _SECRET_TEXT_PATTERNS):
        raise ReleaseManifestError(f"{label} contains secret material")


def _assert_safe_projection(
    value: object,
    canaries: Sequence[bytes],
    label: str,
    *,
    _inside_environment_keys: bool = False,
) -> None:
    if type(value) is dict:
        for key, nested in value.items():
            if type(key) is not str:
                raise ReleaseManifestError(f"{label} has a non-text key")
            _assert_no_canary(key.encode("utf-8"), canaries, label)
            if key == "normalized_observation":
                _assert_safe_normalized_observation(
                    nested,
                    canaries,
                    f"{label}.normalized_observation",
                )
                continue
            normalized = _normalize_semantic_key(key)
            if key not in _SAFE_SEMANTIC_KEYS and any(
                part in normalized for part in _SENSITIVE_KEY_PARTS
            ):
                raise ReleaseManifestError(f"{label} contains a sensitive semantic key")
            _assert_safe_projection(
                nested,
                canaries,
                f"{label}.{key}",
                _inside_environment_keys=key
                in {"environment_keys", "payment_secret_target_names"},
            )
    elif type(value) is list:
        for index, nested in enumerate(value):
            _assert_safe_projection(
                nested,
                canaries,
                f"{label}[{index}]",
                _inside_environment_keys=_inside_environment_keys,
            )
    elif type(value) is str:
        _assert_no_canary(value.encode("utf-8"), canaries, label)
    elif value is not None and type(value) not in {bool, int, float}:
        raise ReleaseManifestError(f"{label} contains a non-JSON projection value")


def _assert_safe_normalized_observation(
    value: object,
    canaries: Sequence[bytes],
    label: str,
) -> None:
    if type(value) is dict:
        if set(value) in (
            {_NORMALIZED_BYTES_KEY},
            {_NORMALIZED_SECRET_KEY},
        ):
            _decode_normalized_observation(value)
            return
        for key, nested in value.items():
            if type(key) is not str:
                raise ReleaseManifestError(
                    f"{label} has a non-text normalized key"
                )
            _assert_no_canary(key.encode("utf-8"), canaries, label)
            _assert_safe_normalized_observation(
                nested,
                canaries,
                f"{label}.{key}",
            )
    elif type(value) is list:
        for index, nested in enumerate(value):
            _assert_safe_normalized_observation(
                nested,
                canaries,
                f"{label}[{index}]",
            )
    elif type(value) is str:
        _assert_no_canary(value.encode("utf-8"), canaries, label)
    elif value is not None and type(value) not in {bool, int, float}:
        raise ReleaseManifestError(
            f"{label} contains an unsafe normalized value"
        )


def _validate_relative_path(relative: str) -> tuple[str, ...]:
    path = PurePosixPath(relative)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or str(path) != relative
    ):
        raise ReleaseManifestError("release path is not repository-relative")
    return path.parts


def _safe_open_flags(*, directory: bool = False) -> int:
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    return flags


def _root_fd(root: Path) -> int:
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise ReleaseManifestError("repository root is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseManifestError("repository root cannot be a symlink")
    try:
        return os.open(root, _safe_open_flags(directory=True))
    except OSError as exc:
        raise ReleaseManifestError("repository root cannot be opened safely") from exc


def _read_bounded_repository_file(
    root: Path, relative: str, limit: int
) -> _RepositoryRead:
    parts = _validate_relative_path(relative)
    descriptor = _root_fd(root)
    try:
        for part in parts[:-1]:
            next_descriptor = os.open(
                part,
                _safe_open_flags(directory=True),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        file_descriptor = os.open(
            parts[-1], _safe_open_flags(directory=False), dir_fd=descriptor
        )
        try:
            before = os.fstat(file_descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ReleaseManifestError(f"{relative} must be a regular file")
            if before.st_size > limit:
                raise ReleaseManifestError(f"{relative} exceeds its size bound")
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining:
                chunk = os.read(file_descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > limit:
                raise ReleaseManifestError(f"{relative} exceeds its size bound")
            after = os.fstat(file_descriptor)
            fingerprint = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            if fingerprint != (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ):
                raise ReleaseManifestError(f"{relative} changed while being read")
            return _RepositoryRead(raw=raw, fingerprint=fingerprint)
        finally:
            os.close(file_descriptor)
    except FileNotFoundError as exc:
        raise ReleaseManifestError(
            f"required release input {relative} is unavailable"
        ) from exc
    except OSError as exc:
        raise ReleaseManifestError(f"{relative} cannot be read safely") from exc
    finally:
        os.close(descriptor)


def _read_secret_file(path: Path, limit: int = 64 * 1024) -> bytes:
    try:
        descriptor = os.open(path, _safe_open_flags(directory=False))
    except FileNotFoundError:
        return b""
    except OSError as exc:
        raise ReleaseManifestError("a fixed release secret file is unsafe") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ReleaseManifestError("a fixed release secret file is invalid")
        raw = os.read(descriptor, limit + 1)
        if len(raw) > limit:
            raise ReleaseManifestError("a fixed release secret file is oversized")
        return raw.strip()
    finally:
        os.close(descriptor)


def run_committed_python_artifact_verifier(
    verifier_name: str,
    artifact_path: Path,
) -> dict[str, object]:
    """Run one fixed Python proof verifier on a bound private data snapshot."""

    if verifier_name not in {"historical", "v3", "card_roots", "registry"}:
        raise ReleaseManifestError("committed Python verifier identity is unknown")
    if not isinstance(artifact_path, Path) or not artifact_path.is_absolute():
        raise ReleaseManifestError("committed verifier input path is invalid")
    try:
        descriptor = os.open(artifact_path, _safe_open_flags(directory=False))
    except OSError as exc:
        raise ReleaseManifestError("committed verifier input is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_mode & 0o777 != 0o400
            or before.st_size > _ARTIFACT_LIMIT
        ):
            raise ReleaseManifestError("committed verifier input is not bound")
        chunks: list[bytes] = []
        remaining = _ARTIFACT_LIMIT + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        artifact_bytes = b"".join(chunks)
        if len(artifact_bytes) > _ARTIFACT_LIMIT:
            raise ReleaseManifestError("committed verifier input exceeds size bound")
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ):
            raise ReleaseManifestError("committed verifier input changed")
    finally:
        os.close(descriptor)

    if verifier_name == "historical":
        from shared.historical_odra_artifact import (
            verify_historical_odra_artifact,
        )

        result = verify_historical_odra_artifact(artifact_bytes)
    elif verifier_name == "v3":
        from scripts.verify_v3_proof import verify_v3_proof_document

        document, _ = _strict_json(artifact_bytes, "committed v3 proof input")
        result = verify_v3_proof_document(document)
    elif verifier_name == "card_roots":
        from scripts.generate_card_chain_release_roots import (
            derive_card_chain_release_roots,
        )

        result = {
            "payload_b64": base64.b64encode(
                derive_card_chain_release_roots(artifact_bytes)
            ).decode("ascii")
        }
    else:
        document, _ = _strict_json(artifact_bytes, "committed proof registry input")
        validated = validate_release_registry_document(document)
        public_items = _sequence(
            validated.get("public_items"), "committed registry public items"
        )
        internal_records = _sequence(
            validated.get("internal_records"), "committed registry internal records"
        )
        result = {
            "valid": True,
            "public_item_count": len(public_items),
            "internal_record_count": len(internal_records),
            "public_items_sha256": hashlib.sha256(
                _canonical_json(public_items)
            ).hexdigest(),
            "internal_records_sha256": hashlib.sha256(
                _canonical_json(internal_records)
            ).hexdigest(),
        }
    projection = _mapping(result, "committed Python verifier result")
    _assert_safe_projection(projection, (), "committed Python verifier result")
    return dict(projection)


def _validate_approval_caddy_secret_files() -> tuple[bytes, bytes, bytes]:
    """Fail closed on Caddy 2.8 file-placeholder whitespace and mode hazards."""

    values: list[bytes] = []
    for path in _APPROVAL_CADDY_SECRET_PATHS:
        try:
            descriptor = os.open(path, _safe_open_flags(directory=False))
        except OSError as exc:
            raise ReleaseManifestError(
                "an approval Caddy credential file is unavailable or unsafe"
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size < 1
                or metadata.st_size > 64 * 1024
                or stat.S_IMODE(metadata.st_mode) & 0o077
            ):
                raise ReleaseManifestError(
                    "an approval Caddy credential file is not restricted"
                )
            raw = os.read(descriptor, metadata.st_size + 1)
            if (
                len(raw) != metadata.st_size
                or raw != raw.strip()
                or b"\x00" in raw
                or not raw
            ):
                raise ReleaseManifestError(
                    "an approval Caddy credential file is not byte-exact"
                )
            values.append(raw)
        finally:
            os.close(descriptor)
    username, bcrypt_hash, proxy_secret = values
    if (
        len(username) > 128
        or any(byte < 0x21 or byte > 0x7E for byte in username)
        or b":" in username
    ):
        raise ReleaseManifestError("the approval Caddy username is invalid")
    if re.fullmatch(rb"\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}", bcrypt_hash) is None:
        raise ReleaseManifestError("the approval Caddy bcrypt hash is invalid")
    if len(proxy_secret) < 32:
        raise ReleaseManifestError("the approval Caddy proxy secret is too short")
    return username, bcrypt_hash, proxy_secret


def _consume_approval_probe_password(path: Path) -> bytes:
    """Read then unlink the one-use human password without following links."""

    try:
        descriptor = os.open(path, _safe_open_flags(directory=False))
    except OSError as exc:
        raise ReleaseManifestError(
            "the one-use approval probe password is unavailable or unsafe"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_size < 1
            or metadata.st_size > 1024
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ReleaseManifestError(
                "the one-use approval probe password file is not restricted"
            )
        try:
            os.unlink(path)
        except OSError as exc:
            raise ReleaseManifestError(
                "the one-use approval probe password cannot be consumed"
            ) from exc
        raw = os.read(descriptor, metadata.st_size + 1)
        if (
            len(raw) != metadata.st_size
            or raw != raw.strip()
            or b"\x00" in raw
            or b"\r" in raw
            or b"\n" in raw
            or not raw
        ):
            raise ReleaseManifestError(
                "the one-use approval probe password is not byte-exact"
            )
        return raw
    finally:
        os.close(descriptor)


def _load_secret_canaries() -> tuple[bytes, ...]:
    return tuple(_load_secret_variant_digests())


def _load_secret_variant_digests() -> dict[bytes, str]:
    values: dict[bytes, str] = {}
    for path in _SECRET_CANARY_PATHS:
        value = _read_secret_file(path)
        if value and len(value) < 16:
            if path.name == "approval_ui_user":
                # This public Basic-Auth identifier is projected only by digest,
                # but it is not credential material and is too short for
                # substring DLP without false positives.
                continue
            raise ReleaseManifestError(
                "a fixed release secret is shorter than the DLP minimum"
            )
        digest = hashlib.sha256(value).hexdigest() if value else ""
        for variant in secret_variants(value):
            previous = values.get(variant)
            if previous is not None and previous != digest:
                raise ReleaseManifestError("secret canary encoding is ambiguous")
            values[variant] = digest
    return values


_NORMALIZED_BYTES_KEY = "$concordia_bytes_b64"
_NORMALIZED_SECRET_KEY = "$concordia_secret_sha256"
_NORMALIZED_ARGV_DIGEST_KEY = "$concordia_argv_sha256"


def _encode_normalized_observation(
    value: object,
    *,
    secret_digests: Mapping[bytes, str],
) -> object:
    if type(value) is bytes:
        digest = secret_digests.get(value)
        if digest is not None:
            return {_NORMALIZED_SECRET_KEY: digest}
        if any(canary in value for canary in secret_digests):
            raise ReleaseManifestError(
                "normalized observation contains embedded secret material"
            )
        return {_NORMALIZED_BYTES_KEY: base64.b64encode(value).decode("ascii")}
    if type(value) is str:
        raw = value.encode("utf-8")
        digest = secret_digests.get(raw)
        if digest is not None:
            return {_NORMALIZED_SECRET_KEY: digest}
        if any(canary in raw for canary in secret_digests):
            raise ReleaseManifestError(
                "normalized observation contains embedded secret material"
            )
        return value
    if type(value) is dict:
        result: dict[str, object] = {}
        for key, nested in value.items():
            if type(key) is not str or key in {
                _NORMALIZED_BYTES_KEY,
                _NORMALIZED_SECRET_KEY,
            }:
                raise ReleaseManifestError(
                    "normalized observation contains an unsafe key"
                )
            result[key] = _encode_normalized_observation(
                nested,
                secret_digests=secret_digests,
            )
        return result
    if type(value) in {list, tuple}:
        return [
            _encode_normalized_observation(
                nested,
                secret_digests=secret_digests,
            )
            for nested in value
        ]
    if value is None or type(value) in {bool, int, float}:
        return value
    raise ReleaseManifestError("normalized observation contains an unsafe value")


def _decode_normalized_observation(value: object) -> object:
    if type(value) is dict:
        if set(value) == {_NORMALIZED_BYTES_KEY}:
            encoded = value[_NORMALIZED_BYTES_KEY]
            if type(encoded) is not str:
                raise ReleaseManifestError(
                    "normalized byte observation is malformed"
                )
            try:
                return base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ReleaseManifestError(
                    "normalized byte observation is malformed"
                ) from exc
        if set(value) == {_NORMALIZED_SECRET_KEY}:
            return {
                _NORMALIZED_SECRET_KEY: _hash32(
                    value[_NORMALIZED_SECRET_KEY],
                    "normalized secret digest",
                )
            }
        if any(
            key in {_NORMALIZED_BYTES_KEY, _NORMALIZED_SECRET_KEY} for key in value
        ):
            raise ReleaseManifestError("normalized observation tag is ambiguous")
        return {
            key: _decode_normalized_observation(nested)
            for key, nested in value.items()
        }
    if type(value) is list:
        return [_decode_normalized_observation(nested) for nested in value]
    if value is None or type(value) in {str, bool, int, float}:
        return value
    raise ReleaseManifestError("normalized observation is malformed")


def _sanitized_command_environment() -> dict[str, str]:
    return {
        "CI": "1",
        "LC_ALL": "C",
        "LANG": "C",
        "NO_COLOR": "1",
        "HOME": "/var/empty",
        "XDG_CACHE_HOME": "/var/empty",
        "XDG_CONFIG_HOME": "/var/empty",
        "NPM_CONFIG_USERCONFIG": "/dev/null",
        "NPM_CONFIG_GLOBALCONFIG": "/dev/null",
        "NPM_CONFIG_REGISTRY": "https://registry.npmjs.org/",
        "DOCKER_HOST": "unix:///var/run/docker.sock",
    }


def _command_environment_sha256() -> str:
    return hashlib.sha256(_canonical_json(_sanitized_command_environment())).hexdigest()


@lru_cache(maxsize=8)
def _accepted_host_authority(
    repository_root: str,
    source_commit: str,
    receipt_raw: bytes,
) -> HostToolchainAuthority:
    document, canonical = _strict_json(receipt_raw, "host-toolchain receipt")
    if canonical != receipt_raw:
        raise ReleaseManifestError("host-toolchain receipt is not canonical")
    try:
        return accepted_tool_authority_from_receipt(
            document,
            repository_root=Path(repository_root),
            source_commit=source_commit,
        )
    except BoundCommandError as exc:
        raise ReleaseManifestError("host-toolchain authority is invalid") from exc


def _host_toolchain_binding(
    root: Path,
) -> tuple[HostToolchainAuthority, _BoundFile, dict[str, object]]:
    bound = _load_bound_file(root, BOUND_HOST_TOOLCHAIN_RECEIPT_PATH, _CONTROL_LIMIT)
    document, canonical = _strict_json(bound.raw, "host-toolchain receipt")
    if canonical != bound.raw:
        raise ReleaseManifestError("host-toolchain receipt is not canonical")
    source_commit = _git40(
        document.get("source_commit"),
        "host-toolchain source commit",
    )
    authority = _accepted_host_authority(
        root.resolve(strict=True).as_posix(),
        source_commit,
        bound.raw,
    )
    projection = {
        "schema_version": BOUND_HOST_TOOLCHAIN_RECEIPT_SCHEMA_VERSION,
        "path": BOUND_HOST_TOOLCHAIN_RECEIPT_PATH,
        "sha256": bound.sha256,
        "artifact_commit": bound.artifact_commit,
        "source_commit": source_commit,
        "runner_sha256": _hash32(
            document.get("runner_sha256"),
            "host-toolchain runner SHA-256",
        ),
        "host_id": _hash32(document.get("host_id"), "host-toolchain host ID"),
        "tools_sha256": hashlib.sha256(
            _canonical_json(_mapping(document.get("tools"), "host-toolchain tools"))
        ).hexdigest(),
    }
    _assert_safe_projection(projection, (), "host-toolchain binding")
    return authority, bound, projection


def _post_freeze_corrections_projection(
    root: Path,
    *,
    integration_commit: str,
) -> tuple[dict[str, object], list[_BoundFile]]:
    integration_commit = _git40(integration_commit, "integration commit")
    authority_bound = _load_bound_file(
        root,
        _G1_POST_FREEZE_CORRECTIONS_PATH,
        _CONTROL_LIMIT,
    )
    if not _is_ancestor(
        root,
        authority_bound.artifact_commit,
        integration_commit,
    ):
        raise ReleaseManifestError(
            "G1 post-freeze corrections postdate integration"
        )
    authority_document, _ = _strict_json(
        authority_bound.raw,
        "G1 post-freeze corrections",
    )
    if set(authority_document) != {
        "schema_id",
        "status",
        "authority_tag",
        "authority_commit",
        "reason",
        "corrections",
    }:
        raise ReleaseManifestError(
            "G1 post-freeze correction authority field set differs"
        )
    authority_rows = _sequence(
        authority_document.get("corrections"),
        "G1 post-freeze corrections",
    )
    correction_ids: list[str] = []
    for raw_row in authority_rows:
        row = _mapping(raw_row, "G1 post-freeze correction")
        if set(row) != {
            "id",
            "affected_schema",
            "rules",
            "acceptance_tests",
        }:
            raise ReleaseManifestError(
                "G1 post-freeze correction field set differs"
            )
        correction_ids.append(
            _text(row.get("id"), "G1 post-freeze correction ID")
        )
        _text(
            row.get("affected_schema"),
            "G1 post-freeze affected schema",
        )
        rules = _sequence(row.get("rules"), "G1 post-freeze correction rules")
        acceptance = _sequence(
            row.get("acceptance_tests"),
            "G1 post-freeze correction acceptance tests",
        )
        if not rules or not acceptance:
            raise ReleaseManifestError(
                "G1 post-freeze correction lacks rules or acceptance tests"
            )
        for value in (*rules, *acceptance):
            _text(value, "G1 post-freeze correction text")
    if (
        authority_document.get("schema_id")
        != _G1_POST_FREEZE_CORRECTIONS_SCHEMA_ID
        or authority_document.get("status") != "required"
        or authority_document.get("authority_tag") != G1_FREEZE_TAG
        or authority_document.get("authority_commit") != G1_FREEZE_COMMIT
        or tuple(correction_ids) != _G1_POST_FREEZE_CORRECTION_IDS
    ):
        raise ReleaseManifestError(
            "G1 post-freeze correction authority differs"
        )
    authority_projection = {
        "path": _G1_POST_FREEZE_CORRECTIONS_PATH,
        "sha256": authority_bound.sha256,
        "artifact_commit": authority_bound.artifact_commit,
        "schema_id": _G1_POST_FREEZE_CORRECTIONS_SCHEMA_ID,
        "status": "required",
        "authority_tag": G1_FREEZE_TAG,
        "authority_commit": G1_FREEZE_COMMIT,
        "correction_ids": correction_ids,
    }
    required_markers = {
        "gateway/app.py": (
            b"/x402/v2/payment-intent",
            b"quote_capability",
            b"SAFEPAY_QUOTE_TOKEN_SECRET",
            b"verify_safepay_v2_quote_capability",
        ),
        "shared/x402_payments.py": (
            b"safepay-wallet-intent-request-v2",
            b"safepay-wallet-intent-v2",
            b"X-Concordia-SafePay-Quote-Capability",
            b"sqc1",
        ),
        COMPOSE_FILE_PATH: (
            b"SAFEPAY_QUOTE_TOKEN_SECRET_FILE",
            b"/run/secrets/safepay_quote_token_secret",
        ),
        "tests/test_safepay_gateway_v2.py": (
            b"test_wallet_intent_requires_an_issuer_authenticated_quote_capability",
            b"test_missing_quote_capability_secret_fails_before_provider_io",
        ),
        "tests/test_compose_secret_scope.py": (b"safepay_quote_token_secret",),
    }
    bindings: list[dict[str, object]] = []
    bounds: list[_BoundFile] = [authority_bound]
    for relative in _SAFEPAY_GATEWAY_CORRECTION_PATHS:
        bound = _load_bound_file(root, relative, _ARTIFACT_LIMIT)
        if not _is_ancestor(root, bound.artifact_commit, integration_commit):
            raise ReleaseManifestError(
                "SafePay post-freeze correction postdates integration"
            )
        if any(marker not in bound.raw for marker in required_markers[relative]):
            raise ReleaseManifestError(
                "SafePay post-freeze correction implementation differs"
            )
        bounds.append(bound)
        bindings.append(
            {
                "path": relative,
                "sha256": bound.sha256,
                "artifact_commit": bound.artifact_commit,
            }
        )
    correction, _ = _strict_json(
        _canonical_json(_SAFEPAY_GATEWAY_CORRECTION),
        "SafePay post-freeze correction",
    )
    correction["implementation_bindings"] = bindings
    projection = {
        "schema_version": POST_FREEZE_CORRECTIONS_SCHEMA_VERSION,
        "authority": authority_projection,
        "corrections": [correction],
    }
    _assert_safe_projection(projection, (), "post-freeze corrections")
    return projection, bounds


def _run(
    root: Path,
    arguments: Sequence[str],
    *,
    limit: int = _GIT_OUTPUT_LIMIT,
    timeout: int = 120,
    check: bool = True,
    repository_root: Path | None = None,
    command_asset_root: Path | None = None,
    bound_data_inputs: Sequence[Path] = (),
) -> BoundCommandResult:
    if (
        not arguments
        or any(type(argument) is not str for argument in arguments)
        or not str(arguments[0])
        or os.path.isabs(str(arguments[0]))
    ):
        raise ReleaseManifestError("fixed release command is empty")
    cwd = root.resolve(strict=True)
    tool_id = str(arguments[0])
    argv = tuple(str(argument) for argument in arguments)
    environment = _sanitized_command_environment()
    private_npm_environment: tempfile.TemporaryDirectory[str] | None = None
    authority: HostToolchainAuthority | None = None
    if tool_id == "git":
        argv = (
            "git",
            "--no-replace-objects",
            *BOUND_GIT_CONFIG_OVERRIDES,
            *argv[1:],
        )
        environment.update(
            {
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
            }
        )
    else:
        authority_root = (repository_root or root).resolve(strict=True)
        authority, _, _ = _host_toolchain_binding(authority_root)
    if tool_id == "npm":
        private_npm_environment = tempfile.TemporaryDirectory(
            prefix="concordia-release-npm-"
        )
        npm_root = Path(private_npm_environment.name).resolve(strict=True)
        npm_home = npm_root / "home"
        npm_cache = npm_root / "cache"
        npm_home.mkdir(mode=0o700)
        npm_cache.mkdir(mode=0o700)
        npmrc = npm_root / "npmrc"
        descriptor = os.open(
            npmrc,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            npmrc_raw = (
                b"registry=https://registry.npmjs.org/\n"
                b"ignore-scripts=true\n"
                b"audit=false\n"
                b"fund=false\n"
                b"update-notifier=false\n"
            )
            written = os.write(descriptor, npmrc_raw)
            if written != len(npmrc_raw):
                raise ReleaseManifestError(
                    "private npm configuration write was incomplete"
                )
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        environment.update(
            {
                "HOME": npm_home.as_posix(),
                "NPM_CONFIG_CACHE": npm_cache.as_posix(),
                "NPM_CONFIG_USERCONFIG": npmrc.as_posix(),
                "NPM_CONFIG_GLOBALCONFIG": "/dev/null",
                "NPM_CONFIG_REGISTRY": "https://registry.npmjs.org/",
            }
        )
    try:
        return run_bound_command(
            cwd=cwd,
            tool_id=tool_id,
            argv=argv,
            env=environment,
            stdout_limit=limit,
            stderr_limit=_CONTROL_LIMIT,
            timeout_s=timeout,
            check=check,
            accepted_authority=authority,
            command_asset_root=(
                command_asset_root.resolve(strict=True)
                if command_asset_root is not None
                else None
            ),
            bound_data_inputs=tuple(
                path.resolve(strict=True) for path in bound_data_inputs
            ),
        )
    except (BoundCommandError, OSError) as exc:
        raise ReleaseManifestError("fixed release command failed") from exc
    finally:
        if private_npm_environment is not None:
            private_npm_environment.cleanup()


def _git(
    root: Path,
    arguments: Sequence[str],
    *,
    check: bool = True,
    limit: int = _GIT_OUTPUT_LIMIT,
) -> BoundCommandResult:
    return _run(root, ["git", *arguments], check=check, limit=limit)


def _require_repository(root: Path) -> None:
    result = _git(root, ["rev-parse", "--show-toplevel"], limit=_CONTROL_LIMIT)
    try:
        actual = Path(result.stdout.decode("utf-8").strip()).resolve()
    except UnicodeDecodeError as exc:
        raise ReleaseManifestError("repository identity is malformed") from exc
    if actual != root.resolve():
        raise ReleaseManifestError("repository root is not the Git top level")


def _require_clean_worktree(root: Path) -> None:
    result = _git(
        root,
        [
            "status",
            "--ignored=matching",
            "--porcelain=v1",
            "--untracked-files=all",
        ],
        limit=_GIT_OUTPUT_LIMIT,
    )
    try:
        rows = result.stdout.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise ReleaseManifestError("release worktree status is malformed") from exc
    ignored_prefixes = (
        ".pytest_cache/",
        ".ruff_cache/",
        ".venv/",
        "node_modules/",
        "dashboard/.next/",
        "dashboard/node_modules/",
        "dashboard/playwright-report/",
        "dashboard/test-results/",
        "packages/verify/node_modules/",
        "packages/verify/dist/",
        "services/x402-official/node_modules/",
        "services/x402-official/dist/",
        "contracts/odra-governance-receipt-v3/target/",
    )
    for row in rows:
        if not row.startswith("!! "):
            raise ReleaseManifestError("release worktree is not clean")
        path = row[3:]
        if not any(path == prefix.rstrip("/") or path.startswith(prefix) for prefix in ignored_prefixes):
            raise ReleaseManifestError(
                f"release worktree has non-allowlisted ignored output: {path}"
            )


def _latest_path_commit(root: Path, relative: str) -> str:
    result = _git(
        root,
        ["log", "-1", "--format=%H", "--", relative],
        limit=_CONTROL_LIMIT,
    )
    try:
        value = result.stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ReleaseManifestError("Git path commit is malformed") from exc
    return _git40(value, f"{relative} artifact commit")


def _first_path_add_commit(root: Path, relative: str) -> str:
    _validate_relative_path(relative)
    result = _git(
        root,
        [
            "log",
            "--diff-filter=A",
            "--reverse",
            "--format=%H",
            "--",
            relative,
        ],
        limit=_CONTROL_LIMIT,
    )
    try:
        commits = [
            _git40(line, f"{relative} first-add commit")
            for line in result.stdout.decode("ascii", errors="strict").splitlines()
            if line
        ]
    except UnicodeDecodeError as exc:
        raise ReleaseManifestError("Git first-add history is malformed") from exc
    if not commits:
        raise ReleaseManifestError(f"{relative} has no committed first-add")
    return commits[0]


def _git_blob(root: Path, commit: str, relative: str, limit: int) -> bytes:
    _git40(commit, "Git blob commit")
    _validate_relative_path(relative)
    result = _git(root, ["show", f"{commit}:{relative}"], limit=limit + 1)
    if len(result.stdout) > limit:
        raise ReleaseManifestError(f"{relative} committed blob exceeds size bound")
    return result.stdout


def _commit_exists(root: Path, commit: str) -> bool:
    result = _git(
        root,
        ["cat-file", "-e", f"{commit}^{{commit}}"],
        check=False,
        limit=_CONTROL_LIMIT,
    )
    return result.returncode == 0


def _is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    result = _git(
        root,
        ["merge-base", "--is-ancestor", ancestor, descendant],
        check=False,
        limit=_CONTROL_LIMIT,
    )
    if result.returncode not in {0, 1}:
        raise ReleaseManifestError("Git ancestry check failed")
    return result.returncode == 0


def _require_ordered_ancestry(
    root: Path,
    *,
    source_commit: str,
    deployment_commit: str,
    artifact_commit: str,
    historical_exception: bool,
) -> None:
    for value in (source_commit, deployment_commit, artifact_commit):
        if not _commit_exists(root, value):
            raise ReleaseManifestError(
                "artifact lineage references an unavailable commit"
            )
    if historical_exception:
        # The sole exception is the frozen v1 historical artifact: both named
        # ancestors must lead to its artifact commit, but their mutual order is
        # not rewritten retroactively.
        if not _is_ancestor(root, source_commit, artifact_commit) or not _is_ancestor(
            root, deployment_commit, artifact_commit
        ):
            raise ReleaseManifestError(
                "historical lineage is not bound to its artifact"
            )
    else:
        if not _is_ancestor(root, source_commit, deployment_commit):
            raise ReleaseManifestError(
                "source to deployment ancestor relation is invalid"
            )
        if not _is_ancestor(root, deployment_commit, artifact_commit):
            raise ReleaseManifestError(
                "deployment commit must be an ancestor of artifact commit"
            )
    if not _is_ancestor(root, artifact_commit, "HEAD"):
        raise ReleaseManifestError(
            "artifact commit must be an ancestor of release HEAD"
        )


def _load_bound_file(root: Path, relative: str, limit: int) -> _BoundFile:
    read = _read_bounded_repository_file(root, relative, limit)
    artifact_commit = _latest_path_commit(root, relative)
    committed = _git_blob(root, artifact_commit, relative, limit)
    if committed != read.raw:
        raise ReleaseManifestError(f"{relative} differs from committed bytes")
    return _BoundFile(
        path=relative,
        raw=read.raw,
        sha256=hashlib.sha256(read.raw).hexdigest(),
        artifact_commit=artifact_commit,
        fingerprint=read.fingerprint,
    )


def _bound_repository_directory_sha256(
    root: Path,
    relative: str,
    *,
    total_limit: int = 128 * 1024 * 1024,
    file_limit: int = _ARTIFACT_LIMIT,
    file_count_limit: int = 4096,
) -> str:
    """Hash one clean, tracked directory without following filesystem links."""

    parts = _validate_relative_path(relative)
    directory = root.joinpath(*parts)
    try:
        metadata = directory.lstat()
    except OSError as exc:
        raise ReleaseManifestError(
            f"bound Compose directory {relative} is unavailable"
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseManifestError(
            f"bound Compose directory {relative} is not a safe directory"
        )

    drift = _git(
        root,
        ["diff", "--quiet", "HEAD", "--", relative],
        check=False,
        limit=_CONTROL_LIMIT,
    )
    if drift.returncode != 0:
        if drift.returncode == 1:
            raise ReleaseManifestError(
                f"bound Compose directory {relative} differs from HEAD"
            )
        raise ReleaseManifestError(
            f"bound Compose directory {relative} cannot be compared to HEAD"
        )
    untracked = _git(
        root,
        ["ls-files", "--others", "--exclude-standard", "-z", "--", relative],
        limit=_GIT_OUTPUT_LIMIT,
    ).stdout
    if untracked:
        raise ReleaseManifestError(
            f"bound Compose directory {relative} contains untracked files"
        )
    listing = _git(
        root,
        ["ls-files", "-z", "--", relative],
        limit=_GIT_OUTPUT_LIMIT,
    ).stdout
    try:
        files = sorted(
            path
            for path in listing.decode("utf-8", errors="strict").split("\0")
            if path
        )
    except UnicodeDecodeError as exc:
        raise ReleaseManifestError(
            f"bound Compose directory {relative} has a non-UTF-8 path"
        ) from exc
    prefix = relative + "/"
    if (
        not files
        or len(files) > file_count_limit
        or any(not path.startswith(prefix) for path in files)
    ):
        raise ReleaseManifestError(
            f"bound Compose directory {relative} file inventory is invalid"
        )

    digest = hashlib.sha256()
    digest.update(b"CONCORDIA_COMPOSE_BOUND_DIRECTORY_V1\0")
    digest.update(len(files).to_bytes(8, "big"))
    total = 0
    for path in files:
        read = _read_bounded_repository_file(root, path, file_limit)
        total += len(read.raw)
        if total > total_limit:
            raise ReleaseManifestError(
                f"bound Compose directory {relative} exceeds its total size limit"
            )
        encoded_path = path.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(4, "big"))
        digest.update(encoded_path)
        digest.update(len(read.raw).to_bytes(8, "big"))
        digest.update(hashlib.sha256(read.raw).digest())
    return digest.hexdigest()


def _bound_external_directory_sha256(
    directory: Path,
    *,
    label: str,
    total_limit: int = 128 * 1024 * 1024,
    file_limit: int = _ARTIFACT_LIMIT,
    file_count_limit: int = 4096,
) -> str:
    """Hash one release-private directory without serializing its contents."""

    try:
        metadata = directory.lstat()
    except OSError as exc:
        raise ReleaseManifestError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseManifestError(f"{label} is not a safe directory")
    files: list[tuple[str, Path]] = []
    try:
        for current, directories, names in os.walk(
            directory,
            topdown=True,
            followlinks=False,
        ):
            current_path = Path(current)
            for name in directories:
                nested = current_path / name
                nested_metadata = nested.lstat()
                if stat.S_ISLNK(nested_metadata.st_mode) or not stat.S_ISDIR(
                    nested_metadata.st_mode
                ):
                    raise ReleaseManifestError(
                        f"{label} contains an unsafe directory entry"
                    )
            for name in names:
                nested = current_path / name
                nested_metadata = nested.lstat()
                if stat.S_ISLNK(nested_metadata.st_mode) or not stat.S_ISREG(
                    nested_metadata.st_mode
                ):
                    raise ReleaseManifestError(
                        f"{label} contains an unsafe file entry"
                    )
                relative = nested.relative_to(directory).as_posix()
                _validate_relative_path(relative)
                files.append((relative, nested))
    except OSError as exc:
        raise ReleaseManifestError(f"{label} cannot be inventoried safely") from exc
    files.sort()
    if not files or len(files) > file_count_limit:
        raise ReleaseManifestError(f"{label} file inventory is invalid")

    digest = hashlib.sha256()
    digest.update(b"CONCORDIA_COMPOSE_BOUND_DIRECTORY_V1\0")
    digest.update(len(files).to_bytes(8, "big"))
    total = 0
    for relative, path in files:
        flags = _safe_open_flags(directory=False)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise ReleaseManifestError(f"{label} file is unreadable") from exc
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > file_limit:
                raise ReleaseManifestError(f"{label} file exceeds its policy")
            chunks: list[bytes] = []
            remaining = file_limit + 1
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            if (
                len(raw) > file_limit
                or (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                )
                != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                )
            ):
                raise ReleaseManifestError(f"{label} changed while being read")
        finally:
            os.close(descriptor)
        total += len(raw)
        if total > total_limit:
            raise ReleaseManifestError(f"{label} exceeds its total size limit")
        encoded_path = relative.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(4, "big"))
        digest.update(encoded_path)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(hashlib.sha256(raw).digest())
    return digest.hexdigest()


def _load_immutable_bound_file(
    root: Path,
    relative: str,
    limit: int,
    *,
    artifact_commit: str | None = None,
) -> _BoundFile:
    first_add = _first_path_add_commit(root, relative)
    expected_commit = (
        first_add
        if artifact_commit is None
        else _git40(artifact_commit, f"{relative} pinned artifact commit")
    )
    if expected_commit != first_add or _latest_path_commit(root, relative) != first_add:
        raise ReleaseManifestError(f"{relative} is not an immutable first-add artifact")
    committed = _git_blob(root, first_add, relative, limit)
    current = _read_bounded_repository_file(root, relative, limit)
    if current.raw != committed:
        raise ReleaseManifestError(f"{relative} differs from its immutable commit")
    return _BoundFile(
        path=relative,
        raw=committed,
        sha256=hashlib.sha256(committed).hexdigest(),
        artifact_commit=first_add,
        fingerprint=current.fingerprint,
    )


def _repository_directory_names(root: Path, relative: str) -> set[str]:
    parts = _validate_relative_path(relative)
    descriptor = _root_fd(root)
    try:
        for part in parts:
            next_descriptor = os.open(
                part,
                _safe_open_flags(directory=True),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        names = os.listdir(descriptor)
        if any(type(name) is not str or name in {"", ".", ".."} for name in names):
            raise ReleaseManifestError("command gate log directory is malformed")
        return set(names)
    except FileNotFoundError as exc:
        raise ReleaseManifestError(
            f"required command gate log directory {relative} is unavailable"
        ) from exc
    except OSError as exc:
        raise ReleaseManifestError(
            f"command gate log directory {relative} cannot be read safely"
        ) from exc
    finally:
        os.close(descriptor)


def _tagged_freeze_commit(root: Path) -> str:
    value = (
        _git(
            root,
            ["rev-parse", f"{G1_FREEZE_TAG}^{{commit}}"],
            limit=_CONTROL_LIMIT,
        )
        .stdout.decode("ascii", errors="strict")
        .strip()
    )
    observed = _git40(value, "G1 freeze tag commit")
    if observed != G1_FREEZE_COMMIT:
        raise ReleaseManifestError("G1 freeze tag commit differs from the contract")
    return observed


def _validate_g1_freeze_authority(
    root: Path,
    *,
    expected_tag: str,
    expected_tag_object: str,
    expected_commit: str,
) -> dict[str, object]:
    """Bind the exact annotated tag and every tagged repository authority."""

    expected_tag_object = _git40(expected_tag_object, "G1 tag object")
    expected_commit = _git40(expected_commit, "G1 expected commit")
    if (
        expected_tag != G1_FREEZE_TAG
        or expected_tag_object != G1_FREEZE_TAG_OBJECT
        or expected_commit != G1_FREEZE_COMMIT
    ):
        raise ReleaseManifestError("G1 freeze tag name differs")
    tag_object = (
        _git(root, ["rev-parse", f"refs/tags/{expected_tag}"], limit=_CONTROL_LIMIT)
        .stdout.decode("ascii", errors="strict")
        .strip()
    )
    if _git40(tag_object, "G1 tag object") != expected_tag_object:
        raise ReleaseManifestError("G1 annotated tag object differs")
    object_type = (
        _git(root, ["cat-file", "-t", expected_tag_object], limit=_CONTROL_LIMIT)
        .stdout.decode("ascii", errors="strict")
        .strip()
    )
    if object_type != "tag":
        raise ReleaseManifestError("G1 freeze reference is not an annotated tag")
    tag_raw = _git(
        root, ["cat-file", "tag", expected_tag_object], limit=_CONTROL_LIMIT
    ).stdout
    try:
        header, annotation = tag_raw.split(b"\n\n", 1)
        header_lines = header.decode("utf-8", errors="strict").splitlines()
        annotation_text = annotation.decode("utf-8", errors="strict")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ReleaseManifestError("G1 annotated tag object is malformed") from exc
    if (
        len(header_lines) != 4
        or header_lines[0] != f"object {expected_commit}"
        or header_lines[1] != "type commit"
        or header_lines[2] != f"tag {expected_tag}"
        or not header_lines[3].startswith("tagger ")
        or annotation_text != _G1_FREEZE_ANNOTATION
    ):
        raise ReleaseManifestError("G1 annotated tag header or message differs")
    if _tagged_freeze_commit(root) != expected_commit:
        raise ReleaseManifestError("G1 annotated tag peeled commit differs")

    manifest_raw = _git_blob(
        root, expected_commit, _G1_FREEZE_MANIFEST_PATH, _CONTROL_LIMIT
    )
    manifest, _ = _strict_json(manifest_raw, "tagged G1 freeze manifest")
    if (
        manifest.get("manifest_version") != "2.0-A.G1.2"
        or manifest.get("spec_id") != "concordia-g1-interface-v3"
        or manifest.get("status") != "ready"
        or manifest.get("tag") != expected_tag
    ):
        raise ReleaseManifestError("tagged G1 freeze manifest identity differs")
    branch_protocol = _mapping(
        manifest.get("branch_protocol"), "tagged G1 branch protocol"
    )
    approval = _mapping(branch_protocol.get("approval"), "tagged G1 approval")
    if (
        branch_protocol.get("required_root") != f"refs/tags/{expected_tag}^{{}}"
        or approval.get("annotated_tag_is_commit_authority") is not True
    ):
        raise ReleaseManifestError("tagged G1 branch protocol differs")
    authority = _mapping(manifest.get("authority"), "tagged G1 authority")
    tracked: dict[str, str] = {}

    def record(path_value: object, digest_value: object) -> None:
        path = _text(path_value, "tagged G1 authority path")
        digest = _hash32(digest_value, f"tagged G1 authority {path} SHA-256")
        if Path(path).is_absolute():
            return
        _validate_relative_path(path)
        prior = tracked.setdefault(path, digest)
        if prior != digest:
            raise ReleaseManifestError(
                "tagged G1 authority path has conflicting digests"
            )

    def walk(value: object) -> None:
        if type(value) is dict:
            if "path" in value and "sha256" in value:
                record(value.get("path"), value.get("sha256"))
            for key, nested in value.items():
                if key.endswith("sha256"):
                    _hash32(nested, f"tagged G1 {key}")
                walk(nested)
        elif type(value) is list:
            for nested in value:
                walk(nested)

    normative_path = authority.get("normative_spec")
    normative_digest = authority.get("normative_spec_sha256")
    record(normative_path, normative_digest)
    walk(authority)
    required = {
        "handoff/G1_INTERFACE_SPEC.md",
        "handoff/G1_CROSS_LANE_SCHEMAS.json",
        "handoff/WCSPR_FACILITATOR_READBACK.json",
        "handoff/HISTORICAL_ODRA_SHA256.txt",
        "handoff/HISTORICAL_LIVE_ARTIFACTS_SHA256.txt",
        "scripts/generate_g1_vectors.py",
        "handoff/G0R_FALLBACK_EVIDENCE.json",
        "handoff/G0R_RESTORE_RUNBOOK.md",
    }
    if not required.issubset(tracked):
        raise ReleaseManifestError("tagged G1 authority inventory is incomplete")
    authority_files: list[dict[str, str]] = []
    for path, digest in sorted(tracked.items()):
        raw = _git_blob(root, expected_commit, path, _ARTIFACT_LIMIT)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ReleaseManifestError("tagged G1 authority digest differs")
        authority_files.append({"path": path, "sha256": digest})
    projection = {
        "tag": expected_tag,
        "tag_object": expected_tag_object,
        "peeled_commit": expected_commit,
        "annotation_sha256": hashlib.sha256(annotation).hexdigest(),
        "manifest_path": _G1_FREEZE_MANIFEST_PATH,
        "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "authority_sha256": hashlib.sha256(_canonical_json(authority)).hexdigest(),
        "authority_files": authority_files,
    }
    _assert_safe_projection(projection, (), "G1 freeze authority")
    return projection


def _validate_normalized_command_log(
    root: Path,
    *,
    bound: _BoundFile,
    expected_sha256: object,
    canaries: Sequence[bytes],
) -> None:
    digest = _hash32(expected_sha256, f"{bound.path} SHA-256")
    if bound.sha256 != digest:
        raise ReleaseManifestError(f"{bound.path} digest differs from its receipt")
    try:
        bound.raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ReleaseManifestError(f"{bound.path} is not UTF-8") from exc
    if b"\r" in bound.raw:
        raise ReleaseManifestError(f"{bound.path} is not LF-normalized")
    forbidden_roots = {
        str(root),
        *(
            os.environ.get(key, "")
            for key in (
                "HOME",
                "USERPROFILE",
                "CARGO_HOME",
                "RUSTUP_HOME",
                "NPM_CONFIG_CACHE",
                "XDG_CACHE_HOME",
                "XDG_CONFIG_HOME",
                "PIP_CACHE_DIR",
                "UV_CACHE_DIR",
            )
        ),
    }
    forbidden_roots.discard("")
    contains_forbidden_root = any(
        value.encode("utf-8") in bound.raw for value in forbidden_roots
    )
    if (
        contains_forbidden_root
        or _COMMAND_LOG_TEMP_PATH.search(bound.raw)
        or _COMMAND_LOG_USER_PATH.search(bound.raw)
    ):
        raise ReleaseManifestError(f"{bound.path} contains an unnormalized path")
    _assert_no_canary(bound.raw, canaries, f"{bound.path} command log")
    if any(pattern.search(bound.raw) for pattern in _COMMAND_LOG_SECRET_PATTERNS):
        raise ReleaseManifestError(f"{bound.path} command log contains sensitive text")


def _validate_executable_chain_projection(
    root: Path,
    value: object,
    *,
    label: str,
    canaries: Sequence[bytes],
) -> None:
    rows = _sequence(value, label)
    if not rows or len(rows) > 64:
        raise ReleaseManifestError(f"{label} inventory is invalid")
    exact_keys = {
        "role",
        "invoked_path",
        "resolved_path",
        "invoked_device",
        "invoked_inode",
        "resolved_device",
        "resolved_inode",
        "size",
        "mode",
        "owner_uid",
        "mtime_ns",
        "ctime_ns",
        "sha256",
    }
    roles: set[str] = set()
    forbidden_roots = {
        str(root.resolve()),
        *(
            os.environ.get(key, "")
            for key in (
                "HOME",
                "USERPROFILE",
                "CARGO_HOME",
                "RUSTUP_HOME",
                "NPM_CONFIG_CACHE",
                "XDG_CACHE_HOME",
                "XDG_CONFIG_HOME",
                "PIP_CACHE_DIR",
                "UV_CACHE_DIR",
            )
        ),
    }
    forbidden_roots.discard("")
    for raw_row in rows:
        row = _mapping(raw_row, f"{label} row")
        if set(row) != exact_keys:
            raise ReleaseManifestError(f"{label} row schema is not exact")
        role = _text(row.get("role"), f"{label} role")
        if re.fullmatch(r"[a-z0-9_.-]{1,128}", role) is None or role in roles:
            raise ReleaseManifestError(f"{label} role is malformed")
        roles.add(role)
        for key in ("invoked_path", "resolved_path"):
            path = _text(row.get(key), f"{label} {key}")
            if (
                len(path) > 4096
                or not path.isprintable()
                or any(root_value in path for root_value in forbidden_roots)
                or _COMMAND_LOG_TEMP_PATH.search(path.encode("utf-8"))
                or _COMMAND_LOG_USER_PATH.search(path.encode("utf-8"))
            ):
                raise ReleaseManifestError(f"{label} contains an unsafe path")
        for key in (
            "invoked_device",
            "invoked_inode",
            "resolved_device",
            "resolved_inode",
            "size",
            "owner_uid",
            "mtime_ns",
            "ctime_ns",
        ):
            number = row.get(key)
            if type(number) is not int or number < 0:
                raise ReleaseManifestError(f"{label} numeric identity is malformed")
        mode = row.get("mode")
        if type(mode) is not int or not 0 <= mode <= 0o7777:
            raise ReleaseManifestError(f"{label} mode is malformed")
        _hash32(row.get("sha256"), f"{label} executable SHA-256")
    _assert_safe_projection(rows, canaries, label)


def _validate_gate_artifact_rows(
    root: Path,
    value: object,
    *,
    gate_id: str,
    label: str,
    expected_paths: Sequence[str],
    integration_commit: str,
    all_bounds: list[_BoundFile],
    require_tracked: bool,
) -> None:
    rows = _sequence(value, f"{gate_id} {label}")
    if len(rows) != len(expected_paths):
        raise ReleaseManifestError(f"{gate_id} {label} allowlist differs")
    for raw_row, expected_path in zip(rows, expected_paths, strict=True):
        row = _mapping(raw_row, f"{gate_id} {label} row")
        if set(row) != {"path", "sha256"} or row.get("path") != expected_path:
            raise ReleaseManifestError(f"{gate_id} {label} allowlist schema differs")
        expected_sha256 = _hash32(row.get("sha256"), f"{gate_id} {label} SHA-256")
        if require_tracked:
            bound = _load_bound_file(root, expected_path, _ARTIFACT_LIMIT)
            if bound.sha256 != expected_sha256 or not _is_ancestor(
                root, bound.artifact_commit, integration_commit
            ):
                raise ReleaseManifestError(
                    f"{gate_id} {label} artifact digest binding differs"
                )
            all_bounds.append(bound)
        else:
            current = _read_bounded_repository_file(
                root,
                expected_path,
                _ARTIFACT_LIMIT,
            )
            if hashlib.sha256(current.raw).hexdigest() != expected_sha256:
                raise ReleaseManifestError(
                    f"{gate_id} {label} artifact digest binding differs"
                )


def _assert_release_only_history(
    root: Path,
    *,
    integration_commit: str,
    descendant_commit: str,
) -> None:
    """Require one linear, release-output-only history above integration."""

    integration_commit = _git40(integration_commit, "integration commit")
    descendant_commit = _git40(descendant_commit, "release descendant commit")
    if not _is_ancestor(root, integration_commit, descendant_commit):
        raise ReleaseManifestError("release descendant does not follow integration")
    try:
        raw_commits = _git(
            root,
            [
                "rev-list",
                "--reverse",
                f"{integration_commit}..{descendant_commit}",
            ],
            limit=_GIT_OUTPUT_LIMIT,
        ).stdout.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ReleaseManifestError("release history identity is malformed") from exc
    allowed_paths = {
        *COMMAND_GATE_RECEIPT_PATHS.values(),
        *RECEIPT_PATHS.values(),
        *PROOF_RECEIPT_PATHS.values(),
        NPM_CAPTURE_PATH,
        ORGANIZER_G12_AUDIT_PATH,
        ORGANIZER_G12_INVOCATION_PATH,
        RELEASE_MANIFEST_PATH,
        G13_SUBMISSION_RECEIPT_PATH,
        G13_BROWSER_RECEIPT_PATH,
        G13_BROWSER_TRACE_PATH,
        ORGANIZER_G13_AUDIT_PATH,
        ORGANIZER_G13_INVOCATION_PATH,
        "release/g13/DORAHACKS_SUBMISSION.png",
        "release/g13/FINAL_LINK_AUDIT.json",
        "release/g13/YOUTUBE_DESCRIPTION.txt",
        "release/g13/YOUTUBE_INCOGNITO.png",
    }
    for gate_id, commands in COMMAND_GATE_COMMANDS.items():
        for command_id, _working_directory, _argv in commands:
            allowed_paths.add(
                f"release/receipts/logs/{gate_id}/{command_id}.stdout"
            )
            allowed_paths.add(
                f"release/receipts/logs/{gate_id}/{command_id}.stderr"
            )

    expected_parent = integration_commit
    for raw_commit in raw_commits.splitlines():
        commit = _git40(raw_commit, "release history commit")
        try:
            parent_row = (
                _git(
                    root,
                    ["rev-list", "--parents", "-n", "1", commit],
                    limit=_CONTROL_LIMIT,
                )
                .stdout.decode("ascii", errors="strict")
                .split()
            )
        except UnicodeDecodeError as exc:
            raise ReleaseManifestError("release history parent is malformed") from exc
        if parent_row != [commit, expected_parent]:
            raise ReleaseManifestError("release history is not strictly linear")
        changed = _git(
            root,
            [
                "diff-tree",
                "--no-commit-id",
                "--name-status",
                "-r",
                "-z",
                expected_parent,
                commit,
            ],
            limit=_GIT_OUTPUT_LIMIT,
        ).stdout.split(b"\0")
        if not any(changed):
            raise ReleaseManifestError("release history contains an empty commit")
        entries = [item for item in changed if item]
        if len(entries) % 2:
            raise ReleaseManifestError("release history status is malformed")
        for index in range(0, len(entries), 2):
            raw_status, raw_path = entries[index : index + 2]
            if raw_status != b"A":
                raise ReleaseManifestError(
                    "release history is not append-only first-add history"
                )
            try:
                path = raw_path.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise ReleaseManifestError("release history path is not UTF-8") from exc
            if path not in allowed_paths:
                raise ReleaseManifestError(
                    "release history added a path outside the exact release allowlist"
                )
        expected_parent = commit
    if expected_parent != descendant_commit:
        raise ReleaseManifestError("release history does not reach its descendant")


def _command_gate_replay_projection(
    document: Mapping[str, object],
) -> dict[str, object]:
    gate_id = _text(document.get("gate_id"), "command-gate replay gate ID")
    commands = [
        {
            "command_id": row.get("command_id"),
            "working_directory": row.get("working_directory"),
            "argv": row.get("argv"),
            "exit_code": row.get("exit_code"),
        }
        for row in (
            _mapping(item, f"{gate_id} replay command")
            for item in _sequence(document.get("commands"), f"{gate_id} replay commands")
        )
    ]
    contract = {
        "gate_id": gate_id,
        "integration_commit": _git40(
            document.get("integration_commit"), f"{gate_id} replay integration commit"
        ),
        "commands": commands,
        # A fresh build must execute and produce every declared artifact, but
        # outputs such as Next's BUILD_ID are intentionally non-deterministic.
        # Bind their exact path inventory here; the gate runner has already
        # verified each fresh output and its digest in the replay receipt.
        "produced_artifact_paths": sorted(
            _text(
                _mapping(item, f"{gate_id} produced artifact").get("path"),
                f"{gate_id} produced artifact path",
            )
            for item in _sequence(
                document.get("produced_artifacts"),
                f"{gate_id} produced artifacts",
            )
        ),
        "input_artifacts": document.get("input_artifacts"),
        "fresh_output_contract": [
            {
                "path": row.get("path"),
                "state_before": row.get("state_before"),
                "state_after": row.get("state_after"),
            }
            for row in (
                _mapping(item, f"{gate_id} fresh output")
                for item in _sequence(
                    document.get("fresh_outputs"),
                    f"{gate_id} fresh outputs",
                )
            )
        ],
    }
    return {
        "gate_id": gate_id,
        "status": "verified",
        "replay_contract_sha256": hashlib.sha256(_canonical_json(contract)).hexdigest(),
    }


def _default_command_gate_replayer(
    root: Path,
    *,
    integration_commit: str,
    expected: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Rerun every frozen gate from an isolated local clone of the exact source."""

    from scripts.release_gate_runner import GateRunError, run_gate

    expected_by_id = {
        _text(row.get("gate_id"), "expected replay gate ID"): dict(row)
        for row in expected
    }
    if set(expected_by_id) != set(COMMAND_GATE_COMMANDS):
        raise ReleaseManifestError("command-gate replay inventory differs")
    observed: list[dict[str, object]] = []
    for gate_id in COMMAND_GATE_COMMANDS:
        with tempfile.TemporaryDirectory(
            prefix=f"concordia-release-replay-{gate_id.lower()}-"
        ) as temporary:
            clone = Path(temporary) / "repository"
            _run(
                Path(temporary),
                [
                    "git",
                    "clone",
                    "--no-local",
                    "--no-hardlinks",
                    "--quiet",
                    str(root),
                    str(clone),
                ],
                timeout=180,
            )
            _git(clone, ["checkout", "--detach", "--quiet", integration_commit])
            try:
                result = run_gate(gate_id, repository_root=clone)
            except GateRunError as exc:
                raise ReleaseManifestError(
                    f"{gate_id} command-gate replay failed"
                ) from exc
            receipt_raw = _read_bounded_repository_file(
                clone,
                result.receipt_path,
                _CONTROL_LIMIT,
            ).raw
            receipt, canonical = _strict_json(
                receipt_raw, f"{gate_id} replay receipt"
            )
            if receipt_raw != canonical:
                raise ReleaseManifestError(
                    f"{gate_id} replay receipt is not canonical"
                )
            projection = _command_gate_replay_projection(receipt)
            if projection != expected_by_id[gate_id]:
                raise ReleaseManifestError(
                    f"{gate_id} command-gate replay differs from committed contract"
                )
            observed.append(projection)
    return observed


def _command_gate_replayer_factory(
    _root: Path,
) -> object:
    return _default_command_gate_replayer


def _load_command_gate_receipts(
    root: Path,
    canaries: Sequence[bytes],
    *,
    require_current_tree: bool,
) -> tuple[
    dict[str, dict[str, object]],
    dict[str, _BoundFile],
    list[_BoundFile],
    str,
    str,
]:
    frozen_commit = _tagged_freeze_commit(root)
    receipts: dict[str, dict[str, object]] = {}
    receipt_bounds: dict[str, _BoundFile] = {}
    all_bounds: list[_BoundFile] = []
    integration_commits: set[str] = set()
    expected_normalization, _ = _strict_json(
        _canonical_json(dict(COMMAND_GATE_NORMALIZATION)),
        "command-gate normalization contract",
    )
    exact_receipt_keys = {
        "schema_version",
        "gate_id",
        "frozen_commit",
        "freeze_tag",
        "integration_commit",
        "clean_tree_sha256",
        "normalization",
        "executable_chain_schema_version",
        "runner",
        "runtime_versions",
        "runtime_executable_chains",
        "started_at",
        "ended_at",
        "commands",
        "produced_artifacts",
        "input_artifacts",
        "fresh_outputs",
    }
    empty_tree_digest = hashlib.sha256(b"").hexdigest()

    for gate_id, receipt_path in COMMAND_GATE_RECEIPT_PATHS.items():
        bound = _load_immutable_bound_file(root, receipt_path, _CONTROL_LIMIT)
        document, canonical = _strict_json(bound.raw, f"{gate_id} command gate receipt")
        if bound.raw != canonical:
            raise ReleaseManifestError(
                f"{gate_id} command gate receipt is not canonical JSON"
            )
        if set(document) != exact_receipt_keys:
            raise ReleaseManifestError(
                f"{gate_id} command gate receipt schema is not exact"
            )
        if (
            document.get("schema_version") != COMMAND_GATE_RECEIPT_SCHEMA_VERSION
            or document.get("gate_id") != gate_id
            or document.get("frozen_commit") != frozen_commit
            or document.get("clean_tree_sha256") != empty_tree_digest
            or document.get("normalization") != expected_normalization
            or document.get("executable_chain_schema_version")
            != COMMAND_GATE_EXECUTABLE_CHAIN_SCHEMA_VERSION
        ):
            raise ReleaseManifestError(f"{gate_id} command gate identity differs")
        freeze_tag = _mapping(document.get("freeze_tag"), f"{gate_id} freeze tag")
        if freeze_tag != {
            "name": G1_FREEZE_TAG,
            "object": G1_FREEZE_TAG_OBJECT,
            "peeled_commit": G1_FREEZE_COMMIT,
        }:
            raise ReleaseManifestError(f"{gate_id} freeze-tag authority differs")

        integration_commit = _git40(
            document.get("integration_commit"), f"{gate_id} integration commit"
        )
        integration_commits.add(integration_commit)
        if not _is_ancestor(
            root, frozen_commit, integration_commit
        ) or not _is_ancestor(root, integration_commit, bound.artifact_commit):
            raise ReleaseManifestError(f"{gate_id} commit ancestry is invalid")

        runner_rows = _sequence(document.get("runner"), f"{gate_id} runner")
        expected_identity_paths = COMMAND_GATE_IDENTITY_PATHS[gate_id]
        if len(runner_rows) != len(expected_identity_paths):
            raise ReleaseManifestError(f"{gate_id} runner inventory differs")
        runner_commits: list[str] = []
        for raw_runner, expected_path in zip(
            runner_rows, expected_identity_paths, strict=True
        ):
            runner = _mapping(raw_runner, f"{gate_id} runner")
            if set(runner) != {"path", "commit", "sha256"}:
                raise ReleaseManifestError(f"{gate_id} runner schema is not exact")
            runner_commit = _git40(runner.get("commit"), f"{gate_id} runner commit")
            runner_bound = _load_bound_file(root, expected_path, _CONTROL_LIMIT)
            if (
                runner.get("path") != expected_path
                or runner_bound.artifact_commit != runner_commit
                or runner_bound.sha256
                != _hash32(runner.get("sha256"), f"{gate_id} runner SHA-256")
                or not _is_ancestor(root, runner_commit, integration_commit)
            ):
                raise ReleaseManifestError(
                    f"{gate_id} runner implementation binding differs"
                )
            runner_commits.append(runner_commit)
            all_bounds.append(runner_bound)

        runtimes = _mapping(document.get("runtime_versions"), f"{gate_id} runtimes")
        expected_runtime_names = COMMAND_GATE_REQUIRED_RUNTIMES[gate_id]
        if set(runtimes) != set(expected_runtime_names):
            raise ReleaseManifestError(f"{gate_id} runtime inventory differs")
        for runtime in expected_runtime_names:
            if runtimes.get(runtime) != COMMAND_GATE_EXPECTED_RUNTIME_VERSIONS[runtime]:
                raise ReleaseManifestError(
                    f"{gate_id} {runtime} runtime version differs"
                )
        runtime_chains = _mapping(
            document.get("runtime_executable_chains"),
            f"{gate_id} runtime executable chains",
        )
        if set(runtime_chains) != set(expected_runtime_names):
            raise ReleaseManifestError(
                f"{gate_id} runtime executable-chain inventory differs"
            )
        for runtime in expected_runtime_names:
            _validate_executable_chain_projection(
                root,
                runtime_chains[runtime],
                label=f"{gate_id} {runtime} runtime executable chain",
                canaries=canaries,
            )

        started_at, started = _parse_timestamp(
            document.get("started_at"), f"{gate_id} started_at"
        )
        ended_at, ended = _parse_timestamp(
            document.get("ended_at"), f"{gate_id} ended_at"
        )
        if ended < started:
            raise ReleaseManifestError(f"{gate_id} execution chronology is invalid")

        rows = _sequence(document.get("commands"), f"{gate_id} commands")
        expected_commands = COMMAND_GATE_COMMANDS[gate_id]
        if len(rows) != len(expected_commands):
            raise ReleaseManifestError(f"{gate_id} command allowlist is incomplete")
        expected_log_names: set[str] = set()
        for raw_row, (command_id, working_directory, argv) in zip(
            rows, expected_commands, strict=True
        ):
            row = _mapping(raw_row, f"{gate_id} command")
            if set(row) != {
                "command_id",
                "working_directory",
                "argv",
                "started_at",
                "ended_at",
                "exit_code",
                "stdout",
                "stderr",
                "executable_chain",
            }:
                raise ReleaseManifestError(f"{gate_id} command schema is not exact")
            if (
                row.get("command_id") != command_id
                or row.get("working_directory") != working_directory
                or row.get("argv") != list(argv)
            ):
                raise ReleaseManifestError(
                    f"{gate_id} command argv is outside the allowlist"
                )
            _validate_executable_chain_projection(
                root,
                row.get("executable_chain"),
                label=f"{gate_id} {command_id} executable chain",
                canaries=canaries,
            )
            for argument in argv:
                if argument.startswith("scripts/"):
                    command_source = _load_bound_file(root, argument, _CONTROL_LIMIT)
                    if not _is_ancestor(
                        root, command_source.artifact_commit, integration_commit
                    ):
                        raise ReleaseManifestError(
                            f"{gate_id} command implementation postdates integration"
                        )
                    all_bounds.append(command_source)
            if working_directory != ".":
                _validate_relative_path(working_directory)
            _, command_started = _parse_timestamp(
                row.get("started_at"), f"{gate_id} {command_id} started_at"
            )
            _, command_ended = _parse_timestamp(
                row.get("ended_at"), f"{gate_id} {command_id} ended_at"
            )
            if not (started <= command_started <= command_ended <= ended):
                raise ReleaseManifestError(f"{gate_id} command chronology is invalid")
            if type(row.get("exit_code")) is not int or row.get("exit_code") != 0:
                raise ReleaseManifestError(f"{gate_id} command exit code is not zero")
            for stream in ("stdout", "stderr"):
                stream_row = _mapping(
                    row.get(stream), f"{gate_id} {command_id} {stream}"
                )
                if set(stream_row) != {"path", "sha256"}:
                    raise ReleaseManifestError(
                        f"{gate_id} command log schema is not exact"
                    )
                expected_path = f"release/receipts/logs/{gate_id}/{command_id}.{stream}"
                if stream_row.get("path") != expected_path:
                    raise ReleaseManifestError(f"{gate_id} command log path differs")
                expected_log_names.add(f"{command_id}.{stream}")
                log_bound = _load_immutable_bound_file(
                    root,
                    expected_path,
                    _GIT_OUTPUT_LIMIT,
                    artifact_commit=bound.artifact_commit,
                )
                if log_bound.artifact_commit != bound.artifact_commit:
                    raise ReleaseManifestError(
                        f"{gate_id} receipt and command logs are not from the same commit"
                    )
                _validate_normalized_command_log(
                    root,
                    bound=log_bound,
                    expected_sha256=stream_row.get("sha256"),
                    canaries=canaries,
                )
                all_bounds.append(log_bound)
        actual_log_names = _repository_directory_names(
            root, f"release/receipts/logs/{gate_id}"
        )
        if actual_log_names != expected_log_names:
            raise ReleaseManifestError(
                f"{gate_id} command log directory has unexpected filenames"
            )

        _validate_gate_artifact_rows(
            root,
            document.get("produced_artifacts"),
            gate_id=gate_id,
            label="produced artifacts",
            expected_paths=COMMAND_GATE_PRODUCED_ARTIFACT_PATHS[gate_id],
            integration_commit=integration_commit,
            all_bounds=all_bounds,
            require_tracked=False,
        )
        _validate_gate_artifact_rows(
            root,
            document.get("input_artifacts"),
            gate_id=gate_id,
            label="input artifacts",
            expected_paths=COMMAND_GATE_INPUT_ARTIFACT_PATHS[gate_id],
            integration_commit=integration_commit,
            all_bounds=all_bounds,
            require_tracked=True,
        )
        fresh_rows = _sequence(
            document.get("fresh_outputs"), f"{gate_id} fresh outputs"
        )
        expected_fresh = COMMAND_GATE_FRESH_OUTPUT_PATHS[gate_id]
        if fresh_rows != [
            {"path": path, "state_before": "removed_or_absent"}
            for path in expected_fresh
        ]:
            raise ReleaseManifestError(f"{gate_id} fresh-output contract differs")

        _assert_safe_projection(document, canaries, f"{gate_id} command gate receipt")
        receipts[gate_id] = {
            "gate_id": gate_id,
            "path": receipt_path,
            "sha256": bound.sha256,
            "artifact_commit": bound.artifact_commit,
            "frozen_commit": frozen_commit,
            "integration_commit": integration_commit,
            "started_at": started_at,
            "ended_at": ended_at,
            "runner_paths": list(expected_identity_paths),
            "runner_commits_sha256": hashlib.sha256(
                _canonical_json(runner_commits)
            ).hexdigest(),
            "replay_contract_sha256": _command_gate_replay_projection(document)[
                "replay_contract_sha256"
            ],
        }
        receipt_bounds[gate_id] = bound
        all_bounds.append(bound)

    if len(integration_commits) != 1:
        raise ReleaseManifestError("command gates do not bind one integration commit")
    integration_commit = next(iter(integration_commits))
    for receipt_bound in receipt_bounds.values():
        _assert_release_only_history(
            root,
            integration_commit=integration_commit,
            descendant_commit=receipt_bound.artifact_commit,
        )
    if require_current_tree:
        try:
            head_commit = (
                _git(root, ["rev-parse", "HEAD^{commit}"], limit=_CONTROL_LIMIT)
                .stdout.decode("ascii", errors="strict")
                .strip()
            )
        except UnicodeDecodeError as exc:
            raise ReleaseManifestError("release HEAD identity is malformed") from exc
        try:
            _assert_release_only_history(
                root,
                integration_commit=integration_commit,
                descendant_commit=_git40(head_commit, "release HEAD"),
            )
        except ReleaseManifestError as exc:
            raise ReleaseManifestError(
                "current release code differs from the command-gated integration "
                f"commit: {exc}"
            ) from exc
    return receipts, receipt_bounds, all_bounds, frozen_commit, integration_commit


def _verify_command_gate_receipts_locked(
    repository_root: str | Path,
) -> dict[str, object]:
    """Verify immutable G2/G9/G11 command receipts without live collection."""

    root = Path(repository_root).absolute()
    _require_repository(root)
    _recover_capture_publication(root)
    _require_clean_worktree(root)
    receipts, _, _, frozen_commit, integration_commit = _load_command_gate_receipts(
        root,
        _load_secret_canaries(),
        require_current_tree=True,
    )
    return {
        "gate_ids": list(receipts),
        "frozen_commit": frozen_commit,
        "integration_commit": integration_commit,
        "status": "verified",
    }


def _artifact_metadata(
    artifact_id: str,
    document: Mapping[str, Any],
    *,
    historical: _Artifact | None,
    artifact_commit: str,
) -> tuple[str, str, str, str, str]:
    if artifact_id == "historical_odra_receipt_v1":
        return (
            _text(document.get("schema_version"), "historical schema"),
            _parse_timestamp(document.get("captured_at"), "historical captured_at")[0],
            _git40(document.get("source_commit"), "historical source_commit"),
            _git40(document.get("deployment_commit"), "historical deployment_commit"),
            "snapshot",
        )
    if artifact_id == "card_chain_roots_v1":
        if historical is None:
            raise ReleaseManifestError("card roots require historical metadata")
        return (
            _text(document.get("schema_version"), "card roots schema"),
            historical.captured_at,
            historical.source_commit,
            historical.deployment_commit,
            "snapshot",
        )
    if artifact_id == "exact_envelope_v3":
        deployment = _mapping(document.get("deployment"), "v3 deployment")
        run = _mapping(document.get("run"), "v3 run")
        steps = _sequence(run.get("steps"), "v3 run steps")
        final = [
            _mapping(step, "v3 run step")
            for step in steps
            if type(step) is dict and step.get("name") == "finalize_exact"
        ]
        if len(final) != 1:
            raise ReleaseManifestError("v3 proof needs exactly one finalize_exact step")
        evidence = _mapping(
            final[0].get("finality_block_evidence"), "v3 finality evidence"
        )
        return (
            _text(document.get("schema_id"), "v3 schema"),
            _parse_timestamp(evidence.get("observed_at"), "v3 captured_at")[0],
            _git40(deployment.get("source_commit"), "v3 source_commit"),
            _git40(deployment.get("deployment_commit"), "v3 deployment_commit"),
            "live",
        )
    if artifact_id in {
        "native_treasury_execution_v1",
        "official_x402_settlement_v1",
        "safepay_v2",
    }:
        return (
            _text(document.get("schema_version"), f"{artifact_id} schema"),
            _parse_timestamp(document.get("captured_at"), f"{artifact_id} captured_at")[
                0
            ],
            _git40(document.get("source_commit"), f"{artifact_id} source_commit"),
            _git40(
                document.get("deployment_commit"),
                f"{artifact_id} deployment_commit",
            ),
            "live",
        )
    if artifact_id == "proof_registry_v1":
        items = _sequence(document.get("public_items"), "registry public_items")
        captures = [
            _parse_timestamp(
                _mapping(item, "registry public item").get("captured_at"),
                "registry item captured_at",
            )
            for item in items
        ]
        if not captures:
            raise ReleaseManifestError("proof registry contains no public proof")
        return (
            "concordia.proof_registry.v1",
            max(captures, key=lambda item: item[1])[0],
            artifact_commit,
            artifact_commit,
            "live",
        )
    raise ReleaseManifestError("unknown fixed proof artifact")


_REQUIRED_EVIDENCE_FIELDS: dict[str, tuple[str, ...]] = {
    "historical_odra_receipt_v1": (
        "lineage_inventory",
        "contract_identity",
        "card_chain",
        "raw_rpc",
    ),
    "card_chain_roots_v1": ("roots",),
    "exact_envelope_v3": ("deployment", "input", "prepared", "run", "readback"),
    "native_treasury_execution_v1": (
        "release_identity",
        "authorization",
        "executor_journal",
        "finality",
        "balance_evidence",
        "bounded_transfer_scan",
    ),
    "official_x402_settlement_v1": (
        "capture_identity",
        "governance_binding",
        "resource_and_payment",
        "authorization",
        "facilitator",
        "wcspr_readbacks",
        "settlement_chain_evidence",
        "fulfillment",
        "protected_report",
        "release_order",
    ),
    "proof_registry_v1": ("public_items", "internal_records", "card_chain_roots"),
    "safepay_v2": (
        "capture_identity",
        "quote",
        "issued_quote_rows",
        "chain_evidence",
        "consumption_rows",
        "ledger_evidence",
        "redemption_observations",
        "protected_report",
    ),
}


def _require_nonempty_proof(artifact_id: str, document: Mapping[str, Any]) -> None:
    for field in _REQUIRED_EVIDENCE_FIELDS[artifact_id]:
        value = document.get(field)
        if value in ({}, [], "", None):
            raise ReleaseManifestError(
                f"{artifact_id} proof artifact has empty required evidence: {field}"
            )


_ADAPTER_RESULT_CONTRACTS: dict[str, tuple[str, frozenset[str]]] = {
    "safepay_v2": (
        "concordia.safepay_v2_adapter_result.v1",
        frozenset(
            {
                "schema_version",
                "proof_type",
                "artifact_sha256",
                "derived_facts",
                "checks",
            }
        ),
    ),
    "official_x402_settlement_v1": (
        "concordia.official_x402_adapter_result.v1",
        frozenset(
            {
                "schema_version",
                "proof_type",
                "artifact_sha256",
                "derived_facts",
                "internal_record",
                "checks",
            }
        ),
    ),
}


def _run_release_adapter(
    *,
    artifact_id: str,
    document: dict[str, Any],
    raw: bytes,
    metadata: tuple[str, str, str, str, str],
) -> dict[str, Any] | None:
    """Run the pinned raw-evidence adapter before registry parity is considered."""

    contract = _ADAPTER_RESULT_CONTRACTS.get(artifact_id)
    if contract is None:
        return None
    try:
        if artifact_id == "safepay_v2":
            value = release_proof_adapters.verify_safepay_v2_artifact(
                document, raw
            )
        else:
            value = release_proof_adapters.verify_official_x402_artifact(
                document, raw
            )
    except release_proof_adapters.ReleaseProofAdapterError as exc:
        raise ReleaseManifestError(
            f"{artifact_id} independent adapter rejected its bound artifact"
        ) from exc
    result = _mapping(value, f"{artifact_id} independent adapter result")
    expected_schema, expected_fields = contract
    if (
        set(result) != expected_fields
        or result.get("schema_version") != expected_schema
        or result.get("proof_type") != artifact_id
        or result.get("artifact_sha256") != hashlib.sha256(raw).hexdigest()
    ):
        raise ReleaseManifestError(
            f"{artifact_id} independent adapter result identity differs"
        )
    facts = _mapping(
        result.get("derived_facts"),
        f"{artifact_id} independent adapter derived facts",
    )
    captured_text, captured_instant = _parse_timestamp(
        facts.get("captured_at"),
        f"{artifact_id} adapter captured_at",
    )
    if (
        captured_text != metadata[1]
        or captured_instant > datetime.now(UTC)
        or _git40(
            facts.get("source_commit"),
            f"{artifact_id} adapter source_commit",
        )
        != metadata[2]
        or _git40(
            facts.get("deployment_commit"),
            f"{artifact_id} adapter deployment_commit",
        )
        != metadata[3]
    ):
        raise ReleaseManifestError(
            f"{artifact_id} independent adapter release identity differs"
        )
    _adapter_registry_checks(result, artifact_id)
    if artifact_id == "official_x402_settlement_v1":
        _mapping(
            result.get("internal_record"),
            "official-x402 adapter internal record",
        )
    return dict(result)


def _adapter_registry_checks(
    result: Mapping[str, Any],
    artifact_id: str,
) -> list[dict[str, object]]:
    """Project independently recomputed adapter evidence into registry checks."""

    raw_checks = _sequence(
        result.get("checks"),
        f"{artifact_id} independent adapter checks",
    )
    projected: list[dict[str, object]] = []
    for raw_check in raw_checks:
        check = _mapping(
            raw_check,
            f"{artifact_id} independent adapter check",
        )
        if set(check) != {
            "name",
            "passed",
            "source",
            "observed_at",
            "evidence_paths",
            "evidence_sha256",
        }:
            raise ReleaseManifestError(
                f"{artifact_id} independent adapter check schema differs"
            )
        if check.get("passed") is not True:
            raise ReleaseManifestError(
                f"{artifact_id} independent adapter returned a failed check"
            )
        name = _text(
            check.get("name"),
            f"{artifact_id} independent adapter check name",
        )
        source = _text(
            check.get("source"),
            f"{artifact_id} independent adapter check source",
        )
        observed_at, observed_instant = _parse_timestamp(
            check.get("observed_at"),
            f"{artifact_id} independent adapter check observed_at",
        )
        if observed_instant > datetime.now(UTC):
            raise ReleaseManifestError(
                f"{artifact_id} independent adapter check is future-dated"
            )
        paths = _sequence(
            check.get("evidence_paths"),
            f"{artifact_id} independent adapter evidence paths",
        )
        if (
            not paths
            or any(
                type(path) is not str or not path.startswith("/")
                for path in paths
            )
            or len(set(paths)) != len(paths)
        ):
            raise ReleaseManifestError(
                f"{artifact_id} independent adapter evidence paths differ"
            )
        _hash32(
            check.get("evidence_sha256"),
            f"{artifact_id} independent adapter evidence SHA-256",
        )
        projected.append(
            {
                "name": name,
                "required": True,
                "passed": True,
                "source": source,
                "observed_at": observed_at,
            }
        )
    if not projected:
        raise ReleaseManifestError(
            f"{artifact_id} independent adapter returned no checks"
        )
    return projected


def _load_artifacts(root: Path) -> dict[str, _Artifact]:
    result: dict[str, _Artifact] = {}
    ordered = [
        "historical_odra_receipt_v1",
        "card_chain_roots_v1",
        "exact_envelope_v3",
        "native_treasury_execution_v1",
        "official_x402_settlement_v1",
        "proof_registry_v1",
        "safepay_v2",
    ]
    for artifact_id in ordered:
        bound = _load_bound_file(root, ARTIFACT_PATHS[artifact_id], _ARTIFACT_LIMIT)
        document, canonical = _strict_json(bound.raw, artifact_id)
        _require_nonempty_proof(artifact_id, document)
        metadata = _artifact_metadata(
            artifact_id,
            document,
            historical=result.get("historical_odra_receipt_v1"),
            artifact_commit=bound.artifact_commit,
        )
        adapter_result = _run_release_adapter(
            artifact_id=artifact_id,
            document=document,
            raw=bound.raw,
            metadata=metadata,
        )
        artifact = _Artifact(
            artifact_id=artifact_id,
            bound=bound,
            document=document,
            canonical=canonical,
            schema_version=metadata[0],
            captured_at=metadata[1],
            source_commit=metadata[2],
            deployment_commit=metadata[3],
            observation_mode=metadata[4],
            adapter_result=adapter_result,
        )
        _require_ordered_ancestry(
            root,
            source_commit=artifact.source_commit,
            deployment_commit=artifact.deployment_commit,
            artifact_commit=artifact.bound.artifact_commit,
            historical_exception=artifact_id == "historical_odra_receipt_v1",
        )
        result[artifact_id] = artifact
    _validate_registry_parity(result)
    return result


_REGISTRY_BINDINGS = {
    "historical_odra_receipt_v2": "historical_odra_receipt_v1",
    "exact_envelope_v3": "exact_envelope_v3",
    "native_treasury_execution_v1": "native_treasury_execution_v1",
    "safepay_v2": "safepay_v2",
    "official_x402_settlement_v1": "official_x402_settlement_v1",
}

_COMPOSE_SERVICE_ALLOWLIST = frozenset(
    {
        "alden",
        "dashboard",
        "gateway",
        "ipfs",
        "jaeger",
        "locke",
        "mercer",
        "otel-collector",
        "recorder-heartbeat",
        "rowan",
        "simulator",
        "verity",
        "wells",
        "x402-official",
        "x402-provider",
    }
)
_COMPOSE_BUILD_ALLOWLIST = frozenset(
    {"dashboard", "gateway", "x402-official"}
)
_COMPOSE_VOLUME_ALLOWLIST = {
    "gateway": frozenset(
        {
            ("volume", "concordia-data", "/data", False),
            ("bind", "artifacts", "/app/artifacts", True),
            (
                "bind",
                "artifacts/live/proof-registry",
                "/run/config/proof-registry",
                True,
            ),
        }
    ),
    "ipfs": frozenset(
        {("volume", "concordia-ipfs-data", "/data/ipfs", False)}
    ),
    "otel-collector": frozenset(
        {
            (
                "bind",
                "deploy/shared-host/otel-collector-config.yml",
                "/etc/otelcol/config.yml",
                True,
            )
        }
    ),
    "x402-official": frozenset(
        {
            ("volume", "x402_official_data", "/data", False),
            (
                "bind",
                "@release-config/x402-official",
                "/run/config",
                True,
            ),
        }
    ),
    "x402-provider": frozenset(
        {("volume", "x402_provider_data", "/data", False)}
    ),
}
_COMPOSE_LOCAL_IMAGES = frozenset(
    {"concordia-dao-council:local", "concordia-dashboard:local"}
)
_COMPOSE_NETWORK_ALLOWLIST = {
    "gateway": frozenset({"concordia-edge", "concordia-internal"}),
    "x402-provider": frozenset({"concordia-edge", "concordia-internal"}),
    "simulator": frozenset({"concordia-internal"}),
    "dashboard": frozenset({"concordia-edge", "concordia-internal"}),
    "rowan": frozenset({"concordia-internal"}),
    "mercer": frozenset({"concordia-internal"}),
    "verity": frozenset({"concordia-internal"}),
    "alden": frozenset({"concordia-internal"}),
    "locke": frozenset({"concordia-internal"}),
    "wells": frozenset({"concordia-internal"}),
    "recorder-heartbeat": frozenset({"concordia-internal"}),
    "ipfs": frozenset({"concordia-internal"}),
    "otel-collector": frozenset({"concordia-internal"}),
    "jaeger": frozenset({"concordia-edge", "concordia-internal"}),
    "x402-official": frozenset({"concordia-edge", "concordia-internal"}),
}
_COMPOSE_SERVICE_FIELDS = frozenset(
    {
        "image",
        "build",
        "command",
        "entrypoint",
        "environment",
        "secrets",
        "volumes",
        "networks",
        "depends_on",
        "healthcheck",
        "restart",
        "logging",
        "mem_limit",
        "cpus",
        "read_only",
        "tmpfs",
        "cap_drop",
        "security_opt",
        "init",
        "stop_grace_period",
    }
)
_COMPOSE_TOP_LEVEL_FIELDS = frozenset(
    {
        "name",
        "services",
        "networks",
        "volumes",
        "secrets",
        "x-concordia-observed-service-config-hashes",
    }
)


def _validate_registry_parity(artifacts: Mapping[str, _Artifact]) -> None:
    registry = artifacts["proof_registry_v1"].document
    try:
        validate_release_registry_document(dict(registry))
    except ValueError as exc:
        raise ReleaseManifestError("proof registry failed strict validation") from exc
    if registry.get("schema_version") != 1:
        raise ReleaseManifestError("proof registry schema is invalid")
    items = _sequence(registry.get("public_items"), "registry public_items")
    by_type: dict[str, Mapping[str, Any]] = {}
    for raw in items:
        item = _mapping(raw, "registry item")
        proof_type = _text(item.get("proof_type"), "registry proof_type")
        if proof_type in by_type:
            raise ReleaseManifestError("registry has duplicate proof type")
        by_type[proof_type] = item
    if set(by_type) != set(_REGISTRY_BINDINGS):
        raise ReleaseManifestError("registry does not contain exact release proof set")
    for proof_type, artifact_id in _REGISTRY_BINDINGS.items():
        item = by_type[proof_type]
        artifact = artifacts[artifact_id]
        _, artifact_captured_at = _parse_timestamp(
            artifact.captured_at,
            f"{proof_type} artifact captured_at",
        )
        if artifact_captured_at > datetime.now(UTC):
            raise ReleaseManifestError(
                f"registry artifact is future-dated: {proof_type}"
            )
        expected = {
            "schema_version": artifact.schema_version,
            "captured_at": artifact.captured_at,
            "source_commit": artifact.source_commit,
            "deployment_commit": artifact.deployment_commit,
            "artifact_path": artifact.bound.path,
            "artifact_sha256": artifact.bound.sha256,
            "observation_mode": artifact.observation_mode,
        }
        if proof_type == "exact_envelope_v3":
            # The six-field v3 artifact records chain-observation time, while
            # its public registry item is created only after the independent
            # verifier recomputes source/build/envelope checks.  That later
            # verification instant is therefore allowed (and becomes the
            # internal record observation boundary), but it can never predate
            # the artifact's intrinsic chain observation.
            item_captured_raw = _text(
                item.get("captured_at"),
                "registry exact-envelope captured_at",
            )
            _, item_captured_at = _parse_timestamp(
                item_captured_raw,
                "registry exact-envelope captured_at",
            )
            if (
                item_captured_at < artifact_captured_at
                or item_captured_at > datetime.now(UTC)
            ):
                raise ReleaseManifestError(
                    "registry exact-envelope verification chronology is invalid"
                )
            expected.pop("captured_at")
        for field, value in expected.items():
            if item.get(field) != value:
                if field == "observation_mode":
                    raise ReleaseManifestError(
                        f"registry observation mode differs for {proof_type}"
                    )
                raise ReleaseManifestError(
                    f"registry item metadata differs for {proof_type}: {field}"
                )
        if item.get("verification_status") != "verified":
            raise ReleaseManifestError("registry item is not verifier-marked")
    exact_item = by_type["exact_envelope_v3"]
    exact_artifact = artifacts["exact_envelope_v3"].document
    exact_deployment = _mapping(
        exact_artifact.get("deployment"),
        "exact-envelope deployment",
    )
    exact_prepared = _mapping(
        exact_artifact.get("prepared"),
        "exact-envelope prepared action",
    )
    if (
        exact_item.get("action_id") != exact_prepared.get("action_id")
        or exact_item.get("envelope_hash") != exact_prepared.get("envelope_hash")
        or exact_item.get("network") != exact_deployment.get("network")
        or exact_item.get("package_hash") != exact_deployment.get("package_hash")
        or exact_item.get("contract_hash") != exact_deployment.get("contract_hash")
    ):
        raise ReleaseManifestError(
            "registry exact-envelope claim differs from its artifact"
        )
    treasury_item = by_type["native_treasury_execution_v1"]
    treasury_artifact = artifacts["native_treasury_execution_v1"].document
    treasury_authorization = _mapping(
        treasury_artifact.get("authorization"),
        "treasury authorization",
    )
    if (
        treasury_item.get("action_id") != treasury_authorization.get("action_id")
        or treasury_item.get("envelope_hash")
        != treasury_authorization.get("envelope_hash")
    ):
        raise ReleaseManifestError(
            "registry native-transfer claim differs from its artifact"
        )
    safepay_item = by_type["safepay_v2"]
    safepay_adapter = _mapping(
        artifacts["safepay_v2"].adapter_result,
        "SafePay independent adapter result",
    )
    safepay_facts = _mapping(
        safepay_adapter.get("derived_facts"),
        "SafePay independent adapter derived facts",
    )
    if (
        safepay_item.get("proposal_id") != safepay_facts.get("proposal_id")
        or safepay_item.get("network") != safepay_facts.get("network")
        or safepay_item.get("report_hash") != safepay_facts.get("report_hash")
        or safepay_item.get("settlement_transaction")
        != safepay_facts.get("payment_hash")
        or safepay_item.get("checks")
        != _adapter_registry_checks(safepay_adapter, "safepay_v2")
    ):
        raise ReleaseManifestError(
            "registry SafePay claim differs from its independent adapter"
        )
    official_item = by_type["official_x402_settlement_v1"]
    official_adapter = _mapping(
        artifacts["official_x402_settlement_v1"].adapter_result,
        "official-x402 independent adapter result",
    )
    official_facts = _mapping(
        official_adapter.get("derived_facts"),
        "official-x402 independent adapter derived facts",
    )
    if (
        official_item.get("proposal_id") != official_facts.get("proposal_id")
        or official_item.get("action_id") != official_facts.get("action_id")
        or official_item.get("envelope_hash")
        != official_facts.get("envelope_hash")
        or official_item.get("network") != official_facts.get("network")
        or official_item.get("package_hash") != official_facts.get("package_hash")
        or official_item.get("contract_hash") != official_facts.get("contract_hash")
        or official_item.get("deployment_domain")
        != official_facts.get("deployment_domain")
        or official_item.get("payment_requirements_hash")
        != official_facts.get("payment_requirements_hash")
        or official_item.get("signed_payment_payload_hash")
        != official_facts.get("signed_payment_payload_hash")
        or official_item.get("report_hash") != official_facts.get("report_hash")
        or official_item.get("settlement_transaction")
        != official_facts.get("settlement_transaction")
        or official_item.get("checks")
        != _adapter_registry_checks(
            official_adapter,
            "official_x402_settlement_v1",
        )
    ):
        raise ReleaseManifestError(
            "registry official-x402 claim differs from its independent adapter"
        )
    internal_records = _sequence(
        registry.get("internal_records"),
        "registry internal records",
    )
    internal_by_action: dict[str, Mapping[str, Any]] = {}
    for raw_record in internal_records:
        record = _mapping(raw_record, "registry internal record")
        action_id = _hash32(
            record.get("action_id"),
            "registry internal action ID",
        )
        if action_id in internal_by_action:
            raise ReleaseManifestError(
                "registry internal action binding is duplicated"
            )
        internal_by_action[action_id] = record

    exact_input = _mapping(exact_artifact.get("input"), "exact-envelope input")
    exact_header = _mapping(
        exact_input.get("header"),
        "exact-envelope header",
    )
    exact_run = _mapping(exact_artifact.get("run"), "exact-envelope run")
    exact_steps = _sequence(exact_run.get("steps"), "exact-envelope run steps")
    exact_finalizations = [
        _mapping(step, "exact-envelope finalize step")
        for step in exact_steps
        if type(step) is dict and step.get("name") == "finalize_exact"
    ]
    if len(exact_finalizations) != 1:
        raise ReleaseManifestError(
            "exact-envelope artifact lacks one finalization projection"
        )
    exact_finalization = exact_finalizations[0]
    exact_finality = _mapping(
        exact_finalization.get("finality_block_evidence"),
        "exact-envelope finality evidence",
    )
    native_record = internal_by_action.get(
        _hash32(exact_prepared.get("action_id"), "exact-envelope action ID")
    )
    if native_record is None:
        raise ReleaseManifestError(
            "registry lacks the exact native-action internal record"
        )
    expected_native_record = {
        "schema_version": 1,
        "proposal_id": exact_header.get("proposal_id"),
        "proposal_hash": exact_header.get("proposal_hash"),
        "proposal_nonce": exact_header.get("proposal_nonce"),
        "action_id": exact_prepared.get("action_id"),
        "action_kind": exact_input.get("action"),
        "action_version": exact_header.get("action_version"),
        "envelope_hash": exact_prepared.get("envelope_hash"),
        "deployment_domain": exact_header.get("deployment_domain"),
        "network": exact_deployment.get("network"),
        "package_hash": exact_deployment.get("package_hash"),
        "contract_hash": exact_deployment.get("contract_hash"),
        "v3_finalized_exact": True,
        "finalization_transaction": exact_finalization.get("deploy_hash"),
        "finalized_at": exact_finality.get("finalized_at"),
        "resource_url_hash": None,
        "report_hash": None,
        "payment_requirements_hash": None,
        "signed_payment_payload_hash": None,
        "verification_status": "verified",
        "observed_at": exact_item.get("captured_at"),
        "checks": exact_item.get("checks"),
    }
    if native_record != expected_native_record:
        raise ReleaseManifestError(
            "registry native internal record is not the exact artifact projection"
        )

    verified_official_record = _mapping(
        official_adapter.get("internal_record"),
        "official-x402 independent adapter internal record",
    )
    official_action_id = _hash32(
        verified_official_record.get("action_id"),
        "official-x402 adapter action ID",
    )
    official_record = internal_by_action.get(official_action_id)
    if official_record is None:
        raise ReleaseManifestError(
            "registry lacks the official-x402 internal record"
        )
    fact_bound_fields = (
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
        "observed_at",
    )
    if any(
        verified_official_record.get(field) != official_facts.get(field)
        for field in fact_bound_fields
    ):
        raise ReleaseManifestError(
            "official-x402 adapter internal record differs from its derived facts"
        )
    if official_record != verified_official_record:
        raise ReleaseManifestError(
            "registry official-x402 internal record is not the exact "
            "independent adapter projection"
        )
    if set(internal_by_action) != {
        str(exact_prepared.get("action_id")),
        official_action_id,
    }:
        raise ReleaseManifestError(
            "registry internal record inventory differs from release artifacts"
        )
    roots = _mapping(registry.get("card_chain_roots"), "registry roots")
    root_artifact = artifacts["card_chain_roots_v1"]
    if roots != {
        "artifact_path": root_artifact.bound.path,
        "artifact_sha256": root_artifact.bound.sha256,
    }:
        raise ReleaseManifestError("registry card-chain root binding differs")


def _validate_payment_artifact_runtime_binding(
    artifacts: Mapping[str, _Artifact],
    runtime: Mapping[str, object],
) -> None:
    """Bind payment capture identities to the observed deployed image bytes."""

    containers = _sequence(
        runtime.get("containers"),
        "payment artifact runtime containers",
    )
    by_service: dict[str, Mapping[str, Any]] = {}
    for raw in containers:
        container = _mapping(raw, "payment artifact runtime container")
        service_id = _text(
            container.get("service_id"),
            "payment artifact runtime service",
        )
        if service_id in by_service:
            raise ReleaseManifestError("payment runtime service is duplicated")
        by_service[service_id] = container

    bindings = (
        (
            "safepay_v2",
            "x402-provider",
            "provider_image_digest",
            "SafePay provider",
        ),
        (
            "official_x402_settlement_v1",
            "x402-official",
            "service_image_digest",
            "official-x402 service",
        ),
    )
    for artifact_id, service_id, digest_field, label in bindings:
        artifact = artifacts.get(artifact_id)
        if artifact is None:
            raise ReleaseManifestError(f"{label} artifact is unavailable")
        identity = _mapping(
            artifact.document.get("capture_identity"),
            f"{label} capture identity",
        )
        captured_digest = _text(
            identity.get(digest_field),
            f"{label} capture image digest",
        )
        runtime_container = by_service.get(service_id)
        if (
            runtime_container is None
            or captured_digest
            != _text(
                runtime_container.get("image_id"),
                f"{label} runtime image digest",
            )
        ):
            raise ReleaseManifestError(
                f"{label} capture image differs from observed runtime"
            )


def _compose_argv_sha256(
    value: object,
    *,
    label: str,
    allow_normalized_digest: bool,
) -> str | None:
    if value is None:
        return None
    if (
        allow_normalized_digest
        and type(value) is dict
        and set(value) == {_NORMALIZED_ARGV_DIGEST_KEY}
    ):
        return _hash32(value[_NORMALIZED_ARGV_DIGEST_KEY], f"{label} SHA-256")
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _compose_projection(
    root: Path,
    raw: Mapping[str, object],
    canaries: Sequence[bytes],
    *,
    allow_normalized_argv_digests: bool = False,
) -> dict[str, object]:
    compose = _mapping(raw, "rendered Compose config")
    if set(compose) != _COMPOSE_TOP_LEVEL_FIELDS:
        raise ReleaseManifestError("rendered Compose top-level schema is not exact")
    project = compose.get("name", "concordia")
    if project != "concordia":
        raise ReleaseManifestError("Compose project must be exactly concordia")
    services_raw = _mapping(compose.get("services"), "Compose services")
    if set(services_raw) != set(_COMPOSE_SERVICE_ALLOWLIST):
        raise ReleaseManifestError("rendered Compose service allowlist differs")
    config_hashes = _mapping(
        compose.get("x-concordia-observed-service-config-hashes"),
        "Compose observed service config hashes",
    )
    if set(config_hashes) != set(services_raw):
        raise ReleaseManifestError(
            "Compose config hash inventory differs from services"
        )
    network_definitions = _mapping(compose.get("networks"), "Compose networks")
    if set(network_definitions) != {"concordia-edge", "concordia-internal"}:
        raise ReleaseManifestError("Compose top-level network allowlist differs")
    edge = _mapping(network_definitions["concordia-edge"], "Compose edge network")
    internal = _mapping(
        network_definitions["concordia-internal"],
        "Compose internal network",
    )
    if (
        set(edge) != {"name", "external"}
        or edge.get("name") != "concordia-edge"
        or edge.get("external") is not True
        or set(internal) != {"name"}
        or internal.get("name") != "concordia-internal"
    ):
        raise ReleaseManifestError("Compose network definitions differ")
    volume_definitions = _mapping(compose.get("volumes"), "Compose volumes")
    expected_volume_names = {
        mount[1]
        for mounts in _COMPOSE_VOLUME_ALLOWLIST.values()
        for mount in mounts
        if mount[0] == "volume"
    }
    if set(volume_definitions) != expected_volume_names:
        raise ReleaseManifestError("Compose top-level volume allowlist differs")
    for volume_name, raw_definition in volume_definitions.items():
        definition = _mapping(raw_definition, f"Compose volume {volume_name}")
        if set(definition) - {"name"} or definition.get("name", volume_name) not in {
            volume_name,
            f"concordia_{volume_name}",
        }:
            raise ReleaseManifestError("Compose volume definition is unsafe")
    secret_definitions = _mapping(compose.get("secrets"), "Compose secrets")
    expected_secret_targets = {
        target for target, _services in _SECRET_FILE_MATRIX.values()
    }
    if set(secret_definitions) != expected_secret_targets:
        raise ReleaseManifestError("Compose top-level secret allowlist differs")
    for target, raw_definition in secret_definitions.items():
        definition = _mapping(raw_definition, f"Compose secret {target}")
        if set(definition) - {"file", "name"}:
            raise ReleaseManifestError("Compose secret definition shape is unsafe")
        expected_file = f"/opt/apps/concordia/secrets/{_SECRET_HOST_BASENAMES[target]}"
        if (
            definition.get("file") != expected_file
            or definition.get("name", target) not in {target, f"concordia_{target}"}
        ):
            raise ReleaseManifestError(
                "Compose secret definition source is outside the exact allowlist"
            )

    services: list[dict[str, object]] = []
    seen_secret_targets: dict[str, set[str]] = {
        key: set() for key in _PAYMENT_SECRET_POLICY
    }
    for service_id in sorted(services_raw):
        service = _mapping(services_raw[service_id], f"Compose service {service_id}")
        if set(service) - _COMPOSE_SERVICE_FIELDS:
            raise ReleaseManifestError(
                f"Compose service {service_id} has an unknown field"
            )
        if (
            service.get("privileged") not in {None, False}
            or service.get("pid") not in {None, ""}
            or service.get("ipc") not in {None, ""}
            or service.get("network_mode") not in {None, ""}
            or service.get("devices") not in (None, [])
            or service.get("cap_add") not in (None, [])
            or service.get("volumes_from") not in (None, [])
            or service.get("cgroup") not in {None, ""}
            or service.get("uts") not in {None, ""}
            or service.get("userns_mode") not in {None, ""}
        ):
            raise ReleaseManifestError(
                f"Compose service {service_id} enables host-level privileges"
            )
        security_options = service.get("security_opt") or []
        if type(security_options) is not list or security_options not in (
            [],
            ["no-new-privileges:true"],
        ):
            raise ReleaseManifestError(
                f"Compose service {service_id} security options are unsafe"
            )
        if service.get("tmpfs") not in (None, []):
            raise ReleaseManifestError(
                f"Compose service {service_id} tmpfs policy is not frozen"
            )
        build_present = service.get("build") is not None and service.get(
            "build"
        ) is not False
        if build_present != (service_id in _COMPOSE_BUILD_ALLOWLIST):
            raise ReleaseManifestError(
                f"Compose service {service_id} build policy differs"
            )
        if build_present:
            build = _mapping(service.get("build"), f"{service_id} build")
            if (
                set(build)
                - {"context", "dockerfile", "args", "target", "labels"}
                or type(build.get("context")) is not str
                or not build["context"]
                or any(
                    key in build
                    for key in (
                        "network",
                        "privileged",
                        "ssh",
                        "secrets",
                        "extra_hosts",
                        "entitlements",
                    )
                )
            ):
                raise ReleaseManifestError(
                    f"Compose service {service_id} build policy is unsafe"
                )
        if service.get("restart") != "unless-stopped":
            raise ReleaseManifestError(
                f"Compose service {service_id} restart policy differs"
            )
        logging = _mapping(
            service.get("logging"),
            f"{service_id} logging",
        )
        if logging != {
            "driver": "local",
            "options": {"max-file": "5", "max-size": "20m"},
        }:
            raise ReleaseManifestError(
                f"Compose service {service_id} logging policy differs"
            )
        if service.get("read_only") not in {None, True}:
            raise ReleaseManifestError(
                f"Compose service {service_id} read-only policy differs"
            )
        if service.get("cap_drop") not in (None, [], ["ALL"]):
            raise ReleaseManifestError(
                f"Compose service {service_id} capability policy differs"
            )
        if service.get("init") not in {None, True}:
            raise ReleaseManifestError(
                f"Compose service {service_id} init policy differs"
            )
        stop_grace = service.get("stop_grace_period")
        if stop_grace is not None and (
            type(stop_grace) is not str
            or re.fullmatch(r"(?:[1-9][0-9]*)(?:ms|s|m)", stop_grace) is None
        ):
            raise ReleaseManifestError(
                f"Compose service {service_id} stop grace period differs"
            )
        image = _text(service.get("image"), f"{service_id} image")
        local_image = (
            image in _COMPOSE_LOCAL_IMAGES
            or image.startswith("concordia/")
            or image.startswith("concordia-")
        )
        if local_image:
            if image.endswith(":latest") or ":" not in image:
                raise ReleaseManifestError(
                    f"Compose service {service_id} local image is mutable"
                )
            image_policy = "runtime_digest_and_commit_bound"
        else:
            if re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", image) is None:
                raise ReleaseManifestError(
                    f"Compose service {service_id} external image is not digest-pinned"
                )
            image_policy = "compose_digest_pinned"
        environment_raw = service.get("environment") or {}
        environment = _mapping(environment_raw, f"{service_id} environment")
        environment_keys = sorted(str(key) for key in environment)
        granted_targets: set[str] = set()
        for raw_secret in service.get("secrets") or []:
            if type(raw_secret) is str:
                target = raw_secret
            else:
                secret = _mapping(raw_secret, f"{service_id} secret grant")
                if set(secret) != {"source", "target"}:
                    raise ReleaseManifestError("Compose secret grant shape is unsafe")
                source = _text(secret.get("source"), f"{service_id} secret source")
                target = _text(secret.get("target"), f"{service_id} secret target")
                if source != target:
                    raise ReleaseManifestError(
                        "Compose secret source and target differ"
                    )
            if PurePosixPath(target).name != target or not target:
                raise ReleaseManifestError("Compose secret grant target is unsafe")
            if target in granted_targets:
                raise ReleaseManifestError("Compose secret grant is duplicated")
            granted_targets.add(target)
        referenced_targets: set[str] = set()
        for raw_key, raw_value in environment.items():
            if type(raw_key) is not str:
                raise ReleaseManifestError("Compose environment key is invalid")
            if raw_key in _LEGACY_PAYMENT_SECRET_KEYS:
                raise ReleaseManifestError(
                    "Compose uses a forbidden legacy secret/token target"
                )
            normalized = _normalize_semantic_key(raw_key)
            sensitive = raw_key in _SECRET_FILE_MATRIX or any(
                part in normalized for part in _SENSITIVE_KEY_PARTS
            )
            is_file_reference = raw_key.endswith(("_FILE", "_PATH"))
            if sensitive and not is_file_reference:
                raise ReleaseManifestError(
                    "Compose contains direct secret or credential material"
                )
            if is_file_reference and sensitive:
                if raw_key not in _SECRET_FILE_MATRIX:
                    raise ReleaseManifestError(
                        "Compose contains an unknown sensitive secret file key"
                    )
                if type(raw_value) is not str or not raw_value.startswith(
                    "/run/secrets/"
                ):
                    raise ReleaseManifestError("Compose secret file target is unsafe")
                target = PurePosixPath(raw_value).name
                if raw_value != f"/run/secrets/{target}":
                    raise ReleaseManifestError("Compose secret file target is unsafe")
                referenced_targets.add(target)
        for legacy in _LEGACY_PAYMENT_SECRET_KEYS:
            if legacy in environment:
                raise ReleaseManifestError(
                    "Compose uses a forbidden legacy secret/token target"
                )
        for key, allowed_services in _PAYMENT_SECRET_POLICY.items():
            if key in environment:
                if service_id not in allowed_services:
                    raise ReleaseManifestError(
                        f"Compose payment secret target {key} is assigned to an unexpected service"
                    )
                seen_secret_targets[key].add(service_id)
                if environment[key] != _EXACT_SECRET_FILE_TARGETS[key]:
                    raise ReleaseManifestError(
                        "Compose payment secret target path is not exact"
                    )
        expected_targets = {
            target
            for target, services_for_target in _SECRET_FILE_MATRIX.values()
            if service_id in services_for_target
        }
        if referenced_targets != granted_targets or granted_targets != expected_targets:
            raise ReleaseManifestError(
                "Compose secret grants and sensitive file references are not exact"
            )
        public_environment = {
            key: environment[key]
            for key in sorted(environment)
            if key in _PUBLIC_ENV_KEYS and type(environment[key]) in {str, int, bool}
        }
        volumes: list[dict[str, object]] = []
        observed_mounts: set[tuple[str, str, str, bool]] = set()
        for raw_volume in service.get("volumes") or []:
            volume = _mapping(raw_volume, f"{service_id} volume")
            kind = str(volume.get("type", "volume"))
            common_fields = {"type", "source", "target", "read_only"}
            option_fields = set(volume) - common_fields
            if kind == "bind":
                if option_fields - {"bind"}:
                    raise ReleaseManifestError("Compose bind shape is not exact")
                bind_options = _mapping(
                    volume.get("bind") or {},
                    f"{service_id} bind options",
                )
                if set(bind_options) - {"create_host_path"}:
                    raise ReleaseManifestError(
                        "Compose bind options are outside the allowlist"
                    )
            elif kind == "volume":
                if option_fields - {"volume"}:
                    raise ReleaseManifestError("Compose volume shape is not exact")
                if _mapping(
                    volume.get("volume") or {},
                    f"{service_id} volume options",
                ):
                    raise ReleaseManifestError(
                        "Compose volume options are outside the allowlist"
                    )
                bind_options = {}
            else:
                raise ReleaseManifestError("Compose mount type is outside allowlist")
            if not {"type", "source", "target"}.issubset(volume):
                raise ReleaseManifestError("Compose mount shape is not exact")
            source = str(volume.get("source", ""))
            target = _text(volume.get("target"), f"{service_id} volume target")
            read_only = bool(
                volume.get("read_only") is True
                or str(volume.get("mode", "")).lower() == "ro"
            )
            if kind == "bind":
                if source.startswith("/run/secrets/") or target.startswith(
                    "/run/secrets/"
                ):
                    raise ReleaseManifestError(
                        "Compose secret bind mount is forbidden"
                    )
                external_marker = "@release-config/x402-official:"
                source_digest: str | None = None
                if allow_normalized_argv_digests and source.startswith(
                    external_marker
                ):
                    source_digest = _hash32(
                        source.removeprefix(external_marker),
                        "normalized release-config directory digest",
                    )
                    source_identity = "@release-config/x402-official"
                else:
                    try:
                        source_path = Path(source)
                        if (
                            allow_normalized_argv_digests
                            and not source_path.is_absolute()
                        ):
                            source_path = root / source_path
                        resolved_source = source_path.resolve(strict=True)
                        try:
                            relative_source = resolved_source.relative_to(
                                root.resolve(strict=True)
                            ).as_posix()
                        except ValueError:
                            expected_external = (
                                root.parent / "config/x402-official"
                            ).resolve(strict=True)
                            if (
                                target != "/run/config"
                                or resolved_source != expected_external
                            ):
                                raise ReleaseManifestError(
                                    "Compose bind source is outside its release scope"
                                )
                            source_identity = "@release-config/x402-official"
                            source_digest = _bound_external_directory_sha256(
                                resolved_source,
                                label="release-scoped x402 config",
                            )
                        else:
                            source_identity = relative_source
                    except ReleaseManifestError:
                        raise
                    except (OSError, ValueError) as exc:
                        raise ReleaseManifestError(
                            "Compose bind source is unavailable"
                        ) from exc
                expected_create_host_path = (
                    False
                    if source_identity
                    in {
                        "artifacts",
                        "artifacts/live/proof-registry",
                        "@release-config/x402-official",
                    }
                    else None
                )
                if (
                    expected_create_host_path is False
                    and bind_options.get("create_host_path") is not False
                ):
                    raise ReleaseManifestError(
                        "release artifact bind may not create its host path"
                    )
                if (
                    expected_create_host_path is None
                    and bind_options.get("create_host_path") not in {None, True}
                ):
                    raise ReleaseManifestError(
                        "Compose repository-file bind options differ"
                    )
            else:
                source_identity = source
                source_digest = None
            observed_mounts.add((kind, source_identity, target, read_only))
            item: dict[str, object] = {
                "type": kind,
                "target": target,
                "read_only": read_only,
            }
            if kind == "volume":
                item["name"] = _text(
                    volume.get("source"), f"{service_id} volume name"
                )
            else:
                source_path = root / source_identity
                if source_digest is not None:
                    item["source_sha256"] = source_digest
                    item["source_type"] = "directory"
                elif source_path.is_dir():
                    item["source_sha256"] = _bound_repository_directory_sha256(
                        root,
                        source_identity,
                    )
                    item["source_type"] = "directory"
                else:
                    item["source_sha256"] = _load_bound_file(
                        root, source_identity, _CONTROL_LIMIT
                    ).sha256
                    item["source_type"] = "file"
            volumes.append(item)
        if observed_mounts != set(_COMPOSE_VOLUME_ALLOWLIST.get(service_id, ())):
            raise ReleaseManifestError(
                f"Compose service {service_id} mount allowlist differs"
            )
        networks_value = service.get("networks") or {}
        if type(networks_value) is dict:
            for network_name, raw_attachment in networks_value.items():
                attachment = _mapping(
                    raw_attachment or {},
                    f"{service_id} {network_name} network attachment",
                )
                if set(attachment) - {"aliases"}:
                    raise ReleaseManifestError(
                        f"Compose service {service_id} network attachment is unsafe"
                    )
                aliases = attachment.get("aliases") or []
                if (
                    type(aliases) is not list
                    or len(aliases) != len(set(aliases))
                    or any(
                        type(alias) is not str
                        or re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,62}", alias) is None
                        for alias in aliases
                    )
                ):
                    raise ReleaseManifestError(
                        f"Compose service {service_id} network aliases differ"
                    )
            networks = sorted(networks_value)
        elif type(networks_value) is list:
            if any(type(item) is not str for item in networks_value):
                raise ReleaseManifestError("Compose network list is malformed")
            networks = sorted(networks_value)
        else:
            raise ReleaseManifestError("Compose network attachment is malformed")
        if set(networks) != set(_COMPOSE_NETWORK_ALLOWLIST[service_id]):
            raise ReleaseManifestError(
                f"Compose service {service_id} network allowlist differs"
            )
        depends_value = service.get("depends_on") or {}
        if type(depends_value) is dict:
            for dependency, raw_condition in depends_value.items():
                condition = _mapping(
                    raw_condition or {},
                    f"{service_id} dependency {dependency}",
                )
                if set(condition) - {"condition", "required", "restart"} or condition.get(
                    "condition", "service_started"
                ) not in {
                    "service_started",
                    "service_healthy",
                    "service_completed_successfully",
                } or condition.get("required", True) is not True or condition.get(
                    "restart", False
                ) is not False:
                    raise ReleaseManifestError(
                        f"Compose service {service_id} dependency policy differs"
                    )
            depends = sorted(depends_value)
        elif type(depends_value) is list:
            if any(type(item) is not str for item in depends_value):
                raise ReleaseManifestError("Compose dependency list is malformed")
            depends = sorted(depends_value)
        else:
            raise ReleaseManifestError("Compose dependency policy is malformed")
        health = service.get("healthcheck")
        health_projection = None
        if type(health) is dict:
            if (
                set(health)
                - {
                    "test",
                    "interval",
                    "timeout",
                    "retries",
                    "start_period",
                    "start_interval",
                    "disable",
                }
                or health.get("disable") not in {None, False}
                or not isinstance(health.get("test"), list)
                or not health["test"]
                or any(type(item) is not str for item in health["test"])
            ):
                raise ReleaseManifestError(
                    f"Compose service {service_id} healthcheck policy differs"
                )
            health_projection = {
                key: health[key]
                for key in (
                    "interval",
                    "timeout",
                    "retries",
                    "start_period",
                    "start_interval",
                )
                if key in health
            }
            health_projection["test_sha256"] = hashlib.sha256(
                _canonical_json(health["test"])
            ).hexdigest()
        command = service.get("command")
        entrypoint = service.get("entrypoint")
        command_sha256 = _compose_argv_sha256(
            command,
            label=f"{service_id} command",
            allow_normalized_digest=allow_normalized_argv_digests,
        )
        entrypoint_sha256 = _compose_argv_sha256(
            entrypoint,
            label=f"{service_id} entrypoint",
            allow_normalized_digest=allow_normalized_argv_digests,
        )
        config_hash = _hash32(
            config_hashes.get(service_id), f"{service_id} Compose config hash"
        )
        services.append(
            {
                "service_id": service_id,
                "image": image,
                "image_policy": image_policy,
                "has_build": build_present,
                "command_sha256": command_sha256,
                "entrypoint_sha256": entrypoint_sha256,
                "config_hash": config_hash,
                "networks": networks,
                "volumes": volumes,
                "depends_on": depends,
                "healthcheck": health_projection,
                "restart": service.get("restart"),
                "security_sha256": hashlib.sha256(
                    _canonical_json(
                        {
                            "build": service.get("build"),
                            "cap_drop": service.get("cap_drop"),
                            "cpus": service.get("cpus"),
                            "depends_on": service.get("depends_on"),
                            "healthcheck": service.get("healthcheck"),
                            "init": service.get("init"),
                            "logging": service.get("logging"),
                            "mem_limit": service.get("mem_limit"),
                            "read_only": service.get("read_only"),
                            "security_opt": service.get("security_opt"),
                            "stop_grace_period": service.get(
                                "stop_grace_period"
                            ),
                        }
                    )
                ).hexdigest(),
                "environment_keys": environment_keys,
                "public_environment": public_environment,
                "payment_secret_target_names": sorted(
                    key for key in _PAYMENT_SECRET_POLICY if key in environment
                ),
            }
        )
    for key, expected in _PAYMENT_SECRET_POLICY.items():
        if seen_secret_targets[key] != set(expected):
            raise ReleaseManifestError(
                f"Compose payment secret target {key} does not match least-privilege services"
            )
    compose_file = _load_bound_file(root, COMPOSE_FILE_PATH, _CONTROL_LIMIT)
    projection: dict[str, object] = {
        "compose_project": "concordia",
        "tracked_compose": {
            "path": compose_file.path,
            "sha256": compose_file.sha256,
            "artifact_commit": compose_file.artifact_commit,
        },
        "services": services,
    }
    projection["semantic_sha256"] = hashlib.sha256(
        _canonical_json({"compose_project": "concordia", "services": services})
    ).hexdigest()
    _assert_safe_projection(projection, canaries, "Compose projection")
    return projection


_RUNTIME_KEYS = {
    "service_id",
    "project",
    "container_id",
    "config_image",
    "image_id",
    "image_revision",
    "image_source",
    "image_deployment",
    "state_status",
    "health_status",
    "started_at",
    "restart_count",
    "config_hash",
}


def _runtime_projection(
    raw: Sequence[Mapping[str, object]],
    compose_projection: Mapping[str, object],
    canaries: Sequence[bytes],
    *,
    integration_commit: str,
) -> dict[str, object]:
    integration_commit = _git40(integration_commit, "runtime integration commit")
    containers: list[dict[str, object]] = []
    for raw_item in raw:
        item = _mapping(raw_item, "runtime container")
        projected = {key: item.get(key) for key in _RUNTIME_KEYS}
        service_id = _text(projected["service_id"], "runtime service_id")
        if projected["project"] != "concordia":
            raise ReleaseManifestError("runtime container is outside concordia project")
        container_id = _text(projected["container_id"], "runtime container_id")
        if re.fullmatch(r"[0-9a-f]{64}", container_id) is None:
            raise ReleaseManifestError("runtime container ID is invalid")
        if (
            _IMAGE_ID.fullmatch(_text(projected["image_id"], "runtime image ID"))
            is None
        ):
            raise ReleaseManifestError("runtime image content identity is invalid")
        if projected["state_status"] != "running":
            raise ReleaseManifestError(f"runtime service {service_id} is not running")
        if projected["health_status"] not in {"healthy", "none"}:
            raise ReleaseManifestError(f"runtime service {service_id} is unhealthy")
        if (
            type(projected["restart_count"]) is not int
            or projected["restart_count"] < 0
        ):
            raise ReleaseManifestError("runtime restart count is invalid")
        _parse_timestamp(projected["started_at"], "runtime started_at")
        _hash32(projected["config_hash"], "runtime config hash")
        _text(projected["config_image"], "runtime Config.Image")
        containers.append(projected)
    containers.sort(key=lambda item: str(item["service_id"]))
    expected_services = {
        str(item["service_id"])
        for item in _sequence(
            compose_projection.get("services"), "Compose projection services"
        )
    }
    actual_services = {str(item["service_id"]) for item in containers}
    if actual_services != expected_services or len(containers) != len(actual_services):
        raise ReleaseManifestError("runtime inventory differs from rendered Compose")
    compose_by_service = {
        str(item["service_id"]): item
        for item in _sequence(
            compose_projection.get("services"), "Compose projection services"
        )
    }
    for container in containers:
        service = compose_by_service[str(container["service_id"])]
        if container["config_image"] != service.get("image"):
            raise ReleaseManifestError("runtime image differs from rendered Compose")
        if container["config_hash"] != service.get("config_hash"):
            raise ReleaseManifestError(
                "runtime config hash differs from rendered Compose"
            )
        has_healthcheck = service.get("healthcheck") is not None
        expected_health = "healthy" if has_healthcheck else "none"
        if container["health_status"] != expected_health:
            raise ReleaseManifestError(
                "runtime health status does not match Compose healthcheck presence"
            )
        image = _text(service.get("image"), "Compose service image")
        if "@sha256:" in image:
            if re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", image) is None:
                raise ReleaseManifestError(
                    "third-party runtime image is not digest pinned"
                )
            if any(
                container.get(field) not in {None, ""}
                for field in ("image_revision", "image_source", "image_deployment")
            ):
                raise ReleaseManifestError(
                    "third-party image has unexpected project labels"
                )
        else:
            if (
                container.get("image_revision") != integration_commit
                or container.get("image_deployment") != integration_commit
                or container.get("image_source")
                != "https://github.com/asadvendor-boop/concordia-dao-council"
            ):
                raise ReleaseManifestError(
                    "project runtime image OCI identity does not bind the integration commit"
                )
    projection = {"containers": containers}
    _assert_safe_projection(projection, canaries, "runtime projection")
    return projection


def _same_caddy_secret_observation(left: object, right: object) -> bool:
    if type(left) is str and type(right) is str:
        return secrets.compare_digest(left, right)
    if (
        type(left) is dict
        and set(left) == {_NORMALIZED_SECRET_KEY}
        and type(right) is dict
        and set(right) == {_NORMALIZED_SECRET_KEY}
    ):
        left_digest = _hash32(
            left[_NORMALIZED_SECRET_KEY],
            "active Caddy secret digest",
        )
        right_digest = _hash32(
            right[_NORMALIZED_SECRET_KEY],
            "expected Caddy secret digest",
        )
        return secrets.compare_digest(left_digest, right_digest)
    return False


def _caddy_handlers(
    value: object,
    *,
    expected_bcrypt_value: object,
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    if type(value) is list:
        for nested in value:
            result.extend(
                _caddy_handlers(
                    nested,
                    expected_bcrypt_value=expected_bcrypt_value,
                )
            )
        return result
    if type(value) is not dict:
        return result
    handler = value.get("handler")
    if type(handler) is str:
        if handler == "authentication":
            providers = (
                value.get("providers") if type(value.get("providers")) is dict else {}
            )
            basic = (
                providers.get("http_basic")
                if type(providers.get("http_basic")) is dict
                else {}
            )
            hash_value = basic.get("hash") if type(basic.get("hash")) is dict else {}
            accounts = (
                basic.get("accounts") if type(basic.get("accounts")) is list else []
            )
            account_projection: list[dict[str, object]] = []
            for raw_account in accounts:
                account = _mapping(raw_account, "Caddy basic-auth account")
                if set(account) != {"username", "password"}:
                    raise ReleaseManifestError("Caddy basic-auth account shape differs")
                username_sha256 = _observation_text_sha256(
                    account.get("username"), "Caddy basic-auth username"
                )
                if not _same_caddy_secret_observation(
                    account.get("password"),
                    expected_bcrypt_value,
                ):
                    raise ReleaseManifestError(
                        "Caddy authentication password differs from approval material"
                    )
                account_projection.append(
                    {
                        "username_sha256": username_sha256,
                        "bcrypt_secret_file_match": True,
                    }
                )
            result.append(
                {
                    "handler": "authentication",
                    "providers": sorted(str(item) for item in providers),
                    "auth_algorithm": hash_value.get("algorithm"),
                    "auth_account_count": len(accounts),
                    "accounts": account_projection,
                }
            )
        elif handler == "headers":
            request = value.get("request") if type(value.get("request")) is dict else {}
            operations: list[dict[str, object]] = []
            for operation in ("set", "add", "delete", "replace"):
                values = request.get(operation)
                if type(values) is dict:
                    for name in sorted(values):
                        header_value = values[name]
                        if type(header_value) is list:
                            value_present = (
                                len(header_value) == 1
                                and _observation_text_sha256(
                                    header_value[0],
                                    "Caddy request header value",
                                    required=False,
                                )
                                is not None
                            )
                        else:
                            value_present = (
                                _observation_text_sha256(
                                    header_value,
                                    "Caddy request header value",
                                    required=False,
                                )
                                is not None
                            )
                        projected_value = (
                            header_value[0]
                            if type(header_value) is list
                            and len(header_value) == 1
                            else header_value
                        )
                        operations.append(
                            {
                                "operation": operation,
                                "name": name,
                                "value_present": value_present,
                                "value_sha256": (
                                    _observation_text_sha256(
                                        projected_value,
                                        "Caddy request header value",
                                    )
                                    if value_present
                                    else None
                                ),
                            }
                        )
                elif type(values) is list:
                    for name in sorted(str(item) for item in values):
                        operations.append(
                            {
                                "operation": operation,
                                "name": name,
                                "value_present": False,
                                "value_sha256": None,
                            }
                        )
            result.append({"handler": "headers", "operations": operations})
        elif handler == "reverse_proxy":
            upstreams = (
                value.get("upstreams") if type(value.get("upstreams")) is list else []
            )
            dials = [
                _text(item.get("dial"), "Caddy upstream")
                for item in upstreams
                if type(item) is dict
            ]
            if any(
                "@" in dial or any(char.isspace() for char in dial) for dial in dials
            ):
                raise ReleaseManifestError(
                    "Caddy upstream contains credential-like material"
                )
            result.append(
                {
                    "handler": "reverse_proxy",
                    "upstreams": sorted(dials),
                }
            )
        else:
            result.append({"handler": handler})
    for key in ("handle", "routes"):
        if key in value:
            result.extend(
                _caddy_handlers(
                    value[key],
                    expected_bcrypt_value=expected_bcrypt_value,
                )
            )
    return result


def _observation_text_sha256(
    value: object,
    label: str,
    *,
    required: bool = True,
) -> str | None:
    if type(value) is str and value and value == value.strip():
        return hashlib.sha256(value.encode()).hexdigest()
    if type(value) is dict and set(value) == {_NORMALIZED_SECRET_KEY}:
        return _hash32(value[_NORMALIZED_SECRET_KEY], f"{label} digest")
    if required:
        raise ReleaseManifestError(f"{label} is unavailable")
    return None


def _caddy_projection(
    raw: Mapping[str, object], canaries: Sequence[bytes]
) -> dict[str, object]:
    wrapper = _mapping(raw, "Caddy observation")
    if set(wrapper) != {
        "active_config",
        "approval_material",
        "unauthenticated_probes",
        "authenticated_probes",
    }:
        raise ReleaseManifestError("Caddy observation schema is not exact")
    active = _mapping(wrapper.get("active_config"), "active Caddy config")
    approval_material = _mapping(
        wrapper.get("approval_material"), "Caddy approval material"
    )
    if set(approval_material) != {
        "username_sha256",
        "bcrypt_value",
        "proxy_secret_sha256",
    }:
        raise ReleaseManifestError("Caddy approval material schema is not exact")
    expected_material = {
        key: _hash32(approval_material.get(key), f"Caddy {key}")
        for key in ("username_sha256", "proxy_secret_sha256")
    }
    expected_bcrypt_value = approval_material.get("bcrypt_value")
    if not (
        (
            type(expected_bcrypt_value) is str
            and re.fullmatch(
                r"\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}",
                expected_bcrypt_value,
            )
            is not None
        )
        or (
            type(expected_bcrypt_value) is dict
            and set(expected_bcrypt_value) == {_NORMALIZED_SECRET_KEY}
            and _hash32(
                expected_bcrypt_value[_NORMALIZED_SECRET_KEY],
                "Caddy bcrypt normalized digest",
            )
        )
    ):
        raise ReleaseManifestError("Caddy approval bcrypt material is malformed")
    apps = _mapping(active.get("apps"), "Caddy apps")
    http = _mapping(apps.get("http"), "Caddy HTTP app")
    servers = _mapping(http.get("servers"), "Caddy servers")
    routes: list[dict[str, object]] = []

    def walk_routes(
        raw_routes: object,
        *,
        server_id: str,
        order_prefix: tuple[int, ...] = (),
        inherited_hosts: Sequence[str] = (),
        inherited_paths: Sequence[str] = (),
        inherited_matchers: Sequence[Mapping[str, object]] = (),
        inherited_handlers: Sequence[Mapping[str, object]] = (),
        inherited_terminal: bool = False,
    ) -> None:
        for index, raw_route in enumerate(_sequence(raw_routes, "Caddy routes")):
            route = _mapping(raw_route, "Caddy route")
            hosts: set[str] = set(inherited_hosts)
            paths: set[str] = set(inherited_paths)
            local_hosts: set[str] = set()
            local_paths: set[str] = set()
            local_matchers: list[dict[str, object]] = []
            for raw_match in route.get("match") or []:
                match = _mapping(raw_match, "Caddy route match")
                unknown_matcher_keys = sorted(
                    str(key) for key in set(match) - {"host", "path", "method"}
                )
                match_hosts = sorted(str(item) for item in match.get("host") or [])
                match_paths = sorted(str(item) for item in match.get("path") or [])
                match_methods = sorted(
                    str(item).upper() for item in match.get("method") or []
                )
                local_hosts.update(match_hosts)
                local_paths.update(match_paths)
                local_matchers.append(
                    {
                        "hosts": match_hosts or sorted(inherited_hosts),
                        "paths": match_paths or sorted(inherited_paths),
                        "methods": match_methods,
                        "unknown_keys": unknown_matcher_keys,
                    }
                )
            if local_hosts:
                hosts = local_hosts
            if local_paths:
                paths = local_paths
            effective_matchers = local_matchers or [
                dict(item) for item in inherited_matchers
            ]
            if not effective_matchers:
                effective_matchers = [
                    {
                        "hosts": sorted(hosts),
                        "paths": sorted(paths),
                        "methods": [],
                        "unknown_keys": [],
                    }
                ]
            direct_handlers: list[dict[str, object]] = [
                dict(item) for item in inherited_handlers
            ]
            nested: list[Mapping[str, object]] = []
            for raw_handle in route.get("handle") or []:
                handle = _mapping(raw_handle, "Caddy handler")
                if handle.get("handler") == "subroute" and "routes" in handle:
                    nested.append(handle)
                else:
                    direct_handlers.extend(
                        _caddy_handlers(
                            handle,
                            expected_bcrypt_value=expected_bcrypt_value,
                        )
                    )
            order = order_prefix + (index,)
            if direct_handlers:
                routes.append(
                    {
                        "server_id": server_id,
                        "order": ".".join(str(part) for part in order),
                        "hosts": sorted(hosts),
                        "paths": sorted(paths),
                        "matchers": effective_matchers,
                        "terminal": inherited_terminal or route.get("terminal") is True,
                        "handlers": direct_handlers,
                    }
                )
            for nested_index, handle in enumerate(nested):
                walk_routes(
                    handle.get("routes"),
                    server_id=server_id,
                    order_prefix=order + (nested_index,),
                    inherited_hosts=sorted(hosts),
                    inherited_paths=sorted(paths),
                    inherited_matchers=effective_matchers,
                    inherited_handlers=direct_handlers,
                    inherited_terminal=(
                        inherited_terminal or route.get("terminal") is True
                    ),
                )

    for server_id in sorted(servers):
        server = _mapping(servers[server_id], "Caddy server")
        walk_routes(server.get("routes"), server_id=server_id)
    if not routes:
        raise ReleaseManifestError("Caddy active topology has no route")
    cohost_routes = [
        route
        for route in routes
        if hashlib.sha256(
            _canonical_json(
                {
                    key: route[key]
                    for key in ("hosts", "paths", "matchers", "handlers")
                }
            )
        ).hexdigest()
        == _SHARED_COHOST_MCP_ROUTE_SHA256
    ]
    if len(cohost_routes) != 1:
        raise ReleaseManifestError(
            "shared Caddy topology lost the exact cohost /mcp binding"
        )
    approvals = [
        route
        for route in routes
        if any(path.startswith("/approve") for path in route["paths"])
    ]
    expected_approval_hosts = {
        "concordia.47.84.232.193.sslip.io",
        "concordiadao.xyz",
    }
    host_counts = {host: 0 for host in expected_approval_hosts}
    if not approvals:
        raise ReleaseManifestError("approval Caddy route is missing")
    for approval in approvals:
        hosts = set(approval["hosts"])
        if not hosts or not hosts.issubset(expected_approval_hosts):
            raise ReleaseManifestError("approval route has an unexpected host")
        if approval["paths"] != ["/approve*"]:
            raise ReleaseManifestError("approval route has an unexpected path")
        if approval.get("terminal") is not True:
            raise ReleaseManifestError("approval route must be terminal")
        matchers = _sequence(approval.get("matchers"), "approval Caddy matchers")
        if not matchers or any(
            set(
                _sequence(
                    _mapping(item, "approval matcher").get("hosts"),
                    "approval hosts",
                )
            )
            - expected_approval_hosts
            or _sequence(
                _mapping(item, "approval matcher").get("paths"),
                "approval paths",
            )
            != ["/approve*"]
            or _mapping(item, "approval matcher").get("methods") != []
            or _mapping(item, "approval matcher").get("unknown_keys") != []
            for item in matchers
        ):
            raise ReleaseManifestError("approval route matcher alternatives differ")
        for host in hosts:
            host_counts[host] += 1
        handlers = approval["handlers"]
        if [item.get("handler") for item in handlers] != [
            "authentication",
            "headers",
            "reverse_proxy",
        ]:
            raise ReleaseManifestError(
                "approval Caddy handler order does not enforce authentication first"
            )
        auth = [item for item in handlers if item.get("handler") == "authentication"]
        if (
            len(auth) != 1
            or auth[0].get("providers") != ["http_basic"]
            or auth[0].get("auth_algorithm") != "bcrypt"
            or auth[0].get("auth_account_count") != 1
            or auth[0].get("accounts")
            != [
                {
                    "username_sha256": expected_material["username_sha256"],
                    "bcrypt_secret_file_match": True,
                }
            ]
        ):
            raise ReleaseManifestError(
                "approval route authentication provider must be http_basic with bcrypt"
            )
        header_sets = [
            operation
            for handler in handlers
            if handler.get("handler") == "headers"
            for operation in handler.get("operations", [])
            if operation.get("name") == "X-Proxy-Secret"
        ]
        if header_sets != [
            {
                "operation": "set",
                "name": "X-Proxy-Secret",
                "value_present": True,
                "value_sha256": expected_material["proxy_secret_sha256"],
            }
        ]:
            raise ReleaseManifestError(
                "approval route does not overwrite X-Proxy-Secret"
            )
        proxies = [item for item in handlers if item.get("handler") == "reverse_proxy"]
        if proxies != [{"handler": "reverse_proxy", "upstreams": ["gateway:8000"]}]:
            raise ReleaseManifestError("approval route lacks one exact gateway proxy")
    if any(count != 1 for count in host_counts.values()):
        raise ReleaseManifestError(
            "approval route host coverage is missing or ambiguous"
        )

    def matcher_overlaps(matcher: Mapping[str, object], host: str) -> bool:
        matcher_hosts = set(_sequence(matcher.get("hosts"), "Caddy matcher hosts"))
        matcher_paths = _sequence(matcher.get("paths"), "Caddy matcher paths")
        matcher_methods = set(
            _sequence(matcher.get("methods"), "Caddy matcher methods")
        )
        host_match = not matcher_hosts or host in matcher_hosts
        path_match = not matcher_paths or any(
            path in {"*", "/*", "/approve", "/approve*"} or path.startswith("/approve/")
            for path in matcher_paths
        )
        method_match = not matcher_methods or bool(matcher_methods & {"GET", "POST"})
        return host_match and path_match and method_match

    for host in expected_approval_hosts:
        approval_route = next(route for route in approvals if host in route["hosts"])
        approval_order = tuple(int(part) for part in approval_route["order"].split("."))
        for route in routes:
            route_order = tuple(int(part) for part in route["order"].split("."))
            if route is approval_route or route_order >= approval_order:
                continue
            if any(
                matcher_overlaps(_mapping(item, "Caddy matcher"), host)
                for item in _sequence(route.get("matchers"), "Caddy matchers")
            ):
                raise ReleaseManifestError(
                    "an earlier overlapping Caddy route can bypass approval authentication"
                )

    expected_unauthenticated = [
        {
            "host": host,
            "method": method,
            "mode": mode,
            "status": 401,
            "basic_challenge": True,
            "reached_gateway": False,
        }
        for host in sorted(expected_approval_hosts)
        for method, mode in (
            ("GET", "unauthenticated"),
            ("POST", "unauthenticated"),
            ("GET", "spoofed_proxy_header"),
        )
    ]
    unauthenticated = _sequence(
        wrapper.get("unauthenticated_probes"), "Caddy unauthenticated probes"
    )
    if unauthenticated != expected_unauthenticated:
        raise ReleaseManifestError("Caddy unauthenticated approval probes differ")
    expected_authenticated = [
        {
            "host": host,
            "method": "GET",
            "status": 200,
            "bcrypt_verified": True,
            "gateway_proxy_verified": True,
        }
        for host in sorted(expected_approval_hosts)
    ]
    authenticated = _sequence(
        wrapper.get("authenticated_probes"), "Caddy authenticated probes"
    )
    if authenticated != expected_authenticated:
        raise ReleaseManifestError("Caddy authenticated approval probes differ")

    projection_material = {
        **expected_material,
        "bcrypt_secret_file_match": True,
    }
    projection: dict[str, object] = {
        "routes": routes,
        "approval_material": projection_material,
        "unauthenticated_probes": unauthenticated,
        "authenticated_probes": authenticated,
    }
    projection["semantic_sha256"] = hashlib.sha256(_canonical_json(routes)).hexdigest()
    _assert_safe_projection(projection, canaries, "Caddy projection")
    return projection


_SAFE_HTTP_HEADERS = {
    "location": "Location",
    "content-type": "Content-Type",
    "cache-control": "Cache-Control",
    "content-disposition": "Content-Disposition",
    "www-authenticate": "WWW-Authenticate",
}


def _tls_projection(
    value: object, *, host: str, now: datetime, canaries: Sequence[bytes]
) -> dict[str, object]:
    tls = _mapping(value, "TLS observation")
    certificate_sha256 = _hash32(
        tls.get("certificate_sha256"), "TLS certificate SHA-256"
    )
    protocol = _text(tls.get("protocol"), "TLS protocol")
    if protocol not in {"TLSv1.2", "TLSv1.3"}:
        raise ReleaseManifestError("TLS protocol is below 1.2")
    cipher = _text(tls.get("cipher"), "TLS cipher")
    sans = sorted(str(item).lower() for item in _sequence(tls.get("sans"), "TLS SANs"))
    if host.lower() not in sans:
        raise ReleaseManifestError("TLS certificate SAN does not match expected host")
    not_before, _ = _parse_timestamp(tls.get("not_before"), "TLS not_before")
    not_after, expiry = _parse_timestamp(tls.get("not_after"), "TLS not_after")
    if expiry < now + timedelta(days=7):
        raise ReleaseManifestError("TLS certificate expires in fewer than seven days")
    resolved = sorted(
        str(item) for item in _sequence(tls.get("resolved_ips"), "DNS IPs")
    )
    dns = _mapping(tls.get("dns"), "DNS observation")
    dns_addresses = sorted(
        str(item) for item in _sequence(dns.get("addresses"), "DNS address records")
    )
    cnames = sorted(
        str(item).lower() for item in _sequence(dns.get("cnames"), "DNS CNAME records")
    )
    if dns_addresses != resolved:
        raise ReleaseManifestError(
            "DNS record projection differs from connection resolution"
        )
    expectation = _FIXED_DNS_EXPECTATIONS.get(host)
    if expectation is None:
        raise ReleaseManifestError("release host has no fixed DNS expectation")
    expected_addresses = expectation["addresses"]
    expected_cnames = list(expectation["cnames"] or ())
    if expected_addresses is not None and dns_addresses != list(expected_addresses):
        raise ReleaseManifestError("DNS differs from the fixed deployment target")
    if cnames != expected_cnames:
        if host == "docs.concordiadao.xyz":
            raise ReleaseManifestError(
                "docs CNAME differs from the fixed GitHub Pages target"
            )
        raise ReleaseManifestError("DNS differs from the fixed deployment target")
    peer = _text(tls.get("peer_ip"), "TLS peer IP")
    if peer not in resolved:
        raise ReleaseManifestError("TLS peer is outside the freshly resolved IP set")
    projection = {
        "certificate_sha256": certificate_sha256,
        "protocol": protocol,
        "cipher": cipher,
        "sans": sans,
        "not_before": not_before,
        "not_after": not_after,
        "issuer_cn": _text(tls.get("issuer_cn"), "TLS issuer CN"),
        "resolved_ips": resolved,
        "dns": {"addresses": dns_addresses, "cnames": cnames},
        "peer_ip": peer,
    }
    _assert_safe_projection(projection, canaries, "TLS projection")
    return projection


def _strict_probe_json(body: bytes, probe_id: str) -> dict[str, Any]:
    value, _ = _strict_json(body, f"HTTP probe {probe_id} JSON")
    return value


def _cid_sha256(cid: str) -> bytes:
    if not cid.startswith("b"):
        raise ReleaseManifestError("IPFS CID is not canonical base32 multibase")
    encoded = cid[1:].upper()
    try:
        decoded = base64.b32decode(
            encoded + "=" * ((8 - len(encoded) % 8) % 8), casefold=False
        )
    except binascii.Error as exc:
        raise ReleaseManifestError("IPFS CID base32 is invalid") from exc
    # CIDv1 + raw codec + sha2-256 multihash + 32-byte digest.
    if len(decoded) != 36 or decoded[:4] != bytes.fromhex("01551220"):
        raise ReleaseManifestError("IPFS CID codec or multihash is not fixed")
    return decoded[4:]


def _pdf_certificate_checks(body: bytes, safe_headers: Mapping[str, str]) -> list[str]:
    expected_disposition = (
        'attachment; filename="concordia-governance-certificate-' + _PROPOSAL + '.pdf"'
    )
    if safe_headers.get("Content-Disposition") != expected_disposition:
        raise ReleaseManifestError("certificate PDF disposition differs")
    if len(body) < 1_024 or not body.startswith(b"%PDF-"):
        raise ReleaseManifestError("certificate PDF is not parseable")
    try:
        import pypdf

        if pypdf.__version__ != "6.14.2":
            raise ReleaseManifestError("certificate PDF parser version is not approved")

        reader = pypdf.PdfReader(io.BytesIO(body), strict=True)
        if reader.is_encrypted or not reader.pages:
            raise ReleaseManifestError("certificate PDF is encrypted or has no pages")
        metadata = reader.metadata
        if (
            metadata is None
            or metadata.title != f"Concordia Governance Certificate - {_PROPOSAL}"
            or metadata.author != "Concordia DAO Council"
        ):
            raise ReleaseManifestError("certificate PDF title or author differs")
        catalog = reader.trailer.get("/Root")
        if catalog is None:
            raise ReleaseManifestError("certificate PDF has no catalog")
        catalog_object = catalog.get_object()

        # A passive certificate must remain passive throughout the complete
        # reachable object graph.  Checking only the catalog misses actions on
        # pages, annotations, widgets, names trees, and indirect descendants.
        active_keys = {
            "/A",
            "/AA",
            "/AcroForm",
            "/EF",
            "/EmbeddedFiles",
            "/GoToR",
            "/ImportData",
            "/JS",
            "/JavaScript",
            "/Launch",
            "/OpenAction",
            "/RichMedia",
            "/SubmitForm",
            "/URI",
            "/XFA",
        }
        active_subtypes = {"/FileAttachment", "/RichMedia", "/Screen", "/Widget"}
        visited: set[tuple[str, int, int] | tuple[str, int]] = set()
        remaining: list[object] = [catalog_object, *reader.pages]
        objects_seen = 0
        while remaining:
            current = remaining.pop()
            indirect_id = getattr(current, "idnum", None)
            generation = getattr(current, "generation", None)
            if type(indirect_id) is int and type(generation) is int:
                identity: tuple[str, int, int] | tuple[str, int] = (
                    "indirect",
                    indirect_id,
                    generation,
                )
                if identity in visited:
                    continue
                visited.add(identity)
                current = current.get_object()
            elif isinstance(current, (dict, list, tuple)):
                identity = ("direct", id(current))
                if identity in visited:
                    continue
                visited.add(identity)
            else:
                continue
            objects_seen += 1
            if objects_seen > 100_000:
                raise ReleaseManifestError("certificate PDF object graph is oversized")
            if isinstance(current, Mapping):
                keys = {str(key) for key in current}
                if (
                    keys & active_keys
                    or str(current.get("/Subtype")) in active_subtypes
                ):
                    raise ReleaseManifestError(
                        "certificate PDF contains active content"
                    )
                remaining.extend(current.values())
            elif isinstance(current, (list, tuple)):
                remaining.extend(current)
        extracted = "\n".join(page.extract_text() or "" for page in reader.pages)
    except ReleaseManifestError:
        raise
    except Exception as exc:
        raise ReleaseManifestError(
            "certificate PDF parser rejected the document"
        ) from exc
    if "Concordia" not in extracted or _PROPOSAL not in extracted:
        raise ReleaseManifestError("certificate PDF visible proposal binding differs")
    return [
        "strict_pdf_parser",
        "certificate_title",
        "proposal_binding",
        "exact_content_disposition",
        "passive_document",
    ]


def _resolve_openapi_schema(
    document: Mapping[str, object], schema_value: object, label: str
) -> dict[str, Any]:
    schema = _mapping(schema_value, f"{label} OpenAPI schema")
    if "$ref" not in schema:
        return schema
    if set(schema) != {"$ref"}:
        raise ReleaseManifestError(f"{label} OpenAPI schema reference has siblings")
    reference = _text(schema.get("$ref"), f"{label} OpenAPI schema reference")
    prefix = "#/components/schemas/"
    if not reference.startswith(prefix) or "/" in reference[len(prefix) :]:
        raise ReleaseManifestError(f"{label} OpenAPI schema reference is not local")
    components = _mapping(document.get("components"), "provider OpenAPI components")
    schemas = _mapping(components.get("schemas"), "provider OpenAPI schemas")
    return _mapping(schemas.get(reference[len(prefix) :]), f"{label} resolved schema")


def _openapi_json_body(
    document: Mapping[str, object], operation: Mapping[str, object], label: str
) -> dict[str, Any]:
    request_body = _mapping(operation.get("requestBody"), f"{label} request body")
    if request_body.get("required") is not True:
        raise ReleaseManifestError(f"{label} OpenAPI request body is not required")
    content = _mapping(request_body.get("content"), f"{label} OpenAPI content")
    media = _mapping(content.get("application/json"), f"{label} JSON media type")
    schema = _resolve_openapi_schema(document, media.get("schema"), label)
    if not schema:
        raise ReleaseManifestError(f"{label} OpenAPI schema is empty")
    return schema


def _provider_openapi_checks(body: bytes) -> list[str]:
    document = _strict_probe_json(body, "provider_openapi")
    if not str(document.get("openapi", "")).startswith("3."):
        raise ReleaseManifestError("provider OpenAPI version differs")
    info = _mapping(document.get("info"), "provider OpenAPI info")
    if info.get("title") != "Concordia Risk Oracle Provider":
        raise ReleaseManifestError("provider OpenAPI title differs")
    paths = _mapping(document.get("paths"), "provider OpenAPI paths")
    operations: dict[str, dict[str, Any]] = {}
    schemas: dict[str, dict[str, Any]] = {}
    http_methods = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}
    for path in ("/x402/v2/quotes", "/x402/v2/redemptions"):
        item = _mapping(paths.get(path), f"provider OpenAPI {path}")
        methods = {
            str(name).lower() for name in item if str(name).lower() in http_methods
        }
        if methods != {"post"}:
            raise ReleaseManifestError("provider OpenAPI v2 routes are not POST-only")
        operation = _mapping(item.get("post"), f"provider OpenAPI POST {path}")
        schemas[path] = _openapi_json_body(document, operation, path)
        operations[path] = operation
    quote_responses = _mapping(
        operations["/x402/v2/quotes"].get("responses"), "quote OpenAPI responses"
    )
    redemption_responses = _mapping(
        operations["/x402/v2/redemptions"].get("responses"),
        "redemption OpenAPI responses",
    )
    if "402" not in quote_responses or "200" not in redemption_responses:
        raise ReleaseManifestError("provider OpenAPI response statuses differ")
    redemption_bytes = _canonical_json(operations["/x402/v2/redemptions"]).lower()
    if b"x-payment" in redemption_bytes or b"x_payment" in redemption_bytes:
        raise ReleaseManifestError("provider OpenAPI permits legacy payment headers")
    expected_quote = {
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "proposal_id", "resource_id"],
        "properties": {
            "schema_version": {"const": "safepay-quote-request-v2"},
            "proposal_id": {"type": "string", "pattern": "^[A-Z0-9-]{1,64}$"},
            "resource_id": {"type": "string", "minLength": 1, "maxLength": 200},
        },
    }
    expected_redemption = {
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "quote", "payment_hash"],
        "properties": {
            "schema_version": {"const": "safepay-redemption-v2"},
            "quote": {"$ref": "#/components/schemas/SafePayQuoteV2"},
            "payment_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
    }
    if schemas["/x402/v2/quotes"] != expected_quote:
        raise ReleaseManifestError("provider OpenAPI quote schema binding differs")
    if schemas["/x402/v2/redemptions"] != expected_redemption:
        raise ReleaseManifestError("provider OpenAPI redemption schema binding differs")
    expected_immutable_quote = {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "quote_id",
            "proposal_id",
            "resource_id",
            "network",
            "payee_account_hash",
            "amount_motes",
            "correlation_id",
            "report_version",
            "report_hash",
            "expires_at",
            "quote_nonce",
            "quote_hash",
        ],
        "properties": {
            "schema_version": {"const": "safepay-v2"},
            "quote_id": {
                "type": "string",
                "pattern": (
                    "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
                    "[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
                ),
            },
            "proposal_id": {"type": "string", "pattern": "^[A-Z0-9-]{1,64}$"},
            "resource_id": {"type": "string", "minLength": 1, "maxLength": 200},
            "network": {"const": "casper:casper-test"},
            "payee_account_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "amount_motes": {
                "type": "string",
                "pattern": "^[1-9][0-9]*$",
                "maxLength": 155,
            },
            "correlation_id": {
                "type": "string",
                "pattern": "^(0|[1-9][0-9]*)$",
                "maxLength": 20,
            },
            "report_version": {"const": "safepay-report-v2"},
            "report_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "expires_at": {
                "type": "integer",
                "minimum": 1,
                "maximum": 18_446_744_073_709_551_615,
            },
            "quote_nonce": {
                "type": "string",
                "pattern": "^(?!0{64}$)[0-9a-f]{64}$",
            },
            "quote_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
    }
    immutable_quote = _resolve_openapi_schema(
        document,
        expected_redemption["properties"]["quote"],
        "SafePay immutable quote",
    )
    if immutable_quote != expected_immutable_quote:
        raise ReleaseManifestError(
            "provider OpenAPI immutable quote schema binding differs"
        )
    return ["quote_post_schema", "redemption_post_schema", "legacy_header_forbidden"]


_CARD_PROPOSAL_ID_FIELDS = {
    "ProposalCard": "signal_id",
    "TriageDecision": "proposal_id",
    "Assessment": "proposal_id",
    "Verdict": "proposal_id",
    "ResponsePlan": "proposal_id",
    "StructuredApproval": "proposal_id",
    "PolicyAuthorization": "proposal_id",
    "CasperExecutionReceipt": "proposal_id",
    "GovernanceSummary": "proposal_id",
}
_DYNAMIC_PUBLIC_TIMESTAMP_FIELDS = {
    "card_chain": "captured_at",
    "proof_registry": "generated_at",
    "proof_registry_official": "generated_at",
    "trace": "generated_at",
}


def _parse_public_utc(value: object, label: str) -> tuple[str, datetime]:
    if type(value) is not str or len(value) > 40:
        raise ReleaseManifestError(f"{label} is not a bounded UTC timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ReleaseManifestError(f"{label} is not a valid UTC timestamp") from exc
    if parsed.utcoffset() != timedelta(0):
        raise ReleaseManifestError(f"{label} is not UTC")
    canonical = parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return canonical, parsed.astimezone(UTC)


def _public_document_safe(
    value: object,
    *,
    label: str,
    canaries: Sequence[bytes],
) -> None:
    raw = _canonical_json(value)
    _assert_no_canary(raw, canaries, label)
    if any(pattern.search(raw) for pattern in _SECRET_TEXT_PATTERNS):
        raise ReleaseManifestError(f"{label} contains sensitive material")
    forbidden_keys = {
        "access_token",
        "api_key",
        "authorization",
        "bearer",
        "client_secret",
        "cookie",
        "credential",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "session",
    }
    stack = [value]
    nodes = 0
    while stack:
        current = stack.pop()
        nodes += 1
        if nodes > 100_000:
            raise ReleaseManifestError(f"{label} is structurally oversized")
        if type(current) is dict:
            for key, nested in current.items():
                normalized = str(key).strip().lower().replace("-", "_")
                if normalized in forbidden_keys or any(
                    normalized.endswith("_" + suffix)
                    for suffix in ("password", "private_key", "secret", "token")
                ):
                    raise ReleaseManifestError(f"{label} contains a sensitive field")
                stack.append(nested)
        elif type(current) is list:
            stack.extend(current)


def _public_release_graph(
    root: Path,
    by_id: Mapping[str, Mapping[str, object]],
    *,
    now: datetime,
    canaries: Sequence[bytes],
) -> dict[str, dict[str, object]]:
    def document(probe_id: str) -> dict[str, Any]:
        body = by_id[probe_id].get("body")
        if type(body) is not bytes:
            raise ReleaseManifestError(f"HTTP probe {probe_id} body is unavailable")
        parsed = _strict_probe_json(body, probe_id)
        _public_document_safe(parsed, label=f"public {probe_id}", canaries=canaries)
        return parsed

    chain = document("card_chain")
    if (
        set(chain)
        != {
            "schema_version",
            "proposal_id",
            "captured_at",
            "source_url",
            "cards",
        }
        or chain.get("schema_version") != "concordia.card_chain.v1"
    ):
        raise ReleaseManifestError("public card-chain shape differs")
    if (
        chain.get("proposal_id") != _PROPOSAL
        or chain.get("source_url") != HTTP_PROBE_SPECS["card_chain"]["url"]
    ):
        raise ReleaseManifestError("public card-chain identity differs")
    _, chain_time = _parse_public_utc(
        chain.get("captured_at"), "card-chain captured_at"
    )
    if chain_time > now or now - chain_time > _RECEIPT_MAX_AGE:
        raise ReleaseManifestError("public card-chain timestamp is stale or future")
    cards = _sequence(chain.get("cards"), "public card-chain cards")
    if not cards or len(cards) > 256:
        raise ReleaseManifestError("public card-chain card count is invalid")
    inventory: list[dict[str, object]] = []
    canonical_cards: list[tuple[dict[str, object], bytes]] = []
    previous: str | None = None
    for expected_sequence, raw_card in enumerate(cards, start=1):
        card = _mapping(raw_card, "public card-chain card")
        if set(card) != {
            "sequence_number",
            "card_type",
            "card_hash",
            "canonical_card_json",
            "published_at",
        }:
            raise ReleaseManifestError("public card-chain card shape differs")
        if card.get("sequence_number") != expected_sequence:
            raise ReleaseManifestError("public card-chain sequence is not contiguous")
        card_type = _text(card.get("card_type"), "public card type")
        identity_field = _CARD_PROPOSAL_ID_FIELDS.get(card_type)
        if identity_field is None or (expected_sequence == 1) != (
            card_type == "ProposalCard"
        ):
            raise ReleaseManifestError("public card-chain card type order differs")
        preimage = _text(card.get("canonical_card_json"), "public card preimage")
        if len(preimage.encode("utf-8")) > 64 * 1024:
            raise ReleaseManifestError("public card preimage is oversized")
        card_hash = _hash32(card.get("card_hash"), "public card hash")
        if not secrets.compare_digest(
            hashlib.sha256(preimage.encode("utf-8")).hexdigest(), card_hash
        ):
            raise ReleaseManifestError("public card-chain card hash mismatch")
        preimage_bytes = preimage.encode("utf-8")
        preimage_document, canonical_preimage = _strict_json(
            preimage_bytes, "public card canonical preimage"
        )
        if (
            preimage_bytes + b"\n" != canonical_preimage
            or "card_hash" in preimage_document
            or preimage_document.get("sequence_number") != expected_sequence
            or preimage_document.get("card_type") != card_type
            or preimage_document.get(identity_field) != _PROPOSAL
            or preimage_document.get("previous_card_hash") != previous
        ):
            raise ReleaseManifestError("public card-chain preimage linkage differs")
        published_at = card.get("published_at")
        if published_at is not None:
            _parse_public_utc(published_at, "public card published_at")
        inventory.append(
            {
                "sequence": expected_sequence,
                "card_type": card_type,
                "card_hash": card_hash,
            }
        )
        canonical_cards.append((preimage_document, canonical_preimage))
        previous = card_hash
    terminal = _hash32(previous, "public card-chain terminal root")
    roots_bound = _load_bound_file(
        root, ARTIFACT_PATHS["card_chain_roots_v1"], _CONTROL_LIMIT
    )
    roots, _ = _strict_json(roots_bound.raw, "committed card-chain roots")
    if (
        _mapping(roots.get("roots"), "committed card-chain roots").get(_PROPOSAL)
        != terminal
    ):
        raise ReleaseManifestError("public card-chain root differs from artifact")
    inventory_sha256 = hashlib.sha256(_canonical_json(inventory)).hexdigest()

    evidence = document("evidence")
    evidence_cards = _sequence(evidence.get("cards"), "public evidence cards")
    if (
        evidence.get("proposal_id") != _PROPOSAL
        or evidence.get("chain_valid") is not True
        or evidence.get("chain_errors") != []
        or evidence.get("total_cards") != len(inventory)
        or len(evidence_cards) != len(inventory)
    ):
        raise ReleaseManifestError("public evidence is not the validated card chain")
    evidence_inventory: list[dict[str, object]] = []
    for index, item in enumerate(evidence_cards):
        card = _mapping(item, "public evidence card")
        data = _mapping(card.get("data"), "public evidence card data")
        evidence_inventory.append(
            {
                "sequence": card.get("sequence"),
                "card_type": card.get("card_type"),
                "card_hash": card.get("hash"),
            }
        )
        expected_document, expected_preimage = canonical_cards[index]
        if (
            data != expected_document
            or _canonical_json(data) != expected_preimage
            or data.get("sequence_number") != card.get("sequence")
        ):
            raise ReleaseManifestError(
                "public evidence card data differs from canonical preimage"
            )
    if evidence_inventory != inventory:
        raise ReleaseManifestError("public evidence card inventory differs")

    committed_bound = _load_bound_file(
        root, ARTIFACT_PATHS["proof_registry_v1"], _ARTIFACT_LIMIT
    )
    committed_registry, _ = _strict_json(
        committed_bound.raw, "committed proof registry"
    )
    all_committed_items = _sequence(
        committed_registry.get("public_items"), "committed public proof items"
    )

    def registry_projection(
        probe_id: str,
        proposal_id: str,
    ) -> tuple[list[object], str]:
        registry = document(probe_id)
        if set(registry) != {
            "schema_version",
            "generated_at",
            "proposal_id",
            "items",
        }:
            raise ReleaseManifestError(
                f"public proof registry shape differs: {probe_id}"
            )
        _, registry_time = _parse_public_utc(
            registry.get("generated_at"),
            f"{probe_id} generated_at",
        )
        if registry_time > now or now - registry_time > _RECEIPT_MAX_AGE:
            raise ReleaseManifestError(
                f"public proof registry timestamp is stale or future: {probe_id}"
            )
        committed_items = [
            item
            for item in all_committed_items
            if _mapping(item, "committed proof item").get("proposal_id")
            in {None, proposal_id}
        ]
        if (
            registry.get("schema_version") != 1
            or registry.get("proposal_id") != proposal_id
            or registry.get("items") != committed_items
        ):
            raise ReleaseManifestError(
                f"public proof registry differs from committed registry: {probe_id}"
            )
        return committed_items, hashlib.sha256(
            _canonical_json(committed_items)
        ).hexdigest()

    committed_items, registry_sha256 = registry_projection(
        "proof_registry",
        _PROPOSAL,
    )
    official_committed_items, official_registry_sha256 = registry_projection(
        "proof_registry_official",
        _OFFICIAL_X402_PROPOSAL,
    )

    proof_pack = document("proof_pack")
    historical_bound = _load_bound_file(
        root,
        ARTIFACT_PATHS["historical_odra_receipt_v1"],
        _ARTIFACT_LIMIT,
    )
    historical, _ = _strict_json(
        historical_bound.raw,
        "committed historical Odra receipt",
    )
    historical_deploy = _mapping(
        _mapping(historical.get("raw_rpc"), "historical raw RPC").get("deploy"),
        "historical deploy",
    )
    historical_deploy_hash = _hash32(
        historical_deploy.get("hash"),
        "historical deploy hash",
    )
    exact_bound = _load_bound_file(
        root,
        ARTIFACT_PATHS["exact_envelope_v3"],
        _ARTIFACT_LIMIT,
    )
    exact_artifact, _ = _strict_json(
        exact_bound.raw,
        "committed exact-envelope proof",
    )
    exact_prepared = _mapping(
        exact_artifact.get("prepared"),
        "exact-envelope prepared action",
    )
    expected_decisions = [
        {
            "sequence": item["sequence"],
            "card_type": item["card_type"],
            "card_hash": item["card_hash"],
        }
        for item in inventory
        if any(
            marker in str(item["card_type"]).lower()
            for marker in ("decision", "approval", "execution")
        )
    ]
    expected_manifest = {
        "proposal_id": _PROPOSAL,
        "card_count": len(inventory),
        "terminal_card_hash": terminal,
        "card_inventory_sha256": inventory_sha256,
    }
    expected_casper_receipt = {
        "deploy_hash": historical_deploy_hash,
        "status": "processed",
    }
    expected_ipfs = {
        "cid": _text(
            HTTP_PROBE_SPECS["ipfs_archive"].get("cid"),
            "fixed IPFS archive CID",
        )
    }
    expected_quorum = {
        "status": "satisfied",
        "proposal_id": _PROPOSAL,
        "action_id": _hash32(
            exact_prepared.get("action_id"),
            "exact-envelope action ID",
        ),
        "envelope_hash": _hash32(
            exact_prepared.get("envelope_hash"),
            "exact-envelope hash",
        ),
    }
    proof_center = _mapping(
        proof_pack.get("proof_center"), "public proof-pack proof center"
    )
    if (
        set(proof_center) != {"outcome_gallery", "casper_receipt"}
        or proof_center.get("outcome_gallery") != expected_decisions
        or proof_center.get("casper_receipt") != expected_casper_receipt
        or proof_pack.get("canonical_manifest") != expected_manifest
        or proof_pack.get("ipfs_evidence") != expected_ipfs
        or proof_pack.get("odra_quorum_exercise") != expected_quorum
    ):
        raise ReleaseManifestError(
            "public proof-pack claims differ from committed evidence"
        )
    expected_tool_calls = {
        "casper_receipt": expected_casper_receipt,
        "safepay_lite": proof_pack.get("safepay_lite"),
        "ipfs_archive": expected_ipfs,
        "odra_quorum": expected_quorum,
    }

    trace = document("trace")
    if set(trace) != {
        "trace_type",
        "proposal_id",
        "generated_at",
        "canonical_manifest",
        "observations",
        "decisions",
        "tool_calls",
        "jaeger_available",
        "traces_url",
        "redaction",
    }:
        raise ReleaseManifestError("public trace shape differs")
    _, trace_time = _parse_public_utc(trace.get("generated_at"), "trace generated_at")
    if trace_time > now or now - trace_time > _RECEIPT_MAX_AGE:
        raise ReleaseManifestError("public trace timestamp is stale or future")
    trace_observations = _sequence(
        trace.get("observations"), "public trace observations"
    )
    expected_trace_observations = [
        {
            "sequence": item["sequence"],
            "card_type": item["card_type"],
            "hash": item["card_hash"],
            "issuer": canonical_cards[index][0].get("sender_role")
            or canonical_cards[index][0].get("agent_role"),
        }
        for index, item in enumerate(inventory)
    ]
    redaction = _mapping(trace.get("redaction"), "trace redaction")
    if (
        trace.get("trace_type") != "ConcordiaPublicRunTrace"
        or trace.get("proposal_id") != _PROPOSAL
        or trace.get("canonical_manifest") != expected_manifest
        or trace_observations != expected_trace_observations
        or trace.get("decisions") != expected_decisions
        or trace.get("tool_calls") != expected_tool_calls
        or trace.get("jaeger_available") is not True
        or trace.get("traces_url") != _APP + "/traces"
        or redaction.get("status") != "applied"
        or type(redaction.get("policy")) is not str
        or not redaction.get("policy")
    ):
        raise ReleaseManifestError(
            "public trace is not bound to the sanitized card chain"
        )

    return {
        "card_chain": {
            "card_count": len(inventory),
            "terminal_card_hash": terminal,
            "card_inventory_sha256": inventory_sha256,
        },
        "evidence": {
            "card_count": len(inventory),
            "terminal_card_hash": terminal,
            "card_inventory_sha256": inventory_sha256,
        },
        "proof_registry": {
            "item_count": len(committed_items),
            "items_sha256": registry_sha256,
        },
        "proof_registry_official": {
            "item_count": len(official_committed_items),
            "items_sha256": official_registry_sha256,
        },
        "trace": {
            "observation_count": len(inventory),
            "card_inventory_sha256": inventory_sha256,
            "decisions_sha256": hashlib.sha256(
                _canonical_json(expected_decisions)
            ).hexdigest(),
            "tool_calls_sha256": hashlib.sha256(
                _canonical_json(expected_tool_calls)
            ).hexdigest(),
            "redaction_policy_sha256": hashlib.sha256(
                _text(redaction.get("policy"), "trace redaction policy").encode()
            ).hexdigest(),
        },
    }


def _probe_adapter_result(
    root: Path,
    artifact_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Recompute one public-route binding from its bound raw proof artifact."""

    bound = _load_bound_file(root, ARTIFACT_PATHS[artifact_id], _ARTIFACT_LIMIT)
    document, _ = _strict_json(bound.raw, f"committed {artifact_id} artifact")
    _require_nonempty_proof(artifact_id, document)
    metadata = _artifact_metadata(
        artifact_id,
        document,
        historical=None,
        artifact_commit=bound.artifact_commit,
    )
    adapter = _run_release_adapter(
        artifact_id=artifact_id,
        document=document,
        raw=bound.raw,
        metadata=metadata,
    )
    if adapter is None:
        raise ReleaseManifestError(
            f"{artifact_id} has no independent public-binding adapter"
        )
    return document, adapter


def _probe_semantic_checks(
    *,
    root: Path,
    probe_id: str,
    spec: Mapping[str, object],
    body: bytes,
    safe_headers: Mapping[str, str],
) -> list[str]:
    semantic = spec.get("semantic")
    if semantic is None:
        return []
    if semantic == "evidence":
        return ["proposal_binding", "chain_recomputed", "committed_terminal_root"]
    if semantic == "proof_registry":
        return ["proposal_binding", "exact_committed_registry"]
    if semantic == "card_chain":
        return ["proposal_binding", "card_hashes_recomputed", "committed_terminal_root"]
    if semantic == "trace":
        return ["proposal_binding", "card_inventory_binding", "redaction_scanned"]
    if semantic == "safepay":
        document = _strict_probe_json(body, probe_id)
        if set(document) != {
            "schema_version",
            "proposal_id",
            "status",
            "replay_safety",
            "payment_hash",
            "report_hash",
        }:
            raise ReleaseManifestError("public SafePay response shape differs")
        if (
            document.get("schema_version") != "safepay-v2"
            or document.get("proposal_id") != _PROPOSAL
            or document.get("status") != "verified"
            or document.get("replay_safety") != "no_double_consumption"
        ):
            raise ReleaseManifestError("public SafePay state is not verified")
        payment_hash = _hash32(document.get("payment_hash"), "public SafePay payment")
        report_hash = _hash32(document.get("report_hash"), "public SafePay report")
        _, adapter = _probe_adapter_result(root, "safepay_v2")
        facts = _mapping(
            adapter.get("derived_facts"),
            "SafePay independent adapter derived facts",
        )
        if (
            facts.get("proposal_id") != _PROPOSAL
            or facts.get("payment_hash") != payment_hash
            or facts.get("report_hash") != report_hash
        ):
            raise ReleaseManifestError("public SafePay response differs from artifact")
        return ["proposal_binding", "payment_binding", "report_binding", "replay_safe"]
    if semantic == "proof_pack":
        document = _strict_probe_json(body, probe_id)
        if set(document) != {
            "schema_version",
            "proposal_id",
            "canonical_manifest",
            "evidence",
            "proof_center",
            "safepay_lite",
            "ipfs_evidence",
            "odra_quorum_exercise",
        }:
            raise ReleaseManifestError("public proof pack shape differs")
        if (
            document.get("schema_version") != "concordia.proof-pack.v2"
            or document.get("proposal_id") != _PROPOSAL
        ):
            raise ReleaseManifestError("public proof pack identity differs")
        evidence = _mapping(document.get("evidence"), "proof pack evidence")
        safepay = _mapping(document.get("safepay_lite"), "proof pack SafePay")
        canonical_manifest = _mapping(
            document.get("canonical_manifest"),
            "proof pack canonical manifest",
        )
        proof_center = _mapping(
            document.get("proof_center"),
            "proof pack proof center",
        )
        ipfs_evidence = _mapping(
            document.get("ipfs_evidence"),
            "proof pack IPFS evidence",
        )
        odra_quorum = _mapping(
            document.get("odra_quorum_exercise"),
            "proof pack Odra quorum",
        )
        roots_bound = _load_bound_file(
            root, ARTIFACT_PATHS["card_chain_roots_v1"], _CONTROL_LIMIT
        )
        roots, _ = _strict_json(roots_bound.raw, "committed card-chain roots")
        expected_root = _mapping(roots.get("roots"), "committed card-chain roots").get(
            _PROPOSAL
        )
        _, safepay_adapter = _probe_adapter_result(root, "safepay_v2")
        safepay_facts = _mapping(
            safepay_adapter.get("derived_facts"),
            "SafePay independent adapter derived facts",
        )
        historical_bound = _load_bound_file(
            root,
            ARTIFACT_PATHS["historical_odra_receipt_v1"],
            _ARTIFACT_LIMIT,
        )
        historical_artifact, _ = _strict_json(
            historical_bound.raw,
            "committed historical Odra artifact",
        )
        historical_hash = _hash32(
            _mapping(
                _mapping(
                    historical_artifact.get("raw_rpc"),
                    "historical raw RPC",
                ).get("deploy"),
                "historical deploy",
            ).get("hash"),
            "historical deploy hash",
        )
        exact_bound = _load_bound_file(
            root,
            ARTIFACT_PATHS["exact_envelope_v3"],
            _ARTIFACT_LIMIT,
        )
        exact_artifact, _ = _strict_json(
            exact_bound.raw,
            "committed exact-envelope artifact",
        )
        exact_prepared = _mapping(
            exact_artifact.get("prepared"),
            "exact-envelope prepared action",
        )
        if evidence != {
            "chain_valid": True,
            "terminal_card_hash": expected_root,
        } or safepay != {
            "schema_version": "safepay-v2",
            "payment_hash": safepay_facts.get("payment_hash"),
            "report_hash": safepay_facts.get("report_hash"),
            "replay_safety": "no_double_consumption",
        } or (
            set(canonical_manifest)
            != {
                "proposal_id",
                "card_count",
                "terminal_card_hash",
                "card_inventory_sha256",
            }
            or canonical_manifest.get("proposal_id") != _PROPOSAL
            or type(canonical_manifest.get("card_count")) is not int
            or canonical_manifest["card_count"] < 1
            or canonical_manifest.get("terminal_card_hash") != expected_root
            or not _HEX32.fullmatch(
                str(canonical_manifest.get("card_inventory_sha256", ""))
            )
            or set(proof_center) != {"outcome_gallery", "casper_receipt"}
            or type(proof_center.get("outcome_gallery")) is not list
            or proof_center.get("casper_receipt")
            != {"deploy_hash": historical_hash, "status": "processed"}
            or ipfs_evidence
            != {
                "cid": _text(
                    HTTP_PROBE_SPECS["ipfs_archive"].get("cid"),
                    "fixed IPFS CID",
                )
            }
            or odra_quorum
            != {
                "status": "satisfied",
                "proposal_id": _PROPOSAL,
                "action_id": _hash32(
                    exact_prepared.get("action_id"),
                    "exact-envelope action ID",
                ),
                "envelope_hash": _hash32(
                    exact_prepared.get("envelope_hash"),
                    "exact-envelope hash",
                ),
            }
        ):
            raise ReleaseManifestError("public proof pack differs from bound artifacts")
        return [
            "proposal_binding",
            "evidence_artifact_binding",
            "safepay_artifact_binding",
            "canonical_manifest_binding",
            "quorum_artifact_binding",
            "ipfs_content_address_binding",
        ]
    if semantic == "ipfs_cid":
        cid = _text(spec.get("cid"), "fixed IPFS CID")
        if not hashlib.sha256(body).digest() == _cid_sha256(cid):
            raise ReleaseManifestError(
                "IPFS response bytes do not match content address"
            )
        return ["cid_sha256_content_address"]
    if semantic == "pdf_certificate":
        return _pdf_certificate_checks(body, safe_headers)
    if semantic == "provider_openapi":
        return _provider_openapi_checks(body)
    if semantic == "official_supported":
        document = _strict_probe_json(body, probe_id)
        if set(document) != {"kinds", "extensions", "signers"}:
            raise ReleaseManifestError("official x402 supported response shape differs")
        kinds = _sequence(document.get("kinds"), "official x402 supported kinds")
        if kinds != [
            {
                "x402Version": 2,
                "scheme": "exact",
                "network": "casper:casper-test",
            }
        ]:
            raise ReleaseManifestError("official x402 supported network differs")
        if document.get("extensions") != {} or document.get("signers") != []:
            raise ReleaseManifestError("official x402 supported metadata differs")
        return ["x402_v2", "exact_scheme", "canonical_network"]
    if semantic == "official_health":
        document = _strict_probe_json(body, probe_id)
        if (
            set(document)
            != {"status", "settlement_state", "settlement_transaction_hash"}
            or document.get("status") != "ok"
            or document.get("settlement_state") != "official_hosted_verified_live"
        ):
            raise ReleaseManifestError(
                "official x402 health is not live-settlement verified"
            )
        settlement_hash = _hash32(
            document.get("settlement_transaction_hash"),
            "official x402 settlement transaction",
        )
        _, adapter = _probe_adapter_result(
            root,
            "official_x402_settlement_v1",
        )
        facts = _mapping(
            adapter.get("derived_facts"),
            "official-x402 independent adapter derived facts",
        )
        if facts.get("settlement_transaction") != settlement_hash:
            raise ReleaseManifestError(
                "official x402 health differs from settlement artifact"
            )
        return ["liveness", "hosted_settlement_verified_live"]
    if semantic == "governance_archive":
        document = _strict_probe_json(body, probe_id)
        if document.get("proposal_id") != _PROPOSAL:
            raise ReleaseManifestError("governance archive proposal differs")
        expected = (
            'attachment; filename="concordia-governance-archive-' + _PROPOSAL + '.json"'
        )
        if safe_headers.get("Content-Disposition") != expected:
            raise ReleaseManifestError("governance archive disposition differs")
        return ["proposal_binding", "exact_content_disposition"]
    if semantic == "csv":
        try:
            lines = body.decode("utf-8").splitlines()
        except UnicodeDecodeError as exc:
            raise ReleaseManifestError("CSV export is not UTF-8") from exc
        expected_header = _text(spec.get("csv_header"), "fixed CSV header")
        if len(lines) < 2 or lines[0] != expected_header:
            raise ReleaseManifestError("CSV export header or data row differs")
        return ["exact_csv_header", "nonempty_csv_data"]
    raise ReleaseManifestError("HTTP probe has an unknown semantic predicate")


def _public_probe_projection(
    raw: Sequence[Mapping[str, object]],
    *,
    root: Path,
    now: datetime,
    canaries: Sequence[bytes],
) -> dict[str, object]:
    by_id: dict[str, Mapping[str, object]] = {}
    for item in raw:
        probe_id = _text(item.get("probe_id"), "HTTP probe_id")
        if probe_id in by_id:
            raise ReleaseManifestError("duplicate HTTP probe identity")
        by_id[probe_id] = item
    if set(by_id) != set(HTTP_PROBE_SPECS):
        raise ReleaseManifestError(
            "HTTP crawl does not contain the exact fixed route set"
        )
    graph_facts = _public_release_graph(
        root,
        by_id,
        now=now,
        canaries=canaries,
    )
    projections: list[dict[str, object]] = []
    for probe_id, spec in HTTP_PROBE_SPECS.items():
        item = by_id[probe_id]
        if item.get("requested_url") != spec["url"]:
            raise ReleaseManifestError(
                f"HTTP probe {probe_id} requested a nonfixed URL"
            )
        if item.get("effective_url") != spec["effective_url"]:
            raise ReleaseManifestError(f"HTTP probe {probe_id} effective URL differs")
        if item.get("redirect_chain") != spec["redirect_chain"]:
            raise ReleaseManifestError(f"HTTP probe {probe_id} redirect chain differs")
        if item.get("status") != spec["status"]:
            raise ReleaseManifestError(f"HTTP probe {probe_id} status differs")
        body = item.get("body")
        if type(body) is not bytes or len(body) > _HTTP_LIMIT:
            raise ReleaseManifestError(
                f"HTTP probe {probe_id} body is unavailable or oversized"
            )
        _assert_no_canary(body, canaries, f"HTTP probe {probe_id}")
        checks: list[str] = ["fixed_url", "redirect_chain", "status"]
        exact_body = spec.get("exact_body")
        if exact_body is not None:
            if body != exact_body:
                raise ReleaseManifestError(f"HTTP probe {probe_id} exact body differs")
            checks.append("exact_body")
        marker = spec.get("marker")
        if marker is not None:
            if type(marker) is not bytes or marker not in body:
                raise ReleaseManifestError(
                    f"HTTP probe {probe_id} semantic marker is missing"
                )
            checks.append("semantic_marker")
        prefix = spec.get("prefix")
        if prefix is not None:
            if type(prefix) is not bytes or not body.startswith(prefix):
                raise ReleaseManifestError(f"HTTP probe {probe_id} prefix differs")
            checks.append("content_prefix")
        headers = _mapping(item.get("headers"), f"HTTP probe {probe_id} headers")
        safe_headers = {}
        for name, value in headers.items():
            normalized = str(name).lower()
            if normalized in _SAFE_HTTP_HEADERS and type(value) is str:
                safe_headers[_SAFE_HTTP_HEADERS[normalized]] = value
        content_type = safe_headers.get("Content-Type", "").lower()
        expected_type = _text(spec.get("content_type"), "fixed content type").lower()
        if content_type != expected_type:
            raise ReleaseManifestError(f"HTTP probe {probe_id} content type differs")
        checks.extend(
            _probe_semantic_checks(
                root=root,
                probe_id=probe_id,
                spec=spec,
                body=body,
                safe_headers=safe_headers,
            )
        )
        binding_ids: tuple[str, ...] = ()
        if spec.get("semantic") in {"evidence", "card_chain", "trace"}:
            binding_ids = ("card_chain_roots_v1",)
        elif spec.get("semantic") == "safepay":
            binding_ids = ("safepay_v2",)
        elif spec.get("semantic") == "proof_pack":
            binding_ids = ("card_chain_roots_v1", "safepay_v2")
        elif spec.get("semantic") == "official_health":
            binding_ids = ("official_x402_settlement_v1",)
        elif spec.get("semantic") == "proof_registry":
            binding_ids = ("proof_registry_v1",)
        artifact_bindings = []
        for artifact_id in binding_ids:
            bound = _load_bound_file(root, ARTIFACT_PATHS[artifact_id], _ARTIFACT_LIMIT)
            artifact_bindings.append(
                {
                    "artifact_path": bound.path,
                    "artifact_sha256": bound.sha256,
                }
            )
        parsed = urlsplit(str(spec["url"]))
        tls = _tls_projection(
            item.get("tls"), host=parsed.hostname or "", now=now, canaries=canaries
        )
        body_sha256 = hashlib.sha256(body).hexdigest()
        stable_body_sha256 = body_sha256
        dynamic_timestamps: dict[str, str] = {}
        dynamic_field = _DYNAMIC_PUBLIC_TIMESTAMP_FIELDS.get(probe_id)
        if dynamic_field is not None:
            dynamic_document = _strict_probe_json(body, probe_id)
            dynamic_value, dynamic_time = _parse_public_utc(
                dynamic_document.get(dynamic_field),
                f"HTTP probe {probe_id} {dynamic_field}",
            )
            if dynamic_time > now or now - dynamic_time > _RECEIPT_MAX_AGE:
                raise ReleaseManifestError(
                    f"HTTP probe {probe_id} dynamic timestamp is stale or future"
                )
            stable_document = dict(dynamic_document)
            del stable_document[dynamic_field]
            stable_body_sha256 = hashlib.sha256(
                _canonical_json(stable_document)
            ).hexdigest()
            dynamic_timestamps = {dynamic_field: dynamic_value}
        projection_row = {
            "probe_id": probe_id,
            "requested_url": spec["url"],
            "effective_url": spec["effective_url"],
            "redirect_chain": spec["redirect_chain"],
            "status": spec["status"],
            "headers": safe_headers,
            "byte_length": len(body),
            "body_sha256": body_sha256,
            "stable_body_sha256": stable_body_sha256,
            "dynamic_timestamps": dynamic_timestamps,
            "checks": checks,
            "artifact_bindings": artifact_bindings,
            "tls": tls,
        }
        if probe_id in graph_facts:
            projection_row["semantic_facts"] = graph_facts[probe_id]
        projections.append(projection_row)
    projection = {"probes": projections}
    _assert_safe_projection(projection, canaries, "public probe projection")
    return projection


def _pages_projection(
    raw: Mapping[str, object], canaries: Sequence[bytes]
) -> dict[str, object]:
    pages = _mapping(raw, "GitHub Pages observation")
    if pages.get("repository") != "asadvendor-boop/concordia-dao-council":
        raise ReleaseManifestError("GitHub Pages repository differs")
    if pages.get("build_type") != "workflow":
        raise ReleaseManifestError("GitHub Pages build_type is not workflow")
    if pages.get("cname") != "docs.concordiadao.xyz":
        raise ReleaseManifestError("GitHub Pages CNAME differs")
    if pages.get("html_url") != "https://docs.concordiadao.xyz/":
        raise ReleaseManifestError("GitHub Pages URL differs")
    if pages.get("https_enforced") is not True:
        raise ReleaseManifestError("GitHub Pages HTTPS is not enforced")
    workflow = _mapping(pages.get("workflow"), "Pages workflow")
    deployment = _mapping(pages.get("deployment"), "Pages deployment")
    identity = _mapping(pages.get("release_identity"), "Pages release identity")
    head_sha = _git40(workflow.get("head_sha"), "Pages workflow head SHA")
    run_id = workflow.get("run_id")
    deployment_id = deployment.get("deployment_id")
    if (
        workflow.get("name") != "docs-pages"
        or workflow.get("status") != "completed"
        or workflow.get("conclusion") != "success"
        or deployment.get("environment") != "github-pages"
        or deployment.get("status") != "success"
        or deployment.get("sha") != head_sha
        or identity.get("GITHUB_SHA") != head_sha
        or identity.get("run_id") != run_id
        or set(identity) != {"GITHUB_SHA", "run_id"}
        or type(run_id) is not int
        or run_id < 1
        or type(deployment_id) is not int
        or deployment_id < 1
    ):
        raise ReleaseManifestError("GitHub Pages workflow/deployment identity differs")
    projection = {
        "repository": pages["repository"],
        "build_type": "workflow",
        "cname": pages["cname"],
        "html_url": pages["html_url"],
        "https_enforced": True,
        "deployment_commit": head_sha,
        "workflow_run_id": run_id,
        "deployment_id": deployment_id,
    }
    _assert_safe_projection(projection, canaries, "Pages projection")
    return projection


def _npm_projection(
    root: Path,
    raw: Mapping[str, object],
    canaries: Sequence[bytes],
) -> tuple[dict[str, object], bytes]:
    npm = _mapping(raw, "npm observation")
    metadata = _mapping(npm.get("metadata"), "npm metadata")
    tarball = npm.get("tarball")
    if type(tarball) is not bytes or not tarball or len(tarball) > _NPM_LIMIT:
        raise ReleaseManifestError("npm tarball is unavailable or oversized")
    _assert_no_canary(tarball, canaries, "npm tarball")
    if metadata.get("name") != "@concordia-dao/verify":
        raise ReleaseManifestError("npm package identity differs")
    version = _text(metadata.get("version"), "npm version")
    if _SEMVER.fullmatch(version) is None:
        raise ReleaseManifestError("npm version is invalid")
    git_head = _git40(metadata.get("gitHead"), "npm gitHead")
    published_at = _parse_timestamp(metadata.get("time"), "npm published_at")[0]
    dist = _mapping(metadata.get("dist"), "npm dist")
    tarball_url = _text(dist.get("tarball"), "npm tarball URL")
    _validate_npm_tarball_url(tarball_url)
    computed_integrity = "sha512-" + base64.b64encode(
        hashlib.sha512(tarball).digest()
    ).decode("ascii")
    if dist.get("integrity") != computed_integrity:
        raise ReleaseManifestError("npm registry integrity differs from tarball bytes")
    tarball_sha256 = hashlib.sha256(tarball).hexdigest()
    registry_signatures = _mapping(
        npm.get("registry_signatures"), "npm registry signatures"
    )
    if registry_signatures != {"invalid": [], "missing": []}:
        raise ReleaseManifestError("npm registry signatures did not verify")
    package = _mapping(npm.get("package_projection"), "npm package projection")
    source_commit = _git40(
        package.get("sourceCommit"), "npm package source commit"
    )
    if source_commit != git_head:
        raise ReleaseManifestError(
            "npm registry gitHead differs from the reproduced package source"
        )
    if (
        package.get("name") != metadata["name"]
        or package.get("version") != version
    ):
        raise ReleaseManifestError("npm package contents differ from registry identity")
    files = _sequence(package.get("files"), "npm package files")
    required = {"LICENSE", "README.md", "dist/cli.js", "package.json"}
    if not required.issubset(set(files)):
        raise ReleaseManifestError("npm tarball fixed file inventory is incomplete")
    for item in files:
        _validate_relative_path(_text(item, "npm package file"))
        if item not in {"LICENSE", "README.md", "package.json"} and not item.startswith(
            "dist/"
        ):
            raise ReleaseManifestError("npm tarball contains an unexpected file")
    self_test_digest = _hash32(
        package.get("self_test_digest"), "npm verifier self-test digest"
    )
    consumer_install_sha256 = _hash32(
        package.get("consumer_install_sha256"),
        "npm clean consumer install SHA-256",
    )
    projection = {
        "name": metadata["name"],
        "version": version,
        "source_commit": source_commit,
        "publication_commit": git_head,
        "publication_policy": "registry_signed_exact_source_reproduction",
        "published_at": published_at,
        "tarball_url": tarball_url,
        "tarball_sha256": tarball_sha256,
        "integrity": computed_integrity,
        "byte_length": len(tarball),
        "files": sorted(str(item) for item in files),
        "consumer_install_sha256": consumer_install_sha256,
        "self_test_digest": self_test_digest,
        "registry_signatures": {"invalid": [], "missing": []},
    }
    _assert_safe_projection(projection, canaries, "npm projection")
    return projection, tarball


def _validate_npm_tarball_url(value: str) -> None:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "registry.npmjs.org"
        or parsed.username
        or parsed.password
        or parsed.port not in {None, 443}
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/@concordia-dao/verify/-/")
        or not parsed.path.endswith(".tgz")
    ):
        raise ReleaseManifestError("npm tarball URL is outside the fixed registry")


def _verify_npm_registry_signatures(
    *,
    repository_root: Path,
    version: str,
    tarball_url: str,
    integrity: str,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="concordia-npm-signatures-") as temporary:
        audit_root = Path(temporary).resolve(strict=True)
        package_document = {
            "name": "concordia-release-signature-audit",
            "version": "0.0.0",
            "private": True,
            "dependencies": {"@concordia-dao/verify": version},
        }
        (audit_root / "package.json").write_bytes(_canonical_json(package_document))
        _run(
            audit_root,
            [
                "npm",
                "install",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                "--save-exact",
                "--registry=https://registry.npmjs.org/",
            ],
            limit=_CONTROL_LIMIT,
            timeout=180,
            repository_root=repository_root,
        )
        lock_raw = (audit_root / "package-lock.json").read_bytes()
        lock, _ = _strict_json(lock_raw, "npm signature audit lock")
        packages = _mapping(lock.get("packages"), "npm signature audit packages")
        installed = _mapping(
            packages.get("node_modules/@concordia-dao/verify"),
            "npm signature audit installed package",
        )
        if (
            installed.get("version") != version
            or installed.get("resolved") != tarball_url
            or installed.get("integrity") != integrity
        ):
            raise ReleaseManifestError(
                "npm signature audit package differs from captured tarball"
            )
        audit = _run(
            audit_root,
            [
                "npm",
                "audit",
                "signatures",
                "--json",
                "--registry=https://registry.npmjs.org/",
            ],
            limit=_CONTROL_LIMIT,
            timeout=180,
            repository_root=repository_root,
        )
        audit_document, _ = _strict_json(audit.stdout, "npm audit signatures result")
        if set(audit_document) != {"invalid", "missing"} or audit_document != {
            "invalid": [],
            "missing": [],
        }:
            raise ReleaseManifestError("npm audit signatures rejected package")
    return dict(audit_document)


def _rpc_projection(
    raw: Sequence[Mapping[str, object]],
    *,
    now: datetime,
    canaries: Sequence[bytes],
) -> dict[str, object]:
    by_id: dict[str, Mapping[str, object]] = {}
    for raw_item in raw:
        item = _mapping(raw_item, "RPC observation")
        provider_id = _text(item.get("provider_id"), "RPC provider_id")
        if provider_id in by_id:
            raise ReleaseManifestError("duplicate RPC provider identity")
        by_id[provider_id] = item
    if set(by_id) != set(RPC_PROVIDERS):
        raise ReleaseManifestError(
            "RPC receipt does not use exactly two reviewed providers"
        )
    projections: list[dict[str, object]] = []
    common: dict[str, object] | None = None
    for provider_id, expected in RPC_PROVIDERS.items():
        item = by_id[provider_id]
        if (
            item.get("operator_id") != expected["operator_id"]
            or item.get("endpoint") != expected["endpoint"]
            or item.get("authentication_mode") != expected["authentication"]
            or item.get("method") != "chain_get_block"
        ):
            raise ReleaseManifestError("RPC provider identity or method differs")
        observed_at, observed_time = _parse_timestamp(
            item.get("observed_at"), "RPC observed_at"
        )
        if observed_time > now or now - observed_time > _RECEIPT_MAX_AGE:
            raise ReleaseManifestError("RPC observation is stale or future-dated")
        result = _mapping(item.get("result"), "RPC projected result")
        exact = {
            "chain_name": _text(result.get("chain_name"), "RPC chain name"),
            "block_hash": _hash32(result.get("block_hash"), "RPC block hash"),
            "block_height": result.get("block_height"),
            "state_root_hash": _hash32(
                result.get("state_root_hash"), "RPC state root hash"
            ),
            "block_timestamp": _parse_timestamp(
                result.get("block_timestamp"), "RPC block timestamp"
            )[0],
            "protocol_version": _text(
                result.get("protocol_version"), "RPC protocol version"
            ),
        }
        if (
            exact["chain_name"] != "casper-test"
            or type(exact["block_height"]) is not int
        ):
            raise ReleaseManifestError("RPC finalized block identity is invalid")
        _, block_time = _parse_timestamp(
            exact["block_timestamp"], "RPC block timestamp"
        )
        if block_time > now or now - block_time > timedelta(minutes=10):
            raise ReleaseManifestError(
                "RPC finalized block timestamp is stale or future"
            )
        if common is None:
            common = exact
        elif exact != common:
            raise ReleaseManifestError(
                "RPC providers did not return the same finalized block"
            )
        projections.append(
            {
                "provider_id": provider_id,
                "operator_id": expected["operator_id"],
                "endpoint": expected["endpoint"],
                "authentication_mode": expected["authentication"],
                "method": "chain_get_block",
                "observed_at": observed_at,
                "result": exact,
            }
        )
    projection = {"providers": projections, "corroborated_block": common}
    _assert_safe_projection(projection, canaries, "RPC projection")
    return projection


def _project_snapshot(
    root: Path,
    snapshot: RawObservationSnapshot,
    *,
    now: datetime,
    canaries: Sequence[bytes],
    integration_commit: str,
    normalized_replay: bool = False,
) -> tuple[dict[str, dict[str, object]], bytes]:
    observed_at, observed_time = _parse_timestamp(
        snapshot.observed_at, "release observation time"
    )
    if observed_time > now or now - observed_time > _RECEIPT_MAX_AGE:
        raise ReleaseManifestError("release observation is stale or future-dated")
    compose = _compose_projection(
        root,
        snapshot.compose,
        canaries,
        allow_normalized_argv_digests=normalized_replay,
    )
    npm, tarball = _npm_projection(root, snapshot.npm, canaries)
    pages = _pages_projection(snapshot.pages, canaries)
    if pages.get("deployment_commit") != npm.get("publication_commit"):
        raise ReleaseManifestError("Pages and npm do not bind the same release commit")
    release_commit = _git40(pages.get("deployment_commit"), "surface release commit")
    if not _commit_exists(root, release_commit) or not _is_ancestor(
        root, release_commit, "HEAD"
    ):
        raise ReleaseManifestError(
            "deployment surface commit is unavailable or unmerged"
        )
    _, published_time = _parse_timestamp(npm.get("published_at"), "npm published_at")
    if published_time > observed_time:
        raise ReleaseManifestError("npm publication timestamp follows its observation")
    projections = {
        "compose": compose,
        "runtime": _runtime_projection(
            snapshot.runtime,
            compose,
            canaries,
            integration_commit=integration_commit,
        ),
        "caddy": _caddy_projection(snapshot.caddy, canaries),
        "public_probes": _public_probe_projection(
            snapshot.public_probes, root=root, now=now, canaries=canaries
        ),
        "pages": pages,
        "npm": npm,
        "rpc": _rpc_projection(snapshot.rpc, now=now, canaries=canaries),
    }
    for projection in projections.values():
        projection["observed_at"] = observed_at
    return projections, tarball


def _verifier_tool_commit(root: Path) -> str:
    result = _git(
        root,
        ["log", "-1", "--format=%H", "--", *_VERIFIER_PATHS],
        limit=_CONTROL_LIMIT,
    )
    try:
        value = result.stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ReleaseManifestError("verifier tool commit is malformed") from exc
    return _git40(value, "verifier tool commit")


def _verifier_source_tree_sha256(root: Path, commit: str) -> str:
    _git40(commit, "verifier source commit")
    listing = _git(
        root,
        ["ls-tree", "-r", "-z", commit, "--", *_VERIFIER_PATHS],
        limit=_GIT_OUTPUT_LIMIT,
    ).stdout
    if not listing:
        raise ReleaseManifestError("verifier source tree is empty")
    return hashlib.sha256(listing).hexdigest()


def _validate_verifier_result(value: object, label: str) -> dict[str, object]:
    result = _mapping(value, label)
    if set(result) != {"verifier_id", "derived_identity", "derived_facts"}:
        raise ReleaseManifestError(f"{label} returned fields outside the fixed schema")
    _text(result.get("verifier_id"), f"{label} verifier_id")
    identity = _mapping(result.get("derived_identity"), f"{label} derived_identity")
    facts = _mapping(result.get("derived_facts"), f"{label} derived_facts")
    if not identity or not facts:
        raise ReleaseManifestError(f"{label} returned empty derived proof")
    _assert_safe_projection(result, (), label)
    return result


def _proof_projection(
    verifier: _ProofVerifier,
    artifact: _Artifact,
) -> dict[str, object]:
    verified = _validate_verifier_result(
        verifier.verify(
            artifact_id=artifact.artifact_id,
            artifact_path=artifact.bound.path,
            artifact_bytes=artifact.bound.raw,
            artifact_document=artifact.document,
        ),
        f"{artifact.artifact_id} verifier",
    )
    return {
        "artifact_id": artifact.artifact_id,
        "artifact_path": artifact.bound.path,
        "artifact_sha256": artifact.bound.sha256,
        "artifact_commit": artifact.bound.artifact_commit,
        "schema_version": artifact.schema_version,
        "captured_at": artifact.captured_at,
        "source_commit": artifact.source_commit,
        "deployment_commit": artifact.deployment_commit,
        "observation_mode": artifact.observation_mode,
        **verified,
    }


def _receipt(
    *,
    receipt_id: str,
    observed_at: str,
    producer_tool_commit: str,
    command_environment_sha256: str,
    normalized_observation: object,
    projection: Mapping[str, object],
) -> dict[str, object]:
    normalized_bytes = _canonical_json(normalized_observation)
    projection_bytes = _canonical_json(projection)
    return {
        "schema_version": OBSERVATION_SCHEMA_VERSION,
        "receipt_id": receipt_id,
        "observed_at": observed_at,
        "producer_tool_commit": producer_tool_commit,
        "command_environment_sha256": command_environment_sha256,
        "normalized_observation_sha256": hashlib.sha256(
            normalized_bytes
        ).hexdigest(),
        "normalized_observation": normalized_observation,
        "projection_sha256": hashlib.sha256(projection_bytes).hexdigest(),
        "projection": dict(projection),
    }


def _proof_receipt(
    *,
    artifact: _Artifact,
    observed_at: str,
    verifier_tool_commit: str,
    verifier_source_tree_sha256: str,
    command_environment_sha256: str,
    projection: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema_version": PROOF_RECEIPT_SCHEMA_VERSION,
        "proof_id": artifact.artifact_id,
        "observed_at": observed_at,
        "verifier_tool_commit": verifier_tool_commit,
        "verifier_source_tree_sha256": verifier_source_tree_sha256,
        "command_environment_sha256": command_environment_sha256,
        "projection_sha256": hashlib.sha256(_canonical_json(projection)).hexdigest(),
        "projection": dict(projection),
    }


def _normalized_compose_observation(
    root: Path,
    compose: Mapping[str, object],
) -> dict[str, object]:
    """Retain replayable Compose structure without host paths or argv contents."""

    normalized = dict(compose)
    services = compose.get("services")
    if type(services) is not dict:
        return normalized
    sanitized_services: dict[str, object] = {}
    for service_id, raw_service in services.items():
        if type(raw_service) is not dict:
            sanitized_services[str(service_id)] = raw_service
            continue
        service = dict(raw_service)
        for field in ("command", "entrypoint"):
            value = service.get(field)
            if value is not None:
                service[field] = {
                    _NORMALIZED_ARGV_DIGEST_KEY: hashlib.sha256(
                        _canonical_json(value)
                    ).hexdigest()
                }
        volumes = service.get("volumes")
        if type(volumes) is list:
            normalized_volumes: list[object] = []
            for raw_volume in volumes:
                if type(raw_volume) is not dict or raw_volume.get("type") != "bind":
                    normalized_volumes.append(raw_volume)
                    continue
                volume = dict(raw_volume)
                source = Path(str(volume.get("source", "")))
                if not source.is_absolute():
                    source = root / source
                try:
                    resolved_source = source.resolve(strict=True)
                    try:
                        volume["source"] = resolved_source.relative_to(
                            root.resolve(strict=True)
                        ).as_posix()
                    except ValueError:
                        expected_external = (
                            root.parent / "config/x402-official"
                        ).resolve(strict=True)
                        if (
                            volume.get("target") != "/run/config"
                            or resolved_source != expected_external
                        ):
                            raise ReleaseManifestError(
                                "Compose bind source cannot be normalized"
                            )
                        digest = _bound_external_directory_sha256(
                            resolved_source,
                            label="release-scoped x402 config",
                        )
                        volume["source"] = (
                            "@release-config/x402-official:" + digest
                        )
                except (OSError, ValueError) as exc:
                    raise ReleaseManifestError(
                        "Compose bind source cannot be normalized"
                    ) from exc
                normalized_volumes.append(volume)
            service["volumes"] = normalized_volumes
        sanitized_services[str(service_id)] = service
    normalized["services"] = sanitized_services
    return normalized


def _raw_snapshot_surfaces(
    root: Path,
    snapshot: RawObservationSnapshot,
) -> dict[str, object]:
    return {
        "compose": _normalized_compose_observation(root, snapshot.compose),
        "runtime": list(snapshot.runtime),
        "caddy": snapshot.caddy,
        "public_probes": list(snapshot.public_probes),
        "pages": snapshot.pages,
        "npm": snapshot.npm,
        "rpc": list(snapshot.rpc),
    }


def _secure_directory_fd(root: Path, parts: Sequence[str], *, create: bool) -> int:
    descriptor = _root_fd(root)
    try:
        for part in parts:
            try:
                next_descriptor = os.open(
                    part,
                    _safe_open_flags(directory=True),
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=descriptor)
                os.fsync(descriptor)
                next_descriptor = os.open(
                    part,
                    _safe_open_flags(directory=True),
                    dir_fd=descriptor,
                )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise ReleaseManifestError("release output directory is unsafe") from exc


def _atomic_create_once(root: Path, relative: str, payload: bytes) -> Path:
    parts = _validate_relative_path(relative)
    parent_fd = _secure_directory_fd(root, parts[:-1], create=True)
    temporary_name = f".{parts[-1]}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NONBLOCK
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_fd,
        )
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise ReleaseManifestError("release write made no progress")
                view = view[written:]
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.link(
                temporary_name,
                parts[-1],
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise ReleaseManifestError(
                f"release output {relative} already exists"
            ) from exc
        os.fsync(parent_fd)
    finally:
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)
    return root / relative


def _atomic_create_sibling_batch_once(
    root: Path,
    payloads: Mapping[str, bytes],
) -> tuple[Path, ...]:
    """Publish a small same-directory evidence batch without partial success."""

    if not payloads:
        raise ReleaseManifestError("release output batch is empty")
    parsed = {
        relative: _validate_relative_path(relative)
        for relative in payloads
    }
    parents = {parts[:-1] for parts in parsed.values()}
    if len(parents) != 1:
        raise ReleaseManifestError(
            "release output batch must share one directory"
        )
    parent_parts = next(iter(parents))
    parent_fd = _secure_directory_fd(root, parent_parts, create=True)
    temporary_names: dict[str, str] = {}
    linked_names: list[str] = []
    try:
        for relative, payload in payloads.items():
            filename = parsed[relative][-1]
            temporary_name = (
                f".{filename}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
            )
            temporary_names[relative] = temporary_name
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | os.O_NONBLOCK
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_fd,
            )
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise ReleaseManifestError(
                            "release batch write made no progress"
                        )
                    view = view[written:]
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        for relative in payloads:
            filename = parsed[relative][-1]
            try:
                os.link(
                    temporary_names[relative],
                    filename,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except FileExistsError as exc:
                raise ReleaseManifestError(
                    f"release output {relative} already exists"
                ) from exc
            linked_names.append(filename)
        os.fsync(parent_fd)
    except BaseException:
        for filename in linked_names:
            try:
                os.unlink(filename, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.fsync(parent_fd)
        raise
    finally:
        for temporary_name in temporary_names.values():
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)
    return tuple(root / relative for relative in payloads)


def _write_capture_journal(
    root: Path, document: Mapping[str, object], *, allow_existing: bool
) -> None:
    payload = _canonical_json(document)
    root_fd = _root_fd(root)
    temporary_name = f".{CAPTURE_JOURNAL_PATH}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    try:
        try:
            existing = os.stat(
                CAPTURE_JOURNAL_PATH,
                dir_fd=root_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            if allow_existing:
                raise ReleaseManifestError("capture publication journal disappeared")
        else:
            if (
                not allow_existing
                or not stat.S_ISREG(existing.st_mode)
                or existing.st_uid != os.geteuid()
                or existing.st_nlink != 1
                or stat.S_IMODE(existing.st_mode) & 0o077
            ):
                raise ReleaseManifestError("capture publication journal is unsafe")
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NONBLOCK
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=root_fd,
        )
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise ReleaseManifestError(
                        "capture publication journal write made no progress"
                    )
                view = view[written:]
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(
            temporary_name,
            CAPTURE_JOURNAL_PATH,
            src_dir_fd=root_fd,
            dst_dir_fd=root_fd,
        )
        os.fsync(root_fd)
    finally:
        try:
            os.unlink(temporary_name, dir_fd=root_fd)
        except FileNotFoundError:
            pass
        os.close(root_fd)


def _capture_journal_document(
    *,
    transaction_id: str,
    release_existed: bool,
    payloads: Mapping[str, bytes],
    phase: str,
) -> dict[str, object]:
    return {
        "schema_version": CAPTURE_JOURNAL_SCHEMA_VERSION,
        "transaction_id": transaction_id,
        "phase": phase,
        "release_existed": release_existed,
        "staging_name": f".release.capture.{transaction_id}",
        "previous_name": f".release.previous.{transaction_id}",
        "payloads": {
            relative: hashlib.sha256(payload).hexdigest()
            for relative, payload in sorted(payloads.items())
        },
    }


def _safe_remove_capture_directory(root: Path, name: str) -> None:
    target = root / name
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseManifestError("capture publication recovery path is unsafe")
    shutil.rmtree(target)


def _recover_capture_publication(root: Path) -> str:
    """Recover one interrupted release-tree swap before any clean-tree gate."""

    journal_path = root / CAPTURE_JOURNAL_PATH
    if not journal_path.exists() and not journal_path.is_symlink():
        return "none"
    read = _read_bounded_repository_file(root, CAPTURE_JOURNAL_PATH, _CONTROL_LIMIT)
    document, canonical = _strict_json(read.raw, "capture publication journal")
    if read.raw != canonical or set(document) != {
        "schema_version",
        "transaction_id",
        "phase",
        "release_existed",
        "staging_name",
        "previous_name",
        "payloads",
    }:
        raise ReleaseManifestError("capture publication journal schema is not exact")
    transaction_id = _text(document.get("transaction_id"), "capture transaction ID")
    if re.fullmatch(r"[0-9a-f]{32}", transaction_id) is None:
        raise ReleaseManifestError("capture publication transaction ID is invalid")
    staging_name = f".release.capture.{transaction_id}"
    previous_name = f".release.previous.{transaction_id}"
    if (
        document.get("schema_version") != CAPTURE_JOURNAL_SCHEMA_VERSION
        or document.get("phase")
        not in {"preparing", "staged", "previous_moved", "published"}
        or type(document.get("release_existed")) is not bool
        or document.get("staging_name") != staging_name
        or document.get("previous_name") != previous_name
    ):
        raise ReleaseManifestError("capture publication journal identity differs")
    payloads = _mapping(document.get("payloads"), "capture journal payloads")
    standard_paths = frozenset(
        {
            *RECEIPT_PATHS.values(),
            *PROOF_RECEIPT_PATHS.values(),
            NPM_CAPTURE_PATH,
        }
    )
    collector_paths = {
        frozenset(
            {
                LIVE_COLLECTOR_RAW_PATHS[proof_id],
                LIVE_COLLECTOR_ARTIFACT_PATHS[proof_id],
                LIVE_COLLECTOR_RECEIPT_PATHS[proof_id],
            }
        )
        for proof_id in LIVE_COLLECTOR_RECEIPT_PATHS
    }
    if frozenset(payloads) not in {standard_paths, *collector_paths}:
        raise ReleaseManifestError("capture publication payload inventory differs")
    for relative, digest in payloads.items():
        _validate_relative_path(relative)
        if not relative.startswith("release/"):
            raise ReleaseManifestError("capture publication payload escaped release")
        _hash32(digest, f"capture payload {relative} SHA-256")

    release_path = root / "release"
    staging_path = root / staging_name
    previous_path = root / previous_name
    release_present = release_path.exists() or release_path.is_symlink()
    staging_present = staging_path.exists() or staging_path.is_symlink()
    previous_present = previous_path.exists() or previous_path.is_symlink()

    def validate_published() -> None:
        if not release_present:
            raise ReleaseManifestError("published capture tree is unavailable")
        for relative, digest in payloads.items():
            current = _read_bounded_repository_file(
                root,
                relative,
                _NPM_LIMIT if relative == NPM_CAPTURE_PATH else _CONTROL_LIMIT,
            )
            if hashlib.sha256(current.raw).hexdigest() != digest:
                raise ReleaseManifestError(
                    "published capture payload digest differs from journal"
                )

    root_fd = _root_fd(root)
    try:
        if release_present and previous_present and not staging_present:
            validate_published()
            _safe_remove_capture_directory(root, previous_name)
            os.unlink(CAPTURE_JOURNAL_PATH, dir_fd=root_fd)
            os.fsync(root_fd)
            return "published"
        if (
            release_present
            and not previous_present
            and not staging_present
            and (
                document.get("release_existed") is False
                or document.get("phase") == "published"
            )
        ):
            validate_published()
            os.unlink(CAPTURE_JOURNAL_PATH, dir_fd=root_fd)
            os.fsync(root_fd)
            return "published"
        if not release_present and previous_present and staging_present:
            os.rename(
                previous_name,
                "release",
                src_dir_fd=root_fd,
                dst_dir_fd=root_fd,
            )
            os.fsync(root_fd)
            _safe_remove_capture_directory(root, staging_name)
            os.unlink(CAPTURE_JOURNAL_PATH, dir_fd=root_fd)
            os.fsync(root_fd)
            return "rolled_back"
        if (
            release_present == bool(document.get("release_existed"))
            and staging_present
            and not previous_present
        ):
            _safe_remove_capture_directory(root, staging_name)
            os.unlink(CAPTURE_JOURNAL_PATH, dir_fd=root_fd)
            os.fsync(root_fd)
            return "rolled_back"
        if (
            document.get("phase") == "preparing"
            and release_present == bool(document.get("release_existed"))
            and not staging_present
            and not previous_present
        ):
            os.unlink(CAPTURE_JOURNAL_PATH, dir_fd=root_fd)
            os.fsync(root_fd)
            return "rolled_back"
    finally:
        os.close(root_fd)
    raise ReleaseManifestError("capture publication state cannot be recovered safely")


def _create_capture_batch_once(
    root: Path, payloads: Mapping[str, bytes]
) -> tuple[Path, ...]:
    """Publish the complete capture tree through a durable recoverable swap."""

    standard_paths = frozenset(
        {
            *RECEIPT_PATHS.values(),
            *PROOF_RECEIPT_PATHS.values(),
            NPM_CAPTURE_PATH,
        }
    )
    collector_paths = {
        frozenset(
            {
                LIVE_COLLECTOR_RAW_PATHS[proof_id],
                LIVE_COLLECTOR_ARTIFACT_PATHS[proof_id],
                LIVE_COLLECTOR_RECEIPT_PATHS[proof_id],
            }
        )
        for proof_id in LIVE_COLLECTOR_RECEIPT_PATHS
    }
    if (
        frozenset(payloads) not in {standard_paths, *collector_paths}
        or any(not relative.startswith("release/") for relative in payloads)
    ):
        raise ReleaseManifestError("capture output escaped the fixed release tree")
    transaction_id = secrets.token_hex(16)
    staging_name = f".release.capture.{transaction_id}"
    previous_name = f".release.previous.{transaction_id}"
    root_fd = _root_fd(root)
    staging = root / staging_name
    previous = root / previous_name
    release_exists = False
    try:
        try:
            release_metadata = os.stat("release", dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISDIR(release_metadata.st_mode):
                raise ReleaseManifestError("release capture tree is unsafe")
            release_exists = True
        journal = _capture_journal_document(
            transaction_id=transaction_id,
            release_existed=release_exists,
            payloads=payloads,
            phase="preparing",
        )
        _write_capture_journal(root, journal, allow_existing=False)
        os.mkdir(staging_name, 0o700, dir_fd=root_fd)
        os.fsync(root_fd)
        try:
            if release_exists:
                total_existing = 0
                tracked_raw = _git(
                    root,
                    ["ls-files", "-z", "--", "release"],
                    limit=_CONTROL_LIMIT,
                ).stdout
                try:
                    tracked = [
                        item.decode("utf-8")
                        for item in tracked_raw.split(b"\x00")
                        if item
                    ]
                except UnicodeDecodeError as exc:
                    raise ReleaseManifestError(
                        "existing release path inventory is malformed"
                    ) from exc
                for relative in tracked:
                    read = _read_bounded_repository_file(
                        root, relative, _VERIFIER_ARCHIVE_LIMIT
                    )
                    total_existing += len(read.raw)
                    if total_existing > _VERIFIER_ARCHIVE_LIMIT:
                        raise ReleaseManifestError(
                            "existing release tree exceeds size bound"
                        )
                    inner = PurePosixPath(relative).relative_to("release").as_posix()
                    _atomic_create_once(staging, inner, read.raw)
            for relative, payload in payloads.items():
                inner = PurePosixPath(relative).relative_to("release").as_posix()
                _atomic_create_once(staging, inner, payload)
            staging_fd = _root_fd(staging)
            try:
                os.fsync(staging_fd)
            finally:
                os.close(staging_fd)
            journal["phase"] = "staged"
            _write_capture_journal(root, journal, allow_existing=True)
            if release_exists:
                os.rename(
                    "release", previous_name, src_dir_fd=root_fd, dst_dir_fd=root_fd
                )
                os.fsync(root_fd)
                journal["phase"] = "previous_moved"
                _write_capture_journal(root, journal, allow_existing=True)
            try:
                os.rename(
                    staging_name, "release", src_dir_fd=root_fd, dst_dir_fd=root_fd
                )
            except BaseException:
                if release_exists:
                    os.rename(
                        previous_name,
                        "release",
                        src_dir_fd=root_fd,
                        dst_dir_fd=root_fd,
                    )
                raise
            os.fsync(root_fd)
            journal["phase"] = "published"
            _write_capture_journal(root, journal, allow_existing=True)
            if release_exists:
                shutil.rmtree(previous)
                os.fsync(root_fd)
            os.unlink(CAPTURE_JOURNAL_PATH, dir_fd=root_fd)
            os.fsync(root_fd)
        except BaseException:
            _recover_capture_publication(root)
            raise
    finally:
        os.close(root_fd)
    return tuple(root / relative for relative in payloads)


def _preflight_outputs_absent(root: Path, paths: Sequence[str]) -> None:
    for relative in paths:
        target = root / relative
        if target.exists() or target.is_symlink():
            raise ReleaseManifestError(f"release output {relative} already exists")


def _prepare_host_toolchain_receipt_locked(repository_root: str | Path) -> Path:
    """Create one untrusted host-toolchain enrollment candidate for review.

    The candidate is deliberately unusable as command authority until an
    operator reviews it and commits it as the only change above ``source_commit``.
    """

    root = Path(repository_root).resolve(strict=True)
    _require_repository(root)
    _recover_capture_publication(root)
    _require_clean_worktree(root)
    target = root / BOUND_HOST_TOOLCHAIN_RECEIPT_PATH
    if target.exists() or target.is_symlink():
        raise ReleaseManifestError("host-toolchain receipt already exists")
    source_commit = _git40(
        _git(root, ["rev-parse", "HEAD^{commit}"], limit=_CONTROL_LIMIT)
        .stdout.decode("ascii", errors="strict")
        .strip(),
        "host-toolchain source commit",
    )
    try:
        candidate = build_host_toolchain_receipt_candidate(
            repository_root=root,
            source_commit=source_commit,
        )
    except (BoundCommandError, OSError) as exc:
        raise ReleaseManifestError(
            "host-toolchain enrollment candidate could not be built"
        ) from exc
    payload = _canonical_json(candidate)
    document, canonical = _strict_json(payload, "host-toolchain receipt candidate")
    if canonical != payload:
        raise ReleaseManifestError("host-toolchain receipt candidate is not canonical")
    if (
        document.get("schema_version") != BOUND_HOST_TOOLCHAIN_RECEIPT_SCHEMA_VERSION
        or document.get("source_commit") != source_commit
    ):
        raise ReleaseManifestError("host-toolchain receipt candidate identity differs")
    _assert_safe_projection(
        document,
        _load_secret_canaries(),
        "host-toolchain receipt candidate",
    )
    _require_clean_worktree(root)
    return _atomic_create_once(root, BOUND_HOST_TOOLCHAIN_RECEIPT_PATH, payload)


def _capture_release_observations_locked(
    repository_root: str | Path,
) -> tuple[Path, ...]:
    """Collect and create the fixed receipt set; accept no caller status input."""

    root = Path(repository_root).absolute()
    _require_repository(root)
    _recover_capture_publication(root)
    _require_clean_worktree(root)
    output_paths = [
        *RECEIPT_PATHS.values(),
        *PROOF_RECEIPT_PATHS.values(),
        NPM_CAPTURE_PATH,
    ]
    _preflight_outputs_absent(root, output_paths)
    canaries = _load_secret_canaries()
    _, host_toolchain_bound, _ = _host_toolchain_binding(root)
    (
        _,
        _,
        command_gate_bounds,
        _,
        integration_commit,
    ) = _load_command_gate_receipts(
        root,
        canaries,
        require_current_tree=False,
    )
    snapshot = _collector_factory(root).collect()
    now = _utc_now()
    projections, npm_tarball = _project_snapshot(
        root,
        snapshot,
        now=now,
        canaries=canaries,
        integration_commit=integration_commit,
    )
    artifacts = _load_artifacts(root)
    verifier = _proof_verifier_factory(root)
    tool_commit = _verifier_tool_commit(root)
    verifier_source_tree_sha256 = _verifier_source_tree_sha256(root, tool_commit)
    command_environment_sha256 = _command_environment_sha256()
    observed_at = _parse_timestamp(snapshot.observed_at, "capture observed_at")[0]
    raw_surfaces = _raw_snapshot_surfaces(root, snapshot)
    if set(raw_surfaces) != set(projections):
        raise ReleaseManifestError("raw observation inventory differs")
    secret_digests = _load_secret_variant_digests()

    documents: dict[str, bytes] = {}
    for receipt_id, projection in projections.items():
        normalized_observation = _encode_normalized_observation(
            raw_surfaces[receipt_id],
            secret_digests=secret_digests,
        )
        document = _receipt(
            receipt_id=receipt_id,
            observed_at=observed_at,
            producer_tool_commit=tool_commit,
            command_environment_sha256=command_environment_sha256,
            normalized_observation=normalized_observation,
            projection=projection,
        )
        _assert_safe_projection(document, canaries, f"{receipt_id} receipt")
        documents[RECEIPT_PATHS[receipt_id]] = _canonical_json(document)
    for artifact_id, artifact in artifacts.items():
        projection = _proof_projection(verifier, artifact)
        document = _proof_receipt(
            artifact=artifact,
            observed_at=observed_at,
            verifier_tool_commit=tool_commit,
            verifier_source_tree_sha256=verifier_source_tree_sha256,
            command_environment_sha256=command_environment_sha256,
            projection=projection,
        )
        _assert_safe_projection(document, canaries, f"{artifact_id} proof receipt")
        documents[PROOF_RECEIPT_PATHS[artifact_id]] = _canonical_json(document)

    documents[NPM_CAPTURE_PATH] = npm_tarball
    _assert_unchanged(root, host_toolchain_bound, _CONTROL_LIMIT)
    for bound in command_gate_bounds:
        _assert_unchanged(root, bound, _ARTIFACT_LIMIT)
    for artifact in artifacts.values():
        _assert_unchanged(root, artifact.bound, _ARTIFACT_LIMIT)
    _require_clean_worktree(root)
    # Every file is fsynced under a private sibling tree.  One rename publishes
    # the whole fixed capture set, so a write failure exposes no partial paths.
    return _create_capture_batch_once(root, documents)


def _load_receipt(
    root: Path,
    relative: str,
    *,
    schema: str,
    receipt_id: str,
    canaries: Sequence[bytes],
    artifact_commit: str | None = None,
) -> tuple[_BoundFile, dict[str, Any]]:
    bound = _load_immutable_bound_file(
        root,
        relative,
        _CONTROL_LIMIT,
        artifact_commit=artifact_commit,
    )
    document, canonical = _strict_json(bound.raw, f"{receipt_id} receipt")
    if bound.raw != canonical:
        raise ReleaseManifestError(f"{receipt_id} receipt is not canonical JSON")
    expected_keys = (
        {
            "schema_version",
            "receipt_id",
            "observed_at",
            "producer_tool_commit",
            "command_environment_sha256",
            "normalized_observation_sha256",
            "normalized_observation",
            "projection_sha256",
            "projection",
        }
        if schema == OBSERVATION_SCHEMA_VERSION
        else {
            "schema_version",
            "proof_id",
            "observed_at",
            "verifier_tool_commit",
            "verifier_source_tree_sha256",
            "command_environment_sha256",
            "projection_sha256",
            "projection",
        }
    )
    if set(document) != expected_keys or document.get("schema_version") != schema:
        raise ReleaseManifestError(f"{receipt_id} receipt schema is not exact")
    id_key = "receipt_id" if schema == OBSERVATION_SCHEMA_VERSION else "proof_id"
    if document.get(id_key) != receipt_id:
        raise ReleaseManifestError(f"{receipt_id} receipt identity differs")
    projection = _mapping(document.get("projection"), f"{receipt_id} projection")
    if schema == OBSERVATION_SCHEMA_VERSION:
        normalized_observation = document.get("normalized_observation")
        if (
            document.get("normalized_observation_sha256")
            != hashlib.sha256(_canonical_json(normalized_observation)).hexdigest()
        ):
            raise ReleaseManifestError(
                f"{receipt_id} normalized observation digest differs"
            )
        _decode_normalized_observation(normalized_observation)
    if (
        document.get("projection_sha256")
        != hashlib.sha256(_canonical_json(projection)).hexdigest()
    ):
        kind = (
            "verifier receipt" if schema == PROOF_RECEIPT_SCHEMA_VERSION else "receipt"
        )
        raise ReleaseManifestError(f"{receipt_id} {kind} projection digest differs")
    _parse_timestamp(document.get("observed_at"), f"{receipt_id} observed_at")
    tool_key = (
        "producer_tool_commit"
        if schema == OBSERVATION_SCHEMA_VERSION
        else "verifier_tool_commit"
    )
    tool_commit = _git40(document.get(tool_key), f"{receipt_id} tool commit")
    _hash32(
        document.get("command_environment_sha256"),
        f"{receipt_id} command environment SHA-256",
    )
    if not _is_ancestor(root, tool_commit, bound.artifact_commit):
        raise ReleaseManifestError(
            f"{receipt_id} receipt predates no valid tool commit"
        )
    if schema == PROOF_RECEIPT_SCHEMA_VERSION:
        expected_tree = _verifier_source_tree_sha256(root, tool_commit)
        if document.get("verifier_source_tree_sha256") != expected_tree:
            raise ReleaseManifestError(
                f"{receipt_id} verifier source tree digest differs"
            )
    _assert_safe_projection(document, canaries, f"{receipt_id} receipt")
    return bound, document


def _snapshot_from_observation_receipts(
    documents: Mapping[str, Mapping[str, object]],
) -> RawObservationSnapshot:
    """Reconstruct the collector input, not a claimed derived projection."""

    if set(documents) != set(RECEIPT_PATHS):
        raise ReleaseManifestError("normalized observation receipt inventory differs")
    observed_at_values = {
        _text(document.get("observed_at"), f"{receipt_id} observed_at")
        for receipt_id, document in documents.items()
    }
    if len(observed_at_values) != 1:
        raise ReleaseManifestError("normalized observations are not one capture")
    decoded = {
        receipt_id: _decode_normalized_observation(
            document.get("normalized_observation")
        )
        for receipt_id, document in documents.items()
    }
    return RawObservationSnapshot(
        observed_at=next(iter(observed_at_values)),
        compose=_mapping(decoded["compose"], "normalized compose observation"),
        runtime=_sequence(decoded["runtime"], "normalized runtime observation"),
        caddy=_mapping(decoded["caddy"], "normalized Caddy observation"),
        public_probes=_sequence(
            decoded["public_probes"], "normalized public probe observation"
        ),
        pages=_mapping(decoded["pages"], "normalized Pages observation"),
        npm=_mapping(decoded["npm"], "normalized npm observation"),
        rpc=_sequence(decoded["rpc"], "normalized RPC observation"),
    )


def _replay_observation_receipts(
    root: Path,
    documents: Mapping[str, Mapping[str, object]],
    *,
    integration_commit: str,
    canaries: Sequence[bytes],
) -> tuple[dict[str, dict[str, object]], bytes]:
    snapshot = _snapshot_from_observation_receipts(documents)
    _, observed_time = _parse_timestamp(
        snapshot.observed_at, "normalized observation replay time"
    )
    projections, tarball = _project_snapshot(
        root,
        snapshot,
        now=observed_time,
        canaries=canaries,
        integration_commit=integration_commit,
        normalized_replay=True,
    )
    for receipt_id, document in documents.items():
        if projections[receipt_id] != document.get("projection"):
            raise ReleaseManifestError(
                f"{receipt_id} projection differs from normalized raw observation"
            )
    return projections, tarball


def _compare_recheck(
    captured: Mapping[str, Mapping[str, Any]],
    rechecked: Mapping[str, Mapping[str, object]],
    *,
    capture_time: datetime,
    recheck_time: datetime,
) -> None:
    if recheck_time - capture_time < _MIN_RECHECK_INTERVAL:
        raise ReleaseManifestError(
            "release recheck must occur at least 20 seconds later"
        )
    for surface in ("compose", "caddy", "pages", "npm"):
        first = dict(captured[surface])
        second = dict(rechecked[surface])
        first.pop("observed_at", None)
        second.pop("observed_at", None)
        if first != second:
            raise ReleaseManifestError(
                f"{surface} projection drifted between observations"
            )
    first_runtime = {
        item["service_id"]: item
        for item in _sequence(captured["runtime"].get("containers"), "captured runtime")
    }
    second_runtime = {
        item["service_id"]: item
        for item in _sequence(
            rechecked["runtime"].get("containers"), "rechecked runtime"
        )
    }
    if first_runtime.keys() != second_runtime.keys():
        raise ReleaseManifestError("runtime service set drifted between observations")
    for service_id in first_runtime:
        before = first_runtime[service_id]
        after = second_runtime[service_id]
        if after.get("restart_count") != before.get("restart_count"):
            raise ReleaseManifestError(
                f"runtime restart count changed for {service_id}"
            )
        if before != after:
            raise ReleaseManifestError(f"runtime identity drifted for {service_id}")
    first_probes = {
        item["probe_id"]: item
        for item in _sequence(
            captured["public_probes"].get("probes"), "captured probes"
        )
    }
    second_probes = {
        item["probe_id"]: item
        for item in _sequence(
            rechecked["public_probes"].get("probes"), "rechecked probes"
        )
    }
    if first_probes.keys() != second_probes.keys():
        raise ReleaseManifestError("public HTTPS probe set drifted")
    for probe_id in first_probes:
        before = dict(first_probes[probe_id])
        after = dict(second_probes[probe_id])
        before_dynamic = _mapping(
            before.get("dynamic_timestamps"), "captured public dynamic timestamps"
        )
        after_dynamic = _mapping(
            after.get("dynamic_timestamps"), "rechecked public dynamic timestamps"
        )
        if bool(before_dynamic) != bool(after_dynamic):
            raise ReleaseManifestError("public HTTPS timestamp contract drifted")
        if before_dynamic:
            if set(before_dynamic) != set(after_dynamic) or len(before_dynamic) != 1:
                raise ReleaseManifestError("public HTTPS timestamp fields drifted")
            before_value = next(iter(before_dynamic.values()))
            after_value = next(iter(after_dynamic.values()))
            _, before_time = _parse_public_utc(
                before_value, f"captured {probe_id} timestamp"
            )
            _, after_time = _parse_public_utc(
                after_value, f"rechecked {probe_id} timestamp"
            )
            if not (
                before_time <= capture_time < recheck_time
                and before_time < after_time <= recheck_time
            ):
                raise ReleaseManifestError(
                    "public HTTPS dynamic timestamp chronology differs"
                )
            for field in ("body_sha256", "byte_length", "dynamic_timestamps"):
                before.pop(field, None)
                after.pop(field, None)
        if before != after:
            raise ReleaseManifestError("public HTTPS content/TLS projection drifted")
    first_rpc = _mapping(
        captured["rpc"].get("corroborated_block"), "captured RPC block"
    )
    second_rpc = _mapping(
        rechecked["rpc"].get("corroborated_block"), "rechecked RPC block"
    )
    if (
        first_rpc.get("chain_name") != second_rpc.get("chain_name")
        or type(first_rpc.get("block_height")) is not int
        or type(second_rpc.get("block_height")) is not int
        or second_rpc["block_height"] < first_rpc["block_height"]
    ):
        raise ReleaseManifestError("RPC corroboration regressed between observations")


def _assert_unchanged(root: Path, bound: _BoundFile, limit: int) -> None:
    latest = _read_bounded_repository_file(root, bound.path, limit)
    if latest.fingerprint != bound.fingerprint or latest.raw != bound.raw:
        raise ReleaseManifestError(f"{bound.path} changed during release assembly")


def _validate_organizer_link_audit_document(
    document: Mapping[str, object],
    *,
    phase: str,
) -> dict[str, object]:
    """Validate the stable release-qualification projection.

    The complete nested browser evidence is independently replayed by the
    locked Node verifier.  This Python layer freezes the cross-gate fields and
    refuses any test fixture or operator-authored success projection.
    """

    expected_keys = {
        "schema_version",
        "verdict",
        "release_qualified",
        "collection_mode",
        "started_at",
        "captured_at",
        "request_sha256",
        "runtime",
        "inventory",
        "summary",
        "dashboard_routes",
        "proof_tabs",
        "links",
    }
    if set(document) != expected_keys:
        raise ReleaseManifestError(
            f"{phase} organizer rendered-link audit schema is not exact"
        )
    if (
        document.get("schema_version") != ORGANIZER_LINK_AUDIT_SCHEMA_VERSION
        or document.get("verdict") != "PASS"
        or document.get("release_qualified") is not True
        or document.get("collection_mode") != "live_incognito"
    ):
        raise ReleaseManifestError(
            f"{phase} only a live-incognito PASS is qualifying release evidence"
        )
    _, started = _parse_timestamp(
        document.get("started_at"), f"{phase} organizer audit start"
    )
    captured_at, captured = _parse_timestamp(
        document.get("captured_at"), f"{phase} organizer audit capture"
    )
    if captured < started:
        raise ReleaseManifestError(
            f"{phase} organizer rendered-link chronology differs"
        )
    _hash32(
        document.get("request_sha256"),
        f"{phase} organizer request SHA-256",
    )
    runtime = _mapping(document.get("runtime"), f"{phase} organizer runtime")
    if set(runtime) != {
        "node",
        "playwright",
        "chromium",
        "chromium_executable_sha256",
    }:
        raise ReleaseManifestError(
            f"{phase} organizer runtime inventory differs"
        )
    for name in ("node", "playwright", "chromium"):
        if len(_text(runtime.get(name), f"{phase} organizer {name}")) > 160:
            raise ReleaseManifestError(
                f"{phase} organizer runtime value is malformed"
            )
    _hash32(
        runtime.get("chromium_executable_sha256"),
        f"{phase} organizer Chromium SHA-256",
    )
    inventory = _mapping(
        document.get("inventory"),
        f"{phase} organizer inventory",
    )
    if set(inventory) != {
        "dashboard_route_ids",
        "proof_tab_ids",
        "known_link_ids",
    }:
        raise ReleaseManifestError(
            f"{phase} organizer inventory schema is not exact"
        )
    route_ids = [
        _text(value, f"{phase} organizer route ID")
        for value in _sequence(
            inventory.get("dashboard_route_ids"),
            f"{phase} organizer route IDs",
        )
    ]
    proof_tab_ids = [
        _text(value, f"{phase} organizer Proof tab ID")
        for value in _sequence(
            inventory.get("proof_tab_ids"),
            f"{phase} organizer Proof tab IDs",
        )
    ]
    known_link_ids = [
        _text(value, f"{phase} organizer known-link ID")
        for value in _sequence(
            inventory.get("known_link_ids"),
            f"{phase} organizer known-link IDs",
        )
    ]
    if (
        tuple(route_ids) != _ORGANIZER_DASHBOARD_ROUTE_IDS
        or tuple(proof_tab_ids) != _ORGANIZER_PROOF_TAB_IDS
        or len(known_link_ids) != 17
        or len(set(known_link_ids)) != 17
    ):
        raise ReleaseManifestError(
            f"{phase} organizer rendered-link inventory differs"
        )
    summary = _mapping(document.get("summary"), f"{phase} organizer summary")
    if set(summary) != {
        "dashboard_route_states",
        "proof_tabs",
        "unique_links",
        "blocked_non_read_requests",
        "console_errors",
        "page_errors",
        "first_party_failures",
        "blocked_websockets",
        "client_downloads",
    }:
        raise ReleaseManifestError(
            f"{phase} organizer summary schema is not exact"
        )
    if (
        summary.get("dashboard_route_states") != len(route_ids)
        or summary.get("proof_tabs") != len(proof_tab_ids)
        or summary.get("unique_links") < len(known_link_ids)
        or any(
            summary.get(name) != 0
            for name in (
                "blocked_non_read_requests",
                "console_errors",
                "page_errors",
                "first_party_failures",
                "blocked_websockets",
            )
        )
        or type(summary.get("client_downloads")) is not int
        or summary["client_downloads"] < 0
    ):
        raise ReleaseManifestError(
            f"{phase} organizer rendered-link summary is not qualifying"
        )
    routes = _sequence(
        document.get("dashboard_routes"), f"{phase} organizer routes"
    )
    tabs = _sequence(document.get("proof_tabs"), f"{phase} organizer tabs")
    links = _sequence(document.get("links"), f"{phase} organizer links")
    if (
        len(routes) != len(route_ids)
        or len(tabs) != len(proof_tab_ids)
        or len(links) != summary["unique_links"]
    ):
        raise ReleaseManifestError(
            f"{phase} organizer rendered-link evidence census differs"
        )
    return {
        "schema_version": ORGANIZER_LINK_AUDIT_SCHEMA_VERSION,
        "verdict": "PASS",
        "release_qualified": True,
        "collection_mode": "live_incognito",
        "captured_at": captured_at,
    }


def _validate_organizer_link_invocation_document(
    document: Mapping[str, object],
    *,
    phase: str,
    audit_path: str,
    audit_sha256: str,
    audit_started_at: str,
    audit_captured_at: str,
    request_sha256: str,
    source_bindings: Sequence[Mapping[str, object]],
    host_toolchain: Mapping[str, object],
) -> dict[str, object]:
    """Validate one authoritative, bound, no-fixture collector invocation."""

    if set(document) != {
        "schema_version",
        "phase",
        "status",
        "collection_mode",
        "started_at",
        "ended_at",
        "command",
        "request",
        "source_bindings",
        "host_toolchain",
        "audit",
    }:
        raise ReleaseManifestError(
            f"{phase} organizer invocation schema is not exact"
        )
    if (
        phase not in {"G12", "G13"}
        or document.get("schema_version")
        != ORGANIZER_LINK_INVOCATION_SCHEMA_VERSION
        or document.get("phase") != phase
        or document.get("status") != "passed"
        or document.get("collection_mode") != "live_incognito"
    ):
        raise ReleaseManifestError(
            f"{phase} organizer invocation is not an authoritative PASS"
        )
    _, started = _parse_timestamp(
        document.get("started_at"),
        f"{phase} organizer invocation start",
    )
    ended_at, ended = _parse_timestamp(
        document.get("ended_at"),
        f"{phase} organizer invocation end",
    )
    _, audit_started = _parse_timestamp(
        audit_started_at,
        f"{phase} organizer audit start",
    )
    _, audit_captured = _parse_timestamp(
        audit_captured_at,
        f"{phase} organizer audit capture",
    )
    if not started <= audit_started <= audit_captured <= ended:
        raise ReleaseManifestError(
            f"{phase} organizer invocation chronology differs"
        )

    command = _mapping(
        document.get("command"),
        f"{phase} organizer invocation command",
    )
    if set(command) != {
        "argv",
        "exit_code",
        "fixture_argument_present",
        "stdout_sha256",
        "stderr_sha256",
        "tool_identity_sha256",
        "command_assets_sha256",
    }:
        raise ReleaseManifestError(
            f"{phase} organizer invocation command schema is not exact"
        )
    expected_argv = [
        "node",
        ORGANIZER_LINK_RUNNER_PATH,
        "--input",
        ORGANIZER_LINK_REQUEST_PATH,
    ]
    argv = _sequence(
        command.get("argv"),
        f"{phase} organizer invocation argv",
    )
    if (
        argv != expected_argv
        or "--fixture" in argv
        or command.get("fixture_argument_present") is not False
    ):
        raise ReleaseManifestError(
            f"{phase} organizer invocation must use the exact no-fixture argv"
        )
    if (
        command.get("exit_code") != 0
        or _hash32(
            command.get("stdout_sha256"),
            f"{phase} organizer invocation stdout SHA-256",
        )
        != audit_sha256
        or _hash32(
            command.get("stderr_sha256"),
            f"{phase} organizer invocation stderr SHA-256",
        )
        != hashlib.sha256(b"").hexdigest()
    ):
        raise ReleaseManifestError(
            f"{phase} organizer invocation stdout/audit binding differs"
        )
    for field in ("tool_identity_sha256", "command_assets_sha256"):
        _hash32(
            command.get(field),
            f"{phase} organizer invocation {field}",
        )

    request = _mapping(
        document.get("request"),
        f"{phase} organizer invocation request",
    )
    if (
        set(request) != {"path", "sha256"}
        or request.get("path") != ORGANIZER_LINK_REQUEST_PATH
        or _hash32(
            request.get("sha256"),
            f"{phase} organizer invocation request SHA-256",
        )
        != request_sha256
    ):
        raise ReleaseManifestError(
            f"{phase} organizer invocation request binding differs"
        )
    audit = _mapping(
        document.get("audit"),
        f"{phase} organizer invocation audit",
    )
    if (
        set(audit) != {"path", "sha256"}
        or audit.get("path") != audit_path
        or _hash32(
            audit.get("sha256"),
            f"{phase} organizer invocation audit SHA-256",
        )
        != audit_sha256
    ):
        raise ReleaseManifestError(
            f"{phase} organizer invocation audit binding differs"
        )
    expected_sources = [dict(row) for row in source_bindings]
    actual_sources = _sequence(
        document.get("source_bindings"),
        f"{phase} organizer invocation source bindings",
    )
    if actual_sources != expected_sources:
        raise ReleaseManifestError(
            f"{phase} organizer invocation source binding differs"
        )
    for row in actual_sources:
        binding = _mapping(
            row,
            f"{phase} organizer invocation source binding",
        )
        if set(binding) != {"path", "sha256"}:
            raise ReleaseManifestError(
                f"{phase} organizer invocation source schema is not exact"
            )
        _text(binding.get("path"), f"{phase} organizer source path")
        _hash32(
            binding.get("sha256"),
            f"{phase} organizer source SHA-256",
        )
    expected_host_toolchain = dict(host_toolchain)
    actual_host_toolchain = _mapping(
        document.get("host_toolchain"),
        f"{phase} organizer invocation host toolchain",
    )
    if (
        actual_host_toolchain != expected_host_toolchain
        or set(actual_host_toolchain)
        != {"path", "sha256", "artifact_commit"}
        or actual_host_toolchain.get("path")
        != BOUND_HOST_TOOLCHAIN_RECEIPT_PATH
    ):
        raise ReleaseManifestError(
            f"{phase} organizer invocation host authority differs"
        )
    _hash32(
        actual_host_toolchain.get("sha256"),
        f"{phase} organizer host-toolchain SHA-256",
    )
    _git40(
        actual_host_toolchain.get("artifact_commit"),
        f"{phase} organizer host-toolchain artifact commit",
    )
    return {
        "path": (
            ORGANIZER_G12_INVOCATION_PATH
            if phase == "G12"
            else ORGANIZER_G13_INVOCATION_PATH
        ),
        "schema_version": ORGANIZER_LINK_INVOCATION_SCHEMA_VERSION,
        "status": "passed",
        "collection_mode": "live_incognito",
        "ended_at": ended_at,
        "audit_sha256": audit_sha256,
    }


def _materialize_organizer_verifier_package(
    root: Path,
    target: Path,
) -> Path:
    """Copy the verifier and its only import into one closed command tree."""

    target.mkdir(mode=0o700)
    scripts = target / "scripts"
    scripts.mkdir(mode=0o700)
    for relative in (
        ORGANIZER_LINK_CORE_PATH,
        ORGANIZER_LINK_VERIFIER_PATH,
    ):
        destination = target / relative
        shutil.copy2(root / relative, destination)
        if destination.is_symlink() or not destination.is_file():
            raise ReleaseManifestError(
                "organizer verifier command package contains an unsafe file"
            )
    return target / ORGANIZER_LINK_VERIFIER_PATH


def _materialize_organizer_collector_package(
    root: Path,
    target: Path,
) -> Path:
    """Create the closed Playwright command tree for a live organizer audit."""

    target.mkdir(mode=0o700)
    scripts = target / "scripts"
    scripts.mkdir(mode=0o700)
    for relative in (
        ORGANIZER_LINK_CORE_PATH,
        ORGANIZER_LINK_RUNNER_PATH,
        ORGANIZER_LINK_VERIFIER_PATH,
    ):
        shutil.copy2(root / relative, target / relative)
    runtime_target = target / "scripts" / "g13-browser-runtime"
    runtime_target.mkdir(mode=0o700)
    runtime_inputs: list[Path] = []
    for name in ("package.json", "package-lock.json", "install-browser.mjs"):
        source = root / "scripts" / "g13-browser-runtime" / name
        destination = runtime_target / name
        shutil.copy2(source, destination)
        runtime_inputs.append(destination)
    _run(
        runtime_target,
        [
            "npm",
            "ci",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--registry=https://registry.npmjs.org/",
        ],
        limit=_CONTROL_LIMIT,
        timeout=180,
        repository_root=root,
        bound_data_inputs=tuple(runtime_inputs),
    )
    browser_download = target.parent / "browser-download"
    browser_download.mkdir(mode=0o700)
    _run(
        runtime_target,
        [
            "node",
            str(runtime_target / "install-browser.mjs"),
            str(browser_download),
        ],
        limit=_GIT_OUTPUT_LIMIT,
        timeout=180,
        repository_root=root,
        command_asset_root=runtime_target,
    )
    local_browsers = (
        runtime_target
        / "node_modules"
        / "playwright-core"
        / ".local-browsers"
    )
    if local_browsers.exists():
        raise ReleaseManifestError(
            "organizer collector local browser destination already exists"
        )
    shutil.copytree(browser_download, local_browsers, symlinks=False)
    binary_links = runtime_target / "node_modules" / ".bin"
    if binary_links.exists():
        shutil.rmtree(binary_links)
    for current_root, directory_names, file_names in os.walk(
        target,
        topdown=True,
        followlinks=False,
    ):
        current = Path(current_root)
        for name in [*directory_names, *file_names]:
            if (current / name).is_symlink():
                raise ReleaseManifestError(
                    "organizer collector command package contains a symlink"
                )
    return target / ORGANIZER_LINK_RUNNER_PATH


def _default_organizer_link_audit_verifier(
    root: Path,
    audit: _BoundFile,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(
        prefix="concordia-organizer-verifier-"
    ) as name:
        package_root = Path(name) / "command-package"
        entrypoint = _materialize_organizer_verifier_package(
            root,
            package_root,
        )
        result = _run(
            root,
            [
                "node",
                str(entrypoint),
                str(root / audit.path),
            ],
            limit=_CONTROL_LIMIT,
            timeout=60,
            repository_root=root,
            command_asset_root=package_root,
            bound_data_inputs=(root / audit.path,),
        )
    document, canonical = _strict_json(
        result.stdout,
        "organizer rendered-link verifier output",
    )
    if result.stdout != canonical:
        raise ReleaseManifestError(
            "organizer rendered-link verifier output is not canonical JSON"
        )
    return document


def _organizer_link_audit_verifier_factory(_root: Path) -> object:
    return _default_organizer_link_audit_verifier


def _organizer_link_audit_binding(
    root: Path,
    *,
    path: str,
    phase: str,
    artifact_commit: str | None = None,
    canaries: Sequence[bytes] = (),
) -> tuple[_BoundFile, dict[str, object]]:
    audit = _load_immutable_bound_file(
        root,
        path,
        _VERIFIER_ARCHIVE_LIMIT,
        artifact_commit=artifact_commit,
    )
    _assert_no_canary(
        audit.raw,
        canaries,
        f"{phase} organizer rendered-link audit",
    )
    document, canonical = _strict_json(
        audit.raw,
        f"{phase} organizer rendered-link audit",
    )
    if audit.raw != canonical:
        raise ReleaseManifestError(
            f"{phase} organizer rendered-link audit is not canonical JSON"
        )
    stable = _validate_organizer_link_audit_document(document, phase=phase)
    _assert_safe_projection(
        document,
        canaries,
        f"{phase} organizer rendered-link audit",
    )
    request = _load_bound_file(
        root,
        ORGANIZER_LINK_REQUEST_PATH,
        _CONTROL_LIMIT,
    )
    request_document, _ = _strict_json(
        request.raw,
        f"{phase} organizer request",
    )
    request_digest = hashlib.sha256(
        _canonical_json(request_document).removesuffix(b"\n")
    ).hexdigest()
    if document.get("request_sha256") != request_digest:
        raise ReleaseManifestError(
            f"{phase} organizer request binding differs"
        )
    source_bounds = [
        request,
        _load_bound_file(root, ORGANIZER_LINK_CORE_PATH, _CONTROL_LIMIT),
        _load_bound_file(root, ORGANIZER_LINK_RUNNER_PATH, _CONTROL_LIMIT),
        _load_bound_file(root, ORGANIZER_LINK_VERIFIER_PATH, _CONTROL_LIMIT),
    ]
    if any(
        not _is_ancestor(root, source.artifact_commit, audit.artifact_commit)
        for source in source_bounds
    ):
        raise ReleaseManifestError(
            f"{phase} organizer collector does not precede its audit"
        )
    invocation_path = (
        ORGANIZER_G12_INVOCATION_PATH
        if phase == "G12"
        else ORGANIZER_G13_INVOCATION_PATH
    )
    invocation = _load_immutable_bound_file(
        root,
        invocation_path,
        _CONTROL_LIMIT,
        artifact_commit=artifact_commit,
    )
    if invocation.artifact_commit != audit.artifact_commit:
        raise ReleaseManifestError(
            f"{phase} organizer audit and invocation are not one immutable batch"
        )
    _assert_no_canary(
        invocation.raw,
        canaries,
        f"{phase} organizer invocation receipt",
    )
    invocation_document, invocation_canonical = _strict_json(
        invocation.raw,
        f"{phase} organizer invocation receipt",
    )
    if invocation.raw != invocation_canonical:
        raise ReleaseManifestError(
            f"{phase} organizer invocation receipt is not canonical JSON"
        )
    invocation_sources = [
        {"path": source.path, "sha256": source.sha256}
        for source in source_bounds
        if source.path
        in {
            ORGANIZER_LINK_CORE_PATH,
            ORGANIZER_LINK_RUNNER_PATH,
        }
    ]
    _, host_toolchain_bound, _ = _host_toolchain_binding(root)
    host_toolchain_row = {
        "path": host_toolchain_bound.path,
        "sha256": host_toolchain_bound.sha256,
        "artifact_commit": host_toolchain_bound.artifact_commit,
    }
    if not _is_ancestor(
        root,
        host_toolchain_bound.artifact_commit,
        audit.artifact_commit,
    ):
        raise ReleaseManifestError(
            f"{phase} organizer host authority does not precede its audit"
        )
    invocation_projection = _validate_organizer_link_invocation_document(
        invocation_document,
        phase=phase,
        audit_path=path,
        audit_sha256=audit.sha256,
        audit_started_at=_text(
            document.get("started_at"),
            f"{phase} organizer audit start",
        ),
        audit_captured_at=_text(
            document.get("captured_at"),
            f"{phase} organizer audit capture",
        ),
        request_sha256=request.sha256,
        source_bindings=invocation_sources,
        host_toolchain=host_toolchain_row,
    )
    _assert_safe_projection(
        invocation_document,
        canaries,
        f"{phase} organizer invocation receipt",
    )
    verified = _mapping(
        _organizer_link_audit_verifier_factory(root)(root, audit),
        f"{phase} organizer verifier projection",
    )
    expected_verified = {
        "schema_version": ORGANIZER_LINK_AUDIT_SCHEMA_VERSION,
        "verdict": "PASS",
        "release_qualified": True,
        "collection_mode": "live_incognito",
        "audit_sha256": audit.sha256,
    }
    if verified != expected_verified:
        raise ReleaseManifestError(
            f"{phase} organizer rendered-link verifier disagrees"
        )
    return audit, {
        "path": path,
        "sha256": audit.sha256,
        "artifact_commit": audit.artifact_commit,
        **stable,
        "invocation": {
            **invocation_projection,
            "sha256": invocation.sha256,
            "artifact_commit": invocation.artifact_commit,
        },
        "source_bindings": [
            {
                "path": source.path,
                "sha256": source.sha256,
                "artifact_commit": source.artifact_commit,
            }
            for source in source_bounds
        ],
    }


def _gate_evidence_map(
    *,
    command_gates: Mapping[str, Mapping[str, object]],
    observations: Sequence[Mapping[str, object]],
    proofs: Sequence[Mapping[str, object]],
    npm_capture: _BoundFile,
    organizer_audit: Mapping[str, object],
) -> list[dict[str, object]]:
    references: dict[tuple[str, str], dict[str, object]] = {}
    for gate_id, binding in command_gates.items():
        references[("command_gate", gate_id)] = {
            "kind": "command_gate",
            "evidence_id": gate_id,
            "path": binding["path"],
            "sha256": binding["sha256"],
            "artifact_commit": binding["artifact_commit"],
        }
    for binding in observations:
        receipt_id = _text(binding.get("receipt_id"), "observation receipt reference")
        references[("observation", receipt_id)] = {
            "kind": "observation",
            "evidence_id": receipt_id,
            "path": binding["path"],
            "sha256": binding["sha256"],
            "artifact_commit": binding["artifact_commit"],
        }
    for binding in proofs:
        proof_id = _text(binding.get("proof_id"), "proof receipt reference")
        references[("proof", proof_id)] = {
            "kind": "proof",
            "evidence_id": proof_id,
            "path": binding["path"],
            "sha256": binding["sha256"],
            "artifact_commit": binding["artifact_commit"],
        }
    references[("capture", "npm_tarball")] = {
        "kind": "capture",
        "evidence_id": "npm_tarball",
        "path": NPM_CAPTURE_PATH,
        "sha256": npm_capture.sha256,
        "artifact_commit": npm_capture.artifact_commit,
    }
    references[("browser_audit", "organizer_rendered_links")] = {
        "kind": "browser_audit",
        "evidence_id": "organizer_rendered_links",
        "path": organizer_audit["path"],
        "sha256": organizer_audit["sha256"],
        "artifact_commit": organizer_audit["artifact_commit"],
    }

    all_proofs = tuple(("proof", proof_id) for proof_id in sorted(PROOF_RECEIPT_PATHS))
    all_observations = tuple(
        ("observation", receipt_id) for receipt_id in sorted(RECEIPT_PATHS)
    )
    all_commands = tuple(
        ("command_gate", gate_id) for gate_id in COMMAND_GATE_RECEIPT_PATHS
    )
    specs: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
        ("G2", (("command_gate", "G2"),)),
        ("G3", (("proof", "exact_envelope_v3"),)),
        (
            "G4",
            (("observation", "compose"), ("observation", "runtime")),
        ),
        (
            "G5",
            (("observation", "caddy"), ("observation", "public_probes")),
        ),
        (
            "G6",
            (
                ("proof", "safepay_v2"),
                ("observation", "public_probes"),
                ("observation", "rpc"),
            ),
        ),
        (
            "G7a",
            (
                ("proof", "exact_envelope_v3"),
                ("proof", "native_treasury_execution_v1"),
                ("observation", "rpc"),
            ),
        ),
        (
            "G7b",
            (
                ("proof", "official_x402_settlement_v1"),
                ("observation", "public_probes"),
                ("observation", "rpc"),
            ),
        ),
        ("G8", all_proofs),
        ("G9", (("command_gate", "G9"),)),
        (
            "G9n",
            (("observation", "npm"), ("capture", "npm_tarball")),
        ),
        (
            "G9d",
            (("observation", "pages"), ("observation", "public_probes")),
        ),
        (
            "G10",
            (
                ("observation", "compose"),
                ("observation", "runtime"),
                ("observation", "caddy"),
                ("observation", "public_probes"),
                ("observation", "pages"),
                ("observation", "rpc"),
            ),
        ),
        (
            "G11",
            (("command_gate", "G11"), ("proof", "proof_registry_v1")),
        ),
        (
            "G12",
            (
                *all_commands,
                *all_observations,
                *all_proofs,
                ("capture", "npm_tarball"),
                ("browser_audit", "organizer_rendered_links"),
            ),
        ),
    )
    result: list[dict[str, object]] = []
    for gate_id, required in specs:
        missing = [key for key in required if key not in references]
        if missing:
            raise ReleaseManifestError(f"{gate_id} has missing fixed release evidence")
        result.append(
            {
                "gate_id": gate_id,
                "status": "verified",
                "evidence_refs": [references[key] for key in required],
            }
        )
    result.append(
        {
            "gate_id": "G13",
            "required_receipt_path": G13_SUBMISSION_RECEIPT_PATH,
            "required_rendered_link_audit_path": ORGANIZER_G13_AUDIT_PATH,
            "status": "pending_external",
        }
    )
    return result


def _g1_freeze_contract_projection(root: Path) -> dict[str, object]:
    """Resolve the G1 authority; final constants come from the shared contract."""

    return _validate_g1_freeze_authority(
        root,
        expected_tag=G1_FREEZE_TAG,
        expected_tag_object=G1_FREEZE_TAG_OBJECT,
        expected_commit=G1_FREEZE_COMMIT,
    )


def _validate_g12_manifest_offline(
    root: Path,
    manifest: Mapping[str, object],
    *,
    canaries: Sequence[bytes],
    manifest_commit: str | None = None,
) -> dict[str, object]:
    """Reconstruct every committed G12 claim without a collector or network."""

    expected_keys = {
        "schema_version",
        "status",
        "overall_status",
        "completion_scope",
        "frozen_commit",
        "integration_commit",
        "g1_freeze",
        "host_toolchain",
        "post_freeze_corrections",
        "generated_at",
        "gate_evidence",
        "command_gate_replays",
        "observation_receipts",
        "proof_verifier_receipts",
        "npm_tarball_capture",
        "organizer_rendered_link_audit",
        "recheck",
        "artifacts",
        "services",
        "deployment_surfaces",
    }
    if set(manifest) != expected_keys:
        raise ReleaseManifestError("G12 release manifest schema is not exact")
    if (
        manifest.get("schema_version") != SCHEMA_VERSION
        or manifest.get("status") != "g12_ready"
        or manifest.get("overall_status") != "pending_external"
        or manifest.get("completion_scope") != "G2-G12"
    ):
        raise ReleaseManifestError("G12 release manifest identity differs")
    _, generated_time = _parse_timestamp(
        manifest.get("generated_at"), "G12 generated_at"
    )
    (
        command_gates,
        _,
        _,
        frozen_commit,
        integration_commit,
    ) = _load_command_gate_receipts(root, canaries, require_current_tree=True)
    if (
        manifest.get("frozen_commit") != frozen_commit
        or manifest.get("integration_commit") != integration_commit
    ):
        raise ReleaseManifestError("G12 command-gate identity differs")
    g1_freeze = _g1_freeze_contract_projection(root)
    if manifest.get("g1_freeze") != g1_freeze:
        raise ReleaseManifestError("G12 G1 freeze authority differs")
    _, _, host_toolchain_projection = _host_toolchain_binding(root)
    if manifest.get("host_toolchain") != host_toolchain_projection:
        raise ReleaseManifestError("G12 host-toolchain authority differs")
    post_freeze_corrections, _ = _post_freeze_corrections_projection(
        root,
        integration_commit=integration_commit,
    )
    if manifest.get("post_freeze_corrections") != post_freeze_corrections:
        raise ReleaseManifestError("G12 post-freeze corrections differ")
    if manifest_commit is not None:
        manifest_commit = _git40(manifest_commit, "G12 manifest commit")
        if not _is_ancestor(root, integration_commit, manifest_commit):
            raise ReleaseManifestError("G12 manifest does not descend from integration")
    claimed_observations: dict[str, Mapping[str, object]] = {}
    for raw_row in _sequence(
        manifest.get("observation_receipts"), "G12 observation bindings"
    ):
        row = _mapping(raw_row, "G12 observation binding")
        receipt_id = _text(row.get("receipt_id"), "G12 observation receipt ID")
        if receipt_id in claimed_observations:
            raise ReleaseManifestError("G12 observation binding is duplicated")
        claimed_observations[receipt_id] = row
    if set(claimed_observations) != set(RECEIPT_PATHS):
        raise ReleaseManifestError("G12 observation binding inventory differs")
    claimed_proofs: dict[str, Mapping[str, object]] = {}
    for raw_row in _sequence(
        manifest.get("proof_verifier_receipts"), "G12 proof bindings"
    ):
        row = _mapping(raw_row, "G12 proof binding")
        proof_id = _text(row.get("proof_id"), "G12 proof receipt ID")
        if proof_id in claimed_proofs:
            raise ReleaseManifestError("G12 proof binding is duplicated")
        claimed_proofs[proof_id] = row
    if set(claimed_proofs) != set(PROOF_RECEIPT_PATHS):
        raise ReleaseManifestError("G12 proof binding inventory differs")
    expected_replays = [
        {
            "gate_id": gate_id,
            "status": "verified",
            "replay_contract_sha256": binding["replay_contract_sha256"],
        }
        for gate_id, binding in command_gates.items()
    ]
    if manifest.get("command_gate_replays") != expected_replays:
        raise ReleaseManifestError("G12 command-gate replay binding differs")
    replayed_gates = _command_gate_replayer_factory(root)(
        root,
        integration_commit=integration_commit,
        expected=expected_replays,
    )
    if replayed_gates != expected_replays:
        raise ReleaseManifestError("G12 command-gate fresh replay differs")

    current_tool_commit = _verifier_tool_commit(root)
    current_tool_tree = _verifier_source_tree_sha256(root, current_tool_commit)
    captured: dict[str, Mapping[str, Any]] = {}
    observation_documents: dict[str, Mapping[str, object]] = {}
    observation_bindings: list[dict[str, object]] = []
    capture_times: set[datetime] = set()
    for receipt_id, path in RECEIPT_PATHS.items():
        bound, document = _load_receipt(
            root,
            path,
            schema=OBSERVATION_SCHEMA_VERSION,
            receipt_id=receipt_id,
            canaries=canaries,
            artifact_commit=(
                _text(
                    claimed_observations[receipt_id].get("artifact_commit"),
                    f"G12 {receipt_id} artifact commit",
                )
                if manifest_commit is not None
                else None
            ),
        )
        if document.get("producer_tool_commit") != current_tool_commit:
            raise ReleaseManifestError(
                "G12 observation verifier implementation is stale"
            )
        observed_at, capture_time = _parse_timestamp(
            document.get("observed_at"), f"G12 {receipt_id} observed_at"
        )
        capture_times.add(capture_time)
        captured[receipt_id] = _mapping(
            document.get("projection"), f"G12 {receipt_id} projection"
        )
        observation_documents[receipt_id] = document
        observation_bindings.append(
            {
                "receipt_id": receipt_id,
                "path": path,
                "sha256": bound.sha256,
                "artifact_commit": bound.artifact_commit,
                "observed_at": observed_at,
                "projection_sha256": document["projection_sha256"],
            }
        )
    if len(capture_times) != 1:
        raise ReleaseManifestError("G12 observation receipts are not one capture")
    capture_time = next(iter(capture_times))
    replayed, replayed_tarball = _replay_observation_receipts(
        root,
        observation_documents,
        integration_commit=integration_commit,
        canaries=canaries,
    )
    if replayed != captured:
        raise ReleaseManifestError("G12 normalized observation replay differs")
    if not (capture_time <= generated_time <= capture_time + _RECEIPT_MAX_AGE):
        raise ReleaseManifestError("G12 manifest chronology differs")
    expected_observations = sorted(
        observation_bindings, key=lambda item: str(item["receipt_id"])
    )
    if manifest.get("observation_receipts") != expected_observations:
        raise ReleaseManifestError("G12 observation receipt bindings differ")

    artifacts = _load_artifacts(root)
    _validate_payment_artifact_runtime_binding(
        artifacts,
        _mapping(captured.get("runtime"), "captured runtime"),
    )
    verifier = _proof_verifier_factory(root)
    proof_bindings: list[dict[str, object]] = []
    for artifact_id, artifact in artifacts.items():
        bound, document = _load_receipt(
            root,
            PROOF_RECEIPT_PATHS[artifact_id],
            schema=PROOF_RECEIPT_SCHEMA_VERSION,
            receipt_id=artifact_id,
            canaries=canaries,
            artifact_commit=(
                _text(
                    claimed_proofs[artifact_id].get("artifact_commit"),
                    f"G12 {artifact_id} artifact commit",
                )
                if manifest_commit is not None
                else None
            ),
        )
        if (
            document.get("verifier_tool_commit") != current_tool_commit
            or document.get("verifier_source_tree_sha256") != current_tool_tree
            or _parse_timestamp(
                document.get("observed_at"), f"G12 {artifact_id} observed_at"
            )[1]
            != capture_time
        ):
            raise ReleaseManifestError(
                "G12 proof verifier identity or chronology differs"
            )
        if document.get("projection") != _proof_projection(verifier, artifact):
            raise ReleaseManifestError("G12 proof receipt does not replay offline")
        proof_bindings.append(
            {
                "proof_id": artifact_id,
                "path": PROOF_RECEIPT_PATHS[artifact_id],
                "sha256": bound.sha256,
                "artifact_commit": bound.artifact_commit,
                "observed_at": document["observed_at"],
                "projection_sha256": document["projection_sha256"],
            }
        )
    expected_proofs = sorted(proof_bindings, key=lambda item: str(item["proof_id"]))
    if manifest.get("proof_verifier_receipts") != expected_proofs:
        raise ReleaseManifestError("G12 proof receipt bindings differ")

    claimed_npm = _mapping(
        manifest.get("npm_tarball_capture"), "G12 npm tarball binding"
    )
    npm_capture = _load_immutable_bound_file(
        root,
        NPM_CAPTURE_PATH,
        _NPM_LIMIT,
        artifact_commit=(
            _text(
                claimed_npm.get("artifact_commit"),
                "G12 npm tarball artifact commit",
            )
            if manifest_commit is not None
            else None
        ),
    )
    expected_npm = {
        "path": NPM_CAPTURE_PATH,
        "sha256": npm_capture.sha256,
        "artifact_commit": npm_capture.artifact_commit,
    }
    if manifest.get(
        "npm_tarball_capture"
    ) != expected_npm or npm_capture.sha256 != captured["npm"].get(
        "tarball_sha256"
    ) or hashlib.sha256(replayed_tarball).hexdigest() != npm_capture.sha256:
        raise ReleaseManifestError("G12 npm tarball capture differs")

    claimed_organizer = _mapping(
        manifest.get("organizer_rendered_link_audit"),
        "G12 organizer rendered-link binding",
    )
    _, organizer_projection = _organizer_link_audit_binding(
        root,
        path=ORGANIZER_G12_AUDIT_PATH,
        phase="G12",
        canaries=canaries,
        artifact_commit=(
            _text(
                claimed_organizer.get("artifact_commit"),
                "G12 organizer audit artifact commit",
            )
            if manifest_commit is not None
            else None
        ),
    )
    if claimed_organizer != organizer_projection:
        raise ReleaseManifestError(
            "G12 organizer rendered-link audit binding differs"
        )
    _, organizer_time = _parse_timestamp(
        organizer_projection.get("captured_at"),
        "G12 organizer rendered-link capture",
    )
    if not capture_time <= organizer_time <= generated_time:
        raise ReleaseManifestError(
            "G12 organizer rendered-link chronology differs"
        )

    expected_artifacts = [
        {
            "artifact_id": artifact.artifact_id,
            "path": artifact.bound.path,
            "sha256": artifact.bound.sha256,
            "artifact_commit": artifact.bound.artifact_commit,
            "schema_version": artifact.schema_version,
            "captured_at": artifact.captured_at,
            "source_commit": artifact.source_commit,
            "deployment_commit": artifact.deployment_commit,
            "observation_mode": artifact.observation_mode,
        }
        for artifact in sorted(artifacts.values(), key=lambda item: item.artifact_id)
    ]
    if manifest.get("artifacts") != expected_artifacts:
        raise ReleaseManifestError("G12 artifact lineage differs")
    expected_gates = _gate_evidence_map(
        command_gates=command_gates,
        observations=observation_bindings,
        proofs=proof_bindings,
        npm_capture=npm_capture,
        organizer_audit=organizer_projection,
    )
    if manifest.get("gate_evidence") != expected_gates:
        raise ReleaseManifestError("G12 gate evidence map differs")
    if manifest.get("services") != captured["runtime"].get("containers"):
        raise ReleaseManifestError("G12 runtime service projection differs")
    expected_surfaces = {
        "caddy_semantic_sha256": captured["caddy"].get("semantic_sha256"),
        "compose_semantic_sha256": captured["compose"].get("semantic_sha256"),
        "pages": captured["pages"],
        "npm": captured["npm"],
        "rpc": captured["rpc"],
        "public_probes": captured["public_probes"],
    }
    if manifest.get("deployment_surfaces") != expected_surfaces:
        raise ReleaseManifestError("G12 deployment surface projection differs")
    if captured["pages"].get("deployment_commit") != integration_commit:
        raise ReleaseManifestError("G12 Pages deployment identity differs")

    recheck = _mapping(manifest.get("recheck"), "G12 recheck")
    if set(recheck) != {"observed_at", "surfaces"}:
        raise ReleaseManifestError("G12 recheck schema is not exact")
    _, recheck_time = _parse_timestamp(recheck.get("observed_at"), "G12 recheck time")
    if not (
        recheck_time - capture_time >= _MIN_RECHECK_INTERVAL
        and recheck_time <= generated_time
    ):
        raise ReleaseManifestError("G12 recheck chronology differs")
    recheck_rows = _mapping(recheck.get("surfaces"), "G12 recheck surfaces")
    if set(recheck_rows) != set(RECEIPT_PATHS):
        raise ReleaseManifestError("G12 recheck surface inventory differs")
    recheck_documents: dict[str, Mapping[str, object]] = {}
    for surface, raw_row in recheck_rows.items():
        row = _mapping(raw_row, f"G12 recheck {surface}")
        if set(row) != {
            "normalized_observation_sha256",
            "normalized_observation",
            "projection_sha256",
        }:
            raise ReleaseManifestError("G12 recheck surface schema is not exact")
        normalized = row.get("normalized_observation")
        if row.get("normalized_observation_sha256") != hashlib.sha256(
            _canonical_json(normalized)
        ).hexdigest():
            raise ReleaseManifestError(
                f"G12 recheck {surface} normalized observation digest differs"
            )
        _hash32(
            row.get("projection_sha256"),
            f"G12 recheck {surface} projection SHA-256",
        )
        recheck_documents[surface] = {
            "observed_at": recheck["observed_at"],
            "normalized_observation": normalized,
        }
    recheck_snapshot = _snapshot_from_observation_receipts(recheck_documents)
    recheck_projections, recheck_tarball = _project_snapshot(
        root,
        recheck_snapshot,
        now=recheck_time,
        canaries=canaries,
        integration_commit=integration_commit,
        normalized_replay=True,
    )
    for surface, projection in recheck_projections.items():
        if recheck_rows[surface].get("projection_sha256") != hashlib.sha256(
            _canonical_json(projection)
        ).hexdigest():
            raise ReleaseManifestError(
                f"G12 recheck {surface} projection replay differs"
            )
    if hashlib.sha256(recheck_tarball).hexdigest() != npm_capture.sha256:
        raise ReleaseManifestError("G12 recheck npm tarball replay differs")
    _compare_recheck(
        captured,
        recheck_projections,
        capture_time=capture_time,
        recheck_time=recheck_time,
    )
    _assert_safe_projection(manifest, canaries, "G12 release manifest")
    return {
        "capture_time": _format_now(capture_time),
        "frozen_commit": frozen_commit,
        "generated_at": _format_now(generated_time),
        "integration_commit": integration_commit,
        "status": "verified_offline",
    }


def _repository_release_lock(root: Path) -> int:
    try:
        common_raw = _git(
            root,
            ["rev-parse", "--git-common-dir"],
            limit=_CONTROL_LIMIT,
        ).stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise ReleaseManifestError("Git common directory is malformed") from exc
    common = Path(common_raw)
    if not common.is_absolute():
        common = root / common
    common = common.resolve(strict=True)
    lock_path = common / "concordia-release-manifest.lock"
    try:
        descriptor = os.open(
            lock_path,
            os.O_RDWR
            | os.O_CREAT
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
        ):
            raise ReleaseManifestError("repository release lock is unsafe")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ReleaseManifestError(
                "another release operation holds the repository lock"
            ) from exc
        return descriptor
    except BaseException:
        if "descriptor" in locals():
            os.close(descriptor)
        raise


def _assemble_release_manifest_locked(root: Path) -> Path:
    """Reverify, reobserve, and atomically create the fixed ready manifest."""

    _require_repository(root)
    _recover_capture_publication(root)
    if (root / RELEASE_MANIFEST_PATH).exists() or (
        root / RELEASE_MANIFEST_PATH
    ).is_symlink():
        raise ReleaseManifestError("release manifest already exists")
    _require_clean_worktree(root)
    now = _utc_now()
    canaries = _load_secret_canaries()
    (
        command_gate_bindings,
        _,
        command_gate_bounds,
        frozen_commit,
        integration_commit,
    ) = _load_command_gate_receipts(
        root,
        canaries,
        require_current_tree=True,
    )
    _, host_toolchain_bound, host_toolchain_projection = _host_toolchain_binding(root)
    post_freeze_corrections, post_freeze_bounds = _post_freeze_corrections_projection(
        root,
        integration_commit=integration_commit,
    )
    g1_freeze = _g1_freeze_contract_projection(root)
    if g1_freeze.get("peeled_commit") != frozen_commit:
        raise ReleaseManifestError("command gates and G1 authority differ")
    artifacts = _load_artifacts(root)
    verifier = _proof_verifier_factory(root)
    current_tool_commit = _verifier_tool_commit(root)
    current_tool_tree = _verifier_source_tree_sha256(root, current_tool_commit)
    current_command_environment = _command_environment_sha256()

    captured: dict[str, Mapping[str, Any]] = {}
    observation_documents: dict[str, Mapping[str, object]] = {}
    receipt_bindings: list[dict[str, object]] = []
    receipt_bounds: list[_BoundFile] = [
        host_toolchain_bound,
        *post_freeze_bounds,
    ]
    capture_times: set[datetime] = set()
    for receipt_id, path in RECEIPT_PATHS.items():
        bound, document = _load_receipt(
            root,
            path,
            schema=OBSERVATION_SCHEMA_VERSION,
            receipt_id=receipt_id,
            canaries=canaries,
        )
        if document["producer_tool_commit"] != current_tool_commit:
            raise ReleaseManifestError("observation receipt tool commit is stale")
        if document["command_environment_sha256"] != current_command_environment:
            raise ReleaseManifestError("observation command environment drifted")
        observed_at, capture_time = _parse_timestamp(
            document["observed_at"], f"{receipt_id} captured_at"
        )
        if now - capture_time > _RECEIPT_MAX_AGE or capture_time > now:
            raise ReleaseManifestError("committed observation receipt is stale")
        capture_times.add(capture_time)
        captured[receipt_id] = document["projection"]
        observation_documents[receipt_id] = document
        receipt_bounds.append(bound)
        receipt_bindings.append(
            {
                "receipt_id": receipt_id,
                "path": path,
                "sha256": bound.sha256,
                "artifact_commit": bound.artifact_commit,
                "observed_at": observed_at,
                "projection_sha256": document["projection_sha256"],
            }
        )
    if len(capture_times) != 1:
        raise ReleaseManifestError("observation receipts are not from one capture")
    capture_time = next(iter(capture_times))
    replayed, replayed_tarball = _replay_observation_receipts(
        root,
        observation_documents,
        integration_commit=integration_commit,
        canaries=canaries,
    )
    if replayed != captured:
        raise ReleaseManifestError("normalized observation replay inventory differs")

    _validate_payment_artifact_runtime_binding(
        artifacts,
        _mapping(captured.get("runtime"), "captured runtime"),
    )
    proof_bindings: list[dict[str, object]] = []
    for artifact_id, artifact in artifacts.items():
        bound, document = _load_receipt(
            root,
            PROOF_RECEIPT_PATHS[artifact_id],
            schema=PROOF_RECEIPT_SCHEMA_VERSION,
            receipt_id=artifact_id,
            canaries=canaries,
        )
        if document["verifier_tool_commit"] != current_tool_commit:
            raise ReleaseManifestError("proof verifier receipt tool commit is stale")
        if document["verifier_source_tree_sha256"] != current_tool_tree:
            raise ReleaseManifestError("proof verifier source tree receipt is stale")
        if document["command_environment_sha256"] != current_command_environment:
            raise ReleaseManifestError("proof verifier command environment drifted")
        proof_observed_at, proof_time = _parse_timestamp(
            document["observed_at"], f"{artifact_id} proof observed_at"
        )
        if proof_time != capture_time:
            raise ReleaseManifestError(
                f"{artifact_id} proof observed_at differs from observation capture"
            )
        expected = _proof_projection(verifier, artifact)
        if document["projection"] != expected:
            raise ReleaseManifestError(
                f"{artifact_id} verifier receipt differs from regenerated proof"
            )
        receipt_bounds.append(bound)
        proof_bindings.append(
            {
                "proof_id": artifact_id,
                "path": PROOF_RECEIPT_PATHS[artifact_id],
                "sha256": bound.sha256,
                "artifact_commit": bound.artifact_commit,
                "observed_at": proof_observed_at,
                "projection_sha256": document["projection_sha256"],
            }
        )

    npm_capture = _load_immutable_bound_file(root, NPM_CAPTURE_PATH, _NPM_LIMIT)
    if (
        npm_capture.sha256 != captured["npm"].get("tarball_sha256")
        or hashlib.sha256(replayed_tarball).hexdigest() != npm_capture.sha256
    ):
        raise ReleaseManifestError("committed npm tarball differs from capture receipt")
    receipt_bounds.append(npm_capture)
    organizer_bound, organizer_projection = _organizer_link_audit_binding(
        root,
        path=ORGANIZER_G12_AUDIT_PATH,
        phase="G12",
        canaries=canaries,
    )
    receipt_bounds.append(organizer_bound)

    recheck_snapshot = _collector_factory(root).collect()
    final_now = _utc_now()
    rechecked, rechecked_tarball = _project_snapshot(
        root,
        recheck_snapshot,
        now=final_now,
        canaries=canaries,
        integration_commit=integration_commit,
    )
    _, recheck_time = _parse_timestamp(
        recheck_snapshot.observed_at, "release recheck observed_at"
    )
    if hashlib.sha256(rechecked_tarball).hexdigest() != npm_capture.sha256:
        raise ReleaseManifestError("npm tarball bytes changed during release recheck")
    if final_now - capture_time > _RECEIPT_MAX_AGE or capture_time > final_now:
        raise ReleaseManifestError("committed observation receipt is stale")
    _, organizer_time = _parse_timestamp(
        organizer_projection.get("captured_at"),
        "G12 organizer rendered-link capture",
    )
    if not capture_time <= organizer_time <= final_now:
        raise ReleaseManifestError(
            "G12 organizer rendered-link chronology differs"
        )
    _compare_recheck(
        captured,
        rechecked,
        capture_time=capture_time,
        recheck_time=recheck_time,
    )
    receipt_bounds.extend(command_gate_bounds)
    if (
        captured["pages"].get("deployment_commit") != integration_commit
        or rechecked["pages"].get("deployment_commit") != integration_commit
    ):
        raise ReleaseManifestError(
            "public deployment does not match the command-gated integration commit"
        )
    recheck_raw_surfaces = _raw_snapshot_surfaces(root, recheck_snapshot)
    if set(recheck_raw_surfaces) != set(rechecked):
        raise ReleaseManifestError("release recheck raw inventory differs")
    recheck_secret_digests = _load_secret_variant_digests()
    recheck_surfaces: dict[str, dict[str, object]] = {}
    for name, projection in sorted(rechecked.items()):
        normalized = _encode_normalized_observation(
            recheck_raw_surfaces[name],
            secret_digests=recheck_secret_digests,
        )
        recheck_surfaces[name] = {
            "normalized_observation_sha256": hashlib.sha256(
                _canonical_json(normalized)
            ).hexdigest(),
            "normalized_observation": normalized,
            "projection_sha256": hashlib.sha256(
                _canonical_json(projection)
            ).hexdigest(),
        }

    artifact_entries = [
        {
            "artifact_id": artifact.artifact_id,
            "path": artifact.bound.path,
            "sha256": artifact.bound.sha256,
            "artifact_commit": artifact.bound.artifact_commit,
            "schema_version": artifact.schema_version,
            "captured_at": artifact.captured_at,
            "source_commit": artifact.source_commit,
            "deployment_commit": artifact.deployment_commit,
            "observation_mode": artifact.observation_mode,
        }
        for artifact in sorted(artifacts.values(), key=lambda item: item.artifact_id)
    ]
    generated_at = _format_now(final_now)
    gate_evidence = _gate_evidence_map(
        command_gates=command_gate_bindings,
        observations=receipt_bindings,
        proofs=proof_bindings,
        npm_capture=npm_capture,
        organizer_audit=organizer_projection,
    )
    command_gate_replays = [
        {
            "gate_id": gate_id,
            "status": "verified",
            "replay_contract_sha256": binding["replay_contract_sha256"],
        }
        for gate_id, binding in command_gate_bindings.items()
    ]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "status": "g12_ready",
        "overall_status": "pending_external",
        "completion_scope": "G2-G12",
        "frozen_commit": frozen_commit,
        "integration_commit": integration_commit,
        "g1_freeze": g1_freeze,
        "host_toolchain": host_toolchain_projection,
        "post_freeze_corrections": post_freeze_corrections,
        "generated_at": generated_at,
        "gate_evidence": gate_evidence,
        "command_gate_replays": command_gate_replays,
        "observation_receipts": sorted(
            receipt_bindings, key=lambda item: item["receipt_id"]
        ),
        "proof_verifier_receipts": sorted(
            proof_bindings, key=lambda item: item["proof_id"]
        ),
        "npm_tarball_capture": {
            "path": NPM_CAPTURE_PATH,
            "sha256": npm_capture.sha256,
            "artifact_commit": npm_capture.artifact_commit,
        },
        "organizer_rendered_link_audit": organizer_projection,
        "recheck": {
            "observed_at": recheck_snapshot.observed_at,
            "surfaces": recheck_surfaces,
        },
        "artifacts": artifact_entries,
        "services": captured["runtime"]["containers"],
        "deployment_surfaces": {
            "caddy_semantic_sha256": captured["caddy"]["semantic_sha256"],
            "compose_semantic_sha256": captured["compose"]["semantic_sha256"],
            "pages": captured["pages"],
            "npm": captured["npm"],
            "rpc": captured["rpc"],
            "public_probes": captured["public_probes"],
        },
    }
    _validate_g12_manifest_offline(
        root,
        manifest,
        canaries=canaries,
    )
    _assert_safe_projection(manifest, canaries, "release manifest")
    payload = _canonical_json(manifest)

    for artifact in artifacts.values():
        _assert_unchanged(root, artifact.bound, _ARTIFACT_LIMIT)
    for bound in receipt_bounds:
        _assert_unchanged(
            root,
            bound,
            _NPM_LIMIT if bound.path == NPM_CAPTURE_PATH else _CONTROL_LIMIT,
        )
    _require_clean_worktree(root)
    return _atomic_create_once(root, RELEASE_MANIFEST_PATH, payload)


def assemble_release_manifest_once(repository_root: str | Path) -> Path:
    """Serialize final validation and immutable G12 manifest creation."""

    root = Path(repository_root).absolute()
    _require_repository(root)
    lock_descriptor = _repository_release_lock(root)
    try:
        return _assemble_release_manifest_locked(root)
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)


def prepare_host_toolchain_receipt_once(repository_root: str | Path) -> Path:
    """Serialize host-toolchain authority candidate creation."""

    root = Path(repository_root).absolute()
    _require_repository(root)
    lock_descriptor = _repository_release_lock(root)
    try:
        return _prepare_host_toolchain_receipt_locked(root)
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)


def _capture_organizer_link_audit_locked(
    repository_root: str | Path,
    *,
    phase: str,
) -> tuple[Path, Path]:
    """Run the bound no-fixture browser collector and publish its receipt."""

    if phase not in {"G12", "G13"}:
        raise ReleaseManifestError("organizer audit phase is invalid")
    root = Path(repository_root).absolute()
    _require_repository(root)
    _recover_capture_publication(root)
    _require_clean_worktree(root)
    audit_path = (
        ORGANIZER_G12_AUDIT_PATH
        if phase == "G12"
        else ORGANIZER_G13_AUDIT_PATH
    )
    invocation_path = (
        ORGANIZER_G12_INVOCATION_PATH
        if phase == "G12"
        else ORGANIZER_G13_INVOCATION_PATH
    )
    _preflight_outputs_absent(root, (audit_path, invocation_path))
    canaries = _load_secret_canaries()
    request = _load_bound_file(
        root,
        ORGANIZER_LINK_REQUEST_PATH,
        _CONTROL_LIMIT,
    )
    core = _load_bound_file(
        root,
        ORGANIZER_LINK_CORE_PATH,
        _CONTROL_LIMIT,
    )
    runner = _load_bound_file(
        root,
        ORGANIZER_LINK_RUNNER_PATH,
        _CONTROL_LIMIT,
    )
    source_rows = [
        {"path": core.path, "sha256": core.sha256},
        {"path": runner.path, "sha256": runner.sha256},
    ]
    _, host_toolchain_bound, _ = _host_toolchain_binding(root)
    host_toolchain_row = {
        "path": host_toolchain_bound.path,
        "sha256": host_toolchain_bound.sha256,
        "artifact_commit": host_toolchain_bound.artifact_commit,
    }
    logical_argv = [
        "node",
        ORGANIZER_LINK_RUNNER_PATH,
        "--input",
        ORGANIZER_LINK_REQUEST_PATH,
    ]

    with tempfile.TemporaryDirectory(
        prefix=f"concordia-organizer-{phase.lower()}-"
    ) as name:
        temporary = Path(name)
        package_root = temporary / "command-package"
        entrypoint = _materialize_organizer_collector_package(
            root,
            package_root,
        )
        started_at = (
            _utc_now()
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
        result = _run(
            root,
            [
                "node",
                str(entrypoint),
                "--input",
                str(root / ORGANIZER_LINK_REQUEST_PATH),
            ],
            limit=_VERIFIER_ARCHIVE_LIMIT,
            timeout=180,
            repository_root=root,
            command_asset_root=package_root,
            bound_data_inputs=(root / ORGANIZER_LINK_REQUEST_PATH,),
        )
        ended_at = (
            _utc_now()
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
        if result.stderr != b"":
            raise ReleaseManifestError(
                f"{phase} organizer collector emitted stderr"
            )
        audit_raw = result.stdout
        document, canonical = _strict_json(
            audit_raw,
            f"{phase} organizer rendered-link audit",
        )
        if audit_raw != canonical:
            raise ReleaseManifestError(
                f"{phase} organizer collector output is not canonical JSON"
            )
        _validate_organizer_link_audit_document(document, phase=phase)
        _assert_no_canary(
            audit_raw,
            canaries,
            f"{phase} organizer collector output",
        )
        _assert_safe_projection(
            document,
            canaries,
            f"{phase} organizer collector output",
        )

        temporary_audit = _atomic_create_once(
            temporary,
            "audit.json",
            audit_raw,
        )
        verifier = package_root / ORGANIZER_LINK_VERIFIER_PATH
        verified = _run(
            root,
            ["node", str(verifier), str(temporary_audit)],
            limit=_CONTROL_LIMIT,
            timeout=60,
            repository_root=root,
            command_asset_root=package_root,
            bound_data_inputs=(temporary_audit,),
        )
        expected_verified = {
            "schema_version": ORGANIZER_LINK_AUDIT_SCHEMA_VERSION,
            "verdict": "PASS",
            "release_qualified": True,
            "collection_mode": "live_incognito",
            "audit_sha256": hashlib.sha256(audit_raw).hexdigest(),
        }
        verified_document, verified_canonical = _strict_json(
            verified.stdout,
            f"{phase} organizer verifier output",
        )
        if (
            verified.stderr != b""
            or verified.stdout != verified_canonical
            or verified_document != expected_verified
        ):
            raise ReleaseManifestError(
                f"{phase} organizer collector failed offline verification"
            )

    invocation_document = {
        "schema_version": ORGANIZER_LINK_INVOCATION_SCHEMA_VERSION,
        "phase": phase,
        "status": "passed",
        "collection_mode": "live_incognito",
        "started_at": started_at,
        "ended_at": ended_at,
        "command": {
            "argv": logical_argv,
            "exit_code": result.returncode,
            "fixture_argument_present": False,
            "stdout_sha256": hashlib.sha256(audit_raw).hexdigest(),
            "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
            "tool_identity_sha256": hashlib.sha256(
                _canonical_json(dict(result.tool_identity))
            ).hexdigest(),
            "command_assets_sha256": hashlib.sha256(
                _canonical_json([dict(row) for row in result.command_assets])
            ).hexdigest(),
        },
        "request": {
            "path": request.path,
            "sha256": request.sha256,
        },
        "source_bindings": source_rows,
        "host_toolchain": host_toolchain_row,
        "audit": {
            "path": audit_path,
            "sha256": hashlib.sha256(audit_raw).hexdigest(),
        },
    }
    _validate_organizer_link_invocation_document(
        invocation_document,
        phase=phase,
        audit_path=audit_path,
        audit_sha256=hashlib.sha256(audit_raw).hexdigest(),
        audit_started_at=_text(
            document.get("started_at"),
            f"{phase} organizer audit start",
        ),
        audit_captured_at=_text(
            document.get("captured_at"),
            f"{phase} organizer audit capture",
        ),
        request_sha256=request.sha256,
        source_bindings=source_rows,
        host_toolchain=host_toolchain_row,
    )
    invocation_raw = _canonical_json(invocation_document)
    _assert_safe_projection(
        invocation_document,
        canaries,
        f"{phase} organizer invocation receipt",
    )
    _require_clean_worktree(root)
    published = _atomic_create_sibling_batch_once(
        root,
        {
            audit_path: audit_raw,
            invocation_path: invocation_raw,
        },
    )
    return published[0], published[1]


def capture_organizer_link_audit_once(
    repository_root: str | Path,
    *,
    phase: str,
) -> tuple[Path, Path]:
    """Serialize one authoritative G12 or G13 rendered-link capture."""

    root = Path(repository_root).absolute()
    _require_repository(root)
    lock_descriptor = _repository_release_lock(root)
    try:
        return _capture_organizer_link_audit_locked(root, phase=phase)
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)


def capture_release_observations_once(
    repository_root: str | Path,
) -> tuple[Path, ...]:
    """Serialize observation, verification, recovery, and receipt publication."""

    root = Path(repository_root).absolute()
    _require_repository(root)
    lock_descriptor = _repository_release_lock(root)
    try:
        return _capture_release_observations_locked(root)
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)


def verify_command_gate_receipts(
    repository_root: str | Path,
) -> dict[str, object]:
    """Serialize receipt verification with interrupted-capture recovery."""

    root = Path(repository_root).absolute()
    _require_repository(root)
    lock_descriptor = _repository_release_lock(root)
    try:
        return _verify_command_gate_receipts_locked(root)
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)


def _g13_support_file(
    root: Path,
    *,
    row: Mapping[str, object],
    label: str,
    expected_path: str,
    receipt_commit: str,
    limit: int,
    canaries: Sequence[bytes],
) -> _BoundFile:
    if set(row) != {"path", "sha256"}:
        raise ReleaseManifestError(f"{label} binding schema is not exact")
    relative = _text(row.get("path"), f"{label} path")
    _validate_relative_path(relative)
    if relative != expected_path:
        raise ReleaseManifestError(f"{label} path differs")
    bound = _load_immutable_bound_file(
        root,
        relative,
        limit,
        artifact_commit=receipt_commit,
    )
    if bound.sha256 != _hash32(row.get("sha256"), f"{label} SHA-256"):
        raise ReleaseManifestError(f"{label} digest differs")
    if bound.artifact_commit != receipt_commit:
        raise ReleaseManifestError(
            f"{label} and G13 receipt are not from the same commit"
        )
    _assert_no_canary(bound.raw, canaries, label)
    return bound


def _assert_png_evidence(raw: bytes, label: str) -> None:
    """Fully decode bounded screenshots and reject malformed or blank evidence."""

    signature = b"\x89PNG\r\n\x1a\n"
    if not raw.startswith(signature):
        raise ReleaseManifestError(f"{label} is not a PNG")

    offset = len(signature)
    chunk_index = 0
    saw_idat = False
    saw_iend = False
    width = height = bit_depth = color_type = interlace = -1
    idat_parts: list[bytes] = []
    palette: bytes | None = None
    while offset < len(raw):
        if chunk_index >= 10_000:
            raise ReleaseManifestError(f"{label} has too many PNG chunks")
        if len(raw) - offset < 12:
            raise ReleaseManifestError(f"{label} has a truncated PNG chunk")
        length = int.from_bytes(raw[offset : offset + 4], "big")
        chunk_type = raw[offset + 4 : offset + 8]
        chunk_end = offset + 12 + length
        if re.fullmatch(rb"[A-Za-z]{4}", chunk_type) is None or chunk_end > len(raw):
            raise ReleaseManifestError(f"{label} has a malformed PNG chunk")
        chunk_data = raw[offset + 8 : offset + 8 + length]
        expected_crc = int.from_bytes(raw[offset + 8 + length : chunk_end], "big")
        actual_crc = binascii.crc32(chunk_type + chunk_data) & 0xFFFF_FFFF
        if actual_crc != expected_crc:
            raise ReleaseManifestError(f"{label} has an invalid PNG CRC")

        if chunk_index == 0:
            if chunk_type != b"IHDR" or length != 13:
                raise ReleaseManifestError(f"{label} has no valid PNG IHDR")
            width = int.from_bytes(chunk_data[0:4], "big")
            height = int.from_bytes(chunk_data[4:8], "big")
            bit_depth, color_type, compression, filtering, interlace = chunk_data[8:]
            valid_depths = {
                0: {1, 2, 4, 8, 16},
                2: {8, 16},
                3: {1, 2, 4, 8},
                4: {8, 16},
                6: {8, 16},
            }
            if (
                width < 640
                or height < 360
                or width > 16_384
                or height > 16_384
                or bit_depth not in valid_depths.get(color_type, set())
                or compression != 0
                or filtering != 0
                or interlace not in {0, 1}
            ):
                raise ReleaseManifestError(f"{label} has invalid PNG image metadata")
        elif chunk_type == b"IHDR":
            raise ReleaseManifestError(f"{label} has duplicate PNG IHDR chunks")

        if chunk_type == b"PLTE":
            if saw_idat:
                raise ReleaseManifestError(f"{label} has a late PNG palette")
            if not chunk_data or len(chunk_data) % 3 or len(chunk_data) > 768:
                raise ReleaseManifestError(f"{label} has an invalid PNG palette")
            palette = chunk_data

        if chunk_type == b"tRNS":
            raise ReleaseManifestError(f"{label} uses unsupported PNG transparency")

        if chunk_type == b"IDAT":
            if length == 0:
                raise ReleaseManifestError(f"{label} has an empty PNG IDAT chunk")
            saw_idat = True
            idat_parts.append(chunk_data)
        if chunk_type == b"IEND":
            if length != 0 or chunk_end != len(raw):
                raise ReleaseManifestError(f"{label} has an invalid PNG IEND chunk")
            saw_iend = True

        offset = chunk_end
        chunk_index += 1

    if not saw_idat or not saw_iend:
        raise ReleaseManifestError(f"{label} has incomplete PNG image data")
    if interlace != 0 or bit_depth != 8 or color_type not in {0, 2, 3, 4, 6}:
        raise ReleaseManifestError(f"{label} uses an unsupported PNG pixel encoding")
    if width * height > 16_000_000:
        raise ReleaseManifestError(f"{label} PNG decoded image is oversized")
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color_type]
    row_size = width * channels
    expected_size = height * (row_size + 1)
    decompressor = zlib.decompressobj()
    try:
        decoded = decompressor.decompress(b"".join(idat_parts), expected_size + 1)
    except zlib.error as exc:
        raise ReleaseManifestError(f"{label} PNG image data is corrupt") from exc
    if (
        len(decoded) != expected_size
        or not decompressor.eof
        or decompressor.unused_data
        or decompressor.unconsumed_tail
    ):
        raise ReleaseManifestError(f"{label} PNG decoded length differs")

    rows: list[bytearray] = []
    position = 0
    for _ in range(height):
        filter_type = decoded[position]
        position += 1
        filtered = decoded[position : position + row_size]
        position += row_size
        previous = rows[-1] if rows else bytearray(row_size)
        reconstructed = bytearray(row_size)
        for index, value in enumerate(filtered):
            left = reconstructed[index - channels] if index >= channels else 0
            above = previous[index]
            upper_left = previous[index - channels] if index >= channels else 0
            if filter_type == 0:
                predictor = 0
            elif filter_type == 1:
                predictor = left
            elif filter_type == 2:
                predictor = above
            elif filter_type == 3:
                predictor = (left + above) // 2
            elif filter_type == 4:
                estimate = left + above - upper_left
                distance_left = abs(estimate - left)
                distance_above = abs(estimate - above)
                distance_upper_left = abs(estimate - upper_left)
                predictor = (
                    left
                    if distance_left <= distance_above
                    and distance_left <= distance_upper_left
                    else above
                    if distance_above <= distance_upper_left
                    else upper_left
                )
            else:
                raise ReleaseManifestError(f"{label} has an invalid PNG row filter")
            reconstructed[index] = (value + predictor) & 0xFF
        rows.append(reconstructed)

    sample_stride = max(1, (width * height) // 20_000)
    colors: set[tuple[int, int, int, int]] = set()
    minima = [255, 255, 255]
    maxima = [0, 0, 0]
    opaque_samples = 0
    sample_index = 0
    for row in rows:
        for offset in range(0, row_size, channels):
            if sample_index % sample_stride:
                sample_index += 1
                continue
            sample_index += 1
            if color_type == 0:
                red = green = blue = row[offset]
                alpha = 255
            elif color_type == 2:
                red, green, blue = row[offset : offset + 3]
                alpha = 255
            elif color_type == 3:
                palette_index = row[offset]
                if palette is None or palette_index * 3 + 2 >= len(palette):
                    raise ReleaseManifestError(
                        f"{label} has an invalid PNG palette index"
                    )
                red, green, blue = palette[palette_index * 3 : palette_index * 3 + 3]
                alpha = 255
            elif color_type == 4:
                red = green = blue = row[offset]
                alpha = row[offset + 1]
            else:
                red, green, blue, alpha = row[offset : offset + 4]
            if alpha:
                opaque_samples += 1
            composite = tuple(
                ((channel * alpha) + (255 * (255 - alpha))) // 255
                for channel in (red, green, blue)
            )
            for channel_index, channel in enumerate(composite):
                minima[channel_index] = min(minima[channel_index], channel)
                maxima[channel_index] = max(maxima[channel_index], channel)
            colors.add((*composite, alpha))
            if len(colors) > 4_096:
                colors.pop()
    if (
        opaque_samples == 0
        or len(colors) < 8
        or max(
            maximum - minimum for minimum, maximum in zip(minima, maxima, strict=True)
        )
        < 12
    ):
        raise ReleaseManifestError(
            f"{label} is blank or lacks meaningful visual variation"
        )


def _expected_g13_browser_events(
    *,
    captured_at: str,
    video_id: str,
    youtube_capture_sha256: str,
    dorahacks_capture_sha256: str,
) -> list[dict[str, object]]:
    _parse_timestamp(captured_at, "G13 browser trace captured_at")
    if re.fullmatch(r"[A-Za-z0-9_-]{11}", video_id) is None:
        raise ReleaseManifestError("G13 browser trace video ID is invalid")
    youtube_capture_sha256 = _hash32(
        youtube_capture_sha256, "G13 browser YouTube capture SHA-256"
    )
    dorahacks_capture_sha256 = _hash32(
        dorahacks_capture_sha256, "G13 browser DoraHacks capture SHA-256"
    )
    youtube_url = f"https://www.youtube.com/watch?v={video_id}"
    dorahacks_url = "https://dorahacks.io/buidl/46732"
    return [
        {
            "sequence": 1,
            "kind": "navigation",
            "target": "youtube",
            "url": youtube_url,
            "status": 200,
        },
        {
            "sequence": 2,
            "kind": "semantic_assertion",
            "target": "youtube",
            "assertion": "playback_state",
            "observed": "playing_or_ended",
        },
        {
            "sequence": 3,
            "kind": "semantic_assertion",
            "target": "youtube",
            "assertion": "captions_visible",
            "observed": True,
        },
        {
            "sequence": 4,
            "kind": "screenshot",
            "target": "youtube",
            "path": "release/g13/YOUTUBE_INCOGNITO.png",
            "sha256": youtube_capture_sha256,
        },
        {
            "sequence": 5,
            "kind": "navigation",
            "target": "dorahacks",
            "url": dorahacks_url,
            "status": 200,
        },
        {
            "sequence": 6,
            "kind": "semantic_assertion",
            "target": "dorahacks",
            "assertion": "edit_state",
            "observed": "saved",
        },
        {
            "sequence": 7,
            "kind": "semantic_assertion",
            "target": "dorahacks",
            "assertion": "embedded_video_id",
            "observed": video_id,
        },
        {
            "sequence": 8,
            "kind": "screenshot",
            "target": "dorahacks",
            "path": "release/g13/DORAHACKS_SUBMISSION.png",
            "sha256": dorahacks_capture_sha256,
        },
    ]


def _g13_browser_request(
    *,
    video_id: str,
    links: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    required = (
        "dashboard_judge",
        "dashboard_proof",
        "dashboard_evidence",
        "dashboard_technical_note",
        "youtube_new_video",
        "dorahacks_buidl_46732",
    )
    if any(link_id not in links for link_id in required):
        raise ReleaseManifestError("G13 browser request lacks a required final route")
    return {
        "schema_version": "concordia.g13_browser_probe_request.v1",
        "video_id": video_id,
        "routes": [
            {
                "link_id": link_id,
                "url": _text(links[link_id].get("url"), f"G13 {link_id} URL"),
            }
            for link_id in required
        ],
    }


def _validate_g13_safe_url(value: object, label: str) -> dict[str, object]:
    row = _mapping(value, label)
    if set(row) != {"origin_path", "query_keys", "raw_sha256"}:
        raise ReleaseManifestError(f"{label} schema is not exact")
    origin_path = _text(row.get("origin_path"), f"{label} origin path")
    parsed = urlsplit(origin_path)
    allowed_hosts = {
        *(urlsplit(url).hostname for url in PUBLIC_URLS.values()),
        "www.youtube.com",
        "dorahacks.io",
    }
    if (
        parsed.scheme != "https"
        or parsed.hostname not in allowed_hosts
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ReleaseManifestError(f"{label} escaped the HTTPS allowlist")
    query_keys = _sequence(row.get("query_keys"), f"{label} query keys")
    if (
        any(type(item) is not str or not item for item in query_keys)
        or list(query_keys) != sorted(set(query_keys))
    ):
        raise ReleaseManifestError(f"{label} query-key inventory differs")
    raw_sha256 = _hash32(row.get("raw_sha256"), f"{label} raw SHA-256")
    return {
        "origin_path": origin_path,
        "query_keys": list(query_keys),
        "raw_sha256": raw_sha256,
    }


def _validate_g13_network_url(value: object, label: str) -> dict[str, object]:
    """Validate a sanitized HTTPS subresource without trusting its vendor host."""

    row = _mapping(value, label)
    if set(row) != {"origin_path", "query_keys", "raw_sha256"}:
        raise ReleaseManifestError(f"{label} schema is not exact")
    origin_path = _text(row.get("origin_path"), f"{label} origin path")
    if len(origin_path) > 4096 or any(ord(character) < 0x20 for character in origin_path):
        raise ReleaseManifestError(f"{label} origin path is unsafe")
    parsed = urlsplit(origin_path)
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or hostname is None
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.port not in {None, 443}
        or not parsed.path.startswith("/")
        or len(hostname) > 253
        or hostname.lower() in {"localhost", "localhost.localdomain"}
    ):
        raise ReleaseManifestError(f"{label} is not a public HTTPS subresource")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        labels = hostname.rstrip(".").split(".")
        if (
            len(labels) < 2
            or any(
                not part
                or len(part) > 63
                or part.startswith("-")
                or part.endswith("-")
                or re.fullmatch(r"[A-Za-z0-9-]+", part) is None
                for part in labels
            )
        ):
            raise ReleaseManifestError(f"{label} hostname is malformed")
    else:
        if not address.is_global:
            raise ReleaseManifestError(f"{label} points to a non-public address")
    query_keys = _sequence(row.get("query_keys"), f"{label} query keys")
    if (
        any(
            type(item) is not str
            or not item
            or len(item) > 128
            or re.fullmatch(r"[A-Za-z0-9_.~:-]+", item) is None
            for item in query_keys
        )
        or len(query_keys) > 128
        or list(query_keys) != sorted(set(query_keys))
    ):
        raise ReleaseManifestError(f"{label} query-key inventory differs")
    return {
        "origin_path_sha256": hashlib.sha256(
            origin_path.encode("utf-8")
        ).hexdigest(),
        "query_keys": list(query_keys),
        "raw_sha256": _hash32(row.get("raw_sha256"), f"{label} raw SHA-256"),
    }


def _validate_g13_dom(value: object, *, link_id: str) -> dict[str, object]:
    dom = _mapping(value, f"G13 {link_id} DOM")
    if set(dom) != {
        "document_url",
        "title",
        "language",
        "html_bytes",
        "html_sha256",
        "visible_text_chars",
        "visible_text_sha256",
        "concordia_occurrences",
        "canonical_proposal_occurrences",
        "headings",
        "landmarks",
        "links",
        "frames",
        "test_ids",
        "error_overlays",
    }:
        raise ReleaseManifestError("G13 raw DOM schema is not exact")
    document_url = _validate_g13_safe_url(
        dom.get("document_url"),
        f"G13 {link_id} DOM URL",
    )
    for field in (
        "html_bytes",
        "visible_text_chars",
        "concordia_occurrences",
        "canonical_proposal_occurrences",
        "error_overlays",
    ):
        if type(dom.get(field)) is not int or int(dom[field]) < 0:
            raise ReleaseManifestError("G13 raw DOM count is invalid")
    if dom["html_bytes"] <= 0 or dom["visible_text_chars"] <= 0:
        raise ReleaseManifestError("G13 raw DOM content is empty")
    html_sha256 = _hash32(dom.get("html_sha256"), "G13 DOM HTML SHA-256")
    visible_sha256 = _hash32(
        dom.get("visible_text_sha256"),
        "G13 DOM visible-text SHA-256",
    )
    collections: dict[str, dict[str, object]] = {}
    for name in ("headings", "links", "frames", "test_ids"):
        collection = _mapping(dom.get(name), f"G13 DOM {name}")
        if set(collection) != {"count", "items", "items_sha256", "truncated"}:
            raise ReleaseManifestError("G13 raw DOM collection schema is not exact")
        count = collection.get("count")
        items = _sequence(collection.get("items"), f"G13 DOM {name} items")
        if (
            type(count) is not int
            or count < len(items)
            or type(collection.get("truncated")) is not bool
            or (count > len(items)) != collection["truncated"]
            or collection.get("items_sha256")
            != hashlib.sha256(
                json.dumps(items, separators=(",", ":"), ensure_ascii=False).encode(
                    "utf-8"
                )
            ).hexdigest()
        ):
            raise ReleaseManifestError("G13 raw DOM collection digest differs")
        collections[name] = {
            "count": count,
            "items_sha256": collection["items_sha256"],
            "truncated": collection["truncated"],
        }
    landmarks = _mapping(dom.get("landmarks"), "G13 DOM landmarks")
    if set(landmarks) != {"main", "navigation", "tablist"} or any(
        type(value) is not int or value < 0 for value in landmarks.values()
    ):
        raise ReleaseManifestError("G13 DOM landmark inventory differs")
    if link_id.startswith("dashboard_") and (
        dom["concordia_occurrences"] < 1
        or dom["error_overlays"] != 0
        or (landmarks["main"] < 1 and collections["headings"]["count"] < 1)
    ):
        raise ReleaseManifestError("G13 judge DOM does not prove a healthy page")
    route_marker = {
        "dashboard_judge": "judge",
        "dashboard_proof": "proof",
        "dashboard_evidence": "evidence",
        "dashboard_technical_note": "technical",
    }.get(link_id)
    if route_marker is not None:
        heading_items = _sequence(
            _mapping(dom.get("headings"), "G13 DOM headings").get("items"),
            "G13 DOM heading items",
        )
        if not any(
            route_marker in str(
                _mapping(item, "G13 DOM heading").get("text", "")
            ).lower()
            and _mapping(item, "G13 DOM heading").get("visible") is True
            for item in heading_items
        ):
            raise ReleaseManifestError(
                f"G13 {link_id} lacks its route-specific heading"
            )
    return {
        "document_url": document_url,
        "html_bytes": dom["html_bytes"],
        "html_sha256": html_sha256,
        "visible_text_chars": dom["visible_text_chars"],
        "visible_text_sha256": visible_sha256,
        "concordia_occurrences": dom["concordia_occurrences"],
        "canonical_proposal_occurrences": dom["canonical_proposal_occurrences"],
        "collections": collections,
        "landmarks": dict(landmarks),
        "error_overlays": dom["error_overlays"],
    }


def _validate_g13_network_events(
    value: object,
    *,
    link_id: str,
) -> list[Mapping[str, object]]:
    events = _sequence(value, f"G13 {link_id} network")
    if not events:
        raise ReleaseManifestError("G13 raw browser network trace is empty")
    observed: list[Mapping[str, object]] = []
    for index, raw_event in enumerate(events, start=1):
        event = _mapping(raw_event, f"G13 {link_id} network event")
        if event.get("sequence") != index:
            raise ReleaseManifestError("G13 network sequence differs")
        kind = event.get("event")
        common = {"sequence", "event", "request_id", "url"}
        if kind == "request":
            expected = common | {
                "method",
                "resource_type",
                "navigation_request",
            }
        elif kind == "response":
            expected = common | {"status", "service_worker", "headers"}
        elif kind == "request_failed":
            expected = common | {
                "method",
                "resource_type",
                "error_text",
            }
        else:
            raise ReleaseManifestError("G13 network event kind differs")
        if set(event) != expected:
            raise ReleaseManifestError("G13 network event schema is not exact")
        if type(event.get("request_id")) is not int or event["request_id"] < 0:
            raise ReleaseManifestError("G13 network request identity differs")
        _validate_g13_network_url(event.get("url"), f"G13 {link_id} network URL")
        if kind in {"request", "request_failed"} and (
            type(event.get("method")) is not str or not event["method"]
        ):
            raise ReleaseManifestError("G13 network method is malformed")
        if kind == "response" and (
            type(event.get("status")) is not int
            or not 100 <= event["status"] <= 599
            or type(event.get("service_worker")) is not bool
            or type(event.get("headers")) is not dict
        ):
            raise ReleaseManifestError("G13 network response facts differ")
        observed.append(event)
    return observed


def _validate_g13_browser_trace(value: object) -> dict[str, object]:
    trace = _mapping(value, "G13 raw browser trace")
    if set(trace) != {
        "schema_version",
        "started_at",
        "captured_at",
        "incognito_context",
        "mutation_guard",
        "runtime_versions",
        "routes",
    } or trace.get("schema_version") != "concordia.g13_browser_probe_result.v1":
        raise ReleaseManifestError("G13 raw browser trace schema is not exact")
    _, started = _parse_timestamp(trace.get("started_at"), "G13 browser trace start")
    _, captured = _parse_timestamp(
        trace.get("captured_at"), "G13 browser trace capture"
    )
    if captured < started:
        raise ReleaseManifestError("G13 raw browser trace chronology differs")
    if trace.get("incognito_context") != {
        "persistent_profile": False,
        "storage_state_loaded": False,
        "cookies_at_start": 0,
    }:
        raise ReleaseManifestError("G13 browser context is not fresh and incognito")
    mutation_guard = _mapping(trace.get("mutation_guard"), "G13 mutation guard")
    if (
        set(mutation_guard)
        != {"allowed_http_methods", "blocked_non_read_request_count"}
        or mutation_guard.get("allowed_http_methods") != ["GET", "HEAD", "OPTIONS"]
        or type(mutation_guard.get("blocked_non_read_request_count")) is not int
        or mutation_guard["blocked_non_read_request_count"] < 0
    ):
        raise ReleaseManifestError("G13 browser mutation guard differs")
    runtimes = _mapping(trace.get("runtime_versions"), "G13 browser runtimes")
    if set(runtimes) != {
        "chromium",
        "chromium_executable_sha256",
        "node",
        "playwright",
    }:
        raise ReleaseManifestError("G13 browser runtime inventory differs")
    _hash32(
        runtimes.get("chromium_executable_sha256"),
        "G13 Chromium executable SHA-256",
    )

    projection: dict[str, object] = {}
    blocked_total = 0
    for raw_route in _sequence(trace.get("routes"), "G13 browser routes"):
        route = _mapping(raw_route, "G13 browser route")
        if set(route) != {
            "link_id",
            "requested_url",
            "final_url",
            "main_response",
            "dom",
            "specialized",
            "network_events",
            "network_events_sha256",
            "blocked_non_read_requests",
            "console_errors",
            "page_errors",
        }:
            raise ReleaseManifestError("G13 browser route schema is not exact")
        link_id = _text(route.get("link_id"), "G13 browser link ID")
        if link_id in projection:
            raise ReleaseManifestError("G13 browser route is duplicated")
        requested_url = _validate_g13_safe_url(
            route.get("requested_url"),
            f"G13 {link_id} requested URL",
        )
        final_url = _validate_g13_safe_url(
            route.get("final_url"),
            f"G13 {link_id} final URL",
        )
        if final_url["origin_path"] != requested_url["origin_path"]:
            raise ReleaseManifestError(
                f"G13 {link_id} redirected away from its fixed route"
            )
        response = _mapping(route.get("main_response"), f"G13 {link_id} response")
        if set(response) != {
            "status",
            "headers",
            "body_bytes",
            "body_sha256",
        } or type(response.get("headers")) is not dict:
            raise ReleaseManifestError("G13 browser main-response schema differs")
        status = response.get("status")
        if (
            status != 200
            or type(response.get("body_bytes")) is not int
            or response["body_bytes"] <= 0
        ):
            raise ReleaseManifestError(
                "G13 browser trace main response is not successful"
            )
        _hash32(response.get("body_sha256"), f"G13 {link_id} body SHA-256")
        dom_projection = _validate_g13_dom(route.get("dom"), link_id=link_id)
        events = _validate_g13_network_events(
            route.get("network_events"),
            link_id=link_id,
        )
        if route.get("network_events_sha256") != hashlib.sha256(
            json.dumps(events, separators=(",", ":"), ensure_ascii=False).encode(
                "utf-8"
            )
        ).hexdigest():
            raise ReleaseManifestError("G13 raw browser network trace digest differs")
        blocked = _sequence(
            route.get("blocked_non_read_requests"),
            f"G13 {link_id} blocked requests",
        )
        for raw_blocked in blocked:
            item = _mapping(raw_blocked, f"G13 {link_id} blocked request")
            if (
                set(item) != {"method", "resource_type", "url"}
                or item.get("method") in {"GET", "HEAD", "OPTIONS"}
                or type(item.get("method")) is not str
                or type(item.get("resource_type")) is not str
            ):
                raise ReleaseManifestError("G13 blocked-request evidence differs")
            _validate_g13_network_url(
                item.get("url"),
                f"G13 {link_id} blocked-request URL",
            )
        blocked_total += len(blocked)
        non_read_network = [
            event
            for event in events
            if event.get("event") == "request"
            and event.get("method") not in {"GET", "HEAD", "OPTIONS"}
        ]
        blocked_keys = {
            (
                item.get("method"),
                _mapping(item.get("url"), "G13 blocked-request URL").get(
                    "raw_sha256"
                ),
            )
            for item in (
                _mapping(raw_item, f"G13 {link_id} blocked request")
                for raw_item in blocked
            )
        }
        if any(
            (
                event.get("method"),
                _mapping(event.get("url"), "G13 network URL").get("raw_sha256"),
            )
            not in blocked_keys
            for event in non_read_network
        ):
            raise ReleaseManifestError(
                "G13 browser allowed an unblocked mutation request"
            )
        if route.get("page_errors") != []:
            raise ReleaseManifestError("G13 browser route emitted a page error")
        console_errors = _sequence(
            route.get("console_errors"),
            f"G13 {link_id} console errors",
        )
        for raw_error in console_errors:
            error = _mapping(raw_error, "G13 console error")
            if set(error) != {"chars", "sha256"}:
                raise ReleaseManifestError("G13 console-error schema differs")
            _hash32(error.get("sha256"), "G13 console-error SHA-256")
        if link_id.startswith("dashboard_") and console_errors:
            raise ReleaseManifestError("G13 judge route emitted a console error")
        specialized = route.get("specialized")
        specialized_projection: object = None
        if link_id == "youtube_new_video":
            wrapper = _mapping(specialized, "G13 YouTube browser facts")
            if set(wrapper) != {"kind", "facts"}:
                raise ReleaseManifestError("G13 YouTube fact wrapper differs")
            facts = _mapping(wrapper.get("facts"), "G13 YouTube facts")
            if set(facts) != {
                "expected_video_id",
                "player_video_id",
                "current_time_seconds",
                "duration_seconds",
                "paused",
                "ended",
                "ready_state",
                "caption_button_aria_pressed",
                "visible_caption_segments",
                "text_tracks",
            }:
                raise ReleaseManifestError("G13 YouTube fact schema differs")
            if (
                wrapper.get("kind") != "youtube"
                or facts.get("expected_video_id") != facts.get("player_video_id")
                or type(facts.get("duration_seconds")) is not int
                or facts["duration_seconds"] <= 0
                or not (
                    facts.get("ended") is True
                    or (
                        facts.get("paused") is False
                        and type(facts.get("current_time_seconds")) in {int, float}
                        and facts["current_time_seconds"] > 0
                    )
                )
                or facts.get("caption_button_aria_pressed") != "true"
                or not any(
                    type(item) is str and item
                    for item in _sequence(
                        facts.get("visible_caption_segments"),
                        "G13 visible caption segments",
                    )
                )
            ):
                raise ReleaseManifestError(
                    "G13 browser did not prove YouTube playback and captions"
                )
            specialized_projection = {
                "kind": "youtube",
                "video_id": facts.get("expected_video_id"),
                "captions_visible": True,
                "duration_seconds": facts.get("duration_seconds"),
            }
        elif link_id == "dorahacks_buidl_46732":
            wrapper = _mapping(specialized, "G13 DoraHacks browser facts")
            if set(wrapper) != {"kind", "facts"}:
                raise ReleaseManifestError("G13 DoraHacks fact wrapper differs")
            facts = _mapping(wrapper.get("facts"), "G13 DoraHacks facts")
            if set(facts) != {
                "video_id",
                "html_occurrences",
                "matching_elements",
                "matching_elements_sha256",
                "canonical_href",
            }:
                raise ReleaseManifestError("G13 DoraHacks fact schema differs")
            matching = _sequence(
                facts.get("matching_elements"),
                "G13 DoraHacks matching elements",
            )
            if (
                wrapper.get("kind") != "dorahacks"
                or type(facts.get("html_occurrences")) is not int
                or facts["html_occurrences"] < 1
                or not matching
                or facts.get("matching_elements_sha256")
                != hashlib.sha256(
                    json.dumps(
                        matching,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ).encode("utf-8")
                ).hexdigest()
            ):
                raise ReleaseManifestError(
                    "G13 browser did not prove the DoraHacks video binding"
                )
            specialized_projection = {
                "kind": "dorahacks",
                "video_id": facts.get("video_id"),
                "embedded": True,
            }
        elif specialized is not None:
            raise ReleaseManifestError("G13 browser route has unexpected special facts")
        projection[link_id] = {
            "status": status,
            # Raw DOM, body, network, blocked-attempt, and console digests are
            # immutable evidence but intentionally excluded from the fresh
            # equality contract: public pages contain live timestamps, ads,
            # telemetry and request ordering.  The stable projection proves
            # the same fixed route and the same semantic success.
            "requested_origin_path": requested_url["origin_path"],
            "final_origin_path": final_url["origin_path"],
            "healthy_dom": bool(
                dom_projection["html_bytes"] > 0
                and dom_projection["visible_text_chars"] > 0
                and dom_projection["error_overlays"] == 0
            ),
            "unblocked_non_read_requests": 0,
            "specialized": specialized_projection,
        }
    required_ids = {
        "dashboard_judge",
        "dashboard_proof",
        "dashboard_evidence",
        "dashboard_technical_note",
        "youtube_new_video",
        "dorahacks_buidl_46732",
    }
    if set(projection) != required_ids:
        raise ReleaseManifestError("G13 raw browser route inventory differs")
    if blocked_total != mutation_guard["blocked_non_read_request_count"]:
        raise ReleaseManifestError("G13 blocked-request count differs")
    return {
        "runtime_versions": dict(runtimes),
        "routes": projection,
    }


def _materialize_g13_command_package(root: Path, target: Path) -> Path:
    """Create the smallest bound package needed by the G13 Node collector."""

    target.mkdir(mode=0o700)
    (target / "scripts").mkdir(mode=0o700)
    runtime_target = target / "scripts" / "g13-browser-runtime"
    runtime_target.mkdir(mode=0o700)
    shutil.copy2(root / G13_RUNNER_PATH, target / G13_RUNNER_PATH)
    runtime_inputs: list[Path] = []
    for name in ("package.json", "package-lock.json", "install-browser.mjs"):
        source = root / "scripts" / "g13-browser-runtime" / name
        destination = runtime_target / name
        shutil.copy2(source, destination)
        runtime_inputs.append(destination)
    _run(
        runtime_target,
        [
            "npm",
            "ci",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--registry=https://registry.npmjs.org/",
        ],
        limit=_CONTROL_LIMIT,
        timeout=180,
        repository_root=root,
        bound_data_inputs=tuple(runtime_inputs),
    )
    browser_download = target.parent / "browser-download"
    browser_download.mkdir(mode=0o700)
    _run(
        runtime_target,
        [
            "node",
            str(runtime_target / "install-browser.mjs"),
            str(browser_download),
        ],
        limit=_GIT_OUTPUT_LIMIT,
        timeout=180,
        repository_root=root,
        command_asset_root=runtime_target,
    )
    local_browsers = (
        runtime_target
        / "node_modules"
        / "playwright-core"
        / ".local-browsers"
    )
    if local_browsers.exists():
        raise ReleaseManifestError("G13 local browser destination already exists")
    shutil.copytree(browser_download, local_browsers, symlinks=False)
    binary_links = runtime_target / "node_modules" / ".bin"
    if binary_links.exists():
        shutil.rmtree(binary_links)
    for current_root, directory_names, file_names in os.walk(
        target,
        topdown=True,
        followlinks=False,
    ):
        current = Path(current_root)
        for name in [*directory_names, *file_names]:
            if (current / name).is_symlink():
                raise ReleaseManifestError(
                    "G13 materialized command package contains a symlink"
                )
    return target / G13_RUNNER_PATH


def _default_g13_browser_runner(
    root: Path,
    request: Mapping[str, object],
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="concordia-g13-browser-input-") as name:
        temporary = Path(name)
        request_path = temporary / "request.json"
        _atomic_create_once(temporary, "request.json", _canonical_json(request))
        package_root = temporary / "command-package"
        entrypoint = _materialize_g13_command_package(root, package_root)
        result = _run(
            root,
            ["node", str(entrypoint), "--input", str(request_path)],
            limit=_GIT_OUTPUT_LIMIT,
            timeout=180,
            repository_root=root,
            command_asset_root=package_root,
            bound_data_inputs=(request_path,),
        )
    document, canonical = _strict_json(result.stdout, "fresh G13 browser trace")
    if result.stdout != canonical:
        raise ReleaseManifestError("fresh G13 browser trace is not canonical JSON")
    return document


def _g13_browser_runner_factory(
    _root: Path,
) -> object:
    return _default_g13_browser_runner


def _default_g13_link_reprobe(
    _root: Path,
    links: Mapping[str, Mapping[str, object]],
) -> dict[str, dict[str, object]]:
    allowed_hosts = {
        *(urlsplit(url).hostname for url in PUBLIC_URLS.values()),
        "www.youtube.com",
        "dorahacks.io",
    }
    observed: dict[str, dict[str, object]] = {}
    for link_id, row in links.items():
        requested_url = _text(row.get("url"), f"G13 {link_id} URL")
        current = requested_url
        for _ in range(6):
            parsed = urlsplit(current)
            if (
                parsed.scheme != "https"
                or parsed.hostname not in allowed_hosts
                or parsed.username
                or parsed.password
            ):
                raise ReleaseManifestError("G13 link reprobe escaped the allowlist")
            status, headers, body = _fixed_https_json(
                url=current,
                limit=_CONTROL_LIMIT,
            )
            if status in {301, 302, 303, 307, 308}:
                location = _header_value(headers, "Location")
                if not location:
                    raise ReleaseManifestError("G13 link reprobe redirect is malformed")
                current = urljoin(current, location)
                continue
            if not 200 <= status < 300:
                raise ReleaseManifestError("G13 final link reprobe failed")
            observed[link_id] = {
                "url": requested_url,
                "effective_url": current,
                "status": status,
                "body_sha256": hashlib.sha256(body).hexdigest(),
            }
            break
        else:
            raise ReleaseManifestError("G13 link reprobe exceeded redirect limit")
    return observed


def _g13_link_reprobe_factory(
    _root: Path,
) -> object:
    return _default_g13_link_reprobe


def _verify_g13_submission_receipt_locked(
    repository_root: str | Path,
) -> dict[str, object]:
    """Verify post-video G13 evidence without mutating the immutable G12 manifest."""

    root = Path(repository_root).absolute()
    _require_repository(root)
    _recover_capture_publication(root)
    _require_clean_worktree(root)
    canaries = _load_secret_canaries()

    receipt_bound = _load_immutable_bound_file(
        root,
        G13_SUBMISSION_RECEIPT_PATH,
        _CONTROL_LIMIT,
    )
    receipt, receipt_canonical = _strict_json(receipt_bound.raw, "G13 receipt")
    if receipt_bound.raw != receipt_canonical:
        raise ReleaseManifestError("G13 receipt is not canonical JSON")
    if set(receipt) != {
        "schema_version",
        "gate_id",
        "status",
        "captured_at",
        "g12_manifest",
        "organizer_rendered_link_audit",
        "browser_receipt",
        "youtube",
        "dorahacks",
        "final_link_audit",
    }:
        raise ReleaseManifestError("G13 receipt schema is not exact")
    if (
        receipt.get("schema_version") != G13_SUBMISSION_RECEIPT_SCHEMA_VERSION
        or receipt.get("gate_id") != "G13"
        or receipt.get("status") != "verified"
    ):
        raise ReleaseManifestError("G13 receipt identity or status differs")

    g12 = _mapping(receipt.get("g12_manifest"), "G13 G12 manifest binding")
    if set(g12) != {
        "path",
        "sha256",
        "manifest_commit",
        "frozen_commit",
        "integration_commit",
    }:
        raise ReleaseManifestError("G13 G12 manifest binding schema is not exact")
    manifest_commit = _git40(
        g12.get("manifest_commit"), "G13 pinned G12 manifest commit"
    )
    manifest_bound = _load_immutable_bound_file(
        root,
        RELEASE_MANIFEST_PATH,
        _ARTIFACT_LIMIT,
        artifact_commit=manifest_commit,
    )
    manifest, manifest_canonical = _strict_json(
        manifest_bound.raw, "G12 release manifest"
    )
    if manifest_bound.raw != manifest_canonical:
        raise ReleaseManifestError("G12 release manifest is not canonical JSON")
    if (
        g12.get("path") != RELEASE_MANIFEST_PATH
        or g12.get("sha256") != manifest_bound.sha256
    ):
        raise ReleaseManifestError("G13 pinned G12 manifest digest differs")
    _validate_g12_manifest_offline(
        root,
        manifest,
        canaries=canaries,
        manifest_commit=manifest_commit,
    )
    if (
        manifest.get("schema_version") != SCHEMA_VERSION
        or manifest.get("status") != "g12_ready"
        or manifest.get("overall_status") != "pending_external"
        or manifest.get("completion_scope") != "G2-G12"
    ):
        raise ReleaseManifestError(
            "G12 release manifest is not in its frozen ready state"
        )
    gates = _sequence(manifest.get("gate_evidence"), "G12 gate evidence")
    if not gates or gates[-1] != {
        "gate_id": "G13",
        "required_receipt_path": G13_SUBMISSION_RECEIPT_PATH,
        "required_rendered_link_audit_path": ORGANIZER_G13_AUDIT_PATH,
        "status": "pending_external",
    }:
        raise ReleaseManifestError(
            "G12 manifest does not preserve the external G13 boundary"
        )

    captured_at, captured_time = _parse_timestamp(
        receipt.get("captured_at"), "G13 captured_at"
    )
    _, generated_time = _parse_timestamp(
        manifest.get("generated_at"), "G12 generated_at"
    )
    if captured_time <= generated_time:
        raise ReleaseManifestError("G13 evidence does not follow the G12 manifest")

    if (
        g12.get("path") != RELEASE_MANIFEST_PATH
        or g12.get("sha256") != manifest_bound.sha256
        or g12.get("manifest_commit") != manifest_bound.artifact_commit
        or g12.get("frozen_commit") != manifest.get("frozen_commit")
        or g12.get("integration_commit") != manifest.get("integration_commit")
    ):
        raise ReleaseManifestError("G13 G12 manifest digest or identity differs")
    if manifest.get("frozen_commit") != _tagged_freeze_commit(root):
        raise ReleaseManifestError("G12 manifest no longer binds the G1 freeze")
    if not _is_ancestor(
        root, manifest_bound.artifact_commit, receipt_bound.artifact_commit
    ):
        raise ReleaseManifestError("G13 receipt does not descend from the G12 manifest")
    expected_g13_files = {
        "BROWSER_RECEIPT.json",
        "BROWSER_TRACE.json",
        "DORAHACKS_SUBMISSION.png",
        "FINAL_LINK_AUDIT.json",
        "ORGANIZER_RENDERED_LINK_INVOCATION.json",
        "ORGANIZER_RENDERED_LINK_AUDIT.json",
        "YOUTUBE_DESCRIPTION.txt",
        "YOUTUBE_INCOGNITO.png",
    }
    if _repository_directory_names(root, "release/g13") != expected_g13_files:
        raise ReleaseManifestError("G13 support-file inventory differs")

    organizer_bound = _g13_support_file(
        root,
        row=_mapping(
            receipt.get("organizer_rendered_link_audit"),
            "G13 organizer rendered-link audit binding",
        ),
        label="G13 organizer rendered-link audit",
        expected_path=ORGANIZER_G13_AUDIT_PATH,
        receipt_commit=receipt_bound.artifact_commit,
        limit=_CONTROL_LIMIT,
        canaries=canaries,
    )
    rebound_organizer, organizer_projection = _organizer_link_audit_binding(
        root,
        path=ORGANIZER_G13_AUDIT_PATH,
        phase="G13",
        canaries=canaries,
        artifact_commit=receipt_bound.artifact_commit,
    )
    if (
        organizer_bound.sha256 != rebound_organizer.sha256
        or organizer_projection.get("captured_at") != captured_at
    ):
        raise ReleaseManifestError(
            "G13 organizer rendered-link audit identity differs"
        )

    browser_bound = _g13_support_file(
        root,
        row=_mapping(receipt.get("browser_receipt"), "G13 browser receipt binding"),
        label="G13 browser receipt",
        expected_path=G13_BROWSER_RECEIPT_PATH,
        receipt_commit=receipt_bound.artifact_commit,
        limit=_CONTROL_LIMIT,
        canaries=canaries,
    )
    browser, browser_canonical = _strict_json(browser_bound.raw, "G13 browser receipt")
    if browser_bound.raw != browser_canonical or set(browser) != {
        "schema_version",
        "status",
        "captured_at",
        "runner",
        "trace",
        "youtube",
        "dorahacks",
    }:
        raise ReleaseManifestError("G13 browser receipt schema is not exact")
    if (
        browser.get("schema_version") != G13_BROWSER_RECEIPT_SCHEMA_VERSION
        or browser.get("status") != "verified"
        or browser.get("captured_at") != captured_at
    ):
        raise ReleaseManifestError("G13 browser receipt identity differs")
    trace_bound = _g13_support_file(
        root,
        row=_mapping(browser.get("trace"), "G13 browser trace binding"),
        label="G13 browser trace",
        expected_path=G13_BROWSER_TRACE_PATH,
        receipt_commit=receipt_bound.artifact_commit,
        limit=_CONTROL_LIMIT,
        canaries=canaries,
    )
    trace, trace_canonical = _strict_json(trace_bound.raw, "G13 browser trace")
    if trace_bound.raw != trace_canonical:
        raise ReleaseManifestError("G13 browser trace is not canonical JSON")
    committed_browser_projection = _validate_g13_browser_trace(trace)
    if trace.get("captured_at") != captured_at:
        raise ReleaseManifestError("G13 browser trace identity differs")

    runner = _mapping(browser.get("runner"), "G13 runner")
    if set(runner) != {
        "path",
        "commit",
        "sha256",
        "clean_tree_sha256",
        "started_at",
        "ended_at",
        "runtime_versions",
    }:
        raise ReleaseManifestError("G13 runner schema is not exact")
    if (
        runner.get("path") != G13_RUNNER_PATH
        or runner.get("clean_tree_sha256") != hashlib.sha256(b"").hexdigest()
    ):
        raise ReleaseManifestError("G13 runner path or clean-tree state differs")
    runner_bound = _load_bound_file(root, G13_RUNNER_PATH, _CONTROL_LIMIT)
    runner_commit = _git40(runner.get("commit"), "G13 runner commit")
    if (
        runner_bound.artifact_commit != runner_commit
        or runner_bound.sha256 != _hash32(runner.get("sha256"), "G13 runner SHA-256")
        or not _is_ancestor(root, runner_commit, manifest_bound.artifact_commit)
    ):
        raise ReleaseManifestError("G13 runner implementation binding differs")
    runtimes = _mapping(runner.get("runtime_versions"), "G13 runtimes")
    if set(runtimes) != {
        "chromium",
        "chromium_executable_sha256",
        "node",
        "playwright",
    }:
        raise ReleaseManifestError("G13 browser runtime inventory differs")
    for name, version in runtimes.items():
        if len(_text(version, f"G13 {name} runtime")) > 160:
            raise ReleaseManifestError("G13 browser runtime version is malformed")
    _, runner_started = _parse_timestamp(runner.get("started_at"), "G13 runner start")
    _, runner_ended = _parse_timestamp(runner.get("ended_at"), "G13 runner end")
    if not (
        generated_time < runner_started <= runner_ended == captured_time
        and runner.get("started_at") == trace.get("started_at")
        and runner.get("ended_at") == trace.get("captured_at")
        and runtimes == trace.get("runtime_versions")
    ):
        raise ReleaseManifestError("G13 runner chronology is invalid")

    youtube = _mapping(receipt.get("youtube"), "G13 YouTube evidence")
    if set(youtube) != {
        "watch_url",
        "video_id",
        "title",
        "description",
        "incognito_playback",
    }:
        raise ReleaseManifestError("G13 YouTube evidence schema is not exact")
    video_id = _text(youtube.get("video_id"), "G13 YouTube video ID")
    if re.fullmatch(r"[A-Za-z0-9_-]{11}", video_id) is None:
        raise ReleaseManifestError("G13 YouTube video ID is invalid")
    watch_url = f"https://www.youtube.com/watch?v={video_id}"
    if youtube.get("watch_url") != watch_url or "Concordia" not in _text(
        youtube.get("title"), "G13 YouTube title"
    ):
        raise ReleaseManifestError("G13 YouTube video URL or title differs")
    description_bound = _g13_support_file(
        root,
        row=_mapping(youtube.get("description"), "G13 YouTube description"),
        label="G13 YouTube description",
        expected_path="release/g13/YOUTUBE_DESCRIPTION.txt",
        receipt_commit=receipt_bound.artifact_commit,
        limit=_CONTROL_LIMIT,
        canaries=canaries,
    )
    try:
        description = description_bound.raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ReleaseManifestError("G13 YouTube description is not UTF-8") from exc
    if (
        len(description) < 80
        or "Concordia" not in description
        or "https://" not in description
    ):
        raise ReleaseManifestError("G13 YouTube description is incomplete")
    _assert_no_canary(description_bound.raw, canaries, "G13 YouTube description")

    playback = _mapping(youtube.get("incognito_playback"), "G13 playback")
    if set(playback) != {
        "incognito",
        "state",
        "duration_seconds",
        "captions_visible",
        "capture",
    }:
        raise ReleaseManifestError("G13 playback schema is not exact")
    if (
        playback.get("incognito") is not True
        or playback.get("state") != "playing_or_ended"
        or type(playback.get("duration_seconds")) is not int
        or playback["duration_seconds"] <= 0
        or playback.get("captions_visible") is not True
    ):
        raise ReleaseManifestError("G13 incognito YouTube playback is unverified")
    youtube_capture = _g13_support_file(
        root,
        row=_mapping(playback.get("capture"), "G13 YouTube capture"),
        label="G13 YouTube capture",
        expected_path="release/g13/YOUTUBE_INCOGNITO.png",
        receipt_commit=receipt_bound.artifact_commit,
        limit=_CONTROL_LIMIT,
        canaries=canaries,
    )
    _assert_png_evidence(youtube_capture.raw, "G13 YouTube capture")

    dorahacks = _mapping(receipt.get("dorahacks"), "G13 DoraHacks evidence")
    if set(dorahacks) != {
        "buidl_url",
        "buidl_id",
        "edit_state",
        "edit_access_verified",
        "embedded_video_id",
        "capture",
    }:
        raise ReleaseManifestError("G13 DoraHacks evidence schema is not exact")
    if (
        dorahacks.get("buidl_url") != "https://dorahacks.io/buidl/46732"
        or dorahacks.get("buidl_id") != 46732
        or dorahacks.get("edit_state") != "saved"
        or dorahacks.get("edit_access_verified") is not True
        or dorahacks.get("embedded_video_id") != video_id
    ):
        raise ReleaseManifestError("G13 DoraHacks embed or edit state differs")
    dorahacks_capture = _g13_support_file(
        root,
        row=_mapping(dorahacks.get("capture"), "G13 DoraHacks capture"),
        label="G13 DoraHacks capture",
        expected_path="release/g13/DORAHACKS_SUBMISSION.png",
        receipt_commit=receipt_bound.artifact_commit,
        limit=_CONTROL_LIMIT,
        canaries=canaries,
    )
    _assert_png_evidence(dorahacks_capture.raw, "G13 DoraHacks capture")

    expected_browser_youtube = {
        "watch_url": watch_url,
        "video_id": video_id,
        "state": playback["state"],
        "duration_seconds": playback["duration_seconds"],
        "captions_visible": playback["captions_visible"],
        "capture": playback["capture"],
    }
    if browser.get("youtube") != expected_browser_youtube:
        raise ReleaseManifestError("G13 browser YouTube evidence differs")
    if browser.get("dorahacks") != dorahacks:
        raise ReleaseManifestError("G13 browser DoraHacks evidence differs")
    _assert_safe_projection(browser, canaries, "G13 browser receipt")
    _assert_safe_projection(trace, canaries, "G13 browser trace")

    audit_bound = _g13_support_file(
        root,
        row=_mapping(receipt.get("final_link_audit"), "G13 final link audit"),
        label="G13 final link audit",
        expected_path="release/g13/FINAL_LINK_AUDIT.json",
        receipt_commit=receipt_bound.artifact_commit,
        limit=_CONTROL_LIMIT,
        canaries=canaries,
    )
    audit, audit_canonical = _strict_json(audit_bound.raw, "G13 final link audit")
    if audit_bound.raw != audit_canonical or set(audit) != {
        "schema_version",
        "captured_at",
        "links",
        "receipt_bindings",
    }:
        raise ReleaseManifestError("G13 final link audit schema is not exact")
    if (
        audit.get("schema_version") != "concordia.g13_final_link_audit.v1"
        or audit.get("captured_at") != captured_at
    ):
        raise ReleaseManifestError("G13 final link audit identity differs")

    expected_links: dict[str, dict[str, object]] = {}
    public_probes = _mapping(
        _mapping(manifest.get("deployment_surfaces"), "G12 surfaces").get(
            "public_probes"
        ),
        "G12 public probes",
    )
    for raw_probe in _sequence(public_probes.get("probes"), "G12 public probes"):
        probe = _mapping(raw_probe, "G12 public probe")
        probe_id = _text(probe.get("probe_id"), "G12 public probe ID")
        expected_links[probe_id] = {
            "link_id": probe_id,
            "url": probe.get("requested_url"),
            "effective_url": probe.get("effective_url"),
            "status": probe.get("status"),
            "tls_verified": True,
            "checked_at": captured_at,
        }
    expected_links["youtube_new_video"] = {
        "link_id": "youtube_new_video",
        "url": watch_url,
        "effective_url": watch_url,
        "status": 200,
        "tls_verified": True,
        "checked_at": captured_at,
    }
    expected_links["dorahacks_buidl_46732"] = {
        "link_id": "dorahacks_buidl_46732",
        "url": "https://dorahacks.io/buidl/46732",
        "effective_url": "https://dorahacks.io/buidl/46732",
        "status": 200,
        "tls_verified": True,
        "checked_at": captured_at,
    }
    actual_links: dict[str, Mapping[str, object]] = {}
    for raw_link in _sequence(audit.get("links"), "G13 final links"):
        link = _mapping(raw_link, "G13 final link")
        link_id = _text(link.get("link_id"), "G13 final link ID")
        if link_id in actual_links:
            raise ReleaseManifestError("G13 final link audit has duplicate links")
        actual_links[link_id] = link
    if actual_links != expected_links:
        raise ReleaseManifestError(
            "G13 final link audit does not contain the exact final links"
        )

    committed_browser_routes = _mapping(
        committed_browser_projection.get("routes"),
        "G13 committed browser routes",
    )
    committed_youtube = _mapping(
        _mapping(
            committed_browser_routes.get("youtube_new_video"),
            "G13 committed YouTube projection",
        ).get("specialized"),
        "G13 committed YouTube facts",
    )
    committed_dorahacks = _mapping(
        _mapping(
            committed_browser_routes.get("dorahacks_buidl_46732"),
            "G13 committed DoraHacks projection",
        ).get("specialized"),
        "G13 committed DoraHacks facts",
    )
    if (
        committed_youtube.get("video_id") != video_id
        or committed_youtube.get("duration_seconds") != playback["duration_seconds"]
        or committed_youtube.get("captions_visible") is not True
        or committed_dorahacks.get("video_id") != video_id
        or committed_dorahacks.get("embedded") is not True
    ):
        raise ReleaseManifestError(
            "G13 raw browser trace contradicts the submission receipt"
        )
    browser_request = _g13_browser_request(video_id=video_id, links=actual_links)
    fresh_trace = _g13_browser_runner_factory(root)(root, browser_request)
    fresh_browser_projection = _validate_g13_browser_trace(fresh_trace)
    if fresh_browser_projection != committed_browser_projection:
        raise ReleaseManifestError(
            "fresh G13 browser execution differs from the committed raw trace"
        )
    reprobed = _g13_link_reprobe_factory(root)(root, actual_links)
    if set(reprobed) != set(actual_links):
        raise ReleaseManifestError("G13 independent link reprobe inventory differs")
    for link_id, fresh in reprobed.items():
        committed = actual_links[link_id]
        if (
            fresh.get("url") != committed.get("url")
            or fresh.get("effective_url") != committed.get("effective_url")
            or fresh.get("status") != committed.get("status")
        ):
            raise ReleaseManifestError(
                f"G13 independent link reprobe differs for {link_id}"
            )

    manifest_receipt_rows = [
        *_sequence(manifest.get("observation_receipts"), "G12 observations"),
        *_sequence(manifest.get("proof_verifier_receipts"), "G12 proofs"),
        _mapping(manifest.get("npm_tarball_capture"), "G12 npm capture"),
        _mapping(
            manifest.get("organizer_rendered_link_audit"),
            "G12 organizer rendered-link audit",
        ),
    ]
    immutable_receipt_commits = {
        _text(item.get("path"), "G12 receipt path"): _text(
            item.get("artifact_commit"), "G12 receipt artifact commit"
        )
        for item in (
            _mapping(raw_item, "G12 receipt binding")
            for raw_item in manifest_receipt_rows
        )
    }
    immutable_receipt_commits[RELEASE_MANIFEST_PATH] = manifest_commit
    expected_receipts = [
        {"path": item["path"], "sha256": item["sha256"]}
        for item in manifest_receipt_rows
    ]
    expected_receipts.append(
        {"path": RELEASE_MANIFEST_PATH, "sha256": manifest_bound.sha256}
    )
    expected_receipts.sort(key=lambda item: item["path"])
    if audit.get("receipt_bindings") != expected_receipts:
        raise ReleaseManifestError("G13 final receipt audit differs from G12")
    for binding in expected_receipts:
        relative = str(binding["path"])
        current = _load_immutable_bound_file(
            root,
            relative,
            _ARTIFACT_LIMIT,
            artifact_commit=immutable_receipt_commits[relative],
        )
        if current.sha256 != binding["sha256"]:
            raise ReleaseManifestError("G13 final receipt binding digest differs")

    _assert_safe_projection(receipt, canaries, "G13 submission receipt")
    _assert_safe_projection(audit, canaries, "G13 final link audit")
    _require_clean_worktree(root)
    return {
        "gate_id": "G13",
        "g12_manifest_sha256": manifest_bound.sha256,
        "overall_status": "complete",
        "status": "verified",
    }


def verify_g13_submission_receipt(
    repository_root: str | Path,
) -> dict[str, object]:
    """Serialize immutable G13 verification and any capture recovery."""

    root = Path(repository_root).absolute()
    _require_repository(root)
    lock_descriptor = _repository_release_lock(root)
    try:
        return _verify_g13_submission_receipt_locked(root)
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)


@dataclass
class _LocalVerifierBundle:
    """Private, byte-exact public-registry replay tree for the JS verifier."""

    temporary: tempfile.TemporaryDirectory[str]
    root: Path
    registry_path: Path
    files: Mapping[str, _RepositoryRead]

    def revalidate(self) -> None:
        expected_files = set(self.files)
        expected_directories = {"."}
        for relative in expected_files:
            parts = PurePosixPath(relative).parts[:-1]
            for index in range(1, len(parts) + 1):
                expected_directories.add(PurePosixPath(*parts[:index]).as_posix())

        actual_files: set[str] = set()
        actual_directories = {"."}
        for current_root, directory_names, file_names in os.walk(
            self.root,
            topdown=True,
            followlinks=False,
        ):
            current = Path(current_root)
            relative_root = current.relative_to(self.root)
            for name in directory_names:
                target = current / name
                metadata = target.lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                    raise ReleaseManifestError(
                        "private verifier data tree contains an unsafe directory"
                    )
                actual_directories.add(
                    (relative_root / name).as_posix() if relative_root.parts else name
                )
            for name in file_names:
                target = current / name
                metadata = target.lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                    raise ReleaseManifestError(
                        "private verifier data tree contains an unsafe file"
                    )
                actual_files.add(
                    (relative_root / name).as_posix() if relative_root.parts else name
                )
        if actual_files != expected_files or actual_directories != expected_directories:
            raise ReleaseManifestError("private verifier data inventory changed")
        for relative, expected in self.files.items():
            current = _read_bounded_repository_file(
                self.root,
                relative,
                _ARTIFACT_LIMIT,
            )
            if current != expected:
                raise ReleaseManifestError("private verifier data bytes changed")

    def cleanup(self) -> None:
        self.temporary.cleanup()


def _materialize_local_verifier_bundle(
    root: Path,
    *,
    generated_at: str,
) -> _LocalVerifierBundle:
    """Materialize the public registry at a root that preserves artifact paths."""

    _parse_timestamp(generated_at, "local verifier registry generated_at")
    internal_bound = _load_bound_file(
        root,
        ARTIFACT_PATHS["proof_registry_v1"],
        _ARTIFACT_LIMIT,
    )
    internal, _ = _strict_json(internal_bound.raw, "committed proof registry")
    public_items = [
        dict(_mapping(item, "committed public proof item"))
        for item in _sequence(
            internal.get("public_items"), "committed public proof items"
        )
        if _mapping(item, "committed public proof item").get("proposal_id")
        in {None, _PROPOSAL}
    ]
    if not public_items:
        raise ReleaseManifestError("local verifier registry contains no public proof")

    allowed_paths = set(ARTIFACT_PATHS.values()) - {ARTIFACT_PATHS["proof_registry_v1"]}
    artifact_bindings: dict[str, _BoundFile] = {}
    for item in public_items:
        if item.get("verification_status") != "verified":
            raise ReleaseManifestError(
                "local verifier registry contains a nonverified proof"
            )
        relative = _text(item.get("artifact_path"), "local verifier artifact path")
        _validate_relative_path(relative)
        if relative not in allowed_paths or relative in artifact_bindings:
            raise ReleaseManifestError(
                "local verifier registry artifact inventory differs"
            )
        bound = _load_bound_file(root, relative, _ARTIFACT_LIMIT)
        if bound.sha256 != _hash32(
            item.get("artifact_sha256"),
            "local verifier artifact SHA-256",
        ):
            raise ReleaseManifestError(
                "local verifier registry artifact digest differs"
            )
        artifact_bindings[relative] = bound

    public_registry = {
        "schema_version": 1,
        "generated_at": generated_at,
        "proposal_id": _PROPOSAL,
        "items": public_items,
    }
    registry_raw = _canonical_json(public_registry)
    temporary = tempfile.TemporaryDirectory(prefix="concordia-local-proof-replay-")
    destination = Path(temporary.name).resolve(strict=True)
    files: dict[str, _RepositoryRead] = {}
    try:
        _atomic_create_once(destination, "registry.json", registry_raw)
        for relative, bound in sorted(artifact_bindings.items()):
            _atomic_create_once(destination, relative, bound.raw)
        for relative in ("registry.json", *sorted(artifact_bindings)):
            files[relative] = _read_bounded_repository_file(
                destination,
                relative,
                _ARTIFACT_LIMIT,
            )
        bundle = _LocalVerifierBundle(
            temporary=temporary,
            root=destination,
            registry_path=destination / "registry.json",
            files=files,
        )
        bundle.revalidate()
        return bundle
    except BaseException:
        temporary.cleanup()
        raise


class _DefaultProofVerifier:
    """Run fixed first-party verifiers; unsupported evidence fails closed."""

    def __init__(self, root: Path):
        self.root = root
        self._registry_cli: dict[str, Mapping[str, object]] | None = None
        self._materialization: tempfile.TemporaryDirectory[str] | None = None
        self._materialized_root_path: Path | None = None
        self._materialized_archive_sha256: str | None = None

    def _materialize_committed_tree(self) -> Path:
        if self._materialized_root_path is not None:
            return self._materialized_root_path
        tool_commit = _verifier_tool_commit(self.root)
        expected_tree = _verifier_source_tree_sha256(self.root, tool_commit)
        try:
            head_commit = (
                _git(self.root, ["rev-parse", "HEAD"], limit=_CONTROL_LIMIT)
                .stdout.decode("ascii")
                .strip()
            )
        except UnicodeDecodeError as exc:
            raise ReleaseManifestError("release HEAD identity is malformed") from exc
        head_commit = _git40(head_commit, "release HEAD")
        if expected_tree != _verifier_source_tree_sha256(self.root, head_commit):
            raise ReleaseManifestError(
                "current verifier sources differ from the bound tool commit"
            )
        archive = _git(
            self.root,
            ["archive", "--format=tar", tool_commit],
            limit=_VERIFIER_ARCHIVE_LIMIT,
        ).stdout
        if not archive:
            raise ReleaseManifestError("committed verifier archive is empty")
        materialization = tempfile.TemporaryDirectory(
            prefix="concordia-committed-verifier-"
        )
        destination = Path(materialization.name).resolve(strict=True)
        total = 0
        seen: set[str] = set()
        try:
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
                for member in source.getmembers():
                    relative = PurePosixPath(member.name)
                    if (
                        relative.is_absolute()
                        or not relative.parts
                        or ".." in relative.parts
                        or member.issym()
                        or member.islnk()
                        or member.isdev()
                    ):
                        raise ReleaseManifestError(
                            "committed verifier archive contains an unsafe path"
                        )
                    normalized = relative.as_posix()
                    if normalized in seen:
                        raise ReleaseManifestError(
                            "committed verifier archive contains a duplicate path"
                        )
                    seen.add(normalized)
                    target = destination.joinpath(*relative.parts)
                    if member.isdir():
                        target.mkdir(mode=0o700, parents=True, exist_ok=True)
                        continue
                    if not member.isfile() or member.size < 0:
                        raise ReleaseManifestError(
                            "committed verifier archive contains a non-file entry"
                        )
                    total += member.size
                    if total > _VERIFIER_ARCHIVE_LIMIT:
                        raise ReleaseManifestError(
                            "committed verifier archive exceeds size bound"
                        )
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    stream = source.extractfile(member)
                    if stream is None:
                        raise ReleaseManifestError(
                            "committed verifier archive member is unavailable"
                        )
                    raw = stream.read(member.size + 1)
                    if len(raw) != member.size:
                        raise ReleaseManifestError(
                            "committed verifier archive member size differs"
                        )
                    descriptor = os.open(
                        target,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | os.O_CLOEXEC
                        | os.O_NONBLOCK
                        | getattr(os, "O_NOFOLLOW", 0),
                        0o700 if member.mode & 0o111 else 0o600,
                    )
                    try:
                        view = memoryview(raw)
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                raise ReleaseManifestError(
                                    "committed verifier extraction made no progress"
                                )
                            view = view[written:]
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
        except BaseException:
            materialization.cleanup()
            raise
        self._materialization = materialization
        self._materialized_root_path = destination
        self._materialized_archive_sha256 = hashlib.sha256(archive).hexdigest()
        return destination

    def _materialize_committed_sdk_cli(self) -> Path:
        materialized = self._materialize_committed_tree()
        package_root = materialized / "packages/verify"
        if not (package_root / "package-lock.json").is_file():
            raise ReleaseManifestError("committed SDK lockfile is unavailable")
        _run(
            package_root,
            ["npm", "ci", "--ignore-scripts", "--offline", "--no-audit", "--no-fund"],
            limit=_CONTROL_LIMIT,
            timeout=180,
            repository_root=self.root,
        )
        _run(
            package_root,
            ["npm", "run", "build"],
            limit=_CONTROL_LIMIT,
            timeout=180,
            repository_root=self.root,
        )
        cli = package_root / "dist/cli.js"
        try:
            metadata = cli.lstat()
        except OSError as exc:
            raise ReleaseManifestError(
                "committed SDK build output is unavailable"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ReleaseManifestError("committed SDK build output is unsafe")
        return cli

    def _committed_python_verifier(
        self, verifier_name: str, artifact_bytes: bytes
    ) -> dict[str, object]:
        materialized = self._materialize_committed_tree()
        if verifier_name not in {"historical", "v3", "card_roots", "registry"}:
            raise ReleaseManifestError("committed Python verifier identity is unknown")
        runner = (materialized / "scripts/build_release_manifest.py").resolve(
            strict=True
        )
        with tempfile.TemporaryDirectory(
            prefix="concordia-verifier-input-"
        ) as temporary:
            input_path = (Path(temporary) / "artifact.json").resolve()
            descriptor = os.open(
                input_path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | os.O_NONBLOCK
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                view = memoryview(artifact_bytes)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise ReleaseManifestError(
                            "committed verifier input write made no progress"
                        )
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            result = _run(
                materialized,
                [
                    "python",
                    str(runner),
                    "verify-python-artifact",
                    "--verifier",
                    verifier_name,
                    "--artifact",
                    str(input_path),
                ],
                limit=_CONTROL_LIMIT,
                timeout=180,
                repository_root=self.root,
                command_asset_root=materialized,
                bound_data_inputs=(input_path,),
            )
        document, _ = _strict_json(result.stdout, "committed Python verifier result")
        return document

    def _packaged_registry_items(self) -> dict[str, Mapping[str, object]]:
        if self._registry_cli is not None:
            return self._registry_cli
        cli = self._materialize_committed_sdk_cli()
        now = _format_now(_utc_now())
        bundle = _materialize_local_verifier_bundle(
            self.root,
            generated_at=now,
        )
        try:
            result = _run(
                self.root,
                [
                    "node",
                    str(cli),
                    "local",
                    str(bundle.registry_path),
                    "--now",
                    now,
                ],
                limit=_CONTROL_LIMIT,
                timeout=180,
                repository_root=self.root,
                command_asset_root=cli.parents[1],
                bound_data_inputs=(bundle.registry_path,),
            )
            bundle.revalidate()
        finally:
            bundle.cleanup()
        payload, _ = _strict_json(result.stdout, "packaged verifier result")
        if (
            payload.get("tool") != "@concordia-dao/verify"
            or payload.get("status") != "verified"
            or payload.get("valid") is not True
            or payload.get("exitCode") != 0
        ):
            raise ReleaseManifestError("packaged verifier rejected release proofs")
        items = _sequence(payload.get("items"), "packaged verifier items")
        by_id: dict[str, Mapping[str, object]] = {}
        for raw in items:
            item = _mapping(raw, "packaged verifier item")
            proof_id = _text(item.get("proofId"), "packaged verifier proofId")
            if (
                item.get("status") != "verified"
                or item.get("green") is not True
                or item.get("ignoredAssertions") != []
            ):
                raise ReleaseManifestError(
                    "packaged verifier returned a non-green proof"
                )
            if proof_id in by_id:
                raise ReleaseManifestError(
                    "packaged verifier returned a duplicate proof ID"
                )
            by_id[proof_id] = item
        self._registry_cli = by_id
        return by_id

    def verify(
        self,
        *,
        artifact_id: str,
        artifact_path: str,
        artifact_bytes: bytes,
        artifact_document: dict[str, object],
    ) -> dict[str, object]:
        _require_nonempty_proof(artifact_id, artifact_document)
        if artifact_id == "historical_odra_receipt_v1":
            facts = self._committed_python_verifier("historical", artifact_bytes)
            identity = {
                "proposal_id": facts["proposalId"],
                "deploy_hash": facts["deployHash"],
                "final_card_hash": facts["finalCardHash"],
            }
            derived = {
                "block_hash": facts["blockHash"],
                "block_height": facts["blockHeight"],
                "package_hash": facts["packageHash"],
                "contract_hash": facts["contractHash"],
            }
            verifier_id = (
                "shared.historical_odra_artifact.verify_historical_odra_artifact"
            )
        elif artifact_id == "exact_envelope_v3":
            facts = self._committed_python_verifier("v3", artifact_bytes)
            if facts.get("valid") is not True:
                raise ReleaseManifestError("exact v3 verifier did not derive validity")
            identity = {
                "proposal_id": facts["proposal_id"],
                "action_id": facts["action_id"],
                "envelope_hash": facts["envelope_hash"],
            }
            derived = {
                "package_hash": facts["package_hash"],
                "contract_hash": facts["contract_hash"],
                "observed_block_hash": facts["observed_block_hash"],
                "observed_block_height": facts["observed_block_height"],
            }
            verifier_id = "scripts.verify_v3_proof.verify_v3_proof_document"
        elif artifact_id == "card_chain_roots_v1":
            historical = _read_bounded_repository_file(
                self.root,
                ARTIFACT_PATHS["historical_odra_receipt_v1"],
                _ARTIFACT_LIMIT,
            ).raw
            encoded = self._committed_python_verifier("card_roots", historical)
            try:
                expected = base64.b64decode(
                    _text(encoded.get("payload_b64"), "card-root verifier payload"),
                    validate=True,
                )
            except (ValueError, binascii.Error) as exc:
                raise ReleaseManifestError(
                    "card-root verifier payload is invalid"
                ) from exc
            if expected != artifact_bytes:
                raise ReleaseManifestError(
                    "card roots differ from verified historical evidence"
                )
            roots = _mapping(artifact_document.get("roots"), "card roots")
            identity = {"proposal_ids": sorted(roots)}
            derived = {"roots_sha256": hashlib.sha256(expected).hexdigest()}
            verifier_id = "scripts.generate_card_chain_release_roots.derive_card_chain_release_roots"
        elif artifact_id == "proof_registry_v1":
            facts = self._committed_python_verifier("registry", artifact_bytes)
            if facts.get("valid") is not True:
                raise ReleaseManifestError("proof registry verifier rejected registry")
            identity = {
                "artifact_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
                "public_items_sha256": facts["public_items_sha256"],
                "internal_records_sha256": facts["internal_records_sha256"],
            }
            derived = {
                "public_item_count": facts["public_item_count"],
                "internal_record_count": facts["internal_record_count"],
            }
            verifier_id = (
                "shared.proof_registry.validate_release_registry_document"
            )
        elif artifact_id in {
            "safepay_v2",
            "official_x402_settlement_v1",
        }:
            try:
                adapter_result = (
                    release_proof_adapters.verify_safepay_v2_artifact(
                        artifact_document,
                        artifact_bytes,
                    )
                    if artifact_id == "safepay_v2"
                    else release_proof_adapters.verify_official_x402_artifact(
                        artifact_document,
                        artifact_bytes,
                    )
                )
            except release_proof_adapters.ReleaseProofAdapterError as exc:
                raise ReleaseManifestError(
                    f"{artifact_id} raw proof adapter rejected its artifact"
                ) from exc
            expected_artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
            if (
                adapter_result.get("proof_type") != artifact_id
                or adapter_result.get("artifact_sha256")
                != expected_artifact_sha256
            ):
                raise ReleaseManifestError(
                    f"{artifact_id} raw proof adapter identity differs"
                )
            facts = _mapping(
                adapter_result.get("derived_facts"),
                f"{artifact_id} raw adapter facts",
            )
            checks = _sequence(
                adapter_result.get("checks"),
                f"{artifact_id} raw adapter checks",
            )
            check_names = [
                check.get("name") for check in checks if type(check) is dict
            ]
            if (
                not checks
                or len(check_names) != len(checks)
                or len(check_names) != len(set(check_names))
                or any(check.get("passed") is not True for check in checks)
            ):
                raise ReleaseManifestError(
                    f"{artifact_id} raw proof adapter returned a non-green check"
                )
            identity = {
                "artifact_sha256": expected_artifact_sha256,
                "proposal_id": _text(
                    facts.get("proposal_id"),
                    f"{artifact_id} adapter proposal ID",
                ),
                "report_hash": _hash32(
                    facts.get("report_hash"),
                    f"{artifact_id} adapter report hash",
                ),
            }
            if artifact_id == "safepay_v2":
                identity["payment_hash"] = _hash32(
                    facts.get("payment_hash"),
                    "SafePay adapter payment hash",
                )
            else:
                identity.update(
                    {
                        "action_id": _hash32(
                            facts.get("action_id"),
                            "official-x402 adapter action ID",
                        ),
                        "envelope_hash": _hash32(
                            facts.get("envelope_hash"),
                            "official-x402 adapter envelope hash",
                        ),
                        "settlement_transaction": _hash32(
                            facts.get("settlement_transaction"),
                            "official-x402 adapter settlement transaction",
                        ),
                    }
                )
            derived = {
                "adapter_result_sha256": hashlib.sha256(
                    _canonical_json(adapter_result)
                ).hexdigest(),
                "check_count": len(checks),
                "check_names_sha256": hashlib.sha256(
                    _canonical_json([check["name"] for check in checks])
                ).hexdigest(),
            }
            verifier_id = (
                "shared.release_proof_adapters."
                + (
                    "verify_safepay_v2_artifact"
                    if artifact_id == "safepay_v2"
                    else "verify_official_x402_artifact"
                )
            )
        else:
            # The read-only SDK independently reparses registry-bound treasury
            # evidence. Payment proofs use the raw adapters above; registry
            # booleans never authorize their release receipts.
            items = self._packaged_registry_items()
            proof_ids = {
                "native_treasury_execution_v1": "native_treasury_execution_v1",
            }
            proof_id = proof_ids[artifact_id]
            item = items.get(proof_id)
            if item is None:
                raise ReleaseManifestError(
                    f"packaged verifier lacks required {proof_id} adapter"
                )
            identity = {
                "proof_id": proof_id,
                "artifact_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
            }
            derived = {
                "result_sha256": hashlib.sha256(_canonical_json(item)).hexdigest(),
                "registry_item_count": len(items),
            }
            verifier_id = "@concordia-dao/verify local"
        if self._materialized_archive_sha256 is not None:
            derived["verifier_archive_sha256"] = self._materialized_archive_sha256
        return {
            "verifier_id": verifier_id,
            "derived_identity": identity,
            "derived_facts": derived,
        }


def _proof_verifier_factory(root: Path) -> _ProofVerifier:
    return _DefaultProofVerifier(root)


def _decode_json_response(raw: bytes, label: str) -> dict[str, object]:
    value, _ = _strict_json(raw, label)
    return value


def _fixed_github_api(root: Path, endpoint: str) -> object:
    base = "/repos/asadvendor-boop/concordia-dao-council"
    fixed = {
        base + "/pages",
        base + "/actions/workflows/docs-pages.yml/runs?per_page=1",
        base + "/deployments?environment=github-pages&per_page=1",
    }
    dynamic_status = re.fullmatch(
        re.escape(base) + r"/deployments/[1-9][0-9]*/statuses\?per_page=1",
        endpoint,
    )
    if endpoint not in fixed and dynamic_status is None:
        raise ReleaseManifestError("GitHub API endpoint is outside the fixed allowlist")
    result = _run(
        root,
        [
            "gh",
            "api",
            "--method",
            "GET",
            "-H",
            "Accept: application/vnd.github+json",
            endpoint,
        ],
        limit=_CONTROL_LIMIT,
    )
    try:
        value = json.loads(
            result.stdout.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseManifestError(
            "authenticated GitHub API returned invalid JSON"
        ) from exc
    if type(value) not in {dict, list}:
        raise ReleaseManifestError("authenticated GitHub API returned invalid JSON")
    return value


def _fixed_https_json(
    *,
    url: str,
    method: str = "GET",
    body: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    limit: int = _CONTROL_LIMIT,
) -> tuple[int, Mapping[str, str], bytes]:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ReleaseManifestError("fixed HTTPS URL is invalid")
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        parsed.port or 443,
        timeout=15,
        context=ssl.create_default_context(),
    )
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    try:
        connection.request(method, path, body=body, headers=dict(headers or {}))
        response = connection.getresponse()
        raw = response.read(limit + 1)
        if len(raw) > limit:
            raise ReleaseManifestError("fixed HTTPS response exceeded size bound")
        projected_headers = {
            name: value
            for name, value in response.getheaders()
            if name.lower() in _SAFE_HTTP_HEADERS
        }
        return response.status, projected_headers, raw
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        # Never include server bodies or reflected authorization in errors.
        raise ReleaseManifestError("fixed HTTPS request failed") from exc
    finally:
        connection.close()


def _header_value(headers: Mapping[str, str], name: str) -> str | None:
    matches = [value for key, value in headers.items() if key.lower() == name.lower()]
    if len(matches) > 1:
        raise ReleaseManifestError("fixed HTTPS response repeated a singleton header")
    return matches[0] if matches else None


def _collect_approval_caddy_probes(
    *, username: bytes, password: bytes, bcrypt_hash: bytes
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    try:
        bcrypt_verified = bcrypt.checkpw(password, bcrypt_hash)
    except (TypeError, ValueError) as exc:
        raise ReleaseManifestError(
            "approval probe credential verification failed"
        ) from exc
    if not bcrypt_verified:
        raise ReleaseManifestError("approval probe credential verification failed")
    try:
        authorization = "Basic " + base64.b64encode(username + b":" + password).decode(
            "ascii"
        )
    except UnicodeError as exc:  # pragma: no cover - base64 is ASCII by construction
        raise ReleaseManifestError("approval probe credential encoding failed") from exc

    hosts = (
        "concordia.47.84.232.193.sslip.io",
        "concordiadao.xyz",
    )
    unauthenticated: list[dict[str, object]] = []
    authenticated: list[dict[str, object]] = []
    for host in sorted(hosts):
        url = f"https://{host}/approve"
        for method, mode, headers in (
            ("GET", "unauthenticated", {}),
            (
                "POST",
                "unauthenticated",
                {"Content-Type": "application/x-www-form-urlencoded"},
            ),
            (
                "GET",
                "spoofed_proxy_header",
                {"X-Proxy-Secret": "CONCORDIA-RELEASE-PROBE-INVALID"},
            ),
        ):
            status, response_headers, _ = _fixed_https_json(
                url=url,
                method=method,
                body=b"" if method == "POST" else None,
                headers=headers,
                limit=_CONTROL_LIMIT,
            )
            challenge = _header_value(response_headers, "WWW-Authenticate")
            basic_challenge = (
                type(challenge) is str
                and re.match(r"(?i)^basic(?:\s|$)", challenge.strip()) is not None
            )
            reached_gateway = not (status == 401 and basic_challenge)
            unauthenticated.append(
                {
                    "host": host,
                    "method": method,
                    "mode": mode,
                    "status": status,
                    "basic_challenge": basic_challenge,
                    "reached_gateway": reached_gateway,
                }
            )

        status, _, _ = _fixed_https_json(
            url=url,
            headers={
                "Authorization": authorization,
                # A successful response proves Caddy replaced this invalid value
                # with its server-side proxy secret before reaching the Gateway.
                "X-Proxy-Secret": "CONCORDIA-RELEASE-PROBE-INVALID",
            },
            limit=_CONTROL_LIMIT,
        )
        authenticated.append(
            {
                "host": host,
                "method": "GET",
                "status": status,
                "bcrypt_verified": True,
                "gateway_proxy_verified": status == 200,
            }
        )
    return unauthenticated, authenticated


def _collect_tls(host: str, *, repository_root: Path) -> dict[str, object]:
    try:
        addresses = sorted(
            {
                item[4][0]
                for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            }
        )
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((host, 443), timeout=5) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                der = tls_socket.getpeercert(binary_form=True)
                cert = tls_socket.getpeercert()
                cipher = tls_socket.cipher()
                peer = tls_socket.getpeername()[0]
                protocol = tls_socket.version()
    except (OSError, ssl.SSLError) as exc:
        raise ReleaseManifestError(
            "fixed deployment host TLS verification failed"
        ) from exc
    sans = [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"]
    issuer_cn = ""
    for group in cert.get("issuer", []):
        for key, value in group:
            if key == "commonName":
                issuer_cn = value
    try:
        not_before = datetime.strptime(
            cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=UTC)
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=UTC
        )
    except (KeyError, ValueError) as exc:
        raise ReleaseManifestError("TLS certificate dates are malformed") from exc
    cname_result = _run(
        repository_root,
        ["dig", "+short", host, "CNAME"],
        limit=_CONTROL_LIMIT,
        timeout=5,
        check=False,
        repository_root=repository_root,
    )
    if (
        cname_result.returncode != 0
        or len(cname_result.stdout) > _CONTROL_LIMIT
        or len(cname_result.stderr) > _CONTROL_LIMIT
    ):
        raise ReleaseManifestError("fixed DNS CNAME observation failed")
    cnames = sorted(
        line.strip().lower()
        for line in cname_result.stdout.decode("ascii").splitlines()
        if line.strip()
    )
    return {
        "certificate_sha256": hashlib.sha256(der).hexdigest(),
        "protocol": protocol,
        "cipher": cipher[0] if cipher else "unknown",
        "sans": sans,
        "not_before": _format_now(not_before),
        "not_after": _format_now(not_after),
        "issuer_cn": issuer_cn,
        "resolved_ips": addresses,
        "dns": {"addresses": addresses, "cnames": cnames},
        "peer_ip": peer,
    }


class _DefaultCollector:
    """Collector for fixed release sources.  It has no caller-selected URLs."""

    def __init__(self, root: Path):
        self.root = root

    def _compose(self) -> Mapping[str, object]:
        result = _run(
            self.root,
            [
                "docker",
                "compose",
                "-p",
                "concordia",
                "--project-directory",
                str(self.root),
                "-f",
                str(self.root / COMPOSE_FILE_PATH),
                "config",
                "--format",
                "json",
            ],
            limit=_CONTROL_LIMIT,
            repository_root=self.root,
            bound_data_inputs=(self.root / COMPOSE_FILE_PATH,),
        )
        compose = _decode_json_response(result.stdout, "rendered Compose config")
        hashes_result = _run(
            self.root,
            [
                "docker",
                "compose",
                "-p",
                "concordia",
                "--project-directory",
                str(self.root),
                "-f",
                str(self.root / COMPOSE_FILE_PATH),
                "config",
                "--hash",
                "*",
            ],
            limit=_CONTROL_LIMIT,
            repository_root=self.root,
            bound_data_inputs=(self.root / COMPOSE_FILE_PATH,),
        )
        try:
            lines = hashes_result.stdout.decode("ascii").splitlines()
        except UnicodeDecodeError as exc:
            raise ReleaseManifestError(
                "Compose config hash output is malformed"
            ) from exc
        config_hashes: dict[str, str] = {}
        for line in lines:
            match = re.fullmatch(r"([^\s:]+)(?::|\s+)\s*([0-9a-f]{64})", line.strip())
            if match is None or match.group(1) in config_hashes:
                raise ReleaseManifestError("Compose config hash output is malformed")
            config_hashes[match.group(1)] = match.group(2)
        if set(config_hashes) != set(
            _mapping(compose.get("services"), "Compose services")
        ):
            raise ReleaseManifestError(
                "Compose config hash inventory differs from services"
            )
        compose["x-concordia-observed-service-config-hashes"] = config_hashes
        return compose

    def _runtime(self) -> Sequence[Mapping[str, object]]:
        ids = (
            _run(
                self.root,
                [
                    "docker",
                    "compose",
                    "-p",
                    "concordia",
                    "--project-directory",
                    str(self.root),
                    "-f",
                    str(self.root / COMPOSE_FILE_PATH),
                    "ps",
                    "-q",
                ],
                limit=_CONTROL_LIMIT,
                repository_root=self.root,
                bound_data_inputs=(self.root / COMPOSE_FILE_PATH,),
            )
            .stdout.decode("ascii")
            .split()
        )
        if not ids:
            raise ReleaseManifestError("Concordia runtime has no containers")
        result = _run(
            self.root,
            ["docker", "inspect", *ids],
            limit=_GIT_OUTPUT_LIMIT,
        )
        try:
            values = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ReleaseManifestError("Docker inspect output is invalid") from exc
        if type(values) is not list:
            raise ReleaseManifestError("Docker inspect output is not an array")
        image_ids = sorted(
            {
                _text(_mapping(value, "Docker inspect item").get("Image"), "image ID")
                for value in values
            }
        )
        image_result = _run(
            self.root,
            ["docker", "image", "inspect", *image_ids],
            limit=_GIT_OUTPUT_LIMIT,
        )
        try:
            image_values = json.loads(image_result.stdout)
        except json.JSONDecodeError as exc:
            raise ReleaseManifestError(
                "Docker image inspect output is invalid"
            ) from exc
        if type(image_values) is not list:
            raise ReleaseManifestError("Docker image inspect output is not an array")
        image_labels: dict[str, Mapping[str, object]] = {}
        for raw_image in image_values:
            image = _mapping(raw_image, "Docker image inspect item")
            image_id = _text(image.get("Id"), "Docker image ID")
            config = _mapping(image.get("Config"), "Docker image Config")
            labels = config.get("Labels") or {}
            image_labels[image_id] = _mapping(labels, "Docker image labels")
        if set(image_labels) != set(image_ids):
            raise ReleaseManifestError("Docker image identity inventory differs")
        projected: list[dict[str, object]] = []
        for raw in values:
            item = _mapping(raw, "Docker inspect item")
            config = _mapping(item.get("Config"), "Docker Config")
            state = _mapping(item.get("State"), "Docker State")
            labels = _mapping(config.get("Labels"), "Docker labels")
            health = state.get("Health") if type(state.get("Health")) is dict else {}
            image_id = _text(item.get("Image"), "runtime image ID")
            oci = image_labels[image_id]
            projected.append(
                {
                    "service_id": labels.get("com.docker.compose.service"),
                    "project": labels.get("com.docker.compose.project"),
                    "container_id": str(item.get("Id", "")).removeprefix("sha256:"),
                    "config_image": config.get("Image"),
                    "image_id": image_id,
                    "image_revision": oci.get("org.opencontainers.image.revision"),
                    "image_source": oci.get("org.opencontainers.image.source"),
                    "image_deployment": oci.get("io.concordia.deployment-commit"),
                    "state_status": state.get("Status"),
                    "health_status": health.get("Status", "none"),
                    "started_at": state.get("StartedAt"),
                    "restart_count": item.get("RestartCount"),
                    "config_hash": labels.get("com.docker.compose.config-hash"),
                }
            )
        return projected

    def _caddy(self) -> Mapping[str, object]:
        username, bcrypt_hash, proxy_secret = _validate_approval_caddy_secret_files()
        connection = http.client.HTTPConnection("127.0.0.1", 2019, timeout=5)
        try:
            connection.request("GET", "/config/")
            response = connection.getresponse()
            raw = response.read(_CONTROL_LIMIT + 1)
            if response.status != 200 or len(raw) > _CONTROL_LIMIT:
                raise ReleaseManifestError("Caddy Admin API observation failed")
            active_config = _decode_json_response(raw, "active Caddy config")
        except (OSError, http.client.HTTPException) as exc:
            raise ReleaseManifestError("Caddy Admin API observation failed") from exc
        finally:
            connection.close()
        password = _consume_approval_probe_password(_APPROVAL_CADDY_PROBE_PASSWORD_PATH)
        unauthenticated, authenticated = _collect_approval_caddy_probes(
            username=username,
            password=password,
            bcrypt_hash=bcrypt_hash,
        )
        return {
            "active_config": active_config,
            "approval_material": {
                "username_sha256": hashlib.sha256(username).hexdigest(),
                "bcrypt_value": bcrypt_hash.decode("ascii"),
                "proxy_secret_sha256": hashlib.sha256(proxy_secret).hexdigest(),
            },
            "unauthenticated_probes": unauthenticated,
            "authenticated_probes": authenticated,
        }

    def _public_probes(self) -> Sequence[Mapping[str, object]]:
        result: list[dict[str, object]] = []
        for probe_id, spec in HTTP_PROBE_SPECS.items():
            current = str(spec["url"])
            redirects: list[dict[str, object]] = []
            body = b""
            headers: Mapping[str, str] = {}
            status = 0
            for _ in range(4):
                status, headers, body = _fixed_https_json(
                    url=current, limit=_HTTP_LIMIT
                )
                if status not in {301, 302, 303, 307, 308}:
                    break
                location = headers.get("Location")
                if not location or len(redirects) >= 3:
                    raise ReleaseManifestError("fixed HTTPS redirect chain is invalid")
                next_url = urljoin(current, location)
                parsed = urlsplit(next_url)
                allowed = {
                    urlsplit(str(spec["url"])).hostname,
                    urlsplit(str(spec["effective_url"])).hostname,
                }
                if (
                    parsed.scheme != "https"
                    or parsed.hostname not in allowed
                    or parsed.username
                    or parsed.password
                ):
                    raise ReleaseManifestError("fixed HTTPS redirect left allowlist")
                redirects.append({"status": status, "location": location})
                current = next_url
            parsed_requested = urlsplit(str(spec["url"]))
            result.append(
                {
                    "probe_id": probe_id,
                    "requested_url": spec["url"],
                    "effective_url": current,
                    "redirect_chain": redirects,
                    "status": status,
                    "headers": headers,
                    "body": body,
                    "tls": _collect_tls(
                        parsed_requested.hostname or "",
                        repository_root=self.root,
                    ),
                }
            )
        return result

    def _pages(self) -> Mapping[str, object]:
        base = "/repos/asadvendor-boop/concordia-dao-council"
        pages = _mapping(
            _fixed_github_api(self.root, base + "/pages"), "GitHub Pages API"
        )
        runs = _mapping(
            _fixed_github_api(
                self.root,
                base + "/actions/workflows/docs-pages.yml/runs?per_page=1",
            ),
            "GitHub workflow API",
        )
        deployments = _fixed_github_api(
            self.root,
            base + "/deployments?environment=github-pages&per_page=1",
        )
        workflow_runs = _sequence(runs.get("workflow_runs"), "Pages workflow runs")
        if not workflow_runs or type(deployments) is not list or not deployments:
            raise ReleaseManifestError(
                "GitHub Pages deployment evidence is unavailable"
            )
        workflow = _mapping(workflow_runs[0], "Pages workflow")
        deployment = _mapping(deployments[0], "Pages deployment")
        deployment_id = deployment.get("id")
        if type(deployment_id) is not int or deployment_id < 1:
            raise ReleaseManifestError("GitHub Pages deployment ID is invalid")
        statuses = _fixed_github_api(
            self.root,
            base + f"/deployments/{deployment_id}/statuses?per_page=1",
        )
        if type(statuses) is not list or not statuses or type(statuses[0]) is not dict:
            raise ReleaseManifestError("GitHub Pages deployment status is unavailable")
        deployment_status = statuses[0]
        sha = workflow.get("head_sha")
        # release-identity.json is workflow-generated and fetched from Pages.
        identity_status, _, identity_raw = _fixed_https_json(
            url="https://docs.concordiadao.xyz/release-identity.json"
        )
        if identity_status != 200:
            raise ReleaseManifestError("Pages release identity is unavailable")
        identity = _decode_json_response(identity_raw, "Pages release identity")
        return {
            "repository": "asadvendor-boop/concordia-dao-council",
            "build_type": pages.get("build_type"),
            "cname": pages.get("cname"),
            "html_url": pages.get("html_url"),
            "https_enforced": pages.get("https_enforced"),
            "workflow": {
                "name": "docs-pages",
                "status": workflow.get("status"),
                "conclusion": workflow.get("conclusion"),
                "head_sha": sha,
                "run_id": workflow.get("id"),
            },
            "deployment": {
                "environment": deployment.get("environment"),
                "status": deployment_status.get("state"),
                "sha": deployment.get("sha"),
                "deployment_id": deployment_id,
            },
            "release_identity": identity,
        }

    def _npm(self) -> Mapping[str, object]:
        status, _, raw = _fixed_https_json(
            url="https://registry.npmjs.org/@concordia-dao%2Fverify/latest"
        )
        if status != 200:
            raise ReleaseManifestError("public npm registry observation failed")
        metadata = _decode_json_response(raw, "npm registry metadata")
        dist = _mapping(metadata.get("dist"), "npm dist")
        tarball_url = _text(dist.get("tarball"), "npm tarball URL")
        _validate_npm_tarball_url(tarball_url)
        packument_status, _, packument_raw = _fixed_https_json(
            url="https://registry.npmjs.org/@concordia-dao%2Fverify"
        )
        if packument_status != 200:
            raise ReleaseManifestError("public npm publish chronology is unavailable")
        packument = _decode_json_response(packument_raw, "npm package history")
        published_times = _mapping(packument.get("time"), "npm publish times")
        version = _text(metadata.get("version"), "npm published version")
        published_at = published_times.get(version)
        status, _, tarball = _fixed_https_json(url=tarball_url, limit=_NPM_LIMIT)
        if status != 200:
            raise ReleaseManifestError("public npm tarball download failed")
        tarball_sha256 = hashlib.sha256(tarball).hexdigest()
        computed_integrity = "sha512-" + base64.b64encode(
            hashlib.sha512(tarball).digest()
        ).decode("ascii")
        if dist.get("integrity") != computed_integrity:
            raise ReleaseManifestError(
                "npm registry integrity differs from tarball bytes"
            )
        registry_signatures = _verify_npm_registry_signatures(
            repository_root=self.root,
            version=version,
            tarball_url=tarball_url,
            integrity=computed_integrity,
        )
        # Execute package code only after registry integrity and signatures
        # authenticate the exact downloaded bytes.
        source_commit = _git40(metadata.get("gitHead"), "npm registry gitHead")
        package_projection = _inspect_npm_tarball(
            tarball,
            self.root,
            source_commit=source_commit,
        )
        return {
            "metadata": {
                "name": metadata.get("name"),
                "version": version,
                "gitHead": metadata.get("gitHead"),
                "time": published_at,
                "dist": {
                    "tarball": tarball_url,
                    "integrity": dist.get("integrity"),
                },
            },
            "tarball": tarball,
            "tarball_sha256": tarball_sha256,
            "registry_signatures": registry_signatures,
            "package_projection": package_projection,
        }

    def _rpc(self) -> Sequence[Mapping[str, object]]:
        request_id = 1
        status_request = _canonical_json(
            {
                "id": request_id,
                "jsonrpc": "2.0",
                "method": "info_get_status",
                "params": {},
            }
        ).rstrip(b"\n")
        association_status = _rpc_call(
            RPC_PROVIDERS["casper_association"]["endpoint"],
            status_request,
            authorization=None,
        )
        association_chain = _rpc_chain_name(association_status)
        latest_request = _canonical_json(
            {
                "id": request_id,
                "jsonrpc": "2.0",
                "method": "chain_get_block",
                "params": {},
            }
        ).rstrip(b"\n")
        first = _rpc_call(
            RPC_PROVIDERS["casper_association"]["endpoint"],
            latest_request,
            authorization=None,
        )
        first_result = _rpc_block_projection(first, chain_name=association_chain)
        same_request = _canonical_json(
            {
                "id": request_id,
                "jsonrpc": "2.0",
                "method": "chain_get_block",
                "params": {"block_identifier": {"Hash": first_result["block_hash"]}},
            }
        ).rstrip(b"\n")
        token = _read_secret_file(
            Path("/run/secrets/cspr_cloud_access_token")
        ) or _read_secret_file(
            Path("/opt/apps/concordia/secrets/cspr_cloud_access_token")
        )
        if not token:
            raise ReleaseManifestError("CSPR.cloud RPC credential file is unavailable")
        cloud_status = _rpc_call(
            RPC_PROVIDERS["cspr_cloud"]["endpoint"],
            status_request,
            authorization=token,
        )
        cloud_chain = _rpc_chain_name(cloud_status)
        second = _rpc_call(
            RPC_PROVIDERS["cspr_cloud"]["endpoint"],
            same_request,
            authorization=token,
        )
        second_result = _rpc_block_projection(second, chain_name=cloud_chain)
        return [
            {
                "provider_id": provider_id,
                "operator_id": expected["operator_id"],
                "endpoint": expected["endpoint"],
                "authentication_mode": expected["authentication"],
                "method": "chain_get_block",
                "result": result,
            }
            for (provider_id, expected), result in zip(
                RPC_PROVIDERS.items(), (first_result, second_result), strict=True
            )
        ]

    def collect(self) -> RawObservationSnapshot:
        compose = self._compose()
        runtime = self._runtime()
        public_probes = self._public_probes()
        pages = self._pages()
        npm = self._npm()
        rpc_without_time = self._rpc()
        # The approval password is deliberately one-use.  Consume it only
        # after every other observation succeeds so an unrelated outage cannot
        # waste the operator-provided credential before the Caddy probe.
        caddy = self._caddy()
        observed_at = _format_now(_utc_now())
        rpc = [
            {**_mapping(item, "RPC collector item"), "observed_at": observed_at}
            for item in rpc_without_time
        ]
        return RawObservationSnapshot(
            observed_at=observed_at,
            compose=compose,
            runtime=runtime,
            caddy=caddy,
            public_probes=public_probes,
            pages=pages,
            npm=npm,
            rpc=rpc,
        )


def _inspect_npm_tarball(
    raw: bytes,
    repository_root: Path,
    *,
    source_commit: str,
) -> dict[str, object]:
    source_commit = _git40(source_commit, "npm package source commit")
    files: list[str] = []
    package_json: dict[str, object] | None = None
    members: list[tuple[str, bytes, int]] = []
    total_unpacked = 0
    try:
        with tarfile.open(
            fileobj=__import__("io").BytesIO(raw), mode="r:gz"
        ) as archive:
            for member in archive.getmembers():
                name = PurePosixPath(member.name)
                if (
                    name.is_absolute()
                    or ".." in name.parts
                    or not name.parts
                    or name.parts[0] != "package"
                    or len(name.parts) < 2
                    or member.issym()
                    or member.islnk()
                ):
                    raise ReleaseManifestError("npm tarball has an unsafe path")
                if not member.isfile():
                    continue
                if member.size < 0 or member.size > _NPM_LIMIT:
                    raise ReleaseManifestError("npm tarball member exceeds size bound")
                total_unpacked += member.size
                if total_unpacked > 64 * 1024 * 1024:
                    raise ReleaseManifestError(
                        "npm tarball unpacked size exceeds bound"
                    )
                relative = PurePosixPath(*name.parts[1:]).as_posix()
                _validate_relative_path(relative)
                if relative in files:
                    raise ReleaseManifestError("npm tarball has a duplicate member")
                files.append(relative)
                stream = archive.extractfile(member)
                if stream is None:
                    raise ReleaseManifestError("npm tarball member is unavailable")
                member_bytes = stream.read(member.size + 1)
                if len(member_bytes) != member.size:
                    raise ReleaseManifestError("npm tarball member size differs")
                members.append((relative, member_bytes, member.mode & 0o111))
                if relative == "package.json":
                    package_json, _ = _strict_json(member_bytes, "npm package.json")
    except (tarfile.TarError, OSError) as exc:
        raise ReleaseManifestError("npm tarball is invalid") from exc
    if package_json is None:
        raise ReleaseManifestError("npm tarball lacks package.json")
    if (
        package_json.get("name") != "@concordia-dao/verify"
        or package_json.get("type") != "module"
        or package_json.get("bin") != {"concordia-verify": "dist/cli.js"}
    ):
        raise ReleaseManifestError("npm tarball package contract differs")
    scripts = _mapping(package_json.get("scripts"), "npm package scripts")
    if set(scripts) - {
        "build",
        "clean",
        "lint",
        "test",
        "test:unit",
        "prepack",
    } or any(
        name in scripts
        for name in (
            "install",
            "postinstall",
            "preinstall",
            "prepare",
            "prepublish",
            "prepublishOnly",
        )
    ):
        raise ReleaseManifestError("npm package lifecycle script policy differs")
    with tempfile.TemporaryDirectory(prefix="concordia-verify-release-") as temporary:
        temporary_root = Path(temporary).resolve(strict=True)
        source_root = temporary_root / "source"
        source_root.mkdir(mode=0o700)
        archive = _git(
            repository_root,
            [
                "archive",
                "--format=tar",
                source_commit,
            ],
            limit=_VERIFIER_ARCHIVE_LIMIT,
        ).stdout
        if not archive:
            raise ReleaseManifestError("npm source archive is empty")
        try:
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
                for member in source.getmembers():
                    original = PurePosixPath(member.name)
                    if (
                        original.is_absolute()
                        or not original.parts
                        or ".." in original.parts
                        or member.issym()
                        or member.islnk()
                        or member.isdev()
                    ):
                        raise ReleaseManifestError(
                            "npm source archive contains an unsafe path"
                        )
                    target = source_root.joinpath(*original.parts)
                    if member.isdir():
                        target.mkdir(mode=0o700, parents=True, exist_ok=True)
                        continue
                    if not member.isfile() or member.size < 0:
                        raise ReleaseManifestError(
                            "npm source archive contains a non-file entry"
                        )
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    stream = source.extractfile(member)
                    if stream is None:
                        raise ReleaseManifestError(
                            "npm source archive member is unavailable"
                        )
                    member_raw = stream.read(member.size + 1)
                    if len(member_raw) != member.size:
                        raise ReleaseManifestError(
                            "npm source archive member size differs"
                        )
                    descriptor = os.open(
                        target,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | os.O_CLOEXEC
                        | getattr(os, "O_NOFOLLOW", 0),
                        0o700 if member.mode & 0o111 else 0o600,
                    )
                    try:
                        view = memoryview(member_raw)
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                raise ReleaseManifestError(
                                    "npm source extraction made no progress"
                                )
                            view = view[written:]
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
        except tarfile.TarError as exc:
            raise ReleaseManifestError("npm source archive is invalid") from exc
        rebuild_root = source_root / "packages" / "verify"
        if not rebuild_root.is_dir():
            raise ReleaseManifestError("npm package source is unavailable at gitHead")
        _run(
            rebuild_root,
            [
                "npm",
                "ci",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                "--registry=https://registry.npmjs.org/",
            ],
            limit=_GIT_OUTPUT_LIMIT,
            timeout=180,
            repository_root=repository_root,
            bound_data_inputs=(
                rebuild_root / "package.json",
                rebuild_root / "package-lock.json",
            ),
        )
        _run(
            rebuild_root,
            ["npm", "run", "clean"],
            limit=_GIT_OUTPUT_LIMIT,
            timeout=180,
            repository_root=repository_root,
        )
        _run(
            rebuild_root,
            ["npm", "run", "build"],
            limit=_GIT_OUTPUT_LIMIT,
            timeout=180,
            repository_root=repository_root,
        )
        pack_result = _run(
            rebuild_root,
            ["npm", "pack", "--ignore-scripts", "--json"],
            limit=_CONTROL_LIMIT,
            timeout=180,
            repository_root=repository_root,
        )
        try:
            pack_document = json.loads(
                pack_result.stdout.decode("utf-8"),
                object_pairs_hook=_pairs,
                parse_constant=_reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReleaseManifestError(
                "reproduced npm pack result is not strict JSON"
            ) from exc
        if (
            type(pack_document) is not list
            or len(pack_document) != 1
            or type(pack_document[0]) is not dict
        ):
            raise ReleaseManifestError("reproduced npm pack result differs")
        filename = _text(
            pack_document[0].get("filename"),
            "reproduced npm tarball filename",
        )
        if PurePosixPath(filename).name != filename:
            raise ReleaseManifestError("reproduced npm tarball path is unsafe")
        reproduced_raw = _read_bounded_repository_file(
            rebuild_root,
            filename,
            _NPM_LIMIT,
        ).raw
        reproduced_members: dict[str, tuple[bytes, int]] = {}
        try:
            with tarfile.open(
                fileobj=io.BytesIO(reproduced_raw),
                mode="r:gz",
            ) as reproduced:
                for member in reproduced.getmembers():
                    name = PurePosixPath(member.name)
                    if (
                        not member.isfile()
                        or not name.parts
                        or name.parts[0] != "package"
                        or len(name.parts) < 2
                    ):
                        continue
                    relative = PurePosixPath(*name.parts[1:]).as_posix()
                    stream = reproduced.extractfile(member)
                    if stream is None or relative in reproduced_members:
                        raise ReleaseManifestError(
                            "reproduced npm tarball inventory differs"
                        )
                    member_raw = stream.read(member.size + 1)
                    if len(member_raw) != member.size:
                        raise ReleaseManifestError(
                            "reproduced npm tarball member size differs"
                        )
                    reproduced_members[relative] = (
                        member_raw,
                        member.mode & 0o111,
                    )
        except tarfile.TarError as exc:
            raise ReleaseManifestError(
                "reproduced npm tarball is invalid"
            ) from exc
        registry_members = {
            relative: (member_raw, executable)
            for relative, member_raw, executable in members
        }
        if reproduced_members != registry_members:
            raise ReleaseManifestError(
                "npm registry tarball differs from an exact source rebuild"
            )
        package_root = temporary_root / "package"
        package_root.mkdir(mode=0o700)
        for relative, member_bytes, executable in members:
            target = package_root / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(
                target,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_CLOEXEC
                | os.O_NONBLOCK
                | getattr(os, "O_NOFOLLOW", 0),
                0o700 if executable else 0o600,
            )
            try:
                view = memoryview(member_bytes)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise ReleaseManifestError("npm extraction made no progress")
                    view = view[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        tarball_path = temporary_root / "concordia-dao-verify.tgz"
        descriptor = os.open(
            tarball_path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NONBLOCK
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            view = memoryview(raw)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise ReleaseManifestError("npm tarball write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        consumer_root = temporary_root / "consumer"
        consumer_root.mkdir(mode=0o700)
        consumer_package = _canonical_json(
            {
                "name": "concordia-release-consumer-smoke",
                "private": True,
                "type": "module",
                "version": "0.0.0",
                "dependencies": {
                    "@concordia-dao/verify": "file:../concordia-dao-verify.tgz"
                },
            }
        )
        consumer_package_path = consumer_root / "package.json"
        descriptor = os.open(
            consumer_package_path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | os.O_NONBLOCK
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            view = memoryview(consumer_package)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise ReleaseManifestError(
                        "npm consumer package write made no progress"
                    )
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _run(
            consumer_root,
            [
                "npm",
                "install",
                "--ignore-scripts",
                "--offline",
                "--no-audit",
                "--no-fund",
            ],
            limit=_CONTROL_LIMIT,
            timeout=180,
            repository_root=repository_root,
        )
        installed_root = consumer_root / "node_modules" / "@concordia-dao" / "verify"
        installed_digest = hashlib.sha256()
        member_by_path = {
            relative: member_bytes for relative, member_bytes, _ in members
        }
        try:
            installed_root_metadata = installed_root.lstat()
        except OSError as exc:
            raise ReleaseManifestError(
                "clean npm consumer install is incomplete"
            ) from exc
        if stat.S_ISLNK(installed_root_metadata.st_mode) or not stat.S_ISDIR(
            installed_root_metadata.st_mode
        ):
            raise ReleaseManifestError("clean npm consumer install is unsafe")
        installed_inventory: set[str] = set()
        for current_root, directory_names, file_names in os.walk(
            installed_root,
            topdown=True,
            followlinks=False,
        ):
            current = Path(current_root)
            for name in directory_names:
                metadata = (current / name).lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                    raise ReleaseManifestError("clean npm consumer install is unsafe")
            for name in file_names:
                installed = current / name
                metadata = installed.lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                    raise ReleaseManifestError("clean npm consumer install is unsafe")
                installed_inventory.add(
                    installed.relative_to(installed_root).as_posix()
                )
        if installed_inventory != set(member_by_path):
            raise ReleaseManifestError(
                "clean npm consumer install inventory differs from tarball"
            )
        for relative in sorted(member_by_path):
            installed = installed_root.joinpath(*PurePosixPath(relative).parts)
            try:
                metadata = installed.lstat()
            except OSError as exc:
                raise ReleaseManifestError(
                    "clean npm consumer install is incomplete"
                ) from exc
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise ReleaseManifestError("clean npm consumer install is unsafe")
            installed_bytes = installed.read_bytes()
            if installed_bytes != member_by_path[relative]:
                raise ReleaseManifestError(
                    "clean npm consumer install differs from tarball"
                )
            installed_digest.update(len(relative).to_bytes(4, "big"))
            installed_digest.update(relative.encode("utf-8"))
            installed_digest.update(len(installed_bytes).to_bytes(8, "big"))
            installed_digest.update(installed_bytes)
        now = _format_now(_utc_now())
        bundle = _materialize_local_verifier_bundle(
            repository_root,
            generated_at=now,
        )
        try:
            self_test = _run(
                consumer_root,
                [
                    "node",
                    str(installed_root / "dist/cli.js"),
                    "local",
                    str(bundle.registry_path),
                    "--now",
                    now,
                ],
                limit=_CONTROL_LIMIT,
                timeout=180,
                repository_root=repository_root,
                command_asset_root=consumer_root,
                bound_data_inputs=(bundle.registry_path,),
            ).stdout
            bundle.revalidate()
        finally:
            bundle.cleanup()
        self_test_document, _ = _strict_json(self_test, "npm verifier self-test")
        if (
            self_test_document.get("tool") != "@concordia-dao/verify"
            or self_test_document.get("status") != "verified"
            or self_test_document.get("valid") is not True
            or self_test_document.get("exitCode") != 0
        ):
            raise ReleaseManifestError("npm verifier offline self-test failed")
    self_test_digest = hashlib.sha256(self_test).hexdigest()
    return {
        "name": package_json.get("name"),
        "version": package_json.get("version"),
        "sourceCommit": source_commit,
        "files": sorted(files),
        "consumer_install_sha256": installed_digest.hexdigest(),
        "self_test_digest": self_test_digest,
    }


def _rpc_call(
    endpoint: str, request: bytes, *, authorization: bytes | None
) -> dict[str, object]:
    headers = {"Content-Type": "application/json"}
    if authorization is not None:
        # CSPR.cloud expects the token directly, never ``Bearer <token>``.
        try:
            headers["Authorization"] = authorization.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ReleaseManifestError(
                "CSPR.cloud credential encoding is invalid"
            ) from exc
    status, _, raw = _fixed_https_json(
        url=endpoint,
        method="POST",
        body=request,
        headers=headers,
        limit=_CONTROL_LIMIT,
    )
    if status != 200:
        # Do not parse or expose a response that may reflect Authorization.
        raise ReleaseManifestError("fixed RPC provider request failed")
    response = _decode_json_response(raw, "fixed RPC response")
    if (
        set(response) != {"jsonrpc", "id", "result"}
        or response.get("jsonrpc") != "2.0"
        or response.get("id") != 1
        or type(response.get("result")) is not dict
    ):
        raise ReleaseManifestError("fixed RPC response envelope is not exact")
    return response


def _rpc_chain_name(response: Mapping[str, object]) -> str:
    result = _mapping(response.get("result"), "RPC status result")
    value = result.get("chainspec_name") or result.get("chain_name")
    return _text(value, "RPC chainspec name")


def _rpc_block_projection(
    response: Mapping[str, object], *, chain_name: str
) -> dict[str, object]:
    result = _mapping(response.get("result"), "RPC result")
    block = _mapping(result.get("block"), "RPC block")
    header = _mapping(block.get("header"), "RPC block header")
    return {
        "chain_name": chain_name,
        "block_hash": block.get("hash"),
        "block_height": header.get("height"),
        "state_root_hash": header.get("state_root_hash"),
        "block_timestamp": header.get("timestamp"),
        "protocol_version": header.get("protocol_version"),
    }


def _collector_factory(root: Path) -> _Collector:
    return _DefaultCollector(root)


__all__ = [
    "ARTIFACT_PATHS",
    "COMPOSE_FILE_PATH",
    "HTTP_PROBE_SPECS",
    "NPM_CAPTURE_PATH",
    "PROOF_RECEIPT_PATHS",
    "PUBLIC_URLS",
    "RECEIPT_PATHS",
    "RELEASE_MANIFEST_PATH",
    "RPC_PROVIDERS",
    "RawObservationSnapshot",
    "ReleaseManifestError",
    "SCHEMA_VERSION",
    "assemble_release_manifest_once",
    "capture_organizer_link_audit_once",
    "capture_release_observations_once",
]
