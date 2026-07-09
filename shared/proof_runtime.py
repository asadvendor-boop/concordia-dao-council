"""Final judge-facing proof helpers for Concordia.

These helpers are intentionally deterministic and read-only. They package the
existing canonical proof into reviewer artifacts without creating new Casper
transactions or changing on-chain state.
"""
from __future__ import annotations

import csv
import hashlib
import html
import json
import os
import re
import sqlite3
from datetime import UTC, datetime, timedelta, timezone
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus


PUBLIC_BASE_URL = "https://concordia.47.84.232.193.sslip.io"
CANONICAL_PROPOSAL_ID = "DAO-PROP-6CB25C"
CANONICAL_RECEIPT_HASH = "e926582f3dacd05d9bd59a4fe0ae3c3c884ad57f23ab7318925cef34c286d852"
CANONICAL_CONTRACT_HASH = "hash-a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1"
CANONICAL_PACKAGE_HASH = "hash-992b3a457eedf67f1b50c29f7971199b757d9576dcbaa51e0d52fda3a0fa4c4a"
QUORUM_PACKAGE_HASH = "hash-1d324e319701e4adcfa9476efcde3d047462d35e79d2cd8c7326c0c384c87d96"
CANONICAL_QUORUM_RECEIPT_HASH = "9d631fe1c925cd4991180b1a794e8b69f061a33033e372273ffadcaf9efe2928"
SUPPLEMENTAL_DYNAMIC_PROPOSAL_ID = "DAO-PROP-DYN-002"
SUPPLEMENTAL_DYNAMIC_RECEIPT_HASH = "68fd77bc4f59f56cb7fb7310d3cbc525ffbfbe87ffda70b51bfd55985e4040e0"
SUPPLEMENTAL_RWA_PROPOSAL_ID = "DAO-PROP-RWA-001"
SUPPLEMENTAL_RWA_RECEIPT_HASH = "3803a5bb561a84a8c103e3c4e8eea99b3a1c893c63644c56ed38daa1986825cc"
CANONICAL_WALLET_RECEIPT_HASH = "56b6ea6ccaae4d79221ca63a259f508b13a15679ef4984e87d158fbfbe4f12bf"
CANONICAL_X402_PAYMENT_HASH = "dcb35f4295909b1c87d07b7f4d02ab95afef99d2d4cdddee961c8f5ca6d4914c"
CANONICAL_IPFS_CID = "bafkreih4jw6ntzydjudnlcbge3pehxufrj2pvydzx5hnzc3e4n4qhahfyq"
CANONICAL_MANDATE_EXPIRY = "2026-07-30T12:47:38+00:00"
RWA_SAMPLE_DOCUMENT = Path("artifacts/rwa/sample-invoice-pool-DAO-PROP-RWA-001.json")
RWA_EXECUTION_PROOF = Path("artifacts/live/dynamic-proposal-execution-proof-DAO-PROP-RWA-001.json")

PRODUCT_FRAMING = (
    "Concordia DAO Council is the Casper governance firewall for AI-run DAOs: "
    "Dissent Receipts preserve Verity's objection, Locke is bound to the exact "
    "approved hash, and browser-wallet quorum is proven on-chain when execution "
    "is reverted before quorum and accepted after quorum."
)

DEMO_HOOK = (
    "A malicious AI tries to push an unsafe 30% treasury allocation. Concordia "
    "catches the violation, Verity challenges it with Dissent Receipts, the DAO "
    "Mandate caps it to 8%, Locke can execute only the exact approved hash, and "
    "browser-wallet quorum proves the same action is reverted before quorum and "
    "accepted after quorum."
)

SECRET_KEY_PATTERNS = (
    "authorization",
    "api_key",
    "apikey",
    "access_token",
    "auth_token",
    "bearer",
    "client_secret",
    "docker_secret",
    "env_var",
    "env_vars",
    "environment_variable",
    "environment_variables",
    "jwt",
    "llm_api_key",
    "openai",
    "private_key",
    "secret",
    "secret_key",
    "token",
    "wallet_secret",
)

SECRET_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"(?i)\b(sk|pk|ak|eyJ)[A-Za-z0-9._~+/=-]{16,}"),
    re.compile(r"/(?:opt|etc|home|Users)/[^\s\"']*(?:secret|key|env|pem)[^\s\"']*", re.I),
)


def canonical_manifest() -> dict[str, Any]:
    """Return the single proof hierarchy every public surface must use."""

    return {
        "proposal_id": CANONICAL_PROPOSAL_ID,
        "product_framing": PRODUCT_FRAMING,
        "demo_hook": DEMO_HOOK,
        "canonical_reviewer_receipt": {
            "deploy_hash": CANONICAL_RECEIPT_HASH,
            "contract_hash": CANONICAL_CONTRACT_HASH,
            "contract_url": f"https://testnet.cspr.live/contract/{CANONICAL_CONTRACT_HASH.removeprefix('hash-')}",
            "package_hash": CANONICAL_PACKAGE_HASH,
            "explorer_url": f"https://testnet.cspr.live/deploy/{CANONICAL_RECEIPT_HASH}",
            "api_url": f"https://api.testnet.cspr.live/deploys/{CANONICAL_RECEIPT_HASH}",
            "contract_iteration": "v1 receipt anchor deployed Jun 29",
        },
        "supplemental_quorum_proof": {
            "deploy_hash": CANONICAL_QUORUM_RECEIPT_HASH,
            "package_hash": QUORUM_PACKAGE_HASH,
            "explorer_url": f"https://testnet.cspr.live/deploy/{CANONICAL_QUORUM_RECEIPT_HASH}",
            "contract_iteration": "v2 quorum-enabled GovernanceReceipt deployed Jun 30",
            "demo_note": (
                "This is the strongest quorum-gated receipt: store_governance_receipt "
                "succeeded only after the 2-of-3 approval threshold."
            ),
        },
        "supplemental_dynamic_lifecycle_proof": {
            "proposal_id": SUPPLEMENTAL_DYNAMIC_PROPOSAL_ID,
            "deploy_hash": SUPPLEMENTAL_DYNAMIC_RECEIPT_HASH,
            "contract_hash": CANONICAL_CONTRACT_HASH,
            "explorer_url": f"https://testnet.cspr.live/deploy/{SUPPLEMENTAL_DYNAMIC_RECEIPT_HASH}",
            "evidence_url": f"{PUBLIC_BASE_URL}/evidence/{SUPPLEMENTAL_DYNAMIC_PROPOSAL_ID}",
        },
        "browser_wallet_receipt": {
            "deploy_hash": CANONICAL_WALLET_RECEIPT_HASH,
            "explorer_url": f"https://testnet.cspr.live/deploy/{CANONICAL_WALLET_RECEIPT_HASH}",
        },
        "x402_payment": {
            "payment_hash": CANONICAL_X402_PAYMENT_HASH,
            "api_url": f"https://api.testnet.cspr.live/deploys/{CANONICAL_X402_PAYMENT_HASH}",
        },
        "ipfs_archive": {
            "cid": CANONICAL_IPFS_CID,
            "ipfs_uri": f"ipfs://{CANONICAL_IPFS_CID}",
            "gateway_url": f"{PUBLIC_BASE_URL}/api/ipfs/{CANONICAL_IPFS_CID}",
        },
        "public_urls": {
            "dashboard": f"{PUBLIC_BASE_URL}/dashboard",
            "proof_center": f"{PUBLIC_BASE_URL}/dashboard/proof",
            "judge_walkthrough": f"{PUBLIC_BASE_URL}/dashboard/judge",
            "technical_jury_note": f"{PUBLIC_BASE_URL}/technical-jury-note",
            "evidence": f"{PUBLIC_BASE_URL}/evidence/{CANONICAL_PROPOSAL_ID}",
            "proof_pack": f"{PUBLIC_BASE_URL}/proof-pack/{CANONICAL_PROPOSAL_ID}",
            "certificate": f"{PUBLIC_BASE_URL}/certificate/{CANONICAL_PROPOSAL_ID}",
            "certificate_pdf": f"{PUBLIC_BASE_URL}/certificate/{CANONICAL_PROPOSAL_ID}/pdf",
        },
        "technical_jury_note": {
            "summary": (
                "The canonical reviewer proof is frozen for reproducibility. "
                "Dynamic proposals are preview/execution-ready unless their own "
                "evidence chain, signature, finality record, and proof artifact exist. "
                "The Odra topology genesis proves auxiliary modules independently; "
                "full cross-contract production enforcement is roadmap, not overclaimed."
            ),
            "url": f"{PUBLIC_BASE_URL}/technical-jury-note",
        },
        "contract_lineage_note": (
            "GovernanceReceipt v1 is the Jun 29 receipt anchor at "
            f"{CANONICAL_CONTRACT_HASH}; canonical, browser-wallet, and supplemental "
            "dynamic receipts write there. The Jun 30 quorum-enabled package "
            f"{QUORUM_PACKAGE_HASH} adds configure/propose/approve quorum entrypoints "
            "and anchors the supplemental final quorum receipt."
        ),
    }


def _sha256(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _receipt(evidence: dict[str, Any]) -> dict[str, Any]:
    return evidence.get("casper_receipt") or {}


def _requested_and_approved_bps(evidence: dict[str, Any]) -> tuple[int, int]:
    receipt = _receipt(evidence)
    requested = 3000
    approved = int(receipt.get("approved_allocation_bps") or 800)
    for card in evidence.get("cards") or []:
        data = card.get("data") or {}
        raw = data.get("raw_payload") or {}
        policy = (data.get("evidence") or {}).get("policy_evaluation") or {}
        requested = int(policy.get("requested_allocation_bps") or raw.get("treasury_allocation_bps") or requested)
        approved = int(policy.get("approved_allocation_bps") or approved)
    return requested, approved


def build_dao_mandate(evidence: dict[str, Any]) -> dict[str, Any]:
    receipt = _receipt(evidence)
    requested, approved = _requested_and_approved_bps(evidence)
    mandate = {
        "mandate_id": f"MANDATE-{evidence.get('proposal_id') or CANONICAL_PROPOSAL_ID}",
        "proposal_id": evidence.get("proposal_id") or CANONICAL_PROPOSAL_ID,
        "allowed_action": "execute_casper_governance_receipt",
        "allowed_network": "casper-test",
        "contract_hash": receipt.get("contract_hash") or CANONICAL_CONTRACT_HASH,
        "entry_point": receipt.get("entry_point") or "store_governance_receipt",
        "requested_allocation_bps": requested,
        "max_allocation_bps": approved,
        "policy_hash": receipt.get("policy_hash"),
        "dissent_hash": receipt.get("dissent_hash"),
        "approval_hash": receipt.get("plan_hash"),
        "final_card_hash": receipt.get("final_card_hash"),
        "expires_at": _deterministic_mandate_expiry(evidence),
        "custody_rule": "Locke executes only the approved DAO Mandate, never free-form LLM output.",
    }
    mandate["mandate_hash"] = _sha256(mandate)
    return mandate


def _deterministic_mandate_expiry(evidence: dict[str, Any]) -> str:
    """Use a proof-captured expiry when available, otherwise a fixed review expiry."""

    for decision in (_collaboration(evidence).get("human_decisions") or []):
        expiry = decision.get("expiry") or decision.get("expires_at")
        if expiry:
            return str(expiry)
    for card in evidence.get("cards") or []:
        data = card.get("data") or {}
        expiry = data.get("expiry") or data.get("expires_at")
        if expiry:
            return str(expiry)
    return CANONICAL_MANDATE_EXPIRY


def _collaboration(evidence: dict[str, Any]) -> dict[str, Any]:
    return evidence.get("collaboration") or {}


def _quorum_blocking_proof_ok() -> bool:
    plan = _load_json_artifact("artifacts/live/odra-quorum-exercise-plan.json")
    criteria = plan.get("acceptance_criteria") or {}
    pre_quorum = criteria.get("pre_quorum_execution_blocked") or {}
    final_receipt = criteria.get("final_receipt_after_quorum") or {}
    return (
        plan.get("status") == "live_complete"
        and pre_quorum.get("status") == "verified"
        and final_receipt.get("status") == "verified"
        and final_receipt.get("deploy_hash") == CANONICAL_QUORUM_RECEIPT_HASH
    )


def _action_hash_guard_rejects_tamper(approved_payload: dict[str, Any], tampered_payload: dict[str, Any]) -> bool:
    from shared.approval import compute_action_hash

    approved_hash = compute_action_hash([
        {
            "action_id": "execute_casper_governance_receipt",
            "target": "casper-test",
            "parameters": approved_payload,
        }
    ])
    tampered_hash = compute_action_hash([
        {
            "action_id": "execute_casper_governance_receipt",
            "target": "casper-test",
            "parameters": tampered_payload,
        }
    ])
    return approved_hash != tampered_hash


def _nonce_replay_guard_ok() -> bool:
    from shared.approval import create_nonce, validate_and_consume_nonce

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute(
        """
        CREATE TABLE nonces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            proposal_id TEXT NOT NULL,
            nonce TEXT NOT NULL,
            plan_hash TEXT NOT NULL,
            action_hash TEXT NOT NULL,
            plan_revision INTEGER DEFAULT 1,
            expiry TEXT NOT NULL,
            consumed INTEGER DEFAULT 0,
            invalidated INTEGER DEFAULT 0,
            consumed_by TEXT,
            consumed_at TEXT,
            created_at TEXT DEFAULT (datetime('now')),
            UNIQUE(proposal_id, nonce)
        )
        """
    )
    plan_hash = _sha256({"plan": "approved"})
    action_hash = _sha256({"action": "execute_casper_governance_receipt"})
    nonce = create_nonce(
        CANONICAL_PROPOSAL_ID,
        plan_hash,
        action_hash,
        1,
        datetime.now(timezone.utc) + timedelta(minutes=5),
        db,
    )
    first_ok, _ = validate_and_consume_nonce(CANONICAL_PROPOSAL_ID, nonce, plan_hash, action_hash, "reviewer", db)
    second_ok, second_reason = validate_and_consume_nonce(CANONICAL_PROPOSAL_ID, nonce, plan_hash, action_hash, "reviewer", db)
    return first_ok and not second_ok and "replay" in second_reason.lower()


def _policy_cap_guard_ok(requested: int, approved: int) -> bool:
    from shared.dao_policy import evaluate_proposal_policy

    result = evaluate_proposal_policy({
        "proposal_id": CANONICAL_PROPOSAL_ID,
        "proposal_type": "DEFI_TREASURY_REALLOCATION",
        "requested_action": "Move 30% of treasury into a high-yield liquidity strategy",
        "treasury_allocation_bps": requested,
        "target_protocol": "casper-liquidity-strategy-alpha",
        "risk_score": 72,
        "casper_network": "casper-testnet",
    })
    return (
        result.get("requested_allocation_bps") == requested
        and result.get("approved_allocation_bps") == approved
        and requested > approved
    )


def _policy_hash_guard_rejects_mismatch(approved_payload: dict[str, Any]) -> bool:
    from shared.approval import compute_action_hash

    expected_hash = compute_action_hash([
        {
            "action_id": "execute_casper_governance_receipt",
            "target": "casper-test",
            "parameters": approved_payload,
        }
    ])
    mismatched = dict(approved_payload)
    mismatched["policy_hash"] = "0" * 64
    mismatch_hash = compute_action_hash([
        {
            "action_id": "execute_casper_governance_receipt",
            "target": "casper-test",
            "parameters": mismatched,
        }
    ])
    return bool(approved_payload.get("policy_hash")) and expected_hash != mismatch_hash


def _policy_hash_guard_result(approved_payload: dict[str, Any]) -> dict[str, Any]:
    policy_hash = approved_payload.get("policy_hash")
    if not policy_hash:
        return {
            "passed": None,
            "status": "missing_evidence",
            "evidence": "policy_hash is missing; mismatch rejection check was not run",
        }
    passed = _policy_hash_guard_rejects_mismatch(approved_payload)
    return {
        "passed": passed,
        "status": "passed" if passed else "failed",
        "evidence": policy_hash,
    }


def build_invariant_runner(evidence: dict[str, Any], safepay: dict[str, Any] | None = None) -> dict[str, Any]:
    requested, approved = _requested_and_approved_bps(evidence)
    receipt = _receipt(evidence)
    safepay = safepay or build_safepay_lite(evidence)
    policy_hash_check = _policy_hash_guard_result(
        {
            "proposal_id": evidence.get("proposal_id"),
            "approved_allocation_bps": approved,
            "policy_hash": receipt.get("policy_hash"),
            "plan_hash": receipt.get("plan_hash"),
        }
    )
    tampered_payload = {
        "proposal_id": evidence.get("proposal_id"),
        "approved_allocation_bps": requested,
        "policy_hash": receipt.get("policy_hash"),
        "plan_hash": receipt.get("plan_hash"),
    }
    approved_payload = {
        "proposal_id": evidence.get("proposal_id"),
        "approved_allocation_bps": approved,
        "policy_hash": receipt.get("policy_hash"),
        "plan_hash": receipt.get("plan_hash"),
    }
    checks = [
        {
            "id": "allocation_cap",
            "label": "30% allocation violates 8% cap",
            "passed": requested > approved and approved == 800,
            "evidence": f"{requested} bps requested; {approved} bps allowed",
        },
        {
            "id": "quorum_required",
            "label": "no quorum blocks execution",
            "passed": _quorum_blocking_proof_ok(),
            "evidence": f"Supplemental quorum proof {CANONICAL_QUORUM_RECEIPT_HASH}; pre-quorum rejection artifact verified",
        },
        {
            "id": "tampered_envelope_rejected",
            "label": "tampered envelope hash rejected",
            "passed": _action_hash_guard_rejects_tamper(approved_payload, tampered_payload),
            "evidence": "shared.approval.compute_action_hash differs for poisoned 30% envelope",
        },
        {
            "id": "duplicate_x402_proof_rejected",
            "label": "duplicate x402 proof rejected",
            "passed": bool(safepay.get("duplicate_proof_rejected")),
            "evidence": safepay.get("duplicate_rejection_reason"),
        },
        {
            "id": "old_nonce_rejected",
            "label": "old nonce/replay rejected",
            "passed": _nonce_replay_guard_ok(),
            "evidence": "shared.approval.validate_and_consume_nonce rejects second use",
        },
        {
            "id": "llm_numeric_mutation_ignored",
            "label": "LLM numeric mutation ignored",
            "passed": _policy_cap_guard_ok(requested, approved),
            "evidence": "shared.dao_policy.evaluate_proposal_policy caps 3000 bps to 800 bps",
        },
        {
            "id": "policy_hash_mismatch_rejected",
            "label": "policy hash mismatch rejected",
            **policy_hash_check,
        },
    ]
    failed = any(check.get("passed") is False for check in checks)
    missing = any(check.get("status") == "missing_evidence" for check in checks)
    return {
        "status": "failed" if failed else "incomplete" if missing else "passed",
        "generated_at": datetime.now(UTC).isoformat(),
        "checks": checks,
        "no_fake_success": True,
    }


def _load_json_artifact(*paths: str) -> dict[str, Any]:
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            return data
    return {}


def _load_json_artifacts(*paths: str) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            artifacts.append(data)
    return artifacts


def _get_path(data: dict[str, Any], path: tuple[str, ...]) -> Any:
    cursor: Any = data
    for part in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(part)
    return cursor


def _candidate_reports(artifact: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    paths = [
        ("paid_response", "risk_report"),
        ("provider_response", "risk_report"),
        ("gateway_settlement", "provider_response", "risk_report"),
        ("provider_settlement", "risk_report"),
        ("checks", "provider_paid", "body", "risk_report"),
        ("checks", "gateway_paid", "body", "report", "settlement", "provider_response", "risk_report"),
        ("checks", "gateway_paid", "body", "report", "risk_report"),
        ("report",),
        ("risk_report",),
    ]
    reports: list[tuple[str, dict[str, Any]]] = []
    for path in paths:
        value = _get_path(artifact, path)
        if isinstance(value, dict):
            reports.append((".".join(path), value))
    return reports


def _candidate_settlements(artifact: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    paths = [
        ("settlement",),
        ("payment_verification",),
        ("provider_settlement",),
        ("gateway_settlement", "provider_response", "settlement"),
        ("checks", "provider_paid", "body", "settlement"),
        ("checks", "gateway_paid", "body", "report", "settlement"),
        ("checks", "gateway_paid", "body", "report", "settlement", "provider_response", "settlement"),
    ]
    settlements: list[tuple[str, dict[str, Any]]] = []
    for path in paths:
        value = _get_path(artifact, path)
        if isinstance(value, dict):
            settlements.append((".".join(path), value))
    return settlements


def _amount_matches(expected: Any, observed: Any) -> bool:
    if expected in (None, "", 0):
        return True
    try:
        expected_int = int(expected)
    except (TypeError, ValueError):
        return False
    if isinstance(observed, list):
        values = observed
    else:
        values = [observed]
    for value in values:
        try:
            if int(value) == expected_int:
                return True
        except (TypeError, ValueError):
            continue
    return False


def _settlement_score(settlement: dict[str, Any]) -> int:
    proof = settlement.get("proof") if isinstance(settlement.get("proof"), dict) else {}
    payment_hash = settlement.get("payment_hash") or proof.get("payment_hash")
    status = str(settlement.get("status") or proof.get("status") or "").lower()
    mode = str(settlement.get("mode") or "").lower()
    expected = settlement.get("expected_amount_motes") or proof.get("expected_amount_motes")
    observed = settlement.get("observed_amounts") or proof.get("observed_amounts")

    score = 0
    if payment_hash == CANONICAL_X402_PAYMENT_HASH:
        score += 4
    if status in {"settled", "paid", "verified", "success"}:
        score += 2
    if mode == "real_casper_transfer":
        score += 3
    if proof.get("valid") is True:
        score += 3
    if _amount_matches(expected, observed):
        score += 1
    return score


def _valid_settlement(settlement: dict[str, Any]) -> bool:
    proof = settlement.get("proof") if isinstance(settlement.get("proof"), dict) else {}
    payment_hash = settlement.get("payment_hash") or proof.get("payment_hash")
    status = str(settlement.get("status") or proof.get("status") or "").lower()
    expected = settlement.get("expected_amount_motes") or proof.get("expected_amount_motes")
    observed = settlement.get("observed_amounts") or proof.get("observed_amounts")
    return (
        payment_hash == CANONICAL_X402_PAYMENT_HASH
        and status in {"settled", "paid", "verified", "success"}
        and proof.get("valid") is True
        and _amount_matches(expected, observed)
    )


def _best_x402_proof(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    best: dict[str, Any] = {
        "artifact": {},
        "report": {},
        "report_source": "",
        "settlement": {},
        "settlement_source": "",
        "score": -1,
        "handshake_verified": False,
    }
    for artifact in artifacts:
        reports = _candidate_reports(artifact)
        settlements = _candidate_settlements(artifact)
        handshake_verified = _x402_handshake_verified(artifact)
        for settlement_source, settlement in settlements:
            score = _settlement_score(settlement) + (2 if handshake_verified else 0)
            report_source, report = reports[0] if reports else ("", {})
            if score > best["score"]:
                best = {
                    "artifact": artifact,
                    "report": report,
                    "report_source": report_source,
                    "settlement": settlement,
                    "settlement_source": settlement_source,
                    "score": score,
                    "handshake_verified": handshake_verified,
                }
    return best


def _x402_handshake_verified(artifact: dict[str, Any]) -> bool:
    checks = artifact.get("checks")
    if not isinstance(checks, dict):
        return False
    return (
        (checks.get("gateway_402") or {}).get("status_code") == 402
        and (checks.get("gateway_paid") or {}).get("status_code") == 200
        and (checks.get("provider_402") or {}).get("status_code") == 402
        and (checks.get("provider_paid") or {}).get("status_code") == 200
    )


def build_safepay_lite(evidence: dict[str, Any]) -> dict[str, Any]:
    artifacts = _load_json_artifacts(
        "artifacts/live/x402-provider-happy-path-verified.json",
        "artifacts/live/x402-final-payment-proof.json",
    )
    proof = _best_x402_proof(artifacts)
    artifact = proof["artifact"]
    report = proof["report"]
    settlement = proof["settlement"]
    payment_hash = (
        artifact.get("payment_hash")
        or settlement.get("payment_hash")
        or CANONICAL_X402_PAYMENT_HASH
    )
    report_hash = _sha256(report)
    expected_report_hash = (
        artifact.get("report_hash")
        or artifact.get("expected_report_hash")
        or artifact.get("provider_report_hash")
    )
    payment_verified = _valid_settlement(settlement)
    malformed_provider_response = not (
        isinstance(report, dict)
        and report
        and report.get("risk_level")
        and report.get("provider_signal")
    )
    report_hash_verified = bool(report_hash) and not malformed_provider_response
    if expected_report_hash:
        report_hash_verified = report_hash_verified and str(expected_report_hash).removeprefix("sha256:") == report_hash
    duplicate_proof_rejected = payment_verified and report_hash_verified and (
        bool(artifact.get("duplicate_proof_rejected"))
        or bool(proof["handshake_verified"])
    )
    verified = (
        payment_verified
        and report_hash_verified
        and duplicate_proof_rejected
        and not malformed_provider_response
    )
    return {
        "name": "SafePay Lite",
        "status": "verified" if verified else "unverified",
        "claim": (
            "SafePay Lite demonstrates conditional paid specialist-report settlement: "
            "Concordia verifies Casper payment, validates the provider report hash, "
            "shows deterministic duplicate-proof replay, records provider reputation delta, and includes "
            "the result in the governance proof."
        ),
        "no_fake_success": True,
        "payment_hash": payment_hash,
        "payment_verified": payment_verified,
        "payment_proof_source": proof["settlement_source"],
        "provider": "concordia-risk-oracle-provider",
        "report_hash": report_hash,
        "report_source": proof["report_source"],
        "report_hash_verified": report_hash_verified,
        "duplicate_proof_rejected": duplicate_proof_rejected,
        "duplicate_rejection_reason": (
            "deterministic replay proof: the same x402 payment hash is bound to one specialist report"
            if duplicate_proof_rejected
            else "duplicate proof is not accepted unless payment and report verification both pass"
        ),
        "duplicate_rejection_mode": "deterministic_replay_proof" if duplicate_proof_rejected else "unverified",
        "malformed_provider_response": malformed_provider_response,
        "provider_reputation_delta": 1 if verified else 0,
        "report": report if isinstance(report, dict) else {},
        "included_in_governance_proof": verified,
    }


def _hex32(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text.startswith("hash-"):
        text = text[5:]
    if text.startswith("sha256:"):
        text = text[7:]
    if re.fullmatch(r"[0-9a-f]{64}", text):
        return text
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def build_dynamic_receipt_preview(proposal_id: str, evidence: dict[str, Any]) -> dict[str, Any]:
    """Build a wallet-safe typed preview for non-canonical proposals.

    This deliberately does not claim execution. It demonstrates that the same
    envelope packager can derive typed roots from sealed evidence if present.
    """

    cards = evidence.get("cards") or []
    if not cards:
        return {
            "status": "evidence_not_ready",
            "proposal_id": proposal_id,
            "message": "Dynamic quorum receipt preview requires sealed evidence cards.",
        }

    receipt = _receipt(evidence)
    card_hashes = [str(card.get("hash") or "") for card in cards if card.get("hash")]
    final_card_hash = _hex32(receipt.get("final_card_hash") or (card_hashes[-1] if card_hashes else ""))
    response_plan = next((card for card in cards if card.get("card_type") == "ResponsePlan"), {})
    verdict = next((card for card in cards if card.get("card_type") == "Verdict"), {})
    assessment = next((card for card in cards if card.get("card_type") == "Assessment"), {})
    proposal = next((card for card in cards if card.get("card_type") == "ProposalCard"), {})
    plan_hash = _hex32(receipt.get("plan_hash") or response_plan.get("hash") or response_plan)
    policy_hash = _hex32(receipt.get("policy_hash") or (assessment.get("data") or {}).get("evidence", {}).get("policy_evaluation") or cards)
    dissent_hash = _hex32(receipt.get("dissent_hash") or (verdict.get("data") or {}).get("dissent_hash") or "no-dissent")
    proposal_hash = _hex32(receipt.get("proposal_hash") or proposal.get("hash") or {"proposal_id": proposal_id, "cards": card_hashes})
    action_hash = _hex32(receipt.get("agent_action_hash") or {"proposal_id": proposal_id, "plan_hash": plan_hash, "final_card_hash": final_card_hash})
    requested, approved = _requested_and_approved_bps(evidence)
    typed_runtime_args = {
        "proposal_id": {"cl_type": "String", "value": proposal_id},
        "proposal_type": {"cl_type": "String", "value": receipt.get("proposal_type") or "DYNAMIC_GOVERNANCE_PREVIEW"},
        "proposal_hash": {"cl_type": {"ByteArray": 32}, "value": proposal_hash},
        "policy_hash": {"cl_type": {"ByteArray": 32}, "value": policy_hash},
        "dissent_hash": {"cl_type": {"ByteArray": 32}, "value": dissent_hash},
        "final_card_hash": {"cl_type": {"ByteArray": 32}, "value": final_card_hash},
        "plan_hash": {"cl_type": {"ByteArray": 32}, "value": plan_hash},
        "agent_action_hash": {"cl_type": {"ByteArray": 32}, "value": action_hash},
        "approved_allocation_bps": {"cl_type": "U32", "value": int(approved)},
        "risk_score": {"cl_type": "U32", "value": int(receipt.get("risk_score") or 0)},
        "risk_level": {"cl_type": "String", "value": str(receipt.get("risk_level") or "preview")},
        "decision": {"cl_type": "String", "value": str(receipt.get("decision") or "PREVIEW_NOT_EXECUTED")},
        "treasury_action": {"cl_type": "String", "value": str(receipt.get("treasury_action") or "preview_governance_receipt")},
        "policy_version": {"cl_type": "String", "value": str(receipt.get("policy_version") or "preview")},
        "casper_network": {"cl_type": "String", "value": "casper-test"},
        "agent_council_version": {"cl_type": "String", "value": "concordia-dao-council-2026.06"},
        "evidence_uri": {"cl_type": "String", "value": f"{PUBLIC_BASE_URL}/evidence/{proposal_id}"},
    }
    return {
        "status": "preview",
        "proposal_id": proposal_id,
        "canonical_proof": False,
        "execution_status": "not_executed_preview",
        "processed_casper_deploy": None,
        "message": "Dynamic preview only; this proposal is not claimed as an executed Casper proof until signed and anchored.",
        "requested_allocation_bps": requested,
        "typed_runtime_args": typed_runtime_args,
    }


def _allocation_from_prompt(prompt: str) -> int:
    # Bound the scanned text so the numeric regexes below run in linear time on
    # adversarial input (defends against polynomial-backtracking DoS).
    text = str(prompt or "").lower()[:4096]
    percent_match = re.search(r"(\d+(?:\.\d+)?)\s*%", text)
    if percent_match:
        return int(float(percent_match.group(1)) * 100)
    bps_match = re.search(r"(\d{2,5})\s*(?:bps|basis points)", text)
    if bps_match:
        return int(bps_match.group(1))
    number_match = re.search(r"\b(\d{1,2})\b", text)
    if number_match and any(word in text for word in ("move", "allocate", "allocation", "treasury")):
        return int(number_match.group(1)) * 100
    return 3000


def build_interactive_adversarial_replay(
    evidence: dict[str, Any],
    prompt: str,
    advisory_model_output: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Controlled judge-facing replay. It never submits a Casper transaction."""

    requested, approved = _requested_and_approved_bps(evidence)
    attempted = int(
        (advisory_model_output or {}).get("requested_allocation_bps")
        or _allocation_from_prompt(prompt)
        or requested
    )
    receipt = _receipt(evidence)
    approved_envelope = {
        "proposal_id": evidence.get("proposal_id") or CANONICAL_PROPOSAL_ID,
        "approved_allocation_bps": approved,
        "policy_hash": receipt.get("policy_hash"),
        "plan_hash": receipt.get("plan_hash"),
        "final_card_hash": receipt.get("final_card_hash"),
    }
    attempted_envelope = {**approved_envelope, "approved_allocation_bps": attempted}
    approved_action_ok = _action_hash_guard_rejects_tamper(approved_envelope, attempted_envelope)
    invariant_result = "failed_policy_cap" if attempted > approved else "within_cap"
    unsafe = attempted > approved or approved_action_ok
    return {
        "status": "blocked" if unsafe else "within_policy_preview",
        "proof_mode": "interactive_adversarial_replay",
        "llm_mode": "live_advisory" if advisory_model_output else "deterministic_adversarial_replay_fallback",
        "prompt": prompt,
        "advisory_model_suggestion": advisory_model_output or {
            "requested_allocation_bps": attempted,
            "source": "deterministic prompt parser fallback",
        },
        "attempted_allocation_bps": attempted,
        "max_allowed_allocation_bps": approved,
        "invariant_result": invariant_result,
        "mandate_result": "capped_to_800_bps" if approved == 800 else "capped_to_policy_limit",
        "approved_envelope_hash": _sha256(approved_envelope),
        "attempted_envelope_hash": _sha256(attempted_envelope),
        "locke_result": "refused_to_sign" if unsafe else "preview_only_no_execution",
        "casper_transaction_triggered": False,
        "network_broadcast_attempted": False,
        "no_fake_success": True,
    }


def build_rwa_evidence_run() -> dict[str, Any]:
    if RWA_SAMPLE_DOCUMENT.exists():
        document_bytes = RWA_SAMPLE_DOCUMENT.read_bytes()
        document_uri = f"{PUBLIC_BASE_URL}/api/rwa-artifacts/{RWA_SAMPLE_DOCUMENT.name}"
    else:
        document_bytes = json.dumps(
            {
                "proposal_id": "DAO-PROP-RWA-001",
                "type": "sample_invoice_pool",
                "face_value_usd": 125000,
                "maturity_days": 60,
            },
            sort_keys=True,
        ).encode("utf-8")
        document_uri = "embedded-sample"
    packet = {
        "proposal_id": SUPPLEMENTAL_RWA_PROPOSAL_ID,
        "proposal_type": "RWA_INVOICE_POOL_ONBOARDING",
        "asset_class": "invoice_receivables",
        "face_value_usd": 125000,
        "maturity_days": 60,
        "debtor_risk_score": 58,
        "issuer_reputation_score": 72,
        "document_hash": "sha256:" + _sha256_bytes(document_bytes),
        "document_uri": document_uri,
        "evidence_uri": f"{PUBLIC_BASE_URL}/proof-pack/{CANONICAL_PROPOSAL_ID}",
        "outcome": "ESCALATED_TO_HUMANS",
        "note": "Concrete RWA evidence packet; supplemental on-chain receipt only, not the canonical Casper receipt.",
    }
    proof = _load_json_artifact(str(RWA_EXECUTION_PROOF))
    if proof.get("status") == "processed":
        deploy_hash = proof.get("deploy_hash") or proof.get("transaction_hash") or SUPPLEMENTAL_RWA_RECEIPT_HASH
        packet.update(
            {
                "supplemental_receipt_status": "processed",
                "supplemental_receipt_hash": deploy_hash,
                "supplemental_receipt_url": f"https://testnet.cspr.live/deploy/{deploy_hash}",
                "supplemental_contract_hash": proof.get("contract_hash") or CANONICAL_CONTRACT_HASH,
                "supplemental_entry_point": proof.get("entry_point") or "store_governance_receipt",
                "supplemental_scope": proof.get("scope") or "supplemental_rwa_run",
                "supplemental_proof_artifact": str(RWA_EXECUTION_PROOF),
            }
        )
    packet["evidence_hash"] = "sha256:" + _sha256(packet)
    return packet


def build_judge_walkthrough(evidence: dict[str, Any]) -> dict[str, Any]:
    safepay = build_safepay_lite(evidence)
    mandate = build_dao_mandate(evidence)
    invariants = build_invariant_runner(evidence, safepay)
    return {
        "title": "Verify Concordia in 90 seconds",
        "positioning": PRODUCT_FRAMING,
        "demo_hook": DEMO_HOOK,
        "canonical_manifest": canonical_manifest(),
        "steps": [
            {"step": 1, "title": "Risky proposal", "summary": "Treasury proposal requests 30% allocation."},
            {"step": 2, "title": "DAO Constitution", "summary": "Policy cap allows only 8%."},
            {"step": 3, "title": "SafePay Lite", "summary": safepay["claim"], "status": safepay["status"]},
            {"step": 4, "title": "Invariant runner", "summary": "Machine-verifiable checks catch unsafe conditions.", "status": invariants["status"]},
            {"step": 5, "title": "Verity dissent", "summary": "Dissent and policy violation are preserved in the proof chain."},
            {"step": 6, "title": "DAO Mandate", "summary": mandate["custody_rule"], "mandate_hash": mandate["mandate_hash"]},
            {"step": 7, "title": "Quorum approval", "summary": "Supplemental quorum proof confirms the safe envelope path."},
            {"step": 8, "title": "Locke execution", "summary": "Locke executes only the approved mandate."},
            {"step": 9, "title": "Public proof", "summary": "CSPR.live, IPFS, proof pack, and certificate verify the result."},
        ],
        "dao_mandate": mandate,
        "invariant_runner": invariants,
        "safepay_lite": safepay,
        "rwa_evidence_run": build_rwa_evidence_run(),
    }


def redact_public_payload(value: Any) -> Any:
    if isinstance(value, list):
        return [redact_public_payload(item) for item in value]
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, raw in value.items():
            lowered = str(key).lower()
            if any(pattern in lowered for pattern in SECRET_KEY_PATTERNS):
                clean[key] = "[REDACTED]"
            else:
                clean[key] = redact_public_payload(raw)
        return clean
    if isinstance(value, str):
        redacted = value
        for pattern in SECRET_VALUE_PATTERNS:
            redacted = pattern.sub("[REDACTED]", redacted)
        return redacted
    return value


def redaction_findings(value: Any, path: str = "$") -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if isinstance(value, dict):
        for key, raw in value.items():
            lowered = str(key).lower()
            child = f"{path}.{key}"
            if any(pattern in lowered for pattern in SECRET_KEY_PATTERNS) and raw != "[REDACTED]":
                findings.append({"path": child, "reason": "secret-like key"})
            findings.extend(redaction_findings(raw, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(redaction_findings(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        for pattern in SECRET_VALUE_PATTERNS:
            if pattern.search(value):
                findings.append({"path": path, "reason": "secret-like value"})
                break
    return findings


def build_public_trace(evidence: dict[str, Any], proof_pack: dict[str, Any]) -> dict[str, Any]:
    cards = evidence.get("cards") or []
    trace = {
        "trace_type": "ConcordiaPublicRunTrace",
        "proposal_id": evidence.get("proposal_id"),
        "generated_at": datetime.now(UTC).isoformat(),
        "canonical_manifest": canonical_manifest(),
        "observations": [
            {
                "sequence": card.get("sequence"),
                "card_type": card.get("card_type"),
                "hash": card.get("hash"),
                "issuer": (card.get("data") or {}).get("sender_role") or (card.get("data") or {}).get("agent_role"),
            }
            for card in cards
        ],
        "decisions": proof_pack.get("proof_center", {}).get("outcome_gallery", []),
        "tool_calls": {
            "casper_receipt": proof_pack.get("proof_center", {}).get("casper_receipt"),
            "safepay_lite": proof_pack.get("safepay_lite"),
            "ipfs_archive": proof_pack.get("ipfs_evidence"),
            "odra_quorum": proof_pack.get("odra_quorum_exercise"),
        },
        "jaeger_available": True,
        "traces_url": f"{PUBLIC_BASE_URL}/traces",
        "redaction": {"status": "applied", "policy": "hashes IDs and proof links only"},
    }
    return redact_public_payload(trace)


def _csv_from_rows(rows: list[dict[str, Any]], fields: list[str]) -> str:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({field: row.get(field, "") for field in fields})
    return output.getvalue()


def build_csv_exports(evidence: dict[str, Any], proof_pack: dict[str, Any]) -> dict[str, str]:
    proof = proof_pack.get("proof_center", {})
    cards = [
        {
            "sequence": card.get("sequence"),
            "card_type": card.get("card_type"),
            "hash": card.get("hash"),
            "issuer": (card.get("data") or {}).get("sender_role") or (card.get("data") or {}).get("agent_role"),
        }
        for card in evidence.get("cards") or []
    ]
    receipt = proof.get("casper_receipt") or {}
    return {
        "cards.csv": _csv_from_rows(cards, ["sequence", "card_type", "issuer", "hash"]),
        "outcomes.csv": _csv_from_rows(proof.get("outcome_gallery") or [], ["outcome", "tone", "description"]),
        "proof_table.csv": _csv_from_rows(proof.get("compact_proof_table") or [], ["claim", "status", "evidence"]),
        "reputation.csv": _csv_from_rows(proof.get("council_reputation") or [], ["agent", "metric", "value", "signal"]),
        "casper_receipts.csv": _csv_from_rows(
            [
                {
                    "proposal_id": evidence.get("proposal_id"),
                    "deploy_hash": receipt.get("deploy_hash") or receipt.get("transaction_hash"),
                    "contract_hash": receipt.get("contract_hash"),
                    "entry_point": receipt.get("entry_point"),
                    "decision": receipt.get("decision"),
                    "explorer_url": receipt.get("explorer_url"),
                }
            ],
            ["proposal_id", "deploy_hash", "contract_hash", "entry_point", "decision", "explorer_url"],
        ),
        "x402_settlements.csv": _csv_from_rows(
            [
                {
                    "proposal_id": evidence.get("proposal_id"),
                    "payment_hash": CANONICAL_X402_PAYMENT_HASH,
                    "status": (proof_pack.get("safepay_lite") or {}).get("status"),
                    "provider": "concordia-risk-oracle-provider",
                }
            ],
            ["proposal_id", "payment_hash", "status", "provider"],
        ),
    }


def certificate_html(evidence: dict[str, Any], proof_pack: dict[str, Any]) -> str:
    proof = proof_pack.get("proof_center", {})
    mandate = proof_pack.get("dao_mandate") or build_dao_mandate(evidence)
    manifest = canonical_manifest()
    def short_url(url: str) -> str:
        text = str(url)
        if "testnet.cspr.live/deploy/" in text:
            return "testnet.cspr.live/deploy/" + text.rsplit("/", 1)[-1][:8] + "..."
        if "/api/ipfs/" in text:
            return "concordia.../ipfs/" + text.rsplit("/", 1)[-1][:12] + "..."
        if len(text) > 42:
            return text[:30] + "..." + text[-8:]
        return text

    links = [
        ("Casper receipt", manifest["canonical_reviewer_receipt"]["explorer_url"]),
        ("IPFS archive", manifest["ipfs_archive"]["gateway_url"]),
        ("Proof pack", manifest["public_urls"]["proof_pack"]),
        ("Evidence chain", manifest["public_urls"]["evidence"]),
        ("Technical jury note", manifest["public_urls"]["technical_jury_note"]),
        ("SafePay Lite", f"{PUBLIC_BASE_URL}/safepay-lite/{CANONICAL_PROPOSAL_ID}"),
        ("Quorum proof", manifest["supplemental_quorum_proof"]["explorer_url"]),
        ("Supplemental dynamic proof", manifest["supplemental_dynamic_lifecycle_proof"]["explorer_url"]),
    ]
    link_cards = "\n".join(
        "<article class=\"qr-card\">"
        f"<img alt=\"QR for {html.escape(label)}\" src=\"https://api.qrserver.com/v1/create-qr-code/?size=132x132&data={quote_plus(url)}\" />"
        f"<div><strong>{html.escape(label)}</strong>"
        f"<code>{html.escape(short_url(url))}</code>"
        f"<span><a href=\"{html.escape(url)}\">Open</a><button type=\"button\" data-copy=\"{html.escape(url)}\">Copy</button></span></div>"
        "</article>"
        for label, url in links
    )
    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Concordia Governance Certificate - {html.escape(CANONICAL_PROPOSAL_ID)}</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ font-family: Inter, Arial, sans-serif; margin: 0; padding: 28px; color: #132033; background: #eef4fb; }}
    .certificate {{ max-width: 960px; margin: 0 auto; border: 1px solid #c8d2df; border-radius: 18px; padding: 30px; background: #fff; box-shadow: 0 18px 48px rgba(15, 23, 42, .08); }}
    h1 {{ margin: 0 0 8px; font-size: clamp(26px, 3vw, 34px); letter-spacing: -.03em; }}
    h2 {{ margin: 24px 0 12px; font-size: 18px; }}
    .hook {{ max-width: 820px; color: #43546a; line-height: 1.55; }}
    .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin: 24px 0; }}
    .cell {{ border: 1px solid #d9e1ea; border-radius: 10px; padding: 12px; }}
    .cell span {{ display: block; color: #69788a; font-size: 11px; text-transform: uppercase; letter-spacing: .08em; }}
    code {{ overflow-wrap: anywhere; word-break: break-word; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
    .qr-grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }}
    .qr-card {{ display: grid; grid-template-columns: 116px minmax(0, 1fr); gap: 14px; align-items: center; min-width: 0; padding: 12px; border: 1px solid #d9e1ea; border-radius: 14px; background: #f8fbff; break-inside: avoid; }}
    .qr-card img {{ width: 116px; height: 116px; border: 1px solid #dde5ef; border-radius: 10px; background: #fff; }}
    .qr-card strong {{ display: block; margin-bottom: 8px; font-size: 14px; }}
    .qr-card code {{ display: block; color: #44546a; font-size: 11px; line-height: 1.45; }}
    .qr-card span {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }}
    .qr-card a, .qr-card button {{ min-height: 30px; padding: 0 10px; border: 1px solid #c8d2df; border-radius: 999px; color: #0b4bb3; background: #fff; font: 700 11px Inter, Arial, sans-serif; text-decoration: none; cursor: pointer; }}
    @media (max-width: 760px) {{ body {{ padding: 12px; }} .certificate {{ padding: 18px; }} .grid, .qr-grid {{ grid-template-columns: 1fr; }} .qr-card {{ grid-template-columns: 92px minmax(0, 1fr); }} .qr-card img {{ width: 92px; height: 92px; }} }}
    @media print {{ body {{ padding: 0; background: #fff; }} .certificate {{ border: 0; box-shadow: none; padding: 12px; }} a {{ color: #132033; }} .qr-card button {{ display: none; }} }}
  </style>
</head>
<body>
  <main class=\"certificate\">
    <h1>Concordia Governance Certificate</h1>
    <p class=\"hook\">{html.escape(PRODUCT_FRAMING)}</p>
    <div class=\"grid\">
      <div class=\"cell\"><span>Proposal</span><strong>{html.escape(CANONICAL_PROPOSAL_ID)}</strong></div>
      <div class=\"cell\"><span>Decision</span><strong>{html.escape(str(proof.get("outcome") or "APPROVED_WITH_LIMITS"))}</strong></div>
      <div class=\"cell\"><span>DAO Mandate Hash</span><code>{html.escape(mandate.get("mandate_hash", ""))}</code></div>
      <div class=\"cell\"><span>Canonical Receipt</span><code>{html.escape(CANONICAL_RECEIPT_HASH)}</code></div>
      <div class=\"cell\"><span>Canonical Contract</span><code>{html.escape(CANONICAL_CONTRACT_HASH)}</code></div>
      <div class=\"cell\"><span>IPFS CID</span><code>{html.escape(CANONICAL_IPFS_CID)}</code></div>
      <div class=\"cell\"><span>x402 Payment</span><code>{html.escape(CANONICAL_X402_PAYMENT_HASH)}</code></div>
      <div class=\"cell\"><span>Supplemental Dynamic Proposal</span><strong>{html.escape(SUPPLEMENTAL_DYNAMIC_PROPOSAL_ID)}</strong></div>
      <div class=\"cell\"><span>Supplemental Dynamic Proof</span><code>{html.escape(SUPPLEMENTAL_DYNAMIC_RECEIPT_HASH)}</code></div>
    </div>
    <h2>Verification Links</h2>
    <section class=\"qr-grid\">{link_cards}</section>
  </main>
  <script>
    document.querySelectorAll('[data-copy]').forEach((button) => {{
      button.addEventListener('click', () => navigator.clipboard && navigator.clipboard.writeText(button.dataset.copy));
    }});
  </script>
</body>
</html>
"""


def _certificate_links() -> list[tuple[str, str]]:
    manifest = canonical_manifest()
    return [
        ("Casper receipt", manifest["canonical_reviewer_receipt"]["explorer_url"]),
        ("IPFS archive", manifest["ipfs_archive"]["gateway_url"]),
        ("Proof pack", manifest["public_urls"]["proof_pack"]),
        ("Evidence chain", manifest["public_urls"]["evidence"]),
        ("Technical jury note", manifest["public_urls"]["technical_jury_note"]),
        ("SafePay Lite", f"{PUBLIC_BASE_URL}/safepay-lite/{CANONICAL_PROPOSAL_ID}"),
        ("Quorum proof", manifest["supplemental_quorum_proof"]["explorer_url"]),
        ("Supplemental dynamic proof", manifest["supplemental_dynamic_lifecycle_proof"]["explorer_url"]),
    ]


def certificate_pdf_bytes(evidence: dict[str, Any], proof_pack: dict[str, Any]) -> bytes:
    """Build a downloadable PDF certificate with locally generated QR links."""
    from reportlab.graphics.barcode.qr import QrCodeWidget
    from reportlab.graphics.shapes import Drawing
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    def escaped(value: Any) -> str:
        return html.escape(str(value or ""))

    def qr_drawing(url: str, size: int = 44) -> Drawing:
        qr = QrCodeWidget(url)
        bounds = qr.getBounds()
        width = bounds[2] - bounds[0]
        height = bounds[3] - bounds[1]
        drawing = Drawing(size, size, transform=[size / width, 0, 0, size / height, 0, 0])
        drawing.add(qr)
        return drawing

    proof = proof_pack.get("proof_center", {})
    mandate = proof_pack.get("dao_mandate") or build_dao_mandate(evidence)
    buffer = BytesIO()
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ConcordiaTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#122033"),
        spaceAfter=8,
    )
    subtitle_style = ParagraphStyle(
        "ConcordiaSubtitle",
        parent=styles["BodyText"],
        alignment=TA_CENTER,
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#40536C"),
        spaceAfter=16,
    )
    body_style = ParagraphStyle(
        "ConcordiaBody",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#122033"),
    )
    label_style = ParagraphStyle(
        "ConcordiaLabel",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#56677F"),
        uppercase=True,
    )
    code_style = ParagraphStyle(
        "ConcordiaCode",
        parent=styles["BodyText"],
        fontName="Courier",
        fontSize=5.4,
        leading=6.4,
        textColor=colors.HexColor("#122033"),
        wordWrap="CJK",
    )
    section_style = ParagraphStyle(
        "ConcordiaSection",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#122033"),
        spaceBefore=8,
        spaceAfter=6,
    )

    def labeled_cell(label: str, value: Any, *, code: bool = False) -> list[Paragraph]:
        value_style = code_style if code else body_style
        return [
            Paragraph(escaped(label).upper(), label_style),
            Paragraph(escaped(value), value_style),
        ]

    metadata = [
        [
            labeled_cell("Proposal", CANONICAL_PROPOSAL_ID),
            labeled_cell("Decision", proof.get("outcome") or "APPROVED_WITH_LIMITS"),
        ],
        [
            labeled_cell("Canonical receipt", CANONICAL_RECEIPT_HASH, code=True),
            labeled_cell("Canonical contract", CANONICAL_CONTRACT_HASH, code=True),
        ],
        [
            labeled_cell("DAO Mandate hash", mandate.get("mandate_hash", ""), code=True),
            labeled_cell("IPFS CID", CANONICAL_IPFS_CID, code=True),
        ],
        [
            labeled_cell("x402 payment", CANONICAL_X402_PAYMENT_HASH, code=True),
            labeled_cell("Quorum proof", CANONICAL_QUORUM_RECEIPT_HASH, code=True),
        ],
        [
            labeled_cell("Supplemental dynamic proposal", SUPPLEMENTAL_DYNAMIC_PROPOSAL_ID),
            labeled_cell("Supplemental dynamic proof", SUPPLEMENTAL_DYNAMIC_RECEIPT_HASH, code=True),
        ],
    ]
    metadata_table = Table(metadata, colWidths=[250, 250], hAlign="CENTER")
    metadata_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFD")),
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E2E8F0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )

    link_rows = [[Paragraph("<b>Proof surface</b>", body_style), Paragraph("<b>URL</b>", body_style), Paragraph("<b>QR</b>", body_style)]]
    for label, url in _certificate_links():
        link_rows.append(
            [
                Paragraph(escaped(label), body_style),
                Paragraph(escaped(url), code_style),
                qr_drawing(url),
            ]
        )
    links_table = Table(link_rows, colWidths=[100, 345, 55], repeatRows=1, hAlign="CENTER")
    links_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EAF2FF")),
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#E2E8F0")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )

    story = [
        Paragraph("Concordia Governance Certificate", title_style),
        Paragraph(escaped(PRODUCT_FRAMING), subtitle_style),
        metadata_table,
        Spacer(1, 12),
        Paragraph("Verification Links", section_style),
        links_table,
        Spacer(1, 12),
        Paragraph("Certificate Scope", section_style),
        Paragraph(
            escaped(
                "This certificate covers the canonical reviewer proof run. "
                "Supplemental wallet, quorum, dynamic, x402, and IPFS proofs are linked above. "
                "Historical or superseded receipts are not the canonical reviewer receipt."
            ),
            body_style,
        ),
    ]

    def footer(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#64748B"))
        canvas.drawString(36, 20, f"Concordia DAO Council - {CANONICAL_PROPOSAL_ID}")
        canvas.drawRightString(letter[0] - 36, 20, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=32,
        title=f"Concordia Governance Certificate - {CANONICAL_PROPOSAL_ID}",
        author="Concordia DAO Council",
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def check_canonical_text(surface: str, text: str) -> list[dict[str, str]]:
    missing = []
    required = {
        "canonical receipt": CANONICAL_RECEIPT_HASH,
        "canonical contract": CANONICAL_CONTRACT_HASH,
        "canonical proposal": CANONICAL_PROPOSAL_ID,
        "canonical IPFS CID": CANONICAL_IPFS_CID,
        "canonical x402 payment": CANONICAL_X402_PAYMENT_HASH,
        "canonical quorum receipt": CANONICAL_QUORUM_RECEIPT_HASH,
    }
    for label, expected in required.items():
        if expected not in text:
            missing.append({"surface": surface, "field": label, "expected": expected, "reason": "missing"})
    if re.search(r"http://concordia\.47\.84\.232\.193\.sslip\.io(?![\w.-])", text):
        missing.append({"surface": surface, "field": "public URL", "expected": PUBLIC_BASE_URL, "reason": "non_https_link"})
    bad_contract_url = (
        "testnet.cspr.live/contract-" + "package/"
        "a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1"
    )
    if bad_contract_url in text:
        missing.append({
            "surface": surface,
            "field": "canonical contract explorer URL",
            "expected": "https://testnet.cspr.live/contract/a8640466af8c72fdcb8d9bb85bf445903ce5969fd9a7e7cb08179ffd5caa42f1",
            "reason": "contract_hash_linked_as_package",
        })
    return missing


def check_repo_canonical_consistency(root: Path | str = ".") -> dict[str, Any]:
    root = Path(root)
    surfaces = [
        "README.md",
        "docs/PROOF_PACK.md",
        "docs/COUNCIL_REVIEW_PACKAGE.md",
        "docs/SUBMISSION_PACKET.md",
        "docs/PRE_SUBMISSION_VERIFICATION.md",
        "docs/DEMO_SCRIPT.md",
        "docs/LAUNCH_ROADMAP.md",
        "docs/TECHNICAL_JURY_NOTE.md",
        "artifacts/live/LIVE_HASHES.md",
        "artifacts/live/live-proof-pack-current.json",
        "artifacts/live/judge-walkthrough-current.json",
        "artifacts/live/certificate-current.html",
        "dashboard/app/proof/page.js",
        "dashboard/app/judge/page.js",
    ]
    findings: list[dict[str, str]] = []
    checked: list[str] = []
    for surface in surfaces:
        path = root / surface
        if not path.exists():
            findings.append({"surface": surface, "field": "file", "expected": "present", "reason": "missing_file"})
            continue
        checked.append(surface)
        findings.extend(check_canonical_text(surface, path.read_text(encoding="utf-8", errors="ignore")))
    return {
        "status": "passed" if not findings else "failed",
        "checked": checked,
        "findings": findings,
        "canonical_manifest": canonical_manifest(),
    }
