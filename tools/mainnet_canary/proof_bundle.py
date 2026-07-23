"""Mainnet canary proof bundle: lineage, required statement, claims discipline.

The bundle lineage is ``concordia-mainnet-canary-v1`` — always separate from
the frozen canonical Testnet chain and never written into a protected
namespace (writes go through :mod:`tools.mainnet_canary.path_policy`).

Claims discipline is enforced mechanically: every string field of the bundle
is scanned, and any forbidden claim refuses.  Forbidden forever:

- the contract custodied or disbursed funds (it authorizes; the bounded
  off-chain executor moves value);
- Testnet and Mainnet Wasm are byte-identical (they are disjoint builds);
- official x402 is supported on Mainnet (fail-closed until a live
  ``/supported`` observation pins the asset constants);
- a wallet transfer proves governance;
- historical evidence was rewritten.
"""

from __future__ import annotations

import re

from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode

BUNDLE_LINEAGE = "concordia-mainnet-canary-v1"
BUNDLE_SCHEMA_ID = "concordia.mainnet-canary.proof-bundle.v1"

REQUIRED_STATEMENT = (
    "Concordia v3 on Casper Mainnet enforced quorum and the exact approved "
    "native-transfer envelope; an off-chain bounded executor submitted one "
    "native transfer only after on-chain authorization."
)

# Case-insensitive patterns; each names the claim it refuses.
_FORBIDDEN_CLAIM_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "contract_custodied_or_disbursed_funds",
        re.compile(r"contract\s+(?:\w+\s+){0,3}?(?:custodied|disburse[ds]?)", re.IGNORECASE),
    ),
    (
        "byte_identical_network_wasm",
        re.compile(r"byte[\s\-]identical", re.IGNORECASE),
    ),
    (
        "mainnet_x402_supported",
        re.compile(
            r"x402[^.\n]{0,80}?supported\s+on\s+(?:casper\s+)?mainnet",
            re.IGNORECASE,
        ),
    ),
    (
        "wallet_transfer_proves_governance",
        re.compile(r"wallet\s+transfer\s+proves", re.IGNORECASE),
    ),
    (
        "historical_evidence_rewritten",
        re.compile(r"historical\s+evidence\s+was\s+(?:rewritten|updated|amended)", re.IGNORECASE),
    ),
)


def scan_forbidden_claims(text: str) -> list[str]:
    """Names of every forbidden claim present in ``text`` (empty = clean)."""

    if not isinstance(text, str):
        return []
    return [name for name, pattern in _FORBIDDEN_CLAIM_PATTERNS if pattern.search(text)]


def _scan_document(value: object, found: set[str]) -> None:
    if isinstance(value, str):
        found.update(scan_forbidden_claims(value))
    elif isinstance(value, dict):
        for child in value.values():
            _scan_document(child, found)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _scan_document(child, found)


def build_proof_bundle_document(
    *,
    plan_hash: str,
    rc_tag: str,
    economic_manifest_sha256: str,
    attestations: dict[str, object],
    step_verifications: dict[str, object],
    journal_head_hash: str,
    narrative: str,
) -> dict[str, object]:
    """Assemble the bundle document; the claims scan runs on every field."""

    document: dict[str, object] = {
        "schema_id": BUNDLE_SCHEMA_ID,
        "lineage": BUNDLE_LINEAGE,
        "required_statement": REQUIRED_STATEMENT,
        "plan_hash": plan_hash,
        "rc_tag": rc_tag,
        "economic_manifest_sha256": economic_manifest_sha256,
        "attestations": attestations,
        "step_verifications": step_verifications,
        "journal_head_hash": journal_head_hash,
        "narrative": narrative,
    }
    validate_bundle_document(document)
    return document


def require_cross_binding(
    document: dict[str, object],
    *,
    journal_plan_hash: str,
    manifest_plan_hash: str,
    verification_plan_hash: str,
    journal_head_hash: str,
) -> None:
    """Every constituent must be bound to the SAME run.

    A bundle that merely embeds four values proves nothing: the journal, the
    economic manifest and the verification report must each be shown to
    belong to this plan, and the journal head must be the one actually read
    from the journal rather than a value the operator typed. Otherwise a
    bundle could pair one run's verification with another run's journal.
    """

    plan_hash = document.get("plan_hash")
    mismatched = sorted(
        name
        for name, value in (
            ("journal", journal_plan_hash),
            ("economic_manifest", manifest_plan_hash),
            ("verification_report", verification_plan_hash),
        )
        if value != plan_hash
    )
    if mismatched:
        raise CanaryRefusal(
            RefusalCode.BUNDLE_CROSS_BINDING_INVALID,
            f"bundle constituents belong to a different plan: {mismatched}",
        )
    if document.get("journal_head_hash") != journal_head_hash:
        raise CanaryRefusal(
            RefusalCode.BUNDLE_CROSS_BINDING_INVALID,
            "bundle journal head does not equal the head recomputed from the "
            "journal itself",
        )


def validate_bundle_document(document: dict[str, object]) -> None:
    """Exact lineage + verbatim required statement + zero forbidden claims."""

    if document.get("lineage") != BUNDLE_LINEAGE:
        raise CanaryRefusal(
            RefusalCode.FORBIDDEN_CLAIM,
            f"bundle lineage must be exactly {BUNDLE_LINEAGE}",
        )
    if document.get("required_statement") != REQUIRED_STATEMENT:
        raise CanaryRefusal(
            RefusalCode.FORBIDDEN_CLAIM,
            "the required statement must appear verbatim; a paraphrase can "
            "smuggle a forbidden claim",
        )
    found: set[str] = set()
    for key, value in document.items():
        if key == "required_statement":
            continue
        _scan_document(value, found)
    if found:
        raise CanaryRefusal(
            RefusalCode.FORBIDDEN_CLAIM,
            f"bundle carries forbidden claims: {sorted(found)}",
        )
