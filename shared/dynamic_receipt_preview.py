"""Dynamic wallet-ready receipt preview helpers."""
from __future__ import annotations

from typing import Any

from shared.proof_runtime import build_dynamic_receipt_preview


def build_preview(proposal_id: str, evidence: dict[str, Any]) -> dict[str, Any]:
    """Build a typed, non-executed receipt preview for sealed evidence."""

    return build_dynamic_receipt_preview(proposal_id, evidence)
