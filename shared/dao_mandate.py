"""DAO Mandate helpers exposed as a stable module boundary.

The implementation lives in ``shared.proof_runtime`` because the mandate is
assembled from the final reviewer proof package. This wrapper gives tests,
verification scripts, and reviewers an explicit DAO-native import path.
"""
from __future__ import annotations

from typing import Any

from shared.proof_runtime import build_dao_mandate


def build_mandate(evidence: dict[str, Any]) -> dict[str, Any]:
    """Build Concordia's deterministic DAO Mandate artifact."""

    return build_dao_mandate(evidence)

