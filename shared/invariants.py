"""Machine-verifiable invariant runner exposed as a stable module boundary."""
from __future__ import annotations

from typing import Any

from shared.proof_runtime import build_invariant_runner


def run_policy_invariants(
    evidence: dict[str, Any],
    safepay: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run Concordia's deterministic proof invariants for a proposal."""

    return build_invariant_runner(evidence, safepay)

