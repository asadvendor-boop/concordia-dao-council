"""Interactive adversarial replay helpers for the judge workflow."""
from __future__ import annotations

from typing import Any

from shared.proof_runtime import build_interactive_adversarial_replay


def build_replay(
    evidence: dict[str, Any],
    *,
    prompt: str,
    live_model_available: bool = False,
) -> dict[str, Any]:
    """Build a deterministic adversarial replay without triggering Casper execution."""

    return build_interactive_adversarial_replay(
        evidence,
        prompt=prompt,
        live_model_available=live_model_available,
    )
