"""Concordia Mainnet canary — PREPARATION lane tooling.

Fail-closed, six-mode CLI (inventory / estimate / plan / stage / verify /
broadcast) prepared ahead of Codex's Testnet-RC gate.  In this lane no
transaction is ever signed, submitted, simulated with a funded key, or
broadcast on any network, and no private key or secret is ever read.

Every deployed/verified claim emitted by this package is
``BLOCKED_PENDING_LIVE_PROOF`` until Codex executes the live gate.
"""

__all__ = ["PREP_LANE"]

# This constant is load-bearing: broadcast submission is structurally
# unavailable while it is True, and nothing in this package mutates it.
PREP_LANE = True
