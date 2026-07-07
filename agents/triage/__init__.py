"""Compatibility shim for the renamed Rowan proposal sentinel.

Use ``agents.rowan`` for new Concordia code. This module remains only so older
scripts, environment variables, and tests continue to resolve during the
buildathon review window.
"""

from agents.rowan import *  # noqa: F401,F403
from agents.rowan import main
