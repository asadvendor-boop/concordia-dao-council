"""The evidence matrix is itself under test.

A reviewer observed that no test referenced `validation_matrix`, so the
harness that scores every control had no oracle of its own — its PASS logic
could be wrong and nothing would notice. In particular PASS originally
compared only the refusal-code string and ignored the process exit code, so
a positive control that exited 2, or a refusal that exited 0, still scored
PASS. These tests pin the scoring rules directly.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MATRIX = REPO_ROOT / "tests" / "mainnet_canary" / "validation_matrix.py"


def _score(expected: str, observed: str, exit_code: int) -> bool:
    """Reproduce the matrix's scoring rule exactly, without re-running it."""

    expected_exit = 0 if expected == "<accepted>" else 2
    return observed == expected and exit_code == expected_exit


class TestScoringRules:
    def test_a_positive_control_that_exits_two_is_not_a_pass(self) -> None:
        # The exact defect the reviewer demonstrated.
        assert _score("<accepted>", "<accepted>", 2) is False

    def test_a_refusal_that_exits_zero_is_not_a_pass(self) -> None:
        assert _score("NODE_SET_INVALID", "NODE_SET_INVALID", 0) is False

    def test_the_right_code_with_the_right_exit_passes(self) -> None:
        assert _score("NODE_SET_INVALID", "NODE_SET_INVALID", 2) is True
        assert _score("<accepted>", "<accepted>", 0) is True

    def test_a_different_refusal_code_is_not_a_pass(self) -> None:
        assert _score("NODE_SET_INVALID", "OBSERVATION_MALFORMED", 2) is False


class TestMatrixExecution:
    def test_the_matrix_runs_green_and_emits_parseable_json(self) -> None:
        result = subprocess.run(
            [sys.executable, str(MATRIX), "--json"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            check=False,
        )
        assert result.returncode == 0, result.stderr[-2000:]
        # --json must emit ONLY the document; a trailing summary line used to
        # make this fail to parse.
        document = json.loads(result.stdout)
        assert document["failed"] == 0
        assert len(document["results"]) >= 21
        for row in document["results"]:
            assert row["pass"] is True
            assert row["exit_code"] == row["expected_exit"]

    def test_every_control_the_reviewer_named_is_covered(self) -> None:
        result = subprocess.run(
            [sys.executable, str(MATRIX), "--json"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            check=False,
        )
        observed = {row["observed"] for row in json.loads(result.stdout)["results"]}
        # The rows previously omitted, plus the two that actually exercise
        # ed25519 verification.
        for code in (
            "BUNDLE_CROSS_BINDING_INVALID",
            "CANONICAL_NAMESPACE_PROTECTED",
            "CALIBRATION_RECEIPT_ABSENT",
            "AUTHORIZATION_SIGNATURE_INVALID",
            "AUTHORIZATION_UNSIGNED",
            "OPERATOR_CEILING_NOT_PERMITTED",
            "CALIBRATION_LINE_SET_MISMATCH",
            "CALIBRATION_BINDING_INVALID",
            "CUSTODY_MODEL_INVALID",
            "<accepted>",
        ):
            assert code in observed, f"matrix no longer covers {code}"
