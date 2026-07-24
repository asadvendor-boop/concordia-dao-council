from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_documented_receipt_verifier_direct_entrypoint_works() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "scripts/verify_concordia_receipt.py",
            "artifacts/live/casper-final-receipt-proof.json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Concordia receipt verification passed." in result.stdout


def test_public_docs_do_not_promote_pending_live_features() -> None:
    submission = (ROOT / "docs/DORAHACKS_SUBMISSION_TEXT.md").read_text(
        encoding="utf-8"
    )
    safepay = (ROOT / "docs-site/safepay-lite.md").read_text(encoding="utf-8")
    official_x402 = (ROOT / "docs-site/official-x402.md").read_text(
        encoding="utf-8"
    )

    assert "preserved as an **on-chain receipt**" not in submission
    assert "The judge deployment has mocking disabled" not in submission
    assert "Payments are live on Casper Testnet" not in submission
    assert "The corrected SafePay implementation is not yet merged" not in safepay
    assert "WP5's corrected commit is not yet integrated" not in official_x402
