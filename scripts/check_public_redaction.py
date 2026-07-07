#!/usr/bin/env python3
"""Redaction gate for public Concordia proof artifacts."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shared.proof_runtime import redaction_findings, redact_public_payload


PUBLIC_ARTIFACTS = [
    ROOT / "artifacts/live/casper-final-receipt-proof.json",
    ROOT / "artifacts/live/public-evidence-reconciled.json",
    ROOT / "artifacts/live/public-runsummary-reconciled.json",
    ROOT / "artifacts/live/live-proof-pack-current.json",
    ROOT / "artifacts/live/judge-walkthrough-current.json",
    ROOT / "artifacts/live/public-trace-current.json",
    ROOT / "artifacts/live/certificate-current.html",
    ROOT / "artifacts/live/certificate-current.pdf",
    ROOT / "artifacts/live/exports/cards.csv",
    ROOT / "artifacts/live/exports/outcomes.csv",
    ROOT / "artifacts/live/exports/proof_table.csv",
    ROOT / "artifacts/live/exports/reputation.csv",
    ROOT / "artifacts/live/exports/casper_receipts.csv",
    ROOT / "artifacts/live/exports/x402_settlements.csv",
    ROOT / "artifacts/live/x402-provider-happy-path-verified.json",
    ROOT / "artifacts/live/x402-final-payment-proof.json",
    ROOT / "artifacts/live/odra-quorum-exercise-plan.json",
    ROOT / "artifacts/live/odra-topology-genesis-proof.json",
    ROOT / "artifacts/live/odra-topology-councilregistry-proof.json",
    ROOT / "artifacts/live/odra-topology-treasurypolicy-v3-proof.json",
    ROOT / "artifacts/live/odra-topology-cardindexledger-v3-proof.json",
]


def _load(path: Path) -> object:
    if path.suffix.lower() == ".pdf":
        try:
            raw = path.read_bytes()
        except Exception:
            return {"path": str(path), "status": "unreadable_or_absent"}
        strings = re.findall(rb"[\x20-\x7e]{8,}", raw)
        return {
            "path": str(path),
            "type": "pdf_printable_strings",
            "strings": [item.decode("ascii", errors="ignore") for item in strings],
        }
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        try:
            return path.read_text(encoding="utf-8")
        except Exception:
            return {"path": str(path), "status": "unreadable_or_absent"}


def main() -> int:
    bundle = {path.name: _load(path) for path in PUBLIC_ARTIFACTS}
    public_bundle = redact_public_payload(bundle)
    findings = redaction_findings(public_bundle)
    result = {
        "status": "passed" if not findings else "failed",
        "checked": [str(path.relative_to(ROOT)) for path in PUBLIC_ARTIFACTS if path.exists()],
        "findings": findings,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
