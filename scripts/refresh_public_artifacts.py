#!/usr/bin/env python3
"""Regenerate static public proof artifacts from the current evidence bundle.

This script is intentionally read-only with respect to Casper. It refreshes the
packaged JSON/CSV/HTML/PDF artifacts from local evidence so the review ZIP and
live runtime helpers expose the same proof hierarchy.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shared.proof_pack import build_audit_packet
from shared.proof_runtime import (
    build_csv_exports,
    build_judge_walkthrough,
    build_public_trace,
    certificate_html,
    certificate_pdf_bytes,
    redact_public_payload,
)


LIVE = ROOT / "artifacts" / "live"
EVIDENCE = LIVE / "public-evidence-reconciled.json"


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def main() -> int:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    packet = build_audit_packet(evidence)
    walkthrough = build_judge_walkthrough(evidence)
    walkthrough["proof_center"] = packet.get("proof_center")
    walkthrough["ipfs_evidence"] = packet.get("ipfs_evidence")
    walkthrough["download_urls"] = {
        "audit_packet": f"/proof-pack/{evidence.get('proposal_id')}/download",
        "cards_csv": f"/proof-pack/{evidence.get('proposal_id')}/exports/cards.csv",
        "outcomes_csv": f"/proof-pack/{evidence.get('proposal_id')}/exports/outcomes.csv",
        "proof_table_csv": f"/proof-pack/{evidence.get('proposal_id')}/exports/proof_table.csv",
        "reputation_csv": f"/proof-pack/{evidence.get('proposal_id')}/exports/reputation.csv",
        "casper_receipts_csv": f"/proof-pack/{evidence.get('proposal_id')}/exports/casper_receipts.csv",
        "x402_settlements_csv": f"/proof-pack/{evidence.get('proposal_id')}/exports/x402_settlements.csv",
        "certificate": f"/certificate/{evidence.get('proposal_id')}",
        "certificate_pdf": f"/certificate/{evidence.get('proposal_id')}/pdf",
        "trace_api": f"/api/runs/{evidence.get('proposal_id')}/trace",
    }
    trace = build_public_trace(evidence, packet)
    exports = build_csv_exports(evidence, packet)

    _write_json(LIVE / "live-proof-pack-current.json", redact_public_payload(packet))
    _write_json(LIVE / "judge-walkthrough-current.json", redact_public_payload(walkthrough))
    _write_json(LIVE / "public-trace-current.json", redact_public_payload(trace))

    (LIVE / "certificate-current.html").write_text(
        certificate_html(evidence, packet),
        encoding="utf-8",
    )
    (LIVE / "certificate-current.pdf").write_bytes(certificate_pdf_bytes(evidence, packet))

    exports_dir = LIVE / "exports"
    exports_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in exports.items():
        (exports_dir / filename).write_text(content, encoding="utf-8")

    print(json.dumps({
        "status": "refreshed",
        "proposal_id": evidence.get("proposal_id"),
        "outputs": [
            "artifacts/live/live-proof-pack-current.json",
            "artifacts/live/judge-walkthrough-current.json",
            "artifacts/live/public-trace-current.json",
            "artifacts/live/certificate-current.html",
            "artifacts/live/certificate-current.pdf",
            "artifacts/live/exports/*.csv",
        ],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
