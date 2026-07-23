#!/usr/bin/env python3
"""Run the exact G9 frontend gates and create their immutable receipt batch."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from scripts.release_gate_runner import GateRunError, run_gate


ROOT = Path(__file__).resolve().parents[1]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        result = run_gate("G9", repository_root=args.repository_root.resolve())
    except GateRunError as exc:
        print(json.dumps({"error": str(exc), "status": "invalid"}, sort_keys=True))
        return 1
    print(
        json.dumps(
            {
                "gate_id": result.gate_id,
                "receipt_path": result.receipt_path,
                "receipt_sha256": result.receipt_sha256,
                "status": "verified",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
