#!/usr/bin/env python3
"""Fail if public surfaces disagree on Concordia's canonical proof hierarchy."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shared.proof_runtime import check_repo_canonical_consistency


def main() -> int:
    result = check_repo_canonical_consistency(ROOT)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
