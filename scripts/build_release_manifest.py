#!/usr/bin/env python3
"""Build Concordia's fixed-path, post-hoc finals release manifest once."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Sequence

from shared.release_manifest import (
    RELEASE_MANIFEST_PATH,
    ReleaseManifestError,
    build_release_manifest,
    write_release_manifest_once,
)


ROOT = Path(__file__).resolve().parents[1]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    parser.add_argument(
        "--generated-at",
        required=True,
        help="canonical RFC3339 UTC-Z time after all staged observations",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        payload = build_release_manifest(
            args.repository_root,
            generated_at=args.generated_at,
        )
        write_release_manifest_once(args.repository_root, payload)
    except ReleaseManifestError as exc:
        print(
            json.dumps(
                {"error": str(exc), "status": "invalid"},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    print(
        json.dumps(
            {
                "path": RELEASE_MANIFEST_PATH,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "status": "ready",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised by CLI acceptance test
    raise SystemExit(main())
