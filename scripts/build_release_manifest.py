#!/usr/bin/env python3
"""Capture or assemble Concordia's fixed finals release receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shared.release_manifest import (  # noqa: E402
    RELEASE_MANIFEST_PATH,
    ReleaseManifestError,
    assemble_release_manifest_once,
    capture_release_observations_once,
    prepare_host_toolchain_receipt_once,
    run_committed_python_artifact_verifier,
    verify_command_gate_receipts,
    verify_g13_submission_receipt,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in (
        "prepare-host-toolchain",
        "verify-command-gates",
        "capture",
        "assemble",
        "verify-g13",
    ):
        child = subparsers.add_parser(command)
        child.add_argument("--repository-root", type=Path, default=ROOT)
    verifier = subparsers.add_parser("verify-python-artifact")
    verifier.add_argument("--repository-root", type=Path, default=ROOT)
    verifier.add_argument(
        "--verifier",
        choices=("historical", "v3", "card_roots", "registry"),
        required=True,
    )
    verifier.add_argument("--artifact", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.repository_root.resolve() != ROOT.resolve():
            raise ReleaseManifestError(
                "target repository must be the executing repository"
            )
        if args.command == "verify-python-artifact":
            result = run_committed_python_artifact_verifier(
                args.verifier,
                args.artifact,
            )
        elif args.command == "prepare-host-toolchain":
            path = prepare_host_toolchain_receipt_once(args.repository_root)
            payload = path.read_bytes()
            result = {
                "command": "prepare-host-toolchain",
                "path": path.relative_to(args.repository_root).as_posix(),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "status": "prepared_untrusted",
            }
        elif args.command == "verify-command-gates":
            result = {
                "command": "verify-command-gates",
                **verify_command_gate_receipts(args.repository_root),
            }
        elif args.command == "capture":
            paths = capture_release_observations_once(args.repository_root)
            result = {
                "command": "capture",
                "receipt_count": len(paths),
                "status": "captured",
            }
        elif args.command == "assemble":
            path = assemble_release_manifest_once(args.repository_root)
            payload = path.read_bytes()
            result = {
                "command": "assemble",
                "overall_status": "pending_external",
                "path": RELEASE_MANIFEST_PATH,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "status": "g12_ready",
            }
        else:
            result = {
                "command": "verify-g13",
                **verify_g13_submission_receipt(args.repository_root),
            }
    except ReleaseManifestError as exc:
        # Every lower-level error is intentionally non-reflecting.  Keep this
        # bounded JSON-only surface free of tracebacks and raw command output.
        print(
            json.dumps(
                {"error": str(exc), "status": "invalid"},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
