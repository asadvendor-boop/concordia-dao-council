#!/usr/bin/env python3
"""Compose, verify, and atomically publish one canonical Concordia v3 proof.

This command is offline and write-once. It neither signs nor submits deploys.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import json
import os
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from scripts.prepare_v3_envelope import prepare_v3_envelope
from scripts.verify_v3_proof import (
    ProofVerificationError,
    verify_v3_proof_document,
)


PROOF_SCHEMA_ID = "concordia.v3-proof.v1"
VERIFICATION_SCHEMA_ID = "concordia.v3-proof-verification.v1"
FINALIZED_RUN_FIELDS = {
    "schema_id",
    "status",
    "network",
    "package_hash",
    "contract_hash",
    "prepared",
    "role_accounts",
    "steps",
    "readback",
}


class ProofCompositionError(ValueError):
    """The supplied artifacts cannot form one verified canonical proof."""


def _object_copy(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofCompositionError(f"{label} must be a JSON object")
    return copy.deepcopy(dict(value))


def compose_v3_release_proof(
    *,
    deployment: Mapping[str, Any],
    typed_input: Mapping[str, Any],
    finalized_run: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive and independently verify the exact six-field v3 proof document."""

    deployment_document = _object_copy(deployment, "deployment manifest")
    input_document = _object_copy(typed_input, "typed action input")
    run_document = _object_copy(finalized_run, "finalized run output")
    if set(run_document) != FINALIZED_RUN_FIELDS:
        raise ProofCompositionError(
            "finalized run output field set is not canonical"
        )
    readback = run_document.get("readback")
    if not isinstance(readback, Mapping):
        raise ProofCompositionError(
            "finalized run output must contain its verified readback"
        )

    try:
        prepared = prepare_v3_envelope(input_document)
    except (ValueError, KeyError, TypeError) as exc:
        raise ProofCompositionError(f"typed action input is invalid: {exc}") from exc

    proof: dict[str, Any] = {
        "schema_id": PROOF_SCHEMA_ID,
        "deployment": deployment_document,
        "input": input_document,
        "prepared": copy.deepcopy(prepared),
        "run": run_document,
        "readback": copy.deepcopy(dict(readback)),
    }
    try:
        verification = verify_v3_proof_document(proof)
    except (ProofVerificationError, OSError, ValueError, KeyError, TypeError) as exc:
        raise ProofCompositionError(f"proof verification failed: {exc}") from exc
    if (
        not isinstance(verification, Mapping)
        or verification.get("schema_id") != VERIFICATION_SCHEMA_ID
        or verification.get("valid") is not True
    ):
        raise ProofCompositionError(
            "proof verification failed without an exact valid result"
        )
    return proof


def _output_exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write_json_once(path: Path, value: object) -> None:
    """Publish complete mode-0600 JSON without ever replacing a directory entry."""

    if _output_exists(path):
        raise ProofCompositionError(
            f"refusing to overwrite existing proof output: {path}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        rendered = (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError) as exc:
        raise ProofCompositionError("proof is not canonical JSON data") from exc

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise ProofCompositionError(
                f"refusing to overwrite existing proof output: {path}"
            ) from exc
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
        _fsync_directory(path.parent)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()


def write_v3_release_proof(
    *,
    output: Path,
    deployment: Mapping[str, Any],
    typed_input: Mapping[str, Any],
    finalized_run: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify all supplied evidence, then publish one new proof path."""

    if _output_exists(output):
        raise ProofCompositionError(
            f"refusing to overwrite existing proof output: {output}"
        )
    proof = compose_v3_release_proof(
        deployment=deployment,
        typed_input=typed_input,
        finalized_run=finalized_run,
    )
    _atomic_write_json_once(output, proof)
    return proof


def _reject_duplicate_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ProofCompositionError(f"duplicate JSON field is forbidden: {name}")
        result[name] = value
    return result


def _reject_nonstandard_constant(value: str) -> object:
    raise ProofCompositionError(f"non-standard JSON constant is forbidden: {value}")


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_fields,
            parse_constant=_reject_nonstandard_constant,
        )
    except ProofCompositionError:
        raise
    except json.JSONDecodeError as exc:
        raise ProofCompositionError(
            f"{label} is not valid JSON: {exc.msg}"
        ) from exc
    except OSError as exc:
        raise ProofCompositionError(f"cannot read {label}: {exc}") from exc
    return _object_copy(value, label)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Compose and offline-verify one canonical concordia.v3-proof.v1 "
            "document. The output is an explicit, atomic, write-once path."
        )
    )
    parser.add_argument(
        "--deployment",
        type=Path,
        required=True,
        help="finalized v3 deployment manifest",
    )
    parser.add_argument(
        "--input",
        dest="typed_input",
        type=Path,
        required=True,
        help="NativeTransferV1 or OfficialX402SettlementV1 typed input",
    )
    parser.add_argument(
        "--run",
        type=Path,
        required=True,
        help="finalized v3 live-run output containing its verified readback",
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="new proof output path; existing paths are never overwritten",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if _output_exists(args.out):
            raise ProofCompositionError(
                f"refusing to overwrite existing proof output: {args.out}"
            )
        deployment = _read_json_object(args.deployment, "deployment manifest")
        typed_input = _read_json_object(args.typed_input, "typed action input")
        finalized_run = _read_json_object(args.run, "finalized run output")
        proof = write_v3_release_proof(
            output=args.out,
            deployment=deployment,
            typed_input=typed_input,
            finalized_run=finalized_run,
        )
    except (ProofCompositionError, OSError) as exc:
        print(
            json.dumps(
                {"error": str(exc), "valid": False, "written": False},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1

    prepared = proof["prepared"]
    print(
        json.dumps(
            {
                "action": prepared["action"],
                "action_id": prepared["action_id"],
                "envelope_hash": prepared["envelope_hash"],
                "output": str(args.out),
                "proposal_id": prepared["proposal_id"],
                "schema_id": PROOF_SCHEMA_ID,
                "valid": True,
                "written": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
