#!/usr/bin/env python3
"""Derive the official-x402 v3 governance binding from verified live proof."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Sequence
from typing import Any

from scripts.verify_v3_proof import verify_v3_proof_document


SCHEMA_VERSION = "concordia.x402-governance-v3-binding.v1"
CAIP2_NETWORK = "casper:casper-test"
VERIFICATION_SCHEMA = "concordia.v3-proof-verification.v1"
ACTION = "OfficialX402SettlementV1"
_HASH32 = re.compile(r"[0-9a-f]{64}")


class GovernanceConfigError(ValueError):
    """The supplied proof cannot produce the frozen governance binding."""


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GovernanceConfigError(f"{label} must be an object")
    return value


def _hash32(value: object, label: str) -> str:
    if not isinstance(value, str) or _HASH32.fullmatch(value) is None:
        raise GovernanceConfigError(f"{label} must be lowercase 32-byte hex")
    return value


def derive_x402_governance_v3_config(
    proof: Mapping[str, Any],
) -> dict[str, str]:
    verification = verify_v3_proof_document(proof)
    verified = _mapping(verification, "v3 proof verification")
    input_document = _mapping(proof.get("input"), "proof input")
    header = _mapping(input_document.get("header"), "proof input header")
    body = _mapping(input_document.get("body"), "proof input body")
    if input_document.get("action") != ACTION:
        raise GovernanceConfigError(
            f"proof must authorize {ACTION}"
        )
    if body.get("caip2_network") != CAIP2_NETWORK:
        raise GovernanceConfigError(
            f"proof network must be exactly {CAIP2_NETWORK}"
        )
    if (
        verified.get("schema_id") != VERIFICATION_SCHEMA
        or verified.get("valid") is not True
        or verified.get("network") != "casper-test"
    ):
        raise GovernanceConfigError(
            "proof verifier did not return an exact finalized Testnet result"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "network": CAIP2_NETWORK,
        "package_hash": _hash32(
            verified.get("package_hash"), "verified package_hash"
        ),
        "contract_hash": _hash32(
            verified.get("contract_hash"), "verified contract_hash"
        ),
        "deployment_domain": _hash32(
            header.get("deployment_domain"), "deployment_domain"
        ),
    }


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise GovernanceConfigError(
            "governance config is not canonical JSON data"
        ) from exc


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


def _atomic_write_once(path: Path, payload: bytes) -> None:
    if _output_exists(path):
        raise GovernanceConfigError(
            f"refusing to overwrite existing governance config: {path}"
        )
    if path.parent.is_symlink():
        raise GovernanceConfigError(
            f"output directory must not be a symlink: {path.parent}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise GovernanceConfigError(
                f"refusing to overwrite existing governance config: {path}"
            ) from exc
        except OSError as exc:
            raise GovernanceConfigError(
                f"cannot atomically publish governance config: {exc}"
            ) from exc
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
        _fsync_directory(path.parent)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()


def write_x402_governance_v3_config(
    *,
    proof: Mapping[str, Any],
    output: Path,
) -> dict[str, str]:
    """Verify the finalized proof, then atomically create one runtime config."""

    if _output_exists(output):
        raise GovernanceConfigError(
            f"refusing to overwrite existing governance config: {output}"
        )
    config = derive_x402_governance_v3_config(proof)
    _atomic_write_once(output, _canonical_json(config))
    return config


def _reject_duplicate_fields(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GovernanceConfigError(
                f"duplicate JSON field is forbidden: {key}"
            )
        result[key] = value
    return result


def _reject_nonstandard_constant(value: str) -> object:
    raise GovernanceConfigError(
        f"non-standard JSON constant is forbidden: {value}"
    )


def _read_proof(path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_fields,
            parse_constant=_reject_nonstandard_constant,
        )
    except GovernanceConfigError:
        raise
    except json.JSONDecodeError as exc:
        raise GovernanceConfigError(
            f"proof is not valid JSON: {exc.msg}"
        ) from exc
    except OSError as exc:
        raise GovernanceConfigError(f"cannot read proof: {exc}") from exc
    return dict(_mapping(parsed, "proof"))


def hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Derive the official-x402 governance identity only from an "
            "independently verified finalized Concordia v3 proof."
        )
    )
    parser.add_argument(
        "--proof",
        required=True,
        type=Path,
        help="finalized and authorized concordia.v3-proof.v1 document",
    )
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="new x402-governance-v3.json path; never overwritten",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        proof = _read_proof(args.proof)
        write_x402_governance_v3_config(proof=proof, output=args.out)
        print(
            json.dumps(
                {
                    "config_sha256": hash_file(args.out),
                    "output": os.fspath(args.out),
                    "status": "written",
                },
                sort_keys=True,
            )
        )
        return 0
    except (GovernanceConfigError, OSError, ValueError, KeyError, TypeError) as exc:
        print(
            json.dumps(
                {"error": str(exc), "status": "refused"},
                sort_keys=True,
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
