#!/usr/bin/env python3
"""Fail-closed production operator for the v3-authorized native transfer.

The default CLI mode is verification-only.  It reads and independently
recomputes the exact v3 authorization plus its raw, block-pinned treasury
snapshot, but neither loads a signer nor creates a journal nor contacts a node.
The only *chain-mutating* path requires ``--submit`` and an explicit signer
*file*.  Snapshot capture and post-hoc manifest generation are read-only with
respect to Casper but intentionally write the explicitly named local output.

After signed bytes are persisted by :class:`TreasuryExecutor`, every uncertain
network result is reconciled by that exact deploy hash.  This script never
rebuilds or rebroadcasts a prepared/pending transfer.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.parse import urlsplit

from pycspr import serializer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from pycspr.factory.accounts import parse_private_key_bytes
from pycspr.types.crypto import KeyAlgorithm
from pycspr.types.node.rpc import Deploy

from scripts.read_v3_state import verify_and_seal_readback_artifact
from scripts.verify_v3_proof import verify_v3_proof_document
from shared.casper_rpc_transport import (
    PinnedHttpsJsonRpc,
    RpcRemoteError,
    RpcTransportError,
    parse_rpc_authorization_file_args,
)
from shared.casper_state_proof import (
    VerifiedAccountBalance,
    verify_account_balance_at_block,
)
from shared.native_transfer_deploy import build_signed_native_transfer_deploy
from shared.native_transfer_scan import (
    VerifiedNoDuplicateNativeTransfer,
    verify_no_duplicate_native_transfer,
)
from shared.secure_secret_file import read_secure_secret_file
from shared.treasury_execution_artifact import (
    build_native_treasury_execution_artifact,
)
from shared.treasury_executor import (
    BroadcastResult,
    ExecutionState,
    FinalityEvidence,
    JournalEntry,
    ReconciliationResult,
    TreasuryExecutor,
)
from shared.v3_authorization import (
    V3DeploymentIdentity,
    VerifiedNativeAuthorization,
    validate_verified_authorization,
    verify_exact_v3_finalization,
    verify_native_authorization,
)


EXACT_TREASURY_BASELINE_MOTES = 625_000_000_000
EXACT_TRANSFER_MOTES = 50_000_000_000
EXACT_APPROVED_BPS = 800
MAX_SCAN_BLOCKS = 2_048
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class OperatorError(RuntimeError):
    """The operator cannot safely advance or publish this execution."""


class TreasuryRpc(Protocol):
    endpoints: Sequence[str]

    def call(
        self,
        endpoint: str,
        method: str,
        params: dict[str, object],
        request_id: object,
        *,
        allow_submit: bool = False,
    ) -> dict[str, object]: ...


@dataclass(frozen=True, slots=True)
class TreasuryOperatorResult:
    entry: JournalEntry
    artifact_bytes: bytes | None


def _object(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise OperatorError(f"{label} is malformed")
    return value


def _lower_hash(value: object, label: str) -> str:
    if type(value) is not str or _HASH_RE.fullmatch(value) is None:
        raise OperatorError(f"{label} is not an exact lowercase hash")
    return value


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise OperatorError("artifact is not canonical JSON") from exc


def _snapshot_node_origin(value: object) -> tuple[str, int]:
    if type(value) is not str or not value:
        raise OperatorError("treasury snapshot node URL is invalid")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise OperatorError("treasury snapshot node URL is invalid") from exc
    host = parts.hostname
    if (
        parts.scheme != "https"
        or host is None
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or parts.path != "/rpc"
        or port not in (None, 443)
    ):
        raise OperatorError("treasury snapshot node URL is not credential-free HTTPS")
    normalized = host.casefold().rstrip(".")
    if not normalized or not normalized.isascii():
        raise OperatorError("treasury snapshot node hostname is invalid")
    try:
        address = ipaddress.ip_address(normalized.strip("[]"))
    except ValueError:
        if "." not in normalized or normalized.endswith(".local"):
            raise OperatorError("treasury snapshot node hostname is not public")
    else:
        if not (
            address.is_global
            and not address.is_multicast
            and not address.is_reserved
            and not address.is_unspecified
            and not address.is_loopback
            and not address.is_link_local
            and not address.is_private
        ):
            raise OperatorError("treasury snapshot node address is not public")
    return normalized, 443


def _snapshot_capture_time(value: object) -> str:
    if type(value) is not str or not value.endswith("Z"):
        raise OperatorError("treasury snapshot capture time is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise OperatorError("treasury snapshot capture time is invalid") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise OperatorError("treasury snapshot capture time is not UTC")
    return value


def _load_json(path: Path, label: str) -> dict[str, Any]:
    def reject_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size > 64 * 1024 * 1024
        ):
            raise OSError("unsafe input")
        decoded = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_pairs,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise OperatorError(f"{label} could not be read safely") from exc
    return _object(decoded, label)


def _snapshot_from_artifact(
    value: object,
    *,
    expected_account_hash: bytes,
    expected_block_hash: bytes,
    expected_block_height: int,
    expected_balance_motes: int,
) -> VerifiedAccountBalance:
    snapshot = _object(value, "treasury snapshot artifact")
    if (
        set(snapshot)
        != {
            "schema_id",
            "network",
            "source_account_hash",
            "expected_balance_motes",
            "observations",
        }
        or snapshot.get("schema_id") != "concordia.native-treasury-snapshot.v1"
    ):
        raise OperatorError("treasury snapshot artifact fields are not exact")
    if (
        snapshot.get("network") != "casper-test"
        or snapshot.get("source_account_hash") != expected_account_hash.hex()
        or snapshot.get("expected_balance_motes") != str(expected_balance_motes)
    ):
        raise OperatorError("treasury snapshot identity differs from the typed action")
    observations = snapshot.get("observations")
    if type(observations) is not list or len(observations) != 2:
        raise OperatorError("treasury snapshot requires exactly two node observations")
    proofs: list[VerifiedAccountBalance] = []
    origins: set[tuple[str, int]] = set()
    try:
        expected_root: bytes | None = None
        for raw_observation in observations:
            observation = _object(raw_observation, "treasury snapshot observation")
            if set(observation) != {
                "node_url",
                "captured_at",
                "status_request",
                "status_response",
                "block_request",
                "block_response",
                "balance_request",
                "balance_response",
            }:
                raise OperatorError(
                    "treasury snapshot observation fields are not exact"
                )
            origin = _snapshot_node_origin(observation.get("node_url"))
            if origin in origins:
                raise OperatorError("treasury snapshot nodes are not distinct")
            origins.add(origin)
            _snapshot_capture_time(observation.get("captured_at"))
            observed_hash, observed_height, observed_root = _block_facts(
                observation["block_response"]
            )
            if (
                observed_hash != expected_block_hash.hex()
                or observed_height != expected_block_height
            ):
                raise OperatorError(
                    "treasury snapshot block differs from the typed action"
                )
            root = bytes.fromhex(observed_root)
            if expected_root is None:
                expected_root = root
            elif root != expected_root:
                raise OperatorError("treasury snapshot nodes disagree on state root")
            proofs.append(
                verify_account_balance_at_block(
                    chain_status_request=observation["status_request"],
                    chain_status_payload=observation["status_response"],
                    canonical_block_request=observation["block_request"],
                    canonical_block_payload=observation["block_response"],
                    balance_request=observation["balance_request"],
                    balance_response=observation["balance_response"],
                    expected_account_hash=expected_account_hash,
                    expected_block_hash=expected_block_hash,
                    expected_block_height=expected_block_height,
                    expected_state_root_hash=root,
                    expected_balance_motes=expected_balance_motes,
                )
            )
        first, second = proofs
        first_facts = (
            first.network,
            first.account_hash,
            first.block_hash,
            first.block_height,
            first.state_root_hash,
            first.balance_motes,
        )
        second_facts = (
            second.network,
            second.account_hash,
            second.block_hash,
            second.block_height,
            second.state_root_hash,
            second.balance_motes,
        )
        if first_facts != second_facts:
            raise OperatorError("treasury snapshot node observations do not agree")
        return first
    except ValueError as exc:
        raise OperatorError("treasury snapshot artifact is not parser-valid") from exc


def verify_native_authorization_artifacts(
    v3_proof: object,
    treasury_snapshot: object,
) -> VerifiedNativeAuthorization:
    """Independently recompute the exact finalized v3 NativeTransfer action."""

    proof = _object(v3_proof, "v3 proof")
    try:
        verified_summary = verify_v3_proof_document(proof)
    except (ValueError, KeyError, TypeError) as exc:
        raise OperatorError("exact-v3 proof did not verify") from exc
    if verified_summary.get("valid") is not True:
        raise OperatorError("exact-v3 proof did not verify")

    deployment_raw = _object(proof.get("deployment"), "v3 deployment")
    input_document = _object(proof.get("input"), "v3 typed input")
    header = _object(input_document.get("header"), "v3 typed header")
    body = _object(input_document.get("body"), "v3 typed body")
    build = _object(deployment_raw.get("build"), "v3 deployment build")
    source = _object(deployment_raw.get("source"), "v3 deployment source")
    try:
        deployment = V3DeploymentIdentity(
            network="casper-test",
            package_hash=bytes.fromhex(
                _lower_hash(deployment_raw.get("package_hash"), "v3 package hash")
            ),
            contract_hash=bytes.fromhex(
                _lower_hash(deployment_raw.get("contract_hash"), "v3 contract hash")
            ),
            schema_version=3,
            deployment_domain=bytes.fromhex(
                _lower_hash(
                    deployment_raw.get("deployment_domain"),
                    "v3 deployment domain",
                )
            ),
            casper_chain_name="casper-test",
            source_sha256=bytes.fromhex(
                _lower_hash(source.get("lib_rs_sha256"), "v3 source hash")
            ),
            wasm_sha256=bytes.fromhex(
                _lower_hash(build.get("wasm_sha256"), "v3 Wasm hash")
            ),
            schema_sha256=bytes.fromhex(
                _lower_hash(build.get("schema_sha256"), "v3 schema hash")
            ),
        )
        readback = verify_and_seal_readback_artifact(proof.get("readback"))
        finalization = verify_exact_v3_finalization(proof)
        snapshot = _snapshot_from_artifact(
            treasury_snapshot,
            expected_account_hash=bytes.fromhex(str(body["source_account"])),
            expected_block_hash=bytes.fromhex(str(body["snapshot_block_hash"])),
            expected_block_height=int(str(body["snapshot_block_height"])),
            expected_balance_motes=int(str(body["treasury_snapshot_balance_motes"])),
        )
        authorization = verify_native_authorization(
            header=header,
            body=body,
            deployment=deployment,
            readback=readback,
            snapshot=snapshot,
            finalization=finalization,
        )
        return validate_verified_authorization(authorization)
    except (ValueError, KeyError, TypeError) as exc:
        raise OperatorError(
            "v3 proof and treasury snapshot are not exactly bound"
        ) from exc


def _require_finals_story(authorization: VerifiedNativeAuthorization) -> None:
    failures: list[str] = []
    if authorization.treasury_snapshot_balance_motes != EXACT_TREASURY_BASELINE_MOTES:
        failures.append("625 CSPR treasury baseline")
    if authorization.amount_motes != EXACT_TRANSFER_MOTES:
        failures.append("50 CSPR transfer")
    if authorization.approved_allocation_bps != EXACT_APPROVED_BPS:
        failures.append("800 bps allocation")
    if failures:
        raise OperatorError("finals authorization must bind " + ", ".join(failures))
    try:
        validate_verified_authorization(authorization)
    except ValueError as exc:
        raise OperatorError("authorization is not factory-verified") from exc
    if (
        authorization.treasury_snapshot_balance_motes
        * authorization.approved_allocation_bps
        // 10_000
        != authorization.amount_motes
    ):
        raise OperatorError("50 CSPR must be exactly 8% of the 625 CSPR snapshot")


def require_durable_journal_path(path: Path) -> Path:
    """Require an explicit absolute, non-symlink SQLite journal target."""

    candidate = Path(path)
    if (
        not candidate.is_absolute()
        or candidate.suffix not in {".db", ".sqlite", ".sqlite3"}
        or candidate.name in {".db", ".sqlite", ".sqlite3"}
    ):
        raise OperatorError("journal must be an absolute durable SQLite file path")
    parent = candidate.parent
    if not parent.exists() or not parent.is_dir() or parent.is_symlink():
        raise OperatorError("journal parent must be an existing durable directory")
    if candidate.exists() and (candidate.is_symlink() or not candidate.is_file()):
        raise OperatorError("journal target is not a regular durable SQLite file")
    return candidate


def load_signer_from_file(
    path: Path,
    key_algorithm: str,
    expected_source_account: bytes,
) -> object:
    """Load a local signer without ever including its path or contents in errors."""

    try:
        raw = read_secure_secret_file(Path(path), max_bytes=64 * 1024)
        algorithm = KeyAlgorithm[key_algorithm.strip().upper()]
        if algorithm not in {KeyAlgorithm.ED25519, KeyAlgorithm.SECP256K1}:
            raise ValueError("unsupported signer algorithm")
        private = serialization.load_pem_private_key(raw, password=None)
        if algorithm is KeyAlgorithm.ED25519:
            if not isinstance(private, ed25519.Ed25519PrivateKey):
                raise ValueError("signer algorithm mismatch")
            private_bytes = private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        else:
            if not isinstance(private, ec.EllipticCurvePrivateKey) or not isinstance(
                private.curve, ec.SECP256K1
            ):
                raise ValueError("signer algorithm mismatch")
            private_bytes = private.private_numbers().private_value.to_bytes(32, "big")
        signer = parse_private_key_bytes(private_bytes, algorithm)
        account_hash = signer.to_public_key().to_account_hash()
        if (
            type(expected_source_account) is not bytes
            or len(expected_source_account) != 32
        ):
            raise ValueError("invalid expected source")
        if account_hash != expected_source_account:
            raise ValueError("source mismatch")
        return signer
    except Exception:
        raise OperatorError(
            "signer key file is invalid or does not match the treasury"
        ) from None


def atomic_write_once(path: Path, data: bytes) -> None:
    """Create an artifact durably; same bytes are idempotent, others conflict."""

    candidate = Path(path)
    if type(data) is not bytes or not data:
        raise OperatorError("artifact bytes must be non-empty")
    if (
        not candidate.is_absolute()
        or not candidate.parent.is_dir()
        or candidate.parent.is_symlink()
    ):
        raise OperatorError("artifact path must be absolute in an existing directory")
    if candidate.exists():
        if candidate.is_symlink() or not candidate.is_file():
            raise OperatorError("artifact target is not a regular file")
        try:
            existing = candidate.read_bytes()
        except OSError as exc:
            raise OperatorError("existing artifact could not be read") from exc
        if existing != data:
            raise OperatorError("artifact already exists with different bytes")
        return
    temporary = candidate.parent / (
        f".{candidate.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(temporary, flags, 0o644)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)
        try:
            os.link(temporary, candidate)
        except FileExistsError:
            if candidate.is_symlink() or not candidate.is_file():
                raise OperatorError("artifact target is not a regular file")
            if candidate.read_bytes() != data:
                raise OperatorError("artifact already exists with different bytes")
        directory = os.open(candidate.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise OperatorError("artifact could not be written durably") from exc
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def build_posthoc_release_manifest(
    *,
    artifact_path: Path,
    artifact_commit: str,
    repository_root: Path,
) -> bytes:
    """Verify the commit that contains an artifact, then name it externally.

    The execution artifact names the clean source commit used by the operator
    and the already-deployed v3 commit.  It cannot honestly name the future
    commit that will contain itself.  This post-hoc manifest closes that loop by
    reading the artifact bytes directly from ``artifact_commit`` with Git.
    """

    if _COMMIT_RE.fullmatch(artifact_commit) is None:
        raise OperatorError("artifact commit is invalid")
    root = repository_root.resolve()
    if artifact_path.is_symlink() or not artifact_path.is_file():
        raise OperatorError("artifact must be a regular repository file")
    candidate = artifact_path.resolve()
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise OperatorError("artifact must be inside the release repository") from exc
    relative_git = relative.as_posix()
    try:
        committed = subprocess.run(
            ["git", "show", f"{artifact_commit}:{relative_git}"],
            cwd=root,
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise OperatorError(
            "artifact commit does not contain the stated artifact"
        ) from exc
    current = candidate.read_bytes()
    if committed != current:
        raise OperatorError("working artifact differs from artifact commit bytes")
    try:
        artifact = _object(json.loads(current), "native treasury artifact")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OperatorError("native treasury artifact is invalid JSON") from exc
    if _canonical_json_bytes(artifact) != current:
        raise OperatorError("native treasury artifact is not canonical JSON")
    if artifact.get("schema_version") != "concordia.native_treasury_execution.v1":
        raise OperatorError("native treasury artifact schema is not supported")
    source_commit = artifact.get("source_commit")
    deployment_commit = artifact.get("deployment_commit")
    if (
        type(source_commit) is not str
        or _COMMIT_RE.fullmatch(source_commit) is None
        or type(deployment_commit) is not str
        or _COMMIT_RE.fullmatch(deployment_commit) is None
    ):
        raise OperatorError("native treasury artifact release identities are invalid")
    authorization = _object(
        artifact.get("authorization"), "native treasury authorization"
    )
    exact_proof = _object(
        authorization.get("exact_v3_proof"), "native treasury exact v3 proof"
    )
    proof_deployment = _object(
        exact_proof.get("deployment"), "native treasury v3 deployment"
    )
    if proof_deployment.get("deployment_commit") != deployment_commit:
        raise OperatorError(
            "native treasury deployment commit differs from exact v3 proof"
        )
    for label, release_commit in (
        ("source", source_commit),
        ("deployment", deployment_commit),
    ):
        try:
            ancestry = subprocess.run(
                [
                    "git",
                    "merge-base",
                    "--is-ancestor",
                    release_commit,
                    artifact_commit,
                ],
                cwd=root,
                capture_output=True,
            )
        except OSError as exc:
            raise OperatorError(
                f"artifact {label} ancestry could not be verified"
            ) from exc
        if ancestry.returncode != 0:
            raise OperatorError(
                f"artifact {label} commit is not an ancestor of artifact commit"
            )
    manifest = {
        "schema_id": "concordia.native-treasury-execution-release.v1",
        "status": "artifact_commit_verified",
        "artifact_path": relative_git,
        "artifact_sha256": hashlib.sha256(current).hexdigest(),
        "source_commit": source_commit,
        "deployment_commit": deployment_commit,
        "artifact_commit": artifact_commit,
        "commit_binding": "git_show_exact_bytes",
    }
    return _canonical_json_bytes(manifest)


def _request(
    rpc: TreasuryRpc,
    endpoint: str,
    method: str,
    params: dict[str, object],
    request_id: str,
    *,
    allow_submit: bool = False,
) -> tuple[dict[str, object], dict[str, object]]:
    request = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": copy.deepcopy(params),
    }
    response = rpc.call(
        endpoint,
        method,
        copy.deepcopy(params),
        request_id,
        allow_submit=allow_submit,
    )
    return request, response


def _unwrap_result(response: object, label: str) -> dict[str, Any]:
    body = _object(response, f"{label} response")
    result = _object(body.get("result"), f"{label} result")
    if "name" in result or "value" in result:
        if set(result) != {"name", "value"} or type(result.get("name")) is not str:
            raise OperatorError(f"{label} result wrapper is malformed")
        return _object(result.get("value"), f"{label} result value")
    return result


def _execution_block_hash(response: object) -> str | None:
    value = _unwrap_result(response, "deploy lookup")
    execution_info = value.get("execution_info")
    if execution_info is not None:
        info = _object(execution_info, "deploy execution info")
        return _lower_hash(info.get("block_hash"), "deploy execution block hash")
    results = value.get("execution_results")
    if results is None:
        return None
    if type(results) is not list:
        raise OperatorError("deploy execution results are malformed")
    if not results:
        return None
    if len(results) != 1:
        raise OperatorError("deploy lookup returned multiple execution results")
    return _lower_hash(
        _object(results[0], "deploy execution result").get("block_hash"),
        "deploy execution block hash",
    )


def _block_facts(response: object) -> tuple[str, int, str]:
    value = _unwrap_result(response, "block")
    if "block_with_signatures" in value:
        wrapper = _object(value["block_with_signatures"], "block wrapper")
        raw = _object(wrapper.get("block"), "block")
    else:
        raw = _object(value.get("block"), "block")
    versions = [version for version in ("Version1", "Version2") if version in raw]
    if versions:
        if len(versions) != 1 or len(raw) != 1:
            raise OperatorError("versioned block wrapper is malformed")
        block = _object(raw[versions[0]], "versioned block")
    else:
        block = raw
    header = _object(block.get("header"), "block header")
    block_hash = _lower_hash(block.get("hash"), "block hash")
    state_root = _lower_hash(
        header.get("state_root_hash", header.get("stateRootHash")),
        "state root hash",
    )
    height = header.get("height")
    if type(height) is not int or isinstance(height, bool) or height < 0:
        raise OperatorError("block height is invalid")
    return block_hash, height, state_root


def _tip_facts(response: object) -> tuple[int, str]:
    value = _unwrap_result(response, "status")
    if value.get("chainspec_name", value.get("chainspecName")) != "casper-test":
        raise OperatorError("RPC status is not casper-test")
    block = _object(value.get("last_added_block_info"), "status tip")
    height = block.get("height")
    if type(height) is not int or isinstance(height, bool) or height < 0:
        raise OperatorError("status tip height is invalid")
    return height, _lower_hash(block.get("hash"), "status tip hash")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def capture_native_treasury_snapshot(
    rpc: TreasuryRpc,
    source_account_hash: bytes,
) -> bytes:
    """Capture two-node, read-only proof of the exact 625 CSPR baseline."""

    if (
        type(source_account_hash) is not bytes
        or len(source_account_hash) != 32
        or source_account_hash == bytes(32)
    ):
        raise OperatorError("treasury source must be a non-zero AccountHash")
    endpoints = tuple(rpc.endpoints)
    if len(endpoints) != 2 or len(set(endpoints)) != 2:
        raise OperatorError("snapshot capture requires exactly two distinct RPC nodes")
    for endpoint in endpoints:
        _snapshot_node_origin(endpoint)

    first_status_request, first_status_response = _request(
        rpc,
        endpoints[0],
        "info_get_status",
        {},
        "treasury-snapshot-status-0",
    )
    selected_height, selected_hash = _tip_facts(first_status_response)
    expected_root: str | None = None
    observations: list[dict[str, object]] = []
    for index, endpoint in enumerate(endpoints):
        if index == 0:
            status_request = first_status_request
            status_response = first_status_response
        else:
            status_request, status_response = _request(
                rpc,
                endpoint,
                "info_get_status",
                {},
                f"treasury-snapshot-status-{index}",
            )
        block_request, block_response = _request(
            rpc,
            endpoint,
            "chain_get_block",
            {"block_identifier": {"Hash": selected_hash}},
            f"treasury-snapshot-block-{index}",
        )
        block_hash, block_height, state_root = _block_facts(block_response)
        if block_hash != selected_hash or block_height != selected_height:
            raise OperatorError("snapshot nodes do not agree on selected block")
        if expected_root is None:
            expected_root = state_root
        elif state_root != expected_root:
            raise OperatorError("snapshot nodes do not agree on state root")
        balance_params = {
            "state_identifier": {"StateRootHash": state_root},
            "purse_identifier": {
                "main_purse_under_account_hash": (
                    f"account-hash-{source_account_hash.hex()}"
                )
            },
        }
        balance_request, balance_response = _request(
            rpc,
            endpoint,
            "query_balance_details",
            balance_params,
            f"treasury-snapshot-balance-{index}",
        )
        observations.append(
            {
                "node_url": endpoint,
                "captured_at": _utc_now(),
                "status_request": status_request,
                "status_response": status_response,
                "block_request": block_request,
                "block_response": block_response,
                "balance_request": balance_request,
                "balance_response": balance_response,
            }
        )
    artifact = {
        "schema_id": "concordia.native-treasury-snapshot.v1",
        "network": "casper-test",
        "source_account_hash": source_account_hash.hex(),
        "expected_balance_motes": str(EXACT_TREASURY_BASELINE_MOTES),
        "observations": observations,
    }
    _snapshot_from_artifact(
        artifact,
        expected_account_hash=source_account_hash,
        expected_block_hash=bytes.fromhex(selected_hash),
        expected_block_height=selected_height,
        expected_balance_motes=EXACT_TREASURY_BASELINE_MOTES,
    )
    return _canonical_json_bytes(artifact)


class TreasuryExecutionOperator:
    """Production adapter around the durable executor state machine."""

    def __init__(
        self,
        *,
        executor: TreasuryExecutor,
        authorization: VerifiedNativeAuthorization,
        rpc: TreasuryRpc,
        signer_loader: Callable[[], object],
        timestamp_seconds: float,
        source_commit: str,
        deployment_commit: str,
    ) -> None:
        _require_finals_story(authorization)
        if len(tuple(rpc.endpoints)) != 2 or len(set(rpc.endpoints)) != 2:
            raise OperatorError(
                "exactly two distinct public RPC endpoints are required"
            )
        if not isinstance(timestamp_seconds, (int, float)) or isinstance(
            timestamp_seconds, bool
        ):
            raise OperatorError("signed deploy timestamp is invalid")
        if _COMMIT_RE.fullmatch(source_commit) is None:
            raise OperatorError("source commit is invalid")
        if _COMMIT_RE.fullmatch(deployment_commit) is None:
            raise OperatorError("deployment commit is invalid")
        try:
            proof = _object(
                json.loads(authorization.v3_proof_artifact_json),
                "exact v3 proof",
            )
            proof_deployment = _object(proof.get("deployment"), "exact v3 deployment")
        except json.JSONDecodeError as exc:
            raise OperatorError("exact v3 proof release identity is invalid") from exc
        if proof_deployment.get("deployment_commit") != deployment_commit:
            raise OperatorError(
                "deployment commit differs from exact v3 authorization proof"
            )
        self.executor = executor
        self.authorization = authorization
        self.rpc = rpc
        self.signer_loader = signer_loader
        self.timestamp_seconds = float(timestamp_seconds)
        self.source_commit = source_commit
        self.deployment_commit = deployment_commit

    def _prepare(self, authorization: VerifiedNativeAuthorization) -> bytes:
        signer = self.signer_loader()
        return build_signed_native_transfer_deploy(
            source_private_key=signer,
            recipient_account_hash=authorization.recipient_account,
            amount_motes=authorization.amount_motes,
            transfer_id=authorization.transfer_id,
            payment_amount_motes=self.executor.payment_amount_motes,
            timestamp_seconds=self.timestamp_seconds,
            ttl="30m",
            chain_name="casper-test",
        )

    def _broadcast(self, signed_bytes: bytes, expected_hash: str) -> BroadcastResult:
        try:
            remainder, deploy = serializer.from_bytes(signed_bytes, Deploy)
            if remainder or serializer.to_bytes(deploy) != signed_bytes:
                raise OperatorError("persisted signed deploy is not canonical")
            deploy_json = serializer.to_json(deploy)
            _, response = _request(
                self.rpc,
                self.rpc.endpoints[0],
                "account_put_deploy",
                {"deploy": deploy_json},
                "concordia-treasury-broadcast",
                allow_submit=True,
            )
            result = _unwrap_result(response, "broadcast")
            returned = _lower_hash(result.get("deploy_hash"), "broadcast deploy hash")
            if returned != expected_hash:
                return BroadcastResult(
                    status="ambiguous",
                    deploy_hash=expected_hash,
                    detail_code="broadcast_hash_mismatch",
                )
            return BroadcastResult(
                status="accepted",
                deploy_hash=expected_hash,
                detail_code="node_accepted_exact_hash",
            )
        except Exception:
            # Once bytes leave the process, every exception is ambiguous.  The
            # journal already contains bytes+hash and reconciliation is the only
            # safe next operation.
            return BroadcastResult(
                status="ambiguous",
                deploy_hash=expected_hash,
                detail_code="broadcast_outcome_ambiguous",
            )

    def _reconcile(self, deploy_hash: str) -> ReconciliationResult:
        observations: list[dict[str, object]] = []
        for index, endpoint in enumerate(self.rpc.endpoints):
            try:
                status_request, status_response = _request(
                    self.rpc,
                    endpoint,
                    "info_get_status",
                    {},
                    f"treasury-status-{index}",
                )
                transaction_request, transaction_response = _request(
                    self.rpc,
                    endpoint,
                    "info_get_deploy",
                    {"deploy_hash": deploy_hash, "finalized_approvals": True},
                    f"treasury-deploy-{index}",
                )
                block_hash = _execution_block_hash(transaction_response)
            except RpcRemoteError:
                return ReconciliationResult(
                    status="pending",
                    deploy_hash=deploy_hash,
                    detail_code="deploy_not_finalized_on_all_nodes",
                )
            if block_hash is None:
                return ReconciliationResult(
                    status="pending",
                    deploy_hash=deploy_hash,
                    detail_code="deploy_not_finalized_on_all_nodes",
                )
            block_request, block_response = _request(
                self.rpc,
                endpoint,
                "chain_get_block",
                {"block_identifier": {"Hash": block_hash}},
                f"treasury-block-{index}",
            )
            observations.append(
                {
                    "node_url": endpoint,
                    "captured_at": _utc_now(),
                    "status_request": status_request,
                    "status_response": status_response,
                    "transaction_request": transaction_request,
                    "transaction_response": transaction_response,
                    "canonical_block_request": block_request,
                    "canonical_block_response": block_response,
                }
            )
        return ReconciliationResult(
            status="finalized",
            deploy_hash=deploy_hash,
            finality_evidence=FinalityEvidence(tuple(observations)),
            detail_code="two_node_finality_observed",
        )

    def _capture_balance(
        self,
        *,
        account_hash: bytes,
        block_hash: bytes,
        block_height: int,
        state_root_hash: bytes,
        request_prefix: str,
        expected_balance_motes: int | None = None,
    ) -> VerifiedAccountBalance:
        endpoint = self.rpc.endpoints[0]
        status_request, status_response = _request(
            self.rpc,
            endpoint,
            "info_get_status",
            {},
            f"{request_prefix}-status",
        )
        block_request, block_response = _request(
            self.rpc,
            endpoint,
            "chain_get_block",
            {"block_identifier": {"Hash": block_hash.hex()}},
            f"{request_prefix}-block",
        )
        balance_params = {
            "state_identifier": {"StateRootHash": state_root_hash.hex()},
            "purse_identifier": {
                "main_purse_under_account_hash": f"account-hash-{account_hash.hex()}"
            },
        }
        balance_request, balance_response = _request(
            self.rpc,
            endpoint,
            "query_balance_details",
            balance_params,
            f"{request_prefix}-balance",
        )
        try:
            return verify_account_balance_at_block(
                chain_status_request=status_request,
                chain_status_payload=status_response,
                canonical_block_request=block_request,
                canonical_block_payload=block_response,
                balance_request=balance_request,
                balance_response=balance_response,
                expected_account_hash=account_hash,
                expected_block_hash=block_hash,
                expected_block_height=block_height,
                expected_state_root_hash=state_root_hash,
                expected_balance_motes=expected_balance_motes,
            )
        except ValueError as exc:
            raise OperatorError("block-pinned account balance did not verify") from exc

    def _pre_source_balance(self) -> VerifiedAccountBalance:
        authorization = self.authorization
        try:
            return verify_account_balance_at_block(
                chain_status_request=json.loads(
                    authorization.snapshot_status_request_json
                ),
                chain_status_payload=json.loads(authorization.snapshot_status_json),
                canonical_block_request=json.loads(
                    authorization.snapshot_block_request_json
                ),
                canonical_block_payload=json.loads(authorization.snapshot_block_json),
                balance_request=json.loads(authorization.snapshot_balance_request_json),
                balance_response=json.loads(
                    authorization.snapshot_balance_response_json
                ),
                expected_account_hash=authorization.source_account,
                expected_block_hash=authorization.snapshot_block_hash,
                expected_block_height=authorization.snapshot_block_height,
                expected_state_root_hash=authorization.snapshot_state_root_hash,
                expected_balance_motes=authorization.treasury_snapshot_balance_motes,
            )
        except (ValueError, json.JSONDecodeError) as exc:
            raise OperatorError(
                "persisted treasury snapshot no longer verifies"
            ) from exc

    def _pre_recipient_balance(self) -> VerifiedAccountBalance:
        """Require an addressable recipient at the snapshot before signing."""

        authorization = self.authorization
        try:
            return self._capture_balance(
                account_hash=authorization.recipient_account,
                block_hash=authorization.snapshot_block_hash,
                block_height=authorization.snapshot_block_height,
                state_root_hash=authorization.snapshot_state_root_hash,
                request_prefix="treasury-preflight-recipient",
            )
        except (OperatorError, RpcRemoteError, RpcTransportError, ValueError):
            raise OperatorError(
                "recipient must exist at the authorization snapshot before signing"
            ) from None

    def _scan_no_duplicate(
        self,
        entry: JournalEntry,
    ) -> VerifiedNoDuplicateNativeTransfer:
        if entry.finality_proof is None:
            raise OperatorError("finality proof is missing")
        endpoint = self.rpc.endpoints[0]
        status_request, status_response = _request(
            self.rpc,
            endpoint,
            "info_get_status",
            {},
            "treasury-scan-tip",
        )
        tip_height, _ = _tip_facts(status_response)
        start = self.authorization.finalization_block_height
        if tip_height < entry.finality_proof.block_height:
            raise OperatorError("observed scan tip predates transfer finality")
        if tip_height - start + 1 > MAX_SCAN_BLOCKS:
            raise OperatorError("bounded no-second-transfer scan exceeds 2048 blocks")
        observations: list[dict[str, object]] = []
        for height in range(start, tip_height + 1):
            block_request, block_response = _request(
                self.rpc,
                endpoint,
                "chain_get_block",
                {"block_identifier": {"Height": height}},
                f"treasury-scan-block-{height}",
            )
            block_hash, observed_height, _ = _block_facts(block_response)
            if observed_height != height:
                raise OperatorError("scan block height differs from requested height")
            transfers_request, transfers_response = _request(
                self.rpc,
                endpoint,
                "chain_get_block_transfers",
                {"block_identifier": {"Hash": block_hash}},
                f"treasury-scan-transfers-{height}",
            )
            observations.append(
                {
                    "block_request": block_request,
                    "block_response": block_response,
                    "transfers_request": transfers_request,
                    "transfers_response": transfers_response,
                }
            )
        try:
            return verify_no_duplicate_native_transfer(
                chain_status_request=status_request,
                chain_status_response=status_response,
                block_observations=observations,
                authorization_block_height=start,
                finality_proof=entry.finality_proof,
            )
        except ValueError as exc:
            raise OperatorError(
                "bounded transfer scan did not prove exactly one match"
            ) from exc

    def _prove(self, entry: JournalEntry) -> JournalEntry:
        finality = entry.finality_proof
        if finality is None:
            raise OperatorError(
                "FINALIZED journal entry has no parser-verified finality"
            )
        authorization = self.authorization
        pre_source = self._pre_source_balance()
        pre_recipient = self._capture_balance(
            account_hash=authorization.recipient_account,
            block_hash=authorization.snapshot_block_hash,
            block_height=authorization.snapshot_block_height,
            state_root_hash=authorization.snapshot_state_root_hash,
            request_prefix="treasury-pre-recipient",
        )
        finality_hash = bytes.fromhex(finality.block_hash)
        finality_root = bytes.fromhex(finality.state_root_hash)
        post_source = self._capture_balance(
            account_hash=authorization.source_account,
            block_hash=finality_hash,
            block_height=finality.block_height,
            state_root_hash=finality_root,
            request_prefix="treasury-post-source",
        )
        post_recipient = self._capture_balance(
            account_hash=authorization.recipient_account,
            block_hash=finality_hash,
            block_height=finality.block_height,
            state_root_hash=finality_root,
            request_prefix="treasury-post-recipient",
        )
        scan = self._scan_no_duplicate(entry)
        return self.executor.prove_execution(
            entry.key,
            pre_source_balance=pre_source,
            pre_recipient_balance=pre_recipient,
            post_source_balance=post_source,
            post_recipient_balance=post_recipient,
            no_duplicate_proof=scan,
        )

    def _public_artifact(self, entry: JournalEntry) -> bytes:
        captured = _utc_now()
        first = build_native_treasury_execution_artifact(
            entry,
            captured_at=captured,
        )
        # Build again from the journal object.  The builder reparses every raw
        # transcript; byte equality proves deterministic local regeneration.
        second = build_native_treasury_execution_artifact(
            self.executor.get(entry.key),
            captured_at=captured,
        )
        if first != second:
            raise OperatorError("public execution artifact is not reproducible")
        decoded = _object(json.loads(first), "public execution artifact")
        authorization = _object(decoded.get("authorization"), "artifact authorization")
        typed_body = _object(authorization.get("typed_body"), "artifact typed body")
        if typed_body.get("treasury_snapshot_balance_motes") != str(
            EXACT_TREASURY_BASELINE_MOTES
        ) or typed_body.get("amount_motes") != str(EXACT_TRANSFER_MOTES):
            raise OperatorError(
                "public execution artifact changed the exact finals story"
            )
        return first

    def advance(self, *, submit: bool = False) -> TreasuryOperatorResult:
        entry = self.executor.authorize(
            self.authorization,
            source_commit=self.source_commit,
            deployment_commit=self.deployment_commit,
        )
        if submit is not True:
            return TreasuryOperatorResult(entry=entry, artifact_bytes=None)
        for _ in range(8):
            before = (entry.state, entry.updated_at, entry.last_detail_code)
            if entry.state is ExecutionState.AUTHORIZED:
                self._pre_recipient_balance()
                entry = self.executor.prepare(entry.key, self._prepare)
            elif entry.state is ExecutionState.PREPARED:
                entry = self.executor.broadcast(entry.key, self._broadcast)
            elif entry.state in {
                ExecutionState.SUBMITTED,
                ExecutionState.AMBIGUOUS_SUBMITTED,
                ExecutionState.RETRYABLE_FAILURE,
            }:
                entry = self.executor.reconcile(entry.key, self._reconcile)
                if entry.state in {
                    ExecutionState.SUBMITTED,
                    ExecutionState.AMBIGUOUS_SUBMITTED,
                    ExecutionState.RETRYABLE_FAILURE,
                }:
                    break
            elif entry.state is ExecutionState.FINALIZED:
                try:
                    entry = self._prove(entry)
                except OperatorError:
                    return TreasuryOperatorResult(entry=entry, artifact_bytes=None)
            elif entry.state is ExecutionState.PROVEN:
                return TreasuryOperatorResult(
                    entry=entry,
                    artifact_bytes=self._public_artifact(entry),
                )
            else:
                return TreasuryOperatorResult(entry=entry, artifact_bytes=None)
            after = (entry.state, entry.updated_at, entry.last_detail_code)
            if after == before:
                break
            if (
                entry.state is ExecutionState.AMBIGUOUS_SUBMITTED
                and entry.broadcast_inflight_until
            ):
                break
            if (
                entry.state is ExecutionState.SUBMITTED
                and entry.last_detail_code == "deploy_not_finalized_on_all_nodes"
            ):
                break
        if entry.state is ExecutionState.PROVEN:
            return TreasuryOperatorResult(
                entry=entry,
                artifact_bytes=self._public_artifact(entry),
            )
        return TreasuryOperatorResult(entry=entry, artifact_bytes=None)


def _clean_git_head(root: Path) -> str:
    try:
        status = subprocess.run(
            ["git", "status", "--porcelain=v1"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise OperatorError("Git release identity could not be established") from exc
    if status.stdout:
        raise OperatorError("execution requires an actually clean Git tree")
    if _COMMIT_RE.fullmatch(head) is None:
        raise OperatorError("Git HEAD is not a full commit identity")
    return head


def _deployment_commit(proof: Mapping[str, Any]) -> str:
    deployment = _object(proof.get("deployment"), "v3 deployment")
    value = deployment.get("deployment_commit")
    if type(value) is not str or _COMMIT_RE.fullmatch(value) is None:
        raise OperatorError("v3 proof deployment commit is invalid")
    return value


def _safe_plan(authorization: VerifiedNativeAuthorization) -> dict[str, object]:
    return {
        "mode": "verification-only",
        "network": authorization.network,
        "proposal_id": authorization.proposal_id,
        "action_id": authorization.action_id.hex(),
        "envelope_hash": authorization.envelope_hash.hex(),
        "deployment_domain": authorization.deployment_domain.hex(),
        "source_account": authorization.source_account.hex(),
        "recipient_account": authorization.recipient_account.hex(),
        "treasury_snapshot_balance_motes": str(
            authorization.treasury_snapshot_balance_motes
        ),
        "amount_motes": str(authorization.amount_motes),
        "approved_allocation_bps": authorization.approved_allocation_bps,
        "transfer_id": authorization.transfer_id,
        "network_mutation_performed": False,
        "local_file_written": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v3-proof", type=Path)
    parser.add_argument("--treasury-snapshot", type=Path)
    parser.add_argument("--capture-snapshot", action="store_true")
    parser.add_argument("--source-account")
    parser.add_argument("--snapshot-out", type=Path)
    parser.add_argument("--submit", action="store_true")
    parser.add_argument("--rpc", action="append", default=[])
    parser.add_argument(
        "--rpc-authorization-file",
        action="append",
        default=[],
        help="repeat URL=/absolute/token-file; token values are never accepted",
    )
    parser.add_argument("--journal", type=Path)
    parser.add_argument("--signer-key-file", type=Path)
    parser.add_argument(
        "--key-algorithm",
        choices=("ED25519", "SECP256K1"),
    )
    parser.add_argument("--artifact-out", type=Path)
    parser.add_argument("--finalize-release-manifest", type=Path)
    parser.add_argument("--artifact-commit")
    parser.add_argument("--release-manifest-out", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.capture_snapshot:
            if (
                args.submit
                or args.v3_proof is not None
                or args.treasury_snapshot is not None
                or args.journal is not None
                or args.signer_key_file is not None
                or args.key_algorithm is not None
                or args.artifact_out is not None
                or args.finalize_release_manifest is not None
                or args.artifact_commit is not None
                or args.release_manifest_out is not None
                or len(args.rpc) != 2
                or args.source_account is None
                or args.snapshot_out is None
            ):
                raise OperatorError(
                    "read-only snapshot capture requires only --source-account, "
                    "exactly two --rpc values, and --snapshot-out"
                )
            if (
                _HASH_RE.fullmatch(args.source_account) is None
                or args.source_account == "00" * 32
            ):
                raise OperatorError("snapshot source must be an exact AccountHash")
            if not args.snapshot_out.is_absolute():
                raise OperatorError("snapshot output must use an absolute path")
            authorization_files = parse_rpc_authorization_file_args(
                args.rpc_authorization_file,
                args.rpc,
            )
            rpc = PinnedHttpsJsonRpc(
                args.rpc,
                authorization_files=authorization_files,
            )
            snapshot_bytes = capture_native_treasury_snapshot(
                rpc,
                bytes.fromhex(args.source_account),
            )
            atomic_write_once(args.snapshot_out, snapshot_bytes)
            print(
                json.dumps(
                    {
                        "mode": "read-only-snapshot-capture",
                        "network_mutation_performed": False,
                        "local_file_written": True,
                        "snapshot_written": True,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        if args.finalize_release_manifest is not None:
            if (
                args.capture_snapshot
                or args.submit
                or args.v3_proof is not None
                or args.treasury_snapshot is not None
                or args.source_account is not None
                or args.snapshot_out is not None
                or args.journal is not None
                or args.signer_key_file is not None
                or args.key_algorithm is not None
                or args.artifact_out is not None
                or args.artifact_commit is None
                or args.release_manifest_out is None
                or args.rpc
                or args.rpc_authorization_file
            ):
                raise OperatorError(
                    "post-hoc finalization requires only --finalize-release-manifest, "
                    "--artifact-commit, and --release-manifest-out"
                )
            root = Path(__file__).resolve().parents[1]
            manifest = build_posthoc_release_manifest(
                artifact_path=args.finalize_release_manifest,
                artifact_commit=args.artifact_commit,
                repository_root=root,
            )
            atomic_write_once(args.release_manifest_out, manifest)
            print(
                json.dumps(
                    {
                        "status": "artifact_commit_verified",
                        "artifact_commit": args.artifact_commit,
                        "manifest_written": True,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        if args.submit and (
            args.source_account is not None
            or args.snapshot_out is not None
            or args.artifact_commit is not None
            or args.release_manifest_out is not None
        ):
            raise OperatorError(
                "submit mode accepts only --v3-proof, --treasury-snapshot, "
                "exactly two --rpc values, optional --rpc-authorization-file, "
                "--journal, --signer-key-file, --key-algorithm, and --artifact-out"
            )
        if not args.submit and (
            args.source_account is not None
            or args.snapshot_out is not None
            or args.rpc
            or args.rpc_authorization_file
            or args.journal is not None
            or args.signer_key_file is not None
            or args.key_algorithm is not None
            or args.artifact_out is not None
            or args.artifact_commit is not None
            or args.release_manifest_out is not None
        ):
            raise OperatorError(
                "verification-only mode accepts only --v3-proof and --treasury-snapshot"
            )
        if args.v3_proof is None or args.treasury_snapshot is None:
            raise OperatorError(
                "verification requires --v3-proof and --treasury-snapshot"
            )
        proof = _load_json(args.v3_proof, "v3 proof")
        snapshot = _load_json(args.treasury_snapshot, "treasury snapshot")
        authorization = verify_native_authorization_artifacts(proof, snapshot)
        _require_finals_story(authorization)
        if not args.submit:
            print(json.dumps(_safe_plan(authorization), indent=2, sort_keys=True))
            return 0
        if (
            len(args.rpc) != 2
            or args.journal is None
            or args.signer_key_file is None
            or args.key_algorithm is None
            or args.artifact_out is None
        ):
            raise OperatorError(
                "--submit requires exactly two --rpc values, --journal, "
                "--signer-key-file, --key-algorithm, and --artifact-out"
            )
        journal = require_durable_journal_path(args.journal)
        if not args.artifact_out.is_absolute():
            raise OperatorError("artifact output must use an absolute path")
        root = Path(__file__).resolve().parents[1]
        source_commit = _clean_git_head(root)
        authorization_files = parse_rpc_authorization_file_args(
            args.rpc_authorization_file,
            args.rpc,
        )
        rpc = PinnedHttpsJsonRpc(
            args.rpc,
            authorization_files=authorization_files,
        )
        executor = TreasuryExecutor(journal)
        operator = TreasuryExecutionOperator(
            executor=executor,
            authorization=authorization,
            rpc=rpc,
            signer_loader=lambda: load_signer_from_file(
                args.signer_key_file,
                args.key_algorithm,
                authorization.source_account,
            ),
            timestamp_seconds=time.time(),
            source_commit=source_commit,
            deployment_commit=_deployment_commit(proof),
        )
        result = operator.advance(submit=True)
        if result.artifact_bytes is not None:
            atomic_write_once(args.artifact_out, result.artifact_bytes)
        print(
            json.dumps(
                {
                    "state": result.entry.state.value,
                    "deploy_hash": result.entry.deploy_hash,
                    "artifact_written": result.artifact_bytes is not None,
                    "broadcast_attempts": result.entry.broadcast_attempts,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0 if result.entry.state is ExecutionState.PROVEN else 2
    except (OperatorError, RpcTransportError, ValueError, OSError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    sys.exit(main())
