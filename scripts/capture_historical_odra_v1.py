#!/usr/bin/env python3
"""Capture the immutable v1 Odra receipt from two public Casper RPC nodes.

This tool is deliberately read-only.  It reconstructs the receipt-selected
historical card prefix from exact public ``card_json`` rows, captures five
URL-credential-free RPC transcripts from each of two independently addressed
nodes, verifies each candidate with the strict offline adapter, and only then
writes one new artifact.  An endpoint may receive raw Authorization loaded
from an endpoint-scoped owner-private file; credentials never enter URLs or
artifacts.  It has no deploy/signing path and never overwrites an existing
output.
"""

from __future__ import annotations

import argparse
import copy
import errno
import hashlib
import json
import os
import secrets
import sqlite3
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol

from gateway.database import init_db
from shared.card_chain_artifact import CardChainArtifactError, build_card_chain_artifact
from shared.casper_rpc_transport import (
    PinnedHttpsJsonRpc,
    RpcEndpointPolicyError,
    parse_rpc_authorization_file_args,
)
from shared.historical_odra_artifact import (
    HistoricalOdraArtifactError,
    PACKAGED_INVENTORY_PATH,
    verify_historical_odra_artifact,
)


MAX_PROPOSAL_PAYLOAD_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
_PROPOSAL_ID = "DAO-PROP-6CB25C"


class HistoricalCaptureError(RuntimeError):
    """The read-only capture could not produce two corroborating artifacts."""


class _Rpc(Protocol):
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


class _DuplicateKey(ValueError):
    pass


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _strict_document(raw: bytes | str, *, label: str, limit: int) -> dict[str, Any]:
    if type(raw) is bytes:
        encoded = raw
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HistoricalCaptureError(f"{label} is not UTF-8 JSON") from exc
    elif type(raw) is str:
        text = raw
        try:
            encoded = raw.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise HistoricalCaptureError(f"{label} is not UTF-8 JSON") from exc
    else:
        raise HistoricalCaptureError(f"{label} must be raw JSON")
    if not encoded or len(encoded) > limit:
        raise HistoricalCaptureError(f"{label} exceeds its size limit")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise HistoricalCaptureError(f"{label} is invalid JSON") from exc
    if type(value) is not dict:
        raise HistoricalCaptureError(f"{label} must contain an object")
    return value


def _object(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise HistoricalCaptureError(f"{label} must be an object")
    return value


def _rpc_result(response: Mapping[str, Any], label: str) -> dict[str, Any]:
    result = _object(response.get("result"), f"{label} result")
    if "name" in result or "value" in result:
        if set(result) != {"name", "value"}:
            raise HistoricalCaptureError(f"{label} result wrapper is invalid")
        result = _object(result.get("value"), f"{label} result value")
    return result


def _request(
    method: str, params: dict[str, object], request_id: int
) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": copy.deepcopy(params),
    }


def _transcript(
    *,
    rpc: _Rpc,
    endpoint: str,
    method: str,
    params: dict[str, object],
    request_id: int,
) -> dict[str, object]:
    response = rpc.call(
        endpoint,
        method,
        params,
        request_id,
        allow_submit=False,
    )
    if type(response) is not dict:
        raise HistoricalCaptureError("public RPC response is invalid")
    return {
        "request": _request(method, params, request_id),
        "response": copy.deepcopy(response),
    }


def _execution_identity(deploy_transcript: Mapping[str, Any]) -> tuple[str, int]:
    response = _object(deploy_transcript.get("response"), "deploy response")
    result = _rpc_result(response, "deploy")
    execution = _object(result.get("execution_info"), "deploy execution_info")
    block_hash = execution.get("block_hash")
    block_height = execution.get("block_height")
    if (
        type(block_hash) is not str
        or len(block_hash) != 64
        or any(character not in "0123456789abcdef" for character in block_hash)
        or type(block_height) is not int
        or block_height < 0
    ):
        raise HistoricalCaptureError("deploy execution identity is invalid")
    return block_hash, block_height


def _block_state_root(block_transcript: Mapping[str, Any]) -> str:
    response = _object(block_transcript.get("response"), "canonical block response")
    result = _rpc_result(response, "canonical block")
    if "block_with_signatures" in result:
        wrapper = _object(result["block_with_signatures"], "canonical block wrapper")
        block = _object(wrapper.get("block"), "canonical block")
    else:
        block = _object(result.get("block"), "canonical block")
    versions = [name for name in ("Version1", "Version2") if name in block]
    if versions:
        if len(versions) != 1:
            raise HistoricalCaptureError("canonical block version is ambiguous")
        block = _object(block[versions[0]], "canonical block")
    header = _object(block.get("header"), "canonical block header")
    roots = [
        header[name] for name in ("state_root_hash", "stateRootHash") if name in header
    ]
    if (
        len(roots) != 1
        or type(roots[0]) is not str
        or len(roots[0]) != 64
        or any(character not in "0123456789abcdef" for character in roots[0])
    ):
        raise HistoricalCaptureError("canonical block state root is invalid")
    return roots[0]


def _load_inventory(inventory_bytes: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    inventory = _strict_document(
        inventory_bytes,
        label="historical inventory",
        limit=256 * 1024,
    )
    chain_identity = _object(
        inventory.get("chain_identity"), "inventory chain_identity"
    )
    identity = _object(chain_identity.get("v1"), "inventory v1 identity")
    session = _object(identity.get("accepted_session"), "inventory v1 session")
    receipts = _object(identity.get("receipt_deploys"), "inventory v1 receipts")
    for field in ("package_hash", "contract_hash", "contract_wasm_state_hash"):
        value = identity.get(field)
        if type(value) is not str or len(value) != 64:
            raise HistoricalCaptureError("historical inventory v1 identity is invalid")
    final_card_hash = session.get("final_card_hash")
    deploy_hash = receipts.get("canonical_accepted")
    if (
        type(final_card_hash) is not str
        or len(final_card_hash) != 64
        or type(deploy_hash) is not str
        or len(deploy_hash) != 64
    ):
        raise HistoricalCaptureError("historical inventory v1 receipt is invalid")
    return identity, inventory


def _card_chain_from_public_payload(
    proposal_payload: Mapping[str, Any],
    *,
    proposal_id: str,
    captured_at: str,
    source_url: str,
    final_card_hash: str,
) -> dict[str, object]:
    proposal = _object(proposal_payload.get("proposal"), "public proposal")
    if proposal.get("proposal_id") != proposal_id:
        raise HistoricalCaptureError("public proposal identity is invalid")
    rows = proposal_payload.get("cards")
    if type(rows) is not list or not rows:
        raise HistoricalCaptureError("public card rows are unavailable")
    db = init_db(":memory:")
    try:
        db.execute(
            "INSERT INTO proposals (proposal_id, state, created_at, updated_at) "
            "VALUES (?, ?, ?, ?)",
            (
                proposal_id,
                str(proposal.get("state") or "UNKNOWN"),
                captured_at,
                captured_at,
            ),
        )
        for raw_row in rows:
            row = _object(raw_row, "public card row")
            if row.get("proposal_id") != proposal_id:
                raise HistoricalCaptureError("public card proposal identity is invalid")
            sequence = row.get("sequence_number")
            card_type = row.get("card_type")
            card_hash = row.get("card_hash")
            card_json = row.get("card_json")
            published_at = row.get("published_at")
            if (
                type(sequence) is not int
                or type(card_type) is not str
                or type(card_hash) is not str
                or type(card_json) is not str
                or (published_at is not None and type(published_at) is not str)
            ):
                raise HistoricalCaptureError("public card row is invalid")
            db.execute(
                "INSERT INTO cards (proposal_id, sequence_number, card_type, card_hash, "
                "card_json, created_at, published_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    proposal_id,
                    sequence,
                    card_type,
                    card_hash,
                    card_json,
                    captured_at,
                    published_at,
                ),
            )
        return build_card_chain_artifact(
            db,
            proposal_id=proposal_id,
            captured_at=captured_at,
            source_url=source_url,
            expected_final_card_hash=final_card_hash,
        )
    except (sqlite3.Error, CardChainArtifactError, HistoricalCaptureError) as exc:
        raise HistoricalCaptureError("public card chain is invalid") from exc
    finally:
        db.close()


def _contract_identity(identity: Mapping[str, Any]) -> dict[str, object]:
    session = _object(identity.get("accepted_session"), "inventory v1 session")
    return {
        "package_hash": identity["package_hash"],
        "contract_hash": identity["contract_hash"],
        "contract_wasm_state_hash": identity["contract_wasm_state_hash"],
        "contract_version": identity["contract_version"],
        "protocol_version_major": identity["protocol_version_major"],
        "entry_point": identity["entry_point"],
        "session_variant": session["variant"],
        "session_target_kind": session["target_kind"],
        "session_target_hash": session["target_hash"],
        "session_version": session["version"],
    }


def _capture_node(
    *,
    rpc: _Rpc,
    endpoint: str,
    identity: Mapping[str, Any],
) -> dict[str, object]:
    receipts = _object(identity.get("receipt_deploys"), "inventory v1 receipts")
    deploy_hash = str(receipts["canonical_accepted"])
    raw_rpc: dict[str, object] = {}
    raw_rpc["deploy"] = _transcript(
        rpc=rpc,
        endpoint=endpoint,
        method="info_get_deploy",
        params={"deploy_hash": deploy_hash, "finalized_approvals": True},
        request_id=1,
    )
    block_hash, _ = _execution_identity(_object(raw_rpc["deploy"], "deploy transcript"))
    raw_rpc["canonical_block"] = _transcript(
        rpc=rpc,
        endpoint=endpoint,
        method="chain_get_block",
        params={"block_identifier": {"Hash": block_hash}},
        request_id=2,
    )
    state_root = _block_state_root(
        _object(raw_rpc["canonical_block"], "canonical block transcript")
    )
    raw_rpc["state_root"] = _transcript(
        rpc=rpc,
        endpoint=endpoint,
        method="chain_get_state_root_hash",
        params={"block_identifier": {"Hash": block_hash}},
        request_id=3,
    )
    for request_id, label, key in (
        (4, "package", "hash-" + str(identity["package_hash"])),
        (5, "contract", "hash-" + str(identity["contract_hash"])),
    ):
        raw_rpc[label] = _transcript(
            rpc=rpc,
            endpoint=endpoint,
            method="query_global_state",
            params={
                "state_identifier": {"StateRootHash": state_root},
                "key": key,
                "path": [],
            },
            request_id=request_id,
        )
    return raw_rpc


def capture_historical_odra_v1(
    *,
    proposal_payload: Mapping[str, Any],
    rpc: _Rpc,
    captured_at: str,
    source_commit: str,
    deployment_commit: str,
    public_base_url: str,
    inventory_bytes: bytes,
) -> dict[str, object]:
    """Return one verified artifact after two independent read-only captures."""

    endpoints = tuple(rpc.endpoints)
    if len(endpoints) != 2 or endpoints[0] == endpoints[1]:
        raise HistoricalCaptureError(
            "exactly two distinct public RPC nodes are required"
        )
    identity, inventory = _load_inventory(inventory_bytes)
    if inventory.get("network") != "casper-test":
        raise HistoricalCaptureError("historical inventory network is invalid")
    session = _object(identity.get("accepted_session"), "inventory v1 session")
    proposal_id = _PROPOSAL_ID
    # Test fixtures intentionally use another frozen proposal identity.  The
    # inventory does not store it, so derive it from the exact public payload.
    proposal = _object(proposal_payload.get("proposal"), "public proposal")
    if type(proposal.get("proposal_id")) is str:
        proposal_id = str(proposal["proposal_id"])
    base = public_base_url.rstrip("/")
    card_chain = _card_chain_from_public_payload(
        proposal_payload,
        proposal_id=proposal_id,
        captured_at=captured_at,
        source_url=f"{base}/proof-artifacts/v1/{proposal_id}/card-chain",
        final_card_hash=str(session["final_card_hash"]),
    )
    common: dict[str, object] = {
        "schema_version": "concordia.historical_odra_receipt.v1",
        "proposal_id": proposal_id,
        "generation": "v1",
        "captured_at": captured_at,
        "source_commit": source_commit,
        "deployment_commit": deployment_commit,
        "source_url": (
            f"{base}/proof-artifacts/v1/{proposal_id}/historical-odra-receipt"
        ),
        "network": "casper-test",
        "lineage_inventory": {
            "schema_version": "concordia.historical_odra_inventory.v1",
            "sha256": hashlib.sha256(inventory_bytes).hexdigest(),
            "canonical_json": inventory_bytes.decode("utf-8"),
        },
        "contract_identity": _contract_identity(identity),
        "card_chain": card_chain,
    }
    verified: list[tuple[dict[str, object], dict[str, object]]] = []
    for endpoint in endpoints:
        candidate = copy.deepcopy(common)
        try:
            candidate["raw_rpc"] = _capture_node(
                rpc=rpc,
                endpoint=endpoint,
                identity=identity,
            )
            facts = verify_historical_odra_artifact(
                json.dumps(
                    candidate,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                ),
                inventory_bytes=inventory_bytes,
            )
        except (
            HistoricalCaptureError,
            HistoricalOdraArtifactError,
            UnicodeError,
        ) as exc:
            raise HistoricalCaptureError("public RPC candidate is invalid") from exc
        except Exception as exc:
            # RPC transport exceptions deliberately omit response bodies.  Keep
            # the capture error equally generic so an upstream reflection can
            # never become operator output.
            raise HistoricalCaptureError("public RPC capture failed") from exc
        verified.append((candidate, facts))
    if verified[0][1] != verified[1][1]:
        raise HistoricalCaptureError("the second public RPC node disagrees")
    return verified[0][0]


def write_capture_atomically(path: Path, payload: bytes) -> None:
    """Create ``path`` atomically without following or replacing any target."""

    if type(payload) is not bytes or not payload or len(payload) > MAX_OUTPUT_BYTES:
        raise HistoricalCaptureError("capture output is invalid")
    target = Path(path)
    parent = target.parent
    try:
        parent_stat = parent.stat()
        if not stat.S_ISDIR(parent_stat.st_mode) or parent.is_symlink():
            raise HistoricalCaptureError("capture parent must be a regular directory")
    except OSError as exc:
        raise HistoricalCaptureError("capture parent is unavailable") from exc
    temporary = parent / f".{target.name}.{secrets.token_hex(12)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise HistoricalCaptureError("capture output write failed")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(temporary, target, follow_symlinks=False)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                raise HistoricalCaptureError("capture output already exists") from exc
            raise HistoricalCaptureError(
                "capture output could not be committed"
            ) from exc
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except HistoricalCaptureError:
        raise
    except OSError as exc:
        raise HistoricalCaptureError("capture output write failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _read_bounded(path_value: str, *, limit: int) -> bytes:
    if path_value == "-":
        raw = sys.stdin.buffer.read(limit + 1)
    else:
        path = Path(path_value)
        try:
            metadata = path.stat()
            if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
                raise HistoricalCaptureError("proposal payload must be a regular file")
            if metadata.st_size > limit:
                raise HistoricalCaptureError("proposal payload exceeds its size limit")
            raw = path.read_bytes()
        except OSError as exc:
            raise HistoricalCaptureError("proposal payload is unavailable") from exc
    if len(raw) > limit:
        raise HistoricalCaptureError("proposal payload exceeds its size limit")
    return raw


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--proposal-json", required=True, help="public proposal JSON file or -"
    )
    parser.add_argument("--rpc-url", action="append", required=True)
    parser.add_argument(
        "--rpc-authorization-file",
        action="append",
        default=[],
        metavar="URL=/absolute/file",
        help="endpoint-scoped raw Authorization secret file; repeat as needed",
    )
    parser.add_argument("--captured-at", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--deployment-commit", required=True)
    parser.add_argument("--public-base-url", required=True)
    parser.add_argument("--inventory", default=str(PACKAGED_INVENTORY_PATH))
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        proposal = _strict_document(
            _read_bounded(args.proposal_json, limit=MAX_PROPOSAL_PAYLOAD_BYTES),
            label="public proposal payload",
            limit=MAX_PROPOSAL_PAYLOAD_BYTES,
        )
        inventory_bytes = _read_bounded(args.inventory, limit=256 * 1024)
        authorization_files = parse_rpc_authorization_file_args(
            args.rpc_authorization_file,
            args.rpc_url,
        )
        rpc = PinnedHttpsJsonRpc(
            args.rpc_url,
            authorization_files=authorization_files,
        )
        artifact = capture_historical_odra_v1(
            proposal_payload=proposal,
            rpc=rpc,
            captured_at=args.captured_at,
            source_commit=args.source_commit,
            deployment_commit=args.deployment_commit,
            public_base_url=args.public_base_url,
            inventory_bytes=inventory_bytes,
        )
        output = (
            json.dumps(artifact, indent=2, ensure_ascii=False, allow_nan=False).encode(
                "utf-8"
            )
            + b"\n"
        )
        write_capture_atomically(Path(args.output), output)
    except RpcEndpointPolicyError:
        print(
            "historical capture failed: public RPC configuration is invalid",
            file=sys.stderr,
        )
        return 1
    except HistoricalCaptureError as exc:
        print(f"historical capture failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through the operator CLI
    raise SystemExit(main())
