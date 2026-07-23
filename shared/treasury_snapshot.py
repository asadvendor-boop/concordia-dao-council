"""Canonical two-observer treasury baseline evidence."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit

from shared.casper_state_proof import (
    CasperStateProofError,
    VerifiedAccountBalance,
    verify_account_balance_at_block,
)


SCHEMA_ID = "concordia.native-treasury-snapshot.v1"
_RFC3339_UTC_RE = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})T"
    r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?Z$"
)
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class TreasurySnapshotError(ValueError):
    """The two-observer treasury snapshot is malformed or inconsistent."""


@dataclass(frozen=True)
class VerifiedTreasurySnapshot:
    network: str
    account_hash: bytes
    block_hash: bytes
    block_height: int
    state_root_hash: bytes
    balance_motes: int
    observations: tuple[VerifiedAccountBalance, VerifiedAccountBalance]
    artifact_json: str
    artifact_sha256: str

    @property
    def primary(self) -> VerifiedAccountBalance:
        return self.observations[0]


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise TreasurySnapshotError(
            "treasury snapshot artifact is not canonical JSON"
        ) from exc


def _mapping(value: object, label: str) -> dict[str, object]:
    if type(value) is not dict:
        raise TreasurySnapshotError(f"{label} is malformed")
    return value


def canonical_snapshot_node_origin(value: object) -> tuple[str, int]:
    if type(value) is not str or not value:
        raise TreasurySnapshotError("treasury snapshot node URL is invalid")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise TreasurySnapshotError("treasury snapshot node URL is invalid") from exc
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
        raise TreasurySnapshotError(
            "treasury snapshot node URL is not credential-free HTTPS"
        )
    normalized = host.casefold().rstrip(".")
    if not normalized or not normalized.isascii():
        raise TreasurySnapshotError("treasury snapshot node hostname is invalid")
    labels = normalized.split(".")
    canonical_dns_name = (
        len(normalized) <= 253
        and len(labels) >= 2
        and all(_DNS_LABEL_RE.fullmatch(label) is not None for label in labels)
        and re.search(r"[a-z]", labels[-1]) is not None
    )
    ipv4_shaped = re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", normalized)
    try:
        ipaddress.ip_address(normalized.strip("[]"))
    except ValueError:
        pass
    else:
        raise TreasurySnapshotError("treasury snapshot node must use a DNS hostname")
    if (
        "." not in normalized
        or not canonical_dns_name
        or ipv4_shaped is not None
        or normalized.endswith(".local")
        or normalized.endswith(".localhost")
        or normalized in {"localhost", "localhost.localdomain"}
        or value != f"https://{normalized}/rpc"
    ):
        raise TreasurySnapshotError(
            "treasury snapshot node hostname is not canonical public DNS"
        )
    return normalized, 443


def _capture_time(value: object) -> str:
    if type(value) is not str:
        raise TreasurySnapshotError("treasury snapshot capture time is invalid")
    match = _RFC3339_UTC_RE.fullmatch(value)
    if match is None:
        raise TreasurySnapshotError("treasury snapshot capture time is invalid")
    try:
        datetime(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
        )
    except ValueError as exc:
        raise TreasurySnapshotError(
            "treasury snapshot capture time is invalid"
        ) from exc
    return value


def _unwrap_result(response: object, label: str) -> dict[str, object]:
    item = _mapping(response, label)
    result = _mapping(item.get("result"), f"{label} result")
    if set(result) == {"name", "value"}:
        return _mapping(result["value"], f"{label} result value")
    return result


def _lower_hash(value: object, label: str) -> str:
    if type(value) is not str or len(value) != 64 or value != value.lower():
        raise TreasurySnapshotError(f"{label} is not an exact lowercase hash")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise TreasurySnapshotError(f"{label} is invalid hexadecimal") from exc
    if raw == bytes(32):
        raise TreasurySnapshotError(f"{label} must be non-zero")
    return value


def _block_facts(response: object) -> tuple[str, int, str]:
    value = _unwrap_result(response, "treasury snapshot block")
    if "block_with_signatures" in value:
        wrapper = _mapping(value["block_with_signatures"], "block wrapper")
        raw = _mapping(wrapper.get("block"), "block")
    else:
        raw = _mapping(value.get("block"), "block")
    versions = [version for version in ("Version1", "Version2") if version in raw]
    if versions:
        if len(versions) != 1 or len(raw) != 1:
            raise TreasurySnapshotError("versioned block wrapper is malformed")
        block = _mapping(raw[versions[0]], "versioned block")
    else:
        block = raw
    header = _mapping(block.get("header"), "block header")
    block_hash = _lower_hash(block.get("hash"), "block hash")
    state_root = _lower_hash(
        header.get("state_root_hash", header.get("stateRootHash")),
        "state root hash",
    )
    height = header.get("height")
    if type(height) is not int or height < 0:
        raise TreasurySnapshotError("block height is invalid")
    return block_hash, height, state_root


def verify_treasury_snapshot_artifact(
    value: object,
    *,
    expected_account_hash: bytes,
    expected_block_hash: bytes,
    expected_block_height: int,
    expected_balance_motes: int,
) -> VerifiedTreasurySnapshot:
    """Reparse, compare, and hash one exact two-node baseline artifact."""

    snapshot = _mapping(value, "treasury snapshot artifact")
    if (
        set(snapshot)
        != {
            "schema_id",
            "network",
            "source_account_hash",
            "expected_balance_motes",
            "observations",
        }
        or snapshot.get("schema_id") != SCHEMA_ID
    ):
        raise TreasurySnapshotError("treasury snapshot artifact fields are not exact")
    if (
        type(expected_account_hash) is not bytes
        or len(expected_account_hash) != 32
        or type(expected_block_hash) is not bytes
        or len(expected_block_hash) != 32
        or type(expected_block_height) is not int
        or expected_block_height < 0
        or type(expected_balance_motes) is not int
        or expected_balance_motes < 0
    ):
        raise TreasurySnapshotError("treasury snapshot expected facts are invalid")
    if (
        snapshot.get("network") != "casper-test"
        or snapshot.get("source_account_hash") != expected_account_hash.hex()
        or snapshot.get("expected_balance_motes") != str(expected_balance_motes)
    ):
        raise TreasurySnapshotError(
            "treasury snapshot identity differs from the typed action"
        )
    observations = snapshot.get("observations")
    if type(observations) is not list or len(observations) != 2:
        raise TreasurySnapshotError(
            "treasury snapshot requires exactly two node observations"
        )
    proofs: list[VerifiedAccountBalance] = []
    origins: set[tuple[str, int]] = set()
    expected_root: bytes | None = None
    try:
        for raw_observation in observations:
            observation = _mapping(raw_observation, "treasury snapshot observation")
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
                raise TreasurySnapshotError(
                    "treasury snapshot observation fields are not exact"
                )
            origin = canonical_snapshot_node_origin(observation.get("node_url"))
            if origin in origins:
                raise TreasurySnapshotError("treasury snapshot nodes are not distinct")
            origins.add(origin)
            _capture_time(observation.get("captured_at"))
            observed_hash, observed_height, observed_root = _block_facts(
                observation["block_response"]
            )
            if (
                observed_hash != expected_block_hash.hex()
                or observed_height != expected_block_height
            ):
                raise TreasurySnapshotError(
                    "treasury snapshot block differs from the typed action"
                )
            root = bytes.fromhex(observed_root)
            if expected_root is None:
                expected_root = root
            elif root != expected_root:
                raise TreasurySnapshotError(
                    "treasury snapshot nodes disagree on state root"
                )
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
    except CasperStateProofError as exc:
        raise TreasurySnapshotError(
            "treasury snapshot account proof is invalid"
        ) from exc
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
        raise TreasurySnapshotError("treasury snapshot node observations do not agree")
    artifact_json = _canonical_json(snapshot)
    return VerifiedTreasurySnapshot(
        network=first.network,
        account_hash=first.account_hash,
        block_hash=first.block_hash,
        block_height=first.block_height,
        state_root_hash=first.state_root_hash,
        balance_motes=first.balance_motes,
        observations=(first, second),
        artifact_json=artifact_json,
        artifact_sha256=hashlib.sha256(artifact_json.encode("ascii")).hexdigest(),
    )


def require_verified_treasury_snapshot(value: object) -> VerifiedTreasurySnapshot:
    if type(value) is not VerifiedTreasurySnapshot:
        raise TreasurySnapshotError("treasury snapshot must be parser-verified")
    try:
        reparsed = verify_treasury_snapshot_artifact(
            json.loads(value.artifact_json),
            expected_account_hash=value.account_hash,
            expected_block_hash=value.block_hash,
            expected_block_height=value.block_height,
            expected_balance_motes=value.balance_motes,
        )
    except (TypeError, json.JSONDecodeError) as exc:
        raise TreasurySnapshotError(
            "treasury snapshot canonical artifact is invalid"
        ) from exc
    if reparsed != value:
        raise TreasurySnapshotError("treasury snapshot parser seal does not match")
    return value


__all__ = [
    "SCHEMA_ID",
    "TreasurySnapshotError",
    "VerifiedTreasurySnapshot",
    "canonical_snapshot_node_origin",
    "require_verified_treasury_snapshot",
    "verify_treasury_snapshot_artifact",
]
