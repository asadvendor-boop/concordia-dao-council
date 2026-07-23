"""Dedicated Mainnet public-key inventory (public halves only).

The future live lane receives a dedicated Mainnet key inventory from
Codex/Asad through file mounts only.  This module validates the PUBLIC
inventory document: public keys, account hashes, roles, and key-file mount
REFERENCES.  It never opens a key file, never accepts secret material, and
recomputes every account hash from the public key (G1 §6 derivation:
``BLAKE2b-256(algorithm_name_ascii || 0x00 || raw_public_key_bytes)``).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from tools.mainnet_canary.constants import (
    ALL_ROLES,
    GOVERNANCE_ROLES,
    MAINNET_CHAIN_NAME,
)
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.secret_guard import (
    refuse_if_secret_material,
    require_secret_mount_reference,
)

KEY_INVENTORY_SCHEMA_ID = "concordia.mainnet-canary.public-key-inventory.v1"

_ED25519_KEY = re.compile(r"01[0-9a-f]{64}\Z")
_SECP256K1_KEY = re.compile(r"02[0-9a-f]{66}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")

_ROLE_FIELDS = {"public_key_hex", "account_hash_hex", "key_file_mount_path"}


@dataclass(frozen=True)
class RoleIdentity:
    role: str
    public_key_hex: str
    account_hash_hex: str
    key_file_mount_path: str


@dataclass(frozen=True)
class KeyInventory:
    network: str
    threshold: int
    roles: dict[str, RoleIdentity]


def derive_account_hash(public_key_hex: str) -> str:
    """Casper ``AccountHash::from_public_key`` (G1 §6, no length prefix)."""

    if _ED25519_KEY.match(public_key_hex):
        algorithm = b"ed25519"
    elif _SECP256K1_KEY.match(public_key_hex):
        algorithm = b"secp256k1"
    else:
        raise CanaryRefusal(
            RefusalCode.KEY_INVENTORY_INVALID,
            "public key must be canonical Casper hex (01+64 or 02+66)",
        )
    raw_key = bytes.fromhex(public_key_hex[2:])
    return hashlib.blake2b(
        algorithm + b"\x00" + raw_key, digest_size=32
    ).hexdigest()


def load_key_inventory(path: Path) -> KeyInventory:
    """Validate the public inventory fail-closed; refuse secrets outright."""

    if not path.is_file():
        raise CanaryRefusal(
            RefusalCode.KEY_INVENTORY_ABSENT,
            "dedicated Mainnet public-key inventory is not mounted; it is a "
            "future Codex/Asad input supplied via file mount only",
        )
    raw = path.read_text(encoding="utf-8")
    refuse_if_secret_material(raw, context="public-key-inventory")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CanaryRefusal(
            RefusalCode.KEY_INVENTORY_INVALID, "inventory is not valid JSON"
        ) from exc
    if not isinstance(document, dict):
        raise CanaryRefusal(
            RefusalCode.KEY_INVENTORY_INVALID, "inventory must be a JSON object"
        )
    expected_top = {"schema_id", "network", "threshold", "roles"}
    if set(document) != expected_top:
        raise CanaryRefusal(
            RefusalCode.KEY_INVENTORY_INVALID,
            f"inventory must contain exactly {sorted(expected_top)}",
        )
    if document["schema_id"] != KEY_INVENTORY_SCHEMA_ID:
        raise CanaryRefusal(
            RefusalCode.KEY_INVENTORY_INVALID,
            f"schema_id must equal {KEY_INVENTORY_SCHEMA_ID}",
        )
    if document["network"] != MAINNET_CHAIN_NAME:
        raise CanaryRefusal(
            RefusalCode.NETWORK_MISMATCH,
            "inventory network must be exactly `casper`; Testnet identities "
            "are never an operational dependency of the Mainnet canary",
        )
    threshold = document["threshold"]
    if threshold not in (2, 3):
        raise CanaryRefusal(
            RefusalCode.KEY_INVENTORY_INVALID, "threshold must be exactly 2 or 3"
        )

    roles_raw = document["roles"]
    if not isinstance(roles_raw, dict) or set(roles_raw) != set(ALL_ROLES):
        raise CanaryRefusal(
            RefusalCode.ROLE_SET_INVALID,
            f"roles must contain exactly {sorted(ALL_ROLES)}",
        )
    roles: dict[str, RoleIdentity] = {}
    for role in ALL_ROLES:
        entry = roles_raw[role]
        if not isinstance(entry, dict) or set(entry) != _ROLE_FIELDS:
            raise CanaryRefusal(
                RefusalCode.KEY_INVENTORY_INVALID,
                f"role {role} must contain exactly {sorted(_ROLE_FIELDS)}",
            )
        public_key_hex = entry["public_key_hex"]
        account_hash_hex = entry["account_hash_hex"]
        if not isinstance(public_key_hex, str) or not isinstance(
            account_hash_hex, str
        ):
            raise CanaryRefusal(
                RefusalCode.KEY_INVENTORY_INVALID, f"role {role} fields malformed"
            )
        if _HEX64.match(account_hash_hex) is None:
            raise CanaryRefusal(
                RefusalCode.KEY_INVENTORY_INVALID,
                f"role {role} account hash must be 64 lowercase hex",
            )
        recomputed = derive_account_hash(public_key_hex)
        if recomputed != account_hash_hex:
            raise CanaryRefusal(
                RefusalCode.KEY_INVENTORY_INVALID,
                f"role {role} account hash does not match its public key",
            )
        mount = require_secret_mount_reference(
            entry["key_file_mount_path"], field=f"roles.{role}.key_file_mount_path"
        )
        roles[role] = RoleIdentity(
            role=role,
            public_key_hex=public_key_hex,
            account_hash_hex=account_hash_hex,
            key_file_mount_path=mount,
        )

    # Governance roles are pairwise distinct (constructor invariant), and the
    # executor pair must differ so a transfer cannot be self-directed.
    governance_hashes = [roles[role].account_hash_hex for role in GOVERNANCE_ROLES]
    if len(set(governance_hashes)) != len(governance_hashes):
        raise CanaryRefusal(
            RefusalCode.ROLE_SET_INVALID,
            "governance roles must be pairwise distinct accounts",
        )
    if roles["treasury_source"].account_hash_hex == roles["recipient"].account_hash_hex:
        raise CanaryRefusal(
            RefusalCode.ROLE_SET_INVALID,
            "treasury source and recipient must be distinct accounts",
        )
    return KeyInventory(
        network=MAINNET_CHAIN_NAME, threshold=int(threshold), roles=roles
    )


def refuse_known_testnet_identity_reuse(
    inventory: KeyInventory, known_testnet_account_hashes: set[str]
) -> None:
    """Dedicated Mainnet identities must never reuse Testnet accounts."""

    reused = sorted(
        role.role
        for role in inventory.roles.values()
        if role.account_hash_hex in known_testnet_account_hashes
    )
    if reused:
        raise CanaryRefusal(
            RefusalCode.TESTNET_IDENTITY_REUSE,
            f"roles reuse known Testnet identities: {reused}",
        )
