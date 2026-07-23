"""Release-dependency gate: the canary is blocked until Codex's Testnet RC.

The canary may never broadcast until Codex publishes a separately annotated
Testnet-RC tag whose manifest says all committed Testnet/local/hosted gates
are green.  This module validates the operator-supplied RC declaration and
recomputes every locally checkable fact:

- exact RC tag and peeled commit SHA (must equal the current worktree HEAD);
- clean tracked source tree (recomputed via git, not trusted from the file);
- exact v3 Wasm SHA-256 recomputed from the tracked Wasm;
- Mainnet-compatible Wasm attestation (the RC-base Testnet Wasm hard-codes
  chain name ``casper-test`` in its constructor validation and CANNOT
  initialise on Mainnet — see interface manifest finding B1);
- historical v1/v2 SHA manifest unchanged (every line re-hashed);
- chain name exactly ``casper`` and pinned official Mainnet RPC endpoint.

Absence of the declaration file is itself the stable preparation-lane
refusal: nothing downstream can run without it.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from tools.mainnet_canary.constants import (
    MAINNET_CHAIN_NAME,
    MAINNET_RPC_URL,
    TESTNET_RC_WASM_SHA256_AT_PREP_BASE,
)
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode
from tools.mainnet_canary.secret_guard import refuse_if_secret_material

RC_DECLARATION_SCHEMA_ID = "concordia.mainnet-canary.rc-declaration.v1"

_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-]{0,100}\Z")

_REQUIRED_FIELDS = {
    "schema_id",
    "rc_tag",
    "peeled_commit_sha",
    "testnet_wasm_sha256",
    "mainnet_wasm_sha256",
    "mainnet_wasm_chain_name",
    "mainnet_chain_name",
    "mainnet_rpc_url",
    "historical_odra_inventory_sha256",
    "expected_prequorum_error_message",
    "gates",
}

_REQUIRED_GATES = (
    "testnet_gates_green",
    "local_gates_green",
    "hosted_gates_green",
    "historical_manifest_unchanged",
    "source_tree_clean_at_tag",
)

WASM_RELPATH = Path("contracts/odra-governance-receipt-v3/wasm/GovernanceReceiptV3.wasm")
HISTORICAL_INVENTORY_RELPATH = Path("handoff/HISTORICAL_ODRA_SHA256.txt")


@dataclass(frozen=True)
class RcDeclaration:
    """A validated Codex Testnet-RC declaration (still locally re-verified)."""

    rc_tag: str
    peeled_commit_sha: str
    testnet_wasm_sha256: str
    mainnet_wasm_sha256: str
    mainnet_wasm_chain_name: str
    expected_prequorum_error_message: str


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise CanaryRefusal(
            RefusalCode.SOURCE_TREE_DIRTY,
            f"git {' '.join(args)} failed; cannot prove tree state",
        )
    return result.stdout


def load_rc_declaration(path: Path) -> dict[str, object]:
    """Load and strictly validate the RC declaration document."""

    if not path.is_file():
        raise CanaryRefusal(
            RefusalCode.RC_DECLARATION_ABSENT,
            "Codex Testnet-RC declaration is not present; the Mainnet canary "
            "is blocked until the RC tag manifest is published",
        )
    raw = path.read_text(encoding="utf-8")
    refuse_if_secret_material(raw, context="rc-declaration")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CanaryRefusal(
            RefusalCode.RC_DECLARATION_INVALID, "declaration is not valid JSON"
        ) from exc
    if not isinstance(document, dict):
        raise CanaryRefusal(
            RefusalCode.RC_DECLARATION_INVALID, "declaration must be a JSON object"
        )
    missing = sorted(_REQUIRED_FIELDS - set(document))
    unknown = sorted(set(document) - _REQUIRED_FIELDS)
    if missing or unknown:
        raise CanaryRefusal(
            RefusalCode.RC_DECLARATION_INVALID,
            f"missing fields {missing}, unknown fields {unknown}",
        )
    if document["schema_id"] != RC_DECLARATION_SCHEMA_ID:
        raise CanaryRefusal(
            RefusalCode.RC_DECLARATION_INVALID,
            f"schema_id must equal {RC_DECLARATION_SCHEMA_ID}",
        )
    return document


def validate_rc_gate(repo_root: Path, declaration_path: Path) -> RcDeclaration:
    """Validate the full release dependency; refuse on the first failure."""

    document = load_rc_declaration(declaration_path)

    rc_tag = document["rc_tag"]
    if not isinstance(rc_tag, str) or _TAG.match(rc_tag) is None:
        raise CanaryRefusal(RefusalCode.RC_DECLARATION_INVALID, "rc_tag malformed")

    gates = document["gates"]
    if not isinstance(gates, dict) or sorted(gates) != sorted(_REQUIRED_GATES):
        raise CanaryRefusal(
            RefusalCode.RC_DECLARATION_INVALID,
            f"gates must contain exactly {sorted(_REQUIRED_GATES)}",
        )
    red = sorted(name for name, value in gates.items() if value is not True)
    if red:
        raise CanaryRefusal(
            RefusalCode.RC_GATES_NOT_GREEN,
            f"RC gates not green: {red}",
        )

    # Chain identity: Mainnet mode accepts only chain `casper` and the pinned
    # official endpoint.  A Testnet chain/endpoint is refused outright.
    if document["mainnet_chain_name"] != MAINNET_CHAIN_NAME:
        raise CanaryRefusal(
            RefusalCode.CHAIN_NAME_MISMATCH,
            "declaration chain name is not exactly `casper`",
        )
    if document["mainnet_rpc_url"] != MAINNET_RPC_URL:
        raise CanaryRefusal(
            RefusalCode.ENDPOINT_NOT_PINNED,
            "declaration RPC endpoint does not match the pinned official "
            "Mainnet endpoint",
        )

    # Exact peeled commit: the deployment tree must BE the RC commit.
    peeled = document["peeled_commit_sha"]
    if not isinstance(peeled, str) or _HEX40.match(peeled) is None:
        raise CanaryRefusal(
            RefusalCode.RC_DECLARATION_INVALID, "peeled_commit_sha malformed"
        )
    head = _git(repo_root, "rev-parse", "HEAD").strip()
    if head != peeled:
        raise CanaryRefusal(
            RefusalCode.RC_COMMIT_MISMATCH,
            "worktree HEAD is not the RC peeled commit; refusing to plan "
            "against a different tree",
        )

    # Clean tracked source tree, recomputed — never trusted from the file.
    dirty = _git(
        repo_root, "status", "--porcelain", "--untracked-files=no"
    ).strip()
    if dirty:
        raise CanaryRefusal(
            RefusalCode.SOURCE_TREE_DIRTY,
            "tracked files are modified; the canary requires a clean tree",
        )

    # Exact v3 Wasm hash recomputed from the tracked artifact.
    wasm_path = repo_root / WASM_RELPATH
    if not wasm_path.is_file():
        raise CanaryRefusal(RefusalCode.RC_WASM_MISMATCH, "tracked v3 Wasm missing")
    wasm_sha = _sha256_file(wasm_path)
    declared_testnet_wasm = document["testnet_wasm_sha256"]
    if (
        not isinstance(declared_testnet_wasm, str)
        or _HEX64.match(declared_testnet_wasm) is None
        or wasm_sha != declared_testnet_wasm
    ):
        raise CanaryRefusal(
            RefusalCode.RC_WASM_MISMATCH,
            "tracked v3 Wasm SHA-256 does not equal the RC declaration",
        )

    # Mainnet-compatibility attestation (interface manifest finding B1): the
    # Testnet RC Wasm validates chain name `casper-test` inside its
    # constructor, so a byte-identical install cannot initialise on Mainnet.
    # Codex must attest a Mainnet-chain build in the RC manifest; reusing the
    # Testnet hash or a non-`casper` chain constant is refused.
    mainnet_wasm = document["mainnet_wasm_sha256"]
    if (
        not isinstance(mainnet_wasm, str)
        or _HEX64.match(mainnet_wasm) is None
        or document["mainnet_wasm_chain_name"] != MAINNET_CHAIN_NAME
    ):
        raise CanaryRefusal(
            RefusalCode.RC_MAINNET_WASM_UNATTESTED,
            "RC declaration does not attest a Mainnet-chain v3 Wasm "
            "(the Testnet RC Wasm hard-codes chain `casper-test` and cannot "
            "initialise on Mainnet); blocked pending Codex resolution",
        )
    if mainnet_wasm == TESTNET_RC_WASM_SHA256_AT_PREP_BASE:
        raise CanaryRefusal(
            RefusalCode.RC_MAINNET_WASM_UNATTESTED,
            "mainnet_wasm_sha256 equals the Testnet build, which cannot "
            "initialise with chain name `casper`",
        )

    # Historical v1/v2 inventory: recompute the inventory file hash AND every
    # line inside it against the live tree.
    inventory_path = repo_root / HISTORICAL_INVENTORY_RELPATH
    if not inventory_path.is_file():
        raise CanaryRefusal(
            RefusalCode.HISTORICAL_HASH_DRIFT, "historical inventory missing"
        )
    inventory_sha = _sha256_file(inventory_path)
    if inventory_sha != document["historical_odra_inventory_sha256"]:
        raise CanaryRefusal(
            RefusalCode.HISTORICAL_HASH_DRIFT,
            "historical inventory file hash does not match the RC declaration",
        )
    for line in inventory_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            expected_sha, relpath = line.split(None, 1)
        except ValueError as exc:
            raise CanaryRefusal(
                RefusalCode.HISTORICAL_HASH_DRIFT,
                "historical inventory line malformed",
            ) from exc
        target = repo_root / relpath.strip()
        if not target.is_file() or _sha256_file(target) != expected_sha:
            raise CanaryRefusal(
                RefusalCode.HISTORICAL_HASH_DRIFT,
                f"historical artifact drift detected: {relpath.strip()}",
            )

    expected_error = document["expected_prequorum_error_message"]
    if not isinstance(expected_error, str) or not expected_error.startswith(
        "User error: "
    ):
        raise CanaryRefusal(
            RefusalCode.RC_DECLARATION_INVALID,
            "expected_prequorum_error_message must be the exact Testnet-RC "
            "measured `User error: <code>` rendering",
        )

    return RcDeclaration(
        rc_tag=rc_tag,
        peeled_commit_sha=peeled,
        testnet_wasm_sha256=declared_testnet_wasm,
        mainnet_wasm_sha256=mainnet_wasm,
        mainnet_wasm_chain_name=str(document["mainnet_wasm_chain_name"]),
        expected_prequorum_error_message=expected_error,
    )
