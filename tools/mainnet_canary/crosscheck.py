"""Dual-implementation identifier recomputation plus golden-vector gate.

Two independent implementations recompute every native envelope identifier:

* Path A — ``tools/mainnet_canary/encoding.py``: a fresh from-spec
  implementation written directly from G1 §2/§4/§5/§7 (no shared/ imports).
* Path B — composition of the frozen primitives in ``shared/envelope_v3.py``
  and the frozen schemas in ``shared/actions_v3.py``.  The shared full
  deriver hard-codes the Testnet chain name, so Path B recomposes the same
  frozen primitives (``encode_fields``, ``blake2b256``, ``length_prefix``)
  per the spec, which works for both chain names.

A single byte of disagreement refuses fail-closed.  Additionally the fresh
implementation must reproduce the immutable G1 golden vectors before any plan
is emitted, and for the Testnet-chain vectors the shared FULL deriver
(``shared.actions_v3.derive_native_material``) is run as a third check.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from shared.actions_v3 import NATIVE_CORE_SCHEMA, NATIVE_SCHEMA, derive_native_material
from shared.envelope_v3 import (
    ACTION_ID_DOMAIN_SEPARATOR,
    ENVELOPE_DOMAIN_SEPARATOR,
    HEADER_SCHEMA,
    TRANSFER_ID_DOMAIN_SEPARATOR,
    EnvelopeEncodingError,
    blake2b256,
    bytes32,
    encode_fields,
    length_prefix,
)

from tools.mainnet_canary.encoding import (
    FreshEncodingError,
    NativeEnvelopeMaterial,
    derive_deployment_domain,
    derive_native_envelope,
    encode_header,
)
from tools.mainnet_canary.errors import CanaryRefusal, RefusalCode

GOLDEN_VECTOR_RELROOT = Path("tests") / "golden" / "envelope_v3"


@dataclass(frozen=True)
class CrosscheckedMaterial:
    """Identifiers agreed byte-for-byte by both implementations."""

    action_id_hex: str
    transfer_id: int
    envelope_hash_hex: str
    header_bytes_hex: str
    body_bytes_hex: str
    action_core_bytes_hex: str


def _shared_primitive_native_material(
    header: dict[str, object], body: dict[str, object]
) -> NativeEnvelopeMaterial:
    """Path B: recompose the frozen shared primitives per G1 §7."""

    header_bytes = encode_fields(header, HEADER_SCHEMA)
    body_bytes = encode_fields(body, NATIVE_SCHEMA)
    core = encode_fields(
        {name: body[name] for name, _ in NATIVE_CORE_SCHEMA}, NATIVE_CORE_SCHEMA
    )
    nonce = bytes32(body["action_nonce"], "action_nonce")
    action_id = blake2b256(ACTION_ID_DOMAIN_SEPARATOR + b"\x01" + nonce + core)
    transfer_digest = blake2b256(
        TRANSFER_ID_DOMAIN_SEPARATOR
        + length_prefix(header["proposal_id"], "proposal_id")
        + bytes32(header["proposal_nonce"], "proposal_nonce")
        + action_id
    )
    transfer_id = int.from_bytes(transfer_digest[:8], "big")
    envelope_hash = blake2b256(ENVELOPE_DOMAIN_SEPARATOR + header_bytes + body_bytes)
    return NativeEnvelopeMaterial(
        header_bytes=header_bytes,
        body_bytes=body_bytes,
        action_core_bytes=core,
        action_id=action_id,
        transfer_id=transfer_id,
        envelope_hash=envelope_hash,
    )


def recompute_native_identifiers(
    header: dict[str, object],
    body: dict[str, object],
    *,
    chain_name: str,
) -> CrosscheckedMaterial:
    """Recompute all identifiers via both implementations; refuse on any drift."""

    try:
        fresh = derive_native_envelope(header, body, chain_name=chain_name)
    except FreshEncodingError as exc:
        raise CanaryRefusal(
            RefusalCode.ENVELOPE_INVALID, f"fresh implementation: {exc}"
        ) from exc
    try:
        composed = _shared_primitive_native_material(header, body)
    except EnvelopeEncodingError as exc:
        raise CanaryRefusal(
            RefusalCode.ENVELOPE_INVALID, f"shared primitives: {exc}"
        ) from exc

    disagreements = [
        name
        for name, left, right in (
            ("header_bytes", fresh.header_bytes, composed.header_bytes),
            ("body_bytes", fresh.body_bytes, composed.body_bytes),
            ("action_core_bytes", fresh.action_core_bytes, composed.action_core_bytes),
            ("action_id", fresh.action_id, composed.action_id),
            ("envelope_hash", fresh.envelope_hash, composed.envelope_hash),
        )
        if left != right
    ]
    if fresh.transfer_id != composed.transfer_id:
        disagreements.append("transfer_id")
    if disagreements:
        raise CanaryRefusal(
            RefusalCode.ID_RECOMPUTATION_MISMATCH,
            "independent implementations disagree on: "
            + ", ".join(sorted(disagreements)),
        )
    return CrosscheckedMaterial(
        action_id_hex=fresh.action_id.hex(),
        transfer_id=fresh.transfer_id,
        envelope_hash_hex=fresh.envelope_hash.hex(),
        header_bytes_hex=fresh.header_bytes.hex(),
        body_bytes_hex=fresh.body_bytes.hex(),
        action_core_bytes_hex=fresh.action_core_bytes.hex(),
    )


def _vector_values(fields: list[dict[str, object]]) -> dict[str, object]:
    return {str(item["name"]): item["value"] for item in fields}


def verify_native_golden_vectors(repo_root: Path) -> dict[str, int]:
    """Prove the fresh implementation against the immutable G1 vectors.

    For every valid native vector the fresh implementation must reproduce the
    frozen canonical bytes and hashes, and the shared FULL deriver must agree
    (third check, Testnet chain).  Every invalid vector must be refused by the
    fresh implementation.  Any deviation refuses fail-closed.
    """

    vector_dir = repo_root / GOLDEN_VECTOR_RELROOT / "native_transfer"
    vector_paths = sorted(vector_dir.glob("GV-NT-*.json"))
    if not vector_paths:
        raise CanaryRefusal(
            RefusalCode.GOLDEN_VECTOR_MISMATCH,
            f"no frozen native golden vectors found under {vector_dir}",
        )
    checked_valid = 0
    checked_invalid = 0
    checked_relationships = 0
    for path in vector_paths:
        vector = json.loads(path.read_text(encoding="utf-8"))
        if "cases" in vector["typed_input"]:
            checked_relationships += _verify_relationship_vector(path, vector)
            continue
        header = _vector_values(vector["typed_input"]["header"])
        body = _vector_values(vector["typed_input"]["body"])
        if vector.get("valid") is True:
            try:
                fresh = derive_native_envelope(
                    header, body, chain_name="casper-test"
                )
                shared_full = derive_native_material(header, body)
            except (FreshEncodingError, EnvelopeEncodingError) as exc:
                raise CanaryRefusal(
                    RefusalCode.GOLDEN_VECTOR_MISMATCH,
                    f"{path.name}: valid vector refused: {exc}",
                ) from exc
            hashes = vector["hashes"]
            observed = {
                "action_id": fresh.action_id.hex(),
                "envelope_hash": fresh.envelope_hash.hex(),
                "canonical_hex": fresh.body_bytes.hex(),
                "action_core_hex": fresh.action_core_bytes.hex(),
                "header_canonical_hex": fresh.header_bytes.hex(),
            }
            expected = {
                "action_id": hashes["action_id"],
                "envelope_hash": hashes["envelope_hash"],
                "canonical_hex": vector["canonical_hex"],
            }
            # Some vectors additionally freeze the core/header byte strings.
            if "action_core_hex" in vector:
                expected["action_core_hex"] = vector["action_core_hex"]
            if "header_canonical_hex" in vector:
                expected["header_canonical_hex"] = vector["header_canonical_hex"]
            drift = sorted(
                key for key in expected if observed[key] != expected[key]
            )
            if drift:
                raise CanaryRefusal(
                    RefusalCode.GOLDEN_VECTOR_MISMATCH,
                    f"{path.name}: fresh implementation drift on {drift}",
                )
            if (
                shared_full.action_id != fresh.action_id
                or shared_full.envelope_hash != fresh.envelope_hash
                or shared_full.transfer_id != fresh.transfer_id
            ):
                raise CanaryRefusal(
                    RefusalCode.GOLDEN_VECTOR_MISMATCH,
                    f"{path.name}: shared full deriver disagrees with fresh",
                )
            checked_valid += 1
        else:
            try:
                derive_native_envelope(header, body, chain_name="casper-test")
            except FreshEncodingError:
                checked_invalid += 1
                continue
            raise CanaryRefusal(
                RefusalCode.GOLDEN_VECTOR_MISMATCH,
                f"{path.name}: invalid vector was not refused",
            )
    return {
        "valid_vectors": checked_valid,
        "invalid_vectors": checked_invalid,
        "relationship_vectors": checked_relationships,
    }


def _verify_relationship_vector(path: Path, vector: dict[str, object]) -> int:
    """Verify a frozen two-case relationship vector (G1 §7 invariants)."""

    typed_input = vector["typed_input"]
    cases = typed_input["cases"]  # type: ignore[index]
    if not isinstance(cases, list) or len(cases) != 2:
        raise CanaryRefusal(
            RefusalCode.GOLDEN_VECTOR_MISMATCH,
            f"{path.name}: relationship vector must contain exactly two cases",
        )
    materials = []
    for case in cases:
        header = _vector_values(case["header"])
        body = _vector_values(case["body"])
        try:
            materials.append(
                derive_native_envelope(header, body, chain_name="casper-test")
            )
        except FreshEncodingError as exc:
            raise CanaryRefusal(
                RefusalCode.GOLDEN_VECTOR_MISMATCH,
                f"{path.name}: relationship case refused: {exc}",
            ) from exc
    first, second = materials
    comparison = vector.get("comparison")
    assertions = (
        comparison.get("assertions", {}) if isinstance(comparison, dict) else {}
    )
    observed = {
        "action_id_equal": first.action_id == second.action_id,
        "envelope_hash_differs": first.envelope_hash != second.envelope_hash,
        "transfer_id_differs": first.transfer_id != second.transfer_id,
        "action_id_differs": first.action_id != second.action_id,
    }
    for name, expected_value in assertions.items():
        if name not in observed:
            raise CanaryRefusal(
                RefusalCode.GOLDEN_VECTOR_MISMATCH,
                f"{path.name}: unknown frozen assertion {name}",
            )
        if observed[name] != expected_value:
            raise CanaryRefusal(
                RefusalCode.GOLDEN_VECTOR_MISMATCH,
                f"{path.name}: frozen assertion {name} does not hold",
            )
    return 1


def verify_header_golden_vectors(repo_root: Path) -> dict[str, int]:
    """Prove the fresh header encoder and domain derivation against G1 vectors."""

    vector_dir = repo_root / GOLDEN_VECTOR_RELROOT / "header"
    vector_paths = sorted(vector_dir.glob("GV-HDR-*.json"))
    if not vector_paths:
        raise CanaryRefusal(
            RefusalCode.GOLDEN_VECTOR_MISMATCH,
            f"no frozen header golden vectors found under {vector_dir}",
        )
    checked_valid = 0
    checked_invalid = 0
    checked_domains = 0
    for path in vector_paths:
        vector = json.loads(path.read_text(encoding="utf-8"))
        values = _vector_values(vector["typed_input"]["fields"])
        if vector.get("valid") is True:
            try:
                encoded = encode_header(values, chain_name="casper-test")
            except FreshEncodingError as exc:
                raise CanaryRefusal(
                    RefusalCode.GOLDEN_VECTOR_MISMATCH,
                    f"{path.name}: valid header vector refused: {exc}",
                ) from exc
            if encoded.hex() != vector["canonical_hex"]:
                raise CanaryRefusal(
                    RefusalCode.GOLDEN_VECTOR_MISMATCH,
                    f"{path.name}: fresh header bytes drift",
                )
            checked_valid += 1
        else:
            try:
                encode_header(values, chain_name="casper-test")
            except FreshEncodingError:
                checked_invalid += 1
            else:
                raise CanaryRefusal(
                    RefusalCode.GOLDEN_VECTOR_MISMATCH,
                    f"{path.name}: invalid header vector was not refused",
                )
        derivation = vector.get("deployment_domain_derivation")
        if isinstance(derivation, dict):
            derived = derive_deployment_domain(
                chain_name=str(derivation["chain_name"]),
                package_key_name=str(derivation["package_key_name"]),
                installation_nonce=str(derivation["installation_nonce"]),
            )
            if derived.hex() != derivation["blake2b256"]:
                raise CanaryRefusal(
                    RefusalCode.GOLDEN_VECTOR_MISMATCH,
                    f"{path.name}: deployment-domain derivation drift",
                )
            checked_domains += 1
    return {
        "valid_vectors": checked_valid,
        "invalid_vectors": checked_invalid,
        "domain_derivations": checked_domains,
    }


def run_golden_vector_gate(repo_root: Path) -> dict[str, dict[str, int]]:
    """The mandatory pre-plan self-check over the immutable G1 vectors."""

    return {
        "native_transfer": verify_native_golden_vectors(repo_root),
        "header": verify_header_golden_vectors(repo_root),
    }
