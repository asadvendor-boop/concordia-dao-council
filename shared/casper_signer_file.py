"""Owner-private Casper PEM signer loading for release operators."""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from pycspr.factory.accounts import parse_private_key_bytes
from pycspr.types.crypto import KeyAlgorithm

from shared.secure_secret_file import read_secure_secret_file


class SecureCasperSignerError(RuntimeError):
    """A Casper signer failed custody, format, or algorithm validation."""


def load_secure_casper_signer(path: Path, key_algorithm: str) -> object:
    """Load one stable 0400/0600 PEM without disclosing path or key material."""

    try:
        raw = read_secure_secret_file(Path(path), max_bytes=64 * 1024)
        if type(key_algorithm) is not str:
            raise ValueError("invalid key algorithm")
        algorithm = KeyAlgorithm[key_algorithm.strip().upper()]
        if algorithm not in {KeyAlgorithm.ED25519, KeyAlgorithm.SECP256K1}:
            raise ValueError("unsupported key algorithm")
        private = serialization.load_pem_private_key(raw, password=None)
        if algorithm is KeyAlgorithm.ED25519:
            if not isinstance(private, ed25519.Ed25519PrivateKey):
                raise ValueError("key algorithm mismatch")
            secret = private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        else:
            if not isinstance(private, ec.EllipticCurvePrivateKey) or not isinstance(
                private.curve, ec.SECP256K1
            ):
                raise ValueError("key algorithm mismatch")
            secret = private.private_numbers().private_value.to_bytes(32, "big")
        return parse_private_key_bytes(secret, algorithm)
    except Exception:
        raise SecureCasperSignerError(
            "Casper signer could not be loaded safely"
        ) from None


__all__ = ["SecureCasperSignerError", "load_secure_casper_signer"]
