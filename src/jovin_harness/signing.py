"""Optional Ed25519 signatures for receipts and for a signed head checkpoint.

A hash chain alone can be rebuilt by anyone who can write the data directory, and a reader cannot
tell a truncated chain from a short one. Signing closes the first gap: a receipt or checkpoint is
accepted only if it carries a valid Ed25519 signature from the configured key. The signed head
checkpoint (count, head hash, epoch, wall time, link to the previous checkpoint) closes the
second gap for truncation that leaves the checkpoint in place.

Restoring an *older* signed checkpoint together with a matching truncation is still internally
consistent. Only a copy of the latest checkpoint held somewhere the writer cannot rewrite (the
``head_anchor`` file, an owner-held git tag, an emailed head) can expose that rollback; the
verifier compares against it when one is configured.

The private key must live outside the data directory and is never written by this module.
Requires the ``cryptography`` package (``pip install 'jovin-harness[signing]'``).
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

ALGORITHM = "ed25519"


class SigningError(ValueError):
    pass


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as error:  # fail closed: signing was asked for but cannot be done
        raise SigningError("receipt signing needs the 'cryptography' package") from error
    return ed25519, serialization, InvalidSignature


def _raw_public(public_key) -> bytes:
    _, serialization, _ = _crypto()
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(public_key) -> str:
    return hashlib.sha256(_raw_public(public_key)).hexdigest()[:16]


def load_private_key(path: Path):
    ed25519, serialization, _ = _crypto()
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as error:
        raise SigningError(f"cannot load signing key {path}: {type(error).__name__}") from None
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise SigningError(f"signing key {path} is not an Ed25519 private key")
    return key


def load_public_key(path: Path):
    ed25519, serialization, _ = _crypto()
    raw = Path(path).read_bytes()
    try:
        key = serialization.load_pem_public_key(raw)
    except ValueError:
        try:
            key = serialization.load_pem_private_key(raw, password=None).public_key()
        except (ValueError, TypeError) as error:
            raise SigningError(f"cannot load verify key {path}: {type(error).__name__}") from None
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise SigningError(f"verify key {path} is not an Ed25519 key")
    return key


class Signer:
    def __init__(self, private_key):
        self._key = private_key
        self.public_key = private_key.public_key()
        self.key_id = key_id(self.public_key)

    @classmethod
    def from_file(cls, path: Path) -> Signer:
        return cls(load_private_key(path))

    def sign(self, message: bytes) -> str:
        return base64.b64encode(self._key.sign(message)).decode("ascii")


class Verifier:
    def __init__(self, public_key):
        self.public_key = public_key
        self.key_id = key_id(public_key)

    @classmethod
    def from_file(cls, path: Path) -> Verifier:
        return cls(load_public_key(path))

    def verify(self, message: bytes, signature) -> bool:
        _, _, invalid = _crypto()
        if not isinstance(signature, str):
            return False
        try:
            self.public_key.verify(base64.b64decode(signature, validate=True), message)
        except (invalid, ValueError):
            return False
        return True
