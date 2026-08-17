"""Offline Ed25519 machine identities and protocol framing."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .errors import InputError

IDENTITY_TYPE = "myt-machine-identity"
IDENTITY_VERSION = 1
IDENTITY_ALGORITHM = "ed25519"
SIGNATURE_VERSION = 1
MAX_IDENTITY_MESSAGE_BYTES = 65_536
MAX_IDENTITY_CONTEXT_BYTES = 128
CHALLENGE_NONCE_BYTES = 32

_MACHINE_ID_DOMAIN = b"MYT-MACHINE-ID\x00v1\x00ed25519\x00"
_SIGNATURE_DOMAIN = b"MYT-MACHINE-SIGNATURE\x00"
_MACHINE_ID_PREFIX = "myt-machine-v1:"
_MACHINE_ID_PATTERN = re.compile(r"^myt-machine-v1:[a-z2-7]{52}$")
_CONTEXT_PATTERN = re.compile(r"^[a-z0-9._:/-]+$")
_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_base64url(value: str, *, expected_bytes: int, field_name: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise InputError(f"{field_name} must be a non-empty Base64url string")
    expected_length = (expected_bytes * 8 + 5) // 6
    if len(value) != expected_length or _BASE64URL_PATTERN.fullmatch(value) is None:
        raise InputError(f"{field_name} is not canonical unpadded Base64url")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error):
        raise InputError(f"{field_name} is not canonical unpadded Base64url") from None
    if len(decoded) != expected_bytes or _encode_base64url(decoded) != value:
        raise InputError(f"{field_name} is not canonical unpadded Base64url")
    return decoded


def encode_public_key(public_key: bytes) -> str:
    """Encode a raw 32-byte Ed25519 public key canonically."""
    raw = _validate_public_key_bytes(public_key)
    return _encode_base64url(raw)


def decode_public_key(value: str) -> bytes:
    """Decode a canonical Base64url Ed25519 public key."""
    return _decode_base64url(value, expected_bytes=32, field_name="Public key")


def encode_signature(signature: bytes) -> str:
    """Encode a raw 64-byte Ed25519 signature canonically."""
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise InputError("Signature must contain exactly 64 bytes")
    return _encode_base64url(signature)


def decode_signature(value: str) -> bytes:
    """Decode a canonical Base64url Ed25519 signature."""
    return _decode_base64url(value, expected_bytes=64, field_name="Signature")


def encode_challenge_nonce(nonce: bytes) -> str:
    """Encode exactly 32 nonce bytes for Base64url transport."""
    if not isinstance(nonce, bytes) or len(nonce) != CHALLENGE_NONCE_BYTES:
        raise InputError("Challenge nonce must contain exactly 32 bytes")
    return _encode_base64url(nonce)


def decode_challenge_nonce(value: str) -> bytes:
    """Decode a canonical 32-byte Base64url challenge nonce."""
    return _decode_base64url(
        value,
        expected_bytes=CHALLENGE_NONCE_BYTES,
        field_name="Challenge nonce",
    )


def _validate_public_key_bytes(public_key: bytes) -> bytes:
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise InputError("Ed25519 public key must contain exactly 32 bytes")
    return public_key


def _machine_id_digest_from_public_key(public_key: bytes) -> bytes:
    return hashlib.sha256(
        _MACHINE_ID_DOMAIN + _validate_public_key_bytes(public_key)
    ).digest()


def derive_machine_id(public_key: bytes) -> str:
    """Derive the stable textual Machine ID from a raw Ed25519 public key."""
    digest = _machine_id_digest_from_public_key(public_key)
    encoded = base64.b32encode(digest).decode("ascii").rstrip("=").lower()
    return _MACHINE_ID_PREFIX + encoded


def machine_id_digest(machine_id: str) -> bytes:
    """Validate a canonical Machine ID and return its embedded digest."""
    if (
        not isinstance(machine_id, str)
        or _MACHINE_ID_PATTERN.fullmatch(machine_id) is None
    ):
        raise InputError("Machine ID has an invalid or non-canonical format")
    encoded = machine_id[len(_MACHINE_ID_PREFIX) :]
    try:
        decoded = base64.b32decode(
            encoded.upper() + "=" * (-len(encoded) % 8), casefold=False
        )
    except (ValueError, binascii.Error):
        raise InputError("Machine ID has an invalid or non-canonical format") from None
    canonical = base64.b32encode(decoded).decode("ascii").rstrip("=").lower()
    if len(decoded) != 32 or canonical != encoded:
        raise InputError("Machine ID has an invalid or non-canonical format")
    return decoded


def validate_identity_context(context: str) -> str:
    if not isinstance(context, str):
        raise InputError("Identity signature context must be a string")
    try:
        encoded = context.encode("ascii")
    except UnicodeEncodeError:
        raise InputError(
            "Identity signature context must contain lowercase ASCII characters"
        ) from None
    if (
        not encoded
        or len(encoded) > MAX_IDENTITY_CONTEXT_BYTES
        or _CONTEXT_PATTERN.fullmatch(context) is None
    ):
        raise InputError(
            "Identity signature context must be 1-128 lowercase ASCII characters using "
            "a-z, 0-9, dot, underscore, colon, slash, or hyphen"
        )
    return context


def validate_identity_message(message: bytes) -> bytes:
    if not isinstance(message, bytes):
        raise InputError("Identity message must be bytes")
    if not message:
        raise InputError("Identity message must not be empty")
    if len(message) > MAX_IDENTITY_MESSAGE_BYTES:
        raise InputError(
            f"Identity message exceeds the {MAX_IDENTITY_MESSAGE_BYTES}-byte limit"
        )
    return message


def create_signature_frame(machine_id: str, context: str, message: bytes) -> bytes:
    """Create the byte-exact v1 domain-separated signature frame."""
    digest = machine_id_digest(machine_id)
    normalized_context = validate_identity_context(context)
    normalized_message = validate_identity_message(message)
    context_bytes = normalized_context.encode("ascii")
    return b"".join(
        (
            _SIGNATURE_DOMAIN,
            bytes((SIGNATURE_VERSION,)),
            digest,
            len(context_bytes).to_bytes(2, "big"),
            context_bytes,
            len(normalized_message).to_bytes(8, "big"),
            normalized_message,
        )
    )


@dataclass(frozen=True)
class PublicMachineIdentity:
    """Validated public identity document content."""

    public_key: bytes
    machine_id: str
    algorithm: str = IDENTITY_ALGORITHM

    def __post_init__(self) -> None:
        raw_public_key = _validate_public_key_bytes(self.public_key)
        if self.algorithm != IDENTITY_ALGORITHM:
            raise InputError("Unsupported machine identity algorithm")
        machine_id_digest(self.machine_id)
        if derive_machine_id(raw_public_key) != self.machine_id:
            raise InputError("Machine ID does not match the public key")

    @classmethod
    def from_public_key(cls, public_key: bytes) -> PublicMachineIdentity:
        raw = _validate_public_key_bytes(public_key)
        return cls(public_key=raw, machine_id=derive_machine_id(raw))

    def verify(
        self,
        message: bytes,
        context: str,
        signature: str,
        *,
        expected_machine_id: str | None = None,
    ) -> IdentityVerification:
        if expected_machine_id is not None:
            machine_id_digest(expected_machine_id)
        frame = create_signature_frame(self.machine_id, context, message)
        raw_signature = decode_signature(signature)
        try:
            Ed25519PublicKey.from_public_bytes(self.public_key).verify(
                raw_signature, frame
            )
            signature_valid = True
        except InvalidSignature:
            signature_valid = False

        if expected_machine_id is None:
            identity_matches: bool | None = None
            authentication_valid: bool | None = None
            valid = signature_valid
        else:
            identity_matches = expected_machine_id == self.machine_id
            authentication_valid = signature_valid and identity_matches
            valid = authentication_valid

        return IdentityVerification(
            valid=valid,
            signature_valid=signature_valid,
            identity_matches=identity_matches,
            authentication_valid=authentication_valid,
            algorithm=IDENTITY_ALGORITHM,
            machine_id=self.machine_id,
            context=validate_identity_context(context),
            signature_version=SIGNATURE_VERSION,
        )


@dataclass(frozen=True)
class IdentitySignature:
    """Public result of an identity signature operation."""

    algorithm: str
    machine_id: str
    context: str
    signature_version: int
    signature: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "machine_id": self.machine_id,
            "context": self.context,
            "signature_version": self.signature_version,
            "signature": self.signature,
        }


@dataclass(frozen=True)
class IdentityVerification:
    """Distinguish cryptographic validity from expected-ID authentication."""

    valid: bool
    signature_valid: bool
    identity_matches: bool | None
    authentication_valid: bool | None
    algorithm: str
    machine_id: str
    context: str
    signature_version: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "signature_valid": self.signature_valid,
            "identity_matches": self.identity_matches,
            "authentication_valid": self.authentication_valid,
            "algorithm": self.algorithm,
            "machine_id": self.machine_id,
            "context": self.context,
            "signature_version": self.signature_version,
        }


class MachineIdentity:
    """An in-memory Ed25519 private identity with a redacted representation."""

    __slots__ = ("_private_key", "public_identity")

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        if not isinstance(private_key, Ed25519PrivateKey):
            raise InputError("Private key is not an Ed25519 key")
        self._private_key = private_key
        raw_public_key = private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self.public_identity = PublicMachineIdentity.from_public_key(raw_public_key)

    @classmethod
    def generate(cls) -> MachineIdentity:
        return cls(Ed25519PrivateKey.generate())

    @property
    def machine_id(self) -> str:
        return self.public_identity.machine_id

    def sign(self, message: bytes, context: str) -> IdentitySignature:
        frame = create_signature_frame(self.machine_id, context, message)
        signature = self._private_key.sign(frame)
        return IdentitySignature(
            algorithm=IDENTITY_ALGORITHM,
            machine_id=self.machine_id,
            context=validate_identity_context(context),
            signature_version=SIGNATURE_VERSION,
            signature=encode_signature(signature),
        )

    def __repr__(self) -> str:
        return (
            f"MachineIdentity(machine_id={self.machine_id!r}, private_key=<redacted>)"
        )
