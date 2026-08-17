"""Encrypted private-key storage for MYT machine identities."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .errors import ConfigurationError
from .identity import MachineIdentity, PublicMachineIdentity
from .identity_artifacts import save_public_identity

MAX_PRIVATE_KEY_FILE_BYTES = 65_536
MIN_PASSPHRASE_BYTES = 16
MAX_PASSPHRASE_BYTES = 1024
MAX_PASSPHRASE_FILE_BYTES = MAX_PASSPHRASE_BYTES + 2
_ENCRYPTED_PKCS8_HEADER = b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
_KEY_LOAD_ERROR = "Unable to unlock encrypted Ed25519 private key"


def validate_identity_passphrase(passphrase: bytes) -> bytes:
    if not isinstance(passphrase, bytes):
        raise ConfigurationError("Identity passphrase must be UTF-8 bytes")
    if not MIN_PASSPHRASE_BYTES <= len(passphrase) <= MAX_PASSPHRASE_BYTES:
        raise ConfigurationError(
            "Identity passphrase must contain between 16 and 1024 UTF-8 bytes"
        )
    try:
        decoded = passphrase.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigurationError("Identity passphrase must be valid UTF-8") from None
    if "\x00" in decoded or "\n" in decoded or "\r" in decoded:
        raise ConfigurationError(
            "Identity passphrase must be a single line without NUL"
        )
    return passphrase


def passphrase_from_text(value: str) -> bytes:
    if not isinstance(value, str):
        raise ConfigurationError("Identity passphrase must be text")
    return validate_identity_passphrase(value.encode("utf-8"))


def _open_secure_file(path: Path, description: str) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    elif path.is_symlink():
        raise ConfigurationError(
            f"{description.capitalize()} must be a regular non-symlink file"
        )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ConfigurationError(f"Unable to read {description}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ConfigurationError(
                f"{description.capitalize()} must be a regular non-symlink file"
            )
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ConfigurationError(
                f"{description.capitalize()} must have Unix mode 0600"
            )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def read_identity_passphrase_file(path: str | os.PathLike[str]) -> bytes:
    passphrase_path = Path(path)
    descriptor: int | None = _open_secure_file(
        passphrase_path, "identity passphrase file"
    )
    try:
        passphrase_file = os.fdopen(descriptor, "rb")
        descriptor = None
        with passphrase_file:
            encoded = passphrase_file.read(MAX_PASSPHRASE_FILE_BYTES + 1)
    except OSError as exc:
        raise ConfigurationError("Unable to read identity passphrase file") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(encoded) > MAX_PASSPHRASE_FILE_BYTES:
        raise ConfigurationError("Identity passphrase file exceeds the size limit")
    if encoded.endswith(b"\n"):
        encoded = encoded[:-1]
        if encoded.endswith(b"\r"):
            encoded = encoded[:-1]
    return validate_identity_passphrase(encoded)


def load_private_identity(
    path: str | os.PathLike[str],
    passphrase: bytes,
) -> MachineIdentity:
    private_path = Path(path)
    password = validate_identity_passphrase(passphrase)
    descriptor: int | None = _open_secure_file(
        private_path, "encrypted identity private key"
    )
    try:
        private_file = os.fdopen(descriptor, "rb")
        descriptor = None
        with private_file:
            encoded = private_file.read(MAX_PRIVATE_KEY_FILE_BYTES + 1)
    except OSError as exc:
        raise ConfigurationError(
            "Unable to read encrypted identity private key"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(encoded) > MAX_PRIVATE_KEY_FILE_BYTES:
        raise ConfigurationError(
            "Encrypted identity private key exceeds the size limit"
        )
    if not encoded.startswith(_ENCRYPTED_PKCS8_HEADER):
        raise ConfigurationError(_KEY_LOAD_ERROR)
    try:
        private_key = load_pem_private_key(encoded, password=password)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise ConfigurationError(_KEY_LOAD_ERROR) from None
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ConfigurationError(_KEY_LOAD_ERROR)
    return MachineIdentity(private_key)


def save_private_identity(
    identity: MachineIdentity,
    path: str | os.PathLike[str],
    passphrase: bytes,
) -> None:
    if not isinstance(identity, MachineIdentity):
        raise ConfigurationError("Private identity must be a MachineIdentity")
    password = validate_identity_passphrase(passphrase)
    private_path = Path(path)
    if not private_path.parent.is_dir():
        raise ConfigurationError("Identity private-key output directory does not exist")
    try:
        encoded = identity._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        )
    except (TypeError, ValueError):
        raise ConfigurationError("Unable to encrypt identity private key") from None

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(private_path, flags, 0o600)
        created = True
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as private_file:
            descriptor = None
            private_file.write(encoded)
            private_file.flush()
            os.fsync(private_file.fileno())
    except FileExistsError:
        raise ConfigurationError(
            "Identity private-key output file already exists"
        ) from None
    except OSError as exc:
        if created:
            try:
                private_path.unlink()
            except OSError:
                pass
        raise ConfigurationError(
            "Unable to write identity private-key output file"
        ) from exc
    except BaseException:
        if created:
            try:
                private_path.unlink()
            except OSError:
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)


def create_identity_files(
    private_key_path: str | os.PathLike[str],
    identity_path: str | os.PathLike[str],
    passphrase: bytes,
) -> PublicMachineIdentity:
    """Create both artifacts without overwriting, rolling back partial creation."""
    private_path = Path(private_key_path)
    public_path = Path(identity_path)
    try:
        private_resolved = os.path.normcase(str(private_path.resolve(strict=False)))
        public_resolved = os.path.normcase(str(public_path.resolve(strict=False)))
    except (OSError, RuntimeError):
        raise ConfigurationError("Unable to resolve identity output paths") from None
    if private_resolved == public_resolved:
        raise ConfigurationError(
            "Private-key and public-identity paths must be different"
        )
    if os.path.lexists(private_path) or os.path.lexists(public_path):
        raise ConfigurationError("Identity output files must not already exist")
    if not private_path.parent.is_dir() or not public_path.parent.is_dir():
        raise ConfigurationError("Identity output directories must already exist")

    identity = MachineIdentity.generate()
    save_private_identity(identity, private_path, passphrase)
    try:
        save_public_identity(identity.public_identity, public_path)
    except BaseException:
        try:
            private_path.unlink()
        except OSError:
            pass
        raise
    return identity.public_identity
