"""Strict serialization for public MYT machine identity documents."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from .errors import ConfigurationError, InputError
from .identity import (
    IDENTITY_ALGORITHM,
    IDENTITY_TYPE,
    IDENTITY_VERSION,
    PublicMachineIdentity,
    decode_public_key,
    encode_public_key,
)

MAX_IDENTITY_DOCUMENT_BYTES = 4096
_IDENTITY_FIELDS = {"type", "version", "algorithm", "machine_id", "public_key"}


def public_identity_document(identity: PublicMachineIdentity) -> dict[str, Any]:
    if not isinstance(identity, PublicMachineIdentity):
        raise InputError("Public identity must be a PublicMachineIdentity")
    return {
        "algorithm": IDENTITY_ALGORITHM,
        "machine_id": identity.machine_id,
        "public_key": encode_public_key(identity.public_key),
        "type": IDENTITY_TYPE,
        "version": IDENTITY_VERSION,
    }


def serialize_public_identity(identity: PublicMachineIdentity) -> bytes:
    """Serialize canonical UTF-8 JSON with one trailing LF."""
    document = public_identity_document(identity)
    return (
        json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def parse_public_identity_document(value: Any) -> PublicMachineIdentity:
    if not isinstance(value, dict):
        raise InputError("Machine identity document must be a JSON object")
    if any(not isinstance(field, str) for field in value):
        raise InputError("Machine identity document field names must be strings")
    fields = set(value)
    missing = sorted(_IDENTITY_FIELDS - fields)
    unknown = sorted(fields - _IDENTITY_FIELDS)
    if missing:
        raise InputError(
            f"Machine identity document is missing required field: {missing[0]}"
        )
    if unknown:
        raise InputError(
            f"Machine identity document contains unknown field: {unknown[0]}"
        )
    if value["type"] != IDENTITY_TYPE:
        raise InputError("Unsupported machine identity document type")
    version = value["version"]
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version != IDENTITY_VERSION
    ):
        raise InputError("Unsupported machine identity document version")
    if value["algorithm"] != IDENTITY_ALGORITHM:
        raise InputError("Unsupported machine identity algorithm")
    public_key = decode_public_key(value["public_key"])
    return PublicMachineIdentity(
        public_key=public_key,
        machine_id=value["machine_id"],
        algorithm=value["algorithm"],
    )


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InputError(
                f"Machine identity document contains duplicate field: {key}"
            )
        result[key] = value
    return result


def parse_public_identity_json(encoded: bytes) -> PublicMachineIdentity:
    if not isinstance(encoded, bytes):
        raise InputError("Machine identity document must be bytes")
    if not encoded or len(encoded) > MAX_IDENTITY_DOCUMENT_BYTES:
        raise InputError("Machine identity document is empty or exceeds the size limit")
    if encoded.startswith(b"\xef\xbb\xbf"):
        raise InputError("Machine identity document must not contain a UTF-8 BOM")
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError:
        raise InputError("Machine identity document is not valid UTF-8 JSON") from None
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_fields)
    except InputError:
        raise
    except (json.JSONDecodeError, RecursionError):
        raise InputError("Machine identity document is not valid UTF-8 JSON") from None
    return parse_public_identity_document(value)


def load_public_identity(path: str | os.PathLike[str]) -> PublicMachineIdentity:
    identity_path = Path(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    elif identity_path.is_symlink():
        raise InputError("Machine identity document must be a regular non-symlink file")
    descriptor: int | None = None
    try:
        descriptor = os.open(identity_path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise InputError(
                "Machine identity document must be a regular non-symlink file"
            )
        with os.fdopen(descriptor, "rb") as identity_file:
            descriptor = None
            encoded = identity_file.read(MAX_IDENTITY_DOCUMENT_BYTES + 1)
    except InputError:
        raise
    except OSError as exc:
        raise InputError("Unable to read machine identity document") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(encoded) > MAX_IDENTITY_DOCUMENT_BYTES:
        raise InputError("Machine identity document exceeds the size limit")
    return parse_public_identity_json(encoded)


def save_public_identity(
    identity: PublicMachineIdentity,
    path: str | os.PathLike[str],
) -> None:
    identity_path = Path(path)
    parent = identity_path.parent
    if not parent.is_dir():
        raise ConfigurationError("Machine identity output directory does not exist")
    encoded = serialize_public_identity(identity)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(identity_path, flags, 0o644)
        created = True
        if os.name != "nt":
            os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as identity_file:
            descriptor = None
            identity_file.write(encoded)
            identity_file.flush()
            os.fsync(identity_file.fileno())
    except FileExistsError:
        raise ConfigurationError(
            "Machine identity output file already exists"
        ) from None
    except OSError as exc:
        if created:
            try:
                identity_path.unlink()
            except OSError:
                pass
        raise ConfigurationError(
            "Unable to write machine identity output file"
        ) from exc
    except BaseException:
        if created:
            try:
                identity_path.unlink()
            except OSError:
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
