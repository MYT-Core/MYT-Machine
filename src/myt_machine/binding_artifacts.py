"""Strict serialization and storage for MYT Address Binding v1 artifacts."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, BinaryIO, TextIO

from .binding import BINDING_TYPE, BINDING_VERSION, AddressBinding
from .errors import ConfigurationError, InputError
from .identity_artifacts import parse_public_identity_document

MAX_BINDING_ARTIFACT_BYTES = 8192
_BINDING_FIELDS = {
    "address",
    "identity",
    "identity_signature",
    "network",
    "type",
    "version",
    "wallet_signature",
}


def serialize_address_binding(binding: AddressBinding) -> bytes:
    """Serialize canonical UTF-8 JSON with one trailing LF."""
    if not isinstance(binding, AddressBinding):
        raise InputError("Address binding must be an AddressBinding")
    return (
        json.dumps(
            binding.as_dict(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def parse_address_binding(value: Any) -> AddressBinding:
    """Parse an already-decoded, exact-schema Binding v1 object."""
    if not isinstance(value, dict):
        raise InputError("Address binding artifact must be a JSON object")
    if any(not isinstance(field, str) for field in value):
        raise InputError("Address binding artifact field names must be strings")

    fields = set(value)
    missing = sorted(_BINDING_FIELDS - fields)
    unknown = sorted(fields - _BINDING_FIELDS)
    if missing:
        raise InputError(
            f"Address binding artifact is missing required field: {missing[0]}"
        )
    if unknown:
        raise InputError(
            f"Address binding artifact contains unknown field: {unknown[0]}"
        )
    if value["type"] != BINDING_TYPE:
        raise InputError("Unsupported address binding artifact type")
    version = value["version"]
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version != BINDING_VERSION
    ):
        raise InputError("Unsupported address binding artifact version")

    identity = parse_public_identity_document(value["identity"])
    return AddressBinding(
        identity=identity,
        network=value["network"],
        address=value["address"],
        identity_signature=value["identity_signature"],
        wallet_signature=value["wallet_signature"],
    )


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InputError(
                f"Address binding artifact contains duplicate field: {key}"
            )
        result[key] = value
    return result


def _reject_nonstandard_constant(value: str) -> None:
    raise InputError(
        f"Address binding artifact contains invalid JSON constant: {value}"
    )


def _parse_address_binding_json(encoded: bytes) -> AddressBinding:
    if not isinstance(encoded, bytes):
        raise InputError("Address binding artifact must be bytes")
    if not encoded:
        raise InputError("Address binding artifact is empty")
    if len(encoded) > MAX_BINDING_ARTIFACT_BYTES:
        raise InputError("Address binding artifact exceeds the size limit")
    if encoded.startswith(b"\xef\xbb\xbf"):
        raise InputError("Address binding artifact must not contain a UTF-8 BOM")
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError:
        raise InputError("Address binding artifact is not valid UTF-8 JSON") from None
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_fields,
            parse_constant=_reject_nonstandard_constant,
        )
    except InputError:
        raise
    except (json.JSONDecodeError, RecursionError):
        raise InputError("Address binding artifact is not valid UTF-8 JSON") from None
    return parse_address_binding(value)


def _read_limited_stream(stream: BinaryIO | TextIO) -> bytes:
    value = stream.read(MAX_BINDING_ARTIFACT_BYTES + 1)
    if isinstance(value, str):
        encoded = value.encode("utf-8")
    elif isinstance(value, bytes):
        encoded = value
    else:
        raise InputError("Address binding artifact input could not be read")
    if len(encoded) > MAX_BINDING_ARTIFACT_BYTES:
        raise InputError("Address binding artifact exceeds the size limit")
    return encoded


def load_address_binding(
    path: str | os.PathLike[str],
    stdin: BinaryIO | TextIO | None = None,
) -> AddressBinding:
    """Load a Binding v1 artifact from a regular file or stdin with ``-``."""
    if os.fspath(path) == "-":
        source: BinaryIO | TextIO
        if stdin is None:
            source = getattr(sys.stdin, "buffer", sys.stdin)
        else:
            source = getattr(stdin, "buffer", stdin)
        try:
            encoded = _read_limited_stream(source)
        except OSError as exc:
            raise InputError("Unable to read address binding artifact") from exc
        return _parse_address_binding_json(encoded)

    binding_path = Path(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    elif binding_path.is_symlink():
        raise InputError("Address binding artifact must be a regular non-symlink file")

    descriptor: int | None = None
    try:
        descriptor = os.open(binding_path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise InputError(
                "Address binding artifact must be a regular non-symlink file"
            )
        with os.fdopen(descriptor, "rb") as binding_file:
            descriptor = None
            encoded = binding_file.read(MAX_BINDING_ARTIFACT_BYTES + 1)
    except InputError:
        raise
    except OSError as exc:
        raise InputError("Unable to read address binding artifact") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)

    if len(encoded) > MAX_BINDING_ARTIFACT_BYTES:
        raise InputError("Address binding artifact exceeds the size limit")
    return _parse_address_binding_json(encoded)


def ensure_binding_output_available(path: str | os.PathLike[str]) -> None:
    """Validate an output path before either private signing operation runs."""
    binding_path = Path(path)
    if os.fspath(path) == "-":
        raise ConfigurationError("Address binding output must be a file path")
    if not binding_path.parent.is_dir():
        raise ConfigurationError("Address binding output directory does not exist")
    if os.path.lexists(binding_path):
        raise ConfigurationError("Address binding output file already exists")


def save_address_binding(
    binding: AddressBinding,
    path: str | os.PathLike[str],
) -> None:
    """Write a new Binding v1 artifact without ever replacing an existing path."""
    ensure_binding_output_available(path)
    binding_path = Path(path)
    encoded = serialize_address_binding(binding)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY

    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(binding_path, flags, 0o600)
        created = True
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as binding_file:
            descriptor = None
            binding_file.write(encoded)
            binding_file.flush()
            os.fsync(binding_file.fileno())
    except FileExistsError:
        raise ConfigurationError("Address binding output file already exists") from None
    except OSError as exc:
        if created:
            try:
                binding_path.unlink()
            except OSError:
                pass
        raise ConfigurationError("Unable to write address binding output file") from exc
    except BaseException:
        if created:
            try:
                binding_path.unlink()
            except OSError:
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
