"""Serialization and validation for MYT payment-proof artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TextIO

from .errors import InputError
from .validation import (
    normalize_txid,
    validate_address_text,
    validate_message,
    validate_signature,
)

PROOF_TYPE = "myt-payment-proof"
PROOF_VERSION = 1
MAX_PROOF_FILE_BYTES = 65_536


def create_proof_artifact(
    txid: str,
    address: str,
    message: str,
    proof: str,
) -> dict[str, Any]:
    return {
        "type": PROOF_TYPE,
        "version": PROOF_VERSION,
        "txid": normalize_txid(txid),
        "address": validate_address_text(address),
        "message": validate_message(message),
        "proof": validate_signature(proof, field_name="proof"),
    }


def parse_proof_artifact(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InputError("Payment proof artifact must be a JSON object")
    if value.get("type") != PROOF_TYPE:
        raise InputError("Unsupported payment proof type")
    version = value.get("version")
    if isinstance(version, bool) or version != PROOF_VERSION:
        raise InputError("Unsupported payment proof version")
    missing = [field for field in ("txid", "address", "message", "proof") if field not in value]
    if missing:
        raise InputError(f"Payment proof is missing required field: {missing[0]}")
    return create_proof_artifact(
        value["txid"],
        value["address"],
        value["message"],
        value["proof"],
    )


def _read_limited(stream: Any) -> bytes:
    data = stream.read(MAX_PROOF_FILE_BYTES + 1)
    if isinstance(data, str):
        encoded = data.encode("utf-8")
    elif isinstance(data, bytes):
        encoded = data
    else:
        raise InputError("Payment proof input could not be read")
    if len(encoded) > MAX_PROOF_FILE_BYTES:
        raise InputError("Payment proof file exceeds the size limit")
    return encoded


def load_proof_artifact(path: str, stdin: TextIO) -> dict[str, Any]:
    try:
        if path == "-":
            encoded = _read_limited(stdin)
        else:
            with Path(path).open("rb") as proof_file:
                encoded = _read_limited(proof_file)
    except OSError as exc:
        raise InputError("Unable to read payment proof file") from exc

    try:
        decoded = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise InputError("Payment proof file is not valid UTF-8 JSON") from None
    return parse_proof_artifact(decoded)
