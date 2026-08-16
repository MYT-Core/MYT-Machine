"""Validation helpers for untrusted CLI and RPC data."""

from __future__ import annotations

import re

from .errors import InputError

MAX_MESSAGE_BYTES = 8192
MAX_ADDRESS_LENGTH = 512
MAX_SIGNATURE_LENGTH = 65536
_TXID_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


def normalize_txid(txid: str) -> str:
    if not isinstance(txid, str) or _TXID_PATTERN.fullmatch(txid) is None:
        raise InputError("Transaction ID must contain exactly 64 hexadecimal characters")
    return txid.lower()


def validate_address_text(address: str) -> str:
    if not isinstance(address, str) or not address:
        raise InputError("MYT address must be a non-empty string")
    if len(address) > MAX_ADDRESS_LENGTH or any(character.isspace() for character in address):
        raise InputError("MYT address has an invalid format")
    return address


def validate_message(message: str) -> str:
    if not isinstance(message, str):
        raise InputError("Message must be a string")
    if len(message.encode("utf-8")) > MAX_MESSAGE_BYTES:
        raise InputError(f"Message exceeds the {MAX_MESSAGE_BYTES}-byte limit")
    return message


def validate_signature(signature: str, *, field_name: str = "signature") -> str:
    if not isinstance(signature, str) or not signature:
        raise InputError(f"{field_name.capitalize()} must be a non-empty string")
    if len(signature.encode("utf-8")) > MAX_SIGNATURE_LENGTH:
        raise InputError(f"{field_name.capitalize()} exceeds the size limit")
    return signature


def validate_uint32(value: int, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise InputError(f"{field_name} must be an integer between 0 and 4294967295")
    return value
