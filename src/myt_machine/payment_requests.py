"""Immutable Payment Request v1; adapted from fallacyofall's PR #1.

Local payment state deliberately lives in invoices.py, never in this artifact.
No wallet keys, signing, spending or network I/O is performed here.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import unicodedata
import uuid
from dataclasses import dataclass
from typing import Any

from .amounts import UINT64_MAX
from .errors import InputError

PAYMENT_REQUEST_TYPE = "myt-payment-request"
PAYMENT_REQUEST_VERSION = 1
MAX_REQUEST_BYTES = 8192
MAX_TIMESTAMP = 253402300799
MAX_LIFETIME = 30 * 24 * 60 * 60
NETWORKS = frozenset({"mainnet", "testnet", "stagenet"})
_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
_ADDRESS = re.compile(r"[1-9A-HJ-NP-Za-km-z]+")
_FIELDS = frozenset(
    {
        "type",
        "version",
        "invoice_id",
        "network",
        "recipient_address",
        "amount_atomic",
        "created_at",
        "expires_at",
        "memo",
        "reference",
    }
)


def bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise InputError(f"Invalid {name}: integer outside supported range")
    return value


def validate_identifier(value: Any, name: str = "invoice ID") -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise InputError(f"Invalid {name}: use 1-128 ASCII letters, digits, _ or -")
    return value


def validate_network(value: Any) -> str:
    if not isinstance(value, str) or value not in NETWORKS:
        raise InputError("Network must be mainnet, testnet or stagenet")
    return value


def validate_recipient(value: Any, network: str) -> str:
    # This checks standard/subaddress syntax only. Native Wallet RPC validates
    # the checksum, network prefix and actual address type before acceptance.
    expected_length = 95 if validate_network(network) == "mainnet" else 97
    if (
        not isinstance(value, str)
        or len(value) != expected_length
        or _ADDRESS.fullmatch(value) is None
    ):
        raise InputError("Recipient must have MYT standard/subaddress Base58 syntax")
    return value


def _optional_text(value: Any, name: str, maximum: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > maximum:
        raise InputError(f"Invalid {name}")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise InputError(f"Invalid {name}: malformed Unicode") from None
    if (
        len(encoded) > maximum
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(c).startswith("C") for c in value)
    ):
        raise InputError(
            f"Invalid {name}: use bounded NFC text without control characters"
        )
    return value


def unix_time(now: int | None = None) -> int:
    return bounded_int(
        int(time.time()) if now is None else now, "now", 0, MAX_TIMESTAMP
    )


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (ValueError, TypeError, RecursionError):
        raise InputError("Invalid JSON value") from None


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InputError("Duplicate JSON field")
        result[key] = value
    return result


def _invalid_number(value: str) -> None:
    raise InputError("JSON floating-point and non-finite values are unsupported")


def strict_json(value: str | bytes, maximum: int = MAX_REQUEST_BYTES) -> Any:
    try:
        if isinstance(value, str):
            if len(value) > maximum:
                raise InputError("JSON input exceeds the size limit")
            encoded = value.encode("utf-8")
        elif isinstance(value, bytes):
            encoded = value
        else:
            raise InputError("JSON input must be UTF-8 text or bytes")
        if not encoded or len(encoded) > maximum or encoded.startswith(b"\xef\xbb\xbf"):
            raise InputError("Empty, oversized or BOM-prefixed JSON input")
        return json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_float=_invalid_number,
            parse_constant=_invalid_number,
        )
    except (ValueError, UnicodeError, RecursionError):
        raise InputError("Invalid UTF-8 JSON input") from None


@dataclass(frozen=True, slots=True)
class PaymentRequest:
    invoice_id: str
    network: str
    recipient_address: str
    amount_atomic: int
    created_at: int
    expires_at: int
    memo: str | None = None
    reference: str | None = None

    def __post_init__(self) -> None:
        validate_identifier(self.invoice_id)
        validate_network(self.network)
        validate_recipient(self.recipient_address, self.network)
        bounded_int(self.amount_atomic, "amount_atomic", 1, UINT64_MAX)
        bounded_int(self.created_at, "created_at", 0, MAX_TIMESTAMP)
        bounded_int(self.expires_at, "expires_at", 0, MAX_TIMESTAMP)
        bounded_int(
            self.expires_at - self.created_at, "request lifetime", 1, MAX_LIFETIME
        )
        _optional_text(self.memo, "memo", 1024)
        _optional_text(self.reference, "reference", 256)

    def as_dict(self) -> dict[str, Any]:
        return {
            "type": PAYMENT_REQUEST_TYPE,
            "version": PAYMENT_REQUEST_VERSION,
            "invoice_id": self.invoice_id,
            "network": self.network,
            "recipient_address": self.recipient_address,
            "amount_atomic": self.amount_atomic,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "memo": self.memo,
            "reference": self.reference,
        }

    @property
    def canonical_content(self) -> bytes:
        return serialize_payment_request(self).encode("ascii")

    @property
    def proof_message(self) -> str:
        """Bind native OutProofV2 to this complete immutable request."""
        return (
            "myt-machine/invoice/v1:"
            + hashlib.sha256(self.canonical_content).hexdigest()
        )


def create_payment_request(
    recipient_address: str,
    amount_atomic: int,
    *,
    network: str,
    expires_in: int = 3600,
    memo: str | None = None,
    reference: str | None = None,
    invoice_id: str | None = None,
    now: int | None = None,
) -> PaymentRequest:
    created = unix_time(now)
    bounded_int(expires_in, "expires_in", 1, MAX_LIFETIME)
    return PaymentRequest(
        invoice_id=str(uuid.uuid4()) if invoice_id is None else invoice_id,
        network=network,
        recipient_address=recipient_address,
        amount_atomic=amount_atomic,
        created_at=created,
        expires_at=created + expires_in,
        memo=memo,
        reference=reference,
    )


def serialize_payment_request(request: PaymentRequest) -> str:
    if not isinstance(request, PaymentRequest):
        raise InputError("Expected a PaymentRequest")
    request.__post_init__()
    return canonical_json(request.as_dict())


def parse_payment_request(value: str | bytes | dict[str, Any]) -> PaymentRequest:
    data = strict_json(value) if isinstance(value, (str, bytes)) else value
    if not isinstance(data, dict) or set(data) != _FIELDS:
        raise InputError("Payment request must contain exactly the v1 schema fields")
    if (
        data["type"] != PAYMENT_REQUEST_TYPE
        or type(data["version"]) is not int
        or data["version"] != 1
    ):
        raise InputError("Unsupported payment request type or version")
    return PaymentRequest(
        **{k: v for k, v in data.items() if k not in {"type", "version"}}
    )
