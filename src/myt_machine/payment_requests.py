"""Phase 4D payment-request / invoice primitives.

This module is deliberately non-custodial. It models payment requests and their
lifecycle but never spends funds, accesses private keys, or talks to wallet RPC.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Mapping, Protocol, runtime_checkable

from .amounts import UINT64_MAX
from .errors import InputError
from .validation import validate_address_text, validate_message

PAYMENT_REQUEST_TYPE = "myt-payment-request"
PAYMENT_REQUEST_VERSION = 1
MAX_INVOICE_ID_LENGTH = 128


class PaymentRequestState(str, Enum):
    """Lifecycle states for a payment request."""

    PENDING = "PENDING"
    PAID = "PAID"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True, slots=True)
class PaymentRequest:
    """A non-custodial request to pay an exact amount of MYT atomic units."""

    invoice_id: str
    recipient_address: str
    amount_atomic: int
    created_at: int
    expires_at: int
    state: PaymentRequestState = PaymentRequestState.PENDING
    memo: str | None = None
    reference: str | None = None

    def effective_state(self, *, now: int | None = None) -> PaymentRequestState:
        """Return EXPIRED for an elapsed pending invoice without mutating it."""
        if self.state is not PaymentRequestState.PENDING:
            return self.state
        current = _unix_time(now)
        if current >= self.expires_at:
            return PaymentRequestState.EXPIRED
        return PaymentRequestState.PENDING

    def mark_paid(self, *, now: int | None = None) -> "PaymentRequest":
        """Return a PAID copy if the request is still payable."""
        state = self.effective_state(now=now)
        if state is PaymentRequestState.EXPIRED:
            raise InputError("Expired payment request cannot be marked paid")
        if state is PaymentRequestState.PAID:
            return self
        return replace(self, state=PaymentRequestState.PAID)

    def expire(self, *, now: int | None = None) -> "PaymentRequest":
        """Return an EXPIRED copy when its expiry time has elapsed."""
        if self.state is PaymentRequestState.PAID:
            raise InputError("Paid payment request cannot be expired")
        current = _unix_time(now)
        if current < self.expires_at:
            raise InputError("Payment request has not reached its expiry time")
        if self.state is PaymentRequestState.EXPIRED:
            return self
        return replace(self, state=PaymentRequestState.EXPIRED)

    def as_dict(self, *, resolve_expiry: bool = False, now: int | None = None) -> dict[str, Any]:
        state = self.effective_state(now=now) if resolve_expiry else self.state
        return {
            "type": PAYMENT_REQUEST_TYPE,
            "version": PAYMENT_REQUEST_VERSION,
            "invoice_id": self.invoice_id,
            "recipient_address": self.recipient_address,
            "amount_atomic": self.amount_atomic,
            "memo": self.memo,
            "reference": self.reference,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "state": state.value,
        }


@dataclass(frozen=True, slots=True)
class PaymentVerification:
    """Minimal verifier result for future payment-status/payment-proof adapters."""

    paid: bool
    txid: str | None = None
    proof: Mapping[str, Any] | None = None


@runtime_checkable
class PaymentRequestVerifier(Protocol):
    """Interface implemented by payment-status/payment-proof backends."""

    def verify(self, request: PaymentRequest) -> PaymentVerification:
        """Check whether *request* has been paid without spending funds."""
        ...


def create_payment_request(
    recipient_address: str,
    amount_atomic: int,
    *,
    expires_in: int,
    memo: str | None = None,
    reference: str | None = None,
    invoice_id: str | None = None,
    now: int | None = None,
) -> PaymentRequest:
    """Create a validated PENDING payment request.

    ``amount_atomic`` is an integer number of MYT atomic units. Floats are
    intentionally rejected.
    """
    created_at = _unix_time(now)
    if isinstance(expires_in, bool) or not isinstance(expires_in, int) or expires_in <= 0:
        raise InputError("expires_in must be a positive integer number of seconds")
    expires_at = created_at + expires_in
    if expires_at > (1 << 63) - 1:
        raise InputError("Payment request expiry is outside the supported timestamp range")

    return _validated_request(
        invoice_id=invoice_id or str(uuid.uuid4()),
        recipient_address=recipient_address,
        amount_atomic=amount_atomic,
        memo=memo,
        reference=reference,
        created_at=created_at,
        expires_at=expires_at,
        state=PaymentRequestState.PENDING,
    )


def serialize_payment_request(request: PaymentRequest) -> str:
    """Serialize a payment request as compact, deterministic UTF-8 JSON text."""
    if not isinstance(request, PaymentRequest):
        raise InputError("Payment request must be a PaymentRequest instance")
    return json.dumps(request.as_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def parse_payment_request(value: str | bytes | Mapping[str, Any]) -> PaymentRequest:
    """Deserialize and validate a payment request artifact."""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            raise InputError("Payment request is not valid UTF-8") from None

    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            raise InputError("Payment request is not valid JSON") from None
    else:
        decoded = value

    if not isinstance(decoded, Mapping):
        raise InputError("Payment request must be a JSON object")
    if decoded.get("type") != PAYMENT_REQUEST_TYPE:
        raise InputError("Unsupported payment request type")
    version = decoded.get("version")
    if isinstance(version, bool) or version != PAYMENT_REQUEST_VERSION:
        raise InputError("Unsupported payment request version")

    required = (
        "invoice_id",
        "recipient_address",
        "amount_atomic",
        "created_at",
        "expires_at",
        "state",
    )
    missing = [field for field in required if field not in decoded]
    if missing:
        raise InputError(f"Payment request is missing required field: {missing[0]}")

    try:
        state = PaymentRequestState(decoded["state"])
    except (TypeError, ValueError):
        raise InputError("Payment request state must be PENDING, PAID, or EXPIRED") from None

    return _validated_request(
        invoice_id=decoded["invoice_id"],
        recipient_address=decoded["recipient_address"],
        amount_atomic=decoded["amount_atomic"],
        memo=decoded.get("memo"),
        reference=decoded.get("reference"),
        created_at=decoded["created_at"],
        expires_at=decoded["expires_at"],
        state=state,
    )


def _validated_request(
    *,
    invoice_id: Any,
    recipient_address: Any,
    amount_atomic: Any,
    memo: Any,
    reference: Any,
    created_at: Any,
    expires_at: Any,
    state: PaymentRequestState,
) -> PaymentRequest:
    normalized_id = _validate_invoice_id(invoice_id)
    address = validate_address_text(recipient_address)
    amount = _validate_amount_atomic(amount_atomic)
    created = _validate_timestamp(created_at, "created_at")
    expires = _validate_timestamp(expires_at, "expires_at")
    if expires <= created:
        raise InputError("expires_at must be later than created_at")
    normalized_memo = _validate_optional_text(memo, "memo")
    normalized_reference = _validate_optional_text(reference, "reference")

    return PaymentRequest(
        invoice_id=normalized_id,
        recipient_address=address,
        amount_atomic=amount,
        memo=normalized_memo,
        reference=normalized_reference,
        created_at=created,
        expires_at=expires,
        state=state,
    )


def _validate_invoice_id(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise InputError("invoice_id must be a non-empty string")
    if len(value) > MAX_INVOICE_ID_LENGTH or any(character.isspace() for character in value):
        raise InputError("invoice_id has an invalid format")
    return value


def _validate_amount_atomic(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputError("amount_atomic must be an integer; floating-point amounts are not accepted")
    if value <= 0:
        raise InputError("amount_atomic must be greater than zero")
    if value > UINT64_MAX:
        raise InputError("amount_atomic exceeds the wallet RPC uint64 range")
    return value


def _validate_timestamp(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InputError(f"{field_name} must be a non-negative integer Unix timestamp")
    return value


def _validate_optional_text(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    try:
        return validate_message(value)
    except InputError as exc:
        raise InputError(f"Invalid {field_name}: {exc.message}") from exc


def _unix_time(value: int | None) -> int:
    if value is None:
        return int(time.time())
    return _validate_timestamp(value, "now")
