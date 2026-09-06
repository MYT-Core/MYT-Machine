"""Local invoice state, separate from the payer-facing request artifact."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .errors import InputError, MytMachineError
from .payment_requests import MAX_TIMESTAMP, PaymentRequest, bounded_int
from .validation import normalize_txid

DEFAULT_CONFIRMATIONS = 10
MAX_CONFIRMATIONS = 0xFFFFFFFF


class InvoiceConflict(InputError):
    code = "invoice_conflict"


class InvoiceNotFound(InputError):
    code = "invoice_not_found"


class InvoiceNotPaid(MytMachineError):
    code = "invoice_not_paid"
    exit_code = 1


class InvoiceStorageError(MytMachineError):
    code = "invoice_storage_error"


class InvoiceState(str, Enum):
    PENDING = "PENDING"
    PAID = "PAID"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True, slots=True)
class InvoiceRecord:
    request: PaymentRequest
    state: InvoiceState
    required_confirmations: int = DEFAULT_CONFIRMATIONS
    txid: str | None = None
    received_atomic: int | None = None
    confirmations: int | None = None
    paid_at: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.request, PaymentRequest) or not isinstance(
            self.state, InvoiceState
        ):
            raise InputError("Invalid invoice record")
        self.request.__post_init__()
        bounded_int(
            self.required_confirmations, "required confirmations", 1, MAX_CONFIRMATIONS
        )
        evidence = (self.txid, self.received_atomic, self.confirmations, self.paid_at)
        if self.state is not InvoiceState.PAID:
            if any(v is not None for v in evidence):
                raise InputError(
                    "Unpaid invoice must not contain finalized payment data"
                )
        else:
            if any(v is None for v in evidence):
                raise InputError("Paid invoice requires complete payment data")
            if normalize_txid(self.txid) != self.txid:
                raise InputError("Stored transaction ID must be lowercase")
            bounded_int(
                self.received_atomic,
                "received amount",
                self.request.amount_atomic,
                self.request.amount_atomic,
            )
            bounded_int(
                self.confirmations,
                "confirmations",
                self.required_confirmations,
                MAX_CONFIRMATIONS,
            )
            bounded_int(
                self.paid_at,
                "paid_at",
                self.request.created_at,
                min(MAX_TIMESTAMP, self.request.expires_at - 1),
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "request": self.request.as_dict(),
            "state": self.state.value,
            "required_confirmations": self.required_confirmations,
            "txid": self.txid,
            "received_atomic": self.received_atomic,
            "confirmations": self.confirmations,
            "paid_at": self.paid_at,
            "proof_message": self.request.proof_message,
        }
