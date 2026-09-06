"""Programmatic, non-custodial billing for API/service integrations."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from .errors import ConfigurationError, InputError
from .invoice_store import SQLiteInvoiceStore
from .invoice_verification import PaymentRequestVerifier
from .invoices import DEFAULT_CONFIRMATIONS, InvoiceNotPaid, InvoiceRecord, InvoiceState
from .payment_requests import canonical_json, create_payment_request, validate_network


@dataclass(frozen=True, slots=True)
class InvoiceVerification:
    invoice: InvoiceRecord
    reason: str

    @property
    def paid(self) -> bool:
        return self.invoice.state is InvoiceState.PAID

    def as_dict(self) -> dict[str, Any]:
        return {
            "invoice": self.invoice.as_dict(),
            "paid": self.paid,
            "reason": self.reason,
        }


class BillingService:
    """Trusted application code owns invoice terms and service authorization.

    The verifier is a trusted dependency, not a payer-supplied callback. Phase 4D
    never sends a transfer, requests a key, or retries a wallet operation.
    """

    def __init__(
        self,
        store: SQLiteInvoiceStore,
        *,
        network: str,
        verifier: PaymentRequestVerifier | None = None,
    ) -> None:
        self.store = store
        self.network = validate_network(network)
        self.verifier = verifier

    def create_invoice(
        self,
        recipient_address: str,
        amount_atomic: int,
        *,
        expires_in: int = 3600,
        invoice_id: str | None = None,
        memo: str | None = None,
        reference: str | None = None,
        idempotency_key: str | None = None,
        required_confirmations: int = DEFAULT_CONFIRMATIONS,
    ) -> InvoiceRecord:
        request = create_payment_request(
            recipient_address,
            amount_atomic,
            network=self.network,
            expires_in=expires_in,
            invoice_id=invoice_id,
            memo=memo,
            reference=reference,
            now=self.store._now(),
        )
        if self.verifier is None:
            raise ConfigurationError(
                "Invoice creation requires native recipient/network validation"
            )
        if not self.verifier.validate_request(request):
            raise InputError(
                "Invoice recipient is invalid or unsupported for this wallet network"
            )
        # Generated IDs and current time are excluded; every client-controlled
        # term, including confirmation policy, participates in idempotency.
        parameters = {
            "network": self.network,
            "recipient_address": recipient_address,
            "amount_atomic": amount_atomic,
            "expires_in": expires_in,
            "invoice_id": invoice_id,
            "memo": memo,
            "reference": reference,
            "required_confirmations": required_confirmations,
        }
        fingerprint = hashlib.sha256(
            canonical_json(parameters).encode("ascii")
        ).hexdigest()
        return self.store.create(
            request,
            required_confirmations=required_confirmations,
            creation_fingerprint=fingerprint,
            idempotency_key=idempotency_key,
        )

    def get_invoice(self, invoice_id: str) -> InvoiceRecord:
        record = self.store.get(invoice_id)
        if record.request.network != self.network:
            raise ConfigurationError(
                "Invoice belongs to a different configured network"
            )
        return record

    def list_invoices(
        self, *, limit: int = 50, after: str | None = None
    ) -> list[InvoiceRecord]:
        return self.store.list(network=self.network, limit=limit, after=after)

    def invoice_status(self, invoice_id: str) -> InvoiceState:
        return self.get_invoice(invoice_id).state

    def verify_invoice(
        self, invoice_id: str, proof: dict[str, Any]
    ) -> InvoiceVerification:
        current = self.get_invoice(invoice_id)
        if current.state is not InvoiceState.PENDING:
            return InvoiceVerification(
                current,
                "already_paid" if current.state is InvoiceState.PAID else "expired",
            )
        if self.verifier is None:
            raise ConfigurationError(
                "Invoice verification requires a read-only Wallet RPC verifier"
            )
        observation = self.verifier.verify(
            current.request,
            proof,
            required_confirmations=current.required_confirmations,
        )
        if observation.eligible:
            current = self.store._finalize(current.request, observation)
        else:
            current = self.get_invoice(invoice_id)
        reason = (
            "expired" if current.state is InvoiceState.EXPIRED else observation.reason
        )
        return InvoiceVerification(current, reason)

    def require_paid(self, invoice_id: str) -> InvoiceRecord:
        """Gate trusted application work; this is not customer authentication.

        Applications must separately bind invoice IDs to the authorized client,
        purchased operation, price and one-time fulfillment where applicable.
        """
        invoice = self.get_invoice(invoice_id)
        if invoice.state is not InvoiceState.PAID:
            raise InvoiceNotPaid("Invoice has not reached paid status")
        return invoice
