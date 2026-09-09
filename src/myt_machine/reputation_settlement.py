"""Read-only 4C/4D bridge: recipient-linked observation, never payer attribution."""

from __future__ import annotations

from .billing import BillingService
from .binding import AddressBinding, AddressBindingService
from .binding_artifacts import parse_address_binding
from .errors import InputError
from .identity import machine_id_digest
from .invoice_store import SQLiteInvoiceStore
from .invoice_verification import WalletPaymentVerifier
from .invoices import InvoiceState
from .reputation import content_digest
from .reputation_store import ReputationStore
from .rpc import WalletRpcClient


def record_verified_settlement(
    store: ReputationStore,
    invoices: SQLiteInvoiceStore,
    client: WalletRpcClient,
    *,
    network: str,
    invoice_id: str,
    binding: AddressBinding,
    proof: dict,
    expected_machine_id: str,
) -> dict:
    """Require durable PAID state AND freshly verify exact native payment proof.

    The proof cannot identify a payer Machine ID, service fulfillment or current
    control. The caller trusts the configured local wallet/daemon and database.
    """
    machine_id_digest(expected_machine_id)
    record = BillingService(invoices, network=network).get_invoice(invoice_id)
    if record.state != InvoiceState.PAID:
        raise InputError("Reputation settlement requires a locally PAID invoice")
    try:
        binding = parse_address_binding(binding.as_dict())
    except InputError:
        raise InputError("Invalid settlement binding") from None
    if (
        binding.address != record.request.recipient_address
        or binding.network != network
    ):
        raise InputError("Binding does not match the invoice recipient and network")
    if (
        not AddressBindingService(client)
        .verify(
            binding, expected_machine_id=expected_machine_id, expected_network=network
        )
        .valid
    ):
        raise InputError("Settlement binding verification failed")
    observation = WalletPaymentVerifier(client, network=network).verify(
        record.request, proof, required_confirmations=record.required_confirmations
    )
    if not observation.eligible or observation.txid != record.txid:
        raise InputError("Fresh settlement proof does not match the PAID invoice")
    evidence = {
        "type": "myt-recipient-settlement-observation",
        "version": 1,
        "network": network,
        "subject_machine_id": binding.machine_id,
        "transaction_digest": content_digest(
            b"MYT-REPUTATION-TX-V1\n",
            {
                "network": network,
                "txid": observation.txid,
            },
        ),
        "request_digest": content_digest(
            b"MYT-REPUTATION-REQUEST-V1\n", record.request.as_dict()
        ),
        "binding_digest": content_digest(
            b"MYT-REPUTATION-BINDING-V1\n", binding.as_dict()
        ),
    }
    digest, inserted = store._record_settlement(evidence)
    return {
        "evidence_digest": digest,
        "inserted": inserted,
        "subject_machine_id": binding.machine_id,
        "network": network,
        "payer_identity_inferred": False,
        "service_quality_verified": False,
    }
