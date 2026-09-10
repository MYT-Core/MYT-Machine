"""Read-only 4C/4D bridge: recipient-linked observation, never payer attribution."""

from __future__ import annotations

import os

from .billing import BillingService
from .binding import AddressBinding, AddressBindingService
from .binding_artifacts import parse_address_binding
from .errors import InputError, WalletRpcError
from .identity import machine_id_digest
from .invoice_store import SQLiteInvoiceStore
from .invoice_verification import WalletPaymentVerifier, _prepare_invoice_proof
from .invoices import InvoiceState
from .reputation import content_digest
from .reputation_store import ReputationStore
from .rpc import WalletRpcClient


def record_verified_settlement(
    store: ReputationStore | str | os.PathLike[str],
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
    Pass a path to defer opening/creating the reputation database until all local
    and native verification succeeds. An already-open store remains supported.
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
        or binding.machine_id != expected_machine_id
    ):
        raise InputError("Binding does not match the invoice recipient and network")
    if not binding.verify_identity(expected_machine_id=expected_machine_id).valid:
        raise InputError("Settlement binding verification failed")
    proof, negative = _prepare_invoice_proof(
        record.request, proof, record.required_confirmations
    )
    if negative is not None or proof["txid"] != record.txid:
        raise InputError("Fresh settlement proof does not match the PAID invoice")
    try:
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
    except WalletRpcError as exc:
        # Native error text can disclose wallet data; preserve only its numeric code.
        raise WalletRpcError(exc.rpc_code, "Wallet RPC application error") from None
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
    # Invoice state is monotonic through the supported API. Fail closed if the
    # trusted local snapshot changed while native verification was in progress.
    if BillingService(invoices, network=network).get_invoice(invoice_id) != record:
        raise InputError("Invoice changed during settlement verification")
    if not isinstance(store, ReputationStore):
        store = ReputationStore(store)
    digest, inserted = store._record_settlement(evidence)
    return {
        "evidence_digest": digest,
        "inserted": inserted,
        "subject_machine_id": binding.machine_id,
        "network": network,
        "payer_identity_inferred": False,
        "service_quality_verified": False,
    }
