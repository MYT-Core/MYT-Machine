"""Read-only invoice verification through native MYT OutProofV2."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from .errors import ConfigurationError, InputError, RpcProtocolError
from .invoices import DEFAULT_CONFIRMATIONS, MAX_CONFIRMATIONS
from .payment_requests import PaymentRequest, bounded_int, validate_network
from .proofs import parse_proof_artifact
from .rpc import WalletRpcClient
from .settlement import MachineSettlement, _rpc_bool, _rpc_int

MAX_INVOICE_PROOF_BYTES = 65536
_PROOF_FIELDS = frozenset({"type", "version", "txid", "address", "message", "proof"})
_OUT_PROOF = re.compile(r"OutProofV2[1-9A-HJ-NP-Za-km-z]+")


@dataclass(frozen=True, slots=True)
class PaymentObservation:
    eligible: bool
    reason: str
    txid: str
    request_message: str
    received_atomic: int = 0
    confirmations: int = 0


def _prepare_invoice_proof(
    request: PaymentRequest, artifact: dict[str, Any], required_confirmations: int
) -> tuple[dict[str, Any], PaymentObservation | None]:
    """Shared local-only preflight; no RPC or persistence before this succeeds."""
    bounded_int(required_confirmations, "required confirmations", 1, MAX_CONFIRMATIONS)
    if not isinstance(artifact, dict) or set(artifact) != _PROOF_FIELDS:
        raise InputError("Invoice verification requires an exact-schema payment proof")
    if type(artifact["version"]) is not int or artifact["version"] != 1:
        raise InputError("Invalid payment proof version")
    proof_text = artifact["proof"]
    if (
        not isinstance(proof_text, str)
        or len(proof_text) > MAX_INVOICE_PROOF_BYTES
        or _OUT_PROOF.fullmatch(proof_text) is None
        or (len(proof_text) - 10) % 132 != 0
    ):
        raise InputError("Invoice verification requires a native OutProofV2")
    proof = parse_proof_artifact(artifact)
    reason = None
    if proof["address"] != request.recipient_address:
        reason = "wrong_recipient"
    elif proof["message"] != request.proof_message:
        reason = "wrong_request"
    negative = (
        PaymentObservation(False, reason, proof["txid"], request.proof_message)
        if reason is not None else None
    )
    return proof, negative


@runtime_checkable
class PaymentRequestVerifier(Protocol):
    def validate_request(self, request: PaymentRequest) -> bool:
        """Validate recipient checksum, type and network without spending."""
        ...

    def verify(
        self,
        request: PaymentRequest,
        artifact: dict[str, Any],
        *,
        required_confirmations: int,
    ) -> PaymentObservation:
        """Observe payment evidence without changing invoice state or spending."""
        ...


class WalletPaymentVerifier:
    """Trusts the configured wallet/daemon for chain membership and depth.

    Transaction proofs authenticate payment to the recipient and an invoice
    message, not a sender address. Wallet-local payment_status alone is not
    sufficient evidence. Only validate_address and check_tx_proof are invoked.
    """

    def __init__(self, client: WalletRpcClient, *, network: str) -> None:
        self.network = validate_network(network)
        self._client = client
        self._settlement = MachineSettlement(client)

    def validate_request(self, request: PaymentRequest) -> bool:
        if not isinstance(request, PaymentRequest):
            raise InputError("Expected a PaymentRequest")
        request.__post_init__()
        if request.network != self.network:
            raise ConfigurationError("Request network differs from verifier network")
        response = self._client.call(
            "validate_address",
            {
                "address": request.recipient_address,
                "any_net_type": False,
                "allow_openalias": False,
            },
        )
        if not _rpc_bool(response.get("valid"), "address validity"):
            return False
        if response.get("nettype") != self.network:
            raise ConfigurationError("Verifier wallet is opened on a different network")
        integrated = _rpc_bool(response.get("integrated"), "integrated flag")
        subaddress = _rpc_bool(response.get("subaddress"), "subaddress flag")
        if integrated and subaddress:
            raise RpcProtocolError("Contradictory wallet address type")
        return not integrated

    def verify(
        self,
        request: PaymentRequest,
        artifact: dict[str, Any],
        *,
        required_confirmations: int = DEFAULT_CONFIRMATIONS,
    ) -> PaymentObservation:
        proof, local_failure = _prepare_invoice_proof(
            request, artifact, required_confirmations
        )
        if local_failure is not None:
            return local_failure
        txid = proof["txid"]

        def negative(reason: str) -> PaymentObservation:
            return PaymentObservation(False, reason, txid, request.proof_message)

        if not self.validate_request(request):
            return negative("invalid_recipient")
        # Reuse Phase 4A proof validation and native Wallet RPC verification.
        # There are no mutations, payment_status shortcuts or retries here.
        result = self._settlement.verify_payment(proof)
        if not _rpc_bool(result["valid"], "proof result"):
            return negative("invalid_proof")
        received = result["received"]["atomic"]
        confirmations = _rpc_int(
            result["confirmations"], "confirmations", maximum=MAX_CONFIRMATIONS
        )
        if received != request.amount_atomic:
            return negative("wrong_amount")
        if result["in_pool"] or confirmations < required_confirmations:
            return PaymentObservation(
                False,
                "awaiting_confirmations",
                txid,
                request.proof_message,
                received,
                confirmations,
            )
        return PaymentObservation(
            True, "confirmed", txid, request.proof_message, received, confirmations
        )
