"""Deterministic offline wallet, incapable of spending real MYT."""

from __future__ import annotations

import copy

ADDRESS = "B" + "C" * 96
OTHER_ADDRESS = "B" + "D" * 96
MAIN_ADDRESS = "A" + "C" * 94
TXID = "ab" * 32


class FakeBillingRpc:
    def __init__(self, *, network="testnet"):
        self.network = network
        self.calls = []
        self.valid = True
        self.integrated = False
        self.subaddress = True
        self.response = {
            "good": True,
            "received": 100000000,
            "confirmations": 10,
            "in_pool": False,
        }
        self.failure = None
        self.on_proof = None
        self.expected = None

    def call(self, method, params=None, *, mutation=False):
        if mutation or method not in {"validate_address", "check_tx_proof"}:
            raise AssertionError("Phase 4D attempted a non-read-only RPC")
        self.calls.append((method, copy.deepcopy(params), mutation))
        if method == "validate_address":
            if (
                params["any_net_type"] is not False
                or params["allow_openalias"] is not False
            ):
                raise AssertionError("Unsafe address validation flags")
            return {
                "valid": self.valid,
                "nettype": self.network,
                "integrated": self.integrated,
                "subaddress": self.subaddress,
            }
        if self.on_proof:
            self.on_proof()
        if self.failure:
            raise self.failure
        if self.expected and params != self.expected:
            return {**self.response, "good": False}
        return copy.deepcopy(self.response)


def proof_for(request, txid=TXID):
    return {
        "type": "myt-payment-proof",
        "version": 1,
        "txid": txid,
        "address": request.recipient_address,
        "message": request.proof_message,
        "proof": "OutProofV2" + "1" * 132,
    }
