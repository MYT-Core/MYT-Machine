"""Higher-level machine settlement operations backed by wallet RPC."""

from __future__ import annotations

from typing import Any

from .amounts import UINT64_MAX, amount_object, parse_myt_amount
from .errors import InputError, RpcProtocolError, WalletRpcError
from .proofs import create_proof_artifact, parse_proof_artifact
from .rpc import WalletRpcClient
from .validation import (
    normalize_txid,
    validate_address_text,
    validate_message,
    validate_signature,
    validate_uint32,
)

RPC_WRONG_TXID = -8
TRANSFER_TYPES = {"in", "out", "pending", "failed", "pool", "block"}


def _rpc_int(
    value: Any,
    field_name: str,
    *,
    minimum: int = 0,
    maximum: int = UINT64_MAX,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise RpcProtocolError(f"Wallet RPC returned an invalid {field_name}")
    return value


def _rpc_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise RpcProtocolError(f"Wallet RPC returned an invalid {field_name}")
    return value


def _rpc_string(value: Any, field_name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise RpcProtocolError(f"Wallet RPC returned an invalid {field_name}")
    return value


def _safe_sum(values: list[int], field_name: str) -> int:
    total = sum(values)
    if total > UINT64_MAX:
        raise RpcProtocolError(f"Wallet RPC {field_name} values overflow uint64")
    return total


class MachineSettlement:
    """Machine-facing wrapper around an existing myt-wallet-rpc instance."""

    def __init__(
        self,
        client: WalletRpcClient,
        *,
        account_index: int = 0,
        address_index: int = 0,
    ) -> None:
        self.client = client
        self.account_index = validate_uint32(account_index, "account index")
        self.address_index = validate_uint32(address_index, "address index")

    def _address(self) -> dict[str, Any]:
        response = self.client.call(
            "get_address",
            {
                "account_index": self.account_index,
                "address_index": [self.address_index],
            },
        )
        addresses = response.get("addresses")
        if not isinstance(addresses, list):
            raise RpcProtocolError("Wallet RPC get_address response is missing addresses")
        selected: dict[str, Any] | None = None
        for candidate in addresses:
            if not isinstance(candidate, dict):
                raise RpcProtocolError("Wallet RPC returned a malformed address entry")
            index = _rpc_int(candidate.get("address_index"), "address index", maximum=0xFFFFFFFF)
            if index == self.address_index:
                selected = candidate
                break
        if selected is None:
            raise RpcProtocolError("Wallet RPC did not return the requested address index")
        return {
            "address": _rpc_string(selected.get("address"), "address"),
            "account_index": self.account_index,
            "address_index": self.address_index,
            "label": _rpc_string(selected.get("label", ""), "address label", allow_empty=True),
            "used": _rpc_bool(selected.get("used"), "address used flag"),
        }

    def address(self) -> dict[str, Any]:
        return self._address()

    def balance(self) -> dict[str, Any]:
        response = self.client.call(
            "get_balance",
            {
                "account_index": self.account_index,
                "address_indices": [self.address_index],
                "all_accounts": False,
                "strict": False,
            },
        )
        total = _rpc_int(response.get("balance"), "balance")
        unlocked = _rpc_int(response.get("unlocked_balance"), "unlocked balance")
        return {
            "total": amount_object(total),
            "unlocked": amount_object(unlocked),
            "blocks_to_unlock": _rpc_int(response.get("blocks_to_unlock", 0), "blocks to unlock"),
            "time_to_unlock": _rpc_int(response.get("time_to_unlock", 0), "time to unlock"),
            "account_index": self.account_index,
            "address_index": self.address_index,
        }

    def _validate_wallet_address(self, address: str) -> dict[str, Any]:
        address = validate_address_text(address)
        response = self.client.call(
            "validate_address",
            {
                "address": address,
                "any_net_type": False,
                "allow_openalias": False,
            },
        )
        valid = _rpc_bool(response.get("valid"), "address validity")
        if not valid:
            raise InputError("Address is not valid for the opened wallet network")
        return {
            "address": address,
            "network": _rpc_string(response.get("nettype"), "network type"),
            "integrated": _rpc_bool(response.get("integrated"), "integrated-address flag"),
            "subaddress": _rpc_bool(response.get("subaddress"), "subaddress flag"),
        }

    def status(self) -> dict[str, Any]:
        version_response = self.client.call("get_version")
        height_response = self.client.call("get_height")
        address = self._address()
        address_info = self._validate_wallet_address(address["address"])
        balance = self.balance()

        version = _rpc_int(version_response.get("version"), "wallet RPC version", maximum=0xFFFFFFFF)
        return {
            "rpc": {
                "url": self.client.url,
                "version": {
                    "raw": version,
                    "major": version >> 16,
                    "minor": version & 0xFFFF,
                },
                "release": _rpc_bool(version_response.get("release"), "release flag"),
            },
            "network": {
                "type": address_info["network"],
                "wallet_height": _rpc_int(height_response.get("height"), "wallet height"),
            },
            "wallet": address,
            "balance": {
                "total": balance["total"],
                "unlocked": balance["unlocked"],
            },
        }

    def pay(self, address: str, amount: str, *, priority: int = 0) -> dict[str, Any]:
        atomic = parse_myt_amount(amount, require_positive=True)
        if isinstance(priority, bool) or not isinstance(priority, int) or not 0 <= priority <= 4:
            raise InputError("Payment priority must be an integer between 0 and 4")
        address_info = self._validate_wallet_address(address)

        response = self.client.call(
            "transfer",
            {
                "destinations": [{"address": address_info["address"], "amount": atomic}],
                "account_index": self.account_index,
                "subaddr_indices": [self.address_index],
                "subtract_fee_from_outputs": [],
                "priority": priority,
                "ring_size": 0,
                "unlock_time": 0,
                "payment_id": "",
                "get_tx_key": False,
                "do_not_relay": False,
                "get_tx_hex": False,
                "get_tx_metadata": False,
            },
            mutation=True,
        )
        txid = normalize_txid(_rpc_string(response.get("tx_hash"), "transaction hash"))
        fee = _rpc_int(response.get("fee"), "transaction fee")
        return {
            "txid": txid,
            "destination": address_info["address"],
            "network": address_info["network"],
            "amount": amount_object(atomic),
            "fee": amount_object(fee),
        }

    def _normalize_transfer(self, entry: Any) -> dict[str, Any]:
        if not isinstance(entry, dict):
            raise RpcProtocolError("Wallet RPC returned a malformed transfer entry")
        transfer_type = _rpc_string(entry.get("type"), "transfer type")
        if transfer_type not in TRANSFER_TYPES:
            raise RpcProtocolError("Wallet RPC returned an unknown transfer type")
        confirmations = _rpc_int(entry.get("confirmations", 0), "confirmations")
        amount = _rpc_int(entry.get("amount"), "transfer amount")
        fee = _rpc_int(entry.get("fee", 0), "transfer fee")
        confirmed = transfer_type in {"in", "out", "block"} and confirmations > 0
        if transfer_type == "pool":
            in_pool: bool | None = True
        elif transfer_type == "pending":
            in_pool = None
        else:
            in_pool = False
        return {
            "type": transfer_type,
            "amount": amount_object(amount),
            "fee": amount_object(fee),
            "height": _rpc_int(entry.get("height", 0), "transfer height"),
            "confirmations": confirmations,
            "confirmed": confirmed,
            "in_pool": in_pool,
            "failed": transfer_type == "failed",
            "locked": _rpc_bool(entry.get("locked"), "transfer locked flag"),
        }

    def payment_status(self, txid: str) -> dict[str, Any]:
        normalized_txid = normalize_txid(txid)
        try:
            response = self.client.call(
                "get_transfer_by_txid",
                {"txid": normalized_txid, "account_index": self.account_index},
            )
        except WalletRpcError as exc:
            if exc.rpc_code == RPC_WRONG_TXID:
                return {"txid": normalized_txid, "found": False}
            raise

        entries = response.get("transfers")
        if not isinstance(entries, list):
            fallback = response.get("transfer")
            entries = [fallback] if isinstance(fallback, dict) else []
        if not entries:
            raise RpcProtocolError("Wallet RPC returned no entries for a found transaction")
        transfers = [self._normalize_transfer(entry) for entry in entries]

        types = {entry["type"] for entry in transfers}
        if "failed" in types:
            state = "failed"
        elif "pool" in types:
            state = "pool"
        elif "pending" in types:
            state = "pending"
        elif all(entry["confirmed"] for entry in transfers):
            state = "confirmed"
        else:
            state = "unconfirmed"

        if "pool" in types:
            in_pool: bool | None = True
        elif "pending" in types:
            in_pool = None
        else:
            in_pool = False
        total_amount = _safe_sum([entry["amount"]["atomic"] for entry in transfers], "amount")
        return {
            "txid": normalized_txid,
            "found": True,
            "state": state,
            "confirmed": all(entry["confirmed"] for entry in transfers),
            "confirmations": min(entry["confirmations"] for entry in transfers),
            "in_pool": in_pool,
            "failed": "failed" in types,
            "amount": amount_object(total_amount),
            "transfers": transfers,
        }

    def prove_payment(self, txid: str, address: str, *, message: str = "") -> dict[str, Any]:
        normalized_txid = normalize_txid(txid)
        message = validate_message(message)
        address_info = self._validate_wallet_address(address)
        response = self.client.call(
            "get_tx_proof",
            {
                "txid": normalized_txid,
                "address": address_info["address"],
                "message": message,
            },
        )
        proof = _rpc_string(response.get("signature"), "payment proof")
        return create_proof_artifact(normalized_txid, address_info["address"], message, proof)

    def verify_payment(self, artifact: Any) -> dict[str, Any]:
        proof = parse_proof_artifact(artifact)
        self._validate_wallet_address(proof["address"])
        response = self.client.call(
            "check_tx_proof",
            {
                "txid": proof["txid"],
                "address": proof["address"],
                "message": proof["message"],
                "signature": proof["proof"],
            },
        )
        valid = _rpc_bool(response.get("good"), "proof verification result")
        received = _rpc_int(response.get("received"), "received amount")
        return {
            "valid": valid,
            "txid": proof["txid"],
            "address": proof["address"],
            "message": proof["message"],
            "received": amount_object(received),
            "confirmations": _rpc_int(response.get("confirmations"), "confirmations"),
            "in_pool": _rpc_bool(response.get("in_pool"), "pool flag"),
        }

    def sign_message(self, message: str) -> dict[str, Any]:
        message = validate_message(message)
        address = self._address()
        response = self.client.call(
            "sign",
            {
                "data": message,
                "account_index": self.account_index,
                "address_index": self.address_index,
                "signature_type": "spend",
            },
        )
        signature = validate_signature(_rpc_string(response.get("signature"), "signature"))
        return {
            "address": address["address"],
            "message": message,
            "signature": signature,
            "signature_type": "spend",
        }

    def verify_message(self, address: str, message: str, signature: str) -> dict[str, Any]:
        message = validate_message(message)
        signature = validate_signature(signature)
        address_info = self._validate_wallet_address(address)
        response = self.client.call(
            "verify",
            {"data": message, "address": address_info["address"], "signature": signature},
        )
        return {
            "valid": _rpc_bool(response.get("good"), "signature verification result"),
            "address": address_info["address"],
            "message": message,
            "version": _rpc_int(response.get("version"), "signature version", maximum=0xFFFFFFFF),
            "old": _rpc_bool(response.get("old"), "legacy-signature flag"),
            "signature_type": _rpc_string(response.get("signature_type"), "signature type", allow_empty=True),
        }
