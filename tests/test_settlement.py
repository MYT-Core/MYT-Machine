import unittest

from myt_machine.errors import InputError, RpcProtocolError, WalletRpcError
from myt_machine.settlement import MachineSettlement

TXID = "ab" * 32
ADDRESS = "4" + "A" * 94
OTHER_ADDRESS = "4" + "B" * 94


class StubClient:
    def __init__(self, responses=None):
        self.url = "http://127.0.0.1:39083"
        self.responses = {key: list(value) for key, value in (responses or {}).items()}
        self.calls = []

    def call(self, method, params=None, *, mutation=False):
        self.calls.append({"method": method, "params": params, "mutation": mutation})
        queue = self.responses.get(method, [])
        if not queue:
            raise AssertionError(f"Unexpected RPC method: {method}")
        response = queue.pop(0)
        if isinstance(response, Exception):
            raise response
        if callable(response):
            return response(params, mutation)
        return response


def address_response(address=ADDRESS, index=0):
    return {
        "address": address,
        "addresses": [
            {
                "address": address,
                "label": "agent",
                "address_index": index,
                "used": False,
            }
        ],
    }


def valid_address_response(nettype="mainnet"):
    return {
        "valid": True,
        "integrated": False,
        "subaddress": False,
        "nettype": nettype,
        "openalias_address": "",
    }


def transfer_entry(transfer_type="out", confirmations=2, amount=100_000_000):
    return {
        "txid": TXID,
        "type": transfer_type,
        "amount": amount,
        "fee": 1_000_000,
        "height": 100,
        "confirmations": confirmations,
        "locked": transfer_type in {"pending", "pool"},
    }


class SettlementTests(unittest.TestCase):
    def test_address_selects_configured_index(self):
        client = StubClient({"get_address": [address_response(index=3)]})
        settlement = MachineSettlement(client, account_index=2, address_index=3)
        result = settlement.address()
        self.assertEqual(result["address"], ADDRESS)
        self.assertEqual(result["account_index"], 2)
        self.assertEqual(result["address_index"], 3)
        self.assertEqual(
            client.calls[0],
            {"method": "get_address", "params": {"account_index": 2, "address_index": [3]}, "mutation": False},
        )

    def test_balance_has_atomic_and_human_values(self):
        client = StubClient(
            {
                "get_balance": [
                    {
                        "balance": 1_250_000_001,
                        "unlocked_balance": 1_000_000_000,
                        "blocks_to_unlock": 2,
                        "time_to_unlock": 120,
                    }
                ]
            }
        )
        result = MachineSettlement(client).balance()
        self.assertEqual(result["total"], {"atomic": 1_250_000_001, "myt": "1.250000001"})
        self.assertEqual(result["unlocked"], {"atomic": 1_000_000_000, "myt": "1.000000000"})
        self.assertEqual(
            client.calls[0],
            {
                "method": "get_balance",
                "params": {
                    "account_index": 0,
                    "address_indices": [0],
                    "all_accounts": False,
                    "strict": False,
                },
                "mutation": False,
            },
        )

    def test_status_combines_wallet_rpc_information(self):
        client = StubClient(
            {
                "get_version": [{"version": (1 << 16) | 29, "release": True}],
                "get_height": [{"height": 182_848}],
                "get_address": [address_response()],
                "validate_address": [valid_address_response("testnet")],
                "get_balance": [
                    {
                        "balance": 500_000_000,
                        "unlocked_balance": 400_000_000,
                        "blocks_to_unlock": 0,
                        "time_to_unlock": 0,
                    }
                ],
            }
        )
        result = MachineSettlement(client).status()
        self.assertEqual(result["rpc"]["version"], {"raw": 65565, "major": 1, "minor": 29})
        self.assertEqual(result["network"], {"type": "testnet", "wallet_height": 182_848})
        self.assertEqual(result["wallet"]["address"], ADDRESS)

    def test_pay_validates_and_sends_exact_payload_once(self):
        client = StubClient(
            {
                "validate_address": [valid_address_response("mainnet")],
                "transfer": [{"tx_hash": TXID, "fee": 2_000_000, "tx_key": "must-not-leak"}],
            }
        )
        result = MachineSettlement(client, account_index=1, address_index=2).pay(
            ADDRESS,
            "1.25",
            priority=3,
        )
        self.assertEqual(result["txid"], TXID)
        self.assertNotIn("tx_key", result)
        self.assertEqual(result["amount"]["atomic"], 1_250_000_000)
        self.assertEqual(
            client.calls[0],
            {
                "method": "validate_address",
                "params": {"address": ADDRESS, "any_net_type": False, "allow_openalias": False},
                "mutation": False,
            },
        )
        transfer = client.calls[1]
        self.assertEqual(transfer["method"], "transfer")
        self.assertTrue(transfer["mutation"])
        self.assertEqual(
            transfer["params"],
            {
                "destinations": [{"address": ADDRESS, "amount": 1_250_000_000}],
                "account_index": 1,
                "subaddr_indices": [2],
                "subtract_fee_from_outputs": [],
                "priority": 3,
                "ring_size": 0,
                "unlock_time": 0,
                "payment_id": "",
                "get_tx_key": False,
                "do_not_relay": False,
                "get_tx_hex": False,
                "get_tx_metadata": False,
            },
        )
        self.assertEqual(len([call for call in client.calls if call["method"] == "transfer"]), 1)

    def test_invalid_payment_fails_before_rpc(self):
        client = StubClient()
        settlement = MachineSettlement(client)
        for amount, priority in (("0", 0), ("1e2", 0), ("1", 5)):
            with self.subTest(amount=amount, priority=priority), self.assertRaises(InputError):
                settlement.pay(ADDRESS, amount, priority=priority)
        self.assertEqual(client.calls, [])

    def test_invalid_network_address_stops_before_transfer(self):
        client = StubClient(
            {
                "validate_address": [
                    {
                        "valid": False,
                        "integrated": False,
                        "subaddress": False,
                        "nettype": "",
                    }
                ]
            }
        )
        with self.assertRaises(InputError):
            MachineSettlement(client).pay(ADDRESS, "1")
        self.assertEqual([call["method"] for call in client.calls], ["validate_address"])

    def test_payment_status_confirmed(self):
        client = StubClient(
            {"get_transfer_by_txid": [{"transfers": [transfer_entry("out", 3)]}]}
        )
        result = MachineSettlement(client).payment_status(TXID.upper())
        self.assertTrue(result["found"])
        self.assertEqual(result["state"], "confirmed")
        self.assertTrue(result["confirmed"])
        self.assertEqual(result["confirmations"], 3)
        self.assertFalse(result["in_pool"])
        self.assertEqual(result["txid"], TXID)
        self.assertEqual(
            client.calls[0],
            {"method": "get_transfer_by_txid", "params": {"txid": TXID, "account_index": 0}, "mutation": False},
        )

    def test_payment_status_states(self):
        cases = (
            ("pending", 0, "pending", None, False),
            ("pool", 0, "pool", True, False),
            ("failed", 0, "failed", False, True),
        )
        for transfer_type, confirmations, state, in_pool, failed in cases:
            with self.subTest(transfer_type=transfer_type):
                client = StubClient(
                    {
                        "get_transfer_by_txid": [
                            {"transfers": [transfer_entry(transfer_type, confirmations)]}
                        ]
                    }
                )
                result = MachineSettlement(client).payment_status(TXID)
                self.assertEqual(result["state"], state)
                self.assertEqual(result["in_pool"], in_pool)
                self.assertEqual(result["failed"], failed)
                self.assertFalse(result["confirmed"])

    def test_payment_status_aggregates_multiple_entries(self):
        client = StubClient(
            {
                "get_transfer_by_txid": [
                    {
                        "transfers": [
                            transfer_entry("in", 4, 10),
                            transfer_entry("in", 4, 20),
                        ]
                    }
                ]
            }
        )
        result = MachineSettlement(client).payment_status(TXID)
        self.assertEqual(result["amount"]["atomic"], 30)
        self.assertEqual(len(result["transfers"]), 2)

    def test_payment_status_not_found(self):
        client = StubClient(
            {"get_transfer_by_txid": [WalletRpcError(-8, "Transaction not found.")]}
        )
        self.assertEqual(
            MachineSettlement(client).payment_status(TXID),
            {"txid": TXID, "found": False},
        )

    def test_other_payment_status_error_is_not_hidden(self):
        client = StubClient({"get_transfer_by_txid": [WalletRpcError(-13, "No wallet file")]})
        with self.assertRaises(WalletRpcError):
            MachineSettlement(client).payment_status(TXID)

    def test_prove_payment_preserves_native_proof(self):
        client = StubClient(
            {
                "validate_address": [valid_address_response()],
                "get_tx_proof": [{"signature": "OutProofV2-native"}],
            }
        )
        result = MachineSettlement(client).prove_payment(
            TXID,
            ADDRESS,
            message="invoice-7",
        )
        self.assertEqual(result["type"], "myt-payment-proof")
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["proof"], "OutProofV2-native")
        self.assertEqual(
            client.calls[1],
            {
                "method": "get_tx_proof",
                "params": {"txid": TXID, "address": ADDRESS, "message": "invoice-7"},
                "mutation": False,
            },
        )

    def test_verify_payment_exposes_actual_rpc_result(self):
        artifact = {
            "type": "myt-payment-proof",
            "version": 1,
            "txid": TXID,
            "address": ADDRESS,
            "message": "invoice-7",
            "proof": "OutProofV2-native",
        }
        client = StubClient(
            {
                "validate_address": [valid_address_response()],
                "check_tx_proof": [
                    {"good": True, "received": 100_000_000, "confirmations": 2, "in_pool": False}
                ],
            }
        )
        result = MachineSettlement(client).verify_payment(artifact)
        self.assertTrue(result["valid"])
        self.assertEqual(result["received"]["myt"], "0.100000000")
        self.assertEqual(result["confirmations"], 2)
        self.assertEqual(
            client.calls[1],
            {
                "method": "check_tx_proof",
                "params": {
                    "txid": TXID,
                    "address": ADDRESS,
                    "message": "invoice-7",
                    "signature": "OutProofV2-native",
                },
                "mutation": False,
            },
        )

    def test_sign_message_uses_spend_signature(self):
        client = StubClient(
            {
                "get_address": [address_response()],
                "sign": [{"signature": "SigV2-native"}],
            }
        )
        result = MachineSettlement(client).sign_message("hello")
        self.assertEqual(result["signature_type"], "spend")
        self.assertEqual(result["address"], ADDRESS)
        self.assertEqual(
            client.calls[1],
            {
                "method": "sign",
                "params": {
                    "data": "hello",
                    "account_index": 0,
                    "address_index": 0,
                    "signature_type": "spend",
                },
                "mutation": False,
            },
        )

    def test_verify_message_exposes_signature_metadata(self):
        client = StubClient(
            {
                "validate_address": [valid_address_response()],
                "verify": [{"good": False, "version": 2, "old": False, "signature_type": "spend"}],
            }
        )
        result = MachineSettlement(client).verify_message(ADDRESS, "hello", "SigV2-native")
        self.assertFalse(result["valid"])
        self.assertEqual(result["version"], 2)
        self.assertEqual(result["signature_type"], "spend")
        self.assertEqual(
            client.calls[1],
            {
                "method": "verify",
                "params": {"data": "hello", "address": ADDRESS, "signature": "SigV2-native"},
                "mutation": False,
            },
        )

    def test_malformed_rpc_data_is_rejected(self):
        client = StubClient({"get_balance": [{"balance": "1", "unlocked_balance": 1}]})
        with self.assertRaises(RpcProtocolError):
            MachineSettlement(client).balance()


if __name__ == "__main__":
    unittest.main()
