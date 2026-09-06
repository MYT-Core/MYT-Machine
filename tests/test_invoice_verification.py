import unittest

from billing_fakes import ADDRESS, OTHER_ADDRESS, TXID, FakeBillingRpc, proof_for

from myt_machine.errors import (
    ConfigurationError,
    InputError,
    RpcAuthenticationError,
    RpcProtocolError,
    RpcTransportError,
    WalletRpcError,
)
from myt_machine.invoice_verification import (
    PaymentRequestVerifier,
    WalletPaymentVerifier,
)
from myt_machine.payment_requests import create_payment_request


class InvoiceVerificationTests(unittest.TestCase):
    def setUp(self):
        self.rpc = FakeBillingRpc()
        self.verifier = WalletPaymentVerifier(self.rpc, network="testnet")
        self.request = create_payment_request(
            ADDRESS, 100000000, network="testnet", now=1000
        )
        self.proof = proof_for(self.request)

    def verify(self, **kwargs):
        return self.verifier.verify(self.request, self.proof, **kwargs)

    def test_readonly_protocol(self):
        self.assertIsInstance(self.verifier, PaymentRequestVerifier)

    def test_correct_payment_and_exact_payloads(self):
        result = self.verify()
        self.assertTrue(result.eligible)
        self.assertEqual(result.txid, TXID)
        self.assertEqual(result.received_atomic, 100000000)
        self.assertEqual(
            [c[0] for c in self.rpc.calls],
            ["validate_address", "validate_address", "check_tx_proof"],
        )
        self.assertEqual(
            self.rpc.calls[-1],
            (
                "check_tx_proof",
                {
                    "txid": TXID,
                    "address": ADDRESS,
                    "message": self.request.proof_message,
                    "signature": self.proof["proof"],
                },
                False,
            ),
        )

    def test_wrong_recipient(self):
        self.proof["address"] = OTHER_ADDRESS
        self.assertEqual(self.verify().reason, "wrong_recipient")
        self.assertEqual(self.rpc.calls, [])

    def test_wrong_request_message(self):
        self.proof["message"] = ""
        self.assertEqual(self.verify().reason, "wrong_request")
        self.assertEqual(self.rpc.calls, [])

    def test_underpayment(self):
        self.rpc.response["received"] = 99999999
        self.assertEqual(self.verify().reason, "wrong_amount")

    def test_overpayment(self):
        self.rpc.response["received"] = 100000001
        self.assertEqual(self.verify().reason, "wrong_amount")

    def test_insufficient_confirmations(self):
        for depth in (0, 1, 9):
            self.rpc.response["confirmations"] = depth
            with self.subTest(depth=depth):
                self.assertEqual(self.verify().reason, "awaiting_confirmations")

    def test_configurable_threshold(self):
        self.assertFalse(self.verify(required_confirmations=11).eligible)
        self.assertTrue(self.verify(required_confirmations=10).eligible)
        self.rpc.response["confirmations"] = 1
        self.assertTrue(self.verify(required_confirmations=1).eligible)

    def test_no_zero_or_float_threshold(self):
        for value in (0, -1, False, 1.0, 1 << 32):
            with self.subTest(value=value), self.assertRaises(InputError):
                self.verify(required_confirmations=value)

    def test_pool_even_with_confirmations(self):
        self.rpc.response["in_pool"] = True
        self.assertFalse(self.verify().eligible)

    def test_bad_native_proof(self):
        self.rpc.response["good"] = False
        self.assertEqual(self.verify().reason, "invalid_proof")

    def test_network_mismatch(self):
        self.rpc.network = "mainnet"
        with self.assertRaises(ConfigurationError):
            self.verify()

    def test_request_network_mismatch(self):
        verifier = WalletPaymentVerifier(self.rpc, network="stagenet")
        with self.assertRaises(ConfigurationError):
            verifier.verify(self.request, self.proof)

    def test_invalid_wallet_address(self):
        self.rpc.valid = False
        self.assertEqual(self.verify().reason, "invalid_recipient")

    def test_integrated_wallet_address(self):
        self.rpc.integrated = True
        self.rpc.subaddress = False
        self.assertFalse(self.verify().eligible)

    def test_contradictory_address_flags(self):
        self.rpc.integrated = True
        with self.assertRaises(RpcProtocolError):
            self.verify()

    def test_standard_address_validated(self):
        self.rpc.subaddress = False
        self.assertTrue(self.verify().eligible)

    def test_false_rpc_flags_not_truthy_strings(self):
        for field in ("good", "in_pool"):
            self.rpc.response[field] = "true"
            with self.subTest(field=field), self.assertRaises(RpcProtocolError):
                self.verify()
            self.rpc.response[field] = field == "good"

    def test_malformed_amounts(self):
        for value in (-1, True, "100000000", 100000000.0, 1 << 64):
            self.rpc.response["received"] = value
            with self.subTest(value=value), self.assertRaises(RpcProtocolError):
                self.verify()

    def test_bad_confirmation_count_and_underflow(self):
        for value in (-1, True, 1.0, "10", (1 << 64) - 1):
            self.rpc.response["confirmations"] = value
            with self.subTest(value=value), self.assertRaises(RpcProtocolError):
                self.verify()

    def test_missing_response_field(self):
        del self.rpc.response["in_pool"]
        with self.assertRaises(RpcProtocolError):
            self.verify()

    def test_reject_inproof_legacy_and_malformed_proofs(self):
        for value in (
            "InProofV2" + "1" * 132,
            "OutProofV1" + "1" * 132,
            "OutProofV2",
            "OutProofV2" + "1" * 131,
            "OutProofV2" + "0" * 132,
            "OutProofV2" + "1" * 66000,
        ):
            self.proof["proof"] = value
            with self.subTest(length=len(value)), self.assertRaises(InputError):
                self.verify()

    def test_malformed_proof_schema(self):
        self.proof["secret"] = "must-not-appear"
        with self.assertRaises(InputError) as caught:
            self.verify()
        self.assertNotIn("must-not-appear", str(caught.exception))

    def test_proof_version_exact_integer(self):
        for value in (True, 1.0, 2):
            self.proof["version"] = value
            with self.subTest(value=value), self.assertRaises(InputError):
                self.verify()

    def test_invalid_txid(self):
        self.proof["txid"] = "not-a-tx"
        with self.assertRaises(InputError):
            self.verify()

    def test_txid_normalized(self):
        self.proof["txid"] = TXID.upper()
        self.assertEqual(self.verify().txid, TXID)

    def test_nonexistent_and_failed_transactions_raise_without_retry(self):
        self.rpc.failure = WalletRpcError(-1, "unavailable")
        with self.assertRaises(WalletRpcError):
            self.verify()
        self.assertEqual(sum(c[0] == "check_tx_proof" for c in self.rpc.calls), 1)

    def test_timeout_never_retried(self):
        self.rpc.failure = RpcTransportError("Timeout", kind="timeout")
        with self.assertRaises(RpcTransportError):
            self.verify()
        self.assertEqual(sum(c[0] == "check_tx_proof" for c in self.rpc.calls), 1)

    def test_authentication_failure(self):
        self.rpc.failure = RpcAuthenticationError()
        with self.assertRaises(RpcAuthenticationError):
            self.verify()

    def test_substituted_txid_is_cryptographically_rechecked(self):
        self.rpc.expected = {
            "txid": TXID,
            "address": ADDRESS,
            "message": self.request.proof_message,
            "signature": self.proof["proof"],
        }
        self.proof["txid"] = "cd" * 32
        self.assertFalse(self.verify().eligible)
