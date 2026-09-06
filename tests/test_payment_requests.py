import json
import unittest

from myt_machine.errors import InputError
from myt_machine.payment_requests import (
    PAYMENT_REQUEST_TYPE,
    PAYMENT_REQUEST_VERSION,
    PaymentRequestState,
    PaymentRequestVerifier,
    PaymentVerification,
    create_payment_request,
    parse_payment_request,
    serialize_payment_request,
)

ADDRESS = "MYT_TEST_ADDRESS_123"


class DummyVerifier:
    def verify(self, request):
        del request
        return PaymentVerification(paid=True, txid="a" * 64, proof={"kind": "test"})


class PaymentRequestTests(unittest.TestCase):
    def test_create_payment_request_uses_atomic_integer_and_defaults_to_pending(self):
        request = create_payment_request(ADDRESS, 1_250_000_000, expires_in=300, now=1_000)
        self.assertEqual(request.recipient_address, ADDRESS)
        self.assertEqual(request.amount_atomic, 1_250_000_000)
        self.assertEqual(request.created_at, 1_000)
        self.assertEqual(request.expires_at, 1_300)
        self.assertIs(request.state, PaymentRequestState.PENDING)
        self.assertTrue(request.invoice_id)

    def test_create_payment_request_supports_memo_reference_and_custom_id(self):
        request = create_payment_request(
            ADDRESS,
            5,
            expires_in=10,
            memo="GPU job",
            reference="job-42",
            invoice_id="invoice-42",
            now=100,
        )
        self.assertEqual(request.memo, "GPU job")
        self.assertEqual(request.reference, "job-42")
        self.assertEqual(request.invoice_id, "invoice-42")

    def test_float_amount_is_rejected(self):
        with self.assertRaisesRegex(InputError, "integer"):
            create_payment_request(ADDRESS, 1.0, expires_in=60, now=0)

    def test_bool_amount_is_rejected(self):
        with self.assertRaisesRegex(InputError, "integer"):
            create_payment_request(ADDRESS, True, expires_in=60, now=0)

    def test_string_amount_is_rejected(self):
        with self.assertRaisesRegex(InputError, "integer"):
            create_payment_request(ADDRESS, "1", expires_in=60, now=0)

    def test_none_amount_is_rejected(self):
        with self.assertRaisesRegex(InputError, "integer"):
            create_payment_request(ADDRESS, None, expires_in=60, now=0)

    def test_zero_amount_is_rejected(self):
        with self.assertRaisesRegex(InputError, "greater than zero"):
            create_payment_request(ADDRESS, 0, expires_in=60, now=0)

    def test_expiry_is_derived_without_mutating_pending_request(self):
        request = create_payment_request(ADDRESS, 1, expires_in=10, now=100)
        self.assertIs(request.effective_state(now=109), PaymentRequestState.PENDING)
        self.assertIs(request.effective_state(now=110), PaymentRequestState.EXPIRED)
        self.assertIs(request.state, PaymentRequestState.PENDING)

    def test_mark_paid_returns_paid_copy(self):
        request = create_payment_request(ADDRESS, 1, expires_in=10, now=100)
        paid = request.mark_paid(now=109)
        self.assertIs(paid.state, PaymentRequestState.PAID)
        self.assertIs(request.state, PaymentRequestState.PENDING)

    def test_expired_request_cannot_be_marked_paid(self):
        request = create_payment_request(ADDRESS, 1, expires_in=10, now=100)
        with self.assertRaisesRegex(InputError, "Expired"):
            request.mark_paid(now=110)

    def test_paid_request_cannot_be_expired(self):
        request = create_payment_request(ADDRESS, 1, expires_in=10, now=100).mark_paid(now=101)
        with self.assertRaisesRegex(InputError, "Paid"):
            request.expire(now=110)

    def test_expire_requires_elapsed_expiry(self):
        request = create_payment_request(ADDRESS, 1, expires_in=10, now=100)
        with self.assertRaisesRegex(InputError, "not reached"):
            request.expire(now=109)
        expired = request.expire(now=110)
        self.assertIs(expired.state, PaymentRequestState.EXPIRED)

    def test_serialization_round_trip_is_stable(self):
        request = create_payment_request(
            ADDRESS,
            123,
            expires_in=60,
            memo="hello",
            reference="ref-1",
            invoice_id="invoice-1",
            now=1_000,
        )
        encoded = serialize_payment_request(request)
        decoded = json.loads(encoded)
        self.assertEqual(decoded["type"], PAYMENT_REQUEST_TYPE)
        self.assertEqual(decoded["version"], PAYMENT_REQUEST_VERSION)
        self.assertEqual(decoded["amount_atomic"], 123)
        self.assertEqual(parse_payment_request(encoded), request)
        self.assertEqual(serialize_payment_request(parse_payment_request(encoded)), encoded)

    def test_parse_accepts_bytes_and_mapping(self):
        request = create_payment_request(ADDRESS, 9, expires_in=60, invoice_id="inv", now=1)
        encoded = serialize_payment_request(request)
        self.assertEqual(parse_payment_request(encoded.encode("utf-8")), request)
        self.assertEqual(parse_payment_request(json.loads(encoded)), request)

    def test_parse_rejects_unknown_state(self):
        request = create_payment_request(ADDRESS, 9, expires_in=60, invoice_id="inv", now=1)
        data = request.as_dict()
        data["state"] = "CANCELLED"
        with self.assertRaisesRegex(InputError, "PENDING, PAID, or EXPIRED"):
            parse_payment_request(data)

    def test_parse_rejects_invalid_expiry_order(self):
        request = create_payment_request(ADDRESS, 9, expires_in=60, invoice_id="inv", now=1)
        data = request.as_dict()
        data["expires_at"] = data["created_at"]
        with self.assertRaisesRegex(InputError, "later than"):
            parse_payment_request(data)

    def test_effective_state_can_be_serialized_without_mutating_request(self):
        request = create_payment_request(ADDRESS, 9, expires_in=10, invoice_id="inv", now=1)
        self.assertEqual(request.as_dict(resolve_expiry=True, now=11)["state"], "EXPIRED")
        self.assertIs(request.state, PaymentRequestState.PENDING)

    def test_verifier_protocol_is_small_and_runtime_checkable(self):
        verifier = DummyVerifier()
        self.assertIsInstance(verifier, PaymentRequestVerifier)
        request = create_payment_request(ADDRESS, 1, expires_in=60, now=0)
        result = verifier.verify(request)
        self.assertTrue(result.paid)
        self.assertEqual(result.txid, "a" * 64)


if __name__ == "__main__":
    unittest.main()
