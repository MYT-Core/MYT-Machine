"""Official unittest coverage, adapting and extending fallacyofall's PR #1."""

import dataclasses
import json
import unittest
from pathlib import Path

from billing_fakes import ADDRESS, MAIN_ADDRESS

from myt_machine.amounts import UINT64_MAX
from myt_machine.errors import InputError
from myt_machine.payment_requests import (
    MAX_REQUEST_BYTES,
    MAX_TIMESTAMP,
    PaymentRequest,
    create_payment_request,
    parse_payment_request,
    serialize_payment_request,
    strict_json,
)


class PaymentRequestTests(unittest.TestCase):
    def test_published_deterministic_vector(self):
        vector = json.loads((Path(__file__).parents[1] / "docs" / "payment-request-v1-test-vector.json").read_text())
        request = parse_payment_request(vector["request"])
        self.assertEqual(request.canonical_content.hex(), vector["canonical_hex"])
        self.assertEqual(request.canonical_content.decode("ascii"), vector["canonical_ascii"])
        self.assertEqual(request.proof_message, vector["proof_message"])

    def request(self, **changes):
        values = {
            "recipient_address": ADDRESS,
            "amount_atomic": 100000000,
            "network": "testnet",
            "now": 1000,
            "expires_in": 3600,
            "invoice_id": "invoice-1",
        }
        values.update(changes)
        return create_payment_request(**values)

    def test_create_exact_amount(self):
        self.assertEqual(self.request().amount_atomic, 100000000)

    def test_uuid_ids_are_distinct(self):
        self.assertNotEqual(
            self.request(invoice_id=None).invoice_id,
            self.request(invoice_id=None).invoice_id,
        )

    def test_constructor_validates(self):
        data = dataclasses.asdict(self.request())
        data["amount_atomic"] = -1
        with self.assertRaises(InputError):
            PaymentRequest(**data)

    def test_immutable(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.request().amount_atomic = 1

    def test_no_state_import(self):
        data = self.request().as_dict()
        data["state"] = "PAID"
        with self.assertRaises(InputError):
            parse_payment_request(data)

    def test_roundtrip_text_bytes_mapping(self):
        request = self.request(memo="hello", reference="job-42")
        for value in (
            serialize_payment_request(request),
            request.canonical_content,
            request.as_dict(),
        ):
            with self.subTest(value_type=type(value)):
                self.assertEqual(parse_payment_request(value), request)

    def test_canonical_serialization(self):
        encoded = serialize_payment_request(self.request())
        self.assertEqual(
            encoded,
            json.dumps(json.loads(encoded), sort_keys=True, separators=(",", ":")),
        )
        self.assertEqual(
            serialize_payment_request(parse_payment_request(encoded)), encoded
        )

    def test_reordered_input_canonicalized(self):
        data = dict(reversed(list(self.request().as_dict().items())))
        self.assertEqual(
            parse_payment_request(data).canonical_content,
            self.request().canonical_content,
        )

    def test_positive_uint64_boundaries(self):
        for value in (1, UINT64_MAX):
            self.assertEqual(self.request(amount_atomic=value).amount_atomic, value)

    def test_reject_amounts(self):
        for value in (0, -1, True, False, 1.0, "1", "1e9", None, UINT64_MAX + 1):
            with self.subTest(value=value), self.assertRaises(InputError):
                self.request(amount_atomic=value)

    def test_reject_invalid_networks(self):
        for value in (None, True, [], "", "TESTNET", "testnet ", "regtest"):
            with self.subTest(value=value), self.assertRaises(InputError):
                self.request(network=value)

    def test_mainnet_and_stagenet_syntax(self):
        self.assertEqual(
            self.request(network="mainnet", recipient_address=MAIN_ADDRESS).network,
            "mainnet",
        )
        self.assertEqual(self.request(network="stagenet").network, "stagenet")

    def test_reject_malformed_addresses(self):
        for value in (
            "MYT_TEST_ADDRESS_123",
            "",
            "B" * 98,
            "0" * 97,
            "O" * 97,
            "l" * 97,
            " " + ADDRESS[1:],
            "\u200b" + ADDRESS[1:],
            None,
        ):
            with self.subTest(value=value), self.assertRaises(InputError):
                self.request(recipient_address=value)

    def test_integrated_address_length_rejected(self):
        with self.assertRaises(InputError):
            self.request(recipient_address="B" * 108)

    def test_invalid_ids(self):
        for value in (
            "",
            False,
            0,
            "x" * 129,
            "../x",
            "a b",
            "a\x00",
            "a\u202e",
            "a/b",
        ):
            with self.subTest(value=value), self.assertRaises(InputError):
                self.request(invoice_id=value)

    def test_unicode_text_roundtrip(self):
        request = self.request(memo="Caf\u00e9 \u65e5\u672c", reference="\u03bb")
        self.assertTrue(serialize_payment_request(request).isascii())
        self.assertEqual(
            parse_payment_request(serialize_payment_request(request)), request
        )

    def test_reject_controls_and_noncanonical_unicode(self):
        for value in ("bad\x00", "bad\n", "x\u202e", "e\u0301", "\ud800", "\x7f"):
            with self.subTest(value=repr(value)), self.assertRaises(InputError):
                self.request(memo=value)

    def test_string_byte_limits(self):
        self.request(memo="x" * 1024, reference="x" * 256)
        for changes in (
            {"memo": "x" * 1025},
            {"reference": "x" * 257},
            {"memo": "\u65e5" * 400},
        ):
            with self.subTest(changes=changes), self.assertRaises(InputError):
                self.request(**changes)

    def test_wrong_type_version(self):
        for field, value in (
            ("type", "myt-payment-proof"),
            ("version", 2),
            ("version", True),
            ("version", 1.0),
        ):
            data = {**self.request().as_dict(), field: value}
            with self.subTest(field=field, value=value), self.assertRaises(InputError):
                parse_payment_request(data)

    def test_unknown_and_missing_fields(self):
        data = self.request().as_dict()
        for field in data:
            with self.subTest(field=field), self.assertRaises(InputError):
                parse_payment_request({k: v for k, v in data.items() if k != field})
        with self.assertRaises(InputError):
            parse_payment_request({**data, "extra": 1})

    def test_duplicate_keys(self):
        text = serialize_payment_request(self.request())
        with self.assertRaises(InputError):
            parse_payment_request(text[:-1] + ',"amount_atomic":1}')

    def test_malformed_json_and_utf8(self):
        for value in (
            b"\xff",
            b"\xef\xbb\xbf{}",
            "{",
            "[]",
            "null",
            "true",
            "",
            "\ud800",
        ):
            with self.subTest(value=repr(value)), self.assertRaises(InputError):
                parse_payment_request(value)

    def test_float_exponent_and_nan(self):
        for value in ("1.0", "1e0", "NaN", "Infinity", "-Infinity"):
            text = serialize_payment_request(self.request()).replace(
                '"version":1', '"version":' + value
            )
            with self.subTest(value=value), self.assertRaises(InputError):
                parse_payment_request(text)

    def test_huge_and_deep_json(self):
        for value in (
            b"x" * (MAX_REQUEST_BYTES + 1),
            "[" * 2000 + "]" * 2000,
            '{"x":' + "9" * 5000 + "}",
        ):
            with self.subTest(size=len(value)), self.assertRaises(InputError):
                parse_payment_request(value)

    def test_timestamp_bounds(self):
        for value in (-1, True, 1.5, MAX_TIMESTAMP + 1):
            with self.subTest(value=value), self.assertRaises(InputError):
                self.request(now=value)

    def test_lifetime_bounds(self):
        for value in (0, -1, True, 1.5, 2592001):
            with self.subTest(value=value), self.assertRaises(InputError):
                self.request(expires_in=value)

    def test_expiry_overflow_and_order(self):
        with self.assertRaises(InputError):
            self.request(now=MAX_TIMESTAMP, expires_in=1)
        with self.assertRaises(InputError):
            dataclasses.replace(self.request(), expires_at=1000)

    def test_optional_nulls_explicit(self):
        self.assertIsNone(self.request().as_dict()["memo"])
        self.assertIsNone(self.request().as_dict()["reference"])

    def test_proof_message_changes_with_every_term(self):
        request = self.request()
        for changes in (
            {"invoice_id": "other"},
            {"network": "stagenet"},
            {"amount_atomic": 1},
            {"memo": "memo"},
            {"reference": "ref"},
            {"created_at": 999},
            {"expires_at": 4601},
            {"recipient_address": "B" + "D" * 96},
        ):
            with self.subTest(changes=changes):
                self.assertNotEqual(
                    dataclasses.replace(request, **changes).proof_message,
                    request.proof_message,
                )

    def test_no_proof_or_payment_state_serialized(self):
        self.assertTrue(
            {"state", "txid", "proof", "paid"}.isdisjoint(self.request().as_dict())
        )

    def test_json_duplicate_nested_rejected(self):
        with self.assertRaises(InputError):
            strict_json('{"a":{"b":1,"b":2}}')

    def test_json_does_not_echo_unknown_keys(self):
        with self.assertRaises(InputError) as caught:
            parse_payment_request({"must-not-appear": "value"})
        self.assertNotIn("must-not-appear", str(caught.exception))
