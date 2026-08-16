import unittest

from myt_machine.amounts import UINT64_MAX, format_myt_amount, parse_myt_amount
from myt_machine.errors import InputError, RpcProtocolError


class AmountTests(unittest.TestCase):
    def test_valid_amounts_are_exact(self):
        cases = {
            "1": 1_000_000_000,
            "1.0": 1_000_000_000,
            "0.000000001": 1,
            "21.123456789": 21_123_456_789,
            "0": 0,
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(parse_myt_amount(value), expected)

    def test_format_is_fixed_precision(self):
        self.assertEqual(format_myt_amount(0), "0.000000000")
        self.assertEqual(format_myt_amount(1), "0.000000001")
        self.assertEqual(format_myt_amount(21_123_456_789), "21.123456789")
        self.assertEqual(format_myt_amount(UINT64_MAX), "18446744073.709551615")

    def test_uint64_boundary(self):
        self.assertEqual(parse_myt_amount("18446744073.709551615"), UINT64_MAX)
        with self.assertRaises(InputError):
            parse_myt_amount("18446744073.709551616")

    def test_positive_payment_rejects_zero(self):
        for value in ("0", "0.0", "0.000000000"):
            with self.subTest(value=value), self.assertRaises(InputError):
                parse_myt_amount(value, require_positive=True)

    def test_invalid_amounts_are_rejected(self):
        invalid = (
            "-1",
            "+1",
            "1.0000000000",
            "1e-9",
            "1E3",
            ".1",
            "1.",
            "01",
            " 1",
            "1 ",
            "",
            "NaN",
            "inf",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(InputError):
                parse_myt_amount(value)

    def test_non_string_input_is_rejected(self):
        for value in (1, 1.0, None, True):
            with self.subTest(value=value), self.assertRaises(InputError):
                parse_myt_amount(value)  # type: ignore[arg-type]

    def test_invalid_atomic_values_are_rejected(self):
        for value in (-1, UINT64_MAX + 1, 1.0, True):
            with self.subTest(value=value), self.assertRaises(RpcProtocolError):
                format_myt_amount(value)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
