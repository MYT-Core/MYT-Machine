import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from billing_fakes import ADDRESS, TXID, FakeBillingRpc, proof_for

from myt_machine.cli import main
from myt_machine.payment_requests import (
    create_payment_request,
    serialize_payment_request,
)


class BillingCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.db = self.path / "billing.sqlite"
        self.rpc = FakeBillingRpc()
        self.request = create_payment_request(ADDRESS, 100000000, network="testnet")
        self.request_file = self.path / "request.json"
        self.request_file.write_text(
            serialize_payment_request(self.request), encoding="utf-8"
        )

    def call(self, arguments, *, stdin="", environ=None, offline=False):
        stream = io.StringIO()

        def factory(config):
            if offline:
                raise AssertionError("Offline operation attempted RPC configuration")
            return self.rpc

        code = main(
            arguments,
            environ={} if environ is None else environ,
            stdin=io.StringIO(stdin),
            stdout=stream,
            client_factory=factory,
        )
        text = stream.getvalue()
        self.assertEqual(len(text.splitlines()), 1)
        return code, json.loads(text)

    def create(self, *extra):
        return self.call(
            [
                "invoice",
                "create",
                "--db",
                str(self.db),
                "--network",
                "testnet",
                "--address",
                ADDRESS,
                "--amount",
                "0.1",
                *extra,
            ]
        )

    def test_offline_request_create_with_invalid_rpc_environment(self):
        code, data = self.call(
            [
                "payment-request",
                "create",
                "--network",
                "testnet",
                "--address",
                ADDRESS,
                "--amount",
                "0.1",
            ],
            environ={"MYT_WALLET_RPC_URL": "ftp://invalid"},
            offline=True,
        )
        self.assertEqual(code, 0)
        self.assertEqual(data["command"], "payment-request-create")
        self.assertFalse(data["address_validated"])
        self.assertEqual(data["request"]["amount_atomic"], 100000000)

    def test_request_show_file_and_stdin(self):
        for path, stdin in (
            (str(self.request_file), ""),
            ("-", serialize_payment_request(self.request)),
        ):
            code, data = self.call(
                ["payment-request", "show", "--request-file", path],
                stdin=stdin,
                offline=True,
            )
            self.assertEqual(code, 0)
            self.assertEqual(data["request"], self.request.as_dict())

    def test_request_verify(self):
        code, data = self.call(
            [
                "payment-request",
                "verify",
                "--request-file",
                str(self.request_file),
                "--network",
                "testnet",
            ]
        )
        self.assertEqual(code, 0)
        self.assertTrue(data["valid"])
        self.assertFalse(data["issuer_authenticated"])

    def test_request_wrong_expected_network_without_rpc(self):
        code, data = self.call(
            [
                "payment-request",
                "verify",
                "--request-file",
                str(self.request_file),
                "--network",
                "stagenet",
            ],
            offline=True,
        )
        self.assertEqual(code, 1)
        self.assertFalse(data["network_matches"])

    def test_request_expired(self):
        expired = create_payment_request(ADDRESS, 1, network="testnet", now=1)
        self.request_file.write_text(serialize_payment_request(expired))
        code, data = self.call(
            [
                "payment-request",
                "verify",
                "--request-file",
                str(self.request_file),
                "--network",
                "testnet",
            ]
        )
        self.assertEqual(code, 1)
        self.assertFalse(data["payable"])

    def test_request_file_no_overwrite(self):
        original = self.request_file.read_bytes()
        code, _ = self.call(
            [
                "payment-request",
                "create",
                "--network",
                "testnet",
                "--address",
                ADDRESS,
                "--amount",
                "1",
                "--request-file",
                str(self.request_file),
            ]
        )
        self.assertEqual(code, 3)
        self.assertEqual(self.request_file.read_bytes(), original)

    def test_request_file_created_privately(self):
        path = self.path / "new.json"
        code, _ = self.call(
            [
                "payment-request",
                "create",
                "--network",
                "testnet",
                "--address",
                ADDRESS,
                "--amount-atomic",
                "1",
                "--request-file",
                str(path),
            ]
        )
        self.assertEqual(code, 0)
        if os.name != "nt":
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_decimal_and_atomic_limits(self):
        base = [
            "payment-request",
            "create",
            "--network",
            "testnet",
            "--address",
            ADDRESS,
        ]
        for amount in ("1", str((1 << 64) - 1)):
            self.assertEqual(self.call([*base, "--amount-atomic", amount])[0], 0)
        for amount in ("0", "-1", "true", "1.0", "1e2", str(1 << 64), "9" * 5000):
            self.assertEqual(self.call([*base, "--amount-atomic", amount])[0], 2)
        for amount in ("0", "-1", "1e0", "1.1234567890", "9" * 5000):
            self.assertEqual(self.call([*base, "--amount", amount])[0], 2)

    def test_invoice_create_get_list_status(self):
        code, data = self.create()
        self.assertEqual(code, 0)
        invoice_id = data["invoice"]["request"]["invoice_id"]
        for action in ("get", "status", "list"):
            args = ["invoice", action, "--db", str(self.db), "--network", "testnet"]
            if action != "list":
                args += ["--invoice-id", invoice_id]
            result = self.call(
                args, environ={"MYT_WALLET_RPC_URL": "ftp://invalid"}, offline=True
            )
            self.assertEqual(result[0], 0)
            self.assertEqual(result[1]["command"], "invoice-" + action)

    def test_invoice_verify_from_stdin(self):
        _, data = self.create()
        from myt_machine import parse_payment_request

        request = parse_payment_request(data["invoice"]["request"])
        code, result = self.call(
            [
                "invoice",
                "verify",
                "--db",
                str(self.db),
                "--network",
                "testnet",
                "--invoice-id",
                request.invoice_id,
                "--proof-file",
                "-",
            ],
            stdin=json.dumps(proof_for(request)),
        )
        self.assertEqual(code, 0)
        self.assertTrue(result["paid"])
        self.assertEqual(result["invoice"]["txid"], TXID)

    def test_invoice_negative_proof_returns_one(self):
        _, data = self.create()
        from myt_machine import parse_payment_request

        request = parse_payment_request(data["invoice"]["request"])
        self.rpc.response["good"] = False
        code, result = self.call(
            [
                "invoice",
                "verify",
                "--db",
                str(self.db),
                "--network",
                "testnet",
                "--invoice-id",
                request.invoice_id,
                "--proof-file",
                "-",
            ],
            stdin=json.dumps(proof_for(request)),
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["invoice"]["state"], "PENDING")

    def test_idempotent_invoice_cli(self):
        first = self.create("--idempotency-key", "same")
        second = self.create("--idempotency-key", "same")
        self.assertEqual(first, second)

    def test_invoice_expire_command(self):
        self.create()
        code, result = self.call(
            ["invoice", "expire", "--db", str(self.db), "--network", "testnet"],
            offline=True,
        )
        self.assertEqual(code, 0)
        self.assertEqual(result["expired_count"], 0)

    def test_read_typo_does_not_create_database(self):
        code, _ = self.call(
            ["invoice", "list", "--db", str(self.db), "--network", "testnet"]
        )
        self.assertEqual(code, 3)
        self.assertFalse(self.db.exists())

    def test_rpc_configuration_errors_are_structured(self):
        code, data = self.call(
            [
                "--rpc-url",
                "ftp://invalid",
                "invoice",
                "create",
                "--db",
                str(self.db),
                "--network",
                "testnet",
                "--address",
                ADDRESS,
                "--amount",
                "1",
            ]
        )
        self.assertEqual(code, 3)
        self.assertEqual(data["command"], "invoice-create")

    def test_malformed_artifacts_and_secret_redaction(self):
        for content in (
            '{"must-not-appear":"private"}',
            '{"x":1,"x":2}',
            "[" * 2000,
            "x" * 9000,
        ):
            code, data = self.call(
                ["payment-request", "show", "--request-file", "-"], stdin=content
            )
            self.assertEqual(code, 2)
            self.assertNotIn("must-not-appear", json.dumps(data))

    def test_invalid_cli_does_not_echo_secret_values(self):
        code, data = self.call(["invoice", "create", "--secret", "must-not-appear"])
        self.assertEqual(code, 2)
        self.assertNotIn("must-not-appear", json.dumps(data))

    def test_wrong_network_cannot_get_invoice(self):
        _, data = self.create()
        code, _ = self.call(
            [
                "invoice",
                "get",
                "--db",
                str(self.db),
                "--network",
                "stagenet",
                "--invoice-id",
                data["invoice"]["request"]["invoice_id"],
            ]
        )
        self.assertEqual(code, 3)
