"""v0.5.1 regressions: synthetic diagnostics and disposable local evidence only."""

import dataclasses
import importlib.metadata
import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stderr
from pathlib import Path
from unittest.mock import patch

from billing_fakes import ADDRESS, OTHER_ADDRESS, TXID, proof_for
from reputation_fakes import OTHER, SUBJECT, ReputationRpc, attest, binding_for
from test_cli import StubClient, valid_address_response

from myt_machine import __version__
from myt_machine.billing import BillingService
from myt_machine.billing_http import BillingApplication
from myt_machine.cli import main
from myt_machine.errors import InputError, RpcTransportError, WalletRpcError
from myt_machine.invoice_store import SQLiteInvoiceStore
from myt_machine.invoice_verification import WalletPaymentVerifier
from myt_machine.reputation_settlement import record_verified_settlement
from myt_machine.reputation_store import ReputationStore
from myt_machine.rpc import RpcConfig, WalletRpcClient

SENTINEL = "EXTERNAL-REVIEW-" + "MUST-NOT-LEAK"


class HardeningFixture(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.db = self.root / "reputation.sqlite"
        self.invoice_db = self.root / "invoices.sqlite"
        self.rpc = ReputationRpc()
        self.invoices = SQLiteInvoiceStore(self.invoice_db)
        self.billing = BillingService(
            self.invoices, network="testnet",
            verifier=WalletPaymentVerifier(self.rpc, network="testnet"),
        )
        record = self.billing.create_invoice(ADDRESS, 100000000, invoice_id="hardening")
        self.proof = proof_for(record.request)
        self.billing.verify_invoice("hardening", self.proof)
        self.binding = binding_for()
        self.binding_file = self.root / "binding.json"
        self.proof_file = self.root / "proof.json"
        self.write_json(self.binding_file, self.binding.as_dict())
        self.write_json(self.proof_file, self.proof)
        self.rpc.calls.clear()

    @staticmethod
    def write_json(path, value):
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(0o600)

    def arguments(self, **changes):
        options = {
            "network": "testnet", "db": self.db, "invoice-db": self.invoice_db,
            "invoice-id": "hardening", "binding-file": self.binding_file,
            "proof-file": self.proof_file, "expected-machine-id": SUBJECT.machine_id,
        }
        options.update(changes)
        return ["reputation", "record-settlement", *[
            item for key, value in options.items() for item in ("--" + key, str(value))
        ]]

    def invoke(self, arguments, client=None):
        output, stderr = io.StringIO(), io.StringIO()
        with redirect_stderr(stderr):
            code = main(
                arguments, environ={}, stdin=io.StringIO(), stdout=output,
                client_factory=lambda _: self.rpc if client is None else client,
            )
        self.assertEqual(stderr.getvalue(), "")
        text = output.getvalue()
        self.assertEqual(len(text.splitlines()), 1)
        self.assertNotIn("Traceback", text)
        self.assertNotIn(SENTINEL, text)
        return code, json.loads(text)

    def service(self, **changes):
        values = {"network": "testnet", "invoice_id": "hardening", "binding": self.binding,
                  "proof": self.proof, "expected_machine_id": SUBJECT.machine_id}
        values.update(changes)
        return record_verified_settlement(self.db, self.invoices, self.rpc, **values)


class DiagnosticHardeningTests(HardeningFixture):
    def assert_diagnostic(self, result, rpc_code):
        code, data = result
        self.assertEqual(code, 5)
        self.assertFalse(data["success"])
        self.assertEqual(data["error"], {
            "code": "wallet_rpc_error", "message": "Wallet RPC rejected the request",
            "rpc_code": rpc_code, "rpc_message": "Wallet RPC application error",
        })

    def test_all_wallet_command_error_boundaries(self):
        commands = [
            (["status"], "get_version"), (["address"], "get_address"),
            (["balance"], "get_balance"),
            (["pay", "--address", ADDRESS, "--amount", "1"], "validate_address"),
            (["payment-status", "--txid", TXID], "get_transfer_by_txid"),
            (["prove-payment", "--txid", TXID, "--address", ADDRESS], "get_tx_proof"),
            (["verify-payment", "--proof-file", str(self.proof_file)], "validate_address"),
            (["sign-message", "--message", "example"], "get_address"),
            (["verify-message", "--message", "example", "--address", ADDRESS,
              "--signature", "SigV2" + "1" * 88], "verify"),
        ]
        for args, method in commands:
            with self.subTest(command=args[0]):
                client = StubClient({method: [WalletRpcError(-99, SENTINEL)]})
                # Proof generation also validates the destination first.
                client.responses.setdefault("validate_address", [valid_address_response()])
                self.assert_diagnostic(self.invoke(args, client), -99)
                self.assertEqual(sum(c[0] == method for c in client.calls), 1)

    def test_transfer_error_not_retried(self):
        client = StubClient({"validate_address": [valid_address_response()],
                             "transfer": [WalletRpcError(91, SENTINEL)]})
        self.assert_diagnostic(self.invoke(
            ["pay", "--address", ADDRESS, "--amount", "1"], client), 91)
        self.assertEqual(sum(c[0] == "transfer" for c in client.calls), 1)

    def test_binding_verify_native_error(self):
        original = self.rpc.call
        def call(method, params=None, **kwargs):
            if method == "verify":
                raise WalletRpcError(-99, SENTINEL)
            return original(method, params, **kwargs)
        with patch.object(self.rpc, "call", side_effect=call):
            self.assert_diagnostic(self.invoke([
                "binding", "verify", "--binding-file", str(self.binding_file)]), -99)

    def test_invoice_and_reputation_native_error(self):
        pending = self.billing.create_invoice(ADDRESS, 100000000, invoice_id="pending")
        pending_proof = self.root / "pending-proof.json"
        self.write_json(pending_proof, proof_for(pending.request))
        self.rpc.failure = WalletRpcError(-99, SENTINEL)
        for args in (
            ["invoice", "verify", "--db", str(self.invoice_db), "--network", "testnet",
             "--invoice-id", "pending", "--proof-file", str(pending_proof)],
            self.arguments(),
        ):
            with self.subTest(command=args[:2]):
                self.assert_diagnostic(self.invoke(args), -99)
        self.assertFalse(self.db.exists())

    def test_hostile_provider_strings_and_codes(self):
        payloads = [SENTINEL, SENTINEL + "\n\r\x1b[31m\x00", '{"secret":"' + SENTINEL + '"}',
                    SENTINEL + "\u202e\u200b\u00fc", SENTINEL + "X" * 100000]
        for text in payloads:
            for rpc_code in (-99, 0, 99, 2**40):
                with self.subTest(length=len(text), rpc_code=rpc_code):
                    self.assert_diagnostic(self.invoke(["balance"], StubClient({
                        "get_balance": [WalletRpcError(rpc_code, text)]})), rpc_code)

    def test_sdk_error_retains_original_diagnostics(self):
        error = WalletRpcError(-99, SENTINEL)
        self.assertEqual(error.rpc_message, SENTINEL)
        self.assertEqual(error.as_dict()["rpc_message"], SENTINEL)
        self.assertNotIn(SENTINEL, str(error))

    def test_http_boundary_remains_redacted(self):
        app = BillingApplication(self.billing, token="x" * 32)
        statuses = []
        with patch.object(app, "_dispatch", side_effect=WalletRpcError(33, SENTINEL)):
            raw = b"".join(app({}, lambda status, headers: statuses.append(status)))
        self.assertEqual(statuses, ["502 Bad Gateway"])
        self.assertNotIn(SENTINEL.encode(), raw)
        self.assertEqual(json.loads(raw)["error"], {"code": "wallet_rpc_error"})


LOCAL_FAILURES = (
    "missing_invoice", "invalid_invoice", "malformed_id", "unknown_id", "unpaid",
    "malformed_machine", "wrong_machine", "missing_binding", "malformed_binding",
    "binding_network", "binding_recipient", "binding_identity", "binding_signature",
    "missing_proof", "proof_json", "proof_schema", "proof_recipient", "proof_message",
    "proof_txid", "proof_encoding",
)
NATIVE_FAILURES = ("invalid_native", "invalid_wallet_signature", "rpc_error", "timeout")


class SettlementHardeningTests(HardeningFixture):
    def check_failure(self, scenario, existing):
        if existing:
            ReputationStore(self.db).import_artifact(attest(), network="testnet")
        before = self.db.read_bytes() if existing else None
        options = {}
        if scenario == "missing_invoice":
            options["invoice-db"] = self.root / "absent.sqlite"
        elif scenario == "invalid_invoice":
            invalid = self.root / "invalid.sqlite"
            invalid.write_bytes(b"not a sqlite database")
            invalid.chmod(0o600)
            options["invoice-db"] = invalid
        elif scenario in {"malformed_id", "unknown_id"}:
            options["invoice-id"] = "!invalid!" if scenario == "malformed_id" else "unknown"
        elif scenario == "unpaid":
            self.billing.create_invoice(ADDRESS, 100000000, invoice_id="unpaid")
            options["invoice-id"] = "unpaid"
            self.rpc.calls.clear()
        elif scenario in {"malformed_machine", "wrong_machine"}:
            options["expected-machine-id"] = (
                "invalid" if scenario == "malformed_machine" else OTHER.machine_id)
        elif scenario == "missing_binding":
            options["binding-file"] = self.root / "absent.json"
        elif scenario == "malformed_binding":
            self.write_json(self.binding_file, {"invalid": True})
        elif scenario.startswith("binding_"):
            value = {
                "binding_network": lambda: binding_for(network="stagenet"),
                "binding_recipient": lambda: binding_for(address=OTHER_ADDRESS),
                "binding_identity": lambda: binding_for(identity=OTHER),
                "binding_signature": lambda: dataclasses.replace(self.binding,
                    identity_signature=OTHER.sign(self.binding.canonical_content,
                        "myt-machine/address-binding/v1").signature),
            }[scenario]()
            self.write_json(self.binding_file, value.as_dict())
        elif scenario == "missing_proof":
            options["proof-file"] = self.root / "absent.json"
        elif scenario == "proof_json":
            self.proof_file.write_bytes(b"{")
        elif scenario.startswith("proof_"):
            change = {
                "proof_schema": {"extra": True}, "proof_recipient": {"address": OTHER_ADDRESS},
                "proof_message": {"message": "wrong-request"}, "proof_txid": {"txid": "cd" * 32},
                "proof_encoding": {"proof": "bad"},
            }[scenario]
            self.write_json(self.proof_file, {**self.proof, **change})
        elif scenario == "invalid_native":
            self.rpc.response["good"] = False
        elif scenario == "invalid_wallet_signature":
            self.rpc.binding_good = False
        elif scenario == "rpc_error":
            self.rpc.failure = WalletRpcError(-99, SENTINEL)
        elif scenario == "timeout":
            self.rpc.failure = RpcTransportError("Timed out", kind="timeout")
        else:
            self.fail("Unknown fixture case")
        code, data = self.invoke(self.arguments(**options))
        self.assertIn(code, (2, 3, 4, 5))
        self.assertFalse(data["success"])
        if existing:
            self.assertEqual(self.db.read_bytes(), before)
        else:
            self.assertFalse(self.db.exists())
        self.assertEqual(list(self.root.glob("reputation.sqlite-*")), [])
        if scenario in LOCAL_FAILURES:
            self.assertEqual(self.rpc.calls, [])
        self.assertTrue(all(not mutation and method in {
            "validate_address", "verify", "check_tx_proof"}
            for method, _, mutation in self.rpc.calls))

    def test_success_deferred_create_and_duplicate(self):
        self.assertFalse(self.db.exists())
        code, first = self.invoke(self.arguments())
        self.assertEqual(code, 0)
        self.assertTrue(first["inserted"])
        before = self.db.read_bytes()
        code, second = self.invoke(self.arguments())
        self.assertEqual(code, 0)
        self.assertFalse(second["inserted"])
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(first["evidence_digest"], second["evidence_digest"])

    def test_path_sdk_and_open_store_sdk_equivalent(self):
        first = self.service()
        opened = record_verified_settlement(
            ReputationStore(self.db), self.invoices, self.rpc, network="testnet",
            invoice_id="hardening", binding=self.binding, proof=self.proof,
            expected_machine_id=SUBJECT.machine_id)
        self.assertEqual(first["evidence_digest"], opened["evidence_digest"])
        self.assertFalse(opened["inserted"])

    def test_does_not_open_store_during_rpc(self):
        original = self.rpc.call
        def call(method, params=None, **kwargs):
            self.assertFalse(self.db.exists())
            return original(method, params, **kwargs)
        with patch.object(self.rpc, "call", side_effect=call):
            self.assertTrue(self.service()["inserted"])

    def test_changed_invoice_during_verification_rejected(self):
        def change_invoice():
            with closing(sqlite3.connect(self.invoice_db)) as db:
                db.execute("UPDATE invoices SET txid=?", ("cd" * 32,))
                db.commit()
        self.rpc.on_proof = change_invoice
        with self.assertRaises(InputError):
            self.service()
        self.assertFalse(self.db.exists())

    def test_rebinding_does_not_replace_existing_evidence(self):
        self.service()
        before = self.db.read_bytes()
        with self.assertRaises(InputError):
            self.service(binding=binding_for(identity=OTHER), expected_machine_id=OTHER.machine_id)
        self.assertEqual(self.db.read_bytes(), before)


def _failure_test(scenario, existing):
    def test(self):
        self.check_failure(scenario, existing)
    return test


for _scenario in LOCAL_FAILURES + NATIVE_FAILURES:
    for _existing in (False, True):
        setattr(SettlementHardeningTests,
                f"test_{_scenario}_{'existing' if _existing else 'new'}_database",
                _failure_test(_scenario, _existing))


class UserAgentHardeningTests(unittest.TestCase):
    def capture(self):
        requests = []
        class Response:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return None
            def read(self, amount=None):
                return b'{"jsonrpc":"2.0","id":"1","result":{}}'
        class Opener:
            def open(self, request, timeout=None):
                requests.append(request)
                return Response()
        client = WalletRpcClient(RpcConfig())
        client._opener = Opener()
        client.call("get_version")
        return requests[0].get_header("User-agent")

    def test_runtime_version_and_agent(self):
        self.assertEqual(__version__, "0.5.1")
        self.assertEqual(self.capture(), "myt-machine/" + __version__)

    def test_source_checkout_needs_no_distribution_metadata(self):
        with patch("importlib.metadata.version", side_effect=importlib.metadata.PackageNotFoundError):
            self.assertEqual(self.capture(), "myt-machine/0.5.1")

    def test_stale_installed_metadata_cannot_override_loaded_code(self):
        with patch("importlib.metadata.version", return_value="0.3.0"):
            self.assertEqual(self.capture(), "myt-machine/0.5.1")
