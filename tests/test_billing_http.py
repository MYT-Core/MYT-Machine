import io
import json
import tempfile
import unittest
from pathlib import Path

from billing_fakes import ADDRESS, FakeBillingRpc, proof_for

from myt_machine.billing import BillingService
from myt_machine.billing_http import MAX_HTTP_BODY, BillingApplication
from myt_machine.errors import ConfigurationError, RpcTransportError
from myt_machine.invoice_store import SQLiteInvoiceStore
from myt_machine.invoice_verification import WalletPaymentVerifier


class BillingHttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.rpc = FakeBillingRpc()
        self.store = SQLiteInvoiceStore(
            Path(self.temp.name) / "invoices.sqlite", clock=lambda: 1000
        )
        self.service = BillingService(
            self.store,
            network="testnet",
            verifier=WalletPaymentVerifier(self.rpc, network="testnet"),
        )
        self.token = "must-not-appear_" * 3
        self.app = BillingApplication(self.service, token=self.token)

    def call(self, method="GET", path="/v1/invoices", data=None, raw=None, **overrides):
        encoded = (
            raw
            if raw is not None
            else json.dumps(data).encode()
            if data is not None
            else b""
        )
        env = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": "",
            "HTTP_AUTHORIZATION": "Bearer " + self.token,
            "CONTENT_TYPE": "application/json",
            "CONTENT_LENGTH": str(len(encoded)),
            "wsgi.input": io.BytesIO(encoded),
        }
        env.update(overrides)
        response = []
        content = b"".join(
            self.app(
                env, lambda status, headers: response.append((status, dict(headers)))
            )
        )
        self.assertNotIn(self.token.encode(), content)
        self.assertEqual(response[0][1]["Cache-Control"], "no-store")
        self.assertEqual(int(response[0][1]["Content-Length"]), len(content))
        return int(response[0][0].split()[0]), json.loads(content)

    def test_health(self):
        code, payload = self.call(path="/health", HTTP_AUTHORIZATION="")
        self.assertEqual(code, 200)
        self.assertEqual(payload["status"], "ok")

    def test_auth_required_on_invoice_routes(self):
        for token in ("", "Bearer wrong", "Bearer \u03bb", "x" * 1000):
            with self.subTest(length=len(token)):
                self.assertEqual(self.call(HTTP_AUTHORIZATION=token)[0], 401)

    def test_token_configuration_and_repr(self):
        self.assertNotIn(self.token, repr(self.app))
        for token in ("", "short", "x" * 257, "\u03bb" * 40):
            with self.subTest(length=len(token)), self.assertRaises(ConfigurationError):
                BillingApplication(self.service, token=token)

    def test_create_get_list_status_verify(self):
        code, payload = self.call(
            "POST", data={"recipient_address": ADDRESS, "amount_atomic": 100000000}
        )
        self.assertEqual(code, 200)
        invoice_id = payload["invoice"]["request"]["invoice_id"]
        route = "/v1/invoices/" + invoice_id
        self.assertEqual(self.call(path=route)[1]["invoice"]["state"], "PENDING")
        self.assertEqual(len(self.call()[1]["invoices"]), 1)
        self.assertEqual(self.call(path=route + "/status")[1]["state"], "PENDING")
        request = self.service.get_invoice(invoice_id).request
        result = self.call("POST", route + "/verify", {"proof": proof_for(request)})
        self.assertEqual(result[0], 200)
        self.assertTrue(result[1]["paid"])
        self.assertEqual(self.call(path=route + "/status")[1]["state"], "PAID")

    def test_idempotency_header(self):
        data = {"recipient_address": ADDRESS, "amount_atomic": 1}
        first = self.call("POST", data=data, HTTP_IDEMPOTENCY_KEY="same")
        second = self.call("POST", data=data, HTTP_IDEMPOTENCY_KEY="same")
        self.assertEqual(first, second)
        data["amount_atomic"] = 2
        self.assertEqual(
            self.call("POST", data=data, HTTP_IDEMPOTENCY_KEY="same")[0], 409
        )

    def test_reject_unknown_fields_and_spend_terms(self):
        for field in ("state", "paid", "seed", "private_key", "network", "txid"):
            data = {
                "recipient_address": ADDRESS,
                "amount_atomic": 1,
                field: "must-not-appear",
            }
            with self.subTest(field=field):
                code, payload = self.call("POST", data=data)
                self.assertEqual(code, 400)
                self.assertNotIn("must-not-appear", json.dumps(payload))

    def test_bad_amounts(self):
        for value in (0, -1, True, 1.0, "1", (1 << 64)):
            with self.subTest(value=value):
                self.assertEqual(
                    self.call(
                        "POST",
                        data={"recipient_address": ADDRESS, "amount_atomic": value},
                    )[0],
                    400,
                )

    def test_malformed_utf8_json_duplicates_and_depth(self):
        for raw in (
            b"\xff",
            b"{",
            b"[]",
            b"null",
            b'{"amount_atomic":1,"amount_atomic":2}',
            b"[" * 2000 + b"]" * 2000,
        ):
            with self.subTest(length=len(raw)):
                self.assertEqual(self.call("POST", raw=raw)[0], 400)

    def test_oversized_body(self):
        code, _ = self.call("POST", raw=b"x" * (MAX_HTTP_BODY + 1))
        self.assertEqual(code, 413)

    def test_missing_and_bad_length(self):
        self.assertEqual(self.call("POST", CONTENT_LENGTH="")[0], 411)
        for value in ("-1", "x", "1.0", "1" * 100):
            self.assertEqual(self.call("POST", CONTENT_LENGTH=value)[0], 400)

    def test_incomplete_body_and_chunked_input(self):
        self.assertEqual(self.call("POST", CONTENT_LENGTH="3")[0], 400)
        self.assertEqual(self.call("POST", HTTP_TRANSFER_ENCODING="chunked")[0], 400)

    def test_content_type(self):
        self.assertEqual(self.call("POST", CONTENT_TYPE="text/plain")[0], 415)

    def test_pagination(self):
        for i in range(3):
            self.service.create_invoice(ADDRESS, 1, invoice_id=f"invoice-{i}")
        code, payload = self.call(QUERY_STRING="limit=2")
        self.assertEqual(code, 200)
        self.assertEqual(len(payload["invoices"]), 2)
        second = self.call(QUERY_STRING="limit=2&after=" + payload["next_after"])[1]
        self.assertEqual(len(second["invoices"]), 1)

    def test_bad_pagination(self):
        for query in (
            "limit=0",
            "limit=101",
            "limit=true",
            "limit=1&limit=2",
            "x=y",
            "after=../x",
            "x" * 600,
        ):
            with self.subTest(query=query[:50]):
                self.assertEqual(self.call(QUERY_STRING=query)[0], 400)

    def test_missing_invoice(self):
        self.assertEqual(self.call(path="/v1/invoices/missing")[0], 404)

    def test_no_spending_or_wallet_endpoints(self):
        for path in (
            "/transfer",
            "/wallet-rpc",
            "/v1/pay",
            "/v1/invoices/x/pay",
            "/v1/invoices/x/mark-paid",
        ):
            self.assertIn(self.call("POST", path, {})[0], (404, 405))
        self.assertEqual(self.rpc.calls, [])

    def test_verification_exact_body(self):
        record = self.service.create_invoice(ADDRESS, 1)
        path = "/v1/invoices/" + record.request.invoice_id + "/verify"
        self.assertEqual(self.call("POST", path, {"paid": True})[0], 400)

    def test_timeout_error_redacted_and_invoice_pending(self):
        record = self.service.create_invoice(ADDRESS, 100000000)
        self.rpc.failure = RpcTransportError("must-not-appear")
        path = "/v1/invoices/" + record.request.invoice_id + "/verify"
        code, payload = self.call("POST", path, {"proof": proof_for(record.request)})
        self.assertEqual(code, 502)
        self.assertNotIn("must-not-appear", json.dumps(payload))
        self.assertEqual(
            self.service.invoice_status(record.request.invoice_id).value, "PENDING"
        )

    def test_unexpected_exceptions_redacted(self):
        original = self.service.list_invoices

        def fail(**kwargs):
            raise RuntimeError("must-not-appear")

        self.service.list_invoices = fail
        self.addCleanup(setattr, self.service, "list_invoices", original)
        code, payload = self.call()
        self.assertEqual(code, 500)
        self.assertNotIn("must-not-appear", json.dumps(payload))
