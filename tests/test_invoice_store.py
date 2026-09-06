import concurrent.futures
import dataclasses
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from billing_fakes import ADDRESS, TXID, FakeBillingRpc, proof_for

from myt_machine.billing import BillingService
from myt_machine.errors import ConfigurationError, InputError, RpcTransportError
from myt_machine.invoice_store import SQLiteInvoiceStore
from myt_machine.invoice_verification import PaymentObservation, WalletPaymentVerifier
from myt_machine.invoices import (
    InvoiceConflict,
    InvoiceNotFound,
    InvoiceNotPaid,
    InvoiceRecord,
    InvoiceState,
    InvoiceStorageError,
)
from myt_machine.payment_requests import create_payment_request


class InvoiceStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "invoices.sqlite"
        self.now = 1000
        self.store = SQLiteInvoiceStore(self.path, clock=lambda: self.now)
        self.rpc = FakeBillingRpc()
        self.billing = BillingService(
            self.store,
            network="testnet",
            verifier=WalletPaymentVerifier(self.rpc, network="testnet"),
        )

    def create(self, **kwargs):
        return self.billing.create_invoice(ADDRESS, 100000000, **kwargs)

    def paid(self):
        record = self.create()
        return self.billing.verify_invoice(
            record.request.invoice_id, proof_for(record.request)
        ).invoice

    def test_create_get_pending(self):
        record = self.create()
        self.assertIs(record.state, InvoiceState.PENDING)
        self.assertEqual(self.billing.get_invoice(record.request.invoice_id), record)

    def test_create_invalid_address_rejected(self):
        self.rpc.valid = False
        with self.assertRaises(InputError):
            self.create()
        self.assertEqual(self.billing.list_invoices(), [])

    def test_create_requires_native_validation(self):
        billing = BillingService(self.store, network="testnet")
        with self.assertRaises(ConfigurationError):
            billing.create_invoice(ADDRESS, 1)

    def test_same_idempotency_returns_original_after_clock_advances(self):
        original = self.create(idempotency_key="request-1")
        self.now += 30
        repeated = self.create(idempotency_key="request-1")
        self.assertEqual(original, repeated)
        self.assertEqual(len(self.billing.list_invoices()), 1)

    def test_different_params_same_key_conflict(self):
        self.create(idempotency_key="key")
        for changes in (
            {"memo": "changed"},
            {"reference": "changed"},
            {"expires_in": 20},
            {"required_confirmations": 20},
            {"invoice_id": "other"},
        ):
            with self.subTest(changes=changes), self.assertRaises(InvoiceConflict):
                self.create(idempotency_key="key", **changes)

    def test_duplicate_id(self):
        self.create(invoice_id="one")
        with self.assertRaises(InvoiceConflict):
            self.create(invoice_id="one")

    def test_idempotency_key_validation(self):
        for value in ("", "x" * 129, "../key", True):
            with self.subTest(value=value), self.assertRaises(InputError):
                self.create(idempotency_key=value)

    def test_restart_persistence(self):
        original = self.paid()
        reopened = SQLiteInvoiceStore(self.path, clock=lambda: self.now)
        self.assertEqual(reopened.get(original.request.invoice_id), original)

    def test_fresh_process_reads_durable_paid_record(self):
        record = self.paid()
        code = "import sys,json; from myt_machine import SQLiteInvoiceStore; print(json.dumps(SQLiteInvoiceStore(sys.argv[1]).get(sys.argv[2]).as_dict()))"
        result = subprocess.run(
            [sys.executable, "-c", code, str(self.path), record.request.invoice_id],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(json.loads(result.stdout)["state"], "PAID")

    def test_pending_to_paid(self):
        paid = self.paid()
        self.assertIs(paid.state, InvoiceState.PAID)
        self.assertEqual(paid.txid, TXID)
        self.assertEqual(paid.paid_at, 1000)
        self.assertEqual(paid.confirmations, 10)

    def test_expiry_boundary(self):
        record = self.create(expires_in=10)
        self.now = 1009
        self.assertIs(
            self.billing.invoice_status(record.request.invoice_id), InvoiceState.PENDING
        )
        self.now = 1010
        self.assertIs(
            self.billing.invoice_status(record.request.invoice_id), InvoiceState.EXPIRED
        )

    def test_expiry_persists_after_clock_rollback(self):
        record = self.create(expires_in=10)
        self.now = 1010
        self.store.expire()
        self.now = 1001
        self.assertIs(
            SQLiteInvoiceStore(self.path, clock=lambda: self.now)
            .get(record.request.invoice_id)
            .state,
            InvoiceState.EXPIRED,
        )

    def test_paid_never_expires(self):
        paid = self.paid()
        self.now = 100000
        self.store.expire()
        self.assertIs(
            self.billing.invoice_status(paid.request.invoice_id), InvoiceState.PAID
        )

    def test_expired_never_paid(self):
        record = self.create(expires_in=10)
        self.now = 1010
        result = self.billing.verify_invoice(
            record.request.invoice_id, proof_for(record.request)
        )
        self.assertFalse(result.paid)
        self.assertEqual(result.reason, "expired")
        self.assertEqual(sum(c[0] == "check_tx_proof" for c in self.rpc.calls), 0)

    def test_expiry_during_rpc_rechecked(self):
        record = self.create(expires_in=10)
        self.rpc.on_proof = lambda: setattr(self, "now", 1010)
        result = self.billing.verify_invoice(
            record.request.invoice_id, proof_for(record.request)
        )
        self.assertIs(result.invoice.state, InvoiceState.EXPIRED)
        self.assertIsNone(result.invoice.txid)

    def test_clock_rollback_before_creation_rejected(self):
        record = self.create()
        self.now = 999
        with self.assertRaises(InputError):
            self.billing.verify_invoice(
                record.request.invoice_id, proof_for(record.request)
            )
        self.now = 1000
        self.assertIs(
            self.billing.invoice_status(record.request.invoice_id), InvoiceState.PENDING
        )

    def test_underconfirmed_disappearing_then_reappearing_payment(self):
        record = self.create()
        self.rpc.response["confirmations"] = 9
        self.assertFalse(
            self.billing.verify_invoice(
                record.request.invoice_id, proof_for(record.request)
            ).paid
        )
        self.rpc.failure = RpcTransportError("disappeared")
        with self.assertRaises(RpcTransportError):
            self.billing.verify_invoice(
                record.request.invoice_id, proof_for(record.request)
            )
        self.assertIs(
            self.billing.invoice_status(record.request.invoice_id), InvoiceState.PENDING
        )
        self.rpc.failure = None
        self.rpc.response["confirmations"] = 10
        self.assertTrue(
            self.billing.verify_invoice(
                record.request.invoice_id, proof_for(record.request)
            ).paid
        )

    def test_no_partial_payment_accumulation(self):
        record = self.create()
        self.rpc.response["received"] = 50000000
        for txid in ("11" * 32, "22" * 32):
            self.assertFalse(
                self.billing.verify_invoice(
                    record.request.invoice_id, proof_for(record.request, txid)
                ).paid
            )

    def test_duplicate_transaction_constraint(self):
        first = self.paid()
        second = self.create()
        with self.assertRaises(InvoiceConflict):
            self.billing.verify_invoice(
                second.request.invoice_id, proof_for(second.request, first.txid)
            )
        self.assertIs(
            self.billing.invoice_status(second.request.invoice_id), InvoiceState.PENDING
        )

    def test_case_variant_txid_cannot_double_pay(self):
        self.paid()
        second = self.create()
        with self.assertRaises(InvoiceConflict):
            self.billing.verify_invoice(
                second.request.invoice_id, proof_for(second.request, TXID.upper())
            )

    def test_reused_proof_cannot_pay_different_invoice(self):
        first, second = self.create(), self.create()
        proof = proof_for(first.request)
        self.billing.verify_invoice(first.request.invoice_id, proof)
        self.assertFalse(
            self.billing.verify_invoice(second.request.invoice_id, proof).paid
        )

    def test_repeated_verification_same_invoice_is_idempotent(self):
        paid = self.paid()
        count = len(self.rpc.calls)
        result = self.billing.verify_invoice(
            paid.request.invoice_id, proof_for(paid.request)
        )
        self.assertEqual(result.invoice, paid)
        self.assertEqual(len(self.rpc.calls), count)

    def test_require_paid(self):
        pending = self.create()
        with self.assertRaises(InvoiceNotPaid):
            self.billing.require_paid(pending.request.invoice_id)
        paid = self.paid()
        self.assertEqual(self.billing.require_paid(paid.request.invoice_id), paid)

    def test_list_pagination_stable(self):
        for index in range(5):
            self.create(invoice_id=f"invoice-{index}")
        first = self.billing.list_invoices(limit=2)
        second = self.billing.list_invoices(limit=2, after=first[-1].request.invoice_id)
        self.assertEqual(
            [r.request.invoice_id for r in first + second],
            [f"invoice-{i}" for i in range(4)],
        )

    def test_bad_pagination_and_lookup(self):
        for limit in (0, 101, True, 1.0):
            with self.subTest(limit=limit), self.assertRaises(InputError):
                self.billing.list_invoices(limit=limit)
        with self.assertRaises(InvoiceNotFound):
            self.billing.get_invoice("missing")
        with self.assertRaises(InputError):
            self.billing.get_invoice("../path")

    def test_network_isolation(self):
        record = self.create()
        other = BillingService(self.store, network="stagenet")
        self.assertEqual(other.list_invoices(), [])
        with self.assertRaises(ConfigurationError):
            other.get_invoice(record.request.invoice_id)

    def test_uint64_stored_without_sqlite_overflow(self):
        value = (1 << 64) - 1
        record = self.billing.create_invoice(ADDRESS, value)
        self.rpc.response["received"] = value
        paid = self.billing.verify_invoice(
            record.request.invoice_id, proof_for(record.request)
        ).invoice
        self.assertEqual(
            self.store.get(record.request.invoice_id).received_atomic, value
        )
        self.assertEqual(paid.request.amount_atomic, value)

    def test_sql_memo_is_data(self):
        memo = "'; DROP TABLE invoices; --"
        record = self.create(memo=memo)
        self.assertEqual(self.store.get(record.request.invoice_id).request.memo, memo)
        self.assertEqual(len(self.billing.list_invoices()), 1)

    def test_forged_unverified_observation_rejected(self):
        record = self.create()
        for eligible in (False, "true", 1):
            observation = PaymentObservation(
                eligible, "x", TXID, record.request.proof_message, 100000000, 10
            )
            with self.subTest(eligible=eligible), self.assertRaises(InputError):
                self.store._finalize(record.request, observation)

    def test_wrong_evidence_request_rejected(self):
        record = self.create()
        observation = PaymentObservation(
            True, "confirmed", TXID, "another-request", 100000000, 10
        )
        with self.assertRaises(InputError):
            self.store._finalize(record.request, observation)

    def test_finalization_revalidates_amount_and_confirmations(self):
        record = self.create()
        for amount, confirmations in ((1, 10), (100000000, 9)):
            observation = PaymentObservation(
                True,
                "confirmed",
                TXID,
                record.request.proof_message,
                amount,
                confirmations,
            )
            with self.subTest(amount=amount), self.assertRaises(InputError):
                self.store._finalize(record.request, observation)

    def test_database_capacity(self):
        store = SQLiteInvoiceStore(self.path, max_invoices=1, clock=lambda: self.now)
        self.billing.store = store
        self.create(idempotency_key="same")
        self.create(idempotency_key="same")
        with self.assertRaises(InvoiceStorageError):
            self.create()

    def test_concurrent_idempotent_creation(self):
        def create(_):
            store = SQLiteInvoiceStore(self.path, clock=lambda: 1000)
            rpc = FakeBillingRpc()
            service = BillingService(
                store,
                network="testnet",
                verifier=WalletPaymentVerifier(rpc, network="testnet"),
            )
            return service.create_invoice(
                ADDRESS, 100000000, idempotency_key="concurrent"
            ).request.invoice_id

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            ids = list(pool.map(create, range(8)))
        self.assertEqual(len(set(ids)), 1)

    def test_concurrent_same_invoice_verification(self):
        record = self.create()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(
                pool.map(
                    lambda _: self.billing.verify_invoice(
                        record.request.invoice_id, proof_for(record.request)
                    ),
                    range(8),
                )
            )
        self.assertTrue(all(r.paid for r in results))
        self.assertEqual(len({r.invoice.txid for r in results}), 1)

    def test_concurrent_tx_reuse_only_one_invoice_paid(self):
        records = [self.create() for _ in range(8)]

        def verify(record):
            try:
                return self.billing.verify_invoice(
                    record.request.invoice_id, proof_for(record.request)
                ).paid
            except InvoiceConflict:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(verify, records))
        self.assertEqual(sum(results), 1)
        self.assertEqual(
            sum(r.state is InvoiceState.PAID for r in self.billing.list_invoices()), 1
        )

    def test_corrupted_database_data_fails_closed(self):
        record = self.paid()
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                "UPDATE invoices SET received_atomic='1' WHERE invoice_id=?",
                (record.request.invoice_id,),
            )
        with self.assertRaises(InvoiceStorageError):
            self.billing.require_paid(record.request.invoice_id)

    def test_corrupted_artifact_fails_closed(self):
        record = self.create()
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                "UPDATE invoices SET request=? WHERE invoice_id=?",
                ('{"state":"PAID"}', record.request.invoice_id),
            )
        with self.assertRaises(InvoiceStorageError):
            self.store.get(record.request.invoice_id)

    def test_unrecognized_schema_rejected(self):
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("PRAGMA user_version=99")
        with self.assertRaises(InvoiceStorageError):
            SQLiteInvoiceStore(self.path)

    def test_invalid_database_bytes_redacted(self):
        path = Path(self.temp.name) / "broken.sqlite"
        path.write_bytes(b"must-not-appear")
        path.chmod(0o600)
        with self.assertRaises(InvoiceStorageError) as caught:
            SQLiteInvoiceStore(path)
        self.assertNotIn("must-not-appear", str(caught.exception))

    @unittest.skipIf(os.name == "nt", "Unix permissions")
    def test_private_database_permissions(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.path.chmod(0o644)
        with self.assertRaises(ConfigurationError):
            self.store.get("missing")

    @unittest.skipIf(os.name == "nt", "Unix symlink setup")
    def test_symlink_database_rejected(self):
        link = Path(self.temp.name) / "link.sqlite"
        link.symlink_to(self.path)
        with self.assertRaises(ConfigurationError):
            SQLiteInvoiceStore(link)

    def test_no_proof_or_secret_persisted(self):
        self.paid()
        data = self.path.read_bytes()
        for sentinel in (b"OutProofV2", b"PRIVATE KEY", b"must-not-appear"):
            self.assertNotIn(sentinel, data)

    def test_domain_record_cannot_claim_incomplete_paid(self):
        request = create_payment_request(ADDRESS, 1, network="testnet", now=1000)
        with self.assertRaises(InputError):
            InvoiceRecord(request, InvoiceState.PAID)
        with self.assertRaises(InputError):
            dataclasses.replace(InvoiceRecord(request, InvoiceState.PENDING), txid=TXID)
