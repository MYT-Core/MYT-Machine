"""Separate hostile pass over attribution, corruption, replay and disclosure."""

import concurrent.futures
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from billing_fakes import ADDRESS, TXID, proof_for
from reputation_fakes import ISSUER, OTHER, SUBJECT, ReputationRpc, attest, binding_for

from myt_machine.billing import BillingService
from myt_machine.errors import InputError
from myt_machine.invoice_store import SQLiteInvoiceStore
from myt_machine.invoice_verification import WalletPaymentVerifier
from myt_machine.reputation import create_attestation
from myt_machine.reputation_policy import ReputationPolicy, reputation_summary
from myt_machine.reputation_settlement import record_verified_settlement
from myt_machine.reputation_store import ReputationStorageError, ReputationStore


class ReputationHostileReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = ReputationStore(self.root / "rep.sqlite")
        self.invoices = SQLiteInvoiceStore(self.root / "inv.sqlite", clock=lambda: 1000)
        self.rpc = ReputationRpc()
        self.billing = BillingService(
            self.invoices,
            network="testnet",
            verifier=WalletPaymentVerifier(self.rpc, network="testnet"),
        )
        self.record = self.billing.create_invoice(
            ADDRESS, 100000000, invoice_id="private-order"
        )
        self.proof = proof_for(self.record.request)

    def capture(self, expected=SUBJECT.machine_id):
        return record_verified_settlement(
            self.store,
            self.invoices,
            self.rpc,
            network="testnet",
            invoice_id="private-order",
            binding=binding_for(),
            proof=self.proof,
            expected_machine_id=expected,
        )

    def paid(self):
        self.billing.verify_invoice("private-order", self.proof)

    def test_fabricated_paid_sql_row_needs_native_proof(self):
        with closing(sqlite3.connect(self.invoices.path)) as db:
            db.execute(
                "UPDATE invoices SET state='PAID',txid=?,received_atomic='100000000',"
                "confirmations=10,paid_at=1000",
                (TXID,),
            )
            db.commit()
        self.rpc.response["good"] = False
        with self.assertRaises(InputError):
            self.capture()
        self.assertEqual(self.store.snapshot(network="testnet")[1], [])

    def test_concurrent_event_replay(self):
        self.paid()
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: self.capture(), range(12)))
        self.assertEqual(sum(r["inserted"] for r in results), 1)
        self.assertEqual(len(self.store.snapshot(network="testnet")[1]), 1)

    def test_evidence_cannot_be_transplanted_to_different_subject(self):
        self.paid()
        digest = self.capture()["evidence_digest"]
        a = create_attestation(
            ISSUER,
            subject_machine_id=OTHER.machine_id,
            network="testnet",
            issued_at=1000,
            outcome="POSITIVE",
            evidence=digest,
        )
        self.store.import_artifact(a, network="testnet")
        s = reputation_summary(
            self.store,
            subject=OTHER.machine_id,
            network="testnet",
            as_of=2000,
            policy=ReputationPolicy((ISSUER.machine_id,), require_settlement=True),
        )
        self.assertEqual(s["local_policy_output"]["accepted_attestations"], 0)
        self.assertEqual(
            s["objective_local_observations"]["verified_recipient_settlement_events"], 0
        )

    def test_many_opinions_do_not_multiply_one_settlement(self):
        self.paid()
        digest = self.capture()["evidence_digest"]
        for n in range(10):
            self.store.import_artifact(
                attest(issued_at=1000 + n, evidence=digest), network="testnet"
            )
        s = reputation_summary(
            self.store,
            subject=SUBJECT.machine_id,
            network="testnet",
            as_of=2000,
            policy=ReputationPolicy((ISSUER.machine_id,), require_settlement=True),
        )
        self.assertEqual(s["local_policy_output"]["accepted_attestations"], 1)
        self.assertEqual(
            s["objective_local_observations"]["verified_recipient_settlement_events"], 1
        )

    def test_no_payer_field_or_raw_history_in_summary(self):
        self.paid()
        digest = self.capture()["evidence_digest"]
        self.store.import_artifact(attest(evidence=digest), network="testnet")
        s = reputation_summary(
            self.store,
            subject=SUBJECT.machine_id,
            network="testnet",
            as_of=2000,
            policy=ReputationPolicy(),
        )
        encoded = json.dumps(s)
        for forbidden in (
            ADDRESS,
            TXID,
            digest,
            "OutProofV2",
            "private-order",
            "payer_machine_id",
        ):
            self.assertNotIn(forbidden, encoded)

    def test_missing_expected_identity_cannot_bypass_bridge(self):
        self.paid()
        with self.assertRaises(InputError):
            self.capture(expected=None)

    def test_corrupt_digest_not_counted(self):
        self.paid()
        self.capture()
        with closing(sqlite3.connect(self.store.path)) as db:
            db.execute("UPDATE settlements SET digest=?", ("0" * 64,))
            db.commit()
        with self.assertRaises(ReputationStorageError):
            self.store.snapshot(network="testnet")
