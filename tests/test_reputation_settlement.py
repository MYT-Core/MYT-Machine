import dataclasses
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from billing_fakes import ADDRESS, OTHER_ADDRESS, proof_for
from reputation_fakes import ISSUER, OTHER, SUBJECT, ReputationRpc, attest, binding_for

from myt_machine.billing import BillingService
from myt_machine.errors import ConfigurationError, InputError, RpcTransportError
from myt_machine.invoice_store import SQLiteInvoiceStore
from myt_machine.invoice_verification import WalletPaymentVerifier
from myt_machine.reputation_policy import ReputationPolicy, reputation_summary
from myt_machine.reputation_settlement import record_verified_settlement
from myt_machine.reputation_store import ReputationStorageError, ReputationStore


class ReputationSettlementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.rpc = ReputationRpc()
        self.invoices = SQLiteInvoiceStore(
            self.root / "invoices.sqlite", clock=lambda: 1000
        )
        self.billing = BillingService(
            self.invoices,
            network="testnet",
            verifier=WalletPaymentVerifier(self.rpc, network="testnet"),
        )
        record = self.billing.create_invoice(
            ADDRESS,
            100000000,
            invoice_id="private-invoice",
            memo="private-service-metadata",
        )
        self.proof = proof_for(record.request)
        self.invoice_id = record.request.invoice_id
        self.store = ReputationStore(self.root / "reputation.sqlite")
        self.binding = binding_for()

    def paid(self):
        return self.billing.verify_invoice(self.invoice_id, self.proof)

    def record(self, **changes):
        args = {
            "network": "testnet",
            "invoice_id": self.invoice_id,
            "binding": self.binding,
            "proof": self.proof,
            "expected_machine_id": SUBJECT.machine_id,
        }
        args.update(changes)
        return record_verified_settlement(self.store, self.invoices, self.rpc, **args)

    def test_paid_and_binding(self):
        self.paid()
        self.rpc.calls.clear()
        result = self.record()
        self.assertTrue(result["inserted"])
        self.assertFalse(result["payer_identity_inferred"])
        self.assertFalse(result["service_quality_verified"])
        self.assertEqual(result["subject_machine_id"], SUBJECT.machine_id)
        self.assertIn("check_tx_proof", [c[0] for c in self.rpc.calls])
        self.assertTrue(all(c[2] is False for c in self.rpc.calls))

    def test_pending_rejected(self):
        with self.assertRaises(InputError):
            self.record()

    def test_expired_rejected(self):
        self.invoices.clock = lambda: 100000
        with self.assertRaises(InputError):
            self.record()

    def test_fake_paid_state_rechecked(self):
        self.paid()
        self.rpc.response["good"] = False
        with self.assertRaises(InputError):
            self.record()
        self.assertEqual(self.store.snapshot(network="testnet")[1], [])

    def test_forged_binding_identity_signature(self):
        self.paid()
        forged = dataclasses.replace(
            self.binding,
            identity_signature=ISSUER.sign(
                self.binding.canonical_content, "myt-machine/address-binding/v1"
            ).signature,
        )
        with self.assertRaises(InputError):
            self.record(binding=forged)

    def test_wallet_signature_rejected(self):
        self.paid()
        self.rpc.binding_good = False
        with self.assertRaises(InputError):
            self.record()

    def test_wrong_address(self):
        self.paid()
        with self.assertRaises(InputError):
            self.record(binding=binding_for(address=OTHER_ADDRESS))

    def test_wrong_expected_machine(self):
        self.paid()
        with self.assertRaises(InputError):
            self.record(expected_machine_id=OTHER.machine_id)

    def test_wrong_network(self):
        self.paid()
        with self.assertRaises(ConfigurationError):
            self.record(network="mainnet")

    def test_wrong_binding_network(self):
        self.paid()
        with self.assertRaises(InputError):
            self.record(binding=binding_for(network="stagenet"))

    def test_integrated_rejected(self):
        self.paid()
        self.rpc.subaddress = False
        self.rpc.integrated = True
        with self.assertRaises(InputError):
            self.record()

    def test_proof_txid_must_match_paid_txid(self):
        self.paid()
        with self.assertRaises(InputError):
            self.record(proof={**self.proof, "txid": "cc" * 32})

    def test_wrong_proof_request(self):
        self.paid()
        with self.assertRaises(InputError):
            self.record(
                proof={**self.proof, "message": "myt-machine/invoice/v1:" + "0" * 64}
            )

    def test_underconfirmed_and_wrong_amount(self):
        self.paid()
        for field, value in (("confirmations", 1), ("received", 1), ("in_pool", True)):
            old = self.rpc.response[field]
            self.rpc.response[field] = value
            with self.subTest(field=field), self.assertRaises(InputError):
                self.record()
            self.rpc.response[field] = old

    def test_timeout_no_retry(self):
        self.paid()
        self.rpc.calls.clear()
        self.rpc.failure = RpcTransportError("redacted", kind="timeout")
        with self.assertRaises(RpcTransportError):
            self.record()
        self.assertEqual(sum(c[0] == "check_tx_proof" for c in self.rpc.calls), 1)

    def test_duplicate_settlement(self):
        self.paid()
        self.assertTrue(self.record()["inserted"])
        self.assertFalse(self.record()["inserted"])
        self.assertEqual(len(self.store.snapshot(network="testnet")[1]), 1)

    def test_rebinding_transaction_cannot_inflate(self):
        self.paid()
        self.record()
        with self.assertRaises(InputError):
            self.record(
                binding=binding_for(identity=OTHER),
                expected_machine_id=OTHER.machine_id,
            )

    def test_linked_opinion_separate_from_fact(self):
        self.paid()
        result = self.record()
        self.store.import_artifact(
            attest(evidence=result["evidence_digest"]), network="testnet"
        )
        summary = reputation_summary(
            self.store,
            subject=SUBJECT.machine_id,
            network="testnet",
            policy=ReputationPolicy((ISSUER.machine_id,), require_settlement=True),
            as_of=2000,
        )
        self.assertEqual(summary["local_policy_output"]["accepted_attestations"], 1)
        self.assertEqual(
            summary["objective_local_observations"][
                "verified_recipient_settlement_events"
            ],
            1,
        )

    def test_no_invoice_proof_address_metadata_in_reputation_db(self):
        self.paid()
        self.record()
        raw = self.store.path.read_bytes()
        for secret in (
            ADDRESS,
            self.proof["txid"],
            self.proof["proof"],
            self.invoice_id,
            "private-service-metadata",
            "rpc-password",
        ):
            self.assertNotIn(secret.encode(), raw)

    def test_corrupt_evidence_rejected(self):
        self.paid()
        self.record()
        with closing(sqlite3.connect(self.store.path)) as db:
            db.execute("UPDATE settlements SET subject=?", (OTHER.machine_id,))
            db.commit()
        with self.assertRaises(ReputationStorageError):
            self.store.snapshot(network="testnet")

    def test_objective_fact_cannot_be_imported_as_attestation(self):
        self.paid()
        self.record()
        from myt_machine.reputation import parse_reputation_artifact

        with self.assertRaises(InputError):
            parse_reputation_artifact(
                json.dumps(self.store.snapshot(network="testnet")[1][0])
            )
