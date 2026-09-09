import concurrent.futures
import dataclasses
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from reputation_fakes import ISSUER, OTHER, SUBJECT, attest

from myt_machine.errors import ConfigurationError, InputError
from myt_machine.reputation import (
    REVOCATION,
    _sign,
    create_attestation,
    create_revocation,
    parse_reputation_artifact,
)
from myt_machine.reputation_policy import ReputationPolicy, reputation_summary
from myt_machine.reputation_store import ReputationStorageError, ReputationStore


class ReputationStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "reputation.sqlite"
        self.store = ReputationStore(self.path)

    def put(self, a=None):
        return self.store.import_artifact(a or attest(), network="testnet")

    def summary(self, **policy):
        return reputation_summary(
            self.store,
            subject=SUBJECT.machine_id,
            network="testnet",
            policy=ReputationPolicy(**policy),
            as_of=2000,
        )

    def accepted(self, **policy):
        return self.summary(trusted_issuers=(ISSUER.machine_id,), **policy)[
            "local_policy_output"
        ]

    def test_import_restart(self):
        self.assertTrue(self.put())
        restarted = ReputationStore(self.path)
        self.assertEqual(restarted.get(attest().id, network="testnet"), attest())

    def test_duplicate_import(self):
        self.assertTrue(self.put())
        self.assertFalse(self.put())
        self.assertEqual(len(self.store.list(network="testnet")), 1)

    def test_whitespace_does_not_duplicate(self):
        self.put()
        self.assertFalse(
            self.put(
                parse_reputation_artifact(json.dumps(attest().as_dict(), indent=4))
            )
        )

    def test_concurrent_imports(self):
        def run(_):
            return ReputationStore(self.path).import_artifact(
                attest(), network="testnet"
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            self.assertEqual(sum(executor.map(run, range(20))), 1)

    def test_wrong_signature_not_stored(self):
        d = attest().as_dict()
        d["signature"] = OTHER.sign(
            attest().canonical_content, "myt-machine/reputation-attestation/v1"
        ).signature
        with self.assertRaises(InputError):
            self.put(parse_reputation_artifact(json.dumps(d)))
        self.assertEqual(self.store.list(network="testnet"), [])

    def test_cross_network_import_rejected(self):
        with self.assertRaises(InputError):
            self.store.import_artifact(attest(), network="mainnet")

    def test_network_separation(self):
        self.put()
        a = attest(network="mainnet")
        self.store.import_artifact(a, network="mainnet")
        self.assertEqual(self.store.list(network="testnet"), [attest()])
        self.assertIsNone(self.store.get(attest().id, network="mainnet"))

    def test_corrupt_artifact_fails_closed(self):
        self.put()
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("UPDATE artifacts SET artifact='not-json'")
            db.commit()
        with self.assertRaises(ReputationStorageError):
            self.summary()

    def test_corrupt_index_fails_closed(self):
        self.put()
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("UPDATE artifacts SET network='mainnet'")
            db.commit()
        with self.assertRaises(ReputationStorageError):
            self.summary()

    def test_corrupt_database_redacted(self):
        self.path.write_bytes(b"must-not-appear" * 100)
        with self.assertRaises(ReputationStorageError) as caught:
            ReputationStore(self.path)
        self.assertNotIn("must-not-appear", str(caught.exception))

    def test_foreign_database_rejected(self):
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("PRAGMA application_id=42")
        with self.assertRaises(ReputationStorageError):
            ReputationStore(self.path)

    def test_capacity(self):
        store = ReputationStore(self.path, capacity=1)
        store.import_artifact(attest(), network="testnet")
        with self.assertRaises(ReputationStorageError):
            store.import_artifact(attest(issued_at=1001), network="testnet")
        self.assertFalse(store.import_artifact(attest(), network="testnet"))

    def test_query_validation(self):
        for limit in (0, True, 201, 1.0):
            with self.assertRaises(InputError):
                self.store.list(network="testnet", limit=limit)
        with self.assertRaises(InputError):
            self.store.list(network="testnet", subject="bad")

    def test_order_and_pagination(self):
        self.put(attest(issued_at=900))
        self.put()
        all_items = self.store.list(network="testnet")
        self.assertEqual([a.id for a in all_items], sorted(a.id for a in all_items))
        self.assertEqual(
            self.store.list(network="testnet", after=all_items[0].id), all_items[1:]
        )

    @unittest.skipIf(os.name == "nt", "Unix mode enforcement")
    def test_permissions(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.path.chmod(0o644)
        with self.assertRaises(ConfigurationError):
            ReputationStore(self.path)

    @unittest.skipIf(os.name == "nt", "Unix links")
    def test_symlink_hardlink(self):
        link = self.path.parent / "link"
        link.symlink_to(self.path)
        with self.assertRaises(ConfigurationError):
            ReputationStore(link)
        link.unlink()
        os.link(self.path, link)
        with self.assertRaises(ConfigurationError):
            ReputationStore(link)

    def test_no_memory_database(self):
        with self.assertRaises(ConfigurationError):
            ReputationStore(":memory:")

    def test_revocation_excludes(self):
        self.put()
        self.put(create_revocation(ISSUER, attest(), issued_at=1001))
        self.assertEqual(self.accepted()["accepted_attestations"], 0)
        self.assertEqual(self.summary()["signed_opinions"]["revoked_attestations"], 1)

    def test_revocation_before_import(self):
        self.put(create_revocation(ISSUER, attest(), issued_at=1001))
        self.put()
        self.assertEqual(self.accepted()["accepted_attestations"], 0)

    def test_duplicate_revocation_idempotent(self):
        self.put()
        r = create_revocation(ISSUER, attest(), issued_at=1001)
        self.assertTrue(self.put(r))
        self.assertFalse(self.put(r))
        self.put(create_revocation(ISSUER, attest(), issued_at=1002))
        self.assertEqual(self.summary()["signed_opinions"]["revoked_attestations"], 1)

    def test_wrong_issuer_revocation_known_target(self):
        self.put()
        wrong = _sign(
            OTHER,
            REVOCATION,
            {"network": "testnet", "issued_at": 1001, "attestation_id": attest().id},
        )
        with self.assertRaises(InputError):
            self.put(wrong)

    def test_wrong_issuer_pending_cannot_revoke_later_import(self):
        wrong = _sign(
            OTHER,
            REVOCATION,
            {"network": "testnet", "issued_at": 1001, "attestation_id": attest().id},
        )
        self.put(wrong)
        self.put()
        self.assertEqual(self.accepted()["accepted_attestations"], 1)

    def test_empty_allowlist_accepts_nothing(self):
        self.put()
        self.assertEqual(
            self.summary()["local_policy_output"]["accepted_attestations"], 0
        )

    def test_per_issuer_cap_and_deterministic_newest(self):
        self.put()
        self.put(attest(issued_at=1100, outcome="NEGATIVE"))
        result = self.accepted()
        self.assertEqual(result["accepted_attestations"], 1)
        self.assertEqual(result["negative"], 1)
        self.assertEqual(result["unique_machine_identity_issuers"], 1)
        self.assertEqual(self.accepted(max_per_issuer=2)["accepted_attestations"], 2)

    def test_policy_min_max_age(self):
        self.put()
        self.assertEqual(self.accepted(min_age=1001)["accepted_attestations"], 0)
        self.assertEqual(self.accepted(max_age=999)["accepted_attestations"], 0)
        self.assertEqual(
            self.accepted(min_age=1000, max_age=1000)["accepted_attestations"], 1
        )

    def test_future_excluded(self):
        self.put(attest(issued_at=2001))
        self.assertEqual(self.accepted()["accepted_attestations"], 0)

    def test_unverified_reference_not_objective_fact(self):
        self.put(attest(evidence="ab" * 32))
        s = self.summary()
        self.assertEqual(
            s["objective_local_observations"]["verified_recipient_settlement_events"], 0
        )
        self.assertEqual(
            self.accepted(require_settlement=True)["accepted_attestations"], 0
        )

    def test_sybil_farming_no_implicit_trust(self):
        self.put()
        self.put(
            create_attestation(
                OTHER,
                subject_machine_id=SUBJECT.machine_id,
                network="testnet",
                issued_at=1000,
                outcome="POSITIVE",
            )
        )
        self.assertEqual(
            self.summary()["local_policy_output"]["accepted_attestations"], 0
        )
        self.assertEqual(self.accepted()["accepted_attestations"], 1)

    def test_policy_validation(self):
        for changes in (
            {"max_per_issuer": True},
            {"min_age": -1},
            {"max_age": 0, "min_age": 1},
            {"require_settlement": 1},
            {"trusted_issuers": ("bad",)},
            {"trusted_issuers": (ISSUER.machine_id, ISSUER.machine_id)},
        ):
            with self.subTest(changes=changes), self.assertRaises(InputError):
                ReputationPolicy(**changes)

    def test_no_private_data_in_database(self):
        self.put()
        data = self.path.read_bytes()
        for secret in (b"PRIVATE KEY", b"password", b"OutProofV2", b"rpc-password"):
            self.assertNotIn(secret, data)

    def test_policy_immutable(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            ReputationPolicy().require_settlement = True
