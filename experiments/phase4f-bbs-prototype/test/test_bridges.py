from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


EXPERIMENT_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = EXPERIMENT_ROOT.parents[1]
sys.path.insert(0, str(EXPERIMENT_ROOT / "bridge"))
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from challenge_store import ChallengeStoreError, DurableChallengeStore  # noqa: E402
from phase4e_adapter import Phase4eAdapterError, evaluate_request  # noqa: E402
from myt_machine.identity import MachineIdentity  # noqa: E402
from myt_machine.reputation_store import ReputationStore  # noqa: E402


FIXED_TIME = 2_000_000_000
SUBJECT_SEED = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"


def challenge(index: int = 0) -> str:
    raw = index.to_bytes(4, "big") + bytes(range(28))
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def request(index: int = 0) -> dict:
    return {
        "type": "myt-phase4f-presentation-request",
        "version": 1,
        "challenge": challenge(index),
        "audience": "https://verifier.example/myt-machine",
        "network": "testnet",
        "policy_digest": "ab" * 32,
        "requested_predicate": {
            "metric_id": "verified_recipient_settlement_events",
            "operator": "gte",
            "threshold": 25,
            "required_result": True,
        },
        "created_at": FIXED_TIME,
        "expires_at": FIXED_TIME + 120,
    }


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


class DurableChallengeStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "challenges.sqlite"

    def test_survives_restart_and_rejects_replay(self):
        first = DurableChallengeStore(self.path)
        first.register(request())
        restarted = DurableChallengeStore(self.path)
        self.assertEqual(restarted.lookup(challenge(), FIXED_TIME), request())
        restarted.consume(challenge(), FIXED_TIME)
        with self.assertRaisesRegex(ChallengeStoreError, "already used"):
            DurableChallengeStore(self.path).lookup(challenge(), FIXED_TIME)

    def test_concurrent_consumption_has_exactly_one_winner(self):
        DurableChallengeStore(self.path).register(request())

        def consume_once(_):
            try:
                DurableChallengeStore(self.path).consume(challenge(), FIXED_TIME)
                return True
            except ChallengeStoreError:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(consume_once, range(16)))
        self.assertEqual(sum(results), 1)

    def test_corrupt_stored_request_fails_closed(self):
        DurableChallengeStore(self.path).register(request())
        with closing(sqlite3.connect(self.path)) as database:
            database.execute("UPDATE challenges SET request_json='{}'")
            database.commit()
        with self.assertRaisesRegex(ChallengeStoreError, "Corrupt"):
            DurableChallengeStore(self.path).lookup(challenge(), FIXED_TIME)

    def test_key_revocation_is_idempotent_and_persistent(self):
        store = DurableChallengeStore(self.path)
        revocation = {
            "type": "myt-phase4f-bbs-key-revocation",
            "version": 1,
            "evaluator_machine_id": "myt-machine-v1:" + "a" * 52,
            "bbs_key_id": "myt-phase4f-bbs-key-v1:" + "ab" * 32,
            "authorization_id": "myt-phase4f-key-auth-v1:" + "cd" * 32,
            "network": "testnet",
            "revoked_at": FIXED_TIME,
            "reason": "compromised",
            "id": "myt-phase4f-key-revocation-v1:" + "ef" * 32,
            "signature": "x" * 86,
        }
        self.assertTrue(store.register_key_revocation(revocation))
        self.assertFalse(store.register_key_revocation(revocation))
        self.assertEqual(
            DurableChallengeStore(self.path).lookup_key_revocation(
                revocation["bbs_key_id"]
            ),
            revocation,
        )

    def test_corrupt_stored_key_revocation_fails_closed(self):
        store = DurableChallengeStore(self.path)
        revocation = {
            "type": "myt-phase4f-bbs-key-revocation",
            "version": 1,
            "evaluator_machine_id": "myt-machine-v1:" + "a" * 52,
            "bbs_key_id": "myt-phase4f-bbs-key-v1:" + "ab" * 32,
            "authorization_id": "myt-phase4f-key-auth-v1:" + "cd" * 32,
            "network": "testnet",
            "revoked_at": FIXED_TIME,
            "reason": "compromised",
            "id": "myt-phase4f-key-revocation-v1:" + "ef" * 32,
            "signature": "x" * 86,
        }
        store.register_key_revocation(revocation)
        with closing(sqlite3.connect(self.path)) as database:
            database.execute("UPDATE key_revocations SET revocation_json='{}'")
            database.commit()
        with self.assertRaisesRegex(ChallengeStoreError, "Corrupt"):
            DurableChallengeStore(self.path).lookup_key_revocation(
                revocation["bbs_key_id"]
            )


class RealPhase4eAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "reputation.sqlite"
        self.subject = MachineIdentity(
            Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SUBJECT_SEED))
        )
        store = ReputationStore(self.path)
        for index in range(37):
            store._record_settlement(
                {
                    "type": "myt-recipient-settlement-observation",
                    "version": 1,
                    "network": "testnet",
                    "subject_machine_id": self.subject.machine_id,
                    "transaction_digest": digest(f"transaction-{index}"),
                    "request_digest": digest(f"request-{index}"),
                    "binding_digest": digest(f"binding-{index}"),
                }
            )

    def evaluator_request(self):
        return {
            "subject_machine_id": self.subject.machine_id,
            "network": "testnet",
            "policy": {
                "trusted_issuers": [],
                "max_per_issuer": 1,
                "min_age": 0,
                "max_age": 253402300799,
                "require_settlement": False,
            },
            "as_of": FIXED_TIME,
            "requested_predicate": {
                "metric_id": "verified_recipient_settlement_events",
                "operator": "gte",
                "threshold": 25,
            },
        }

    def test_real_store_produces_bounded_assertion(self):
        result = evaluate_request(str(self.path), self.evaluator_request())
        self.assertEqual(result["predicate"]["metric_value"], 37)
        self.assertIs(result["predicate"]["result"], True)
        self.assertEqual(
            result["evaluation"]["objective_local_observations"]
            ["verified_recipient_settlement_events"],
            37,
        )
        self.assertEqual(len(result["evaluation"]["phase4e_evidence_digest"]), 64)

    def test_fake_snapshot_input_is_rejected(self):
        attack = self.evaluator_request()
        attack["snapshot"] = {"source": "validated-phase4e-v0.5.x-snapshot"}
        with self.assertRaisesRegex(Phase4eAdapterError, "unknown fields"):
            evaluate_request(str(self.path), attack)


if __name__ == "__main__":
    unittest.main()
