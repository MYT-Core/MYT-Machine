import base64
import io
import json
import multiprocessing
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ProcessPoolExecutor
from contextlib import closing
from dataclasses import asdict, replace
from pathlib import Path
from unittest.mock import patch

from disclosure_support import CompanionFixture
from disclosure_worker import consume

from myt_machine.cli import main
from myt_machine.disclosure import (
    DisclosurePolicy,
    authorize_bbs_key,
    create_disclosure_request,
    issue_reputation_credential,
    present_reputation_credential,
    reputation_policy_digest,
    revoke_bbs_key,
    verify_reputation_presentation,
)
from myt_machine.disclosure_artifacts import (
    CONTROL_CONTEXT,
    LEVELS,
    active,
    artifact,
    b64,
    control_content,
    credential_messages,
    parse_disclosure,
    presentation_header,
    strict_object,
)
from myt_machine.disclosure_backend import BbsBackend, DisclosureBackendError
from myt_machine.disclosure_files import load_disclosure, save_disclosure
from myt_machine.disclosure_store import DisclosureStorageError, DisclosureStore
from myt_machine.errors import ConfigurationError, InputError
from myt_machine.identity import MachineIdentity
from myt_machine.payment_requests import unix_time
from myt_machine.reputation_policy import ReputationPolicy
from myt_machine.reputation_store import ReputationStore


class DisclosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = tempfile.TemporaryDirectory()
        cls.companion = CompanionFixture(cls.runtime.name)

    @classmethod
    def tearDownClass(cls):
        cls.companion.close()
        cls.runtime.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.evaluator = MachineIdentity.generate()
        self.subject = MachineIdentity.generate()
        self.backend = self.companion.backend
        self.authorization = authorize_bbs_key(
            self.evaluator, self.backend, network="testnet"
        )
        self.state = DisclosureStore(self.root / "state.db")
        self.state.refresh_issuer(
            self.authorization, expected_evaluator=self.evaluator.machine_id
        )
        self.evidence = ReputationStore(self.root / "reputation.db")
        for i in range(25):
            self.evidence._record_settlement(
                {
                    "type": "myt-recipient-settlement-observation",
                    "version": 1,
                    "network": "testnet",
                    "subject_machine_id": self.subject.machine_id,
                    "transaction_digest": f"{i:064x}",
                    "request_digest": f"{i + 100:064x}",
                    "binding_digest": "b" * 64,
                }
            )
        self.rpolicy = ReputationPolicy()
        self.policy = DisclosurePolicy(
            self.subject.machine_id,
            self.evaluator.machine_id,
            self.authorization.as_dict()["statement"]["bbs_key_id"],
            "testnet",
            "test.example",
            reputation_policy_digest(self.rpolicy),
            25,
        )

    def issue(self, **overrides):
        args = {
            "reputation_store": self.evidence,
            "policy": self.rpolicy,
            "subject": self.subject.machine_id,
            "identity": self.evaluator,
            "authorization": self.authorization,
            "issuer_state": self.state,
            "backend": self.backend,
        }
        return issue_reputation_credential(**{**args, **overrides})

    def request(self):
        return create_disclosure_request(self.policy, self.state)

    def presentation(self, request=None):
        return present_reputation_credential(
            credential=self.issue(),
            request=request or self.request(),
            policy=self.policy,
            identity=self.subject,
            issuer_state=self.state,
            backend=self.backend,
        )

    def verify(self, value, **kwargs):
        return verify_reputation_presentation(
            presentation=value,
            policy=kwargs.get("policy", self.policy),
            store=kwargs.get("store", self.state),
            backend=kwargs.get("backend", self.backend),
        )

    def test_exact_header_bytes_on_both_native_operations(self):
        with patch.object(self.backend, "call", wraps=self.backend.call) as call:
            value = self.presentation()
            self.assertTrue(self.verify(value).valid)
        expected = presentation_header(value.as_dict()["request"])
        self.assertIn(b"\n", expected)
        operations = [
            c
            for c in call.call_args_list
            if c.args[0] in ("derive-proof", "verify-proof")
        ]
        self.assertEqual(len(operations), 2)
        for c in operations:
            params = c.args[1]
            self.assertEqual(
                base64.urlsafe_b64decode(params["presentation_header"] + "=="), expected
            )
            self.assertEqual(params["request"], value.as_dict()["request"])

    def test_16_concurrent_consumers_exactly_one_winner(self):
        value = self.presentation()
        data = (
            value.raw,
            asdict(self.policy),
            str(self.state.path),
            self.companion.url,
            str(self.companion.token),
        )
        with ProcessPoolExecutor(
            max_workers=16, mp_context=multiprocessing.get_context("spawn")
        ) as executor:
            results = list(executor.map(consume, [data] * 16))
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), 15)
        self.assertFalse(self.verify(value).valid)

    def test_malformed_transport_is_not_retried(self):
        req = self.request().as_dict()
        credential = self.issue().as_dict()
        normal = b64(presentation_header(req))
        params = {
            "public_key": credential["authorization"]["statement"]["bbs_public_key"],
            "signature": credential["signature"],
            "messages": credential_messages(credential),
            "request": req,
            "threshold": 25,
        }
        for bad in (
            normal + "=",
            "",
            normal + "\n",
            "+" + normal[1:],
            b64(b"wrong-domain"),
        ):
            with (
                self.subTest(transport=bad[:8]),
                self.assertRaises(DisclosureBackendError),
            ):
                self.backend.call(
                    "derive-proof", {**params, "presentation_header": bad}
                )

    def test_full_flow_and_replay(self):
        value = self.presentation()
        self.assertTrue(self.verify(value).valid)
        self.assertFalse(self.verify(value).valid)

    def test_restart_replay(self):
        value = self.presentation()
        self.assertTrue(self.verify(value).valid)
        self.assertFalse(
            self.verify(value, store=DisclosureStore(self.state.path)).valid
        )

    def test_real_phase4e_predicates_and_data_minimization(self):
        cred = self.issue().as_dict()
        self.assertEqual(cred["claims"]["predicates"], [True, True, True, False, False])
        self.assertNotIn("metric_value", cred["claims"])
        self.assertNotIn("history", cred["claims"])
        self.assertEqual(len(credential_messages(cred)), 15)

    def test_no_snapshot_shortcut(self):
        with self.assertRaises(InputError):
            self.issue(reputation_store={"validated_snapshot": True, "result": True})
        with self.assertRaises(TypeError):
            self.issue(predicate_result=True)

    def test_empty_real_store_does_not_satisfy(self):
        empty = ReputationStore(self.root / "empty.db")
        cred = self.issue(reputation_store=empty)
        self.assertEqual(cred.as_dict()["claims"]["predicates"], [False] * 5)
        with self.assertRaises(InputError):
            present_reputation_credential(
                credential=cred,
                request=self.request(),
                policy=self.policy,
                identity=self.subject,
                issuer_state=self.state,
                backend=self.backend,
            )

    def test_self_evaluator_rejected(self):
        with self.assertRaises(InputError):
            replace(self.policy, evaluator=self.subject.machine_id)

    def test_unsupported_threshold(self):
        with self.assertRaises(InputError):
            replace(self.policy, threshold=26)

    def test_random_challenges(self):
        self.assertNotEqual(
            self.request().as_dict()["challenge"], self.request().as_dict()["challenge"]
        )

    def test_random_proofs(self):
        req = self.request()
        a, b = self.presentation(req), self.presentation(req)
        self.assertNotEqual(a.as_dict()["proof"], b.as_dict()["proof"])
        self.assertNotIn("predicates", a.as_dict()["claims"])

    def test_wrong_subject_private_key(self):
        with self.assertRaises(InputError):
            present_reputation_credential(
                credential=self.issue(),
                request=self.request(),
                policy=self.policy,
                identity=MachineIdentity.generate(),
                issuer_state=self.state,
                backend=self.backend,
            )

    def test_revocation_revalidated_and_sticky(self):
        value = self.presentation()
        rev = revoke_bbs_key(self.evaluator, self.authorization, reason="retired")
        self.state.refresh_issuer(
            self.authorization,
            expected_evaluator=self.evaluator.machine_id,
            revocations=[rev],
        )
        self.state.refresh_issuer(
            self.authorization, expected_evaluator=self.evaluator.machine_id
        )
        self.assertFalse(self.verify(value).valid)

    def test_revocation_wrong_signer(self):
        with self.assertRaises(InputError):
            revoke_bbs_key(self.subject, self.authorization, reason="retired")

    def test_status_missing(self):
        value = self.presentation()
        empty = DisclosureStore(self.root / "fresh.db")
        self.assertFalse(self.verify(value, store=empty).valid)

    def test_status_stale(self):
        value = self.presentation()
        now = unix_time()
        with patch("myt_machine.disclosure_store.unix_time", return_value=now + 301):
            self.assertFalse(self.verify(value).valid)

    def test_expired_request_not_consumed(self):
        value = self.presentation()
        end = value.as_dict()["request"]["expires_at"]
        with patch("myt_machine.disclosure_store.unix_time", return_value=end):
            self.assertFalse(self.verify(value).valid)
        self.assertTrue(self.verify(value).valid)

    def test_future_request_not_consumed(self):
        now = unix_time()
        with patch("myt_machine.disclosure.unix_time", return_value=now + 50):
            req = self.request()
        with self.assertRaises(InputError):
            self.presentation(req)

    def test_time_exact_boundaries(self):
        active(100, 200, 100)
        for now in (99, 200, 201):
            with self.assertRaises(InputError):
                active(100, 200, now)

    def test_expiry_during_crypto_check_does_not_consume(self):
        value = self.presentation()
        now = unix_time()
        expiry = value.as_dict()["request"]["expires_at"]
        with patch("myt_machine.disclosure_store.unix_time", side_effect=[now, expiry]):
            self.assertFalse(self.verify(value).valid)
        self.assertTrue(self.verify(value).valid)

    def test_backend_failure_no_consume_no_retry(self):
        value = self.presentation()
        with patch.object(
            self.backend, "call", side_effect=DisclosureBackendError("redacted")
        ) as call:
            with self.assertRaises(DisclosureBackendError):
                self.verify(value)
            self.assertEqual(call.call_count, 1)
        self.assertTrue(self.verify(value).valid)

    def test_unknown_challenge(self):
        value = self.presentation()
        with closing(sqlite3.connect(self.state.path)) as db, db:
            db.execute("DELETE FROM requests")
        self.assertFalse(self.verify(value).valid)

    def test_corrupt_database_artifact(self):
        self.request()
        with closing(sqlite3.connect(self.state.path)) as db, db:
            db.execute("UPDATE requests SET artifact=x'00'")
        with self.assertRaises(DisclosureStorageError):
            self.request()

    def test_corrupt_database_digest(self):
        self.request()
        with closing(sqlite3.connect(self.state.path)) as db, db:
            db.execute("UPDATE requests SET digest='changed'")
        with self.assertRaises(DisclosureStorageError):
            self.request()

    def test_corrupt_database_schema(self):
        with closing(sqlite3.connect(self.state.path)) as db, db:
            db.execute("CREATE TABLE extra (a TEXT)")
        with self.assertRaises(DisclosureStorageError):
            self.request()

    def test_wrong_database_id(self):
        with closing(sqlite3.connect(self.state.path)) as db, db:
            db.execute("PRAGMA application_id=0")
        with self.assertRaises(DisclosureStorageError):
            self.request()

    def test_clock_rollback(self):
        with (
            patch("myt_machine.disclosure_store.unix_time", return_value=0),
            self.assertRaises(DisclosureStorageError),
        ):
            self.request()

    def test_output_no_overwrite_private_and_load(self):
        value = self.request()
        file = self.root / "request.json"
        save_disclosure(file, value)
        self.assertEqual(load_disclosure(file), value)
        with self.assertRaises(ConfigurationError):
            save_disclosure(file, value)
        if os.name != "nt":
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)

    def test_linked_file_rejected(self):
        file = self.root / "request.json"
        save_disclosure(file, self.request())
        os.link(file, self.root / "linked")
        with self.assertRaises(ConfigurationError):
            load_disclosure(file)

    def test_issuer_key_mismatch(self):
        with (
            patch.object(
                self.backend, "call", return_value={"public_key": b64(bytes(96))}
            ),
            self.assertRaises(InputError),
        ):
            self.issue()

    def test_untrusted_evaluator(self):
        self.assertFalse(
            self.verify(
                self.presentation(),
                policy=replace(
                    self.policy, evaluator=MachineIdentity.generate().machine_id
                ),
            ).valid
        )

    def test_wrong_independent_subject(self):
        self.assertFalse(
            self.verify(
                self.presentation(),
                policy=replace(
                    self.policy, subject=MachineIdentity.generate().machine_id
                ),
            ).valid
        )

    def test_wrong_network(self):
        self.assertFalse(
            self.verify(
                self.presentation(), policy=replace(self.policy, network="mainnet")
            ).valid
        )

    def test_wrong_policy(self):
        self.assertFalse(
            self.verify(
                self.presentation(), policy=replace(self.policy, policy_digest="0" * 64)
            ).valid
        )

    def test_wrong_threshold(self):
        self.assertFalse(
            self.verify(
                self.presentation(), policy=replace(self.policy, threshold=50)
            ).valid
        )

    def test_wrong_audience(self):
        self.assertFalse(
            self.verify(
                self.presentation(),
                policy=replace(self.policy, audience="attacker.example"),
            ).valid
        )

    def test_subject_signature_tamper(self):
        value = self.presentation().as_dict()
        value["subject_control"]["signature"] = b64(bytes(64))
        self.assertFalse(self.verify(artifact(value)).valid)

    def test_holder_cannot_change_bbs_proof_with_resign(self):
        value = self.presentation().as_dict()
        proof = bytearray(__import__("base64").urlsafe_b64decode(value["proof"] + "=="))
        proof[-1] ^= 1
        value["proof"] = b64(proof)
        body = {k: v for k, v in value.items() if k != "subject_control"}
        value["subject_control"]["signature"] = self.subject.sign(
            control_content(body), CONTROL_CONTEXT
        ).signature
        self.assertFalse(self.verify(artifact(value)).valid)

    def test_holder_cannot_transplant_to_another_request(self):
        value = self.presentation().as_dict()
        value["request"] = self.request().as_dict()
        body = {k: v for k, v in value.items() if k != "subject_control"}
        value["subject_control"]["signature"] = self.subject.sign(
            control_content(body), CONTROL_CONTEXT
        ).signature
        self.assertFalse(self.verify(artifact(value)).valid)

    def test_cli_offline_show(self):
        value = self.request()
        file = self.root / "request.json"
        save_disclosure(file, value)
        output = io.StringIO()
        rc = main(
            ["disclosure", "show", "--artifact-file", str(file)],
            environ={"MYT_WALLET_RPC_URL": "ftp://must-not-appear"},
            stdout=output,
            client_factory=lambda _: self.fail("Wallet RPC must not be used"),
        )
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(output.getvalue())["artifact"], value.as_dict())
        self.assertNotIn("must-not-appear", output.getvalue())

    def test_cli_error_redaction(self):
        file = self.root / "malformed.json"
        file.write_bytes(b'{"must-not-appear":0,"must-not-appear":1}\n')
        output = io.StringIO()
        self.assertEqual(
            main(["disclosure", "show", "--artifact-file", str(file)], stdout=output), 2
        )
        self.assertNotIn("must-not-appear", output.getvalue())


class StrictDisclosureTests(unittest.TestCase):
    def test_catalogue_is_narrow(self):
        self.assertEqual(LEVELS, (1, 10, 25, 50, 100))

    def test_nondict_rejected(self):
        for value in (None, [], 3, "x"):
            with self.assertRaises(InputError):
                artifact(value)

    def test_invalid_text_encoding(self):
        with self.assertRaises(InputError):
            parse_disclosure("\ud800")

    def test_backend_secret_repr(self):
        obj = object.__new__(BbsBackend)
        self.assertNotIn("token", repr(obj))


for name, raw in {
    "bom": b'\xef\xbb\xbf{"a":1}\n',
    "invalid_utf8": b'\xfb"a":1}\n',
    "utf16": '{"a":1}\n'.encode("utf-16"),
    "duplicates": b'{"a":0,"a":1}\n',
    "escaped_duplicates": b'{"a":0,"\\u0061":1}\n',
    "whitespace": b'{"a": 1}\n',
    "trailing": b'{"a":1}\nx',
    "leading": b' {"a":1}\n',
    "null": b'{"a":null}\n',
    "float": b'{"a":1.1}\n',
    "exponent": b'{"a":1e0}\n',
    "nan": b'{"a":NaN}\n',
    "infinity": b'{"a":Infinity}\n',
    "control": b'{"a":"\\u0000"}\n',
    "surrogate": b'{"a":"\\ud800"}\n',
    "oversize": b"x" * 32769,
    "no_newline": b'{"a":1}',
    "two_newlines": b'{"a":1}\n\n',
}.items():

    def check(self, value=raw):
        with self.assertRaises(InputError):
            strict_object(value)

    setattr(StrictDisclosureTests, "test_reject_" + name, check)
