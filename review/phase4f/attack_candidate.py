"""Independent attack builder, excluded from distributions. Never deployment code."""
import base64
import io
import json
import multiprocessing
import tempfile
import unittest
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, replace
from pathlib import Path
from unittest.mock import patch

from disclosure_support import CompanionFixture

from myt_machine import MachineIdentity, ReputationPolicy, ReputationStore
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
from myt_machine.disclosure_artifacts import parse_disclosure
from myt_machine.disclosure_backend import BbsBackend, DisclosureBackendError
from myt_machine.disclosure_store import DisclosureStore
from myt_machine.errors import MytMachineError


def wire(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def consume(data):
    raw, policy, path, url, token = data
    return verify_reputation_presentation(
        presentation=parse_disclosure(raw), policy=DisclosurePolicy(**policy),
        store=DisclosureStore(path), backend=BbsBackend(url=url, token_file=token),
    ).valid


class IndependentAttacks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = tempfile.TemporaryDirectory()
        cls.companion = CompanionFixture(cls.runtime.name)

    @classmethod
    def tearDownClass(cls):
        cls.companion.close()
        cls.runtime.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.a, self.b, self.evaluator = (MachineIdentity.generate() for _ in range(3))
        self.backend = self.companion.backend
        self.auth = authorize_bbs_key(self.evaluator, self.backend, network="testnet")
        self.state = DisclosureStore(self.root / "state")
        self.state.refresh_issuer(self.auth, expected_evaluator=self.evaluator.machine_id)
        self.evidence = ReputationStore(self.root / "evidence")
        for i in range(37):
            self.evidence._record_settlement({
                "type": "myt-recipient-settlement-observation", "version": 1,
                "network": "testnet", "subject_machine_id": self.a.machine_id,
                "transaction_digest": f"{i:064x}", "request_digest": f"{i+1000:064x}",
                "binding_digest": "f" * 64,
            })
        self.policy = DisclosurePolicy(
            self.a.machine_id, self.evaluator.machine_id,
            json.loads(self.auth.raw)["statement"]["bbs_key_id"],
            "testnet", "verifier.example", reputation_policy_digest(ReputationPolicy()), 25,
        )
        self.cred = issue_reputation_credential(
            reputation_store=self.evidence, policy=ReputationPolicy(), subject=self.a.machine_id,
            identity=self.evaluator, authorization=self.auth,
            issuer_state=self.state, backend=self.backend,
        )
        self.request = create_disclosure_request(self.policy, self.state)
        self.proof = present_reputation_credential(
            credential=self.cred, request=self.request, policy=self.policy,
            identity=self.a, issuer_state=self.state, backend=self.backend,
        )

    def verify(self, raw, **kwargs):
        try:
            return verify_reputation_presentation(
                presentation=parse_disclosure(raw), policy=kwargs.get("policy", self.policy),
                store=kwargs.get("store", self.state), backend=self.backend,
            ).valid
        except MytMachineError:
            return False

    def test_subject_b_cannot_satisfy_subject_a(self):
        self.assertFalse(self.verify(self.proof.raw, policy=replace(self.policy, subject=self.b.machine_id)))

    def test_valid_untrusted_evaluator(self):
        self.assertFalse(self.verify(self.proof.raw, policy=replace(self.policy, evaluator=self.b.machine_id)))

    def test_self_issued_perfect_credential(self):
        with self.assertRaises(MytMachineError):
            replace(self.policy, evaluator=self.a.machine_id)

    def test_credential_subject_transplant(self):
        value = json.loads(self.cred.raw)
        value["claims"]["subject_machine_id"] = self.b.machine_id
        with self.assertRaises(MytMachineError):
            present_reputation_credential(
                credential=parse_disclosure(wire(value)), request=self.request, policy=self.policy,
                identity=self.b, issuer_state=self.state, backend=self.backend,
            )

    def test_presentation_subject_transplant(self):
        value = json.loads(self.proof.raw)
        value["claims"]["subject_machine_id"] = self.b.machine_id
        self.assertFalse(self.verify(wire(value)))

    def test_request_transplant(self):
        value = json.loads(self.proof.raw)
        value["request"] = json.loads(create_disclosure_request(self.policy, self.state).raw)
        self.assertFalse(self.verify(wire(value)))

    def test_replay_after_restart(self):
        self.assertTrue(self.verify(self.proof.raw))
        self.assertFalse(self.verify(self.proof.raw, store=DisclosureStore(self.state.path)))

    def test_16_processes(self):
        data = (self.proof.raw, asdict(self.policy), str(self.state.path),
                self.companion.url, str(self.companion.token))
        with ProcessPoolExecutor(max_workers=16, mp_context=multiprocessing.get_context("spawn")) as pool:
            results = list(pool.map(consume, [data] * 16))
        self.assertEqual((results.count(True), results.count(False)), (1, 15))

    def test_revoked_key(self):
        rev = revoke_bbs_key(self.evaluator, self.auth, reason="compromised")
        self.state.refresh_issuer(self.auth, expected_evaluator=self.evaluator.machine_id, revocations=[rev])
        self.assertFalse(self.verify(self.proof.raw))

    def test_stale_status(self):
        req = json.loads(self.request.raw)
        with patch("myt_machine.disclosure_store.unix_time", return_value=req["not_before"] + 301):
            self.assertFalse(self.verify(self.proof.raw))

    def test_future_request(self):
        now = json.loads(self.request.raw)["not_before"]
        with patch("myt_machine.disclosure_store.unix_time", return_value=now - 1):
            self.assertFalse(self.verify(self.proof.raw))

    def test_exact_expiry(self):
        expiry = json.loads(self.request.raw)["expires_at"]
        with patch("myt_machine.disclosure_store.unix_time", return_value=expiry):
            self.assertFalse(self.verify(self.proof.raw))

    def test_future_credential(self):
        value = json.loads(self.proof.raw)
        value["claims"]["issued_at"] += 3600
        self.assertFalse(self.verify(wire(value)))

    def test_expired_credential(self):
        value = json.loads(self.proof.raw)
        value["claims"]["expires_at"] = value["claims"]["issued_at"]
        self.assertFalse(self.verify(wire(value)))

    def test_future_authorization(self):
        value = json.loads(self.proof.raw)
        value["authorization"]["statement"]["not_before"] += 86400
        self.assertFalse(self.verify(wire(value)))

    def test_expired_authorization(self):
        value = json.loads(self.proof.raw)
        value["authorization"]["statement"]["expires_at"] = 1
        self.assertFalse(self.verify(wire(value)))

    def test_proof_mutation(self):
        value = json.loads(self.proof.raw)
        raw = bytearray(base64.urlsafe_b64decode(value["proof"] + "=="))
        raw[-1] ^= 1
        value["proof"] = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        self.assertFalse(self.verify(wire(value)))

    def test_subject_signature_mutation(self):
        value = json.loads(self.proof.raw)
        value["subject_control"]["signature"] = base64.urlsafe_b64encode(bytes(64)).decode().rstrip("=")
        self.assertFalse(self.verify(wire(value)))

    def test_malformed_bbs_key(self):
        with self.assertRaises(DisclosureBackendError):
            self.backend.call("validate-key", {"public_key": base64.urlsafe_b64encode(bytes(96)).decode().rstrip("=")})

    def test_malformed_header_direct_api(self):
        value = json.loads(self.proof.raw)
        for bad in ("", "AA==", "+/bad", "\u00e9", "raw-header\n", "A" * 12000):
            with self.subTest(case=bad[:8]), self.assertRaises(DisclosureBackendError):
                self.backend.call("verify-proof", {
                    "public_key": value["authorization"]["statement"]["bbs_public_key"],
                    "proof": value["proof"], "messages": ["myt-reputation-bbs-v1"] + ["public"] * 9 + ["true"],
                    "presentation_header": bad, "request": value["request"], "threshold": 25,
                })

    def test_secret_sentinel_cli(self):
        file = self.root / "bad.json"
        file.write_bytes(b'{"must-not-appear":1,"must-not-appear":2}\n')
        output = io.StringIO()
        self.assertEqual(main(["disclosure", "show", "--artifact-file", str(file)], stdout=output), 2)
        self.assertNotIn("must-not-appear", output.getvalue())
        self.assertNotIn(self.companion.password.read_text().strip(), output.getvalue())
        self.assertNotIn("PRIVATE KEY", output.getvalue())


for field, replacement in {
    "audience": "evil.example",
    "challenge": base64.urlsafe_b64encode(bytes(32)).decode().rstrip("="),
    "network": "mainnet", "policy_digest": "e" * 64, "threshold": 50,
    "metric_id": "accepted_attestations", "purpose": "unrelated", "version": 2,
    "expected_subject_machine_id": "myt-machine-v1:" + "a" * 52,
    "expected_issuer_key_id": "myt-bbs-key-v1:" + "e" * 64,
}.items():
    def mutation(self, k=field, v=replacement):
        value = json.loads(self.proof.raw)
        value["request"][k] = v
        self.assertFalse(self.verify(wire(value)))
    setattr(IndependentAttacks, "test_swap_" + field, mutation)


class IndependentParsers(unittest.TestCase):
    def test_invalid_artifact_encodings(self):
        for raw in (
            b"\xff", b"\xef\xbb\xbf{}\n", b'{"a":1,"a":2}\n',
            b'{"a":1,"\\u0061":2}\n', b'{"a":"\\ud800"}\n',
            b'{"a":NaN}\n', b'{"a":Infinity}\n', b'{"version":true}\n',
            b"{}\nextra", b"x" * 32769, "{}\n".encode("utf-16"),
        ):
            with self.subTest(raw=raw[:8]), self.assertRaises(MytMachineError):
                parse_disclosure(raw)

    def test_runtime_has_no_private_fixture_in_output(self):
        self.assertNotIn("PRIVATE KEY", wire({"scope": "independent-review"}).decode())


if __name__ == "__main__":
    unittest.main()
