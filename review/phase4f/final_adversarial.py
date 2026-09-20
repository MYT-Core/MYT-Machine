"""Final separate adversarial gate; valid signatures on hostile statements."""
import base64
import http.client
import json
import unittest
from urllib.parse import urlsplit

import attack_candidate as setup

from myt_machine.disclosure import present_reputation_credential
from myt_machine.disclosure_artifacts import (
    AUTH,
    credential_messages,
    parse_disclosure,
    sign_statement,
    verify_statement,
)
from myt_machine.disclosure_store import DisclosureStore
from myt_machine.errors import MytMachineError
from myt_machine.payment_requests import unix_time


class FinalAttacks(setup.IndependentAttacks):
    def signed_auth(self, start, end):
        value = json.loads(self.auth.raw)["statement"]
        value.update(not_before=start, expires_at=end)
        auth = sign_statement(self.evaluator, AUTH, value)
        verify_statement(json.loads(auth.raw), self.evaluator.machine_id)
        return auth

    def signed_credential(self, value):
        params = {
            "public_key": value["authorization"]["statement"]["bbs_public_key"],
            "messages": credential_messages(value),
        }
        value["signature"] = self.backend.call("sign", params)["signature"]
        self.assertEqual(self.backend.call("verify-signature", {
            **params, "signature": value["signature"],
        }), {"valid": True})
        return parse_disclosure(setup.wire(value))

    def reject_credential(self, credential):
        with self.assertRaises(MytMachineError):
            present_reputation_credential(
                credential=credential, request=self.request, policy=self.policy,
                identity=self.a, issuer_state=self.state, backend=self.backend,
            )

    def test_final_valid_future_authorization(self):
        now = unix_time()
        auth = self.signed_auth(now + 30, now + 300)
        with self.assertRaises(MytMachineError):
            DisclosureStore(self.root / "future").refresh_issuer(
                auth, expected_evaluator=self.evaluator.machine_id,
            )

    def test_final_valid_expired_authorization(self):
        now = unix_time()
        auth = self.signed_auth(now - 300, now - 1)
        with self.assertRaises(MytMachineError):
            DisclosureStore(self.root / "expired").refresh_issuer(
                auth, expected_evaluator=self.evaluator.machine_id,
            )

    def test_final_valid_future_credential(self):
        value = json.loads(self.cred.raw)
        now = unix_time()
        value["claims"].update(issued_at=now + 30, as_of=now + 30, expires_at=now + 100)
        self.reject_credential(self.signed_credential(value))

    def test_final_valid_expired_credential(self):
        now = unix_time()
        auth = self.signed_auth(now - 300, now + 300)
        self.state.refresh_issuer(auth, expected_evaluator=self.evaluator.machine_id)
        value = json.loads(self.cred.raw)
        value["authorization"] = json.loads(auth.raw)
        value["claims"].update(issued_at=now - 20, as_of=now - 20, expires_at=now - 1)
        self.reject_credential(self.signed_credential(value))

    def test_final_valid_credential_for_other_subject(self):
        value = json.loads(self.cred.raw)
        value["claims"]["subject_machine_id"] = self.b.machine_id
        self.reject_credential(self.signed_credential(value))

    def test_final_valid_false_predicate_cannot_be_disclosed(self):
        value = json.loads(self.cred.raw)
        value["claims"]["predicates"][2] = False
        self.reject_credential(self.signed_credential(value))

    def test_final_authenticated_parser_differential(self):
        port = urlsplit(self.companion.url).port
        token = self.companion.token.read_text().strip()
        raw = b'{"id":"00000000000000000000000000000000","operation":"hello","params":{},"version":1,"version":1}\n'
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            conn.request("POST", "/v1", body=raw, headers={
                "Content-Type": "application/json", "Authorization": "Bearer " + token,
            })
            response = conn.getresponse()
            body = response.read(32769)
            self.assertEqual(response.status, 400)
            self.assertNotIn(token.encode(), body)
            self.assertNotIn(self.companion.password.read_text().strip().encode(), body)
        finally:
            conn.close()

    def test_final_invalid_capability_rejected_without_leak(self):
        port = urlsplit(self.companion.url).port
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            conn.request("POST", "/v1", body=b"{}\n", headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer must-not-appear",
            })
            response = conn.getresponse()
            body = response.read(32769)
            self.assertEqual(response.status, 400)
            self.assertNotIn(b"must-not-appear", body)
        finally:
            conn.close()

    def test_final_public_header_vector_is_not_raw_base64_text(self):
        value = json.loads(self.proof.raw)
        request = value["request"]
        header = b"MYT-REPUTATION-DISCLOSURE-PRESENTATION-V1\n" + setup.wire(request)[:-1]
        encoded = base64.urlsafe_b64encode(header).decode().rstrip("=")
        from myt_machine.disclosure_artifacts import base_messages
        result = self.backend.call("verify-proof", {
            "public_key": value["authorization"]["statement"]["bbs_public_key"],
            "proof": value["proof"],
            "messages": base_messages(value["authorization"], value["claims"]) + ["true"],
            "request": request, "threshold": 25, "presentation_header": encoded,
        })
        self.assertEqual(result, {"valid": True})


if __name__ == "__main__":
    names = sorted(name for name in FinalAttacks.__dict__ if name.startswith("test_final_"))
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(FinalAttacks(name) for name in names))
    raise SystemExit(not result.wasSuccessful())
