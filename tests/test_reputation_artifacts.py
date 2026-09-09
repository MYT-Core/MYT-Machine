import dataclasses
import hashlib
import json
import unittest
from pathlib import Path

from reputation_fakes import ISSUER, OTHER, SEED, SUBJECT, attest

from myt_machine.errors import InputError
from myt_machine.identity import create_signature_frame
from myt_machine.payment_requests import MAX_TIMESTAMP, canonical_json
from myt_machine.reputation import (
    MAX_REPUTATION_BYTES,
    ReputationArtifact,
    create_revocation,
    parse_reputation_artifact,
)


class ReputationArtifactTests(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(
            attest().verify(
                expected_network="testnet", expected_issuer=ISSUER.machine_id
            )
        )

    def test_offline_no_rpc(self):
        self.assertTrue(parse_reputation_artifact(attest().encoded).verify())

    def test_deterministic(self):
        self.assertEqual(attest(), attest())

    def test_transport_variants(self):
        a = attest()
        self.assertEqual(
            parse_reputation_artifact(json.dumps(a.as_dict(), indent=4)), a
        )
        self.assertEqual(parse_reputation_artifact(a.encoded.encode() + b"\n"), a)

    def test_immutable(self):
        a = attest()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            a.encoded = "bad"
        d = a.as_dict()
        d["statement"]["outcome"] = "NEGATIVE"
        self.assertEqual(a.statement["outcome"], "POSITIVE")

    def test_wrong_network(self):
        self.assertFalse(attest().verify(expected_network="mainnet"))

    def test_wrong_expected_issuer(self):
        self.assertFalse(attest().verify(expected_issuer=OTHER.machine_id))

    def test_self_rejected(self):
        with self.assertRaises(InputError):
            attest(subject_machine_id=ISSUER.machine_id)

    def test_wrong_signature(self):
        d = attest().as_dict()
        d["signature"] = OTHER.sign(
            attest().canonical_content, "myt-machine/reputation-attestation/v1"
        ).signature
        self.assertFalse(ReputationArtifact(canonical_json(d)).verify())

    def test_wrong_context(self):
        d = attest().as_dict()
        d["signature"] = ISSUER.sign(
            attest().canonical_content, "myt-machine/wrong/v1"
        ).signature
        self.assertFalse(ReputationArtifact(canonical_json(d)).verify())

    def test_every_statement_field_authenticated(self):
        for field, changed in {
            "subject_machine_id": OTHER.machine_id,
            "network": "mainnet",
            "issued_at": 1001,
            "category": "OTHER",
            "outcome": "NEGATIVE",
            "evidence_digest": "ab" * 32,
        }.items():
            with self.subTest(field=field):
                d = attest().as_dict()
                d["statement"][field] = changed
                with self.assertRaises(InputError):
                    ReputationArtifact(canonical_json(d))
                body = {k: d[k] for k in ("type", "version", "issuer", "statement")}
                d["id"] = (
                    "myt-reputation-v1:"
                    + hashlib.sha256(
                        b"MYT-REPUTATION-ATTESTATION-V1\n"
                        + canonical_json(body).encode()
                    ).hexdigest()
                )
                if field == "category":
                    with self.assertRaises(InputError):
                        ReputationArtifact(canonical_json(d))
                else:
                    self.assertFalse(ReputationArtifact(canonical_json(d)).verify())

    def test_id_cannot_be_rechosen(self):
        d = attest().as_dict()
        d["id"] = "myt-reputation-v1:" + "01" * 32
        with self.assertRaises(InputError):
            ReputationArtifact(canonical_json(d))

    def test_identity_key_mismatch(self):
        d = attest().as_dict()
        d["issuer"]["machine_id"] = OTHER.machine_id
        with self.assertRaises(InputError):
            ReputationArtifact(canonical_json(d))

    def test_missing_unknown_fields_at_all_levels(self):
        for level in (None, "issuer", "statement"):
            for operation in ("missing", "unknown"):
                d = attest().as_dict()
                target = d if level is None else d[level]
                if operation == "missing":
                    target.pop(next(iter(target)))
                else:
                    target["must-not-appear"] = "secret-sentinel"
                with (
                    self.subTest(level=level, operation=operation),
                    self.assertRaises(InputError) as caught,
                ):
                    ReputationArtifact(canonical_json(d))
                self.assertNotIn("must-not-appear", str(caught.exception))

    def test_duplicate_keys(self):
        for old, new in (
            ('"version":1', '"version":1,"version":1'),
            ('"issued_at":1000', '"issued_at":1000,"issued_at":1000'),
        ):
            with self.assertRaises(InputError):
                parse_reputation_artifact(attest().encoded.replace(old, new))

    def test_bool_int_floats_nonfinite(self):
        for token in ("true", "false", "1.0", "1e3", "NaN", "Infinity", "-Infinity"):
            with self.subTest(token=token), self.assertRaises(InputError):
                parse_reputation_artifact(
                    attest().encoded.replace('"issued_at":1000', '"issued_at":' + token)
                )

    def test_bad_utf8_bom_empty_oversized_nested(self):
        for value in (
            b"\xff",
            b"\xef\xbb\xbf" + attest().encoded.encode(),
            b"",
            b" " * (MAX_REPUTATION_BYTES + 1),
            b"[" * 1000 + b"]" * 1000,
        ):
            with self.subTest(length=len(value)), self.assertRaises(InputError):
                parse_reputation_artifact(value)

    def test_invalid_machine_ids(self):
        for value in (
            True,
            {},
            "bad",
            SUBJECT.machine_id + "=",
            SUBJECT.machine_id.upper(),
            "\x00",
        ):
            with self.subTest(value=value), self.assertRaises(InputError):
                attest(subject_machine_id=value)

    def test_enums_and_control_characters(self):
        for field, value in (
            ("outcome", "positive"),
            ("outcome", "POSITIVE\n"),
            ("network", "testnet\x00"),
            ("network", {}),
        ):
            with self.subTest(field=field), self.assertRaises(InputError):
                attest(**{field: value})

    def test_evidence_digest_bounds(self):
        for value in ("", "AB" * 32, "ab" * 31, "ab" * 33, {}, True):
            with self.subTest(value=value), self.assertRaises(InputError):
                attest(evidence=value)

    def test_timestamp_boundaries(self):
        for value in (0, MAX_TIMESTAMP):
            self.assertTrue(attest(issued_at=value).verify())
        for value in (-1, MAX_TIMESTAMP + 1, True, 1.0):
            with self.assertRaises(InputError):
                attest(issued_at=value)

    def test_signature_canonical(self):
        for value in ("", "A" * 86 + "=", "A" * 85 + "B", True):
            d = attest().as_dict()
            d["signature"] = value
            with self.assertRaises(InputError):
                ReputationArtifact(canonical_json(d))

    def test_revocation_authorized(self):
        rev = create_revocation(ISSUER, attest(), issued_at=1001)
        self.assertTrue(rev.verify())
        self.assertEqual(rev.statement["attestation_id"], attest().id)

    def test_revocation_wrong_issuer(self):
        with self.assertRaises(InputError):
            create_revocation(OTHER, attest(), issued_at=1001)

    def test_revocation_cannot_target_revocation(self):
        rev = create_revocation(ISSUER, attest(), issued_at=1001)
        with self.assertRaises(InputError):
            create_revocation(ISSUER, rev, issued_at=1002)

    def test_vector(self):
        path = (
            Path(__file__).resolve().parents[1]
            / "docs/reputation-attestation-v1-test-vector.json"
        )
        vector = json.loads(path.read_text())
        self.assertEqual(vector["test_only_seed_hex"], SEED.hex())
        a = attest()
        self.assertEqual(vector["artifact"], a.as_dict())
        self.assertEqual(vector["canonical_content_hex"], a.canonical_content.hex())
        frame = create_signature_frame(
            ISSUER.machine_id,
            "myt-machine/reputation-attestation/v1",
            a.canonical_content,
        )
        self.assertEqual(vector["phase4b_frame_hex"], frame.hex())
        self.assertEqual(vector["artifact_digest"], a.digest)
        self.assertEqual(
            vector["revocation"], create_revocation(ISSUER, a, issued_at=1001).as_dict()
        )


if __name__ == "__main__":
    unittest.main()
