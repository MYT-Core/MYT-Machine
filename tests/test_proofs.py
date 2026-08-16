import io
import json
import tempfile
import unittest
from pathlib import Path

from myt_machine.errors import InputError
from myt_machine.proofs import (
    MAX_PROOF_FILE_BYTES,
    create_proof_artifact,
    load_proof_artifact,
    parse_proof_artifact,
)

TXID = "ab" * 32
ADDRESS = "4" + "A" * 94
PROOF = "OutProofV2" + "x" * 64


class ProofArtifactTests(unittest.TestCase):
    def test_create_and_parse_artifact(self):
        artifact = create_proof_artifact(TXID.upper(), ADDRESS, "invoice-42", PROOF)
        self.assertEqual(
            artifact,
            {
                "type": "myt-payment-proof",
                "version": 1,
                "txid": TXID,
                "address": ADDRESS,
                "message": "invoice-42",
                "proof": PROOF,
            },
        )
        self.assertEqual(parse_proof_artifact({**artifact, "future": True}), artifact)

    def test_invalid_type_and_version(self):
        artifact = create_proof_artifact(TXID, ADDRESS, "", PROOF)
        for changed in (
            {**artifact, "type": "other"},
            {**artifact, "version": 2},
            {**artifact, "version": True},
        ):
            with self.subTest(changed=changed), self.assertRaises(InputError):
                parse_proof_artifact(changed)

    def test_missing_fields(self):
        artifact = create_proof_artifact(TXID, ADDRESS, "", PROOF)
        for field in ("txid", "address", "message", "proof"):
            changed = dict(artifact)
            del changed[field]
            with self.subTest(field=field), self.assertRaises(InputError):
                parse_proof_artifact(changed)

    def test_malformed_field_values(self):
        artifact = create_proof_artifact(TXID, ADDRESS, "", PROOF)
        invalid = (
            {**artifact, "txid": "no"},
            {**artifact, "address": "bad address"},
            {**artifact, "message": None},
            {**artifact, "proof": ""},
        )
        for changed in invalid:
            with self.subTest(changed=changed), self.assertRaises(InputError):
                parse_proof_artifact(changed)

    def test_load_from_stdin(self):
        artifact = create_proof_artifact(TXID, ADDRESS, "", PROOF)
        loaded = load_proof_artifact("-", io.StringIO(json.dumps(artifact)))
        self.assertEqual(loaded, artifact)

    def test_load_from_file(self):
        artifact = create_proof_artifact(TXID, ADDRESS, "hello", PROOF)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            path.write_text(json.dumps(artifact), encoding="utf-8")
            loaded = load_proof_artifact(str(path), io.StringIO())
        self.assertEqual(loaded, artifact)

    def test_invalid_json_and_utf8(self):
        with self.assertRaises(InputError):
            load_proof_artifact("-", io.StringIO("{"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proof.json"
            path.write_bytes(b"\xff")
            with self.assertRaises(InputError):
                load_proof_artifact(str(path), io.StringIO())

    def test_file_size_limit(self):
        oversized = io.StringIO("x" * (MAX_PROOF_FILE_BYTES + 1))
        with self.assertRaises(InputError):
            load_proof_artifact("-", oversized)

    def test_missing_file(self):
        with self.assertRaises(InputError):
            load_proof_artifact("/definitely/missing/proof.json", io.StringIO())


if __name__ == "__main__":
    unittest.main()
