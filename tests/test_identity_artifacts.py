import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from myt_machine.errors import ConfigurationError, InputError
from myt_machine.identity import MachineIdentity
from myt_machine.identity_artifacts import (
    MAX_IDENTITY_DOCUMENT_BYTES,
    load_public_identity,
    parse_public_identity_document,
    parse_public_identity_json,
    public_identity_document,
    save_public_identity,
    serialize_public_identity,
)

VECTOR_PATH = Path(__file__).parents[1] / "docs" / "identity-v1-test-vector.json"
VECTOR = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


def vector_public_identity():
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(VECTOR["seed_hex"]))
    return MachineIdentity(key).public_identity


class IdentityArtifactTests(unittest.TestCase):
    def test_document_and_canonical_serialization(self):
        identity = vector_public_identity()
        document = public_identity_document(identity)
        self.assertEqual(
            document,
            {
                "algorithm": "ed25519",
                "machine_id": VECTOR["machine_id"],
                "public_key": VECTOR["public_key_base64url"],
                "type": "myt-machine-identity",
                "version": 1,
            },
        )
        expected = (
            json.dumps(
                document,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
        self.assertEqual(serialize_public_identity(identity), expected)
        self.assertEqual(parse_public_identity_json(expected), identity)

    def test_reader_accepts_insignificant_json_whitespace(self):
        document = public_identity_document(vector_public_identity())
        encoded = json.dumps(document, indent=4).encode("utf-8")
        self.assertEqual(parse_public_identity_json(encoded), vector_public_identity())

    def test_exact_fields_are_required(self):
        document = public_identity_document(vector_public_identity())
        for field in tuple(document):
            changed = dict(document)
            del changed[field]
            with self.subTest(missing=field), self.assertRaises(InputError):
                parse_public_identity_document(changed)
        with self.assertRaises(InputError):
            parse_public_identity_document({**document, "future": True})

    def test_duplicate_fields_are_rejected(self):
        document = (
            serialize_public_identity(vector_public_identity()).decode("ascii").strip()
        )
        duplicate = document[:-1] + ',"version":1}'
        with self.assertRaisesRegex(InputError, "duplicate field"):
            parse_public_identity_json(duplicate.encode("ascii"))

    def test_type_version_and_algorithm_are_strict(self):
        document = public_identity_document(vector_public_identity())
        invalid = (
            {**document, "type": "other"},
            {**document, "version": 2},
            {**document, "version": True},
            {**document, "version": 1.0},
            {**document, "algorithm": "rsa"},
        )
        for changed in invalid:
            with self.subTest(changed=changed), self.assertRaises(InputError):
                parse_public_identity_document(changed)

    def test_non_string_field_names_are_rejected_by_sdk_parser(self):
        document = public_identity_document(vector_public_identity())
        document[1] = document.pop("version")
        with self.assertRaises(InputError):
            parse_public_identity_document(document)

    def test_public_key_and_machine_id_must_match(self):
        document = public_identity_document(vector_public_identity())
        other = MachineIdentity.generate().public_identity
        invalid = (
            {**document, "machine_id": other.machine_id},
            {**document, "machine_id": "invalid"},
            {**document, "public_key": "invalid"},
            {**document, "public_key": None},
        )
        for changed in invalid:
            with self.subTest(changed=changed), self.assertRaises(InputError):
                parse_public_identity_document(changed)

    def test_json_input_limits_and_encoding(self):
        invalid = (
            b"",
            b"[]",
            b"{",
            b"\xff",
            b"\xef\xbb\xbf{}",
            b"x" * (MAX_IDENTITY_DOCUMENT_BYTES + 1),
        )
        for encoded in invalid:
            with self.subTest(size=len(encoded)), self.assertRaises(InputError):
                parse_public_identity_json(encoded)

    def test_save_and_load_roundtrip(self):
        identity = vector_public_identity()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            save_public_identity(identity, path)
            self.assertEqual(load_public_identity(path), identity)
            self.assertTrue(path.read_bytes().endswith(b"\n"))
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)

    def test_save_never_overwrites(self):
        identity = vector_public_identity()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity.json"
            path.write_text("keep", encoding="utf-8")
            with self.assertRaises(ConfigurationError):
                save_public_identity(identity, path)
            self.assertEqual(path.read_text(encoding="utf-8"), "keep")

    def test_save_requires_existing_parent(self):
        identity = vector_public_identity()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing" / "identity.json"
            with self.assertRaises(ConfigurationError):
                save_public_identity(identity, path)
            self.assertFalse(path.exists())

    def test_load_rejects_missing_nonregular_and_symlink_files(self):
        identity = vector_public_identity()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(InputError):
                load_public_identity(root / "missing.json")
            with self.assertRaises(InputError):
                load_public_identity(root)

            target = root / "target.json"
            save_public_identity(identity, target)
            link = root / "link.json"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks are not available")
            with self.assertRaises(InputError):
                load_public_identity(link)

    def test_load_enforces_size_limit_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.json"
            path.write_bytes(b"x" * (MAX_IDENTITY_DOCUMENT_BYTES + 1))
            with self.assertRaises(InputError):
                load_public_identity(path)


if __name__ == "__main__":
    unittest.main()
