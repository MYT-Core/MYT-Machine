import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from myt_machine.errors import ConfigurationError
from myt_machine.identity import MachineIdentity
from myt_machine.identity_artifacts import load_public_identity
from myt_machine.identity_keys import (
    MAX_PRIVATE_KEY_FILE_BYTES,
    create_identity_files,
    load_private_identity,
    passphrase_from_text,
    read_identity_passphrase_file,
    save_private_identity,
    validate_identity_passphrase,
)

VECTOR_PATH = Path(__file__).parents[1] / "docs" / "identity-v1-test-vector.json"
VECTOR = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
PASSPHRASE = b"phase4b-test-passphrase-123456"


def vector_identity():
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(VECTOR["seed_hex"]))
    return MachineIdentity(key)


def secure_write(path: Path, value: bytes) -> None:
    path.write_bytes(value)
    if os.name != "nt":
        path.chmod(0o600)


class IdentityKeyTests(unittest.TestCase):
    def test_encrypted_pkcs8_roundtrip(self):
        identity = vector_identity()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "identity-key.pem"
            save_private_identity(identity, path, PASSPHRASE)
            encoded = path.read_bytes()
            self.assertTrue(
                encoded.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
            )
            self.assertNotIn(bytes.fromhex(VECTOR["seed_hex"]), encoded)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            loaded = load_private_identity(path, PASSPHRASE)
            self.assertEqual(loaded.machine_id, identity.machine_id)

    def test_wrong_passphrase_and_corrupt_key_share_redacted_error(self):
        identity = vector_identity()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = root / "valid.pem"
            corrupt = root / "corrupt.pem"
            save_private_identity(identity, valid, PASSPHRASE)
            secure_write(corrupt, b"-----BEGIN ENCRYPTED PRIVATE KEY-----\ninvalid\n")

            messages = []
            for path, password in (
                (valid, b"different-passphrase-1234"),
                (corrupt, PASSPHRASE),
            ):
                with (
                    self.subTest(path=path),
                    self.assertRaises(ConfigurationError) as captured,
                ):
                    load_private_identity(path, password)
                messages.append(str(captured.exception))
            self.assertEqual(messages[0], messages[1])
            self.assertNotIn(PASSPHRASE.decode(), messages[0])

    def test_unencrypted_ed25519_key_is_rejected(self):
        key = Ed25519PrivateKey.generate()
        encoded = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unencrypted.pem"
            secure_write(path, encoded)
            with self.assertRaises(ConfigurationError):
                load_private_identity(path, PASSPHRASE)

    def test_encrypted_non_ed25519_key_is_rejected(self):
        key = generate_private_key(public_exponent=65537, key_size=2048)
        encoded = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(PASSPHRASE),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rsa.pem"
            secure_write(path, encoded)
            with self.assertRaises(ConfigurationError):
                load_private_identity(path, PASSPHRASE)

    def test_private_key_size_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.pem"
            secure_write(
                path,
                b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
                + b"x" * MAX_PRIVATE_KEY_FILE_BYTES,
            )
            with self.assertRaises(ConfigurationError):
                load_private_identity(path, PASSPHRASE)

    def test_private_key_must_be_regular_nonsymlink_and_mode_0600(self):
        if os.name == "nt":
            self.skipTest("Unix permission checks do not apply on Windows")
        identity = vector_identity()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.pem"
            save_private_identity(identity, target, PASSPHRASE)
            target.chmod(0o640)
            with self.assertRaises(ConfigurationError):
                load_private_identity(target, PASSPHRASE)
            target.chmod(0o600)
            link = root / "link.pem"
            link.symlink_to(target)
            with self.assertRaises(ConfigurationError):
                load_private_identity(link, PASSPHRASE)
            with self.assertRaises(ConfigurationError):
                load_private_identity(root, PASSPHRASE)

    def test_passphrase_boundaries_and_text_validation(self):
        self.assertEqual(validate_identity_passphrase(b"x" * 16), b"x" * 16)
        self.assertEqual(validate_identity_passphrase(b"x" * 1024), b"x" * 1024)
        self.assertEqual(
            passphrase_from_text("sicheres-p\u00e4sswort-123"),
            b"sicheres-p\xc3\xa4sswort-123",
        )
        invalid = (
            b"x" * 15,
            b"x" * 1025,
            b"valid-passphrase\n",
            b"valid-passphrase\r",
            b"valid-passphrase\x00",
            b"\xff" * 16,
            "not-bytes",
        )
        for value in invalid:
            with (
                self.subTest(value_type=type(value)),
                self.assertRaises(ConfigurationError),
            ):
                validate_identity_passphrase(value)

    def test_passphrase_file_accepts_lf_and_crlf(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, ending in enumerate((b"\n", b"\r\n")):
                path = root / f"pass-{index}"
                secure_write(path, PASSPHRASE + ending)
                self.assertEqual(read_identity_passphrase_file(path), PASSPHRASE)

    def test_passphrase_file_rejects_embedded_lines_and_nul(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = (
                PASSPHRASE + b"\nsecond",
                PASSPHRASE + b"\r",
                PASSPHRASE + b"\x00",
                b"short\n",
            )
            for index, value in enumerate(values):
                path = root / f"pass-{index}"
                secure_write(path, value)
                with self.subTest(index=index), self.assertRaises(ConfigurationError):
                    read_identity_passphrase_file(path)

    def test_passphrase_file_security_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ConfigurationError):
                read_identity_passphrase_file(root / "missing")
            if os.name != "nt":
                insecure = root / "insecure"
                secure_write(insecure, PASSPHRASE)
                insecure.chmod(0o644)
                with self.assertRaises(ConfigurationError):
                    read_identity_passphrase_file(insecure)
                target = root / "target"
                secure_write(target, PASSPHRASE)
                link = root / "link"
                link.symlink_to(target)
                with self.assertRaises(ConfigurationError):
                    read_identity_passphrase_file(link)

    def test_save_never_overwrites_or_creates_parent(self):
        identity = vector_identity()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = root / "existing.pem"
            existing.write_bytes(b"keep")
            with self.assertRaises(ConfigurationError):
                save_private_identity(identity, existing, PASSPHRASE)
            self.assertEqual(existing.read_bytes(), b"keep")
            missing = root / "missing" / "key.pem"
            with self.assertRaises(ConfigurationError):
                save_private_identity(identity, missing, PASSPHRASE)
            self.assertFalse(missing.exists())

    def test_create_identity_files_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_path = root / "key.pem"
            public_path = root / "identity.json"
            public_identity = create_identity_files(
                private_path, public_path, PASSPHRASE
            )
            self.assertEqual(
                load_private_identity(private_path, PASSPHRASE).public_identity,
                public_identity,
            )
            self.assertEqual(load_public_identity(public_path), public_identity)

    def test_create_requires_distinct_nonexisting_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            same = root / "same"
            with self.assertRaises(ConfigurationError):
                create_identity_files(same, same, PASSPHRASE)

            existing = root / "existing"
            existing.write_bytes(b"keep")
            with self.assertRaises(ConfigurationError):
                create_identity_files(root / "key.pem", existing, PASSPHRASE)
            self.assertFalse((root / "key.pem").exists())
            self.assertEqual(existing.read_bytes(), b"keep")

    def test_create_rolls_back_private_key_when_public_write_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_path = root / "key.pem"
            public_path = root / "identity.json"
            with (
                mock.patch(
                    "myt_machine.identity_keys.save_public_identity",
                    side_effect=ConfigurationError("simulated public write failure"),
                ),
                self.assertRaises(ConfigurationError),
            ):
                create_identity_files(private_path, public_path, PASSPHRASE)
            self.assertFalse(private_path.exists())
            self.assertFalse(public_path.exists())


if __name__ == "__main__":
    unittest.main()
