import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from myt_machine.binding import BINDING_CONTEXT, AddressBinding, create_binding_content
from myt_machine.binding_artifacts import (
    MAX_BINDING_ARTIFACT_BYTES,
    _parse_address_binding_json,
    ensure_binding_output_available,
    load_address_binding,
    parse_address_binding,
    save_address_binding,
    serialize_address_binding,
)
from myt_machine.errors import ConfigurationError, InputError
from myt_machine.identity import MachineIdentity

VECTOR_PATH = Path(__file__).parents[1] / "docs" / "identity-v1-test-vector.json"
VECTOR = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
ADDRESS = "B" + "C" * 94
WALLET_SIGNATURE = "SigV2" + "1" * 88


def vector_identity():
    private_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(VECTOR["seed_hex"])
    )
    return MachineIdentity(private_key)


def binding_fixture():
    identity = vector_identity()
    content = create_binding_content(identity.machine_id, "testnet", ADDRESS)
    signature = identity.sign(content, BINDING_CONTEXT)
    return AddressBinding(
        identity=identity.public_identity,
        network="testnet",
        address=ADDRESS,
        identity_signature=signature.signature,
        wallet_signature=WALLET_SIGNATURE,
    )


class BindingArtifactTests(unittest.TestCase):
    def test_schema_and_canonical_serialization_are_exact(self):
        binding = binding_fixture()
        document = binding.as_dict()
        self.assertEqual(
            set(document),
            {
                "address",
                "identity",
                "identity_signature",
                "network",
                "type",
                "version",
                "wallet_signature",
            },
        )
        self.assertEqual(
            set(document["identity"]),
            {"algorithm", "machine_id", "public_key", "type", "version"},
        )
        encoded = serialize_address_binding(binding)
        expected = (
            json.dumps(
                document,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
        self.assertEqual(encoded, expected)
        self.assertEqual(_parse_address_binding_json(encoded), binding)

    def test_artifact_contains_no_unapproved_metadata_or_secret_fields(self):
        document = binding_fixture().as_dict()
        encoded = serialize_address_binding(binding_fixture()).decode("ascii")
        forbidden = {
            "timestamp",
            "created_at",
            "expires_at",
            "nonce",
            "scope",
            "purpose",
            "private_key",
            "passphrase",
            "seed",
            "wallet_password",
        }
        self.assertTrue(forbidden.isdisjoint(document))
        for field in forbidden:
            self.assertNotIn(f'"{field}"', encoded)

    def test_reader_accepts_insignificant_json_whitespace(self):
        document = binding_fixture().as_dict()
        encoded = json.dumps(document, indent=2).encode("utf-8")
        self.assertEqual(_parse_address_binding_json(encoded), binding_fixture())

    def test_exact_top_level_fields_are_required(self):
        document = binding_fixture().as_dict()
        for field in tuple(document):
            changed = dict(document)
            del changed[field]
            with self.subTest(missing=field), self.assertRaises(InputError):
                parse_address_binding(changed)
        with self.assertRaises(InputError):
            parse_address_binding({**document, "future": True})

    def test_embedded_identity_schema_remains_strict(self):
        document = binding_fixture().as_dict()
        changed = dict(document)
        changed["identity"] = {**document["identity"], "future": True}
        with self.assertRaises(InputError):
            parse_address_binding(changed)

    def test_duplicate_top_level_and_nested_fields_are_rejected(self):
        encoded = serialize_address_binding(binding_fixture()).decode("ascii").strip()
        top_duplicate = encoded[:-1] + ',"version":1}'
        nested_duplicate = encoded.replace(
            '"algorithm":"ed25519"',
            '"algorithm":"ed25519","algorithm":"ed25519"',
            1,
        )
        for value in (top_duplicate, nested_duplicate):
            with self.subTest(value=value[:80]), self.assertRaisesRegex(
                InputError, "duplicate field"
            ):
                _parse_address_binding_json(value.encode("ascii"))

    def test_type_version_network_address_and_signatures_are_strict(self):
        document = binding_fixture().as_dict()
        invalid = (
            {**document, "type": "other"},
            {**document, "version": 2},
            {**document, "version": True},
            {**document, "version": 1.0},
            {**document, "network": "devnet"},
            {**document, "address": "not an address"},
            {**document, "identity_signature": "not-base64url"},
            {**document, "wallet_signature": "SigV1invalid"},
        )
        for changed in invalid:
            with self.subTest(changed=changed), self.assertRaises(InputError):
                parse_address_binding(changed)

    def test_non_string_sdk_field_names_are_rejected(self):
        document = binding_fixture().as_dict()
        document[1] = document.pop("version")
        with self.assertRaises(InputError):
            parse_address_binding(document)

    def test_json_encoding_size_and_constants_are_strict(self):
        valid = serialize_address_binding(binding_fixture())
        nonstandard = valid.replace(
            b'"version":1,"wallet_signature"',
            b'"version":NaN,"wallet_signature"',
        )
        invalid = (
            b"",
            b"[]",
            b"{",
            b"\xff",
            b"\xef\xbb\xbf{}",
            nonstandard,
            b"x" * (MAX_BINDING_ARTIFACT_BYTES + 1),
        )
        for encoded in invalid:
            with self.subTest(size=len(encoded)), self.assertRaises(InputError):
                _parse_address_binding_json(encoded)

    def test_save_load_roundtrip_and_unix_mode(self):
        binding = binding_fixture()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binding.json"
            save_address_binding(binding, path)
            self.assertEqual(load_address_binding(path), binding)
            self.assertTrue(path.read_bytes().endswith(b"\n"))
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_load_supports_binary_and_text_stdin(self):
        binding = binding_fixture()
        encoded = serialize_address_binding(binding)
        self.assertEqual(load_address_binding("-", io.BytesIO(encoded)), binding)
        self.assertEqual(
            load_address_binding("-", io.StringIO(encoded.decode("ascii"))),
            binding,
        )

    def test_save_never_overwrites_existing_file_or_symlink(self):
        binding = binding_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "binding.json"
            target.write_text("keep", encoding="utf-8")
            with self.assertRaises(ConfigurationError):
                save_address_binding(binding, target)
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")

            link = root / "binding-link.json"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                return
            with self.assertRaises(ConfigurationError):
                save_address_binding(binding, link)
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")

    def test_save_requires_real_file_path_and_existing_parent(self):
        binding = binding_fixture()
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing" / "binding.json"
            with self.assertRaises(ConfigurationError):
                save_address_binding(binding, missing)
            self.assertFalse(missing.exists())
        with self.assertRaises(ConfigurationError):
            ensure_binding_output_available("-")

    def test_load_rejects_missing_directory_and_symlink(self):
        binding = binding_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(InputError):
                load_address_binding(root / "missing.json")
            with self.assertRaises(InputError):
                load_address_binding(root)

            target = root / "binding.json"
            save_address_binding(binding, target)
            link = root / "binding-link.json"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks are not available")
            with self.assertRaises(InputError):
                load_address_binding(link)

    def test_load_enforces_size_limit_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.json"
            path.write_bytes(b"x" * (MAX_BINDING_ARTIFACT_BYTES + 1))
            with self.assertRaises(InputError):
                load_address_binding(path)


if __name__ == "__main__":
    unittest.main()
