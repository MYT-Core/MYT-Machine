import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from myt_machine.errors import InputError
from myt_machine.identity import (
    MAX_IDENTITY_CONTEXT_BYTES,
    MAX_IDENTITY_MESSAGE_BYTES,
    MachineIdentity,
    PublicMachineIdentity,
    create_signature_frame,
    decode_challenge_nonce,
    decode_public_key,
    decode_signature,
    derive_machine_id,
    encode_challenge_nonce,
    encode_public_key,
    encode_signature,
    machine_id_digest,
    validate_identity_context,
    validate_identity_message,
)

VECTOR_PATH = Path(__file__).parents[1] / "docs" / "identity-v1-test-vector.json"
VECTOR = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


def vector_identity():
    private_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(VECTOR["seed_hex"])
    )
    return MachineIdentity(private_key)


class IdentityProtocolTests(unittest.TestCase):
    def test_published_machine_id_vector(self):
        public_key = bytes.fromhex(VECTOR["public_key_hex"])
        self.assertEqual(encode_public_key(public_key), VECTOR["public_key_base64url"])
        self.assertEqual(decode_public_key(VECTOR["public_key_base64url"]), public_key)
        self.assertEqual(derive_machine_id(public_key), VECTOR["machine_id"])
        self.assertEqual(
            machine_id_digest(VECTOR["machine_id"]).hex(),
            VECTOR["machine_id_digest_hex"],
        )

    def test_published_message_frame_and_signature_vector(self):
        identity = vector_identity()
        message = bytes.fromhex(VECTOR["message_hex"])
        frame = create_signature_frame(
            identity.machine_id,
            VECTOR["message_context"],
            message,
        )
        self.assertEqual(frame.hex(), VECTOR["message_frame_hex"])
        signature = identity.sign(message, VECTOR["message_context"])
        self.assertEqual(signature.signature, VECTOR["message_signature_base64url"])
        self.assertEqual(len(decode_signature(signature.signature)), 64)

    def test_published_nonce_frame_and_signature_vector(self):
        identity = vector_identity()
        nonce = bytes.fromhex(VECTOR["nonce_hex"])
        self.assertEqual(encode_challenge_nonce(nonce), VECTOR["nonce_base64url"])
        self.assertEqual(decode_challenge_nonce(VECTOR["nonce_base64url"]), nonce)
        frame = create_signature_frame(
            identity.machine_id, VECTOR["nonce_context"], nonce
        )
        self.assertEqual(frame.hex(), VECTOR["nonce_frame_hex"])
        signature = identity.sign(nonce, VECTOR["nonce_context"])
        self.assertEqual(signature.signature, VECTOR["nonce_signature_base64url"])

    def test_machine_id_is_deterministic_and_key_specific(self):
        identity = vector_identity()
        same = vector_identity()
        other = MachineIdentity.generate()
        self.assertEqual(identity.machine_id, same.machine_id)
        self.assertNotEqual(identity.machine_id, other.machine_id)
        self.assertEqual(len(identity.machine_id), 67)

    def test_public_identity_recalculates_machine_id(self):
        public_key = bytes.fromhex(VECTOR["public_key_hex"])
        identity = PublicMachineIdentity.from_public_key(public_key)
        self.assertEqual(identity.machine_id, VECTOR["machine_id"])
        with self.assertRaises(InputError):
            PublicMachineIdentity(public_key, MachineIdentity.generate().machine_id)

    def test_public_key_encoding_is_strict_and_canonical(self):
        valid = VECTOR["public_key_base64url"]
        invalid = (
            valid + "=",
            " " + valid,
            valid[:-1],
            valid + "A",
            valid[:-1] + "+",
            "",
            None,
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(InputError):
                decode_public_key(value)
        for value in (b"", b"x" * 31, b"x" * 33, "x"):
            with self.subTest(value=value), self.assertRaises(InputError):
                encode_public_key(value)

    def test_machine_id_encoding_is_strict_and_canonical(self):
        valid = VECTOR["machine_id"]
        invalid = (
            valid.upper(),
            valid + "=",
            valid[:-1],
            valid + "a",
            valid.replace("g", "0", 1),
            "other:" + valid.split(":", 1)[1],
            "",
            None,
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(InputError):
                machine_id_digest(value)

    def test_nonce_transport_rejects_malformed_or_noncanonical_values(self):
        valid = VECTOR["nonce_base64url"]
        invalid = (
            valid + "=",
            valid + "\n",
            valid[:-1],
            valid + "A",
            valid[:-1] + "+",
            "",
            None,
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(InputError):
                decode_challenge_nonce(value)
        for nonce in (b"", b"x" * 31, b"x" * 33, bytearray(32)):
            with self.subTest(nonce=nonce), self.assertRaises(InputError):
                encode_challenge_nonce(nonce)

    def test_signature_transport_rejects_malformed_values(self):
        valid = VECTOR["message_signature_base64url"]
        for value in (valid + "=", valid[:-1], valid + "A", valid[:-1] + "+", "", None):
            with self.subTest(value=value), self.assertRaises(InputError):
                decode_signature(value)
        for signature in (b"", b"x" * 63, b"x" * 65, bytearray(64)):
            with self.subTest(signature=signature), self.assertRaises(InputError):
                encode_signature(signature)

    def test_context_validation(self):
        valid = (
            "a",
            "myt-machine/auth/v1/service.example",
            "x" * MAX_IDENTITY_CONTEXT_BYTES,
        )
        for context in valid:
            self.assertEqual(validate_identity_context(context), context)
        invalid = (
            "",
            "UPPER",
            "contains space",
            "contains@symbol",
            "umlaut-?",
            "x" * (MAX_IDENTITY_CONTEXT_BYTES + 1),
            None,
        )
        for context in invalid:
            with self.subTest(context=context), self.assertRaises(InputError):
                validate_identity_context(context)

    def test_message_validation(self):
        self.assertEqual(validate_identity_message(b"x"), b"x")
        self.assertEqual(
            validate_identity_message(b"x" * MAX_IDENTITY_MESSAGE_BYTES),
            b"x" * MAX_IDENTITY_MESSAGE_BYTES,
        )
        for message in (
            b"",
            b"x" * (MAX_IDENTITY_MESSAGE_BYTES + 1),
            "text",
            bytearray(b"x"),
        ):
            with (
                self.subTest(message_type=type(message)),
                self.assertRaises(InputError),
            ):
                validate_identity_message(message)

    def test_generic_verification_reports_signature_validity(self):
        identity = vector_identity()
        signature = identity.sign(b"hello", "myt-machine/message")
        result = identity.public_identity.verify(
            b"hello",
            "myt-machine/message",
            signature.signature,
        )
        self.assertTrue(result.valid)
        self.assertTrue(result.signature_valid)
        self.assertIsNone(result.identity_matches)
        self.assertIsNone(result.authentication_valid)

    def test_expected_machine_id_enables_authentication_result(self):
        identity = vector_identity()
        signature = identity.sign(b"hello", "myt-machine/auth/v1/example")
        matched = identity.public_identity.verify(
            b"hello",
            "myt-machine/auth/v1/example",
            signature.signature,
            expected_machine_id=identity.machine_id,
        )
        self.assertTrue(matched.valid)
        self.assertTrue(matched.signature_valid)
        self.assertTrue(matched.identity_matches)
        self.assertTrue(matched.authentication_valid)

        other_id = MachineIdentity.generate().machine_id
        mismatched = identity.public_identity.verify(
            b"hello",
            "myt-machine/auth/v1/example",
            signature.signature,
            expected_machine_id=other_id,
        )
        self.assertFalse(mismatched.valid)
        self.assertTrue(mismatched.signature_valid)
        self.assertFalse(mismatched.identity_matches)
        self.assertFalse(mismatched.authentication_valid)

    def test_modified_inputs_are_negative_results(self):
        identity = vector_identity()
        signature = identity.sign(b"hello", "myt-machine/message")
        changed_signature = bytearray(decode_signature(signature.signature))
        changed_signature[0] ^= 1
        cases = (
            (b"changed", "myt-machine/message", signature.signature),
            (b"hello", "myt-machine/other", signature.signature),
            (
                b"hello",
                "myt-machine/message",
                encode_signature(bytes(changed_signature)),
            ),
        )
        for message, context, encoded_signature in cases:
            with self.subTest(context=context):
                result = identity.public_identity.verify(
                    message, context, encoded_signature
                )
                self.assertFalse(result.valid)
                self.assertFalse(result.signature_valid)

    def test_wrong_identity_is_a_negative_result(self):
        signer = vector_identity()
        verifier = MachineIdentity.generate()
        signature = signer.sign(b"hello", "myt-machine/message")
        result = verifier.public_identity.verify(
            b"hello",
            "myt-machine/message",
            signature.signature,
        )
        self.assertFalse(result.valid)
        self.assertFalse(result.signature_valid)

    def test_malformed_expected_id_is_input_error(self):
        identity = vector_identity()
        signature = identity.sign(b"hello", "myt-machine/message")
        with self.assertRaises(InputError):
            identity.public_identity.verify(
                b"hello",
                "myt-machine/message",
                signature.signature,
                expected_machine_id="not-an-id",
            )

    def test_signatures_are_deterministic_but_do_not_return_content_fingerprints(self):
        identity = vector_identity()
        first = identity.sign(b"private low entropy message", "myt-machine/message")
        second = identity.sign(b"private low entropy message", "myt-machine/message")
        self.assertEqual(first.signature, second.signature)
        output = first.as_dict()
        self.assertNotIn("message", output)
        self.assertNotIn("message_digest", output)
        self.assertEqual(output["signature_version"], 1)

    def test_private_identity_repr_is_redacted(self):
        identity = vector_identity()
        representation = repr(identity)
        self.assertIn("private_key=<redacted>", representation)
        self.assertNotIn(VECTOR["seed_hex"], representation)


if __name__ == "__main__":
    unittest.main()
