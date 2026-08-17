import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from myt_machine.cli import main
from myt_machine.identity import MachineIdentity, encode_challenge_nonce
from myt_machine.identity_artifacts import save_public_identity
from myt_machine.identity_keys import (
    create_identity_files,
    save_private_identity,
)

PASSPHRASE_TEXT = "phase4b-cli-passphrase-123456"
PASSPHRASE = PASSPHRASE_TEXT.encode("utf-8")
VECTOR_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)


class ForbiddenRpcFactory:
    def __init__(self):
        self.calls = []

    def __call__(self, config):
        self.calls.append(config)
        raise AssertionError("Identity command attempted to create an RPC client")


def run_identity_cli(arguments, *, stdin="", environ=None, passphrase_reader=None):
    output = io.StringIO()
    factory = ForbiddenRpcFactory()
    input_stream = io.BytesIO(stdin) if isinstance(stdin, bytes) else io.StringIO(stdin)
    exit_code = main(
        arguments,
        environ={} if environ is None else environ,
        stdin=input_stream,
        stdout=output,
        client_factory=factory,
        passphrase_reader=passphrase_reader,
    )
    lines = output.getvalue().splitlines()
    if len(lines) != 1:
        raise AssertionError(f"Expected one JSON line, got {lines!r}")
    return exit_code, json.loads(lines[0]), factory


def secure_passphrase_file(root: Path, text=PASSPHRASE_TEXT):
    path = root / "passphrase"
    path.write_text(text + "\n", encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)
    return path


def create_identity(root: Path):
    private_path = root / "identity-key.pem"
    public_path = root / "identity.json"
    identity = create_identity_files(private_path, public_path, PASSPHRASE)
    return private_path, public_path, identity


def create_vector_identity(root: Path):
    private_path = root / "identity-key.pem"
    public_path = root / "identity.json"
    identity = MachineIdentity(Ed25519PrivateKey.from_private_bytes(VECTOR_SEED))
    save_private_identity(identity, private_path, PASSPHRASE)
    save_public_identity(identity.public_identity, public_path)
    return private_path, public_path, identity.public_identity


class IdentityCliTests(unittest.TestCase):
    def test_create_writes_artifacts_and_public_only_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_path = root / "key.pem"
            public_path = root / "identity.json"
            passphrase_path = secure_passphrase_file(root)
            code, payload, factory = run_identity_cli(
                [
                    "identity",
                    "create",
                    "--private-key-file",
                    str(private_path),
                    "--identity-file",
                    str(public_path),
                    "--passphrase-file",
                    str(passphrase_path),
                ]
            )
            self.assertEqual(code, 0)
            self.assertTrue(payload["success"])
            self.assertEqual(payload["command"], "identity-create")
            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(payload["algorithm"], "ed25519")
            self.assertTrue(payload["machine_id"].startswith("myt-machine-v1:"))
            self.assertNotIn("private_key", payload)
            self.assertNotIn("passphrase", json.dumps(payload))
            self.assertNotIn(str(root), json.dumps(payload))
            self.assertTrue(private_path.exists())
            self.assertTrue(public_path.exists())
            self.assertEqual(factory.calls, [])

    def test_create_can_prompt_twice_without_exposing_passphrase(self):
        prompts = []

        def reader(prompt):
            prompts.append(prompt)
            return PASSPHRASE_TEXT

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, payload, _ = run_identity_cli(
                [
                    "identity",
                    "create",
                    "--private-key-file",
                    str(root / "key.pem"),
                    "--identity-file",
                    str(root / "identity.json"),
                ],
                passphrase_reader=reader,
            )
        self.assertEqual(code, 0)
        self.assertEqual(len(prompts), 2)
        self.assertNotIn(PASSPHRASE_TEXT, json.dumps(payload))

    def test_create_rejects_mismatched_confirmation(self):
        answers = iter((PASSPHRASE_TEXT, PASSPHRASE_TEXT + "-different"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, payload, _ = run_identity_cli(
                [
                    "identity",
                    "create",
                    "--private-key-file",
                    str(root / "key.pem"),
                    "--identity-file",
                    str(root / "identity.json"),
                ],
                passphrase_reader=lambda prompt: next(answers),
            )
            self.assertEqual(code, 3)
            self.assertFalse(payload["success"])
            self.assertFalse((root / "key.pem").exists())
            self.assertFalse((root / "identity.json").exists())

    def test_noninteractive_key_operation_requires_passphrase_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, payload, _ = run_identity_cli(
                [
                    "identity",
                    "create",
                    "--private-key-file",
                    str(root / "key.pem"),
                    "--identity-file",
                    str(root / "identity.json"),
                ]
            )
        self.assertEqual(code, 3)
        self.assertEqual(payload["error"]["code"], "invalid_configuration")

    def test_invalid_signing_input_fails_before_passphrase_prompt(self):
        prompted = False

        def reader(prompt):
            nonlocal prompted
            prompted = True
            return PASSPHRASE_TEXT

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_path, public_path, _ = create_identity(root)
            code, payload, _ = run_identity_cli(
                [
                    "identity",
                    "sign",
                    "--private-key-file",
                    str(private_path),
                    "--identity-file",
                    str(public_path),
                    "--context",
                    "INVALID CONTEXT",
                    "--message",
                    "hello",
                ],
                passphrase_reader=reader,
            )
        self.assertEqual(code, 2)
        self.assertEqual(payload["error"]["code"], "invalid_input")
        self.assertFalse(prompted)

    def test_show_is_offline_and_ignores_invalid_rpc_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, public_path, identity = create_identity(root)
            code, payload, factory = run_identity_cli(
                ["identity", "show", "--identity-file", str(public_path)],
                environ={
                    "MYT_WALLET_RPC_URL": "ftp://bad.invalid",
                    "MYT_WALLET_RPC_TIMEOUT": "not-a-number",
                    "MYT_WALLET_RPC_PASSWORD": "rpc-secret-sentinel",
                },
            )
        self.assertEqual(code, 0)
        self.assertEqual(payload["machine_id"], identity.machine_id)
        self.assertNotIn("rpc-secret-sentinel", json.dumps(payload))
        self.assertEqual(factory.calls, [])

    def test_sign_and_generic_verify_roundtrip(self):
        message = "offline identity message"
        context = "myt-machine/message"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_path, public_path, identity = create_identity(root)
            passphrase_path = secure_passphrase_file(root)
            sign_code, signed, _ = run_identity_cli(
                [
                    "identity",
                    "sign",
                    "--private-key-file",
                    str(private_path),
                    "--identity-file",
                    str(public_path),
                    "--passphrase-file",
                    str(passphrase_path),
                    "--context",
                    context,
                    "--message",
                    message,
                ]
            )
            verify_code, verified, factory = run_identity_cli(
                [
                    "identity",
                    "verify",
                    "--identity-file",
                    str(public_path),
                    "--context",
                    context,
                    "--message",
                    message,
                    "--signature",
                    signed["signature"],
                ]
            )
        self.assertEqual(sign_code, 0)
        self.assertEqual(signed["machine_id"], identity.machine_id)
        self.assertNotIn("message", signed)
        self.assertNotIn("message_digest", signed)
        self.assertNotIn(message, json.dumps(signed))
        self.assertEqual(verify_code, 0)
        self.assertTrue(verified["valid"])
        self.assertTrue(verified["signature_valid"])
        self.assertIsNone(verified["identity_matches"])
        self.assertIsNone(verified["authentication_valid"])
        self.assertEqual(factory.calls, [])

    def test_expected_machine_id_distinguishes_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_path, public_path, identity = create_identity(root)
            passphrase_path = secure_passphrase_file(root)
            _, signed, _ = run_identity_cli(
                [
                    "identity",
                    "sign",
                    "--private-key-file",
                    str(private_path),
                    "--identity-file",
                    str(public_path),
                    "--passphrase-file",
                    str(passphrase_path),
                    "--context",
                    "myt-machine/auth/v1/example",
                    "--message",
                    "challenge",
                ]
            )
            code, matched, _ = run_identity_cli(
                [
                    "identity",
                    "verify",
                    "--identity-file",
                    str(public_path),
                    "--expected-machine-id",
                    identity.machine_id,
                    "--context",
                    "myt-machine/auth/v1/example",
                    "--message",
                    "challenge",
                    "--signature",
                    signed["signature"],
                ]
            )
            other_id = MachineIdentity.generate().machine_id
            mismatch_code, mismatched, _ = run_identity_cli(
                [
                    "identity",
                    "verify",
                    "--identity-file",
                    str(public_path),
                    "--expected-machine-id",
                    other_id,
                    "--context",
                    "myt-machine/auth/v1/example",
                    "--message",
                    "challenge",
                    "--signature",
                    signed["signature"],
                ]
            )
        self.assertEqual(code, 0)
        self.assertTrue(matched["authentication_valid"])
        self.assertEqual(mismatch_code, 1)
        self.assertTrue(mismatched["success"])
        self.assertTrue(mismatched["signature_valid"])
        self.assertFalse(mismatched["identity_matches"])
        self.assertFalse(mismatched["authentication_valid"])
        self.assertFalse(mismatched["valid"])

    def test_changed_message_is_negative_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_path, public_path, _ = create_identity(root)
            passphrase_path = secure_passphrase_file(root)
            _, signed, _ = run_identity_cli(
                [
                    "identity",
                    "sign",
                    "--private-key-file",
                    str(private_path),
                    "--identity-file",
                    str(public_path),
                    "--passphrase-file",
                    str(passphrase_path),
                    "--context",
                    "myt-machine/message",
                    "--message",
                    "original",
                ]
            )
            code, payload, _ = run_identity_cli(
                [
                    "identity",
                    "verify",
                    "--identity-file",
                    str(public_path),
                    "--context",
                    "myt-machine/message",
                    "--message",
                    "changed",
                    "--signature",
                    signed["signature"],
                ]
            )
        self.assertEqual(code, 1)
        self.assertTrue(payload["success"])
        self.assertFalse(payload["valid"])

    def test_nonce_mode_signs_decoded_bytes(self):
        nonce = bytes(range(32))
        encoded_nonce = encode_challenge_nonce(nonce)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_path, public_path, _ = create_identity(root)
            passphrase_path = secure_passphrase_file(root)
            _, signed, _ = run_identity_cli(
                [
                    "identity",
                    "sign",
                    "--private-key-file",
                    str(private_path),
                    "--identity-file",
                    str(public_path),
                    "--passphrase-file",
                    str(passphrase_path),
                    "--context",
                    "myt-machine/auth/v1/example",
                    "--nonce-base64url",
                    encoded_nonce,
                ]
            )
            code, verified, _ = run_identity_cli(
                [
                    "identity",
                    "verify",
                    "--identity-file",
                    str(public_path),
                    "--context",
                    "myt-machine/auth/v1/example",
                    "--message-file",
                    "-",
                    "--signature",
                    signed["signature"],
                ],
                stdin=nonce,
            )
        self.assertEqual(code, 0)
        self.assertTrue(verified["valid"])

    def test_binary_message_file_roundtrip(self):
        data = b"\x00\xffbinary\r\nbytes"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_path, public_path, _ = create_identity(root)
            passphrase_path = secure_passphrase_file(root)
            message_path = root / "message.bin"
            message_path.write_bytes(data)
            _, signed, _ = run_identity_cli(
                [
                    "identity",
                    "sign",
                    "--private-key-file",
                    str(private_path),
                    "--identity-file",
                    str(public_path),
                    "--passphrase-file",
                    str(passphrase_path),
                    "--context",
                    "myt-machine/data",
                    "--message-file",
                    str(message_path),
                ]
            )
            code, verified, _ = run_identity_cli(
                [
                    "identity",
                    "verify",
                    "--identity-file",
                    str(public_path),
                    "--context",
                    "myt-machine/data",
                    "--message-file",
                    str(message_path),
                    "--signature",
                    signed["signature"],
                ]
            )
        self.assertEqual(code, 0)
        self.assertTrue(verified["valid"])

    def test_dash_prefixed_signature_is_accepted_as_separate_argument(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_path, public_path, _ = create_vector_identity(root)
            passphrase_path = secure_passphrase_file(root)
            _, signed, _ = run_identity_cli(
                [
                    "identity",
                    "sign",
                    "--private-key-file",
                    str(private_path),
                    "--identity-file",
                    str(public_path),
                    "--passphrase-file",
                    str(passphrase_path),
                    "--context",
                    "myt-machine/test-vector/v1",
                    "--message",
                    "MYT Phase 4B deterministic vector",
                ]
            )
            self.assertTrue(signed["signature"].startswith("-"))
            code, verified, _ = run_identity_cli(
                [
                    "identity",
                    "verify",
                    "--identity-file",
                    str(public_path),
                    "--context",
                    "myt-machine/test-vector/v1",
                    "--message",
                    "MYT Phase 4B deterministic vector",
                    "--signature",
                    signed["signature"],
                ]
            )
        self.assertEqual(code, 0)
        self.assertTrue(verified["valid"])

    def test_dash_prefixed_nonce_context_and_message_are_accepted(self):
        nonce = encode_challenge_nonce(b"\xf8" + b"x" * 31)
        self.assertTrue(nonce.startswith("-"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_path, public_path, _ = create_identity(root)
            passphrase_path = secure_passphrase_file(root)
            _, nonce_signature, _ = run_identity_cli(
                [
                    "identity",
                    "sign",
                    "--private-key-file",
                    str(private_path),
                    "--identity-file",
                    str(public_path),
                    "--passphrase-file",
                    str(passphrase_path),
                    "--context",
                    "-auth",
                    "--nonce-base64url",
                    nonce,
                ]
            )
            nonce_code, nonce_result, _ = run_identity_cli(
                [
                    "identity",
                    "verify",
                    "--identity-file",
                    str(public_path),
                    "--context",
                    "-auth",
                    "--nonce-base64url",
                    nonce,
                    "--signature",
                    nonce_signature["signature"],
                ]
            )
            _, message_signature, _ = run_identity_cli(
                [
                    "identity",
                    "sign",
                    "--private-key-file",
                    str(private_path),
                    "--identity-file",
                    str(public_path),
                    "--passphrase-file",
                    str(passphrase_path),
                    "--context",
                    "myt-machine/message",
                    "--message",
                    "-leading-hyphen",
                ]
            )
            message_code, message_result, _ = run_identity_cli(
                [
                    "identity",
                    "verify",
                    "--identity-file",
                    str(public_path),
                    "--context",
                    "myt-machine/message",
                    "--message",
                    "-leading-hyphen",
                    "--signature",
                    message_signature["signature"],
                ]
            )
        self.assertEqual(nonce_code, 0)
        self.assertTrue(nonce_result["valid"])
        self.assertEqual(message_code, 0)
        self.assertTrue(message_result["valid"])

    def test_malformed_nonce_and_signature_are_input_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, public_path, _ = create_identity(root)
            cases = (
                [
                    "identity",
                    "verify",
                    "--identity-file",
                    str(public_path),
                    "--context",
                    "myt-machine/auth/v1/example",
                    "--nonce-base64url",
                    "invalid",
                    "--signature",
                    "invalid",
                ],
                [
                    "identity",
                    "verify",
                    "--identity-file",
                    str(public_path),
                    "--context",
                    "myt-machine/message",
                    "--message",
                    "hello",
                    "--signature",
                    "invalid",
                ],
            )
            for arguments in cases:
                code, payload, _ = run_identity_cli(arguments)
                self.assertEqual(code, 2)
                self.assertFalse(payload["success"])
                self.assertEqual(payload["error"]["code"], "invalid_input")

    def test_wrong_passphrase_is_redacted_configuration_error(self):
        sentinel = "wrong-secret-passphrase-98765"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_path, public_path, _ = create_identity(root)
            wrong_path = secure_passphrase_file(root, sentinel)
            code, payload, _ = run_identity_cli(
                [
                    "identity",
                    "sign",
                    "--private-key-file",
                    str(private_path),
                    "--identity-file",
                    str(public_path),
                    "--passphrase-file",
                    str(wrong_path),
                    "--context",
                    "myt-machine/message",
                    "--message",
                    "hello",
                ]
            )
        self.assertEqual(code, 3)
        self.assertFalse(payload["success"])
        self.assertNotIn(sentinel, json.dumps(payload))

    def test_private_key_must_match_public_document(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            private_path, _, _ = create_identity(first)
            _, public_path, _ = create_identity(second)
            passphrase_path = secure_passphrase_file(root)
            code, payload, _ = run_identity_cli(
                [
                    "identity",
                    "sign",
                    "--private-key-file",
                    str(private_path),
                    "--identity-file",
                    str(public_path),
                    "--passphrase-file",
                    str(passphrase_path),
                    "--context",
                    "myt-machine/message",
                    "--message",
                    "hello",
                ]
            )
        self.assertEqual(code, 3)
        self.assertFalse(payload["success"])

    def test_invalid_arguments_do_not_echo_possible_passphrase(self):
        sentinel = "do-not-print-passphrase"
        code, payload, _ = run_identity_cli(
            ["identity", "create", "--passphrase", sentinel]
        )
        self.assertEqual(code, 2)
        self.assertNotIn(sentinel, json.dumps(payload))
        self.assertEqual(payload["command"], "identity-create")


if __name__ == "__main__":
    unittest.main()
