import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from myt_machine.binding import BINDING_CONTEXT, AddressBinding, create_binding_content
from myt_machine.binding_artifacts import load_address_binding, save_address_binding
from myt_machine.cli import main
from myt_machine.errors import RpcAuthenticationError, RpcTransportError
from myt_machine.identity import MachineIdentity
from myt_machine.identity_keys import create_identity_files

PASSPHRASE_TEXT = "phase4c-cli-passphrase-123456"
PASSPHRASE = PASSPHRASE_TEXT.encode("utf-8")
STANDARD_ADDRESS = "9" + "A" * 94
SUBADDRESS = "B" + "C" * 94
WALLET_SIGNATURE = "SigV2" + "1" * 88


def address_response(address=SUBADDRESS, index=1):
    return {
        "address": address,
        "addresses": [
            {
                "address": address,
                "label": "binding",
                "address_index": index,
                "used": False,
            }
        ],
    }


def valid_address_response(
    *, nettype="testnet", subaddress=True, integrated=False, valid=True
):
    if not valid:
        return {"valid": False}
    return {
        "valid": True,
        "integrated": integrated,
        "subaddress": subaddress,
        "nettype": nettype,
        "openalias_address": "",
    }


def wallet_verify_response(*, good=True):
    return {
        "good": good,
        "version": 2,
        "old": False,
        "signature_type": "spend",
    }


class StubClient:
    def __init__(self, responses=None):
        self.url = "http://127.0.0.1:38083"
        self.responses = {
            key: list(value) for key, value in (responses or {}).items()
        }
        self.calls = []

    def call(self, method, params=None, *, mutation=False):
        self.calls.append((method, params, mutation))
        queue = self.responses.get(method, [])
        if not queue:
            raise AssertionError(f"Unexpected RPC call: {method}")
        response = queue.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class Factory:
    def __init__(self, client=None, exception=None):
        self.client = client
        self.exception = exception
        self.configs = []

    def __call__(self, config):
        self.configs.append(config)
        if self.exception is not None:
            raise self.exception
        return self.client


class ForbiddenRpcFactory:
    def __init__(self):
        self.calls = []

    def __call__(self, config):
        self.calls.append(config)
        raise AssertionError("Offline binding command attempted to create an RPC client")


def run_cli(
    arguments,
    client=None,
    *,
    factory=None,
    environ=None,
    stdin="",
    passphrase_reader=None,
):
    output = io.StringIO()
    selected_factory = factory if factory is not None else Factory(client)
    input_stream = io.BytesIO(stdin) if isinstance(stdin, bytes) else io.StringIO(stdin)
    exit_code = main(
        arguments,
        environ={} if environ is None else environ,
        stdin=input_stream,
        stdout=output,
        client_factory=selected_factory,
        passphrase_reader=passphrase_reader,
    )
    lines = output.getvalue().splitlines()
    if len(lines) != 1:
        raise AssertionError(f"Expected one JSON line, got {lines!r}")
    return exit_code, json.loads(lines[0]), selected_factory


def create_identity_fixture(root):
    private_path = root / "machine-key.pem"
    identity_path = root / "identity.json"
    passphrase_path = root / "identity-passphrase"
    passphrase_path.write_text(PASSPHRASE_TEXT + "\n", encoding="utf-8")
    if os.name != "nt":
        passphrase_path.chmod(0o600)
    identity = create_identity_files(
        private_path,
        identity_path,
        PASSPHRASE,
    )
    return identity, private_path, identity_path, passphrase_path


def create_binding_fixture(root):
    identity = MachineIdentity.generate()
    content = create_binding_content(identity.machine_id, "testnet", SUBADDRESS)
    identity_signature = identity.sign(content, BINDING_CONTEXT)
    binding = AddressBinding(
        identity=identity.public_identity,
        network="testnet",
        address=SUBADDRESS,
        identity_signature=identity_signature.signature,
        wallet_signature=WALLET_SIGNATURE,
    )
    path = root / "binding.json"
    save_address_binding(binding, path)
    return binding, path


class BindingCliTests(unittest.TestCase):
    def test_create_writes_binding_and_returns_public_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity, key_path, identity_path, passphrase_path = (
                create_identity_fixture(root)
            )
            binding_path = root / "binding.json"
            client = StubClient(
                {
                    "get_address": [address_response()],
                    "validate_address": [valid_address_response()],
                    "sign": [{"signature": WALLET_SIGNATURE}],
                    "verify": [wallet_verify_response()],
                }
            )
            code, payload, _ = run_cli(
                [
                    "--account-index",
                    "0",
                    "--address-index",
                    "1",
                    "binding",
                    "create",
                    "--private-key-file",
                    str(key_path),
                    "--identity-file",
                    str(identity_path),
                    "--binding-file",
                    str(binding_path),
                    "--passphrase-file",
                    str(passphrase_path),
                ],
                client,
            )
            self.assertEqual(code, 0)
            self.assertTrue(payload["success"])
            self.assertEqual(payload["command"], "binding-create")
            self.assertEqual(payload["machine_id"], identity.machine_id)
            self.assertEqual(payload["address_type"], "subaddress")
            self.assertNotIn("identity_signature", payload)
            self.assertNotIn("wallet_signature", payload)
            self.assertNotIn(PASSPHRASE_TEXT, json.dumps(payload))
            binding = load_address_binding(binding_path)
            self.assertEqual(binding.machine_id, identity.machine_id)
            self.assertEqual(
                len([call for call in client.calls if call[0] == "sign"]), 1
            )
            self.assertTrue(next(call for call in client.calls if call[0] == "sign")[2])

    def test_show_is_offline_and_ignores_invalid_rpc_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            binding, path = create_binding_fixture(Path(directory))
            factory = ForbiddenRpcFactory()
            code, payload, captured = run_cli(
                ["binding", "show", "--binding-file", str(path)],
                factory=factory,
                environ={
                    "MYT_WALLET_RPC_URL": "ftp://invalid.example",
                    "MYT_WALLET_RPC_USER": "unused",
                    "MYT_WALLET_RPC_PASSWORD": "must-not-appear",
                },
            )
            self.assertEqual(code, 0)
            self.assertEqual(payload["command"], "binding-show")
            self.assertEqual(
                payload["binding"]["identity"]["machine_id"], binding.machine_id
            )
            self.assertEqual(captured.calls, [])
            self.assertNotIn("must-not-appear", json.dumps(payload))

    def test_show_reads_artifact_from_stdin(self):
        with tempfile.TemporaryDirectory() as directory:
            binding, path = create_binding_fixture(Path(directory))
            encoded = path.read_bytes()
            code, payload, _ = run_cli(
                ["binding", "show", "--binding-file", "-"],
                factory=ForbiddenRpcFactory(),
                stdin=encoded,
            )
            self.assertEqual(code, 0)
            self.assertEqual(payload["binding"], binding.as_dict())

    def test_independent_verifier_reports_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            binding, path = create_binding_fixture(Path(directory))
            client = StubClient(
                {
                    "validate_address": [
                        valid_address_response(),
                        valid_address_response(),
                    ],
                    "verify": [wallet_verify_response()],
                }
            )
            code, payload, _ = run_cli(
                [
                    "binding",
                    "verify",
                    "--binding-file",
                    str(path),
                    "--expected-machine-id",
                    binding.machine_id,
                    "--expected-network",
                    "testnet",
                ],
                client,
            )
            self.assertEqual(code, 0)
            self.assertTrue(payload["valid"])
            self.assertTrue(payload["binding_valid"])
            self.assertTrue(payload["authentication_valid"])
            self.assertEqual(payload["wallet_signature_type"], "spend")

    def test_negative_wallet_signature_is_exit_one_not_internal_error(self):
        with tempfile.TemporaryDirectory() as directory:
            _, path = create_binding_fixture(Path(directory))
            client = StubClient(
                {
                    "validate_address": [
                        valid_address_response(),
                        valid_address_response(),
                    ],
                    "verify": [wallet_verify_response(good=False)],
                }
            )
            code, payload, _ = run_cli(
                ["binding", "verify", "--binding-file", str(path)],
                client,
            )
            self.assertEqual(code, 1)
            self.assertTrue(payload["success"])
            self.assertFalse(payload["valid"])
            self.assertFalse(payload["wallet_signature_valid"])

    def test_expected_identity_and_network_mismatch_are_exit_one(self):
        with tempfile.TemporaryDirectory() as directory:
            _, path = create_binding_fixture(Path(directory))
            client = StubClient(
                {
                    "validate_address": [
                        valid_address_response(),
                        valid_address_response(),
                    ],
                    "verify": [wallet_verify_response()],
                }
            )
            code, payload, _ = run_cli(
                [
                    "binding",
                    "verify",
                    "--binding-file",
                    str(path),
                    "--expected-machine-id",
                    MachineIdentity.generate().machine_id,
                    "--expected-network",
                    "mainnet",
                ],
                client,
            )
            self.assertEqual(code, 1)
            self.assertTrue(payload["success"])
            self.assertFalse(payload["identity_matches"])
            self.assertFalse(payload["network_matches"])
            self.assertFalse(payload["authentication_valid"])

    def test_standard_address_needs_cli_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, key_path, identity_path, passphrase_path = create_identity_fixture(root)
            client = StubClient(
                {
                    "get_address": [address_response(STANDARD_ADDRESS, 0)],
                    "validate_address": [
                        valid_address_response(subaddress=False)
                    ],
                }
            )
            code, payload, _ = run_cli(
                [
                    "binding",
                    "create",
                    "--private-key-file",
                    str(key_path),
                    "--identity-file",
                    str(identity_path),
                    "--binding-file",
                    str(root / "binding.json"),
                    "--passphrase-file",
                    str(passphrase_path),
                ],
                client,
            )
            self.assertEqual(code, 3)
            self.assertEqual(payload["error"]["code"], "invalid_configuration")
            self.assertNotIn("sign", [call[0] for call in client.calls])

    def test_no_overwrite_fails_before_any_wallet_rpc(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, key_path, identity_path, passphrase_path = create_identity_fixture(root)
            binding_path = root / "binding.json"
            binding_path.write_text("keep", encoding="utf-8")
            client = StubClient()
            code, payload, _ = run_cli(
                [
                    "--address-index",
                    "1",
                    "binding",
                    "create",
                    "--private-key-file",
                    str(key_path),
                    "--identity-file",
                    str(identity_path),
                    "--binding-file",
                    str(binding_path),
                    "--passphrase-file",
                    str(passphrase_path),
                ],
                client,
            )
            self.assertEqual(code, 3)
            self.assertFalse(payload["success"])
            self.assertEqual(client.calls, [])
            self.assertEqual(binding_path.read_text(encoding="utf-8"), "keep")

    def test_sign_timeout_is_structured_secret_free_and_not_retried(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, key_path, identity_path, passphrase_path = create_identity_fixture(root)
            client = StubClient(
                {
                    "get_address": [address_response()],
                    "validate_address": [valid_address_response()],
                    "sign": [
                        RpcTransportError(
                            "Wallet RPC request timed out",
                            kind="timeout",
                            outcome_unknown=True,
                        )
                    ],
                }
            )
            code, payload, _ = run_cli(
                [
                    "--address-index",
                    "1",
                    "binding",
                    "create",
                    "--private-key-file",
                    str(key_path),
                    "--identity-file",
                    str(identity_path),
                    "--binding-file",
                    str(root / "binding.json"),
                    "--passphrase-file",
                    str(passphrase_path),
                ],
                client,
            )
            self.assertEqual(code, 4)
            self.assertTrue(payload["error"]["outcome_unknown"])
            self.assertNotIn(PASSPHRASE_TEXT, json.dumps(payload))
            self.assertEqual(
                len([call for call in client.calls if call[0] == "sign"]), 1
            )

    def test_wrong_passphrase_is_redacted_and_never_reaches_rpc(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, key_path, identity_path, _ = create_identity_fixture(root)
            wrong = "wrong-passphrase-must-not-appear"
            wrong_path = root / "wrong-passphrase"
            wrong_path.write_text(wrong + "\n", encoding="utf-8")
            if os.name != "nt":
                wrong_path.chmod(0o600)
            client = StubClient()
            code, payload, _ = run_cli(
                [
                    "--address-index",
                    "1",
                    "binding",
                    "create",
                    "--private-key-file",
                    str(key_path),
                    "--identity-file",
                    str(identity_path),
                    "--binding-file",
                    str(root / "binding.json"),
                    "--passphrase-file",
                    str(wrong_path),
                ],
                client,
            )
            self.assertEqual(code, 3)
            self.assertNotIn(wrong, json.dumps(payload))
            self.assertEqual(client.calls, [])

    def test_malformed_artifact_is_exit_two_without_wallet_call(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binding.json"
            path.write_text('{"type":"bad"}', encoding="utf-8")
            client = StubClient()
            code, payload, _ = run_cli(
                ["binding", "verify", "--binding-file", str(path)],
                client,
            )
            self.assertEqual(code, 2)
            self.assertEqual(payload["error"]["code"], "invalid_input")
            self.assertEqual(client.calls, [])

    def test_rpc_authentication_error_uses_existing_exit_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            _, path = create_binding_fixture(Path(directory))
            secret = "rpc-password-must-not-appear"
            factory = Factory(exception=RpcAuthenticationError())
            code, payload, captured = run_cli(
                ["binding", "verify", "--binding-file", str(path)],
                factory=factory,
                environ={
                    "MYT_WALLET_RPC_USER": "verifier",
                    "MYT_WALLET_RPC_PASSWORD": secret,
                },
            )
            self.assertEqual(code, 4)
            self.assertEqual(payload["error"]["code"], "rpc_authentication_failed")
            self.assertNotIn(secret, json.dumps(payload))
            self.assertNotIn(secret, repr(captured.configs[0]))


if __name__ == "__main__":
    unittest.main()
