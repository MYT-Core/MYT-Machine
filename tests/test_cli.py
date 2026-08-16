import io
import json
import tempfile
import unittest
from pathlib import Path

from myt_machine.cli import main
from myt_machine.errors import RpcAuthenticationError, WalletRpcError

TXID = "ab" * 32
ADDRESS = "4" + "A" * 94


class StubClient:
    def __init__(self, responses=None, url="http://127.0.0.1:39083"):
        self.url = url
        self.responses = {key: list(value) for key, value in (responses or {}).items()}
        self.calls = []

    def call(self, method, params=None, *, mutation=False):
        self.calls.append((method, params, mutation))
        queue = self.responses.get(method, [])
        if not queue:
            raise AssertionError(f"Unexpected RPC call: {method}")
        result = queue.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class Factory:
    def __init__(self, client=None, exception=None):
        self.client = client
        self.exception = exception
        self.configs = []

    def __call__(self, config):
        self.configs.append(config)
        if self.exception:
            raise self.exception
        return self.client


def valid_address_response():
    return {
        "valid": True,
        "integrated": False,
        "subaddress": False,
        "nettype": "testnet",
        "openalias_address": "",
    }


def run_cli(arguments, client, *, environ=None, stdin=""):
    output = io.StringIO()
    factory = client if isinstance(client, Factory) else Factory(client=client)
    exit_code = main(
        arguments,
        environ={} if environ is None else environ,
        stdin=io.StringIO(stdin),
        stdout=output,
        client_factory=factory,
    )
    lines = output.getvalue().splitlines()
    if len(lines) != 1:
        raise AssertionError(f"Expected one JSON line, got {lines!r}")
    return exit_code, json.loads(lines[0]), factory


class CliTests(unittest.TestCase):
    def test_balance_outputs_one_json_document(self):
        client = StubClient(
            {
                "get_balance": [
                    {
                        "balance": 1_000_000_001,
                        "unlocked_balance": 1_000_000_000,
                        "blocks_to_unlock": 0,
                        "time_to_unlock": 0,
                    }
                ]
            }
        )
        code, payload, _ = run_cli(["balance"], client)
        self.assertEqual(code, 0)
        self.assertTrue(payload["success"])
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["command"], "balance")
        self.assertEqual(payload["total"]["myt"], "1.000000001")

    def test_invalid_amount_returns_input_error_without_rpc(self):
        client = StubClient()
        code, payload, _ = run_cli(
            ["pay", "--address", ADDRESS, "--amount", "1e3"],
            client,
        )
        self.assertEqual(code, 2)
        self.assertFalse(payload["success"])
        self.assertEqual(payload["error"]["code"], "invalid_input")
        self.assertEqual(client.calls, [])

    def test_invalid_arguments_do_not_echo_possible_secret(self):
        secret = "do-not-print-this-password"
        code, payload, _ = run_cli(
            ["--rpc-password", secret, "balance"],
            StubClient(),
        )
        self.assertEqual(code, 2)
        self.assertNotIn(secret, json.dumps(payload))
        self.assertEqual(payload["error"]["message"], "Invalid command-line arguments; use --help for usage")

    def test_auth_failure_does_not_expose_environment_password(self):
        secret = "environment-secret"
        factory = Factory(exception=RpcAuthenticationError())
        code, payload, captured = run_cli(
            ["balance"],
            factory,
            environ={
                "MYT_WALLET_RPC_USER": "agent",
                "MYT_WALLET_RPC_PASSWORD": secret,
            },
        )
        self.assertEqual(code, 4)
        self.assertEqual(payload["error"]["code"], "rpc_authentication_failed")
        self.assertNotIn(secret, json.dumps(payload))
        self.assertNotIn(secret, repr(captured.configs[0]))

    def test_cli_configuration_precedes_environment(self):
        client = StubClient(
            {
                "get_balance": [
                    {
                        "balance": 0,
                        "unlocked_balance": 0,
                        "blocks_to_unlock": 0,
                        "time_to_unlock": 0,
                    }
                ]
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            password_file = Path(directory) / "rpc-password"
            password_file.write_text("file-secret\n", encoding="utf-8")
            code, _, factory = run_cli(
                [
                    "--rpc-url",
                    "http://127.0.0.1:38083",
                    "--rpc-user",
                    "cli-user",
                    "--rpc-password-file",
                    str(password_file),
                    "--timeout",
                    "7",
                    "balance",
                ],
                client,
                environ={
                    "MYT_WALLET_RPC_URL": "http://127.0.0.1:39999",
                    "MYT_WALLET_RPC_USER": "env-user",
                    "MYT_WALLET_RPC_PASSWORD": "env-secret",
                    "MYT_WALLET_RPC_TIMEOUT": "9",
                },
            )
        self.assertEqual(code, 0)
        config = factory.configs[0]
        self.assertEqual(config.url, "http://127.0.0.1:38083")
        self.assertEqual(config.username, "cli-user")
        self.assertEqual(config.password, "file-secret")
        self.assertEqual(config.timeout, 7)

    def test_empty_cli_value_does_not_fall_back_to_environment(self):
        code, payload, factory = run_cli(
            ["--rpc-url", "", "balance"],
            StubClient(),
            environ={"MYT_WALLET_RPC_URL": "http://127.0.0.1:38083"},
        )
        self.assertEqual(code, 3)
        self.assertEqual(payload["error"]["code"], "invalid_configuration")
        self.assertEqual(factory.configs, [])

    def test_empty_password_file_does_not_fall_back_to_environment(self):
        secret = "environment-secret"
        code, payload, factory = run_cli(
            ["--rpc-user", "agent", "--rpc-password-file", "", "balance"],
            StubClient(),
            environ={
                "MYT_WALLET_RPC_USER": "agent",
                "MYT_WALLET_RPC_PASSWORD": secret,
            },
        )
        self.assertEqual(code, 3)
        self.assertEqual(payload["error"]["code"], "invalid_configuration")
        self.assertNotIn(secret, json.dumps(payload))
        self.assertEqual(factory.configs, [])

    def test_payment_not_found_is_negative_result(self):
        client = StubClient(
            {"get_transfer_by_txid": [WalletRpcError(-8, "Transaction not found.")]}
        )
        code, payload, _ = run_cli(
            ["payment-status", "--txid", TXID],
            client,
        )
        self.assertEqual(code, 1)
        self.assertTrue(payload["success"])
        self.assertFalse(payload["found"])

    def test_verify_payment_from_stdin_negative_result(self):
        artifact = {
            "type": "myt-payment-proof",
            "version": 1,
            "txid": TXID,
            "address": ADDRESS,
            "message": "invoice",
            "proof": "OutProofV2-native",
        }
        client = StubClient(
            {
                "validate_address": [valid_address_response()],
                "check_tx_proof": [
                    {"good": False, "received": 0, "confirmations": 1, "in_pool": False}
                ],
            }
        )
        code, payload, _ = run_cli(
            ["verify-payment", "--proof-file", "-"],
            client,
            stdin=json.dumps(artifact),
        )
        self.assertEqual(code, 1)
        self.assertTrue(payload["success"])
        self.assertFalse(payload["valid"])
        self.assertEqual(payload["received"]["atomic"], 0)

    def test_verify_message_negative_result(self):
        client = StubClient(
            {
                "validate_address": [valid_address_response()],
                "verify": [
                    {"good": False, "version": 2, "old": False, "signature_type": "spend"}
                ],
            }
        )
        code, payload, _ = run_cli(
            [
                "verify-message",
                "--address",
                ADDRESS,
                "--message",
                "hello",
                "--signature",
                "SigV2-native",
            ],
            client,
        )
        self.assertEqual(code, 1)
        self.assertFalse(payload["valid"])

    def test_transfer_rpc_error_is_exit_five(self):
        client = StubClient(
            {
                "validate_address": [valid_address_response()],
                "transfer": [WalletRpcError(-17, "not enough money")],
            }
        )
        code, payload, _ = run_cli(
            ["pay", "--address", ADDRESS, "--amount", "1"],
            client,
        )
        self.assertEqual(code, 5)
        self.assertEqual(payload["error"]["rpc_code"], -17)

    def test_timeout_environment_must_be_numeric(self):
        code, payload, _ = run_cli(
            ["balance"],
            StubClient(),
            environ={"MYT_WALLET_RPC_TIMEOUT": "never"},
        )
        self.assertEqual(code, 3)
        self.assertEqual(payload["error"]["code"], "invalid_configuration")

    def test_missing_command_is_structured(self):
        code, payload, _ = run_cli([], StubClient())
        self.assertEqual(code, 2)
        self.assertEqual(payload["command"], "unknown")
        self.assertFalse(payload["success"])

    def test_unexpected_exception_is_redacted(self):
        class ExplodingFactory:
            def __call__(self, config):
                raise RuntimeError("private implementation detail")

        code, payload, _ = run_cli(["balance"], ExplodingFactory())
        self.assertEqual(code, 4)
        self.assertEqual(payload["error"]["code"], "internal_error")
        self.assertNotIn("private implementation detail", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
