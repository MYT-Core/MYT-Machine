"""Command-line interface for MYT Machine Settlement."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, TextIO

from .errors import ConfigurationError, InputError, MytMachineError
from .proofs import load_proof_artifact
from .rpc import DEFAULT_RPC_URL, DEFAULT_TIMEOUT, RpcConfig, WalletRpcClient
from .settlement import MachineSettlement

SCHEMA_VERSION = 1
MAX_PASSWORD_FILE_BYTES = 4096
COMMANDS = {
    "status",
    "address",
    "balance",
    "pay",
    "payment-status",
    "prove-payment",
    "verify-payment",
    "sign-message",
    "verify-message",
}


class _JsonArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)

    def error(self, message: str) -> None:
        raise InputError("Invalid command-line arguments; use --help for usage")


def build_parser() -> argparse.ArgumentParser:
    parser = _JsonArgumentParser(
        prog="myt-machine",
        description="Machine-facing settlement interface for myt-wallet-rpc",
    )
    parser.add_argument("--rpc-url", help="Wallet RPC base URL")
    parser.add_argument("--rpc-user", help="Wallet RPC Digest Auth username")
    parser.add_argument(
        "--rpc-password-file",
        help="Read the Wallet RPC password from a UTF-8 file",
    )
    parser.add_argument("--timeout", type=float, help="Wallet RPC timeout in seconds")
    parser.add_argument("--account-index", type=int, default=0)
    parser.add_argument("--address-index", type=int, default=0)
    parser.add_argument(
        "--allow-insecure-http",
        action="store_true",
        help="Allow unencrypted Wallet RPC connections outside loopback",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status", help="Return wallet RPC and network status")
    subparsers.add_parser("address", help="Return the configured receiving address")
    subparsers.add_parser("balance", help="Return total and unlocked balance")

    pay = subparsers.add_parser("pay", help="Send a MYT payment")
    pay.add_argument("--address", required=True)
    pay.add_argument("--amount", required=True)
    pay.add_argument("--priority", type=int, choices=range(5), default=0)

    payment_status = subparsers.add_parser(
        "payment-status",
        help="Return wallet-local transaction state",
    )
    payment_status.add_argument("--txid", required=True)

    prove_payment = subparsers.add_parser(
        "prove-payment",
        help="Generate a native MYT transaction proof",
    )
    prove_payment.add_argument("--txid", required=True)
    prove_payment.add_argument("--address", required=True)
    prove_payment.add_argument("--message", default="")

    verify_payment = subparsers.add_parser(
        "verify-payment",
        help="Verify a MYT payment-proof artifact",
    )
    verify_payment.add_argument("--proof-file", required=True)

    sign_message = subparsers.add_parser(
        "sign-message",
        help="Sign a message with the configured wallet address",
    )
    sign_message.add_argument("--message", required=True)

    verify_message = subparsers.add_parser(
        "verify-message",
        help="Verify a native MYT message signature",
    )
    verify_message.add_argument("--address", required=True)
    verify_message.add_argument("--message", required=True)
    verify_message.add_argument("--signature", required=True)
    return parser


def _read_password_file(path: str) -> str:
    try:
        with Path(path).open("rb") as password_file:
            data = password_file.read(MAX_PASSWORD_FILE_BYTES + 1)
    except OSError as exc:
        raise ConfigurationError("Unable to read Wallet RPC password file") from exc
    if len(data) > MAX_PASSWORD_FILE_BYTES:
        raise ConfigurationError("Wallet RPC password file exceeds the size limit")
    try:
        password = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigurationError("Wallet RPC password file must contain UTF-8 text") from None
    password = password.rstrip("\r\n")
    if not password or "\n" in password or "\r" in password or "\x00" in password:
        raise ConfigurationError("Wallet RPC password file contains an invalid password")
    return password


def _environment_value(environ: Mapping[str, str], name: str) -> str | None:
    return environ.get(name)


def _build_config(args: argparse.Namespace, environ: Mapping[str, str]) -> RpcConfig:
    environment_url = _environment_value(environ, "MYT_WALLET_RPC_URL")
    rpc_url = (
        args.rpc_url
        if args.rpc_url is not None
        else environment_url if environment_url is not None else DEFAULT_RPC_URL
    )
    environment_username = _environment_value(environ, "MYT_WALLET_RPC_USER")
    username = args.rpc_user if args.rpc_user is not None else environment_username
    if args.rpc_password_file is not None:
        password = _read_password_file(args.rpc_password_file)
    else:
        password = _environment_value(environ, "MYT_WALLET_RPC_PASSWORD")

    if args.timeout is not None:
        timeout: float = args.timeout
    else:
        timeout_value = _environment_value(environ, "MYT_WALLET_RPC_TIMEOUT")
        if timeout_value is None:
            timeout = DEFAULT_TIMEOUT
        else:
            try:
                timeout = float(timeout_value)
            except ValueError:
                raise ConfigurationError("MYT_WALLET_RPC_TIMEOUT must be a number") from None

    return RpcConfig(
        url=rpc_url,
        username=username,
        password=password,
        timeout=timeout,
        allow_insecure_http=args.allow_insecure_http,
    )


def _emit(stream: TextIO, payload: dict[str, Any]) -> None:
    stream.write(json.dumps(payload, separators=(",", ":"), ensure_ascii=True, sort_keys=True))
    stream.write("\n")
    stream.flush()


def _command_hint(arguments: Sequence[str]) -> str:
    for argument in arguments:
        if argument in COMMANDS:
            return argument
    return "unknown"


def _run_command(
    args: argparse.Namespace,
    settlement: MachineSettlement,
    stdin: TextIO,
) -> tuple[dict[str, Any], bool]:
    command = args.command
    if command == "status":
        return settlement.status(), True
    if command == "address":
        return settlement.address(), True
    if command == "balance":
        return settlement.balance(), True
    if command == "pay":
        return settlement.pay(args.address, args.amount, priority=args.priority), True
    if command == "payment-status":
        result = settlement.payment_status(args.txid)
        return result, bool(result["found"])
    if command == "prove-payment":
        return (
            settlement.prove_payment(args.txid, args.address, message=args.message),
            True,
        )
    if command == "verify-payment":
        artifact = load_proof_artifact(args.proof_file, stdin)
        result = settlement.verify_payment(artifact)
        return result, bool(result["valid"])
    if command == "sign-message":
        return settlement.sign_message(args.message), True
    if command == "verify-message":
        result = settlement.verify_message(args.address, args.message, args.signature)
        return result, bool(result["valid"])
    raise InputError("Unknown command")


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    client_factory: Callable[[RpcConfig], WalletRpcClient] = WalletRpcClient,
) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    environment = os.environ if environ is None else environ
    input_stream = sys.stdin if stdin is None else stdin
    output_stream = sys.stdout if stdout is None else stdout
    command = _command_hint(arguments)

    try:
        args = build_parser().parse_args(arguments)
        command = args.command
        config = _build_config(args, environment)
        client = client_factory(config)
        settlement = MachineSettlement(
            client,
            account_index=args.account_index,
            address_index=args.address_index,
        )
        result, positive = _run_command(args, settlement, input_stream)
        _emit(
            output_stream,
            {
                "schema_version": SCHEMA_VERSION,
                "command": command,
                "success": True,
                **result,
            },
        )
        return 0 if positive else 1
    except MytMachineError as exc:
        _emit(
            output_stream,
            {
                "schema_version": SCHEMA_VERSION,
                "command": command,
                "success": False,
                "error": exc.as_dict(),
            },
        )
        return exc.exit_code
    except Exception:  # noqa: BLE001 - the CLI must emit redacted JSON for unexpected failures.
        _emit(
            output_stream,
            {
                "schema_version": SCHEMA_VERSION,
                "command": command,
                "success": False,
                "error": {
                    "code": "internal_error",
                    "message": "Unexpected internal error",
                },
            },
        )
        return 4


def entrypoint() -> None:
    raise SystemExit(main())
