"""Command-line interface for MYT Machine Settlement and Identity."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, TextIO

from .errors import ConfigurationError, InputError, MytMachineError
from .identity import (
    MAX_IDENTITY_MESSAGE_BYTES,
    decode_challenge_nonce,
    validate_identity_context,
    validate_identity_message,
)
from .identity_artifacts import (
    load_public_identity,
    public_identity_document,
)
from .identity_keys import (
    create_identity_files,
    load_private_identity,
    passphrase_from_text,
    read_identity_passphrase_file,
)
from .proofs import load_proof_artifact
from .rpc import DEFAULT_RPC_URL, DEFAULT_TIMEOUT, RpcConfig, WalletRpcClient
from .settlement import MachineSettlement

SCHEMA_VERSION = 1
MAX_PASSWORD_FILE_BYTES = 4096
WALLET_COMMANDS = {
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
IDENTITY_COMMANDS = {"create", "show", "sign", "verify"}
_GLOBAL_VALUE_OPTIONS = {
    "--account-index",
    "--address-index",
    "--rpc-password-file",
    "--rpc-url",
    "--rpc-user",
    "--timeout",
}
_IDENTITY_VALUE_OPTIONS = {
    "--context",
    "--expected-machine-id",
    "--identity-file",
    "--message",
    "--message-file",
    "--nonce-base64url",
    "--passphrase-file",
    "--private-key-file",
    "--signature",
}


class _JsonArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)

    def error(self, message: str) -> None:
        raise InputError("Invalid command-line arguments; use --help for usage")


def _add_identity_message_source(parser: argparse.ArgumentParser) -> None:
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--message", help="Sign or verify this UTF-8 text")
    source.add_argument(
        "--message-file",
        help="Sign or verify exact bytes from FILE, or stdin with -",
    )
    source.add_argument(
        "--nonce-base64url",
        help="Sign or verify a canonical 32-byte Base64url challenge nonce",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = _JsonArgumentParser(
        prog="myt-machine",
        description="Machine-facing settlement and offline identity interface for MYT",
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

    identity = subparsers.add_parser(
        "identity",
        help="Create and use an offline Ed25519 machine identity",
    )
    identity_subparsers = identity.add_subparsers(
        dest="identity_command", required=True
    )

    identity_create = identity_subparsers.add_parser(
        "create",
        help="Create an encrypted private key and public identity document",
    )
    identity_create.add_argument("--private-key-file", required=True)
    identity_create.add_argument("--identity-file", required=True)
    identity_create.add_argument("--passphrase-file")

    identity_show = identity_subparsers.add_parser(
        "show",
        help="Validate and display a public identity document",
    )
    identity_show.add_argument("--identity-file", required=True)

    identity_sign = identity_subparsers.add_parser(
        "sign",
        help="Sign bytes with an offline machine identity",
    )
    identity_sign.add_argument("--private-key-file", required=True)
    identity_sign.add_argument("--identity-file", required=True)
    identity_sign.add_argument("--passphrase-file")
    identity_sign.add_argument("--context", required=True)
    _add_identity_message_source(identity_sign)

    identity_verify = identity_subparsers.add_parser(
        "verify",
        help="Verify an offline machine identity signature",
    )
    identity_verify.add_argument("--identity-file", required=True)
    identity_verify.add_argument("--expected-machine-id")
    identity_verify.add_argument("--context", required=True)
    identity_verify.add_argument("--signature", required=True)
    _add_identity_message_source(identity_verify)
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
        raise ConfigurationError(
            "Wallet RPC password file must contain UTF-8 text"
        ) from None
    password = password.rstrip("\r\n")
    if not password or "\n" in password or "\r" in password or "\x00" in password:
        raise ConfigurationError(
            "Wallet RPC password file contains an invalid password"
        )
    return password


def _environment_value(environ: Mapping[str, str], name: str) -> str | None:
    return environ.get(name)


def _build_config(args: argparse.Namespace, environ: Mapping[str, str]) -> RpcConfig:
    environment_url = _environment_value(environ, "MYT_WALLET_RPC_URL")
    rpc_url = (
        args.rpc_url
        if args.rpc_url is not None
        else environment_url
        if environment_url is not None
        else DEFAULT_RPC_URL
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
                raise ConfigurationError(
                    "MYT_WALLET_RPC_TIMEOUT must be a number"
                ) from None

    return RpcConfig(
        url=rpc_url,
        username=username,
        password=password,
        timeout=timeout,
        allow_insecure_http=args.allow_insecure_http,
    )


def _emit(stream: TextIO, payload: dict[str, Any]) -> None:
    stream.write(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=True, sort_keys=True)
    )
    stream.write("\n")
    stream.flush()


def _command_hint(arguments: Sequence[str]) -> str:
    for index, argument in enumerate(arguments):
        if argument == "identity":
            if index + 1 < len(arguments) and arguments[index + 1] in IDENTITY_COMMANDS:
                return f"identity-{arguments[index + 1]}"
            return "identity"
        if argument in WALLET_COMMANDS:
            return argument
    return "unknown"


def _preserve_dash_prefixed_identity_values(arguments: Sequence[str]) -> list[str]:
    """Prevent argparse from treating valid Base64url values as options."""
    normalized: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if (
            argument in _IDENTITY_VALUE_OPTIONS
            and index + 1 < len(arguments)
            and arguments[index + 1].startswith("-")
        ):
            normalized.append(f"{argument}={arguments[index + 1]}")
            index += 2
            continue
        normalized.append(argument)
        index += 1
    return normalized


def _is_identity_invocation(arguments: Sequence[str]) -> bool:
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in _GLOBAL_VALUE_OPTIONS:
            index += 2
            continue
        if any(argument.startswith(f"{option}=") for option in _GLOBAL_VALUE_OPTIONS):
            index += 1
            continue
        if argument == "--allow-insecure-http":
            index += 1
            continue
        return argument == "identity"
    return False


def _run_wallet_command(
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


def _read_identity_message_file(path: str, stdin: TextIO) -> bytes:
    try:
        if path == "-":
            stream = getattr(stdin, "buffer", stdin)
            value = stream.read(MAX_IDENTITY_MESSAGE_BYTES + 1)
        else:
            with Path(path).open("rb") as message_file:
                value = message_file.read(MAX_IDENTITY_MESSAGE_BYTES + 1)
    except OSError as exc:
        raise InputError("Unable to read identity message file") from exc
    if isinstance(value, str):
        encoded = value.encode("utf-8")
    elif isinstance(value, bytes):
        encoded = value
    else:
        raise InputError("Identity message input could not be read")
    return validate_identity_message(encoded)


def _identity_message(args: argparse.Namespace, stdin: TextIO) -> bytes:
    if args.message is not None:
        return validate_identity_message(args.message.encode("utf-8"))
    if args.message_file is not None:
        return _read_identity_message_file(args.message_file, stdin)
    return decode_challenge_nonce(args.nonce_base64url)


def _identity_passphrase(
    args: argparse.Namespace,
    stdin: TextIO,
    passphrase_reader: Callable[[str], str] | None,
    *,
    confirm: bool,
) -> bytes:
    if args.passphrase_file is not None:
        return read_identity_passphrase_file(args.passphrase_file)
    if passphrase_reader is None:
        if not getattr(stdin, "isatty", lambda: False)():
            raise ConfigurationError(
                "Interactive passphrase entry requires a TTY; use --passphrase-file"
            )
        reader = getpass.getpass
    else:
        reader = passphrase_reader
    try:
        first = reader("Identity key passphrase: ")
        if confirm:
            second = reader("Confirm identity key passphrase: ")
            if first != second:
                raise ConfigurationError(
                    "Identity passphrase confirmation does not match"
                )
    except (EOFError, KeyboardInterrupt):
        raise ConfigurationError(
            "Unable to read identity passphrase securely"
        ) from None
    return passphrase_from_text(first)


def _run_identity_command(
    args: argparse.Namespace,
    stdin: TextIO,
    passphrase_reader: Callable[[str], str] | None,
) -> tuple[dict[str, Any], bool]:
    if args.identity_command == "create":
        passphrase = _identity_passphrase(
            args,
            stdin,
            passphrase_reader,
            confirm=True,
        )
        identity = create_identity_files(
            args.private_key_file,
            args.identity_file,
            passphrase,
        )
        return public_identity_document(identity), True

    public_identity = load_public_identity(args.identity_file)
    if args.identity_command == "show":
        return public_identity_document(public_identity), True
    if args.identity_command == "sign":
        message = _identity_message(args, stdin)
        validate_identity_context(args.context)
        passphrase = _identity_passphrase(
            args,
            stdin,
            passphrase_reader,
            confirm=False,
        )
        private_identity = load_private_identity(args.private_key_file, passphrase)
        if private_identity.public_identity != public_identity:
            raise ConfigurationError(
                "Encrypted private key does not match the public identity document"
            )
        return private_identity.sign(message, args.context).as_dict(), True
    if args.identity_command == "verify":
        message = _identity_message(args, stdin)
        result = public_identity.verify(
            message,
            args.context,
            args.signature,
            expected_machine_id=args.expected_machine_id,
        )
        return result.as_dict(), result.valid
    raise InputError("Unknown identity command")


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    client_factory: Callable[[RpcConfig], WalletRpcClient] = WalletRpcClient,
    passphrase_reader: Callable[[str], str] | None = None,
) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if _is_identity_invocation(arguments):
        arguments = _preserve_dash_prefixed_identity_values(arguments)
    environment = os.environ if environ is None else environ
    input_stream = sys.stdin if stdin is None else stdin
    output_stream = sys.stdout if stdout is None else stdout
    command = _command_hint(arguments)

    try:
        args = build_parser().parse_args(arguments)
        if args.command == "identity":
            command = f"identity-{args.identity_command}"
            result, positive = _run_identity_command(
                args,
                input_stream,
                passphrase_reader,
            )
        else:
            command = args.command
            config = _build_config(args, environment)
            client = client_factory(config)
            settlement = MachineSettlement(
                client,
                account_index=args.account_index,
                address_index=args.address_index,
            )
            result, positive = _run_wallet_command(args, settlement, input_stream)
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
