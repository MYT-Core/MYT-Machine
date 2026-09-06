"""Phase 4D CLI additions, isolated from existing settlement/identity semantics."""

from __future__ import annotations

import argparse
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any, TextIO

from .amounts import parse_myt_amount
from .billing import BillingService
from .errors import ConfigurationError, InputError
from .invoice_store import SQLiteInvoiceStore
from .invoice_verification import WalletPaymentVerifier
from .invoices import DEFAULT_CONFIRMATIONS
from .payment_requests import (
    MAX_REQUEST_BYTES,
    NETWORKS,
    create_payment_request,
    parse_payment_request,
    serialize_payment_request,
    strict_json,
    unix_time,
)
from .rpc import WalletRpcClient


def add_billing_parsers(subparsers: Any) -> None:
    request = subparsers.add_parser(
        "payment-request", help="Create and validate immutable payment requests"
    )
    actions = request.add_subparsers(dest="request_command", required=True)
    create = actions.add_parser("create")
    _creation_arguments(create)
    create.add_argument(
        "--request-file", help="Optional new artifact file, never overwritten"
    )
    show = actions.add_parser("show")
    show.add_argument("--request-file", required=True)
    verify = actions.add_parser("verify")
    verify.add_argument("--request-file", required=True)
    verify.add_argument("--network", choices=sorted(NETWORKS), required=True)

    invoice = subparsers.add_parser(
        "invoice", help="Persist and verify non-custodial invoices"
    )
    actions = invoice.add_subparsers(dest="invoice_command", required=True)
    for name in ("create", "get", "list", "status", "expire", "verify"):
        command = actions.add_parser(name)
        command.add_argument("--db", required=True)
        if name == "create":
            _creation_arguments(command)
            command.add_argument("--idempotency-key")
            command.add_argument(
                "--confirmations", type=int, default=DEFAULT_CONFIRMATIONS
            )
        else:
            command.add_argument("--network", choices=sorted(NETWORKS), required=True)
        if name in {"get", "status", "verify"}:
            command.add_argument("--invoice-id", required=True)
        if name == "verify":
            command.add_argument("--proof-file", required=True)
        if name == "list":
            command.add_argument("--limit", type=int, default=50)
            command.add_argument("--after")


def _creation_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--network", choices=sorted(NETWORKS), required=True)
    parser.add_argument("--address", required=True)
    amount = parser.add_mutually_exclusive_group(required=True)
    amount.add_argument("--amount", help="Exact decimal MYT string")
    amount.add_argument("--amount-atomic", help="Exact positive uint64 decimal integer")
    parser.add_argument("--expires-in", type=int, default=3600)
    parser.add_argument("--invoice-id")
    parser.add_argument("--memo")
    parser.add_argument("--reference")


def _amount(args: argparse.Namespace) -> int:
    if args.amount is not None:
        if len(args.amount) > 30:
            raise InputError("MYT amount exceeds the size limit")
        return parse_myt_amount(args.amount, require_positive=True)
    text = args.amount_atomic
    if (
        not isinstance(text, str)
        or not 1 <= len(text) <= 20
        or not text.isascii()
        or not text.isdecimal()
        or text.startswith("0")
    ):
        raise InputError("Atomic amount must be a positive decimal integer")
    return int(text)


def _load(path: str, stdin: TextIO, maximum: int) -> Any:
    try:
        if path == "-":
            encoded = getattr(stdin, "buffer", stdin).read(maximum + 1)
        else:
            file_path = Path(path)
            flags = (
                os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            )
            flags |= getattr(os, "O_NONBLOCK", 0)
            if file_path.is_symlink():
                raise InputError("Artifact must be a regular non-symlink file")
            descriptor = os.open(file_path, flags)
            with os.fdopen(descriptor, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise InputError("Artifact must be a regular file")
                encoded = stream.read(maximum + 1)
    except OSError:
        raise InputError("Unable to read artifact") from None
    return strict_json(encoded, maximum)


def _save_request(encoded: str, path: str) -> None:
    if path == "-":
        raise ConfigurationError("Use stdout or a new request file")
    try:
        descriptor = os.open(
            path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded.encode("ascii") + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise ConfigurationError("Unable to create new payment request file") from None


def run_billing_command(
    args: argparse.Namespace,
    stdin: TextIO,
    client_factory: Callable[[], WalletRpcClient],
) -> tuple[dict[str, Any], bool]:
    if args.command == "payment-request":
        if args.request_command == "create":
            request = create_payment_request(
                args.address,
                _amount(args),
                network=args.network,
                expires_in=args.expires_in,
                invoice_id=args.invoice_id,
                memo=args.memo,
                reference=args.reference,
            )
            if args.request_file:
                _save_request(serialize_payment_request(request), args.request_file)
            return {
                "request": request.as_dict(),
                "proof_message": request.proof_message,
                "address_validated": False,
            }, True
        request = parse_payment_request(
            _load(args.request_file, stdin, MAX_REQUEST_BYTES)
        )
        if args.request_command == "show":
            return {
                "request": request.as_dict(),
                "proof_message": request.proof_message,
                "address_validated": False,
            }, True
        network_matches = request.network == args.network
        address_valid = network_matches and WalletPaymentVerifier(
            client_factory(),
            network=args.network,
        ).validate_request(request)
        payable = request.created_at <= unix_time() < request.expires_at
        valid = bool(network_matches and payable and address_valid)
        return {
            "valid": valid,
            "network_matches": network_matches,
            "payable": payable,
            "address_validated": address_valid,
            "issuer_authenticated": False,
        }, valid

    # A typo in a read/verify database path must not silently create a new store.
    if args.invoice_command != "create" and not Path(args.db).is_file():
        raise ConfigurationError("Invoice database does not exist")
    store = SQLiteInvoiceStore(args.db)
    verifier = (
        WalletPaymentVerifier(client_factory(), network=args.network)
        if args.invoice_command in {"create", "verify"}
        else None
    )
    service = BillingService(store, network=args.network, verifier=verifier)
    if args.invoice_command == "create":
        record = service.create_invoice(
            args.address,
            _amount(args),
            expires_in=args.expires_in,
            invoice_id=args.invoice_id,
            memo=args.memo,
            reference=args.reference,
            idempotency_key=args.idempotency_key,
            required_confirmations=args.confirmations,
        )
        return {"invoice": record.as_dict()}, True
    if args.invoice_command == "get":
        return {"invoice": service.get_invoice(args.invoice_id).as_dict()}, True
    if args.invoice_command == "status":
        return {
            "invoice_id": args.invoice_id,
            "state": service.invoice_status(args.invoice_id).value,
        }, True
    if args.invoice_command == "list":
        records = service.list_invoices(limit=args.limit, after=args.after)
        return {
            "invoices": [r.as_dict() for r in records],
            "next_after": records[-1].request.invoice_id if records else None,
        }, True
    if args.invoice_command == "expire":
        return {"expired_count": store.expire()}, True
    proof = _load(args.proof_file, stdin, 73728)
    result = service.verify_invoice(args.invoice_id, proof)
    return result.as_dict(), result.paid
