"""Durable local invoices; SQLite enforces transaction reuse and idempotency."""

from __future__ import annotations

import os
import re
import sqlite3
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from .errors import ConfigurationError, InputError
from .invoice_verification import PaymentObservation
from .invoices import (
    MAX_CONFIRMATIONS,
    InvoiceConflict,
    InvoiceNotFound,
    InvoiceRecord,
    InvoiceState,
    InvoiceStorageError,
)
from .payment_requests import (
    PaymentRequest,
    bounded_int,
    parse_payment_request,
    serialize_payment_request,
    unix_time,
    validate_identifier,
    validate_network,
)
from .validation import normalize_txid

_SCHEMA = """
CREATE TABLE invoices (
    invoice_id TEXT PRIMARY KEY NOT NULL,
    network TEXT NOT NULL CHECK (network IN ('mainnet','testnet','stagenet')),
    request TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('PENDING','PAID','EXPIRED')),
    required_confirmations INTEGER NOT NULL CHECK (required_confirmations >= 1),
    txid TEXT,
    received_atomic TEXT,
    confirmations INTEGER,
    paid_at INTEGER,
    idempotency_key TEXT UNIQUE,
    creation_fingerprint TEXT NOT NULL,
    UNIQUE(network, txid),
    CHECK ((state = 'PAID' AND txid IS NOT NULL AND received_atomic IS NOT NULL
            AND confirmations IS NOT NULL AND paid_at IS NOT NULL)
        OR (state != 'PAID' AND txid IS NULL AND received_atomic IS NULL
            AND confirmations IS NULL AND paid_at IS NULL))
)
"""
_APP_ID = 0x4D595449


class SQLiteInvoiceStore:
    """One private, service-owned database. Do not open untrusted DB files.

    Each operation opens its own connection. BEGIN IMMEDIATE serializes writers
    across threads and processes; UNIQUE(network,txid) is the durable backstop.
    No seed, private key, requester IP or full payment proof is persisted.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        clock: Callable[[], int] = unix_time,
        max_invoices: int = 100000,
    ) -> None:
        self.path = Path(path).absolute()
        self.clock = clock
        self.max_invoices = bounded_int(max_invoices, "invoice capacity", 1, 1000000)
        if str(path) in {":memory:", "-", ""} or not self.path.parent.is_dir():
            raise ConfigurationError(
                "Invoice database requires a persistent file in an existing directory"
            )
        if os.name != "nt" and self.path.parent.stat().st_mode & 0o022:
            raise ConfigurationError(
                "Invoice database directory must not be writable by other users"
            )
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except FileExistsError:
            pass
        except OSError:
            raise ConfigurationError("Unable to create invoice database") from None
        else:
            os.close(descriptor)
        self._check_file()
        with self._transaction() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            app_id = connection.execute("PRAGMA application_id").fetchone()[0]
            if version == 0 and app_id == 0:
                if connection.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone():
                    raise InvoiceStorageError("Unrecognized invoice database schema")
                connection.execute(_SCHEMA)
                connection.execute(
                    "CREATE INDEX invoice_expiry ON invoices(state, expires_at)"
                )
                connection.execute("PRAGMA user_version=1")
                connection.execute(f"PRAGMA application_id={_APP_ID}")
            elif version != 1 or app_id != _APP_ID:
                raise InvoiceStorageError("Unsupported invoice database version")

    def _check_file(self) -> None:
        try:
            metadata = self.path.lstat()
        except OSError:
            raise ConfigurationError("Unable to access invoice database") from None
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ConfigurationError(
                "Invoice database must be a regular non-linked file"
            )
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ConfigurationError("Invoice database permissions must be 0600")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        self._check_file()
        connection = None
        try:
            connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except sqlite3.Error:
            raise InvoiceStorageError("Invoice database operation failed") from None
        finally:
            if connection is not None:
                if connection.in_transaction:
                    connection.rollback()
                connection.close()

    def _now(self) -> int:
        return unix_time(self.clock())

    @staticmethod
    def _decode(row: sqlite3.Row) -> InvoiceRecord:
        try:
            request = parse_payment_request(row["request"])
            if (
                row["request"] != serialize_payment_request(request)
                or row["invoice_id"] != request.invoice_id
                or row["network"] != request.network
                or row["expires_at"] != request.expires_at
            ):
                raise InputError("Inconsistent invoice data")
            raw_amount = row["received_atomic"]
            if raw_amount is not None and (
                not isinstance(raw_amount, str)
                or re.fullmatch(r"[1-9][0-9]{0,19}", raw_amount) is None
            ):
                raise InputError("Invalid stored amount")
            return InvoiceRecord(
                request,
                InvoiceState(row["state"]),
                row["required_confirmations"],
                row["txid"],
                None if raw_amount is None else int(raw_amount),
                row["confirmations"],
                row["paid_at"],
            )
        except (InputError, ValueError, TypeError, KeyError, IndexError):
            raise InvoiceStorageError("Malformed stored invoice") from None

    @staticmethod
    def _expire(connection: sqlite3.Connection, now: int) -> int:
        return connection.execute(
            "UPDATE invoices SET state='EXPIRED' WHERE state='PENDING' AND expires_at<=?",
            (now,),
        ).rowcount

    def create(
        self,
        request: PaymentRequest,
        *,
        required_confirmations: int,
        creation_fingerprint: str,
        idempotency_key: str | None = None,
    ) -> InvoiceRecord:
        encoded = serialize_payment_request(request)
        bounded_int(
            required_confirmations, "required confirmations", 1, MAX_CONFIRMATIONS
        )
        if (
            not isinstance(creation_fingerprint, str)
            or re.fullmatch(r"[a-f0-9]{64}", creation_fingerprint) is None
        ):
            raise InputError("Invalid creation fingerprint")
        if idempotency_key is not None:
            validate_identifier(idempotency_key, "idempotency key")
        with self._transaction() as connection:
            now = self._now()
            self._expire(connection, now)
            if idempotency_key is not None:
                previous = connection.execute(
                    "SELECT * FROM invoices WHERE idempotency_key=?",
                    (idempotency_key,),
                ).fetchone()
                if previous is not None:
                    if previous["creation_fingerprint"] != creation_fingerprint:
                        raise InvoiceConflict(
                            "Idempotency key was used with different invoice parameters"
                        )
                    return self._decode(previous)
            if now < request.created_at or now >= request.expires_at:
                raise InputError("New invoice must be currently payable")
            if (
                connection.execute("SELECT COUNT(*) FROM invoices").fetchone()[0]
                >= self.max_invoices
            ):
                raise InvoiceStorageError(
                    "Invoice capacity reached; archive with a retained transaction ledger"
                )
            try:
                connection.execute(
                    "INSERT INTO invoices(invoice_id,network,request,expires_at,state,"
                    "required_confirmations,idempotency_key,creation_fingerprint) "
                    "VALUES(?,?,?,?,'PENDING',?,?,?)",
                    (
                        request.invoice_id,
                        request.network,
                        encoded,
                        request.expires_at,
                        required_confirmations,
                        idempotency_key,
                        creation_fingerprint,
                    ),
                )
            except sqlite3.IntegrityError:
                raise InvoiceConflict(
                    "Invoice ID or idempotency key already exists"
                ) from None
            return InvoiceRecord(request, InvoiceState.PENDING, required_confirmations)

    def get(self, invoice_id: str) -> InvoiceRecord:
        validate_identifier(invoice_id)
        with self._transaction() as connection:
            self._expire(connection, self._now())
            row = connection.execute(
                "SELECT * FROM invoices WHERE invoice_id=?", (invoice_id,)
            ).fetchone()
            if row is None:
                raise InvoiceNotFound("Invoice does not exist")
            return self._decode(row)

    def list(
        self, *, network: str, limit: int = 50, after: str | None = None
    ) -> list[InvoiceRecord]:
        validate_network(network)
        bounded_int(limit, "page size", 1, 100)
        if after is not None:
            validate_identifier(after)
        with self._transaction() as connection:
            self._expire(connection, self._now())
            rows = connection.execute(
                "SELECT * FROM invoices WHERE network=? AND invoice_id>? ORDER BY invoice_id LIMIT ?",
                (network, after or "", limit),
            ).fetchall()
            return [self._decode(row) for row in rows]

    def expire(self) -> int:
        with self._transaction() as connection:
            return self._expire(connection, self._now())

    def _finalize(
        self, request: PaymentRequest, observation: PaymentObservation
    ) -> InvoiceRecord:
        """Trusted billing-service boundary, never a client-facing mark-paid API."""
        if (
            not isinstance(observation, PaymentObservation)
            or observation.eligible is not True
        ):
            raise InputError("Finalization requires verified payment evidence")
        txid = normalize_txid(observation.txid)
        if observation.request_message != request.proof_message:
            raise InputError("Payment evidence belongs to a different request")
        with self._transaction() as connection:
            # Re-evaluate time after RPC and after acquiring the write lock.
            now = self._now()
            self._expire(connection, now)
            row = connection.execute(
                "SELECT * FROM invoices WHERE invoice_id=?", (request.invoice_id,)
            ).fetchone()
            if row is None:
                raise InvoiceNotFound("Invoice does not exist")
            current = self._decode(row)
            if current.request != request:
                raise InvoiceConflict("Invoice changed during verification")
            if current.state is not InvoiceState.PENDING:
                return current
            paid = InvoiceRecord(
                request,
                InvoiceState.PAID,
                current.required_confirmations,
                txid,
                observation.received_atomic,
                observation.confirmations,
                now,
            )
            try:
                connection.execute(
                    "UPDATE invoices SET state='PAID',txid=?,received_atomic=?,confirmations=?,paid_at=? "
                    "WHERE invoice_id=? AND state='PENDING'",
                    (
                        txid,
                        str(paid.received_atomic),
                        paid.confirmations,
                        paid.paid_at,
                        request.invoice_id,
                    ),
                )
            except sqlite3.IntegrityError:
                raise InvoiceConflict(
                    "Transaction already consumed by another invoice on this network"
                ) from None
            return paid
