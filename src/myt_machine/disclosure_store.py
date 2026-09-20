"""Private, bounded, durable verifier state. Do not open untrusted databases."""

from __future__ import annotations

import os
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path

from .disclosure_artifacts import (
    AUTH,
    REQUEST,
    REVOKE,
    active,
    artifact,
    digest,
    parse_disclosure,
    verify_statement,
)
from .disclosure_files import is_reparse, private_parent
from .errors import ConfigurationError, InputError, MytMachineError
from .payment_requests import MAX_TIMESTAMP, bounded_int, unix_time

_COUNT = {
    "requests": "SELECT count(*) FROM requests",
    "issuers": "SELECT count(*) FROM issuers",
    "revocations": "SELECT count(*) FROM revocations",
}
_ROWS = {
    "requests": "SELECT * FROM requests",
    "issuers": "SELECT * FROM issuers",
    "revocations": "SELECT * FROM revocations",
}
APP_ID = 0x4D594446
SCHEMA = (
    "CREATE TABLE clock (id INTEGER PRIMARY KEY CHECK(id=1), floor INTEGER NOT NULL)",
    "CREATE TABLE requests (challenge TEXT PRIMARY KEY, artifact BLOB NOT NULL, digest TEXT NOT NULL, used INTEGER NOT NULL CHECK(used IN (0,1)))",
    "CREATE TABLE issuers (id TEXT PRIMARY KEY, artifact BLOB NOT NULL, digest TEXT NOT NULL, checked_at INTEGER NOT NULL)",
    "CREATE TABLE revocations (id TEXT PRIMARY KEY, artifact BLOB NOT NULL, digest TEXT NOT NULL)",
)


class DisclosureStorageError(MytMachineError):
    code = "disclosure_storage_error"


class DisclosureStore:
    def __init__(self, path, *, capacity=10000):
        self.path = Path(path).absolute()
        self.capacity = bounded_int(capacity, "disclosure capacity", 1, 100000)
        if str(path) in ("", "-", ":memory:"):
            raise ConfigurationError("Disclosure requires a private durable database")
        try:
            private_parent(self.path)
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                created = False
            else:
                os.close(fd)
                created = True
            with self._transaction(initialize=created) as db:
                if created:
                    for sql in SCHEMA:
                        db.execute(sql)
                    db.execute("INSERT INTO clock VALUES (1,0)")
                    db.execute(f"PRAGMA application_id={APP_ID}")
                    db.execute("PRAGMA user_version=1")
        except OSError:
            raise ConfigurationError("Cannot open disclosure database") from None

    @contextmanager
    def _transaction(self, *, initialize=False):
        db = None
        try:
            private_parent(self.path)
            before = self.path.lstat()
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or is_reparse(before)
            ):
                raise ConfigurationError(
                    "Disclosure database must be a regular non-linked file"
                )
            if os.name != "nt" and (
                stat.S_IMODE(before.st_mode) != 0o600 or before.st_uid != os.getuid()
            ):
                raise ConfigurationError("Disclosure database requires owned mode 0600")
            db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("BEGIN IMMEDIATE")
            after = self.path.lstat()
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise DisclosureStorageError("Disclosure database changed")
            if not initialize:
                self._validate(db)
            yield db
            db.commit()
        except (sqlite3.Error, OSError, ValueError, TypeError):
            raise DisclosureStorageError(
                "Disclosure database operation failed"
            ) from None
        finally:
            if db is not None:
                if db.in_transaction:
                    db.rollback()
                db.close()

    def _validate(self, db):
        if (
            db.execute("PRAGMA application_id").fetchone()[0] != APP_ID
            or db.execute("PRAGMA user_version").fetchone()[0] != 1
        ):
            raise DisclosureStorageError("Unknown disclosure database")
        actual = [
            r[0]
            for r in db.execute(
                "SELECT sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        if actual != sorted(SCHEMA, key=lambda s: s.split()[2]):
            raise DisclosureStorageError("Unexpected disclosure schema")
        if db.execute("PRAGMA quick_check(1)").fetchall() != [("ok",)]:
            raise DisclosureStorageError("Corrupt disclosure database")
        clock = db.execute("SELECT * FROM clock").fetchall()
        if len(clock) != 1 or clock[0][0] != 1:
            raise DisclosureStorageError("Corrupt disclosure clock")
        bounded_int(clock[0][1], "clock floor", 0, MAX_TIMESTAMP)
        total = 0
        for table, kind in (
            ("requests", REQUEST),
            ("issuers", AUTH),
            ("revocations", REVOKE),
        ):
            total += db.execute(_COUNT[table]).fetchone()[0]
            if total > self.capacity:
                raise DisclosureStorageError("Disclosure capacity exceeded")
            for row in db.execute(_ROWS[table]):
                try:
                    value = parse_disclosure(row[1]).as_dict()
                    identifier = value["challenge"] if kind == REQUEST else value["id"]
                    if (
                        value["type"] != kind
                        or row[0] != identifier
                        or row[2] != digest(row[1])
                    ):
                        raise InputError("Corrupt disclosure row")
                    if kind != REQUEST:
                        verify_statement(value, value["evaluator"]["machine_id"])
                    if kind == REQUEST and (
                        type(row[3]) is not int or row[3] not in (0, 1)
                    ):
                        raise InputError("Corrupt request use state")
                    if kind == AUTH:
                        bounded_int(row[3], "issuer status time", 0, MAX_TIMESTAMP)
                except (InputError, KeyError, IndexError, TypeError):
                    raise DisclosureStorageError(
                        "Corrupt stored disclosure state"
                    ) from None

    @staticmethod
    def _clock(db):
        now = unix_time()
        floor = db.execute("SELECT floor FROM clock WHERE id=1").fetchone()[0]
        if now < floor:
            raise DisclosureStorageError("Disclosure clock moved backwards")
        db.execute("UPDATE clock SET floor=? WHERE id=1", (now,))
        return now

    def _space(self, db):
        total = sum(
            db.execute(_COUNT[t]).fetchone()[0]
            for t in ("requests", "issuers", "revocations")
        )
        if total >= self.capacity:
            raise DisclosureStorageError("Disclosure capacity reached")

    def register(self, request):
        request = artifact(request.as_dict())
        value = request.as_dict()
        if value["type"] != REQUEST:
            raise InputError("Expected disclosure request")
        with self._transaction() as db:
            now = self._clock(db)
            if value["expires_at"] <= now:
                raise InputError("Cannot register expired request")
            self._space(db)
            db.execute(
                "INSERT INTO requests VALUES (?,?,?,0)",
                (value["challenge"], request.raw, digest(request.raw)),
            )

    def refresh_issuer(self, authorization, *, expected_evaluator, revocations=()):
        """Trusted operator records a locally checked status, NOT global freshness."""
        authorization = artifact(authorization.as_dict())
        auth = authorization.as_dict()
        if auth["type"] != AUTH:
            raise InputError("Expected issuer authorization")
        verify_statement(auth, expected_evaluator)
        revocations = tuple(artifact(r.as_dict()) for r in revocations)
        if len(revocations) > 100:
            raise InputError("Too many revocations")
        with self._transaction() as db:
            now = self._clock(db)
            active(
                auth["statement"]["not_before"], auth["statement"]["expires_at"], now
            )
            for rev in revocations:
                v = rev.as_dict()
                if v["type"] != REVOKE:
                    raise InputError("Expected issuer revocation")
                verify_statement(v, expected_evaluator)
                s = v["statement"]
                if (
                    s["authorization_id"] != auth["id"]
                    or s["bbs_key_id"] != auth["statement"]["bbs_key_id"]
                    or s["network"] != auth["statement"]["network"]
                    or s["issued_at"] > now
                ):
                    raise InputError("Revocation does not match authorization or time")
                existing = db.execute(
                    "SELECT artifact FROM revocations WHERE id=?", (v["id"],)
                ).fetchone()
                if existing is None:
                    self._space(db)
                    db.execute(
                        "INSERT INTO revocations VALUES (?,?,?)",
                        (v["id"], rev.raw, digest(rev.raw)),
                    )
                elif existing[0] != rev.raw:
                    raise InputError("Revocation conflict")
            existing = db.execute(
                "SELECT artifact FROM issuers WHERE id=?", (auth["id"],)
            ).fetchone()
            if existing is None:
                self._space(db)
                db.execute(
                    "INSERT INTO issuers VALUES (?,?,?,?)",
                    (auth["id"], authorization.raw, digest(authorization.raw), now),
                )
            elif existing[0] != authorization.raw:
                raise InputError("Authorization conflict")
            else:
                db.execute(
                    "UPDATE issuers SET checked_at=? WHERE id=?", (now, auth["id"])
                )

    @staticmethod
    def _issuer(db, auth, expected_evaluator, now, freshness):
        verify_statement(auth, expected_evaluator)
        active(auth["statement"]["not_before"], auth["statement"]["expires_at"], now)
        row = db.execute(
            "SELECT artifact,checked_at FROM issuers WHERE id=?", (auth["id"],)
        ).fetchone()
        if (
            row is None
            or row[0] != artifact(auth).raw
            or not 0 <= now - row[1] <= freshness
        ):
            raise InputError("Missing or stale local issuer status")
        for (raw,) in db.execute("SELECT artifact FROM revocations"):
            rev = parse_disclosure(raw).as_dict()
            s = rev["statement"]
            if (
                s["bbs_key_id"] == auth["statement"]["bbs_key_id"]
                and s["network"] == auth["statement"]["network"]
                and rev["evaluator"]["machine_id"] == expected_evaluator
            ):
                verify_statement(rev, expected_evaluator)
                raise InputError("BBS issuer key revoked locally")

    def check_issuer(self, auth, expected_evaluator, *, freshness=300):
        bounded_int(freshness, "issuer freshness", 0, 3600)
        with self._transaction() as db:
            self._issuer(db, auth, expected_evaluator, self._clock(db), freshness)
