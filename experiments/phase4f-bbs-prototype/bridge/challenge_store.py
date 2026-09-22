"""Durable, bounded Phase 4F verifier challenge storage.

This bridge deliberately uses Python's standard-library SQLite driver so the
experimental JavaScript BBS boundary does not add another native dependency.
Every invocation opens its own transaction, which makes the final unused-to-
used transition durable and atomic across processes.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any


_APP_ID = 0x4D594634
_MAX_INPUT_BYTES = 65_536
_MAX_CAPACITY = 100_000
_NETWORKS = {"mainnet", "testnet", "stagenet"}
_HEX_32 = re.compile(r"^[0-9a-f]{64}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]{43}$")
_REQUEST_FIELDS = {
    "type",
    "version",
    "challenge",
    "audience",
    "network",
    "policy_digest",
    "requested_predicate",
    "created_at",
    "expires_at",
}
_PREDICATE_FIELDS = {"metric_id", "operator", "threshold", "required_result"}
_REVOCATION_FIELDS = {
    "type",
    "version",
    "evaluator_machine_id",
    "bbs_key_id",
    "authorization_id",
    "network",
    "revoked_at",
    "reason",
    "id",
    "signature",
}
_KEY_ID = re.compile(r"^myt-phase4f-bbs-key-v1:[0-9a-f]{64}$")
_REVOCATION_ID = re.compile(r"^myt-phase4f-key-revocation-v1:[0-9a-f]{64}$")


class ChallengeStoreError(Exception):
    """A deliberately redacted verifier-state error."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ChallengeStoreError(f"{name} is not an integer")
    if value < minimum or value > maximum:
        raise ChallengeStoreError(f"{name} is outside its bounds")
    return value


def _decode_challenge(value: Any) -> bytes:
    if not isinstance(value, str) or _BASE64URL.fullmatch(value) is None:
        raise ChallengeStoreError("Verifier challenge is not canonical Base64url")
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        raise ChallengeStoreError("Verifier challenge is not canonical Base64url") from None
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise ChallengeStoreError("Verifier challenge is not canonical Base64url")
    return decoded


def validate_request(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _REQUEST_FIELDS:
        raise ChallengeStoreError("Presentation request has missing or unknown fields")
    if value["type"] != "myt-phase4f-presentation-request" or value["version"] != 1:
        raise ChallengeStoreError("Unsupported presentation request")
    _decode_challenge(value["challenge"])
    audience = value["audience"]
    if (
        not isinstance(audience, str)
        or not 1 <= len(audience) <= 256
        or any(ord(character) < 32 or ord(character) == 127 for character in audience)
    ):
        raise ChallengeStoreError("Invalid verifier audience")
    if value["network"] not in _NETWORKS:
        raise ChallengeStoreError("Unsupported MYT network")
    if not isinstance(value["policy_digest"], str) or _HEX_32.fullmatch(
        value["policy_digest"]
    ) is None:
        raise ChallengeStoreError("Invalid requested policy digest")
    predicate = value["requested_predicate"]
    if not isinstance(predicate, dict) or set(predicate) != _PREDICATE_FIELDS:
        raise ChallengeStoreError("Requested predicate has missing or unknown fields")
    if (
        predicate["metric_id"] != "verified_recipient_settlement_events"
        or predicate["operator"] != "gte"
        or predicate["required_result"] is not True
    ):
        raise ChallengeStoreError("Requested predicate is not supported")
    _bounded_int(predicate["threshold"], "Predicate threshold", 0, 10_000)
    created_at = _bounded_int(value["created_at"], "Challenge creation time", 0, 253402300799)
    expires_at = _bounded_int(value["expires_at"], "Challenge expiry", 0, 253402300799)
    if expires_at <= created_at or expires_at - created_at > 300:
        raise ChallengeStoreError("Challenge lifetime must be between 1 and 300 seconds")
    return value


def _request_digest(request: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(request).encode("ascii")).hexdigest()


def validate_revocation(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _REVOCATION_FIELDS:
        raise ChallengeStoreError("Key revocation has missing or unknown fields")
    if value["type"] != "myt-phase4f-bbs-key-revocation" or value["version"] != 1:
        raise ChallengeStoreError("Unsupported BBS key revocation")
    if not isinstance(value["bbs_key_id"], str) or _KEY_ID.fullmatch(
        value["bbs_key_id"]
    ) is None:
        raise ChallengeStoreError("Invalid BBS key ID")
    if not isinstance(value["id"], str) or _REVOCATION_ID.fullmatch(value["id"]) is None:
        raise ChallengeStoreError("Invalid BBS key revocation ID")
    for field in ("evaluator_machine_id", "authorization_id", "signature"):
        if not isinstance(value[field], str) or not 1 <= len(value[field]) <= 256:
            raise ChallengeStoreError("Invalid BBS key revocation field")
    if value["network"] not in _NETWORKS:
        raise ChallengeStoreError("Unsupported MYT network")
    _bounded_int(value["revoked_at"], "Key revocation time", 0, 253402300799)
    if value["reason"] not in {"unspecified", "compromised", "rotated", "retired"}:
        raise ChallengeStoreError("Unsupported BBS key revocation reason")
    return value


class DurableChallengeStore:
    """SQLite state with a single atomic success for every challenge."""

    def __init__(self, path: str | os.PathLike[str], *, capacity: int = _MAX_CAPACITY):
        self.path = Path(path).absolute()
        self.capacity = _bounded_int(capacity, "Challenge capacity", 1, _MAX_CAPACITY)
        if not self.path.parent.is_dir():
            raise ChallengeStoreError("Challenge database requires an existing directory")
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        except OSError:
            raise ChallengeStoreError("Cannot create challenge database") from None
        else:
            os.close(descriptor)
        with self._transaction() as database:
            version = database.execute("PRAGMA user_version").fetchone()[0]
            application = database.execute("PRAGMA application_id").fetchone()[0]
            if version == 0 and application == 0:
                if database.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone():
                    raise ChallengeStoreError("Unrecognized challenge database")
                database.execute(
                    "CREATE TABLE challenges ("
                    "challenge TEXT PRIMARY KEY, request_digest TEXT NOT NULL UNIQUE, "
                    "request_json TEXT NOT NULL, expires_at INTEGER NOT NULL, "
                    "used_at INTEGER)"
                )
                database.execute("CREATE INDEX challenge_expiry ON challenges(expires_at)")
                database.execute(
                    "CREATE TABLE key_revocations ("
                    "key_id TEXT PRIMARY KEY, revocation_id TEXT NOT NULL UNIQUE, "
                    "revocation_digest TEXT NOT NULL UNIQUE, revocation_json TEXT NOT NULL)"
                )
                database.execute("PRAGMA user_version=1")
                database.execute(f"PRAGMA application_id={_APP_ID}")
            elif version != 1 or application != _APP_ID:
                raise ChallengeStoreError("Unsupported challenge database")

    @contextmanager
    def _transaction(self):
        database = None
        try:
            metadata = self.path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ChallengeStoreError(
                    "Challenge database must be a regular non-linked file"
                )
            if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o600:
                raise ChallengeStoreError("Challenge database permissions must be 0600")
            database = sqlite3.connect(self.path, timeout=5, isolation_level=None)
            database.row_factory = sqlite3.Row
            database.execute("PRAGMA trusted_schema=OFF")
            database.execute("PRAGMA synchronous=FULL")
            database.execute("BEGIN IMMEDIATE")
            yield database
            database.commit()
        except ChallengeStoreError:
            raise
        except (sqlite3.Error, OSError):
            raise ChallengeStoreError("Challenge database operation failed") from None
        finally:
            if database is not None:
                if database.in_transaction:
                    database.rollback()
                database.close()

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, Any]:
        try:
            request = json.loads(row["request_json"], object_pairs_hook=_reject_duplicates)
            request = validate_request(request)
            if (
                row["challenge"] != request["challenge"]
                or row["request_digest"] != _request_digest(request)
                or row["request_json"] != _canonical_json(request)
                or row["expires_at"] != request["expires_at"]
                or (row["used_at"] is not None and not isinstance(row["used_at"], int))
            ):
                raise ChallengeStoreError("Corrupt stored presentation request")
            return request
        except (ChallengeStoreError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            raise ChallengeStoreError("Corrupt stored presentation request") from None

    def register(self, request: dict[str, Any]) -> None:
        request = validate_request(request)
        encoded = _canonical_json(request)
        with self._transaction() as database:
            count = database.execute(
                "SELECT (SELECT count(*) FROM challenges)+"
                "(SELECT count(*) FROM key_revocations)"
            ).fetchone()[0]
            if count >= self.capacity:
                raise ChallengeStoreError("Challenge database capacity reached")
            try:
                database.execute(
                    "INSERT INTO challenges VALUES (?,?,?,?,NULL)",
                    (
                        request["challenge"],
                        _request_digest(request),
                        encoded,
                        request["expires_at"],
                    ),
                )
            except sqlite3.IntegrityError:
                raise ChallengeStoreError("Duplicate verifier challenge") from None

    def lookup(self, challenge: str, now: int) -> dict[str, Any]:
        _decode_challenge(challenge)
        _bounded_int(now, "Verification time", 0, 253402300799)
        with self._transaction() as database:
            row = database.execute(
                "SELECT * FROM challenges WHERE challenge=?", (challenge,)
            ).fetchone()
            if row is None:
                raise ChallengeStoreError("Verifier challenge is unknown")
            request = self._decode(row)
            if row["used_at"] is not None:
                raise ChallengeStoreError("Verifier challenge was already used")
            if now >= request["expires_at"]:
                raise ChallengeStoreError("Verifier challenge is expired")
            return request

    def consume(self, challenge: str, now: int) -> None:
        _decode_challenge(challenge)
        _bounded_int(now, "Verification time", 0, 253402300799)
        with self._transaction() as database:
            changed = database.execute(
                "UPDATE challenges SET used_at=? "
                "WHERE challenge=? AND used_at IS NULL AND expires_at>?",
                (now, challenge, now),
            ).rowcount
            if changed == 1:
                return
            row = database.execute(
                "SELECT * FROM challenges WHERE challenge=?", (challenge,)
            ).fetchone()
            if row is None:
                raise ChallengeStoreError("Verifier challenge is unknown")
            request = self._decode(row)
            if row["used_at"] is not None:
                raise ChallengeStoreError("Verifier challenge was already used")
            if now >= request["expires_at"]:
                raise ChallengeStoreError("Verifier challenge is expired")
            raise ChallengeStoreError("Verifier challenge cannot be consumed")

    def prune(self, now: int, retention_seconds: int = 86_400) -> int:
        _bounded_int(now, "Prune time", 0, 253402300799)
        retention_seconds = _bounded_int(
            retention_seconds, "Retention period", 300, 31_536_000
        )
        cutoff = max(0, now - retention_seconds)
        with self._transaction() as database:
            return database.execute(
                "DELETE FROM challenges WHERE expires_at<?", (cutoff,)
            ).rowcount

    def register_key_revocation(self, revocation: dict[str, Any]) -> bool:
        revocation = validate_revocation(revocation)
        encoded = _canonical_json(revocation)
        digest = hashlib.sha256(encoded.encode("ascii")).hexdigest()
        with self._transaction() as database:
            stored = database.execute(
                "SELECT * FROM key_revocations WHERE key_id=?",
                (revocation["bbs_key_id"],),
            ).fetchone()
            if stored is not None:
                if (
                    stored["revocation_id"] != revocation["id"]
                    or stored["revocation_digest"] != digest
                    or stored["revocation_json"] != encoded
                ):
                    raise ChallengeStoreError("Conflicting BBS key revocation")
                return False
            count = database.execute(
                "SELECT (SELECT count(*) FROM challenges)+"
                "(SELECT count(*) FROM key_revocations)"
            ).fetchone()[0]
            if count >= self.capacity:
                raise ChallengeStoreError("Verifier-state database capacity reached")
            try:
                database.execute(
                    "INSERT INTO key_revocations VALUES (?,?,?,?)",
                    (revocation["bbs_key_id"], revocation["id"], digest, encoded),
                )
            except sqlite3.IntegrityError:
                raise ChallengeStoreError("Conflicting BBS key revocation") from None
            return True

    def lookup_key_revocation(self, key_id: str) -> dict[str, Any] | None:
        if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
            raise ChallengeStoreError("Invalid BBS key ID")
        with self._transaction() as database:
            row = database.execute(
                "SELECT * FROM key_revocations WHERE key_id=?", (key_id,)
            ).fetchone()
            if row is None:
                return None
            try:
                value = json.loads(
                    row["revocation_json"], object_pairs_hook=_reject_duplicates
                )
                value = validate_revocation(value)
                digest = hashlib.sha256(
                    _canonical_json(value).encode("ascii")
                ).hexdigest()
                if (
                    row["key_id"] != value["bbs_key_id"]
                    or row["revocation_id"] != value["id"]
                    or row["revocation_digest"] != digest
                    or row["revocation_json"] != _canonical_json(value)
                ):
                    raise ChallengeStoreError("Corrupt stored BBS key revocation")
                return value
            except (ChallengeStoreError, KeyError, TypeError, ValueError):
                raise ChallengeStoreError("Corrupt stored BBS key revocation") from None


def _reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ChallengeStoreError("JSON contains a duplicate field")
        result[key] = value
    return result


def _read_payload() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
    if len(raw) > _MAX_INPUT_BYTES:
        raise ChallengeStoreError("Bridge request exceeds its size limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ChallengeStoreError("Bridge request is not valid JSON") from None
    if not isinstance(value, dict):
        raise ChallengeStoreError("Bridge request must be an object")
    return value


def _main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--database", required=True)
    parser.add_argument(
        "--action",
        required=True,
        choices=(
            "init",
            "register",
            "lookup",
            "consume",
            "prune",
            "register-key-revocation",
            "lookup-key-revocation",
        ),
    )
    arguments = parser.parse_args()
    try:
        payload = _read_payload()
        store = DurableChallengeStore(arguments.database)
        response: dict[str, Any] = {"ok": True}
        if arguments.action == "init":
            if payload:
                raise ChallengeStoreError("Init request must be empty")
        elif arguments.action == "register":
            if set(payload) != {"request"}:
                raise ChallengeStoreError("Register request has unknown fields")
            store.register(payload["request"])
        elif arguments.action == "lookup":
            if set(payload) != {"challenge", "now"}:
                raise ChallengeStoreError("Lookup request has unknown fields")
            response["request"] = store.lookup(payload["challenge"], payload["now"])
        elif arguments.action == "consume":
            if set(payload) != {"challenge", "now"}:
                raise ChallengeStoreError("Consume request has unknown fields")
            store.consume(payload["challenge"], payload["now"])
        elif arguments.action == "prune":
            if set(payload) != {"now", "retention_seconds"}:
                raise ChallengeStoreError("Prune request has unknown fields")
            response["deleted"] = store.prune(
                payload["now"], payload["retention_seconds"]
            )
        elif arguments.action == "register-key-revocation":
            if set(payload) != {"revocation"}:
                raise ChallengeStoreError("Revocation request has unknown fields")
            response["inserted"] = store.register_key_revocation(
                payload["revocation"]
            )
        else:
            if set(payload) != {"key_id"}:
                raise ChallengeStoreError("Key-status request has unknown fields")
            response["revocation"] = store.lookup_key_revocation(payload["key_id"])
        print(_canonical_json(response))
        return 0
    except ChallengeStoreError as error:
        print(_canonical_json({"ok": False, "error": str(error)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(_main())
