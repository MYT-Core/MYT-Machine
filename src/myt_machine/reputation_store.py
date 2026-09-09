"""Private local evidence storage. Never open attacker-controlled SQLite files."""

from __future__ import annotations

import os
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .errors import ConfigurationError, InputError, MytMachineError
from .identity import machine_id_digest
from .payment_requests import bounded_int, canonical_json, strict_json, validate_network
from .reputation import (
    ATTESTATION,
    REVOCATION,
    ReputationArtifact,
    content_digest,
    evidence_digest,
    parse_reputation_artifact,
    reputation_id,
)

_APP_ID = 0x4D595452
_SCHEMA = (
    (
        "CREATE TABLE artifacts (id TEXT PRIMARY KEY, digest TEXT NOT NULL UNIQUE, "
        "network TEXT NOT NULL, kind TEXT NOT NULL, issuer TEXT NOT NULL, "
        "subject TEXT, artifact TEXT NOT NULL)"
    ),
    (
        "CREATE TABLE settlements (digest TEXT PRIMARY KEY, network TEXT NOT NULL, "
        "subject TEXT NOT NULL, transaction_digest TEXT NOT NULL, "
        "request_digest TEXT NOT NULL, evidence TEXT NOT NULL, "
        "UNIQUE(network,transaction_digest), UNIQUE(network,request_digest))"
    ),
)
_SETTLEMENT_FIELDS = {
    "type",
    "version",
    "network",
    "subject_machine_id",
    "transaction_digest",
    "request_digest",
    "binding_digest",
}


class ReputationStorageError(MytMachineError):
    code = "reputation_storage_error"


def validate_settlement(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _SETTLEMENT_FIELDS:
        raise InputError("Invalid local settlement evidence")
    if value["type"] != "myt-recipient-settlement-observation":
        raise InputError("Unsupported local evidence type")
    bounded_int(value["version"], "evidence version", 1, 1)
    validate_network(value["network"])
    machine_id_digest(value["subject_machine_id"])
    for field in ("transaction_digest", "request_digest", "binding_digest"):
        evidence_digest(value[field])
    return value


def settlement_digest(value: dict[str, Any]) -> str:
    return content_digest(b"MYT-RECIPIENT-SETTLEMENT-V1\n", validate_settlement(value))


class ReputationStore:
    """One connection/transaction per operation, durable uniqueness, bounded size.

    Artifacts are revalidated cryptographically on reads. Local settlement rows
    are observations of the trusted local verifier, not portable signed facts.
    A malicious process with database write access is outside this trust boundary.
    """

    def __init__(self, path: str | os.PathLike[str], *, capacity: int = 10000):
        self.path = Path(path).absolute()
        self.capacity = bounded_int(capacity, "reputation capacity", 1, 100000)
        if str(path) in {"", "-", ":memory:"} or not self.path.parent.is_dir():
            raise ConfigurationError(
                "Reputation database requires an existing directory"
            )
        if os.name != "nt" and self.path.parent.stat().st_mode & 0o022:
            raise ConfigurationError(
                "Reputation directory must not be writable by others"
            )
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        except OSError:
            raise ConfigurationError("Cannot create reputation database") from None
        else:
            os.close(fd)
        with self._transaction() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            app = db.execute("PRAGMA application_id").fetchone()[0]
            if version == 0 and app == 0:
                if db.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone():
                    raise ReputationStorageError("Unrecognized reputation database")
                for sql in _SCHEMA:
                    db.execute(sql)
                db.execute("PRAGMA user_version=1")
                db.execute(f"PRAGMA application_id={_APP_ID}")
            elif version != 1 or app != _APP_ID:
                raise ReputationStorageError("Unsupported reputation database")

    @contextmanager
    def _transaction(self):
        db = None
        try:
            metadata = self.path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ConfigurationError(
                    "Reputation database must be a regular non-linked file"
                )
            if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o600:
                raise ConfigurationError("Reputation database permissions must be 0600")
            db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except (sqlite3.Error, OSError):
            raise ReputationStorageError(
                "Reputation database operation failed"
            ) from None
        finally:
            if db is not None:
                if db.in_transaction:
                    db.rollback()
                db.close()

    @staticmethod
    def _decode(row) -> ReputationArtifact:
        try:
            artifact = parse_reputation_artifact(row["artifact"])
            expected = (
                artifact.id,
                artifact.digest,
                artifact.statement["network"],
                artifact.kind,
                artifact.issuer_machine_id,
                artifact.statement.get("subject_machine_id"),
                artifact.encoded,
            )
            if tuple(row) != expected or not artifact.verify():
                raise InputError("Inconsistent artifact")
            return artifact
        except (InputError, TypeError, KeyError):
            raise ReputationStorageError("Corrupt stored reputation artifact") from None

    @staticmethod
    def _decode_settlement(row) -> dict[str, Any]:
        try:
            value = validate_settlement(strict_json(row["evidence"]))
            expected = (
                settlement_digest(value),
                value["network"],
                value["subject_machine_id"],
                value["transaction_digest"],
                value["request_digest"],
                canonical_json(value),
            )
            if tuple(row) != expected:
                raise InputError("Inconsistent local evidence")
            return value
        except (InputError, TypeError, KeyError):
            raise ReputationStorageError("Corrupt local settlement evidence") from None

    def _snapshot(self, db):
        count = db.execute(
            "SELECT (SELECT count(*) FROM artifacts)+(SELECT count(*) FROM settlements)"
        ).fetchone()[0]
        if count > self.capacity:
            raise ReputationStorageError("Reputation database capacity exceeded")
        artifacts = [
            self._decode(row)
            for row in db.execute("SELECT * FROM artifacts ORDER BY id")
        ]
        settlements = [
            self._decode_settlement(row)
            for row in db.execute("SELECT * FROM settlements ORDER BY digest")
        ]
        return artifacts, settlements

    def snapshot(self, *, network: str):
        validate_network(network)
        with self._transaction() as db:
            artifacts, settlements = self._snapshot(db)
            return (
                [a for a in artifacts if a.statement["network"] == network],
                [s for s in settlements if s["network"] == network],
            )

    def import_artifact(self, artifact: ReputationArtifact, *, network: str) -> bool:
        # Reparse even SDK-created objects; caller flags are never verification.
        artifact = parse_reputation_artifact(artifact.encoded)
        if not artifact.verify(expected_network=network):
            raise InputError("Invalid reputation signature or network")
        with self._transaction() as db:
            artifacts, settlements = self._snapshot(db)
            for stored in artifacts:
                if stored.id == artifact.id:
                    if stored.encoded != artifact.encoded:
                        raise InputError("Conflicting reputation artifact")
                    return False
            if artifact.kind == REVOCATION:
                for target in artifacts:
                    if target.id == artifact.statement["attestation_id"] and (
                        target.kind != ATTESTATION
                        or target.issuer_machine_id != artifact.issuer_machine_id
                        or target.statement["network"] != network
                    ):
                        raise InputError(
                            "Revocation is not authorized by target issuer"
                        )
            if len(artifacts) + len(settlements) >= self.capacity:
                raise ReputationStorageError("Reputation database capacity reached")
            db.execute(
                "INSERT INTO artifacts VALUES (?,?,?,?,?,?,?)",
                (
                    artifact.id,
                    artifact.digest,
                    network,
                    artifact.kind,
                    artifact.issuer_machine_id,
                    artifact.statement.get("subject_machine_id"),
                    artifact.encoded,
                ),
            )
        return True

    def get(self, artifact_id: str, *, network: str) -> ReputationArtifact | None:
        reputation_id(artifact_id)
        artifacts, _ = self.snapshot(network=network)
        return next((a for a in artifacts if a.id == artifact_id), None)

    def list(
        self,
        *,
        network: str,
        subject: str | None = None,
        limit: int = 50,
        after: str | None = None,
    ) -> list[ReputationArtifact]:
        bounded_int(limit, "reputation list limit", 1, 200)
        if after is not None:
            reputation_id(after)
        if subject is not None:
            machine_id_digest(subject)
        artifacts, _ = self.snapshot(network=network)
        return [
            a
            for a in artifacts
            if (after is None or a.id > after)
            and (subject is None or a.statement.get("subject_machine_id") == subject)
        ][:limit]

    def _record_settlement(self, value: dict[str, Any]) -> tuple[str, bool]:
        """Trusted bridge only. Never expose an arbitrary evidence-import endpoint."""
        value = validate_settlement(strict_json(canonical_json(value)))
        digest = settlement_digest(value)
        with self._transaction() as db:
            artifacts, settlements = self._snapshot(db)
            for stored in settlements:
                if settlement_digest(stored) == digest:
                    return digest, False
                if stored["network"] == value["network"] and (
                    stored["transaction_digest"] == value["transaction_digest"]
                    or stored["request_digest"] == value["request_digest"]
                ):
                    raise InputError(
                        "Settlement transaction or invoice already attributed"
                    )
            if len(artifacts) + len(settlements) >= self.capacity:
                raise ReputationStorageError("Reputation database capacity reached")
            db.execute(
                "INSERT INTO settlements VALUES (?,?,?,?,?,?)",
                (
                    digest,
                    value["network"],
                    value["subject_machine_id"],
                    value["transaction_digest"],
                    value["request_digest"],
                    canonical_json(value),
                ),
            )
        return digest, True
