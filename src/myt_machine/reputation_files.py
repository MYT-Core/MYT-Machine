"""Bounded local artifacts, intentional disclosure and exclusive private outputs."""

import os
from pathlib import Path

from .billing_cli import _load
from .errors import ConfigurationError, InputError
from .payment_requests import canonical_json
from .reputation import (
    MAX_REPUTATION_BYTES,
    ReputationArtifact,
    parse_reputation_artifact,
)


def load_reputation_artifact(path, stdin) -> ReputationArtifact:
    try:
        return parse_reputation_artifact(
            canonical_json(_load(path, stdin, MAX_REPUTATION_BYTES))
        )
    except InputError:
        raise InputError("Unable to load a valid reputation artifact") from None


def ensure_reputation_output(path) -> None:
    if (
        str(path) in {"", "-"}
        or not Path(path).parent.is_dir()
        or os.path.lexists(path)
    ):
        raise ConfigurationError(
            "Reputation output requires a new file in an existing directory"
        )


def save_reputation_artifact(artifact: ReputationArtifact, path) -> None:
    encoded = (
        parse_reputation_artifact(artifact.encoded).encoded.encode("ascii") + b"\n"
    )
    ensure_reputation_output(path)
    created = None
    try:
        fd = os.open(
            path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0),
            0o600,
        )
        with os.fdopen(fd, "wb") as stream:
            created = os.fstat(stream.fileno())
            if os.name != "nt":
                os.fchmod(stream.fileno(), 0o600)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException as exc:
        if created is not None:
            try:
                current = os.lstat(path)
                if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                    os.unlink(path)
            except OSError:
                pass
        if isinstance(exc, OSError):
            raise ConfigurationError("Unable to write reputation artifact") from None
        raise
