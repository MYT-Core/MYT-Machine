"""Bounded files for the optional Phase 4F candidate."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .disclosure_artifacts import MAX_ARTIFACT, DisclosureArtifact, parse_disclosure
from .errors import ConfigurationError, InputError


def is_reparse(meta) -> bool:
    return bool(getattr(meta, "st_file_attributes", 0) & 0x400)


def private_parent(path: Path) -> None:
    for parent in path.absolute().parents:
        meta = parent.lstat()
        if stat.S_ISLNK(meta.st_mode) or is_reparse(meta):
            raise ConfigurationError("Disclosure directory must not be a link")
    meta = path.parent.lstat()
    if not stat.S_ISDIR(meta.st_mode):
        raise ConfigurationError("Disclosure directory must not be a link")
    if os.name != "nt" and (meta.st_mode & 0o022 or meta.st_uid != os.getuid()):
        raise ConfigurationError("Disclosure directory must be owned and protected")


def read_regular(path, limit=MAX_ARTIFACT, *, private=False) -> bytes:
    fd = None
    try:
        path = Path(path).absolute()
        if private:
            private_parent(path)
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or is_reparse(before)
        ):
            raise ConfigurationError(
                "Disclosure input must be a regular non-linked file"
            )
        fd = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0),
        )
        meta = os.fstat(fd)
        if (meta.st_dev, meta.st_ino) != (before.st_dev, before.st_ino):
            raise ConfigurationError("Disclosure input changed")
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or is_reparse(meta):
            raise ConfigurationError(
                "Disclosure input must be a regular non-linked file"
            )
        if (
            private
            and os.name != "nt"
            and (stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_uid != os.getuid())
        ):
            raise ConfigurationError("Disclosure private files require owned mode 0600")
        if not 0 < meta.st_size <= limit:
            raise InputError("Disclosure file size limit")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            raw = stream.read(limit + 1)
        if not 0 < len(raw) <= limit:
            raise InputError("Disclosure file size limit")
        return raw
    except OSError:
        raise ConfigurationError("Cannot read disclosure file") from None
    finally:
        if fd is not None:
            os.close(fd)


def save_disclosure(path, value: DisclosureArtifact) -> None:
    raw = parse_disclosure(value.raw).raw
    fd = None
    own = None
    path = Path(path).absolute()
    try:
        private_parent(path)
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        own = os.fstat(fd)
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        if own is not None:
            try:
                current = path.lstat()
                if (current.st_dev, current.st_ino) == (own.st_dev, own.st_ino):
                    path.unlink()
            except OSError:
                pass
        raise ConfigurationError(
            "Cannot create disclosure file without overwriting"
        ) from None
    finally:
        if fd is not None:
            os.close(fd)


def load_disclosure(path) -> DisclosureArtifact:
    return parse_disclosure(read_regular(path))
