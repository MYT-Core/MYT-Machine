"""Immutable signed opinions and revocations using the existing Phase 4B frame."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from .errors import InputError
from .identity import MachineIdentity, decode_signature, machine_id_digest
from .identity_artifacts import parse_public_identity_document, public_identity_document
from .payment_requests import (
    MAX_TIMESTAMP,
    bounded_int,
    canonical_json,
    strict_json,
    validate_network,
)

MAX_REPUTATION_BYTES = 16384
ATTESTATION = "myt-reputation-attestation"
REVOCATION = "myt-reputation-revocation"
_DOMAINS = {
    ATTESTATION: b"MYT-REPUTATION-ATTESTATION-V1\n",
    REVOCATION: b"MYT-REPUTATION-REVOCATION-V1\n",
}
_CONTEXTS = {
    ATTESTATION: "myt-machine/reputation-attestation/v1",
    REVOCATION: "myt-machine/reputation-revocation/v1",
}
_FIELDS = {"type", "version", "issuer", "statement", "id", "signature"}
_ATTEST_FIELDS = {
    "subject_machine_id",
    "network",
    "issued_at",
    "category",
    "outcome",
    "evidence_digest",
}


def reputation_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"myt-reputation-v1:[0-9a-f]{64}", value) is None
    ):
        raise InputError("Invalid reputation artifact ID")
    return value


def evidence_digest(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise InputError("Invalid reputation evidence digest")
    return value


def content_digest(domain: bytes, value: Any) -> str:
    return hashlib.sha256(domain + canonical_json(value).encode("ascii")).hexdigest()


def _body(value: dict[str, Any]) -> dict[str, Any]:
    return {k: value[k] for k in ("type", "version", "issuer", "statement")}


def _content(value: dict[str, Any]) -> bytes:
    return _DOMAINS[value["type"]] + canonical_json(_body(value)).encode("ascii")


def _validate(value: Any) -> dict[str, Any]:
    try:
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise InputError("Invalid reputation artifact fields")
        kind = value["type"]
        if not isinstance(kind, str) or kind not in _DOMAINS:
            raise InputError("Unsupported reputation artifact type")
        bounded_int(value["version"], "reputation version", 1, 1)
        issuer = parse_public_identity_document(value["issuer"])
        s = value["statement"]
        fields = (
            _ATTEST_FIELDS
            if kind == ATTESTATION
            else {"network", "issued_at", "attestation_id"}
        )
        if not isinstance(s, dict) or set(s) != fields:
            raise InputError("Invalid reputation statement fields")
        validate_network(s["network"])
        bounded_int(s["issued_at"], "issuer timestamp", 0, MAX_TIMESTAMP)
        if kind == ATTESTATION:
            machine_id_digest(s["subject_machine_id"])
            if s["subject_machine_id"] == issuer.machine_id:
                raise InputError("Self-attestations are unsupported")
            if s["category"] != "SERVICE_INTERACTION" or s["outcome"] not in (
                "POSITIVE",
                "NEUTRAL",
                "NEGATIVE",
            ):
                raise InputError("Unsupported reputation category or outcome")
            if s["evidence_digest"] is not None:
                evidence_digest(s["evidence_digest"])
        else:
            reputation_id(s["attestation_id"])
        reputation_id(value["id"])
        expected = "myt-reputation-v1:" + hashlib.sha256(_content(value)).hexdigest()
        if value["id"] != expected:
            raise InputError("Reputation ID does not match canonical content")
        decode_signature(value["signature"])
        return value
    except (InputError, ValueError, TypeError, KeyError, RecursionError):
        # Artifact-controlled field names and values must never reach exceptions.
        raise InputError("Malformed reputation artifact") from None


@dataclass(frozen=True, slots=True)
class ReputationArtifact:
    """A schema-valid immutable artifact; validity/trust require separate checks."""

    encoded: str

    def __post_init__(self) -> None:
        value = _validate(strict_json(self.encoded, MAX_REPUTATION_BYTES))
        object.__setattr__(self, "encoded", canonical_json(value))

    def as_dict(self) -> dict[str, Any]:
        return strict_json(self.encoded, MAX_REPUTATION_BYTES)

    @property
    def id(self) -> str:
        return self.as_dict()["id"]

    @property
    def kind(self) -> str:
        return self.as_dict()["type"]

    @property
    def issuer_machine_id(self) -> str:
        return self.as_dict()["issuer"]["machine_id"]

    @property
    def statement(self) -> dict[str, Any]:
        return self.as_dict()["statement"]

    @property
    def canonical_content(self) -> bytes:
        return _content(self.as_dict())

    @property
    def digest(self) -> str:
        return content_digest(b"MYT-REPUTATION-ARTIFACT-V1\n", self.as_dict())

    def verify(
        self, *, expected_network: str | None = None, expected_issuer: str | None = None
    ) -> bool:
        value = _validate(self.as_dict())
        if expected_network is not None:
            validate_network(expected_network)
        issuer = parse_public_identity_document(value["issuer"])
        result = issuer.verify(
            self.canonical_content,
            _CONTEXTS[self.kind],
            value["signature"],
            expected_machine_id=expected_issuer,
        )
        return result.valid and (
            expected_network is None or expected_network == self.statement["network"]
        )


def parse_reputation_artifact(value: str | bytes) -> ReputationArtifact:
    return ReputationArtifact(
        canonical_json(_validate(strict_json(value, MAX_REPUTATION_BYTES)))
    )


def _sign(
    identity: MachineIdentity, kind: str, statement: dict[str, Any]
) -> ReputationArtifact:
    value = {
        "type": kind,
        "version": 1,
        "issuer": public_identity_document(identity.public_identity),
        "statement": statement,
    }
    content = _content(value)
    value["id"] = "myt-reputation-v1:" + hashlib.sha256(content).hexdigest()
    value["signature"] = identity.sign(content, _CONTEXTS[kind]).signature
    return ReputationArtifact(canonical_json(value))


def create_attestation(
    identity: MachineIdentity,
    *,
    subject_machine_id: str,
    network: str,
    issued_at: int,
    outcome: str,
    evidence: str | None = None,
) -> ReputationArtifact:
    return _sign(
        identity,
        ATTESTATION,
        {
            "subject_machine_id": subject_machine_id,
            "network": network,
            "issued_at": issued_at,
            "category": "SERVICE_INTERACTION",
            "outcome": outcome,
            "evidence_digest": evidence,
        },
    )


def create_revocation(
    identity: MachineIdentity, attestation: ReputationArtifact, *, issued_at: int
) -> ReputationArtifact:
    if attestation.kind != ATTESTATION or not attestation.verify(
        expected_issuer=identity.machine_id
    ):
        raise InputError("Revocation requires the original attestation issuer")
    return _sign(
        identity,
        REVOCATION,
        {
            "network": attestation.statement["network"],
            "issued_at": issued_at,
            "attestation_id": attestation.id,
        },
    )
