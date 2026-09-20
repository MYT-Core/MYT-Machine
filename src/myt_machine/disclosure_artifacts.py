"""Strict Phase 4F artifacts; existing Phase 4B does all identity cryptography.

Design credit: fallacyofall's experimental BBS architecture and independent
follow-up review. This official profile is intentionally not wire-compatible
with that unreleased prototype.
"""

from __future__ import annotations

import base64
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

SUITE = "BLS12-381-SHA-256"
PROFILE = "myt-reputation-bbs-v1"
METRIC = "verified_recipient_settlement_events"
LEVELS = (1, 10, 25, 50, 100)
MAX_ARTIFACT = 32768
HEADER = b"MYT-REPUTATION-CREDENTIAL-V1\n"
AUTH = "myt-reputation-issuer-authorization"
REVOKE = "myt-reputation-issuer-revocation"
CREDENTIAL = "myt-reputation-credential"
REQUEST = "myt-reputation-disclosure-request"
PRESENTATION = "myt-reputation-disclosure-presentation"
PURPOSE = "myt-reputation-selective-disclosure-v1"
CONTEXTS = {
    AUTH: "myt-machine/disclosure/issuer-authorization/v1",
    REVOKE: "myt-machine/disclosure/issuer-revocation/v1",
}
SIGN_DOMAIN = {
    AUTH: b"MYT-REPUTATION-ISSUER-AUTHORIZATION-V1\n",
    REVOKE: b"MYT-REPUTATION-ISSUER-REVOCATION-V1\n",
}
CONTROL_CONTEXT = "myt-machine/disclosure/subject-control/v1"
BASE_CLAIMS = {
    "subject_machine_id",
    "network",
    "policy_digest",
    "metric_id",
    "as_of",
    "issued_at",
    "expires_at",
}
REQUEST_FIELDS = {
    "type",
    "version",
    "purpose",
    "expected_subject_machine_id",
    "expected_evaluator_machine_id",
    "expected_issuer_key_id",
    "network",
    "challenge",
    "audience",
    "policy_digest",
    "metric_id",
    "threshold",
    "not_before",
    "expires_at",
}


def exact(value: Any, fields: set[str]) -> dict:
    if type(value) is not dict or set(value) != fields:
        raise InputError("Disclosure artifact has missing or unknown fields")
    return value


def ascii_text(value: Any, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or any(not 33 <= ord(char) <= 126 for char in value)
    ):
        raise InputError("Invalid bounded disclosure text")
    return value


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def hex_digest(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch("[0-9a-f]{64}", value) is None:
        raise InputError("Invalid disclosure digest")
    return value


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def unb64(value: Any, length: int) -> bytes:
    if not isinstance(value, str) or re.fullmatch("[A-Za-z0-9_-]+", value) is None:
        raise InputError("Invalid disclosure Base64url")
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except ValueError:
        raise InputError("Invalid disclosure Base64url") from None
    if len(raw) != length or b64(raw) != value:
        raise InputError("Noncanonical disclosure Base64url or length")
    return raw


def key_id(public_key: str) -> str:
    raw = unb64(public_key, 96)
    if not any(raw):
        raise InputError("Invalid BBS public key")
    return "myt-bbs-key-v1:" + digest(
        b"MYT-BBS-KEY-V1\0" + SUITE.encode() + b"\0" + raw
    )


def validate_key_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch("myt-bbs-key-v1:[0-9a-f]{64}", value) is None
    ):
        raise InputError("Invalid BBS key ID")
    return value


def encoded(value: dict) -> bytes:
    return canonical_json(value).encode("ascii")


def strict_object(
    raw: bytes | str, limit: int = MAX_ARTIFACT, *, newline: bool = True
) -> dict:
    try:
        data = raw.encode("utf-8") if isinstance(raw, str) else raw
        value = strict_json(data, limit)

        # The protocol has ASCII-only strings. Reject escaped controls/surrogates too.
        def walk(item, depth=0):
            if depth > 12:
                raise InputError("Disclosure nesting limit")
            if isinstance(item, str):
                if any(not 32 <= ord(char) <= 126 for char in item):
                    raise InputError(
                        "Disclosure strings must be ASCII without controls"
                    )
            elif type(item) is dict:
                for k, v in item.items():
                    walk(k, depth + 1)
                    walk(v, depth + 1)
            elif type(item) is list:
                if len(item) > 128:
                    raise InputError("Disclosure array limit")
                for child in item:
                    walk(child, depth + 1)
            elif type(item) not in (int, bool):
                raise InputError("Unsupported disclosure value")

        walk(value)
        if (
            type(value) is not dict
            or encoded(value) + (b"\n" if newline else b"") != data
        ):
            raise InputError("Disclosure input is not canonical")
        return value
    except (ValueError, TypeError, RecursionError, UnicodeError, InputError):
        raise InputError("Malformed canonical disclosure JSON") from None


def _version(value: dict, kind: str) -> None:
    if value["type"] != kind:
        raise InputError("Wrong disclosure type")
    bounded_int(value["version"], "disclosure version", 1, 1)


def _window(start, end, maximum=86400):
    bounded_int(start, "activation", 0, MAX_TIMESTAMP)
    bounded_int(end, "expiry", 0, MAX_TIMESTAMP)
    bounded_int(end - start, "lifetime", 1, maximum)


def active(start: int, end: int, now: int) -> None:
    bounded_int(now, "verification time", 0, MAX_TIMESTAMP)
    if not start <= now < end:
        raise InputError("Disclosure is not currently active")


def signed_content(value: dict) -> bytes:
    return SIGN_DOMAIN[value["type"]] + encoded(
        {k: value[k] for k in ("type", "version", "evaluator", "statement")}
    )


def _authorization(value):
    exact(value, {"type", "version", "evaluator", "statement", "id", "signature"})
    _version(value, AUTH)
    parse_public_identity_document(value["evaluator"])
    s = exact(
        value["statement"],
        {
            "bbs_public_key",
            "bbs_key_id",
            "ciphersuite",
            "network",
            "purpose",
            "not_before",
            "expires_at",
        },
    )
    if s["ciphersuite"] != SUITE or s["purpose"] != PURPOSE:
        raise InputError("Unsupported issuer authorization profile")
    if s["bbs_key_id"] != key_id(s["bbs_public_key"]):
        raise InputError("BBS key ID mismatch")
    validate_network(s["network"])
    _window(s["not_before"], s["expires_at"], 366 * 86400)
    if value["id"] != "myt-bbs-authorization-v1:" + digest(signed_content(value)):
        raise InputError("Issuer authorization ID mismatch")
    decode_signature(value["signature"])


def validate(value: dict) -> dict:
    try:
        if type(value) is not dict:
            raise InputError("Expected disclosure object")
        kind = value.get("type")
        if kind == AUTH:
            _authorization(value)
        elif kind == REVOKE:
            exact(
                value, {"type", "version", "evaluator", "statement", "id", "signature"}
            )
            _version(value, REVOKE)
            parse_public_identity_document(value["evaluator"])
            s = exact(
                value["statement"],
                {"network", "issued_at", "authorization_id", "bbs_key_id", "reason"},
            )
            validate_network(s["network"])
            bounded_int(s["issued_at"], "revocation time", 0, MAX_TIMESTAMP)
            validate_key_id(s["bbs_key_id"])
            if (
                re.fullmatch(
                    "myt-bbs-authorization-v1:[0-9a-f]{64}",
                    ascii_text(s["authorization_id"]),
                )
                is None
            ):
                raise InputError("Invalid revoked authorization ID")
            if s["reason"] not in ("compromised", "retired", "unspecified"):
                raise InputError("Invalid revocation reason")
            if value["id"] != "myt-bbs-revocation-v1:" + digest(signed_content(value)):
                raise InputError("Revocation ID mismatch")
            decode_signature(value["signature"])
        elif kind == REQUEST:
            exact(value, REQUEST_FIELDS)
            _version(value, REQUEST)
            if value["purpose"] != PURPOSE or value["metric_id"] != METRIC:
                raise InputError("Unsupported disclosure purpose or metric")
            machine_id_digest(value["expected_subject_machine_id"])
            machine_id_digest(value["expected_evaluator_machine_id"])
            validate_key_id(value["expected_issuer_key_id"])
            validate_network(value["network"])
            unb64(value["challenge"], 32)
            ascii_text(value["audience"])
            hex_digest(value["policy_digest"])
            bounded_int(value["threshold"], "threshold", 1, 100)
            if value["threshold"] not in LEVELS:
                raise InputError("Unsupported threshold")
            _window(value["not_before"], value["expires_at"], 300)
        elif kind in (CREDENTIAL, PRESENTATION):
            fields = {"type", "version", "authorization", "claims"}
            fields |= (
                {"signature"}
                if kind == CREDENTIAL
                else {"request", "proof", "subject_control"}
            )
            exact(value, fields)
            _version(value, kind)
            _authorization(value["authorization"])
            claims = exact(
                value["claims"],
                BASE_CLAIMS | ({"predicates"} if kind == CREDENTIAL else set()),
            )
            machine_id_digest(claims["subject_machine_id"])
            validate_network(claims["network"])
            hex_digest(claims["policy_digest"])
            if claims["metric_id"] != METRIC:
                raise InputError("Unsupported credential metric")
            bounded_int(claims["as_of"], "evaluation time", 0, MAX_TIMESTAMP)
            _window(claims["issued_at"], claims["expires_at"], 86400)
            if claims["as_of"] > claims["issued_at"]:
                raise InputError("Evaluation cannot follow issuance")
            s = value["authorization"]["statement"]
            if claims["network"] != s["network"] or not (
                s["not_before"]
                <= claims["issued_at"]
                < claims["expires_at"]
                <= s["expires_at"]
            ):
                raise InputError("Credential exceeds issuer authorization")
            if kind == CREDENTIAL:
                p = claims["predicates"]
                if (
                    type(p) is not list
                    or len(p) != 5
                    or any(type(x) is not bool for x in p)
                ):
                    raise InputError("Invalid fixed predicate vector")
                unb64(value["signature"], 80)
            else:
                validate(value["request"])
                if value["request"]["type"] != REQUEST:
                    raise InputError("Expected disclosure request")
                unb64(value["proof"], 400)
                ctl = exact(value["subject_control"], {"identity", "signature"})
                parse_public_identity_document(ctl["identity"])
                decode_signature(ctl["signature"])
        else:
            raise InputError("Unsupported disclosure artifact")
        return value
    except (KeyError, TypeError, ValueError, RecursionError, InputError):
        raise InputError("Malformed disclosure artifact") from None


@dataclass(frozen=True, slots=True)
class DisclosureArtifact:
    """Syntactic/canonical validity only; trust and native BBS require verification."""

    raw: bytes

    def __post_init__(self):
        validate(strict_object(self.raw))

    def as_dict(self) -> dict:
        return strict_object(self.raw)

    @property
    def kind(self) -> str:
        return self.as_dict()["type"]


def artifact(value: dict) -> DisclosureArtifact:
    return DisclosureArtifact(encoded(validate(value)) + b"\n")


def parse_disclosure(value: bytes | str) -> DisclosureArtifact:
    try:
        return DisclosureArtifact(
            value.encode("utf-8") if isinstance(value, str) else value
        )
    except UnicodeError:
        raise InputError("Invalid disclosure encoding") from None


def sign_statement(
    identity: MachineIdentity, kind: str, statement: dict
) -> DisclosureArtifact:
    value = {
        "type": kind,
        "version": 1,
        "evaluator": public_identity_document(identity.public_identity),
        "statement": statement,
    }
    prefix = "myt-bbs-authorization-v1:" if kind == AUTH else "myt-bbs-revocation-v1:"
    value["id"] = prefix + digest(signed_content(value))
    value["signature"] = identity.sign(signed_content(value), CONTEXTS[kind]).signature
    return artifact(value)


def verify_statement(value: dict, expected_evaluator: str) -> None:
    validate(value)
    identity = parse_public_identity_document(value["evaluator"])
    if not identity.verify(
        signed_content(value),
        CONTEXTS[value["type"]],
        value["signature"],
        expected_machine_id=expected_evaluator,
    ).valid:
        raise InputError("Issuer identity authorization failed")


def base_messages(auth: dict, claims: dict) -> list[str]:
    return [
        PROFILE,
        auth["evaluator"]["machine_id"],
        auth["statement"]["bbs_key_id"],
        claims["subject_machine_id"],
        claims["network"],
        claims["policy_digest"],
        claims["metric_id"],
        str(claims["as_of"]),
        str(claims["issued_at"]),
        str(claims["expires_at"]),
    ]


def credential_messages(value: dict) -> list[str]:
    return base_messages(value["authorization"], value["claims"]) + [
        "true" if p else "false" for p in value["claims"]["predicates"]
    ]


def disclosed_indices(threshold: int) -> list[int]:
    if type(threshold) is not int or threshold not in LEVELS:
        raise InputError("Unsupported threshold")
    return list(range(10)) + [10 + LEVELS.index(threshold)]


def presentation_header(request: dict) -> bytes:
    validate(request)
    return b"MYT-REPUTATION-DISCLOSURE-PRESENTATION-V1\n" + encoded(request)


def control_content(body: dict) -> bytes:
    request = body["request"]
    return b"MYT-REPUTATION-DISCLOSURE-CONTROL-V1\n" + encoded(
        {
            "version": 1,
            "request_digest": digest(presentation_header(request)),
            "presentation_digest": digest(
                b"MYT-REPUTATION-PRESENTATION-BODY-V1\n" + encoded(body)
            ),
            "subject_machine_id": request["expected_subject_machine_id"],
            "bbs_key_id": request["expected_issuer_key_id"],
        }
    )
