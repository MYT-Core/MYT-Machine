"""Unreleased Phase 4F candidate: evaluator assertions, NOT arithmetic ZK proofs."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from .disclosure_artifacts import (
    AUTH,
    CONTROL_CONTEXT,
    CREDENTIAL,
    LEVELS,
    METRIC,
    PRESENTATION,
    PURPOSE,
    REQUEST,
    REVOKE,
    SUITE,
    DisclosureArtifact,
    active,
    artifact,
    b64,
    base_messages,
    control_content,
    credential_messages,
    digest,
    disclosed_indices,
    encoded,
    key_id,
    presentation_header,
    sign_statement,
    verify_statement,
)
from .disclosure_backend import BbsBackend
from .disclosure_store import DisclosureStore
from .errors import InputError
from .identity import MachineIdentity
from .identity_artifacts import parse_public_identity_document, public_identity_document
from .payment_requests import bounded_int, unix_time
from .reputation_policy import ReputationPolicy, reputation_summary
from .reputation_store import ReputationStore


@dataclass(frozen=True, slots=True)
class DisclosurePolicy:
    """Independent verifier configuration. Never infer it from a received proof."""

    subject: str
    evaluator: str
    issuer_key_id: str
    network: str
    audience: str
    policy_digest: str
    threshold: int
    issuer_status_max_age: int = 300

    def request_fields(self):
        return {
            "expected_subject_machine_id": self.subject,
            "expected_evaluator_machine_id": self.evaluator,
            "expected_issuer_key_id": self.issuer_key_id,
            "network": self.network,
            "audience": self.audience,
            "policy_digest": self.policy_digest,
            "metric_id": METRIC,
            "threshold": self.threshold,
        }

    def __post_init__(self):
        bounded_int(self.issuer_status_max_age, "issuer freshness", 0, 3600)
        # Validate fields with a synthetic public nonce; requests use secrets below.
        artifact(
            {
                "type": REQUEST,
                "version": 1,
                "purpose": PURPOSE,
                **self.request_fields(),
                "challenge": b64(bytes(32)),
                "not_before": 0,
                "expires_at": 1,
            }
        )
        if self.subject == self.evaluator:
            raise InputError("Self-issued reputation is unsupported")


def reputation_policy_digest(policy: ReputationPolicy) -> str:
    if type(policy) is not ReputationPolicy:
        raise InputError("Expected official ReputationPolicy")
    policy.__post_init__()
    return digest(b"MYT-REPUTATION-POLICY-V1\n" + encoded(policy.as_dict()))


def create_disclosure_request(
    policy: DisclosurePolicy, store: DisclosureStore, *, lifetime=120
):
    policy.__post_init__()
    bounded_int(lifetime, "request lifetime", 1, 300)
    now = unix_time()
    value = artifact(
        {
            "type": REQUEST,
            "version": 1,
            "purpose": PURPOSE,
            **policy.request_fields(),
            "challenge": b64(secrets.token_bytes(32)),
            "not_before": now,
            "expires_at": now + lifetime,
        }
    )
    store.register(value)
    return value


def authorize_bbs_key(
    identity: MachineIdentity, backend: BbsBackend, *, network, lifetime=86400
):
    bounded_int(lifetime, "authorization lifetime", 1, 366 * 86400)
    public_key = backend.call("public-key", {})["public_key"]
    if backend.call("validate-key", {"public_key": public_key}) != {"valid": True}:
        raise InputError("Invalid issuer public key")
    now = unix_time()
    return sign_statement(
        identity,
        AUTH,
        {
            "bbs_public_key": public_key,
            "bbs_key_id": key_id(public_key),
            "ciphersuite": SUITE,
            "network": network,
            "purpose": PURPOSE,
            "not_before": now,
            "expires_at": now + lifetime,
        },
    )


def revoke_bbs_key(
    identity: MachineIdentity, authorization: DisclosureArtifact, *, reason
):
    auth = artifact(authorization.as_dict()).as_dict()
    if auth["type"] != AUTH:
        raise InputError("Expected issuer authorization")
    verify_statement(auth, identity.machine_id)
    return sign_statement(
        identity,
        REVOKE,
        {
            "network": auth["statement"]["network"],
            "issued_at": unix_time(),
            "authorization_id": auth["id"],
            "bbs_key_id": auth["statement"]["bbs_key_id"],
            "reason": reason,
        },
    )


def issue_reputation_credential(
    *,
    reputation_store: ReputationStore,
    policy: ReputationPolicy,
    subject: str,
    identity: MachineIdentity,
    authorization: DisclosureArtifact,
    issuer_state: DisclosureStore,
    backend: BbsBackend,
    lifetime=3600,
) -> DisclosureArtifact:
    """Always compute from validated Phase 4E state. No caller assertion shortcut."""
    if type(reputation_store) is not ReputationStore:
        raise InputError("Issuance requires the official local ReputationStore")
    bounded_int(lifetime, "credential lifetime", 1, 86400)
    pd = reputation_policy_digest(policy)
    auth = artifact(authorization.as_dict()).as_dict()
    if auth["type"] != AUTH:
        raise InputError("Expected issuer authorization")
    evaluator = identity.machine_id
    if evaluator == subject:
        raise InputError("Self-issued reputation is unsupported")
    issuer_state.check_issuer(auth, evaluator)
    public_key = auth["statement"]["bbs_public_key"]
    if backend.call("public-key", {}) != {"public_key": public_key}:
        raise InputError("Issuer key does not match authorization")
    now = unix_time()
    summary = reputation_summary(
        reputation_store,
        subject=subject,
        network=auth["statement"]["network"],
        policy=policy,
        as_of=now,
    )
    count = summary["objective_local_observations"][METRIC]
    bounded_int(count, "local evidence count", 0, 100000)
    value = {
        "type": CREDENTIAL,
        "version": 1,
        "authorization": auth,
        "claims": {
            "subject_machine_id": subject,
            "network": auth["statement"]["network"],
            "policy_digest": pd,
            "metric_id": METRIC,
            "as_of": now,
            "issued_at": now,
            "expires_at": min(now + lifetime, auth["statement"]["expires_at"]),
            "predicates": [count >= level for level in LEVELS],
        },
    }
    # Validate every signed field before accessing the signing capability.
    artifact({**value, "signature": b64(bytes(80))})
    result = backend.call(
        "sign",
        {
            "public_key": public_key,
            "messages": credential_messages(value),
        },
    )
    if set(result) != {"signature"}:
        raise InputError("Unexpected BBS signing result")
    value["signature"] = result["signature"]
    signed = artifact(value)
    if backend.call(
        "verify-signature",
        {
            "public_key": public_key,
            "messages": credential_messages(value),
            "signature": value["signature"],
        },
    ) != {"valid": True}:
        raise InputError("Issued credential signature failed verification")
    return signed


def _match(policy, request, auth, claims, now):
    policy.__post_init__()
    if any(request[k] != v for k, v in policy.request_fields().items()):
        raise InputError(
            "Disclosure request does not match independent verifier policy"
        )
    active(request["not_before"], request["expires_at"], now)
    active(claims["issued_at"], claims["expires_at"], now)
    if (
        auth["evaluator"]["machine_id"] != policy.evaluator
        or auth["statement"]["bbs_key_id"] != policy.issuer_key_id
        or claims["subject_machine_id"] != policy.subject
        or claims["network"] != policy.network
        or claims["policy_digest"] != policy.policy_digest
        or claims["metric_id"] != METRIC
    ):
        raise InputError(
            "Credential does not match request and independent verifier policy"
        )


def present_reputation_credential(
    *,
    credential: DisclosureArtifact,
    request: DisclosureArtifact,
    policy: DisclosurePolicy,
    identity: MachineIdentity,
    issuer_state: DisclosureStore,
    backend: BbsBackend,
) -> DisclosureArtifact:
    cred, req = (
        artifact(credential.as_dict()).as_dict(),
        artifact(request.as_dict()).as_dict(),
    )
    if cred["type"] != CREDENTIAL or req["type"] != REQUEST:
        raise InputError("Expected credential and request")
    auth, claims = cred["authorization"], cred["claims"]
    _match(policy, req, auth, claims, unix_time())
    if identity.machine_id != policy.subject:
        raise InputError("Holder does not control the expected subject identity")
    issuer_state.check_issuer(
        auth, policy.evaluator, freshness=policy.issuer_status_max_age
    )
    if claims["predicates"][LEVELS.index(policy.threshold)] is not True:
        raise InputError("Requested predicate was not asserted by evaluator")
    result = backend.call(
        "derive-proof",
        {
            "public_key": auth["statement"]["bbs_public_key"],
            "signature": cred["signature"],
            "messages": credential_messages(cred),
            "presentation_header": b64(presentation_header(req)),
            "request": req,
            "threshold": policy.threshold,
        },
    )
    if set(result) != {"proof"}:
        raise InputError("Unexpected BBS presentation result")
    body = {
        "type": PRESENTATION,
        "version": 1,
        "authorization": auth,
        "claims": {k: v for k, v in claims.items() if k != "predicates"},
        "request": req,
        "proof": result["proof"],
    }
    signed = identity.sign(control_content(body), CONTROL_CONTEXT)
    return artifact(
        {
            **body,
            "subject_control": {
                "identity": public_identity_document(identity.public_identity),
                "signature": signed.signature,
            },
        }
    )


@dataclass(frozen=True, slots=True)
class DisclosureVerification:
    valid: bool
    consumed: bool


def verify_reputation_presentation(
    *,
    presentation: DisclosureArtifact,
    policy: DisclosurePolicy,
    store: DisclosureStore,
    backend: BbsBackend,
) -> DisclosureVerification:
    value = artifact(presentation.as_dict()).as_dict()
    if value["type"] != PRESENTATION:
        raise InputError("Expected disclosure presentation")
    request, auth, claims = value["request"], value["authorization"], value["claims"]
    policy.__post_init__()
    try:
        # Keep status validation, cryptographic checks and consume in one transaction.
        # A failed backend call rolls back; caller-supplied verification flags do not exist.
        with store._transaction() as db:
            now = store._clock(db)
            _match(policy, request, auth, claims, now)
            store._issuer(db, auth, policy.evaluator, now, policy.issuer_status_max_age)
            row = db.execute(
                "SELECT artifact,used FROM requests WHERE challenge=?",
                (request["challenge"],),
            ).fetchone()
            if row is None or row[0] != artifact(request).raw or row[1] != 0:
                raise InputError(
                    "Disclosure request missing, altered or already consumed"
                )
            ctl = value["subject_control"]
            identity = parse_public_identity_document(ctl["identity"])
            body = {k: v for k, v in value.items() if k != "subject_control"}
            if not identity.verify(
                control_content(body),
                CONTROL_CONTEXT,
                ctl["signature"],
                expected_machine_id=policy.subject,
            ).valid:
                raise InputError("Expected subject control failed")
            disclosed_indices(policy.threshold)
            result = backend.call(
                "verify-proof",
                {
                    "public_key": auth["statement"]["bbs_public_key"],
                    "proof": value["proof"],
                    "messages": base_messages(auth, claims) + ["true"],
                    "presentation_header": b64(presentation_header(request)),
                    "request": request,
                    "threshold": policy.threshold,
                },
            )
            if result != {"valid": True}:
                raise InputError("BBS proof failed")
            now = store._clock(db)
            _match(policy, request, auth, claims, now)
            store._issuer(db, auth, policy.evaluator, now, policy.issuer_status_max_age)
            cursor = db.execute(
                "UPDATE requests SET used=1 WHERE challenge=? AND used=0",
                (request["challenge"],),
            )
            if cursor.rowcount != 1:
                raise InputError("Disclosure request concurrently consumed")
        return DisclosureVerification(True, True)
    except InputError:
        return DisclosureVerification(False, False)
