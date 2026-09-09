"""Caller-local deterministic counts, never a global MYT reputation score."""

from __future__ import annotations

from dataclasses import dataclass

from .errors import InputError
from .identity import machine_id_digest
from .payment_requests import MAX_TIMESTAMP, bounded_int, unix_time, validate_network
from .reputation import ATTESTATION, REVOCATION
from .reputation_store import ReputationStore, settlement_digest


@dataclass(frozen=True, slots=True)
class ReputationPolicy:
    trusted_issuers: tuple[str, ...] = ()
    max_per_issuer: int = 1
    min_age: int = 0
    max_age: int = MAX_TIMESTAMP
    require_settlement: bool = False

    def __post_init__(self):
        if (
            not isinstance(self.trusted_issuers, tuple)
            or len(self.trusted_issuers) > 1000
        ):
            raise InputError("Policy requires a bounded tuple of trusted issuer IDs")
        for issuer in self.trusted_issuers:
            machine_id_digest(issuer)
        if len(set(self.trusted_issuers)) != len(self.trusted_issuers):
            raise InputError("Duplicate policy issuer")
        bounded_int(self.max_per_issuer, "per-issuer limit", 1, 100)
        bounded_int(self.min_age, "minimum age", 0, MAX_TIMESTAMP)
        bounded_int(self.max_age, "maximum age", self.min_age, MAX_TIMESTAMP)
        if type(self.require_settlement) is not bool:
            raise InputError("Settlement policy flag must be boolean")

    def as_dict(self):
        return {
            "trusted_issuers": sorted(self.trusted_issuers),
            "max_per_issuer": self.max_per_issuer,
            "min_age": self.min_age,
            "max_age": self.max_age,
            "require_settlement": self.require_settlement,
        }


def reputation_summary(
    store: ReputationStore,
    *,
    subject: str,
    network: str,
    policy: ReputationPolicy,
    as_of: int,
) -> dict:
    machine_id_digest(subject)
    validate_network(network)
    policy.__post_init__()
    unix_time(as_of)
    artifacts, events = store.snapshot(network=network)
    revocations = {
        (a.statement["attestation_id"], a.issuer_machine_id)
        for a in artifacts
        if a.kind == REVOCATION
    }
    attestations = [
        a
        for a in artifacts
        if a.kind == ATTESTATION and a.statement["subject_machine_id"] == subject
    ]
    settlements = [s for s in events if s["subject_machine_id"] == subject]
    linked = {settlement_digest(s) for s in settlements}
    accepted = []
    contributions: dict[str, int] = {}
    revoked = 0
    # Newest issuer-claimed timestamp first, then content ID: stable tie-break.
    for a in sorted(attestations, key=lambda a: (-a.statement["issued_at"], a.id)):
        s = a.statement
        if (a.id, a.issuer_machine_id) in revocations:
            revoked += 1
            continue
        if (
            a.issuer_machine_id == subject
            or a.issuer_machine_id not in policy.trusted_issuers
        ):
            continue
        if not policy.min_age <= as_of - s["issued_at"] <= policy.max_age:
            continue
        if policy.require_settlement and s["evidence_digest"] not in linked:
            continue
        if contributions.get(a.issuer_machine_id, 0) >= policy.max_per_issuer:
            continue
        contributions[a.issuer_machine_id] = (
            contributions.get(a.issuer_machine_id, 0) + 1
        )
        accepted.append(a)
    times = [a.statement["issued_at"] for a in accepted]
    return {
        "subject_machine_id": subject,
        "network": network,
        "objective_local_observations": {
            "verified_recipient_settlement_events": len(settlements)
        },
        "signed_opinions": {
            "cryptographically_valid_attestations": len(attestations),
            "revoked_attestations": revoked,
        },
        "local_policy_output": {
            "policy": policy.as_dict(),
            "as_of": as_of,
            "accepted_attestations": len(accepted),
            "unique_machine_identity_issuers": len(contributions),
            "positive": sum(a.statement["outcome"] == "POSITIVE" for a in accepted),
            "neutral": sum(a.statement["outcome"] == "NEUTRAL" for a in accepted),
            "negative": sum(a.statement["outcome"] == "NEGATIVE" for a in accepted),
            "oldest_accepted_issuer_claimed_time": min(times) if times else None,
            "newest_accepted_issuer_claimed_time": max(times) if times else None,
        },
    }
