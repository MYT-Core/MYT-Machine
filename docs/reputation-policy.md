# Local policy, storage and revocation

## Default and deterministic evaluation

`ReputationPolicy` defaults to an **empty trusted-issuer allowlist**. Signed
opinions remain inspectable but none is accepted by the default local policy.
Adding a Machine ID to the allowlist is the operator's trust decision, not a
decision made by MYT-Core or a protocol authority. IDs do not establish unique
people, independence, devices, businesses or absence of collusion.

An explicit `as_of` integer makes evaluations repeatable. For one subject and
network, evaluation uses one consistent SQLite transaction snapshot:

1. Verify schemas, canonical encodings, indexes, digests and signatures on read.
2. Identify matching issuer-signed revocations, irrespective of claimed time.
3. Remove revoked attestations. Self-attestations cannot enter the parser/store.
4. Require membership in the caller's `trusted_issuers` tuple.
5. Require `min_age <= as_of - issued_at <= max_age`; default 0 to 253402300799.
   Future claims therefore contribute nothing. This is filtering issuer claims,
   NOT proof of age or an authorization timestamp.
6. If `require_settlement`, require the evidence digest in this store's verified
   settlement observations for the **same subject and network**. This is not proof
   that the attesting issuer was the payer or provided/received the service.
7. Sort descending issuer-claimed time, then ascending artifact ID. Accept up to
   `max_per_issuer` (default 1, supported 1-100) per issuer.

The output has three distinct sections: `objective_local_observations`,
`signed_opinions`, `local_policy_output`. Outcome counts and unique Machine
Identity issuer counts belong only to the last section. No numeric score or
economic weighting is supplied. The raw cryptographically-valid count includes
revoked and untrusted opinions and must never be used as a trust score.

## Revocation

An issuer signs a `myt-reputation-revocation` with the original Phase 4B key.
`reputation revoke` requires the original, cryptographically valid attestation
and matching issuer. The target attestation remains stored, never deleted.
Import verifies the revocation signature. When a target is known, a different
issuer/network or a revocation target is rejected. Before the target is known,
the revocation can be stored pending. It takes effect only for an attestation
whose issuer, network and ID all match. An unrelated pending revocation cannot
block a legitimate target import or make its opinion disappear.

Repeated identical imports are idempotent. Multiple issuer-authorized revocations
of one attestation exclude it only once. A valid revocation does not establish
chronological ordering or prove when authorization occurred. It is an instruction
to exclude that opinion once the verifier has received it. There is no online
registry, guaranteed revocation delivery, retraction of revocations, key rotation
or recovery protocol. Offline verification alone cannot know about unseen
revocations, and generic `reputation verify` does not check target authority.

## Storage trust and limits

`ReputationStore` is a service-owned SQLite database in a directory not writable
by other users. Unix files require mode 0600 and must be regular, non-symlink,
single-link files. On Windows use an operator-only NTFS ACL: encryption of
identity PEM keys does not encrypt the reputation database. Protect the directory
and backups, not only the database file. Hostile same-account processes, modified
application code, hostile SQLite files and administrator access are outside the
boundary. Unix parent directories must also be controlled by the operator.

Each operation opens a connection, sets trusted_schema=OFF and synchronous=FULL,
and uses BEGIN IMMEDIATE; unique IDs/digests and network/transaction constraints
are durable across processes/restarts. Failure rolls back. Default capacity is
10000 artifacts plus observations (SDK configurable 1-100000); there is no
automatic deletion to make room. Full snapshot validation trades performance
for fail-closed corruption detection. This is intended for bounded local stores,
not a public global registry. Public lists use ID cursors and limits 1-200.

Signatures and canonical/index checks detect inconsistent stored data, but they
cannot authenticate an entire database against an attacker with write access.
In particular settlement observations are **local trust records**, not signed
portable certificates. Copying their hashes cannot make another installation
regard them as verified. Only the trusted read-only 4C/4D bridge writes them;
there is no public JSON-import path for objective observations.

## Threats and explicit non-goals

Self-attestations are rejected; per-issuer caps constrain repeated opinions;
allowlists constrain unknown issuers. None prevents a trusted colluding issuer
from lying, reissuing an opinion, manipulating its timestamp or creating
economically circular payments. Unique Machine IDs are not unique people.
Many self-controlled transactions can create many genuine settlement
observations: **they confer no automatic trust or service-quality credit**.
Replaying one transaction or invoice cannot create multiple local observations.

Revocation availability, policy selection and freshness of chain observations
remain local responsibilities. Summaries are not authenticated global facts,
selective-disclosure proofs or statements of complete history. Evidence hashes
are stable inputs for future work, not commitments to a Phase 4F construction.
