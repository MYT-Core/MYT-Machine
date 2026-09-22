# Experimental Phase 4F design note

## Verdict

The composition is feasible as a production-candidate experiment with
`@digitalbazaar/bbs-signatures@3.1.0`. The positive flow works and the specified
substitution, tampering, replay, expiry, issuer, subject, and key-authorization
failures are rejected. The candidate now uses the real Phase 4E store/policy
boundary, durable one-use verifier state, signed BBS-key revocations, and
encrypted BBS-key files.

This is **not a production approval**. The backend's tagged 3.1.0 source says it
implements the IETF BBS draft-06 interface, while the current standards work has
moved beyond that draft. This experiment did not establish an independent audit
covering the exact 3.1.0 + Noble 2.4.0 paths or the MYT composition. Keep the
backend and all 4F code outside production until that assurance gap is resolved.

Primary implementation reference:
<https://github.com/digitalbazaar/bbs-signatures/tree/v3.1.0>

## Meaning of the proof

The evaluator opens the real Phase 4E evidence store and applies a caller-local
policy compatible with v0.5.0's concepts: trusted issuers,
per-issuer caps, age bounds, optional settlement linkage, explicit network, and
explicit `as_of`. It then computes the bounded catalog predicate:

```text
metric:    verified_recipient_settlement_events = 37
predicate: verified_recipient_settlement_events >= 25
assertion: true
```

The BBS proof establishes possession of a credential signed by the authorized
evaluator BBS key and integrity of the disclosed messages. It establishes that
the evaluator asserted `true`; it does not evaluate `37 >= 25` inside zero
knowledge. The evaluator sees the input and exact metric. Trust in the evaluator
and its Phase 4E validation is therefore part of the security model.

The deterministic vector still uses a synthetic Phase 4E snapshot so that its
BBS-only test fixture remains portable. The production-candidate adapter is
different: `bridge/phase4e_adapter.py` opens the actual v0.5.1
`ReputationStore`, calls the actual `reputation_summary`, and rejects extra input
such as a caller-supplied snapshot. It takes before/after manifests of the
append-only store around evaluation and fails if evidence changes. The hidden
evidence digest commits to the validated artifact/settlement digests and the
exact summary without exporting those records to the JavaScript boundary.

## Signed credential messages

Messages have fixed indexes; arbitrary JSON-to-message mapping is excluded.

| Index | Message | Disclosed? |
|---:|---|:---:|
| 0 | schema | yes |
| 1 | evaluator Machine ID | yes |
| 2 | BBS key ID | yes |
| 3 | subject Machine ID | yes |
| 4 | network | yes |
| 5 | local policy digest | yes |
| 6 | validated Phase 4E snapshot digest | **no** |
| 7 | exact metric identifier | yes |
| 8 | exact metric value (`37`) | **no** |
| 9-12 | predicate identifier, operator, threshold, result | yes |
| 13-14 | issued-at and expiry | yes |

With exactly two hidden messages, the raw BBS proof is 336 bytes in this
backend/ciphersuite. Complete JSON transport is larger and is recorded in the
generated vector and transcript.

## Composition and bindings

1. The evaluator's Phase 4B Ed25519 identity signs a canonical authorization for
   a 96-byte BLS12-381 BBS public key, its key ID, purpose, network, activation,
   and expiry. Verification pins the evaluator Machine ID independently.
2. The BBS credential signs the evaluator ID, BBS key ID, subject, network,
   policy digest, hidden evidence/metric, predicate, and lifetime.
3. The verifier stores a fresh 32-byte challenge with audience, network, policy
   digest, requested predicate, creation, expiry, and `used=false` state.
4. The complete request is a canonical, domain-separated BBS presentation
   header. Audience, challenge, policy, network, and predicate substitution
   therefore invalidate the proof.
5. The subject signs a Phase 4B frame containing hashes of the exact request and
   BBS proof, plus the BBS key ID and subject Machine ID. This prevents mixing a
   valid identity response with a different BBS presentation.
6. Only after every check succeeds is the challenge marked used.

The implementation reproduces the Phase 4B v1 Machine ID derivation and
signature frame. A regression test matches MYT's published deterministic vector.

## Subject privacy limitation

The subject Machine ID is disclosed. That is deliberate. A normal Ed25519
challenge signature proves control of a public identity, but it cannot prove in
zero knowledge that this public identity equals a hidden BBS message. Hiding the
subject while retaining non-transferability needs an additional, carefully
reviewed equality/link-secret construction. This prototype does not invent one.

## Durable replay state

`bridge/challenge_store.py` stores the complete canonical verifier request in a
service-owned SQLite database. It uses one connection and `BEGIN IMMEDIATE` per
operation, `synchronous=FULL`, a unique challenge key, bounded capacity, and an
atomic `used_at IS NULL` update. Verification returns success only after that
update wins. Restart, competing-consumer, corruption, expiry, and replay tests
fail closed. Expired records may be pruned only after a bounded retention
period; "durable" does not mean storing random nonces forever.

The JavaScript bridge currently starts a short-lived Python process per state
operation. It passes public challenge/status data through bounded canonical JSON
and never invokes a shell. A deployed service should replace process startup
with an authenticated local service or equally narrow in-process binding after
that interface receives review.

Every production-style issuance, presentation, and verification call must pass
the durable key-status store; verification must also pass the durable challenge
store. The optional in-memory/no-status paths in the low-level module are kept
only for the original deterministic vector tests, not as deployment defaults.

## BBS issuer-key revocation

The evaluator's Phase 4B key signs a domain-separated revocation bound to the
exact authorization ID, BBS key ID, evaluator, network, reason, and claimed
time. A durable store accepts only a cryptographically verified revocation,
treats identical imports as idempotent, rejects conflicting replacements, and
revalidates the signed artifact during presentation verification. A valid
revocation excludes the key regardless of its claimed time, matching Phase 4E's
fail-safe revocation semantics.

This is local revocation enforcement, not global revocation delivery. A
production network still needs a signed status-distribution/freshness policy.
Phase 4B identity compromise recovery also remains a separate protocol problem.

## Encrypted BBS issuer-key storage

`src/secure-key-store.mjs` encrypts the 32-byte BBS secret scalar with
AES-256-GCM under a scrypt-derived wrapping key (`N=131072`, `r=8`, `p=1`). The
authenticated metadata binds the ciphertext to its derived BBS public-key ID.
Files are created exclusively and never overwritten; Unix files must remain
regular, single-link mode `0600` files. Windows deployments must add an
operator-only NTFS ACL. Passphrase and wrapping-key copies are overwritten on a
best-effort basis after use.

This protects a copied file at rest. It does not protect a compromised service
account or process, guarantee JavaScript garbage-collector zeroization, or
provide hardware-backed/non-exportable BLS12-381 operations.

The candidate treats evaluator key authorization as needing to be active at
verification time and gives credentials a maximum 24-hour lifetime. Credential
revocation, remote status distribution, complete rotation ceremonies, clock
policy, Phase 4B recovery, side-channel analysis, and deployment denial-of-
service limits still need separate review or design.

## Tested failures

- replay after one successful verification;
- audience substitution;
- verifier challenge substitution;
- requested-predicate substitution;
- disclosed claim tampering;
- wrong BBS issuer key;
- wrong Phase 4B subject controller;
- expired credential and expired challenge;
- tampered, expired, untrusted-evaluator, wrong-purpose, and wrong-network BBS
  key authorizations;
- issuer secret key not matching the authorized public key;
- full credential message tampering;
- replay after verifier restart and competing durable consumers;
- corrupt durable challenge state;
- signed, persisted BBS key revocation and revocation tampering;
- wrong BBS key-file passphrase/key ID, modified ciphertext, and overwrite;
- caller-supplied fake Phase 4E snapshot input.

Two presentations derived from the same credential are also checked to have
different randomized BBS proof bytes while both verify with fresh challenge
state. This demonstrates proof randomization, not a complete application-level
unlinkability guarantee: disclosed subject, evaluator, policy, and claim values
remain correlatable.

## Fallback position

ZKryptium 0.7.0 remains a fallback candidate only. It is intentionally not
installed or hidden behind an untested runtime switch. Adding it would double
the cryptographic boundary and vector matrix. A fallback should be implemented
only after the same message mapping, presentation-header binding, exact-version
review, and hostile tests are ported explicitly.
