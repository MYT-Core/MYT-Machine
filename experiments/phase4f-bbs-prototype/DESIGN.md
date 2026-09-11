# Experimental Phase 4F design note

## Verdict

The composition is feasible as a small experiment with
`@digitalbazaar/bbs-signatures@3.1.0`. The positive flow works and the specified
substitution, tampering, replay, expiry, issuer, subject, and key-authorization
failures are rejected.

This is **not a production approval**. The backend's tagged 3.1.0 source says it
implements the IETF BBS draft-06 interface, while the current standards work has
moved beyond that draft. This experiment did not establish an independent audit
covering the exact 3.1.0 + Noble 2.4.0 paths or the MYT composition. Keep the
backend and all 4F code outside production until that assurance gap is resolved.

Primary implementation reference:
<https://github.com/digitalbazaar/bbs-signatures/tree/v3.1.0>

## Meaning of the proof

The evaluator receives an already validated Phase 4E snapshot and applies a
caller-local policy compatible with v0.5.0's concepts: trusted issuers,
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

The Phase 4E adapter in this experiment accepts an object explicitly labelled
`validated-phase4e-v0.5.x-snapshot`. It exercises local policy semantics but does
not reimplement the production Phase 4E artifact parser or Ed25519 verification.
A real integration must call the existing, hardened `ReputationStore` and
`reputation_summary` boundary rather than trusting arbitrary JSON bearing that
label.

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

## Replay and lifecycle limits

The in-memory challenge store demonstrates expiry and one-time consumption, but
it is not durable or atomic across processes. Production needs a bounded,
persistent store with an atomic unused-to-used transition. Cryptographic proof
verification alone does not stop replay.

The prototype treats evaluator key authorization as needing to be active at
verification time and gives credentials a maximum 24-hour lifetime. Credential
revocation, evaluator-key revocation, rotation, status distribution, clock
policy, multi-process races, secure secret-key storage, side-channel analysis,
and denial-of-service limits need separate designs.

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
- full credential message tampering.

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
