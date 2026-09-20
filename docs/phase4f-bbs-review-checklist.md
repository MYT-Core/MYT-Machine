# External cryptographic review checklist

CRYPTO BACKEND EXTERNALLY QUALIFIED: NO.
EXTERNAL CRYPTO REVIEW REQUIRED: YES.
Engineering tests and registry audits must NOT close the items below.

## Reviewer inputs

- Exact feature commit and baseline, recorded in the final handoff.
- docs/phase4f-protocol-v1.md and public phase4f-header-vector.json.
- docs/phase4f-bbs-codepath-map.md, threat model and audit gap analysis.
- companions/bbs/npm-shrinkwrap.json and machine-readable review evidence.
- Source under src/myt_machine/disclosure*.py and companions/bbs/src.
- 66 permanent Python tests, 67 native tests, separate 33-case attack harness
  plus nine final valid-signature adversarial cases.
- Existing Phase 4B identity framing and Phase 4E store/policy semantics.

## Open external qualification items

- [ ] Review exact Digital Bazaar 3.1.0 and Noble 2.4.0 code paths, not older audits.
- [ ] Confirm BLS12-381/SHA-256 suite, generator/domain derivation and assumptions.
- [ ] Review point decoding, infinity/subgroup rejection and canonical scalars.
- [ ] Review native signature/proof equations and malformed input behavior.
- [ ] Trace all native randomness and assess managed-runtime side channels.
- [ ] Confirm fixed 15-message mapping and exactly eleven disclosed positions.
- [ ] Confirm the selected boolean assertion cannot substitute another threshold.
- [ ] Independently reproduce public credential signature and 400-byte proof vector.
- [ ] Confirm raw credential/presentation headers, lengths and challenge inclusion.
- [ ] Confirm Base64url is transport only and cannot alter the signed bytes.
- [ ] Review 4B subject control and equality of all four expected-subject references.
- [ ] Review signed evaluator/key authorization and local sticky revocations.
- [ ] Review exact activation/expiry, stale status and clock rollback semantics.
- [ ] Assess trusted-evaluator and authenticated local-capability assumptions.
- [ ] Review SQLite atomic consume, corruption and hostile concurrent operations.
- [ ] Assess encrypted-key envelope, scrypt/AES-GCM use and secret lifetime.
- [ ] Assess public-identity correlation, repeated threshold inference and minimization.
- [ ] Review the complete composition and provide exact-version findings/coverage.
- [ ] Resolve findings and independently approve a specific final commit.

## Not claimed

No arithmetic hidden-integer range proof, global reputation score, anonymity,
global revocation discovery, secure-memory guarantee or proof of an evaluator's
honesty. Local status freshness records operator checking, not global truth.
No MYT trusted-setup ceremony is introduced; backend assumptions still require review.
This checklist is a review request, not a certification or deployment authorization.
