# Official Phase 4F candidate review scope

Repository: MYT-Core/MYT-Machine.
Review ONLY the fixed annotated tag v0.6.0-rc1 and its exact peeled commit SHA
recorded in the public release notes and external-review handoff. Verify using
`git rev-parse 'v0.6.0-rc1^{commit}'` and compare with that published SHA.
Do not review moving main or latest HEAD as a substitute.

Reviewed feature ancestor: dc69abb41f8f044abecd146137162357fb242ffb.
Previous stable baseline: 73beb99102f56671d6b2d85c9368bfa788249dc2.
Python version: 0.6.0rc1. Separate optional companion: 0.6.0-rc1.
PUBLIC REVIEW CANDIDATE. External cryptographic review: PENDING.
Backend externally qualified: NO. No production approval, PyPI or deployment.

## Security claim to evaluate

A verifier accepts a randomized BBS presentation of an assertion signed by its
independently trusted evaluator and bound to its independently expected
Phase 4B subject, network, audience, policy, threshold and exact one-time request.
It additionally verifies current subject-key control for that request.

The assertion is computed from actual local Phase 4E evidence.
It does not cryptographically prove an arithmetic relation over a committed
hidden integer, prove the evaluator honest, or establish global reputation.

## Review boundary

Python owns Phase 4E policy/evidence, unchanged Phase 4B keys/signatures,
canonical artifacts, independent verifier policy and private durable replay state.
The optional persistent Node service owns BBS operations and its encrypted BBS
key. Its capability grants local signing authority and must never be public.
A keyless companion is sufficient for verification. Only loopback is supported.
Existing 4A-4E commands do not require or spawn Node.

Native backend is exactly Digital Bazaar BBS 3.1.0 plus Noble curves/hashes 2.4.0.
The locked dependency graph, source references and relevant upstream functions
are documented separately. No native batch-verification interface is exposed.

## Delivered engineering evidence

See MYT_Phase4F_Validation.md and phase4f-bbs-review-evidence.json for measured
results, local package hashes and platform versions. Public vector bytes are
in phase4f-header-vector.json. Its historical timestamps intentionally do not
constitute a currently usable authentication; native cryptographic verification
and framing checks remain reproducible.

Tests use ephemeral keys and synthetic local settlement observations.
No funds were sent and no Wallet RPC, daemon, blockchain, Testnet or Mainnet
access was needed for this candidate review.
The separate attack harness is independently constructed relative to product
serialization where practical, but executed by the same engineering agent.
It is NOT a third-party cryptographic audit.

## Handoff and remaining gate

The exact release-tag commit, public asset hashes and main/tag CI results form
the review handoff. Historical feature-validation hashes are NOT release hashes.
Use the release's SHA256SUMS.txt for the separately published RC artifacts.
Follow phase4f-bbs-review-checklist.md; explicitly report actual path/version
coverage, limitations, findings and retest requirements.

CRYPTO BACKEND EXTERNALLY QUALIFIED: NO.
EXTERNAL CRYPTO REVIEW REQUIRED: YES.

Separate express authorization permits main integration and a public prerelease
before external review. Successful engineering/CI gates do NOT constitute
independent cryptographic qualification or authorize production use.

Community design/adversarial-review credit: fallacyofall. Reference materials
were reviewed as untrusted input; no merge or cherry-pick of contributor history
was performed and no legal name is inferred.
