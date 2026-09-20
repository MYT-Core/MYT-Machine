# Official Phase 4F candidate review scope

Baseline: 73beb99102f56671d6b2d85c9368bfa788249dc2.
Feature branch: feature/phase4f-bbs-selective-disclosure.
Main must remain unchanged. No release, tag, PyPI publication or deployment.
Python version remains 0.5.1 for regression compatibility; this feature build
is NOT the published v0.5.1 distribution. Optional companion is private and
separately packaged, with internal candidate version 0.6.0-dev.0.

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

The exact feature commit plus its GitHub CI results are the review handoff.
Local artifacts are validation-only, not install recommendations or a release.
Follow phase4f-bbs-review-checklist.md; explicitly report actual path/version
coverage, limitations, findings and retest requirements.

CRYPTO BACKEND EXTERNALLY QUALIFIED: NO.
EXTERNAL CRYPTO REVIEW REQUIRED: YES.

Successful engineering/CI gates authorize only feature-branch publication for
review. They do not authorize merging to main or production use.

Community design/adversarial-review credit: fallacyofall. Reference materials
were reviewed as untrusted input; no merge or cherry-pick of contributor history
was performed and no legal name is inferred.
