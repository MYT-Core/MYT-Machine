# MYT Machine Phase 4F experiment

Status: **experimental, isolated, and not approved for production**.

This is a minimal proof of the proposed Phase 4F composition:

```text
validated Phase 4E evidence
  -> caller-local ReputationPolicy
  -> trusted evaluator computes a bounded boolean predicate
  -> evaluator's Phase 4B Ed25519 identity authorizes a BBS issuer key
  -> BBS credential
  -> fresh verifier challenge + audience + requested predicate
  -> BBS selective-disclosure proof
  -> Phase 4B subject-control signature bound to that exact proof
```

The example starts with the exact local value `37`, and the evaluator issues
`verified_recipient_settlement_events >= 25 = true`. The presentation reveals
the boolean predicate assertion but hides both `37` and the Phase 4E evidence
digest.

This proves that a trusted evaluator signed that assertion. It is **not** a
mathematical zero-knowledge range proof that an independently committed hidden
integer is at least 25.

## Run

Requirements: Node.js 20.19.0 or newer and npm.

```text
npm ci --ignore-scripts
npm test
npm run demo
```

`npm test` regenerates the vector, runs the positive flow, and runs all attack
tests. The checked-in `package-lock.json` pins every installed package.

## Files

- `src/phase4f.mjs` — protocol experiment and verification boundary.
- `src/fixture.mjs` — deterministic identities, synthetic validated Phase 4E
  input, policy, credential, and request fixture.
- `test/phase4f.test.mjs` — positive and hostile tests.
- `vectors/phase4f-v1.json` — standalone generated vector.
- `DESIGN.md` — concise design, trust boundary, limitations, and verdict.
- `DEPENDENCIES.md` — exact dependency and environment record.
- `TEST-TRANSCRIPT.txt` — recorded install, test, demo, and dependency output.
- `SHA256SUMS.txt` — SHA-256 manifest for the shareable tree.

The vector contains public test seeds. Never use them for real identities or
issuer keys. BBS proof generation is intentionally randomized, so regenerating
the vector changes the proof and the proof-bound subject signature.
