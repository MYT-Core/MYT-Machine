# MYT Machine Phase 4F experiment

Status: **production-candidate engineering experiment, isolated and not approved
for production**.

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

Requirements: Node.js 20.19.0 or newer, npm, Python 3.10 or newer, and the
MYT Machine v0.5.1 source tree containing this directory.

```text
npm ci --ignore-scripts
# If Python is not on PATH, set MYT_PHASE4F_PYTHON to its full executable path.
npm test
npm run demo
```

`npm test` regenerates the vector and runs the Python persistence/Phase 4E tests,
the positive BBS flow, and all attack tests. The checked-in `package-lock.json`
pins every installed JavaScript package.

## Production-candidate milestone

The branch adds four concrete safety components around the original proof:

- a Python adapter that opens the real v0.5.1 `ReputationStore` and calls the
  real `reputation_summary`; caller-supplied "validated snapshot" JSON is not an
  accepted adapter input;
- durable SQLite verifier challenges with atomic one-use consumption across
  restarts and competing processes;
- Phase 4B-signed BBS issuer-key revocations stored durably and reverified when
  a presentation is checked; and
- encrypted BBS secret-key files using scrypt plus AES-256-GCM, exclusive file
  creation, key-ID binding, and Unix mode checks.

These features make the experiment a stronger audit candidate. They do not
resolve the external backend-audit/spec-version gate, revocation distribution,
Phase 4B identity recovery, hardware-backed signing, or independent review.
Production-style callers must supply the durable store as both the challenge
store and key-status store. The optional in-memory/no-status paths remain only
so the original deterministic experiment and its vectors stay reproducible.

## Files

- `src/phase4f.mjs` — protocol experiment and verification boundary.
- `src/python-bridge.mjs` — bounded JavaScript-to-Python adapter and durable
  verifier-state client.
- `src/secure-key-store.mjs` — encrypted BBS issuer-key storage experiment.
- `bridge/phase4e_adapter.py` — real Phase 4E store/policy evaluation boundary.
- `bridge/challenge_store.py` — durable replay and BBS key-revocation state.
- `src/fixture.mjs` — deterministic identities, synthetic validated Phase 4E
  input, policy, credential, and request fixture.
- `test/phase4f.test.mjs` — positive and hostile tests.
- `test/phase4f-integration.test.mjs` — real Phase 4E-to-BBS and durable-state
  integration tests.
- `test/test_bridges.py` — restart, corruption, concurrency, and adapter tests.
- `vectors/phase4f-v1.json` — standalone generated vector.
- `DESIGN.md` — concise design, trust boundary, limitations, and verdict.
- `DEPENDENCIES.md` — exact dependency and environment record.
- `TEST-TRANSCRIPT.txt` — recorded install, test, demo, and dependency output.
- `SHA256SUMS.txt` — SHA-256 manifest for the shareable tree.

The vector contains public test seeds. Never use them for real identities or
issuer keys. BBS proof generation is intentionally randomized, so regenerating
the vector changes the proof and the proof-bound subject signature.
