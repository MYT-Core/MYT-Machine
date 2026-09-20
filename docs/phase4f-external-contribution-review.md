# Current Candidate Scope (2026-09-20)

The material below is retained historical research/external-contribution evidence.
The official feature candidate now implements evaluator-signed BBS selective disclosure;
not an arithmetic hidden-value range proof, private-balance proof, counterparty
anonymity or general ZK computation. Current normative protocol and engineering
results: [Phase 4F protocol](phase4f-protocol-v1.md) and
[validation](../MYT_Phase4F_Validation.md). External cryptographic qualification
remains NO; no main merge or release is authorized. Earlier versions, counts and
blocked prototype decisions below are not current runtime support claims.

---

# Phase 4F External Contribution Review

Review date: 2026-09-11. Baseline: `73beb99102f56671d6b2d85c9368bfa788249dc2`.

## Pre-execution static gate

**SAFE TO TEST**, limited to isolated copies, public test fixtures, explicit
runtime paths and `npm ci --ignore-scripts`. This is not production approval
or independent cryptographic qualification.

Sources attributed to public GitHub contributor **fallacyofall**:

- Prototype: `fallacyofall/myt-phase4f-experiment`,
  `b8b8e68a200fdd406dcd790f0235a44505430154`.
- Candidate: `fallacyofall/MYT-Machine-Phase4F-Private`, branch
  `experiment/phase4f-production-candidate`,
  `85bd11ca26f6412cd7d3e59b582962bedbc98b3c`.
- Intermediate commit: `3bc606c4e655721c9a9e745533b1e2dba0d9376e`.
- Candidate merge base equals baseline; two commits ahead, zero behind.
  Files outside `experiments/` match official v0.5.1 byte-for-byte.
  The repository is publicly accessible despite its name.

All JavaScript modules, Python bridges/tests, PowerShell scripts, manifests,
vectors, documentation and prototype-to-candidate differences were inspected
before execution. No instruction override, hidden Unicode format character,
credential/token access, wallet/daemon call, telemetry or network-upload path
was found in the inspected experiment. Deterministic seeds are public test-only
fixtures. No real identity or wallet material is used.

The candidate invokes Python with `shell: false`, a bundled script, 15-second
timeout and bounded I/O. Its executable selection and inherited environment
are not approved as a production boundary. Tests remove only their generated
temporary directories. Vector/checksum/transcript generators overwrite their
own outputs; reproduction preserves originals and runs on copies. `pretest`
invokes the reviewed vector generator. No install lifecycle script is declared.

The locked graph is Digital Bazaar BBS 3.1.0, Noble curves 2.4.0 and Noble hashes
2.4.0, public npm URLs and SHA-512 integrity fields. Fresh registry/audit and
runtime evidence will be recorded below.

The prototype manifest has one newline discrepancy: `TEST-TRANSCRIPT.txt` in Git
has LF and SHA-256
`1d3dee132b9ece516257b496811dbfff28d8090ba8bb864cd8972171f1ecedcd`.
Converting only newlines to CRLF yields its recorded hash
`ee58d3f2e5b9e801c842b9779c33a51c733aa26c476636c5c397028d0ae1d2af`.
Every other prototype entry and all candidate entries match. Contributor-local
paths in transcripts must not be copied into official product documentation.
Attribution uses the verified public handle, not an inferred legal name.

## Initial independent-review questions

Inspection identifies missing independently expected subject/purpose in the
request/verifier, optional key-status enforcement, caller-supplied evaluation
issuance and absent strict raw-artifact parser boundaries. Controlled public-
fixture tests applied the explicit implementation stop. The follow-up below
records the three reproduced blockers and the separately tested remediation.

All six pre-existing research files were backed up and hash-verified. Their
historical findings remain unchanged.

## Independent finding reproduction

The archived external candidate is **NOT production-approved**. Its green
original suites did not exercise the following application requirements.
Independent attack code reproduced all three failures on Linux and native
Windows, using public disposable fixtures only. The same harness also checked
a successful legitimate verification followed by a rejected replay.

| ID | Classification | Reproduced failure | Security consequence |
| --- | --- | --- | --- |
| F4F-01 | Application authentication / binding | A valid B credential and B control signature are accepted when the application independently expects A; the original API cannot express that expectation. | Missing mandatory authentication-policy composition. Not an A signature forgery. |
| F4F-02 | Lifecycle / time validation | Verification accepts a request before its creation/activation timestamp; SQLite lookup and consume only enforce expiry. | Future requests can be accepted early, including under a backwards verifier-clock scenario. |
| F4F-03 | Parser / canonicalization | Replacing the opening byte 0x7b with invalid UTF-8 byte 0xfb still loads the encrypted key. | Node's ASCII decoding clears the high bit before canonical-string comparison. An invalid file aliases a valid one. |

These are release blockers for the reviewed external commit. There is no
evidence here of a BBS, Ed25519, AES-GCM, scrypt, pairing or hash-function break.
F4F-03 does not bypass the passphrase or authenticated encryption.

## Isolated remediation, not an upstream or official product patch

A separate review copy changes exactly four external source modules:

- src/phase4f.mjs
- src/python-bridge.mjs
- src/secure-key-store.mjs
- bridge/challenge_store.py

The upstream checkout/archives and all original tests remain byte-identical.
There is no merge, cherry-pick, upstream submission, official product code,
package-version change or new dependency. The public contributor attribution
above also applies to the derived review-only modules.

The repaired request is intentionally incompatible with the unsafe unreleased
request format. It requires expected_subject_machine_id, a fixed purpose and
not_before; the verifier separately requires expectedSubjectMachineId.
No default is inferred from a proof, credential, signer or incoming request.
Missing/legacy fields are rejected. Frozen-at-entry copies prevent mutation of
verification inputs across asynchronous lookup.

Both holder and verifier enforce the full request's canonical header through
the backend's existing presentationHeader API. The verifier checks independently
expected ID = request ID = disclosed credential subject = Phase-4B signer.
The existing subject-control message binds the complete canonical request hash,
exact decoded BBS proof hash, issuer key ID and subject ID. No new cryptographic
primitive, transcript challenge algorithm or group arithmetic was added.

Activation is not_before <= now < expires_at, with zero clock tolerance.
Both stores enforce it at lookup and consumption. SQLite decodes and validates
the stored request and consumes it inside the same BEGIN IMMEDIATE transaction.
Failed attempts do not consume an otherwise usable challenge.

Key loading now reads bytes, uses fatal UTF-8 decoding with BOM preservation,
then requires exact equality to UTF8(canonicalJson(envelope) + LF). BOM,
UTF-16, invalid/overlong sequences, byte aliases, duplicates/escaped duplicates,
extra whitespace/bytes, NUL, CRLF, missing LF and repeated LF fail closed.
No sanitizing or replacement decoding is used. Error text stays redacted.

## Follow-up results (2026-09-11)

| Test target | Linux | Native Windows |
| --- | --- | --- |
| Unchanged prototype b8b8e68 | 24/24 Node | 24/24 Node |
| Unchanged external candidate 85bd11c | 7/7 Python + 35/35 Node | 7/7 Python + 35/35 Node |
| Isolated remediation, independent Node suite | 76/76 | 76/76 |
| Isolated remediation, independent SQLite suite | 35/35 | 35/35 |

There are 111 new tests, each executed on both platforms, not 222 unique tests.
There were no skipped tests. The 16-contender SQLite test launches independent
Python processes and observes exactly one successful consumption; restart
replay is rejected.

IMPORTANT: the original tests were rerun unchanged against their original
archived implementations, not adapted to silently supply the new mandatory
subject argument. Their green results are baseline reproduction, not proof of
remediation. The separate 111-test suites exercise the incompatible strict
review implementation. Original source-test hashes were checked before/after
execution and against the source archives.

The first new Windows Python run hit an open SQLite inspection connection in
the newly authored test's cleanup. Explicitly closing those two test-only
connections corrected the harness; the final complete 35-test rerun passed.
No original contributor test was changed.

Full follow-up suites: Node 24.14.0, Linux Python 3.12.3 and Windows Python
3.12.14. The dependency graph remains Digital Bazaar 3.1.0, Noble curves 2.4.0
and Noble hashes 2.4.0. Node 20/22 and the full official candidate matrix were
not run in this limited follow-up.

A separate public interoperability fixture exercises the unchanged official
v0.5.1 Phase-4B SDK: frame equality, Node signature verification, deterministic
Python signature equality, altered-message rejection and wrong-expected-ID
rejection. This is five checks, not additional unittest cases. Results and
Python versions are recorded in the follow-up evidence file. These checks are
not the full 487-test baseline regression suite.

No real wallet, daemon, chain, Testnet/Mainnet endpoint, production identity or
secret was used. The string "testnet" in artifacts is a fixture network label.
Final new-test outputs passed known-passphrase-sentinel and PEM-header scans.
They are not evidence of guaranteed zeroization or immunity to process-memory
inspection.

## Pinned dependency provenance and audit gap

The package-lock SHA-256 is
23dd686c84d238e60d9c939310d084b642e743af3b8b9139a7174c4029fd400b.

Fresh registry metadata, installed dependency trees, lockfile integrity fields,
npm audit outputs and upstream public advisory responses were retained.
npm audit reported zero known advisories for the pinned graph. Absence of
advisories does not establish cryptographic security.

Exact source mapping:

- Digital Bazaar BBS 3.1.0: annotated tag object
  584a8dbed4988611b3a6fae1416190338b536d30; peeled source commit
  1b03d2528922ea6ee6f290a198136421f282fed8. The latter matches npm gitHead.
  This corrects the tag-object/commit distinction in historical research.
- Noble curves 2.4.0: source commit
  656c4364dffa44c64aa0c49914b8000b278b67a9.
- Noble hashes 2.4.0: source commit
  663c2aeeffc308ac0cded59bd32f7c212adacfc2.

The backend's existing ProofGen/ProofVerify path incorporates the exact
presentationHeader into its native challenge calculation. MYT must not
reimplement that calculation. See the pinned
[public API](https://github.com/digitalbazaar/bbs-signatures/blob/1b03d2528922ea6ee6f290a198136421f282fed8/lib/index.js)
and
[proof implementation](https://github.com/digitalbazaar/bbs-signatures/blob/1b03d2528922ea6ee6f290a198136421f282fed8/lib/bbs/proof.js).
The inspected implementation references BBS draft-06; do not claim that this
proves interoperability with another draft or a final standard.

The known historical Noble audit does not independently qualify this exact
Digital Bazaar/Noble composition, version graph and MYT application protocol.
The fixes do not close that gap:

- CRYPTO BACKEND INDEPENDENTLY QUALIFIED: NO
- EXTERNAL CRYPTO REVIEW REQUIRED: YES
- BBS architecture for trusted-evaluator selective disclosure: STILL VIABLE
- Numeric inequality proven in ZK: NO
- Custom cryptographic primitives required for these fixes: NO

## Official preparation and remaining gates

The mandatory contract is now
[phase4f-bbs-integration-contract.md](phase4f-bbs-integration-contract.md).
It records subject, lifecycle and storage invariants plus exact review-profile
bytes and acceptance tests. Preparing that contract is not creating a product.

No official product candidate was created in this follow-up. The research
branch remains based on 73beb99102f56671d6b2d85c9368bfa788249dc2. All six
pre-existing research documents remain byte-identical to the saved hashes.

Before an official candidate can be called ready for external review, it must
still independently implement the trusted real-Phase-4E issuance path, production
artifact parsers and bounds, mandatory issuer status/freshness policy, and a
defensible Python/Node packaging boundary. The external fixture issuer accepting
caller-supplied evaluation is not an approved production issuer. The inherited
Node-to-Python subprocess bridge is review scaffolding, not a runtime decision.

The full official regression/matrix, packaging, dependency/security gates,
performance/privacy review and external cryptographic qualification remain
separate gates. No previously completed v0.5.1 gate was relabelled as a 4F gate.
main and released v0.5.1 are unchanged. No commit, push, tag, release, PyPI
publication or deployment was performed.
