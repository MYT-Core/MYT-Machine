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

# Phase 4F Credential Architecture Review

Review date: 2026-09-10. Baseline: MYT Machine **0.5.0**, commit
`ff1624ff6263bfd4142550391a381f96006a0413`.
Branch: `feature/phase4f-zk-selective-disclosure`.

**Decision: credential architecture B is promising, but external cryptographic
review is required. No implementation/version is production-qualified.**

This is source inspection, primary-source research and external API testing by
a coding agent, not an independent professional cryptographic audit. The earlier
range-proof design remains blocked. Functional platform success is not a waiver
of the evidence gate. No production implementation is authorized by this report.

## Executive Findings

1. MYT's stated requirement does not necessarily require proving a hidden integer.
   An evaluator-issued assertion about a bounded policy predicate can reveal only
   the required property. Architecture B avoids MYT-specific range composition.
2. BBS selective disclosure proves possession of an issuer signature covering the
   disclosed assertion and undisclosed attributes. It does **not** independently
   prove that the evaluator calculated the count correctly, or that `v >= t` for
   an integer witness. Calling this a range proof would be incorrect.
3. Two BBS implementations passed external Linux/native-Windows probes:
   `@digitalbazaar/bbs-signatures=3.1.0` and `zkryptium=0.7.0` (BBS-only).
   Neither has sufficient identified current implementation/composition assurance
   to approve MYT production use. They are review subjects, not supported deps.
4. AnonCreds 0.2.3 supports the desired numeric predicate family, but the tested
   bare public verification path accepts a changed requested predicate, including an
   impossible higher threshold. This is reproduced on all six OS/Python pairs.
   The direct API is therefore insufficient on its own. Existing ACA-Py source
   supplies additional predicate-bound checks; this is not evidence that all
   AnonCreds applications are vulnerable or that CL mathematics is broken.
5. Eight additional AnonCreds raw-text mutations also pass native verification.
   Raw/encoded validation is an explicitly documented application responsibility,
   also implemented by ACA-Py. These are not eight new crypto flaws. Neither
   observation qualifies an unreviewed MYT wrapper or authorizes a patch here.
6. All credential designs still require explicit evaluator trust, exact 4E
   semantics, subject possession, freshness/replay checks and privacy consent.
   No design establishes global reputation, unique humans, service quality or
   complete history.

The previous five research documents are preserved. This report changes the
question, not the outcome of their numeric range-proof qualification.

## Scope And Evidence Method

Sources below were checked on the review date. Exact release artifacts were
distinguished from repository HEAD and search-engine snippets. Current package
registries, source history, security advisories, audit PDFs and specifications
were used. A lack of a found audit/advisory is recorded as a bounded search result,
not proof that no private audit or undisclosed vulnerability exists.

Evidence classes are kept separate:

| Evidence | What it can establish | What it cannot establish |
| --- | --- | --- |
| Academic protocol analysis | Security under its model and assumptions | Correct current parser, FFI, verifier or application |
| Independent implementation audit | Scoped findings at identified snapshots | Automatic coverage of later rewrites or a MYT composition |
| Maintainer self-review | Useful additional scrutiny | Independent assurance |
| Advisory/fix history | Specific defects and their fixes | Absence of other defects |
| Tests/vectors/fuzzing | Exercised behavior and interoperability | General soundness or zero knowledge |
| Deployment | Operational experience | Equivalence of a deployed path to this package/profile |
| Registry hash/SBOM/scan | Artifact identity and known graph issues | Honest publisher, reproducibility or unknown-vulnerability immunity |

No new cryptographic primitive, curve arithmetic, circuit, Fiat-Shamir transform,
production credential API, issuer key format or MYT protocol was implemented.
External probes call existing upstream APIs with synthetic, ephemeral data only.

## Actual Phase 4E Semantics

The baseline sources were inspected, not inferred from roadmap language:
[policy](../src/myt_machine/reputation_policy.py),
[store](../src/myt_machine/reputation_store.py),
[settlement bridge](../src/myt_machine/reputation_settlement.py),
and [signed artifacts](../src/myt_machine/reputation.py).

`reputation_summary(store, subject, network, policy, as_of)` reads a consistent
local snapshot. Stored artifacts are reparsed and signatures revalidated on
reads. Storage uniqueness, network filtering and capacity checks are retained.
Policy trust defaults to an empty issuer tuple. Self-attestations do not count.
Trust is not inferred from signature validity.

Attestations are processed by decreasing issuer-claimed timestamp, then content
ID. Matching issuer-authorized revocations, issuer allowlist, age relative to
`as_of`, optional settlement linkage and per-issuer caps affect acceptance.
Known revocations are applied from the snapshot; `as_of` is **not** a historical
database time-travel parameter that hides later-known revocations. Issuer-claimed
timestamps are not trusted evidence of when an event happened.

| Proposed predicate input | Existing exact summary field | Critical distinction |
| --- | --- | --- |
| Accepted attestations | `local_policy_output.accepted_attestations` | Policy-filtered signed opinions, not objective service quality |
| Accepted positive attestations | `local_policy_output.positive` | Outcome among accepted opinions; not an invented composite score |
| Verified recipient settlement events | `objective_local_observations.verified_recipient_settlement_events` | Count of local recipient observations; NOT filtered by attestation age/allowlist policy |

The third metric must not silently be redefined as a policy-filtered global
payment count. The existing bridge requires a locally PAID invoice, matching
recipient binding and a fresh native payment-proof check. Unique network/TX and
network/request constraints prevent repeated attribution in that local store.
These observations trust the local wallet/daemon/database; they are not portable
signed blockchain facts and do not identify a payer Machine ID.

Current store capacity is at most 100,000 combined artifacts/events; the policy
allows at most 1,000 trusted issuers and 100 contributions per issuer. These
current counts fit a nonnegative signed 32-bit domain. This does not retroactively
change architecture A's proposed 32-bit unsigned profile or future 4E semantics.

### Proposed Normal Issuance Boundary

The normal issuer API would accept a private validated store, a strict existing
`ReputationPolicy`, subject, network, `as_of`, an allowlisted metric selector and
a fixed credential profile. It would call the real summary function and derive
the requested metric/claims internally. There must be **no** normal
`issue(value=37, predicate=true)` shortcut. Synthetic upstream probes are not
that issuance API and do not prove such an API has been implemented.

The signed policy reference must cover the full normalized policy, metric
definition/version, bounded predicate catalog and profile version. The verifier
must resolve it from an independently accepted definition; a digest copied from
the presentation is not an accepted policy. The actual evidence snapshot and
exact output may be retained privately for issuer accountability, not disclosed
or published as a correlation-prone history hash by default.

An evaluator can still lie or use incomplete evidence. Local DB write compromise
is outside 4E's existing trust boundary. No ZK primitive can repair either by
itself. Reject untrusted evaluators by default, and do not automatically trust
self-evaluation. Policy trust in original attestors and trust in a new credential
evaluator are two separate decisions.

## Architecture Comparison

| Property | A: signed commitment + range ZK | B: signed predicate claims + BBS presentation | C: AnonCreds numeric predicate | D: minimized ordinary signed claim |
| --- | --- | --- | --- | --- |
| Statement | Know opening of evaluator-authorized bounded integer commitment satisfying threshold | Know issuer signature authorizing the disclosed claim | Know issuer-signed encoded integer and holder secret, satisfying predicate | Issuer signed the disclosed claim |
| Hidden witness | Integer/opening | Signature and undisclosed messages | Integer, signature, link secret and hidden attributes | None required |
| Numeric inequality in ZK | YES, proposed composition | **NO** | YES at protocol level | NO |
| Undisclosed attributes | Not inherently a general credential scheme | ZK-hidden, not just omitted | ZK-hidden, subject to correct encoding and verification | Omitted by separate signed claim; not ZK |
| Who evaluates 4E | Evaluator | Evaluator | Evaluator | Evaluator |
| Evaluator truth/completeness trusted | YES | YES | YES | YES |
| Fresh subject authentication | Separate 4B needed | Separate 4B needed | Link secret plus separate 4B needed | Separate 4B needed |
| Additional issuer key type | Existing Ed25519 plus proof backend parameters | BBS/BLS12-381 | CL/RSA credential-definition keys | Existing Ed25519 |
| Setup | Backend-dependent; reviewed BP paths transparent | No trusted setup ceremony | Per-issuer RSA/CL parameter generation, no global ceremony | None |
| User-visible correlators | Subject, evaluator, policy, stable commitment | Public subject/evaluator/policy; no public unique credential ID needed | Public subject/evaluator/policy/schema/definition | Subject/evaluator/policy and stable signature/claim |
| MYT-specific crypto composition | Largest of A/B | Smallest ZK-oriented option; still application binding review | Predicate machinery native, but substantial API/revocation integration | Lowest, but not a ZK milestone |
| Present decision | Remains blocked | **Preferred architecture for external review** | Exact tested API fails semantic gate | Optional separate non-ZK decision, not 4F completion |

Architecture B's precise public description would be:
**zero-knowledge selective disclosure of evaluator-signed bounded reputation
predicate claims**. Not a hidden-balance proof, not an arithmetic range proof,
not proof of the full evaluation and not an anonymous global trust score.

D is useful as a simplicity control. If each predicate is independently signed,
only that full signed statement need be shown. Deleting fields from one ordinary
Ed25519-signed object does not create selective-disclosure verification. Calling
D completion of ZK Phase 4F would change the requirement and needs separate approval.

## Architecture B: Predicate Catalog And Encoding

The following is a **design proposal for specialist review**, not a finalized
wire schema or an implemented credential format.

Use a fixed, bounded, policy-versioned catalog, for example thresholds
`[1, 10, 25, 50, 100]` for exactly one named metric. Every issued credential for
that profile has the same ordered set of messages, including true/false values
for every threshold. Do not issue a variable-length list of only satisfied
thresholds: its count would reveal the bucket. Do not issue one threshold for
every integer, request arbitrary ad-hoc thresholds or change a catalog silently.

For `v=37`, disclose the signed claim for `>=25` and keep `>=50=false` and other
claims hidden. Revealing the highest attained bucket would reveal an upper bound
too, unnecessarily. A request for `>=26` must not accept a `>=25` claim. The first
profile should require exact catalog membership; an optional future implication
rule such as using `>=50` to satisfy `>=26` needs explicit review and consent,
and is not part of the current proposal.

The schema fixes message indexes and types. Each message should encode its
field name, type and value unambiguously using the existing canonical-JSON
discipline, not concatenate ambiguous strings, locale numbers or raw arbitrary
JSON. No custom hash-to-scalar/curve is permitted; encoded message bytes go into
the backend's standard message API. Public metadata fields are obligatorily
disclosed and validated. A fixed profile/header binds the version and suite.

Proposed limits: one credential/one evaluator/one metric per presentation, a
catalog of at most 16 thresholds, at most 32 messages, exact expected indexes,
bounded fields and total presentation bytes within the existing Phase-4B signing
limit. These are application limits to finalize before implementation, not BBS
library guarantees. Proof-size and generator-work checks must happen before
expensive parsing/verification. No arbitrary batch verification is needed.

The evaluator must issue all claims from one summary snapshot and one policy.
Signature validity does not prove the booleans are mutually consistent. Verifiers
must not combine claims across different subjects, evaluators, policies, metrics,
schemas, snapshots or epochs. Every credential remains indivisible for this
consistency purpose even though its attributes are selectively disclosed.

Consent must display the exact requested predicate and exposed metadata. Repeated
requests, multiple audiences and issuer collusion can refine a bucket; a subject
ID makes this easy to correlate. Fixed catalogs reduce resolution, not remove
inference. Policy/cap boundary predicates can disclose an exact value logically.
Refusing a proof also must not be represented as proof that the predicate is false.

## Identity, Evaluator Keys And Holder Possession

Phase 4B Machine IDs and Ed25519 signatures stay unchanged. BBS keys must not be
derived by ad-hoc conversion from Ed25519 secret bytes. Use backend-native random
key generation. AnonCreds likewise needs its own issuer key generation and
holder link secret; a CL key is not a Machine Identity key.

Proposed issuer-key authorization: a strict object signed through existing 4B
functions binds evaluator Machine ID, role/purpose, exact algorithm/suite, public
key or complete credential-definition digest, network, schema/profile, key ID,
validity interval and authorization version. A verifier pins the evaluator via
its own trust policy and validates the entire authorization, not just its key ID.
Unknown fields, duplicate fields, noncanonical encodings and algorithm downgrade
must fail. No DID/network lookup is implicitly trusted.

Multiple keys may coexist only with distinct identifiers and explicit approved
roles/validity. Rotation means publishing a newly authorized key, not silently
replacing bytes behind the same identifier. Revoke compromised issuer keys in
the verifier's trust data; default policy should reject their credentials even
if an embedded issuer-claimed timestamp predates compromise. Trusted issuance
time is absent. Compromise of the Ed25519 authorizer requires out-of-band trust
recovery; this task does not implement 4B identity rotation or a new key hierarchy.

Plain BBS credentials are transferable: anyone copying signature and messages
can create a valid selective-disclosure proof. This was positively demonstrated
without the issuer secret key. A public subject label alone does not stop theft.
The proposed MYT holder must sign the **complete canonical request and complete
presentation envelope** using the existing 4B signature API, with a dedicated
new application context and independently expected subject ID. The verifier
requires that ID to equal the authenticated credential subject.

This establishes current access to the subject key in response to a challenge,
not exclusive possession, hardware binding or absence of live relay. Protect
the transport and expected audience. An attacker stealing both credential and
subject key can authenticate. The issuer's ability to create credentials does
not give it the subject's 4B key.

AnonCreds binds credentials to a holder-generated blinded link secret. Copying
only a credential without that secret is insufficient in the tested ordinary
path; copying both permits presentation. The secret is not an Ed25519 identity
and must not be replaced by public subject bytes or by a custom equality proof.
The same outer 4B subject authorization would still be needed.

## Request, Challenge And Replay Binding

Every accepted request must independently fix:

| Value | Required binding |
| --- | --- |
| Protocol/profile/suite/schema | Pinned verifier profile, signed issuer metadata and presentation domain |
| Challenge | Fresh 32-byte 4B-style decoded nonce, canonical transport, pending request record |
| Audience and purpose | Explicit expected service identifier/context, never inferred from proof-supplied URL |
| Policy and metric | Authenticated credential claim AND exact expected definition/digest |
| Subject | Authenticated credential attribute AND verified 4B signer AND expected ID |
| Evaluator/key | Trusted evaluator authorization, exact issuer public key and credential signature |
| Network | Credential, issuer-key authorization, request, verifier configuration and subject signature |
| Threshold/operator | Exact requested catalog member and signed true claim for B; exact proven/requested predicate for C |
| Snapshot/freshness | Authenticated `as_of`, issuer-claimed issue/expiry and local maximum-age/lifetime policy |

BBS exposes `presentationHeader`; supply canonical request bytes there and in
the outer subject-signed envelope. Use the library's domain separation as-is.
The external JS probe changed nonce/audience/policy/metric/subject/network/schema/
threshold one at a time and all changes failed verification. That demonstrates
the header API, not an implemented complete MYT request protocol.

AnonCreds uses an upstream-generated 80-bit nonce (not the 32-byte 4B nonce).
Do not invent a custom Fiat-Shamir nonce derivation, truncate a MYT challenge or
pretend the native API authenticates arbitrary request JSON. A proposed adapter
would retain a native nonce plus the separate full MYT request/4B signature and
explicitly check actual proven predicates against requests. The observed
predicate mismatch prevents qualifying that adapter now.

Durable pending challenges must store all expected fields, expiration and used
state. After all signature, trust, policy and freshness checks succeed, consume
the matching pending record atomically with accepting the authentication result.
Concurrent submissions, replay after restart, expired entries and changed
audiences must fail. A proof alone does not remember use. Rate limits, pending
record caps, request timeouts and worker resource limits are required. No product
replay implementation or concurrent E2E was created in this task.

## Privacy Matrix

For B, "hidden" below describes the intended credential presentation, not a
released MYT feature or a guarantee against inference/collusion.

| Field/information | B visibility | C comparison / caveat |
| --- | --- | --- |
| Exact numeric metric | Not included in credential; evaluator knows it | Credential contains it; holder/evaluator know it; predicate proof hides it from verifier |
| Requested threshold and truth value | Public | Threshold/operator public; predicate truth proven |
| Other thresholds / highest bucket | Hidden fixed-index messages | Other comparisons not required |
| Subject Machine ID | Public, deliberately linkable | Public in proposed MYT profile, despite generic anonymous capability |
| Evaluator identity / issuer key | Public | Public issuer/credential-definition reference |
| Policy digest / metric / network / schema | Public | Must be authenticated and checked, not read from unverified raw strings |
| `as_of`, issuance, expiry | Public; timestamp/cohort correlation possible | Could use native predicates for dates, but public exact values proposed for simplicity |
| Credential ID | No public unique ID in initial short-lived profile | Registry/definition IDs public; revocation mechanisms add metadata |
| Attribute count / layout | Public fixed profile; cannot be hidden merely by BBS | Schema/structure and proof sizes reveal layout |
| Full attestation and settlement history | Not included | Not included |
| TXIDs, addresses, evidence digests | Not included | Not included |
| Original issuer signature | Hidden by randomized presentation | Hidden by CL presentation |
| Subject signature | New per challenge, but same public subject key links it | Same |
| Traffic/IP/timing/issuer issuance logs | Not protected | Not protected |

ZK hiding is not the same as just deleting private attributes from an artifact.
It applies under the chosen scheme's assumptions. It does not conceal information
already public, remove inference from correlated predicates or make this
public-subject MYT profile anonymous. Do not add stable hidden-data hashes to
public metadata as a debugging convenience. Credential files and issuer records
still require local confidentiality and encrypted secret storage.

## Freshness And Revocation

Short-lived credentials are the smallest initial design: bounded issuer-claimed
issue/expiry, policy `as_of`, local clock checks and a verifier-selected maximum
age. An illustrative 24-hour maximum is not an approved default. Issuance time
and expiry do not prove when evaluation actually happened. Offline verification
is possible with trusted cached issuer keys/policies and challenge state.

Short lifetimes limit stale acceptance but do not immediately apply new 4E
revocations. Explicit credential/key revocation lists improve response but need
authenticated distribution and freshness rules, and public credential IDs can
introduce correlation. Per-key revocation affects all credentials under that key.

AnonCreds' native accumulator revocation additionally needs registry definitions,
status snapshots, witnesses/tails and update handling. That is substantial new
state and proof surface. No revocation E2E was run for this candidate. A proof
against a cached registry cannot establish absence of later revocation. Online
fetching needs separate SSRF/transport/trust protections, not automatic arbitrary
URLs from untrusted credentials. No design offers instantaneous global revocation
while offline.

## Standards And Protocol Evidence

- The [IRTF tracker](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/)
  identifies draft **10**, latest revision 2026-01-08, now expired/archived.
  It is not an IETF RFC or endorsed Internet Standard. Expiry is not a demonstrated
  cryptographic defect, but version/interoperability must be pinned explicitly.
- [W3C BBS Data Integrity](https://www.w3.org/TR/2026/CRD-vc-di-bbs-20260902/)
  is a **Candidate Recommendation Draft dated 2026-09-02**, not a Recommendation.
  Its JSON-LD/RDF canonicalization suite is not identical to a raw ordered-message
  MYT BBS profile. MYT must not claim W3C conformance merely by using BBS math.
- The [BBS draft](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-10.html)
  defines BLS12-381 suites with XMD/SHA-256 or XOF/SHAKE-256 hash-to-curve and
  randomized proofs of signature knowledge. The examined profile uses SHA-256.
  Key validation, subgroup/identity checks, scalar encoding, generator derivation,
  transcript ordering and secure randomizers are backend responsibilities, not
  invitations to implement replacements in MYT.
- [Tight Security for BBS Signatures](https://arxiv.org/abs/2608.06724)
  supplies new 2026 protocol-level evidence with explicit conditions on repeated
  message signing. It is not a current JS/Rust implementation audit. Do not turn
  its conditional reduction into a blanket security-level claim for MYT.
- [AnonCreds v1 specification](https://anoncreds.github.io/anoncreds-spec/)
  describes ledger-agnostic credentials, hidden integer predicates and link
  secrets. v2 research is not a drop-in production replacement for v1 CL.
- [Fraser/Schneider, EuroS&P 2025](https://eprint.iacr.org/2025/694)
  analyzes correctness, unforgeability and anonymity of its modeled AnonCreds
  protocol, including predicate-proof constructions. This is meaningful positive
  evidence, not a proof that the 0.2.3 FFI verifier enforces every request field.

BBS has no circuit ceremony or toxic waste. Its fixed generators come from the
specified suite. AnonCreds generates RSA/CL parameters per issuer; correct modulus,
key generation and key-correctness verification remain trust/security assumptions.
Neither design is post-quantum. No blanket 128-bit or constant-time certification
is made for the tested implementations.

## Concrete Implementations

### B1: Digital Bazaar 3.1.0

Exact npm package: `@digitalbazaar/bbs-signatures=3.1.0`, published 2026-06-02.
The examined graph resolved `@noble/curves=2.4.0` and `@noble/hashes=2.4.0`.
BSD-3-Clause top-level, MIT dependencies. Source:
[Digital Bazaar](https://github.com/digitalbazaar/bbs-signatures).
Repository HEAD `1d4c17315a5d2e11c0f3f97e07dbdaf398fa3ebc` is a
`3.1.1-0` development manifest; it was **not** installed as 3.1.0.
The 3.1.0 tag resolves to `584a8dbed4988611b3a6fae1416190338b536d30`;
there are no later `lib/` changes between that tag and the examined HEAD.

The [changelog](https://github.com/digitalbazaar/bbs-signatures/blob/1d4c17315a5d2e11c0f3f97e07dbdaf398fa3ebc/CHANGELOG.md)
describes draft-06 challenge changes in 3.0.0 and a Noble update in 3.1.0.
Source/README still reference draft 06. Current draft-10 interoperability was
not established by the same-library probes and must not be asserted.

Pure JS with Node/WebCrypto randomness makes native-Windows use practical, but
MYT would gain a Node runtime/IPC packaging dependency unless a separately
qualified bridge is chosen. Noble 2.4 requires Node >=20.19 although the BBS
package still advertises >=18; Node 24.14.0 was used on both OSes. No install
scripts were executed. No application-time downloads are acceptable.

The [Cure53 2024 report](https://cure53.de/audit-report_noble-crypto-libs.pdf)
includes BLS12-381, hash-to-curve and lower-level Noble modules. Its listed input
is 1.5.0; upstream identifies the remediated audited version as 1.6.0. It does
**not** review Digital Bazaar's BBS transcript, proof parser or MYT semantics.
Noble 2.2.0's April 2026 review is explicitly a **self-audit**. Relevant
1.6.0-to-2.2.0 files include 2,629 additions/1,490 deletions; 2.2.0-to-2.4.0
adds 617/removes 114 across BLS, tower, hash-to-curve and curve modules. Counts
include refactoring and are not vulnerability counts, but this is not an
unexamined assumption of patch-level equivalence.

Public BBS API probes all passed. Current independent coverage is
**MATERIAL AUDIT GAP** for the whole path; BBS-specific audit scope is **UNKNOWN**.
Noble's known BigInt timing limitations also prevent claiming constant-time
issuer/prover operations. The open fixture-update issue #18 underlines that
interoperability coverage needs explicit evidence. No public repository advisory
was returned; the resolved npm graph had zero reported known vulnerabilities.

### B2: ZKryptium 0.7.0

Exact crates.io artifact: `zkryptium=0.7.0`, default features disabled and only
`bbsplus` enabled. Apache-2.0, LINKS Foundation. Registry checksum:
`00d24b3f82a8410c6b321e1e62e9858d9e0f3d5b7ba7e07b8356965c67dba816`.
[Repository](https://github.com/Cybersecurity-LINKS/zkryptium), examined HEAD
`2959148b748f569f9c119bbbc3129524bf07a326`.

Registry and GitHub release labels differ: the non-hyphenated 0.7.0 crate exists,
while the August 31 GitHub release is `v0.7.0-alpha` marked prerelease. Do not
describe this as a mature stable audited release. Search snippets still showing
0.6.1/0.6.2 were not used as the installed version.

The source targets BBS draft 10. `bbsplus` is the feature/module name, not evidence
that it implements only the older BBS+ protocol. Blind signatures, pseudonyms and
CL03 were excluded. This avoids optional Rug/GMP dependencies and their additional
platform/license implications. The graph still includes `bls12_381_plus`, field,
group, hash and randomness crates: Rust memory safety is not cryptographic proof.
The resolved primitive is `bls12_381_plus=0.8.18`, not the manifest's 0.8.13
minimum. Other exact graph entries include `ff=0.13.1`, `group=0.13.0`,
`rand=0.8.8`, `sha2=0.10.9`, `sha3=0.10.9` and `zeroize=1.9.0`.

The 52-entry locked probe graph has zero reported RustSec findings/warnings.
Linux and Windows GNU-target native executions passed; no upstream Python wheel
was claimed. A reviewed ABI3 wrapper or packaged helper remains future work.
No implementation audit identifying this exact BBS path was located in the
repository, release/security material or primary-source searches. Classification:
**UNKNOWN** independent implementation coverage, with application composition
also unreviewed. Functional tests do not fill that gap.

### B3: MATTR And Dock Screen

[MATTR pairing_crypto](https://github.com/mattrglobal/pairing_crypto) at
`0437217da793eddc9bf6927faae3a1f33b994a30` declares 0.4.4 and explicitly says
it has not undergone an independent implementation audit. It references BBS
draft 03 and a pinned MATTR `blstrs` fork (`a0cb960`, declared 0.6.1).
Apache-2.0; recent wrapper dependency activity does not prove the cryptographic
path was newly reviewed. The deprecated older MATTR package is not a safe way
to inherit an unrelated audit. This route is not selected and was not built.

[Dock crypto](https://github.com/docknetwork/crypto) provides BBS/BBS+ plus many
additional proof systems via Rust/WASM. Its broader composition framework is
not necessary for the minimum B design. No exact current BBS-only audit scope
and deployable Python graph were established. The unresolved range-boundary
issue #27 concerns its range proof, not automatically BBS selective disclosure.
It remains screened, not declared generally vulnerable or production-qualified.
No Dock local proving or package matrix result is claimed.
The inspected source is `224f195bb8babc2d0de5256135120e0aca9fbd19`
(2025-10-02), `bbs_plus` manifest 0.25.0, Apache-2.0. This is a source screen,
not a claim to have installed that crate or the separate WASM release.

### C: AnonCreds 0.2.3

Published Python package: [anoncreds 0.2.3](https://pypi.org/project/anoncreds/0.2.3/),
released 2025-11-13. Rust tag resolves to
`f445039e312f38e848f4c6b990c37d56511b380a`; current inspected HEAD is
`08317a7428afe81f7b710669dc64878f98a6447b`.
Source declares `anoncreds-clsignatures=0.3.2`, Rust >=1.85 and Apache-2.0.
Python `py3-none` wheels contain native code, not pure Python. Both the Python
metadata and loaded library report 0.2.3 on all six interpreters.

The published [link-secret advisory](https://github.com/anoncreds/anoncreds-rs/security/advisories/GHSA-89r4-4c4j-7wx9)
identifies 0.2.2 as affected and 0.2.3 as patched. Fix `d202eaf` adds
`add_common_attribute("master_secret")` to the verifier; it is present in the
release and current path. Source regression tests include mixed-secret legacy
and W3C presentations. They were inspected, not rerun as a full upstream suite.
This specific correction has direct source/advisory support and is not reported
as still missing. It is separate from the finding below.

#### Observed Bare-API Request-Predicate Verification Failure

Synthetic credential numeric attribute: 37. Presentation generated for `>=25`.
With the **same native nonce, key, schema and presentation**, `Presentation.verify`
also returns true when the verifier's requested threshold is changed to 26 or
100,000, and when the requested operator changes. Each run first verifies the
ordinary valid case; generating a genuine proof for an unsatisfied predicate
is rejected. There is no forged issuer signature or proof of `37>=100000` here:
the actual weaker predicate inside the proof remains valid, but the requested
predicate is not enforced by this path.

Source explanation in
[release verifier.rs](https://github.com/anoncreds/anoncreds-rs/blob/f445039e312f38e848f4c6b990c37d56511b380a/src/services/verifier.rs):
the request comparison checks referent sets; `CLProofVerifier::add_sub_proof`
builds its cryptographic sub-request from `sub_proof.predicates()`, rather than
enforcing the requested predicate's name/operator/value equality. The inspected
HEAD has no subsequent changes to this verifier file. This is a **confirmed
local integration security failure**, not a claimed break of CL mathematics or
a newly assigned CVE. No production application or third-party server was attacked.

Consequences: a direct true/false API adapter cannot satisfy MYT's mandatory
threshold binding. Do not reinterpret a passing native verification as the
requested predicate. An explicit complete consistency check would be a separate
reviewed integration requirement, not a patch performed or a qualification granted
here. The failure rejects the assumption that the bare API alone implements all
MYT verification obligations, not every framework built on that API.

Relevant established integration evidence:
[ACA-Py verifier at c148063](https://github.com/openwallet-foundation/acapy/blob/c148063f307ba33a41402ed1b73e241c07dd55c4/acapy_agent/anoncreds/verifier.py#L281)
explicitly prechecks predicate bounds and raw/encoded values. Its `pre_verify`
matches the canonical predicate attribute and requested threshold against the
proof, then checks disclosed encoded values against both the proof and the
encoding of `raw`. Thus additional framework-side checking is existing practice,
not a newly invented MYT cryptographic fix. This limited source inspection does
not establish complete operator handling, qualification of the full ACA-Py stack,
or a green MYT matrix for that stack; ACA-Py was not installed or tested here.

Before reconsideration, specify and independently review the complete verifier
contract, including exact name/operator/value and raw/encoded consistency, using
established integration guidance and upstream clarification where needed. A new
upstream crypto patch is not assumed to be the only valid resolution. No CVE,
public issue or private report was filed by this task. Preserve the reproducible
local API evidence without presenting it as a newly established ecosystem-wide
vulnerability. Source file SHA-256:
`81699541a13226e438843905986003a822fa0a95c1726c4a52f0e8a28dd762a5`.

#### Raw Encodings, Numeric Limits And Scope

Changing each of eight disclosed `raw` strings without changing `encoded` also
passes native verification. The [specification's revealed-attribute section](https://anoncreds.github.io/anoncreds-spec/#revealed-attributes)
explicitly assigns raw-to-encoded checking to the application. This confirms an
integration obligation, not eight newly discovered upstream defects. A future
adapter would use the existing encoder, strict canonical values and independent
expected-context checks; no field read from raw JSON is automatically trusted.

Native predicates use signed 32-bit values; zero, 100,000 and 2^31-1 encode as
integers, while 2^31 is hashed rather than treated as an integer. MYT's present
counts fit, but arbitrary 32-bit-unsigned Phase-4F inputs do not. Source uses
four-square difference proofs; a reviewed profile must reject overflow, booleans,
negatives and alternate lexical forms, not assume every numeric-looking string
is comparable. CL03 in ZKryptium is not this AnonCreds implementation.

The protocol literature is useful positive evidence; no complete current
implementation audit of the precise Python/native verifier path was located.
Current coverage is **MATERIAL AUDIT GAP**, also backed by the observed semantic
failure. The project has a published security policy and maintenance, but open
issues include W3C verification pitfalls (#322), link-secret zeroing (#202),
coverage (#343) and build problems (#372). Those issues have different scopes;
they are not all demonstrated vulnerabilities in this probe.

## Supply Chain And Artifact Identity

Installed only in external review directories, from official registries with
exact top-level versions. No production dependency, version or build pipeline
changed. Direct artifact identities:

```text
5fe3172d37a88640a0af65e16a1f6da74f9dbac9d962e77b288dcacbb1c10cfc  anoncreds-0.2.3-py3-none-manylinux2014_x86_64.whl
cd9c747eeff5dc3d975f99671f6e79b1d287c5fb625abf4dafadeaa69bdfc739  anoncreds-0.2.3-py3-none-win_amd64.whl
00d24b3f82a8410c6b321e1e62e9858d9e0f3d5b7ba7e07b8356965c67dba816  zkryptium-0.7.0.crate
```

Digital Bazaar npm integrity:
`sha512-wx86l/PFOaRcoLBPmzwpF9Oo4uYJrm4uq/B1rHX5OHD15NakmUINfRr8NAGDG356GeTBDGZkMsBFgNj1x0dc+g==`.

AnonCreds wheels have no accompanying sdist on that PyPI release and no Trusted
Publishing attestation shown there. The workflows build vendored OpenSSL; the
Windows DLL contains the version string **OpenSSL 3.5.4, 30 Sep 2025**. This
needs an exact binary SBOM/backport/reachability assessment; today's OpenSSL 3.5
advisory page contains later fixes. Do not claim every TLS/AEAD advisory is
reachable through CL bignum operations, or that `pip-audit` checks static native
libraries. Rebuilding current source is not proof of what is inside an older wheel.
See [OpenSSL's official advisories](https://openssl-library.org/news/vulnerabilities-3.5/).

`pip check` passed in all six AnonCreds environments. `pip-audit` of the exact
Python package found no known entry; it does not cover the opaque Rust/OpenSSL
wheel graph or contradict the observed verifier failure. `npm audit --omit=dev`
reported zero known issues in both three-package BBS graphs. `cargo audit`
reported zero known vulnerabilities and warnings in the 52-entry ZKryptium probe
graph, RustSec snapshot `b50980aad8b8f14f77e25a97b32dd94bf008b0af`.
No advisory ignores were used. None is a production dependency certification.

Additional evidence hashes:

```text
cfc8423485c19852aea30d7624c67f847bd555af0f80de6d62db351411b44d03  zk-probe/Cargo.lock
5ddd00229aa9440c66698c7e404b394618f347826a9644beb96036a4fd2efb70  Linux package-lock.json
2bac97956e80a33bead082c2001893384142c215fe0b612f84dbb19bdc888806  Linux libanoncreds.so
943b9d8c18ff95c4b6d52de412edfce564f4822845b151d9a4f9c8fd0a704a54  Windows anoncreds.dll
1182598baa0715f0bae3d5cd2bcc47c44b8d7589d620645d0cda809e2e47fab2  anoncreds-formal.pdf
be2f348140729f6d58071ee08fca76f1d13c430e316270455abee73ebd009b50  noble-cure53.pdf
ffbf24f09118cea9b286254854be7aed134bd774aefc7bfe65394dc0545e010a  anon-probe.py
bfd9453ab7dd00ce7dd7babe6c5df213e2897a3d0df2dd53a0afc2d4157c3f99  bbs-probe.mjs
bf965c915dbedefa083b1be1efe8cfaf13a74610787b1d819396d3d225162a18  zkryptium-probe.rs
```

Linux `ldd` lists no dynamic libcrypto; no OpenSSL version string was extracted
from that stripped library, so its exact embedded OpenSSL version remains
**unidentified**, not assumed equal to Windows. `pip-audit` version was 2.10.1.
The registry checksum is not a reproducible-build proof for either native wheel.

Future distribution needs immutable full lockfiles, SBOM/notices, source/binary
provenance, build-script review, supported compiler/OpenSSL, manylinux/MSVC or GNU
ABI decisions, reproducibility checks, signed/checksummed release assets and a
maintenance response plan. Node/Rust/Python subprocess execution must be local,
bounded and shell-free; secrets must not appear in command arguments or logs.
JS BigInt/GC and Python immutable objects cannot promise complete secret erasure.

## Platform Probes And Measurements

All data are synthetic. No wallet/RPC/daemon/chain, MYT transfer, cloud prover,
mainnet or testnet access was used. Research/package downloads used the network;
proving and verification are local. Windows runs are actual Windows executables
and Windows Python, not Wine, Linux containers or WSL pretending to be Windows.

| Environment | Python | Digital Bazaar 3.1.0 | ZKryptium 0.7.0 | AnonCreds 0.2.3 |
| --- | --- | --- | --- | --- |
| Linux x86_64/WSL | 3.10.21 | 22/22 | 25/25 | 12/23 requirements; semantic FAIL |
| Linux x86_64/WSL | 3.12.3 | 22/22 | 25/25 | 12/23 requirements; semantic FAIL |
| Linux x86_64/WSL | 3.13.15 | 22/22 | 25/25 | 12/23 requirements; semantic FAIL |
| Native Windows x86_64 | 3.10.21 | 22/22 | 25/25 | 12/23 requirements; semantic FAIL |
| Native Windows x86_64 | 3.12.14 | 22/22 | 25/25 | 12/23 requirements; semantic FAIL |
| Native Windows x86_64 | 3.13.9 | 22/22 | 25/25 | 12/23 requirements; semantic FAIL |

Counts are external API assertions, **not new MYT unit tests**. AnonCreds' eleven
unmet direct-adapter requirements comprise three predicate substitutions and
eight documented raw-encoding responsibilities. They are intentionally not
converted into an all-green report. Package import and ordinary issuance/proof
operations succeed; security qualification fails.

BBS JS uses a local Node 24.14.0 subprocess from each Python version. ZKryptium
uses an external native Rust executable invoked by Python; 25 checks repeat five
operations five times, not 25 distinct attack classes. Rust/Cargo 1.98.1 built
Linux and Windows GNU targets. These are feasibility probes, not MYT wheels,
FFI lifetime tests, production packaging, side-channel analysis, complete fuzzing
or a clean-wheel product E2E. MATTR/Dock were screened before platform tests.

Approximate measured sizes and representative **Python 3.12** runs:

| Candidate | Credential / presentation | Linux: issue, prove, verify | Windows: issue, prove, verify |
| --- | --- | --- | --- |
| Digital Bazaar BBS | Raw signature 80 B, public key 96 B, raw proof 336 B; synthetic credential JSON 418 B, presentation JSON 981 B | 192.759 / 256.679 / 290.801 ms medians | 217.555 / 338.302 / 435.564 ms medians |
| ZKryptium BBS | Raw proof 336 B, same 13-message/11-disclosure shape | 20.560 / 26.430 / 26.690 ms medians | 18.025 / 22.867 / 25.813 ms medians |
| AnonCreds | Synthetic credential 3,663 B; presentation ~19 KB; public definition ~9.6 KB | issuance 98.646 ms; prove 109.923 / verify 118.699 ms medians | issuance 111.601 ms; prove 194.083 / verify 187.129 ms medians |

Five samples per timing run after initial operations. AnonCreds initial
credential-definition generation was 3.760 s Linux / 2.799 s Windows in those
runs and varied strongly with prime generation. Its issuance measurement is
one sample including holder processing, not a median. BBS issuance here is
signature generation, not a full MYT issuer workflow. No 4E evaluation, 4B
envelope or transport overhead is included. Short synthetic IDs understate a
real MYT envelope; neither JSON size is a finalized product-format size.

For the tested modern BBS proof shape, raw size is `272 + 32 * U` bytes where
`U` is the number of undisclosed messages: two hidden claims yield 336 bytes.
Disclosure of every attribute is not required. AnonCreds decimal JSON size varies
with random bignums. Host contention, warmup and implementation differences make
these observations unsuitable as OS comparisons, guarantees or a DoS defense.

The first Windows install command treated an npm notice on stderr as a PowerShell
error; corrected shell handling completed the run. The first AnonCreds harness
stopped on the threshold failure; it was changed to record all requirements,
not to alter the backend or weaken the expected results.

## Qualification Matrix

### Evidence Classes Per Serious Candidate

| Evidence class | Digital Bazaar 3.1.0 | ZKryptium 0.7.0, BBS only | AnonCreds 0.2.3 |
| --- | --- | --- | --- |
| Protocol / academic design | BBS specifications and academic security analyses; draft06-to-draft10 mapping open | BBS specifications and academic security analyses; source targets draft10 | AnonCreds v1 specification and 2025 formal protocol analysis, including predicates |
| Independent implementation audit | Historical Cure53 review of lower-level Noble, not the BBS implementation | No exact implementation audit located | No complete current Python/native verifier audit located |
| Current-version audit coverage | MATERIAL AUDIT GAP for graph and composition; BBS-specific coverage UNKNOWN | UNKNOWN; current implementation and MYT composition unqualified | MATERIAL AUDIT GAP for complete application/native contract |
| Security advisories | None reported by the queried repository/npm graph | Zero findings/warnings for the locked RustSec graph | Specific link-secret advisory patched in 0.2.3; native dependency reachability/SBOM remains open |
| Fuzzing / testing | 22 external API checks in six environments; upstream fixtures do not establish draft10 interoperability; no new fuzz campaign | Five API checks repeated five times in six environments; no independent vector differential or fuzz campaign run | 12/23 direct-API requirements in six environments; mixed-secret regression source inspected, not rerun; no new fuzz campaign |
| Formal verification | No machine-checked proof of this current implementation established | No machine-checked proof of this current implementation established | Formal protocol result is positive evidence, not verification of this source, FFI or framework contract |
| Production deployment history | No exact 3.1.0/Noble2.4/MYT-profile deployment assurance established | Alpha-labelled GitHub release; no exact profile deployment assurance established | Existing framework integration practice evidenced by ACA-Py source; no deployed MYT profile or whole-framework qualification established |

MATTR and Dock were screened out before the full platform gate: for MATTR the
implementation explicitly disclaims an independent audit; for Dock exact current
BBS-path audit/dependency evidence remained UNKNOWN. Neither receives inherited
formal-verification, production-history or test credit from a project name.
Architecture A retains its separate earlier evidence matrices unchanged.

The tested BBS suites are Digital Bazaar `BLS12-381-SHA-256` and ZKryptium
`BbsBls12381Sha256`, using the respective upstream BLS12-381/SHA-256 XMD paths.
The JS wrong-suite rejection also probes SHAKE-256 substitution; that is not a
positive full qualification of the SHAKE-256 suite. Neither test rewrites the
backend's generator derivation, hash-to-curve or Fiat-Shamir implementation.

### Decision Gates

| Gate | A previous range family | B1 Digital Bazaar 3.1.0 | B2 ZKryptium 0.7.0 | C AnonCreds 0.2.3 |
| --- | --- | --- | --- | --- |
| Actual property fit | Yes, more machinery than required | Yes for signed predicates only | Yes for signed predicates only | Yes for numeric predicates at protocol level |
| Scope-compatible independent evidence | Previously insufficient | Lower-level historical audit only | No exact implementation audit located | Formal protocol analysis and specific fix, not whole current API |
| Current path coverage | MATERIAL AUDIT GAP | MATERIAL AUDIT GAP; BBS layer UNKNOWN | UNKNOWN | MATERIAL AUDIT GAP |
| Observed semantic blockers | No new evidence closes prior stop | No probe failure, draft-version and audit mapping open | No probe failure, alpha maturity and audit evidence open | Requested predicate substitution accepted |
| Exact dependency/platform evidence | Prior report preserved | Locked npm graph; six real runs | Locked Cargo graph; six real runs | Exact wheels; six real runs; native SBOM gap |
| Minimal MYT-specific crypto | No | Yes relative to A/C | Yes relative to A/C | Native arithmetic, larger integration obligations |
| Holder/challenge/audience binding | Proposed 4B composition | Proposed 4B plus standard header | Proposed 4B plus standard header | Link secret + proposed 4B; native request mismatch unresolved |
| Production-ready decision | NO | NO | NO | NO |

The labels **COVERED** and **LIKELY COVERED WITH LIMITED CHANGES** are not awarded
to a complete current credential path here. Direct evidence covers only narrower
facts, such as the AnonCreds link-secret fix and historical Noble audit scope.
This is not a rule that every post-audit patch invalidates all evidence: actual
security-path changes, missing application coverage and an observed semantic
failure drive this decision.

## Whitepaper Fit And Honest Public Claims

See the amended [whitepaper mapping](phase4f-whitepaper-mapping.md). Architecture
B would advance narrow privacy-preserving reputation-property disclosure, not
complete all selective-disclosure language in the whitepaper. Existing 4A-4E
payment proofs, binding, invoices and local reputation remain separately valid.
Hidden wallet-balance ranges, private transaction-set audits, anonymous subjects,
counterparty-blind payments, global reputation and complete-history proofs are
not delivered by signing a boolean claim.

No claim is marked implemented in 4F. All suggested key authorizations, schemas,
replay state and credential issuance adapters remain proposals for later review.

## External Review Needed Before An Implementation Prompt

1. Select one exact BBS implementation/graph and obtain path-specific independent
   assurance for parsing, subgroup/identity checks, generator derivation, message
   mapping, transcript/header handling, randomness, proof verification and
   issuer/prover side-channel assumptions. Do not automatically select B2 solely
   because it is faster or Rust, or B1 because Noble has a historical audit.
2. Reconcile the exact selected BBS draft/vector version with the frozen MYT
   profile. Test independent implementations against authoritative vectors; no
   same-library roundtrip can establish interoperability alone.
3. Review the bounded catalog semantics, required disclosures, evaluator key
   authorization, 4B subject envelope and atomic challenge acceptance together.
   Include malicious issuers, credential copying, cross-policy/network swapping,
   hidden-message counts, adaptive disclosure and freshness/revocation limits.
4. For C, review a complete framework-style verifier contract, including exact
   requested-predicate and raw/encoded checks. ACA-Py provides relevant existing
   integration evidence, not automatic qualification. Obtain upstream clarification
   as needed and resolve native dependency provenance. Preserve local failure
   evidence; neither a bare API result nor an improvised wrapper is sufficient.
5. Approve the exact supply chain, native/Node packaging and maintenance model.
   Only then request implementation, with all original 4A-4F regression,
   security, packaging, replay and release gates. This report is not that request.

## Repository And Reproduction

No `src/`, `tests/`, production metadata, CLI/REST, workflow or version changes.
No new commits, pushes, main integration, tags, releases, PyPI or deployment.
The prior 424/424 tests and 14/14 CI jobs remain **historical baseline evidence**;
they were not unnecessarily rerun or relabeled as credential tests. There are
zero new product tests and no 0.6.0 build.

Raw external evidence is under `myt-phase4f-backend-review/credentials` and the
native-Windows temporary `myt-phase4f-credentials` directory: pinned registry
metadata, pip install reports, npm/Cargo lockfiles and audit results, source
snapshots, audit PDFs, `anon-probe.py`, `bbs-probe.mjs`, `zkryptium-probe.rs`,
Python subprocess drivers and per-environment JSON results. No production private
keys, seeds, wallets or RPC passwords were read. The probe outputs contain no
generated private keys or link secrets. No product secret-redaction certification
is claimed for a product that does not yet exist.

Illustrative reproduction after reviewing those external scripts, with `REVIEW`
set to the external directory and `NODE` to the pinned local Node binary:

```bash
cd "$REVIEW/credentials"
anon-312/bin/python anon-probe.py
anon-312/bin/python bbs-python.py "$NODE" "$PWD/bbs-probe.mjs"
anon-312/bin/python native-python.py "$PWD/zk-probe/target/release/credential-review-only"
# AnonCreds deliberately records failed requirements; inspect passed AND cases.
```

No probe performs a network verification request. A future private upstream
report would need separate approval. Research documents remain uncommitted on
the existing feature branch; do not merge them into main under this design stop.

**Final architecture conclusion: PROMISING - EXTERNAL CRYPTO REVIEW REQUIRED.**
Recommended architecture: **B**, for further independent review only.
Recommended production implementation: **NONE**.
