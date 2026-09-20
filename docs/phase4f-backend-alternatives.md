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

# Phase 4F Backend Alternatives Review

Review date: 2026-09-10. Status: **DESIGN BLOCKED; NO BACKEND SELECTED**.

This supplements the completed [Tari design report](phase4f-cryptographic-design.md).
It is an agent-run source, provenance and security-evidence assessment, not an
independent professional cryptographic audit. No new upstream exploit is claimed.
No candidate below is a supported MYT runtime dependency. This review does not
assert that no suitable backend could exist; none examined here clears all of
the approved gates with the evidence obtained.

## Selection Rule

The required statement is knowledge of an opening of the evaluator-authorized
commitment to the **same** bounded integer `v`, with `0 <= v <= 2^32-1` and
`v >= threshold`. The 32-bit limit is the proposed Phase 4F profile, not an
existing product protocol. An honest prover's input check cannot replace the
verifier's upper-bound constraint. Field comparisons are not integer comparisons.

Production qualification needs all of the following, not a weighted score that
lets fast performance compensate for incomplete security evidence:

- Exact source/release and dependency graph, patched and traceable.
- Existing library primitives, including commitments and transcript machinery.
- Relevant independent audit or comparably strong evidence for the actual paths,
  with security-relevant changes since the reviewed snapshot accounted for.
- A justified same-opening threshold composition and explicit context binding.
- A credible maintenance/security response and supply-chain plan.
- Linux and native Windows proving/verification, with Python 3.10/3.12/3.13
  packaging realistically supportable without remote proving or runtime downloads.
- Documented setup, side-channel, privacy and resource assumptions.

Passing compilation, API probes or a known-advisory scan does not satisfy the
cryptographic evidence requirement. A framework audit also does not certify a
new application circuit automatically. Conversely, a new application circuit
is not inherently a new cryptographic primitive or inherently unsafe: it needs
its own constraint and composition review before acceptance.

## Decision Matrix

| Exact candidate | Threshold/context fit | Setup | Maintenance and security evidence | Decision for this MYT gate |
| --- | --- | --- | --- | --- |
| Tari Bulletproofs+ 0.5.3 | Native minima plus two assertions on one commitment; external transcript | No trusted setup | Active; 2023 Quarkslab audit; fixed batch advisory; significant later transcript/RNG/verifier changes | Not selected: current-path assurance incomplete |
| zkcrypto `bulletproofs` 5.0.0 | Ristretto range API; shifted-commitment composition and Merlin context possible | No trusted setup | Relevant 2019 audit of 1.0.2; dependency migrations; last observed repository activity September 2025 | Not selected: audit-to-release mapping and active security-maintenance assurance insufficient |
| BlockstreamResearch `secp256k1-zkp` at `037cc6d...` | Native minimum, returned bounds and `extra_commit`; two same-commitment proofs | No trusted setup | Active C project and deployed family; exact current rangeproof review not established; published Rust wrapper vendors older C | Not selected: version/path qualification incomplete, despite successful Linux/Windows probes |
| `gnark` v0.16.3 / `gnark-crypto` v0.21.0 | Dedicated constraint circuit with commitment gadget and public context | Groth16 circuit-specific or PLONK KZG universal SRS | Active, multiple scoped audits, recent security corrections to relevant gadgets | Not selected: current gadget/composition assurance and approved setup lifecycle missing |
| Zcash `halo2_proofs` 0.3.5 | Dedicated circuit, public instances and built-in transcript | IPA variant: no trusted setup | Active; protocol reviews and 2026 external review exist; exact findings/remediation-to-path mapping incomplete | Not selected: concrete commitment/range circuit and current audit mapping not qualified |
| RISC Zero `risc0-zkvm` 3.0.6 | Guest asserts opening/range; journal plus pinned image ID binds statement | Transparent STARK; optional Groth16 wrapper has ceremony | Active; audit collection and security advisories; unresolved published ZK-assurance warning | Not selected: privacy assurance and native-Windows prover qualification missing |

## Context And Subject Binding

All candidates require the verifier to supply independently expected values.
Accepting a context simply because it appears inside an artifact is not binding
to the verifier's request. A future canonical context must cover at least:

- Protocol/profile version and proof system identifier.
- Evaluator-authorized credential/commitment, evaluator ID and subject Machine ID.
- Network, exact metric, policy digest, integer bound and threshold.
- Fresh challenge bytes, audience, validity window and request identifier.

Tari and Dalek expose a transcript into which these canonical bytes can be
appended before proving/verifying. The C rangeproof API accepts `extra_commit`
for the same purpose. These are existing transcript APIs, not permission to
implement a replacement Fiat-Shamir transform. A SNARK circuit/zkVM guest must
bind the commitment, threshold and context as constrained public inputs or
authenticated journal output, with a verifier-pinned verifying key/image ID.
Unconstrained public-looking metadata does not qualify.

Canonical length/type boundaries, credential signature validation and expected
context checks must be enforced outside the primitive as well. Never cache
acceptance using only proof bytes or a commitment while omitting authenticated
context. No positive-result cache is needed for the first MYT profile.

None of these mechanisms consumes a challenge. Durable atomic replay state and
expiry enforcement remain application work. Since the evaluator knows the
opening, a fresh Phase 4B subject authorization is also needed: knowledge of an
opening alone must not impersonate the subject. Evaluator trust defaults to an
empty allowlist; cryptography cannot establish whether the evaluator's metric
was truthful or complete. The detailed 4E limitations remain in the design report.

## Dalek / zkcrypto Bulletproofs

The actual published `bulletproofs=5.0.0` identifies
[`zkcrypto/bulletproofs`](https://github.com/zkcrypto/bulletproofs), not the stale
`dalek-cryptography/bulletproofs` repository, as its source. Its VCS reference is
`86eadbeeb4a96d8da41427137b45ead810d03b41`; the registry artifact was downloaded
and hashed. Do not infer the current package's maintenance solely from the old
repository. The checked successor HEAD is
`04bce4e66013ff857ed462fd4206210544101461`, a September 2025 merge of serialization
work. No more recent release than 5.0.0 was in the inspected registry index.
This is limited activity, not proof that every maintainer has abandoned it.

The [2019 Quarkslab report](https://blog.quarkslab.com/resources/2019-08-26-audit-dalek-libraries/19-06-594-REP.pdf),
section 3.1, identifies Bulletproofs 1.0.2 at
`6a17ceb3bf3ce9b94cfa16a2a1a7311eef2dc6e7`, curve25519-dalek 1.2.1 and a 2019
nightly compiler. Sections 6.2/6.3 include proof construction, verification and
MPC; it is relevant evidence, not merely a review of unrelated signatures.
It is nevertheless not an audit of release 5.0.0 or its current curve backend.

The local comparison of that snapshot against the published release changes
eight selected core/metadata paths, with 497 insertions and 177 deletions,
including range proving, the inner-product argument, generators and transcript.
These counts include documentation/refactoring and are **not** vulnerability
counts. The changelog separately records Merlin/RNG/curve dependency migrations.
The exact security-relevant delta is not independently closed by the old audit.

`RangeProof::prove_multiple` and `verify_multiple` support ordinary bounded
ranges with library Pedersen generators and a caller-supplied Merlin transcript.
A proposed threshold construction would also constrain the original commitment
and its threshold-shifted counterpart, retaining the same opening. That requires
reviewed application composition using library operations, not custom EC code.
The experimental warning on R1CS/`yoloproofs` must not be misrepresented as a
warning that the ordinary range API itself is experimental. R1CS is unnecessary.

The isolated dependency resolution uses `curve25519-dalek=4.1.3`, not an older
vulnerable curve release just because the manifest's lower constraint is older.
Merlin is 3.0.0. The 47-entry lockfile reports no known RustSec findings. License
is MIT with transitive notices still required. Rust/PyO3 integration is plausible
on both OSes, but **not locally matrix-tested for this candidate**. No MYT timing
claim is made. The published serialization shape gives 672 raw bytes for one
aggregate of two 32-bit ranges (21 32-byte elements); this is a source-derived
size, not an executed MYT threshold benchmark and excludes commitments/envelope.

Decision: do not downgrade to old audited dependencies, and do not inherit Tari's
successful platform tests as Dalek qualification. Obtain release-delta review and
a credible ongoing security-maintenance commitment before reconsideration.

## secp256k1-zkp Rangeproof Module

Examined native source:
[`037cc6d74cbb4a89e443117459b577d56a582e54`](https://github.com/BlockstreamResearch/secp256k1-zkp/tree/037cc6d74cbb4a89e443117459b577d56a582e54).
This is the established Borromean rangeproof module, **not** the separate BPPP
module. Only generator/rangeproof modules were enabled in the isolated build;
ECDH, Schnorr, MuSig, BPPP, surjection and other optional modules were disabled.
No batch verifier is required by this construction.

The [public header](https://github.com/BlockstreamResearch/secp256k1-zkp/blob/037cc6d74cbb4a89e443117459b577d56a582e54/include/secp256k1_rangeproof.h)
exposes commitments, proof generation with a minimum, verified min/max outputs
and `extra_commit`. The proposed profile uses exponent 0, fixed 32 hidden bits,
and two proofs against the same commitment: `[0, MAX]` and `[threshold,
threshold + MAX]`. Their intersection supplies the required integer predicate.
The wrapper must check returned bounds exactly; `rangeproof_info` alone does
not verify anything. Nonzero exponent and auto/minimal bit length can disclose
additional value information and must not be silently allowed.

**The library proof nonce is secret and must be unique per generation call. It
is not the public MYT challenge.** Someone who knows it can rewind the proof to
recover the value and blinding. Each of the two component proofs needs a distinct
secret nonce. No rewind API or embedded secret message belongs in a public MYT
interface. A production wrapper would obtain nonces from an OS CSPRNG and must
never log them; the external probe deliberately uses public test-only fixtures.

The isolated API probe passed **31 counted checks on Linux and the same 31 on
native Windows**. It checked boundaries, a value above the fixed bound, a value
below the threshold, all six requested context substitutions, wrong threshold,
wrong commitment, truncation and a proof-byte mutation. It did not implement
Borromean signatures, hashing, curve arithmetic or a production artifact.

The pair totals **5,136 raw bytes** for the measured `17 >= 10` fixture. Ten
iterations on the same i5-6400 host gave median `clock()` deltas of 9.724 ms
proving / 6.636 ms verifying on Linux and 10 ms / 8 ms on native Windows.
The clock implementation/resolution differs by C runtime; these are rough local
feasibility samples, not comparable CPU/wall-clock SLAs. Commitment/context setup
is outside those timing brackets. No Python wheel matrix was run for this C
candidate. The initial Windows link used DLL import declarations with a static
archive and failed; using the documented `SECP256K1_NO_API_VISIBILITY_ATTRIBUTES`
consumer macro resolved it without changing the library.

The C project is actively maintained and used by the Liquid/Elements ecosystem,
as described by [Blockstream](https://blog.blockstream.com/blockstream-research-brings-libsecp256k1-zkp-back-up-to-speed/).
This is meaningful deployment evidence, but Bitcoin's ECDSA-library reputation
does not independently certify this added rangeproof module. The repository
labels its added Confidential Assets APIs experimental/unstable; that warning
alone is not a demonstrated cryptographic defect. No current module-specific
independent report mapping to this exact source and MYT composition was obtained.

Supply-chain detail is material: published Rust wrapper `secp256k1-zkp=0.11.0`
resolves `secp256k1-zkp-sys=0.10.1`, whose vendored native reference is
`6152622613fdf1c5af6f31f74c427c4e9ee120ce` from June 2024. It is **not** the C
source tested above. The current C history includes the July 2026 secret-clearing
change `a69a662d052f2a3839798fdb7d98864d26ccf2cb` and other integration changes.
The old wrapper's nine-entry graph has no reported RustSec findings; that does
not establish parity with the reviewed current C source. A direct pinned C
binding could avoid this mismatch, but still needs its own provenance/FFI and
side-channel review. Native C is MIT; the Rust wrapper is CC0-1.0 with transitive
licenses. No unreviewed fork or vendored patch was promoted into MYT.

Decision: promising direct API fit, but not security-qualified for production.
The API probe is supporting engineering evidence, not independent validation.

## gnark

Examined release: [`v0.16.3`](https://github.com/Consensys-Incorporated/gnark/tree/v0.16.3),
commit `cfc7b2f907cc4212ec152077e022c6d0b4805759`, with `gnark-crypto=0.21.0`
and Go 1.25.7 declared by the inspected tree. Active maintenance and the public
[`audits/`](https://github.com/Consensys-Incorporated/gnark/tree/v0.16.3/audits)
collection are positive evidence. The May 2024 zkSecurity report covers specific
foreign-field/curve, range-check and recursive-verification components, not an
arbitrary MYT credential circuit.

The August 2026 [GHSA-3mvx-pp85-pm65](https://github.com/Consensys-Incorporated/gnark/security/advisories/GHSA-3mvx-pp85-pm65)
describes underconstrained gadget outputs, including arithmetic and byte operations
used by hash gadgets. It identifies versions below 0.16.2 as affected and 0.16.2+
as patched. **The examined 0.16.3 is not in that advisory's affected range.**
An old audit must not justify choosing an old affected version. The advisory
credits internal security work and community reporters; current security-path
closure for the proposed MYT gadget set was not established independently here.

The library can express a bounded integer, a commitment opening, a comparison
and public context with existing gadgets. It would require a newly specified
MYT circuit, careful constraints on every hint/output and a pinned verifying key.
It is not a drop-in native minimum-proof API. A successful honest circuit test
cannot establish that a malicious prover has no unconstrained alternative.

The [supported schemes](https://docs.gnark.consensys.io/Concepts/schemes_curves)
require setup: Groth16 is circuit-specific; the available PLONK/KZG route uses
a universal SRS. Neither may be presented as transparent merely because a
ceremony already exists elsewhere. No MYT setup provenance/ceremony policy was
approved or checked. The Go toolchain can target Linux and Windows; a local
native helper/FFI and Python packaging would still need qualification. Apache-2.0
is permissive; Go modules, generated curve code and build graph enlarge review
scope. No local MYT circuit benchmark, complete Go dependency audit or six-way
Python matrix was run. Proofs can be compact, but no MYT-specific size or latency
number is claimed without an actual qualified circuit.

Decision: do not replace a missing backend review with a new unaudited circuit
and an unapproved setup lifecycle.

## Zcash Halo2

Examined registry release: `halo2_proofs=0.3.5`, source
`8e22adbdce480e5db7625df56aff9c2c8ca79f8f` in
[`zcash/halo2`](https://github.com/zcash/halo2). This means the Zcash IPA/Pasta
variant, not another project's Halo2 KZG fork. The IPA route has no trusted
ceremony, but its circuit parameters/generators and verifying key must still be
derived, pinned and validated correctly. No application circuit was built.

There is current external evidence: [Least Authority's June 2026 publication](https://leastauthority.com/blog/ai-assisted-security-auditing-in-the-zcash-ecosystem/)
reports a human-triaged review including Halo2, with final reports delivered on
May 29 and two confirmed Halo2 findings (one High, one Low). This must not be
misreported as "no audits since 2022". However, the public summary does not
provide enough exact snapshot, affected-path and remediation mapping to close
the MYT decision for the 0.3.5 path and a new commitment/range circuit.
Audits of Orchard application changes are not automatically generic Halo2 or
MYT circuit audits either.

The published changelog identifies a security fix in 0.3.1 rejecting inconsistent
evaluations for the same commitment/point in multiopen, reported by zkSecurity.
Version 0.3.5 includes it. Subsequent 0.3.3-0.3.5 additions mainly concern optional
verifier-fingerprint/Lean fixtures; those off-by-default features must not be
automatically described as changes to every default verifier. Likewise, the
current source HEAD and the published 0.3.5 package must not be conflated.

Existing gadgets and a custom application circuit could constrain the commitment,
32-bit range, threshold and public context. Context must be connected to the
actual relation/public instances rather than serialized as unused metadata.
The ordinary `SingleVerifier` route would suffice; an exposed batch API is not
needed. Default Cargo features include batch and multicore; narrowing features
would require reviewing and testing that exact resulting graph.

The examined default-feature graph has 42 entries, `pasta_curves=0.5.2`, and no
known RustSec findings. Rust with an ABI3 binding is plausible on both OSes;
neither that candidate's native Python matrix nor its MYT circuit benchmarks
were executed. MIT/Apache-2.0 choices and transitive notices require inventory.
Proof size, proving work and memory depend on the circuit; quoting Orchard or
another KZG-fork benchmark as MYT performance would be misleading.

Decision: retain as a research candidate, but require the detailed recent review
and fix mapping plus a reviewed concrete commitment/range circuit before selection.

## RISC Zero And Non-Threshold Credential Systems

The registry/release metadata identifies stable `risc0-zkvm=3.0.6` from July 2026;
`5.0.0-rc.1` is a prerelease, not a substitute stable candidate. The project has
active maintenance, a public [audit collection](https://github.com/risc0/rz-security/tree/main/audits)
including a February 2026 zkVM review, and published security advisories. That
evidence is stronger than a bare "audited" badge, but requires matching the
guest, host, proof mode, toolchain and patched dependency versions.

For MYT, a guest would verify the commitment opening, range and threshold using
existing primitives and output only the bound statement into the journal. The
host verifier would pin the guest image ID and compare expected journal/context.
Remote proving is not an acceptable replacement for local proving of a secret
metric. A verifier-only Windows build would not meet the Windows prover gate.
Official [installation guidance](https://dev.risczero.com/api/zkvm/install)
provides Linux/macOS routes; native Windows full local proving was not qualified
here. It must not be silently replaced by WSL, Docker or a cloud service.

The transparent STARK route and the optional
[Groth16 wrapping ceremony](https://dev.risczero.com/api/trusted-setup-ceremony)
have different setup assumptions. The still-published
[GHSA-5xgj-pmjj-gw49](https://github.com/risc0/risc0/security/advisories/GHSA-5xgj-pmjj-gw49)
warns that the specific provable zero-knowledge property is not established for
the affected construction and lists all versions with no patched version. It
does not demonstrate practical extraction of a MYT value, but MYT's primary
requirement here is privacy, not only computational integrity. No independent
evidence closing that warning for the exact proposed mode was obtained.
This and the platform gap stop selection before a heavy local prover benchmark.
No RISC Zero package, guest or large proving asset was installed in MYT.
The Apache-2.0 host/toolchain ecosystem and guest build assets would need a full
supply-chain inventory; no such product inventory is claimed complete.

[BBS selective disclosure](https://www.w3.org/TR/vc-di-bbs/) by itself reveals
selected signed attributes while hiding others; that does not prove a hidden
integer exceeds a public threshold. Systems such as
[Dock's cryptography collection](https://github.com/docknetwork/crypto) offer
additional predicate constructions, but that is a separate proof/composition
and credential-scheme review, not a property inherited from BBS. They were
screened out as non-drop-in alternatives; no exact Dock version is qualified or
declared insecure here. Replacing Phase 4B identity semantics is out of scope.

## Evidence Inventory

Registry archive SHA-256 values, verified against downloaded files:

```text
012e2e5f88332083bd4235d445ae78081c00b2558443821a9ca5adfe1070073d  bulletproofs-5.0.0.crate
f5aca1c66059a919227dec97444a11a4350d2f9c820ca48690988f0aa0e81cbf  halo2_proofs-0.3.5.crate
52a44aed3002b5ae975f8624c5df3a949cfbf00479e18778b6058fcd213b76e3  secp256k1-zkp-0.11.0.crate
57f08b2d0b143a22e07f798ae4f0ab20d5590d7c68e0d090f2088a48a21d1654  secp256k1-zkp-sys-0.10.1.crate
36aa069bd19fcd6f60f08aad442309a5260a3c64ee71f41eb2f57394e4ff4eca  dalek-quarkslab-2019.pdf
```

Known-advisory scans used RustSec database
`b50980aad8b8f14f77e25a97b32dd94bf008b0af`, with no ignored advisories:

| Probe graph | Lockfile entries, including local harness | Known vulnerabilities / warnings | Cargo.lock SHA-256 |
| --- | --- | --- | --- |
| bulletproofs 5.0.0 | 47 | 0 / 0 | `879ea36871e5db473b789b39f98e06a6104df442cefa32946315f96b54ef2f75` |
| halo2_proofs 0.3.5 | 42 | 0 / 0 | `903a16e743b1283ec3a978cc7b37c1350d73ba155b150ce03090c9578c5623b7` |
| secp256k1-zkp 0.11.0 | 9 | 0 / 0 | `7e32d13ae17ec18294b126bf2b142ab5db87c352c5fb4d8649cc66e2fd402dda` |

These are isolated feasibility lockfiles, not MYT dependency changes or complete
FFI release SBOMs. The C source test and the old Rust-wrapper graph are different
artifacts; their results are deliberately not combined into a false all-green
candidate. Empty advisory lists are not proof of absence of vulnerabilities.

Raw review evidence is in the external `myt-phase4f-backend-review/alternatives`
directory: source checkouts, registry archives/index snapshots, GitHub metadata,
audit material, `graph-*/Cargo.lock`, `graph-*/audit.json`, C build logs and the
two `secp-review-*.jsonl` execution logs. The C probe source SHA-256 is
`3e7ab0b2a6a40bb89a0a952c33412a7b5c7832e20a779a25f3956645f8bb533d`.
No private production keys, MYT wallet data or network credentials were used.

## Final Decision And Reopening Requirements

**Zero candidates clear all gates.** This is a bounded evidence-based decision,
not a claim that every examined current library is exploitable. In particular,
Tari's known batch flaw is fixed and gnark 0.16.3 is outside the cited affected
range. Successful API probes do not repair an independent-review gap.

Before implementation can resume, obtain one of:

1. Qualified review of Tari's exact post-2023 transcript/RNG and singleton
   verifier changes, plus the same-commitment double-range/context composition.
2. Current path-specific evidence for a pinned secp256k1-zkp rangeproof build,
   including secret nonce/rewind handling, FFI provenance and the two-range use.
3. The detailed recent Halo2 findings/fix mapping and a reviewed application
   circuit/gadget composition, followed by platform qualification.
4. Equivalent closure of the explicitly listed gates for another established
   backend, without changing MYT's privacy/platform requirements silently.

After that design review passes, execute **all** original Phase 4F implementation
and release-review gates. Until then keep v0.5.0 / 4A-4E unchanged. These research
documents stay uncommitted on the feature branch; no merge of even the research
documents into main is authorized by this blocked gate.

No tag, release, PyPI publication, deployment or Phase 4G work.

## Subsequent Credential-Oriented Question

The [credential architecture review](phase4f-credential-architecture-review.md)
revisits BBS and AnonCreds for a newly authorized, different architecture question.
The earlier BBS screening remains correct for an arithmetic threshold proof:
selective disclosure alone does not prove a hidden integer exceeds a threshold.

For pre-evaluated signed predicate claims, BBS is instead a plausible minimal ZK
credential approach. The new review records exact current packages, standards,
audit gaps, native-platform probes and disclosure/holder/freshness semantics.
Its decision is **PROMISING - EXTERNAL CRYPTO REVIEW REQUIRED**, with no exact
production implementation selected. The earlier range-proof decision is not
overridden. AnonCreds 0.2.3 additionally failed the requested-predicate binding
gate in the external API tests; see the new report for the distinction from
documented application-level raw-encoding checks and ACA-Py's existing additional
predicate-bound validation. The bare API result is not a blanket finding against
frameworks that already perform those checks.

No custom primitive, product adapter, dependency change or Git integration is
authorized by either review. These are uncommitted research addenda only.
