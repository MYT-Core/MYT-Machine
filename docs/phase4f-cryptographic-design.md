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

# Phase 4F Cryptographic Design Gate

Review date: 2026-09-10. Status: **BLOCKED BEFORE PRODUCTION IMPLEMENTATION**.

This is a backend assessment, not a released protocol or a security certification.
No backend has been selected for MYT Machine. The package remains at 0.5.0.
Passing functional probes does not establish cryptographic soundness.

## Decision

Tari Bulletproofs+ 0.5.3 is technically suitable for further evaluation, but this
review cannot clear its production-design gate. Its known batch bypass is fixed;
the remaining blocker is assurance over the current security-critical execution
paths, not an assertion that the same vulnerability remains exploitable.

The published audit does not establish coverage of subsequent transcript/RNG
changes or the September 2026 verifier rewrite. No current independent review
covering those changes was located in the examined upstream materials. The local
probes below cannot replace that review. Alternative families were compared, but
none was qualified as an immediate, sufficiently reviewed replacement for this
specific deployment. This does not mean that those projects are generally unsafe.

Production work, version changes and Git integration are deliberately stopped.

## Exact Candidate and Provenance

| Item | Examined value |
| --- | --- |
| Registry package | `tari_bulletproofs_plus` |
| Version | `0.5.3`, published release dated 2026-09-07 |
| Upstream release commit | `b72778d2a5aee5dad5a0bb85e9df1d0b8be698aa` |
| Crate SHA-256 | `66582d6709d2b7c49509a3c56a63fe1e893af16e86fb757ae60eac8d15a70903` |
| Audit PDF SHA-256 | `e7a839ba5824881bcc57318c2f957a68f2075728693bc8db7b28dba04f58689b` |
| Native probe lockfile SHA-256 | `32ae3a982c5d911d6b849c17315c233cac5c235cebab11674e913c9535871742` |
| Python probe lockfile SHA-256 | `7f0745c01032243de92fa97a11b7d5f7d484f12db975b24aeb18f881e1d4b9ee` |

The official crates.io archive was downloaded, its checksum compared with the
registry index, and its VCS metadata compared with the release commit. The
published `src/` tree matches that commit's `src/` tree byte for byte. These are
integrity/provenance checks, not proof of an uncompromised publisher or compiler.

Sources: [upstream](https://github.com/tari-project/bulletproofs-plus),
[release source](https://github.com/tari-project/bulletproofs-plus/tree/b72778d2a5aee5dad5a0bb85e9df1d0b8be698aa),
[registry archive](https://static.crates.io/crates/tari_bulletproofs_plus/tari_bulletproofs_plus-0.5.3.crate).

## Critical Advisory

[GHSA-4rf5-q25p-h3rh](https://github.com/tari-project/bulletproofs-plus/security/advisories/GHSA-4rf5-q25p-h3rh)
describes a critical verification bypass through 0.5.1: chunked verification
processed only the first 256 entries. Upstream identifies 0.5.2 as patched.

The fix commit `1f240408830d5065e2e864a8413200472771fbcd` is present in 0.5.3.
Its loop processes corresponding transcript, statement and proof chunks instead
of consuming only one chunk. Local tests of 0.5.3 exercised batch lengths
1, 255, 256, 257 and 513. Valid batches returned one result per proof; an invalid
statement/proof pair at either the first or last position was rejected.
The upstream regression for batches larger than 256 also passed.

Conclusion: the reported bypass is addressed in the exact examined artifact.
No claim is made here about exploitation on any deployed Tari network. MYT Core
does not acquire this dependency through this review.

## Audit Coverage and Current API

The [Quarkslab report](https://github.com/tari-project/bulletproofs-plus/blob/b72778d2a5aee5dad5a0bb85e9df1d0b8be698aa/docs/quarkslab-audit/report.pdf)
is dated 2023-10-20. Sections 5-7 cover range proofs, minimum-value assertions,
transcripts, generators and batch equations. Section 5.1 excludes prover-device
side channels and assumes the underlying papers and Merlin are sound. Thus the
audit is relevant, but not a blanket certificate for today's dependency graph.

The [upstream audit note](https://github.com/tari-project/bulletproofs-plus/blob/b72778d2a5aee5dad5a0bb85e9df1d0b8be698aa/docs/quarkslab-audit/README.md)
points to `pre-audit-commit`, resolving to
`a8647e28d49c48308ea05001b3723cd0eb7f3bab`. The reference-to-release `src/` diff
contains 24 files, 1,861 insertions and 1,447 deletions. Some changes occurred
during the audit itself; these totals must NOT be described as exclusively
unaudited production changes. They include tests, refactoring and a `.DS_Store`.

The following changes are demonstrably later than the report:

| Commit | Date | Security-relevant change |
| --- | --- | --- |
| `854dd885859c5ef772e731d34dfe4de7f9cbe636` | 2024-01-15 | RNG state moved into the proof transcript |
| `6be2bda1dfe13b6e14ea14ac58e28250051640ef` | 2024-03-04 | Caller-provided composable transcripts |
| `8759a59a1feaa9b4ae99475e107e49f7a0ca8ff5` | 2024-03-04 | Verifier external RNG replaced by transcript-derived weights |
| `9954f5a4f526903bdd37eb13f4780d90e7d748d8` | 2025-07-14 | Entropy handling change |
| `eba79a26e2cb8fae50da951474e2d5e2a54e22ca` | 2026-04-28 | Randomness dependencies upgraded |
| `1f240408830d5065e2e864a8413200472771fbcd` | 2026-07-27 | Chunked verification bypass fixed |
| `c6f0afd012bc5fd0ed6fd3cb154e82d14c85c176` | 2026-09-07 | Verifier scalar recurrence, MSM selection and generator fast path changed |

In particular, [the 0.5.3 optimization](https://github.com/tari-project/bulletproofs-plus/commit/c6f0afd012bc5fd0ed6fd3cb154e82d14c85c176)
changes scalar assembly even for single-proof verification; it is not merely an
unreachable large-batch optimization. Its final code restores canonical-point
checks that an earlier PR revision had removed in recovery-only mode. That
earlier revision is NOT reported as a remaining defect in the final release.

The historical reference also contains the first-chunk-only construct. An audit
label therefore cannot substitute for checking the actual control flow.
No new successful forgery or current soundness failure was demonstrated here.
The unresolved question is independent assurance of the changed current path.

## Proposed Integer Semantics, Not Yet a Product Protocol

Let `MAX = 2^32 - 1`. A future metric and public threshold must both be integers
in `[0, MAX]`; booleans, floats, negatives and overflow must be rejected.

Use only the library's standard Pedersen generators. In Tari's notation,
`C = v*H + r*G`, with value base `H` and masking base `G`. The library supplies
the Ristretto operations and generator derivation. No user-selected generators,
extended masks or recovery seed are needed. There is no trusted setup ceremony.
Security depends on the group/discrete-log assumptions and the proof system's
Fiat-Shamir/Merlin assumptions, not on secrecy of parameter generation.

A minimum-value assertion alone establishes a shifted range. It must NOT be
mistaken for a proof of the application's fixed upper bound. An honest prover's
input check is not a constraint on a malicious prover.

The examined construction asks the library to aggregate two statements for the
same commitment, with 32-bit ranges and minima `[None, Some(threshold)]`:

```text
0 <= v <= MAX
0 <= v - threshold <= MAX
```

This is intended to establish `threshold <= v <= MAX`. The two commitments must
be exactly identical. The group order is far larger than these ranges, excluding
an integer wraparound interpretation under the commitment-binding assumption.
No manual curve subtraction, scalar arithmetic or proof equation was added to
MYT; all cryptographic operations in the external probe call upstream APIs.

The fixed probe uses `RangeParameters::init(32, 2, DefaultPedersen)`, one aggregated
proof and `VerifyAction::VerifyOnly`. Positive/negative boundary tests passed.
This supports feasibility; it is not an independent proof of adversarial
soundness or a substitute for reviewing the composition.

## Context Binding and Evaluator Trust

The current API accepts a caller-owned Merlin transcript. Before proving or
verifying, a future adapter can append canonical public context through the
library's `append_message`; it must not implement its own Fiat-Shamir transform.

The experimental domain is `myt-machine/backend-review/v1` and is TEST ONLY.
Mutating audience, nonce, policy, metric, subject, network or credential context
caused rejection in the local probes. Changing the public minimum did too.
These tests used an illustrative byte string, not a finalized artifact schema.

A product design still requires a strict canonical envelope that binds the
protocol/backend version, full credential digest, evaluator, subject, network,
policy digest, metric definition, threshold, challenge, audience, purpose and
expiry. Expected values must come from the verifier, not solely from the proof.
Binding context does not implement freshness: a durable, bounded challenge store
must atomically consume a valid challenge and reject replay after restart.

The evaluator would sign the commitment/context using the existing Phase 4B
signature API. Default evaluator trust remains empty, and self-issued credentials
must not gain trust. Since the evaluator knows the opening too, the range proof
alone cannot authenticate current subject-key control: the holder must separately
authorize the presentation with Phase 4B, bound to the same fresh challenge.

The normal issuance API must call actual Phase 4E `reputation_summary` on a
validated `ReputationStore`, not accept an arbitrary claimed metric. Candidate
mappings from the current code are:

| Candidate metric | Actual Phase 4E source |
| --- | --- |
| `accepted_attestations` | `local_policy_output.accepted_attestations` |
| `accepted_positive_attestations` | `local_policy_output.positive` |
| `verified_settlement_events` | `objective_local_observations.verified_recipient_settlement_events` |

The first two reflect revocations, trusted issuers, age, per-issuer caps and
optional settlement linkage. The last counts local recipient observations; it
is not filtered by the attestation issuer/age policy. A future specification must
state that distinction rather than silently changing Phase 4E semantics.
None proves payer identity, universal reputation or complete global history.

Short-lived credentials would be snapshots with an issuer-claimed issuance time.
An illustrative maximum lifetime is 24 hours with a shorter verifier policy;
this is a proposal, not implemented configuration. Unseen revocations remain
unseen offline. Expiry is not global revocation or trusted blockchain time.

## Batch Exposure

MYT does not need to verify multiple independent proofs in one call. The public
upstream entry point is nevertheless `verify_batch`; its singleton path runs
the same verifier code. A future wrapper must fix batch cardinality to one,
use `VerifyOnly`, disable mask recovery, and check the returned cardinality.
It must not expose arbitrary batch sizes or `RecoverOnly` as proof validation.
Aggregation of two range statements is distinct from a batch of two proofs.
These restrictions reduce surface area but do not make the audit gap disappear.

## Privacy and Side Channels

Fresh production openings must use the OS CSPRNG through established library
APIs. The fixed scalar `424242` in the external probe is public TEST ONLY data.
Production must not use it. Reusing one opening for the two constraints on the
same commitment is intentional; reusing it for distinct credentials is not.
Repeated proofs with fresh library randomness produced different proof bytes.

An exact metric and evidence need not be serialized into a proof, but subject,
evaluator, policy and stable credential/commitment identifiers remain linkable.
This is not an anonymous credential. Adaptive threshold requests can binary
search a small metric. In addition, an accepted threshold equal to `MAX` reveals
the exact value logically. UI and documentation must not promise that every
possible threshold hides the exact value. Disclosure consent must cover the
predicate and repeated-query risk, not merely the absence of a JSON field.

The current prover performs variable-time operations involving witness-derived
scalars. Local-only proving reduces remote exposure but does not prove safety
against co-resident, timing or cache adversaries. A concrete side-channel threat
model and qualified assessment remain required. No such exploit was established
here, and no constant-time guarantee is claimed.

## Platforms, Dependencies and Packaging

The isolated Rust probe was built with Rust/Cargo 1.98.1. The native Windows
executable was cross-compiled using the GNU Windows target and executed on
Windows, not Wine. A separate PyO3 0.29.0 `abi3-py310` module also built and passed
real import/prove/verify checks on all six Python/OS combinations listed in the
[validation report](../MYT_Phase4F_Validation.md). This establishes integration
feasibility, not finished wheel support or a supported dependency floor.

Important examined dependencies include `curve25519-dalek=5.0.0` (BSD-3-Clause),
`tari_merlin=4.0.0` (MIT), `getrandom=0.4.3` (MIT OR Apache-2.0),
`rand_core=0.10.1` (MIT OR Apache-2.0), `zeroize=1.9.0` (Apache-2.0 OR MIT),
and the test binding `pyo3=0.29.0` (MIT OR Apache-2.0). Tari itself is BSD-3-Clause.
The resolved license expressions provide permissive choices; redistribution
would still require a complete notice inventory. No new MYT runtime dependency
has been added. PyO3 0.29.2 was available during resolution but was not tested.

`cargo audit` found zero known vulnerabilities and no informational warnings
in the native probe lockfile (50 entries) and Python probe lockfile (57 entries),
against database commit `b50980aad8b8f14f77e25a97b32dd94bf008b0af`.
No ignored advisories were configured. This is a snapshot, not a security proof.

Maintenance is active, including prompt advisory remediation, but current
pre-1.0 releases and cryptographic dependency transitions create integration
maintenance risk. A future release must pin and review the complete Cargo graph,
build with `--locked`, preserve notices/SBOM and artifact provenance, and ship
platform-specific wheels. No binary may be downloaded at application runtime.
The Rust edition is 2024; a supported compiler/MSRV must be established rather
than inferred solely from this 1.98.1 build. Linux portability/manylinux and
Windows DLL dependencies remain packaging gates, not completed work.

## Measurements

External probe: one proof aggregating the two 32-bit assertions, default mask,
10 iterations, Intel Core i5-6400 at 2.70 GHz. Setup of generators is included
in the measured helper calls. WSL and Windows runs had different host load;
these are feasibility measurements, not a fair OS comparison or an SLA.

| Measurement | Linux/WSL | Native Windows, persisted run |
| --- | --- | --- |
| Raw proof size | 577 bytes | 577 bytes |
| Median proving | 55.492 ms | 17.819 ms |
| Proving min / max | 21.790 / 71.570 ms | 16.989 / 18.746 ms |
| Median verification | 13.482 ms | 5.811 ms |
| Verification min / max | 8.727 / 38.958 ms | 4.574 / 6.143 ms |

Credential size/issuance and full CLI verification were not measured because
there is no product credential implementation. A future wrapper should require
the exact proof shape/size before deserialization and bounded context, parameters,
artifact size and concurrency. Timings alone are not a DoS limit.

## Alternatives Compared

The subsequent [detailed alternatives review](phase4f-backend-alternatives.md)
is complete for the candidates examined. It records exact releases/source,
audited snapshots, current advisories, context/range composition, setup,
maintenance, licenses, dependency graphs, platform evidence and measurements.
No alternative cleared all gates. Not selected does not mean a new exploitable
defect was demonstrated.

| Candidate | Advantages | Remaining qualification / reason not selected now |
| --- | --- | --- |
| Tari BP+ 0.5.2 | Contains advisory fix, avoids the 0.5.3 optimizer | Still post-audit transcript/RNG changes; exact alternative graph and path require review. No automatic downgrade. |
| [zkcrypto Bulletproofs 5.0.0](https://github.com/zkcrypto/bulletproofs) | Rust/Ristretto, transparent range proofs, relevant 2019 review, MIT | The audit identifies 1.0.2; current security-path delta and active maintenance need qualification. Resolved curve 4.1.3 graph has no known RustSec findings. R1CS warning does not apply automatically to range API. |
| [secp256k1-zkp rangeproofs](https://github.com/BlockstreamResearch/secp256k1-zkp) | Native minimum/context APIs, no trusted setup, MIT; 31 external checks pass on each OS | Current module review not established. Published Rust wrapper vendors June 2024 C, not tested current C. A secret rewind nonce must never be confused with the public challenge. |
| [gnark 0.16.3](https://github.com/Consensys-Incorporated/gnark) | Active Go framework, multiple scoped audits, Apache-2.0; outside cited advisory's affected range | New MYT circuit, current gadget assurance and trusted-setup lifecycle not qualified. No MYT circuit benchmark or platform matrix claimed. |
| [Zcash halo2_proofs 0.3.5](https://github.com/zcash/halo2) | Active Rust IPA/Pasta system, no trusted setup; newer 2026 independent review exists | Detailed findings/remediation-to-current-path mapping and MYT circuit review still needed. No false claim that only a 2022 audit exists. |
| [RISC Zero zkVM 3.0.6](https://dev.risczero.com/api/secure-sdlc) | Active audited zkVM approach, transparent STARK route | Published provable-ZK assurance warning not closed for the chosen mode; native Windows local prover and MYT guest unqualified. Groth16 wrapping has separate setup assumptions. |
| [BBS selective disclosure](https://www.w3.org/TR/vc-di-bbs/) / [Dock](https://github.com/docknetwork/crypto) | Established credential/signature families; specialized predicate systems exist | BBS disclosure alone is not an integer-threshold proof. Additional predicate composition and credential/signature machinery require separate review and must not replace Phase 4B identity semantics. |

## Conditions to Reopen the Design Gate

1. Obtain a qualified independent review of the exact selected release's
   post-audit transcript/RNG and verifier changes, including the singleton path.
2. Review the double-range composition, holder authorization, adaptive-disclosure
   risks and canonical challenge/credential binding as one application protocol.
3. Accept and document a concrete local-prover side-channel threat model.
4. Alternatively qualify an exact established replacement through the same gates;
   do not select one merely because its README says audited.
5. Only then write production code and execute every original Phase 4F gate.

No replacement primitive, special-purpose Fiat-Shamir implementation, curve
implementation, public production schema or release artifact was created.
Only research documents remain in the local feature worktree. While the design
is blocked, even integrating these documents into main requires separate express
approval for roadmap/research documentation. No product integration is authorized.

## Credential Architecture Follow-Up, 2026-09-10

The subsequent [credential architecture review](phase4f-credential-architecture-review.md)
asks a different question: can the actual reputation-disclosure requirement be
met using evaluator-signed bounded predicate claims rather than a hidden-integer
range composition? It does not reopen or qualify any range backend above.

Architecture B, BBS selective disclosure of pre-evaluated predicate claims, is
promising **subject to external cryptographic review**. Its proof authenticates
an evaluator's assertion, not an integer inequality or the evaluator's execution
of Phase 4E. No exact implementation is production-qualified. Existing identity,
policy, local observations and trust semantics remain unchanged.

New external probes cover Digital Bazaar BBS 3.1.0, ZKryptium 0.7.0 and AnonCreds
0.2.3 on Linux/native Windows and three Python versions each. Passing BBS probes
do not close current audit/composition gaps. AnonCreds' direct verifier accepted
requested-predicate substitution; its separately documented raw/encoded checking
obligation was also confirmed. These new findings concern the new credential
review, not the earlier statement that no new range-backend exploit was shown.
ACA-Py's existing predicate-bound and raw/encoded prechecks show that the bare
API is not the entire established verifier contract. The report does not claim
a break of the CL primitive or qualify a full framework that was not tested.

No production code, dependency, version, public wire protocol or release was
created. This follow-up remains local research only. The prior evidence is
preserved above; main and released v0.5.0 remain unchanged.
