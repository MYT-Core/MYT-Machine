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

# Phase 4F BBS Integration Contract

Status: mandatory design contract after the three-finding follow-up review,
2026-09-11. NOT an implemented official product or cryptographic qualification.
Official baseline: 73beb99102f56671d6b2d85c9368bfa788249dc2.

The isolated repair is derived from public contributor fallacyofall's candidate
85bd11ca26f6412cd7d3e59b582962bedbc98b3c. No upstream commit is integrated.

## Meaning and trust boundary

Architecture B proves possession of an evaluator-signed credential, selectively
disclosing a bounded predicate assertion. It does not prove a numeric inequality
over independently verified private settlement history. Evaluator selection,
evidence policy, issuer authorization and current issuer-key status remain
trusted application policy. Machine and evaluator IDs and disclosed metadata
remain linkable. This is not anonymity or a global reputation score.

A verifier MUST independently obtain its expected subject from its own policy
or authenticated application session before registering a request. It MUST NOT
derive that expectation from an incoming credential, request, proof or signer.
An API parameter supplied directly by an unauthenticated caller is not
automatically an independent trust anchor.

Existing v0.5.1 Phase 4A-4E behavior, package dependencies and commands MUST remain
unchanged. No wallet spending, wallet secrets, MYT Core or consensus changes.

## Request schema and canonical bytes

The reviewed strict profile uses ReputationDisclosureRequestV1 with exactly:

    {
      "type": "myt-phase4f-reputation-disclosure-request",
      "version": 1,
      "purpose": "myt-phase4f-reputation-disclosure-v1",
      "expected_subject_machine_id": "<canonical Machine ID>",
      "challenge": "<canonical unpadded Base64url of 32 random bytes>",
      "audience": "<1-256 visible ASCII characters>",
      "network": "mainnet|testnet|stagenet",
      "policy_digest": "<64 lowercase hex characters>",
      "requested_predicate": {
        "metric_id": "verified_recipient_settlement_events",
        "operator": "gte",
        "threshold": 25,
        "required_result": true
      },
      "not_before": 1700000100,
      "expires_at": 1700000220
    }

String placeholders above are not literal allowed values. version is integer 1,
not bool. Machine IDs require canonical Base32 padding bits, not just a regex.
The review request allows the external predicate range for comparison. The
official product MUST instead lock a documented bounded threshold catalogue;
the proposed catalogue remains [1, 10, 25, 50, 100], with no arbitrary probing
thresholds. It must reject unsupported metric/operator/catalogue combinations.

Canonical JSON C(x) has lexicographically sorted object keys, minimal decimal
integers, no insignificant whitespace, and no additional terminal newline.
This reviewed request's field names and all strings are ASCII; it deliberately
rejects Unicode audience strings rather than rely on mismatched JavaScript and
Python escaping rules. Strict incoming artifact parsing must additionally reject
duplicate/escaped duplicate keys, BOM, invalid UTF-8, floats, negative zero in
wire representation, non-canonical forms and unknown/missing fields.

Exact bytes passed to the backend:

    ph = UTF8("MYT-MACHINE-PHASE4F-PRESENTATION-V1\n" || C(request))

The final LF above belongs to the domain prefix. There is NO terminal LF after
the request JSON. No normalization, field omission or Base64url text signing is
permitted at the cryptographic API boundary.

All of expected subject, challenge, audience, purpose, network, policy, metric,
operator, threshold, required result and temporal fields are therefore inside ph.
The backend MUST receive this exact ph for both deriveProof and verifyProof.
Use the backend's existing API; do not implement transcript hashing, pairings,
hash-to-curve or BBS operations.

The public interoperability fixture's deterministic request/header digest is:

    f33bb331a999e6aec45aaffb288c1e177fc3f4eae2843ad1dc78f8632dcac7f1

The retained fixture includes the entire request and header hex bytes.
Its BBS proof is randomized; proof bytes and subject signature are not claimed
to be reproducible across newly generated proofs.

## Subject authentication invariant

Successful verification requires ALL of:

1. Stored request expected_subject_machine_id equals the independently supplied
   verifier policy expected ID.
2. The incoming request is exactly the stored canonical request.
3. Disclosed evaluator, authorized BBS key, network, policy and fixed predicate
   match verifier policy and the request.
4. The disclosed credential subject equals the request's expected subject.
5. BBS verification succeeds for the exact request ph and fixed disclosed
   message positions.
6. The validated Phase-4B public identity equals the expected subject.
7. The Phase-4B control signature authenticates the exact request and BBS
   presentation proof, with the authorized key ID and same subject.
8. Active credential, authorization, current non-revoked key status and request
   validity all pass; one-use consumption succeeds atomically.

Mandatory expected-ID omission is an error, not generic anonymous verification.
A cryptographically valid B credential plus valid B proof/signature MUST fail
under A policy. Checking credential subject = signer alone is insufficient.

The isolated review keeps the contributor's existing subject-control statement:

    control = UTF8("MYT-PHASE4F-SUBJECT-CONTROL-V1\n" || C({
      "request_digest": lowercase_hex(SHA256(ph)),
      "proof_digest": lowercase_hex(SHA256(decoded_bbs_proof)),
      "bbs_key_id": authorized_bbs_key_id,
      "subject_machine_id": expected_subject_machine_id
    }))

The Phase-4B context is:

    myt-machine/phase4f/subject-control/v1

The exact BBS proof bytes, not its transport encoding, are hashed. Disclosed
claims are also authenticated by native BBS verification with their fixed
positions; their textual JSON spelling is not signed independently. The
presentation/header transport encodings must themselves be canonical.

The official implementation MUST call existing Phase-4B MachineIdentity.sign,
PublicMachineIdentity.verify and their existing framing, rather than duplicate
Ed25519 or the Machine-ID/framing implementation from the contributor prototype.
The follow-up confirms byte-for-byte frame and deterministic signature
interoperability with the unchanged official v0.5.1 SDK.

This composition is still subject to external cryptographic review. Application
hashing/framing is not evidence that the BBS backend has been audited.

## Activation and one-use lifecycle invariant

    0 <= not_before < expires_at <= 253402300799
    1 <= expires_at - not_before <= 300
    not_before <= verifier_now < expires_at

Integers only: reject bool, float, string, NaN, infinity and overflow.
Zero clock tolerance. not_before is semantic activation, not informational
metadata. Future scheduling is allowed, but future lookup/consume/verification
MUST fail until activation. The exact activation second passes; the exact expiry
second fails. No legacy created_at-only request is silently upgraded.

The supplied verification timestamp MUST come from the verifier's trusted local
clock, never the presentation or holder. The isolated API's explicit now is a
testable verification instant. A product adapter must obtain trusted time again
for final consumption, fail closed on material clock rollback, and cannot make
claims stronger than its clock assumptions. No hidden broad skew window.

Both stores enforce activation and expiry at lookup AND consumption. The durable
store validates its complete canonical stored record and its digest inside the
same BEGIN IMMEDIATE transaction that performs unused -> used. Do not trust an
expiry-only SQL condition. A failed proof or early/expired use MUST NOT consume
an otherwise usable nonce. Replays after restart and concurrent success attempts
must be rejected; only one process may return authentication success.

Snapshots of request/presentation inputs must be taken before asynchronous work.
Production storage must independently address schema versioning, capacity,
permissions, corruption, locking and symlink/TOCTOU behavior. This limited fix
does not certify all inherited storage code.

## Canonical key-storage invariant

A key file is a bounded byte artifact, not text to repair.

1. Read raw bytes subject to the size cap (8,192 bytes for the reviewed envelope).
2. Decode UTF-8 fatally. Do not remove BOM, clear high bits or replace bad bytes.
3. Parse and validate the exact supported envelope and fixed KDF/cipher profile.
4. Require original_bytes == UTF8(C(envelope) + one LF).
5. Only after canonical/profile checks perform the existing KDF and authenticated
   decryption; verify expected key ID against the derived public key.
6. Fail with the same redacted load error for malformed keys and wrong passwords.

The supported on-disk profile is canonical JSON plus exactly one LF. Reject
CRLF, missing LF, repeated LF, leading/trailing whitespace, duplicate keys
(including escaped duplicates), non-canonical escapes, BOM, UTF-16, invalid or
overlong UTF-8, NUL/control bytes and trailing content. No compatibility fallback.

Canonical parse-and-byte-compare cannot accept duplicate keys: their additional
bytes cannot survive reserialization to the exact schema. A product parser must
also explicitly reject duplicates at decode time and enforce nesting/size caps.

The existing envelope uses platform scrypt and AES-256-GCM; these primitives and
their cryptographic parameters were not redesigned in the follow-up. Do not
infer production storage approval from these parsing tests. Production still
requires no-overwrite, race-resistant file handling, passphrase/permission rules,
Windows ACL guidance, secret redaction and honest zeroization limitations.

## Backend and integration boundary

Pinned review graph:

- @digitalbazaar/bbs-signatures 3.1.0
- @noble/curves 2.4.0
- @noble/hashes 2.4.0

Required exact lockfile, npm registry integrity checks, and explicit runtime
support. The current tested runtime is Node 24.14.0. No claim is made here for
Node 20/22 or a Python-only implementation.

| Boundary | Preparation decision |
| --- | --- |
| Implicit Python -> Node/Node -> Python subprocess bridge | Do not inherit as production default; executable/env selection and secret flow need redesign. |
| Network proving sidecar | Not a default; introduces unnecessary transport, service and secret trust boundaries. |
| Explicit optional local JS companion with bounded artifact handoff | Preferred route to investigate; must preserve genuine Phase-4E issuance provenance, existing Python Phase-4B operations and exact verifier-state binding. Not yet product-approved. |
| New native BBS port / bespoke primitive | Not allowed to close this integration gap. |

Preparing a candidate requires resolving the companion boundary without
accepting arbitrary synthetic Phase-4E evaluations as official issuance,
without silently adding Node to current commands, and without inventing another
credential protocol. If those requirements cannot be met cleanly, STOP.

The independent review copy is deliberately not an official SDK implementation.
It retains external fixture-only issuance and other scaffolding to isolate
these three findings. It MUST NOT be packaged as MYT Machine v0.6.0.

## Acceptance and remaining release gates

Required adversarial cases now reproduced against the isolated remediation:

- A request + valid B credential + valid B signature; mixed A/B credential/signers.
- Subject mutation, credential and presentation transplant, refreshed holder
  signature over an old proof, old holder signature over a fresh proof.
- Exact ph changes under audience/network/policy/threshold/nonce/time mutation.
- Before/equal activation and before/equal/after expiry; integer bounds.
- Both lookup and consume; failed attempt preserves nonce; restart and process race.
- Invalid encoding, byte aliases, BOM, UTF-16, overlong sequences, whitespace,
  duplicate/escaped keys, control/NUL bytes and exact LF behavior.

These narrow engineering gates passed; they are not the entire original
Phase-4F product attack suite. Before calling an official candidate complete:

- Real read-only Phase-4E snapshot/policy evaluation and issuance integrity.
- Fixed minimal credential schema; do not retain exact metric/evidence digest
  merely because the review fixture hides them.
- Mandatory independent evaluator trust, key authorization/revocation freshness.
- Full bounded artifact parsing and hostile BLS-point/proof tests.
- Reuse official Phase-4B key handling and signatures, with no secret exports.
- Unchanged 487-test v0.5.1 regression suite plus complete new 4F tests.
- Full Linux/native-Windows Python/runtime matrix, security and packaging gates.
- Privacy/performance measurements and exact external code-path review package.
- Independent cryptographic qualification of the pinned backend and composition.

CRYPTO BACKEND INDEPENDENTLY QUALIFIED: NO.
EXTERNAL CRYPTO REVIEW REQUIRED: YES.
No merge to main, tag, release, PyPI publication or deployment is authorized.
