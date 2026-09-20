# Phase 4F v1 candidate protocol

UNRELEASED FEATURE CANDIDATE. Python runtime version remains the baseline 0.5.1
so all 487 existing expectations and the RPC User-Agent stay unchanged.
This feature checkout is NOT the released v0.5.1 artifact. CRYPTO BACKEND EXTERNALLY QUALIFIED = NO.
EXTERNAL CRYPTO REVIEW REQUIRED = YES. Not deployment approval.

## Meaning

A trusted evaluator computes assertions from the actual v0.5.1 Phase 4E
ReputationStore, ReputationPolicy and reputation_summary. A holder proves
possession of the resulting evaluator-signed credential and control of the
independently expected Phase 4B subject identity.

This is NOT an arithmetic ZK proof that a hidden integer exceeds a threshold.
It is not a global reputation score. A malicious trusted evaluator can lie.
Protected local settlement observations are not transferable blockchain proofs.
No wallet, settlement-address binding, daemon, consensus or blockchain changes.

## Narrow catalogue and privacy

Only verified_recipient_settlement_events is supported. It is the number of
validated local recipient settlement observations for the subject and network
in the current Phase 4E snapshot, bounded by store capacity <=100000.
Phase 4E revalidates its rows and signed artifacts, including its existing
revocation semantics. Its opinion-policy filters do not change this observation
count. Policy digest nevertheless identifies the exact evaluator configuration.

Thresholds are exactly 1,10,25,50,100. Each is an independently signed boolean
predicate; disclosure requires that specific position to be true. There is no
predicate 26 or arbitrary metric. The exact count and full history are NOT
credentialized. Four unrelated booleans are hidden in each presentation.

as_of records evaluator snapshot time, not a historical blockchain query:
settlement observations have no per-event timestamp. Issuance sets as_of and
issued_at from the local clock. Credential lifetime is <=86400 seconds and
contained by the issuer authorization. Request lifetime is <=300 seconds.
All checks use not_before <= now < expires_at (credential uses issued_at).
No clock grace. Trusted local clocks required. Stored clock rollback fails closed.

Repeated threshold requests can reveal a count interval. Stable subject ID,
evaluator, key ID, network, policy digest and timestamps remain public and
correlatable. BBS proof randomization does not provide counterparty anonymity.

## Exact artifacts

All JSON is UTF-8 restricted to printable ASCII strings, sorted keys, minimal
separators, no floats/null, no duplicate/unknown/missing keys, exactly one final
LF, <=32768 bytes. No BOM, normalization, alternate encodings or trailing bytes.
Public identity is the exact embedded five-field Phase 4B identity document.

Authorization:
type=myt-reputation-issuer-authorization, version=1,
evaluator, statement, id, signature.
Statement: bbs_public_key, bbs_key_id, ciphersuite, network, purpose,
not_before, expires_at. ciphersuite=BLS12-381-SHA-256.
purpose=myt-reputation-selective-disclosure-v1.
Lifetime <=366 days. Public key: canonical unpadded Base64url, 96 bytes,
native subgroup/point validation at the crypto boundary.
BBS key ID: myt-bbs-key-v1: plus lowercase SHA256 of
ASCII("MYT-BBS-KEY-V1") || 00 || ASCII(ciphersuite) || 00 || public_key_bytes.
Authorization content domain: ASCII("MYT-REPUTATION-ISSUER-AUTHORIZATION-V1\n")
followed by canonical JSON (no terminal LF) of type,version,evaluator,statement.
ID: myt-bbs-authorization-v1: plus lowercase SHA256(content).
Phase 4B context: myt-machine/disclosure/issuer-authorization/v1.

Revocation:
type=myt-reputation-issuer-revocation, version=1,
evaluator, statement, id, signature.
Statement: network,issued_at,authorization_id,bbs_key_id,reason.
Reason: compromised|retired|unspecified.
Same content construction, domain MYT-REPUTATION-ISSUER-REVOCATION-V1 plus LF,
ID prefix myt-bbs-revocation-v1:,
Phase 4B context myt-machine/disclosure/issuer-revocation/v1.
Every read revalidates the signature. Local revocation of a key is sticky,
including across renewed authorizations. Refresh cannot remove revocations.
This is LOCAL status, not global revocation discovery or trusted time.

Credential:
type=myt-reputation-credential,version=1,authorization,claims,signature.
Claims: subject_machine_id,network,policy_digest,metric_id,as_of,issued_at,
expires_at,predicates (five booleans in catalogue order).
Native BBS signature: canonical Base64url of 80 bytes.

Request:
type=myt-reputation-disclosure-request,version=1,purpose,
expected_subject_machine_id,expected_evaluator_machine_id,expected_issuer_key_id,
network,challenge,audience,policy_digest,metric_id,threshold,not_before,expires_at.
Challenge: exactly 32 OS-random bytes, canonical unpadded Base64url.
Audience: 1-256 visible ASCII characters, exact matching, no URL normalization.
Independent verifier configuration supplies subject, evaluator, key, network,
audience, policy and threshold. Never infer them from a received presentation.

Presentation:
type=myt-reputation-disclosure-presentation,version=1,authorization,claims,
request,proof,subject_control.
Claims: credential claims without predicates. Proof: 400 bytes, Base64url.
subject_control: identity (embedded Phase 4B document), signature (64 bytes).

## Fixed BBS messages

All messages are separate ASCII byte arrays; no map iteration or delimiter join.
Integers use unpadded base-10 text. Max message length 256 bytes.

| Index | Meaning | Limit | Disclosure |
| --- | --- | --- | --- |
| 0 | myt-reputation-bbs-v1 | 21 | public |
| 1 | evaluator Machine ID | 67 | public |
| 2 | BBS key ID | 79 | public |
| 3 | subject Machine ID | 67 | public |
| 4 | network | 8 | public |
| 5 | policy digest, lowercase hex | 64 | public |
| 6 | verified_recipient_settlement_events | 36 | public |
| 7 | as_of | 12 | public |
| 8 | issued_at | 12 | public |
| 9 | expires_at | 12 | public |
| 10 | >=1 boolean | 5 | selected only |
| 11 | >=10 boolean | 5 | selected only |
| 12 | >=25 boolean | 5 | selected only |
| 13 | >=50 boolean | 5 | selected only |
| 14 | >=100 boolean | 5 | selected only |

Boolean text is true or false. Disclosed positions are 0..9 plus exactly the
selected predicate position. Verification expects true at that position.
Policy digest: lowercase SHA256(ASCII("MYT-REPUTATION-POLICY-V1\n") ||
canonical JSON of ReputationPolicy.as_dict(), without terminal LF).

## Headers: transport encoding only

Credential header is exactly ASCII("MYT-REPUTATION-CREDENTIAL-V1\n").
Presentation header bytes are exactly:

    ASCII("MYT-REPUTATION-DISCLOSURE-PRESENTATION-V1\n")
    || canonical_request_JSON_without_terminal_LF

No cryptographic header bytes changed to fix transport. Python encodes those
raw bytes as canonical UNPADDED Base64url in the local JSON request.
Node uses the existing strict decoder, independently reconstructs the expected
bytes from the complete request and requires byte equality. The decoded bytes,
not the transport string, are passed unchanged to native BBS presentationHeader.
No newline removal, Unicode normalization, ASCII round trip, padding, alternative
alphabet or arbitrary caller-chosen domain is accepted.

## Subject control

Phase 4B signs with context myt-machine/disclosure/subject-control/v1.
Message:
ASCII("MYT-REPUTATION-DISCLOSURE-CONTROL-V1\n") || canonical JSON of:
version=1,
request_digest=SHA256(raw presentation header),
presentation_digest=SHA256(ASCII("MYT-REPUTATION-PRESENTATION-BODY-V1\n") ||
canonical presentation without subject_control),
subject_machine_id=request.expected_subject_machine_id,
bbs_key_id=request.expected_issuer_key_id.

Independently expected subject == request subject == signed credential subject
== Phase 4B signer. Existing Phase 4B framing and primitives are reused unchanged.

## Replay, trust and runtime

Private SQLite, application ID 0x4D594446, schema version 1, BEGIN IMMEDIATE,
synchronous FULL, trusted_schema OFF, bounded tables, schema/row validation.
An exact stored request must exist and be unused. Within one transaction:
clock, independent policy, signed issuer authorization, locally checked freshness
and revocations, subject signature, native BBS proof, then a second clock/status
check and atomic one-time consume. Backend errors roll back without retry.
Completed consumption survives restart. Local status maximum age <=3600 seconds,
default 300. A trusted operator explicitly refreshes status; this does not prove
that unreceived remote revocations do not exist.

A compromised local administrator, database replacement/rollback, stolen issuer
capability or malicious runtime is outside the boundary. Do not open arbitrary
attacker-supplied SQLite files. Same-user/root compromise defeats private files.
Hold an exclusive transaction during bounded native verification; this deliberately
serializes verification and can cause availability contention.

See phase4f-runtime-architecture.md and companions/bbs/README.md. Existing
4A-4E operations do not require, install, spawn or contact Node.
