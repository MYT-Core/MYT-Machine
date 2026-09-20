# Phase 4F candidate threat model

## Protected claims

An independently trusted evaluator authorized an exact BBS issuer key for a
specific network/purpose/time window. That key signed the selected predicate
for the independently expected Machine Identity under the pinned policy.
A fresh request binds subject, audience, challenge, network, evaluator, key,
metric, threshold and validity window. The holder signs the exact request and
presentation digests using unchanged Phase 4B.

Neither a stolen credential without its subject key nor a subject key without
a matching credential should authenticate. Valid credentials for subject B
must never answer a request for subject A. Every acceptance consumes a registered
challenge atomically only after all checks, with an exact expiry boundary.

## Untrusted inputs

Artifacts, encoded messages, proof points, public keys, network peers and
external contribution source are untrusted. Strict schema/size/canonical bytes
are required before native cryptographic work. Native validation cannot be
replaced by caller flags. The loopback service rejects unknown operations and
fields, unauthenticated requests, browser Origin, wrong Host, redirects/proxies,
arbitrary domains and normalized presentation headers.

## Trusted and limited components

The evaluator can lie about its local evidence. Local Phase 4E observations are
trusted verifier records, not transferable transaction proofs. Its policy
configuration and machine cannot be compromised. A capability holder can ask
the configured low-level signer to sign; therefore never expose that capability
as a public issuance endpoint.

Local OS clock, private SQLite state, interpreter, installed code, private
identity files and sidecar capability are trusted. Same-user/root compromise,
database replacement/rollback, hostile parent directories and debugger access
are outside this boundary. Native Windows ACLs must be configured by operators.
POSIX 0600 checks do not establish Windows ACL safety. Managed runtimes provide
only best-effort secret-buffer wiping, not reliable whole-process zeroization.

Revocation is local. A freshness marker means the trusted operator refreshed
its local status, not that the world has published no revocation.
Deleting state or offline operation cannot be marketed as global revocation
awareness. Authorized key revocations stay sticky.

## Privacy and availability

Public stable subject/evaluator/key IDs, network, policy digest, credential
times, threshold and audience permit correlation. Repeated threshold queries
reveal intervals. Four unselected signed predicate bits are hidden; exact
metric and history are absent. No anonymity, private-balance proof or general ZK.

Requests last at most 300s and credentials at most 86400s. Timing has no grace.
SQLite BEGIN IMMEDIATE deliberately serializes bounded crypto verification.
A stopped/overloaded sidecar, stale status, wrong clock, corrupt state or
concurrency timeout fails closed and may deny service. No automatic signing
or verification retry is used to hide uncertain outcomes.
