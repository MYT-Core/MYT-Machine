# Phase 4F runtime decision

Public review candidate v0.6.0-rc1, not production approval.
External cryptographic review: PENDING. Backend externally qualified: NO.
Baseline: 73beb99102f56671d6b2d85c9368bfa788249dc2.

## Decision before implementation

Choose a separately packaged, explicitly optional, persistent authenticated
Node loopback crypto service. Python retains all application policy,
Phase 4E reads, Phase 4B keys/signatures, and durable verifier state.
Only the new disclosure API requires the companion. Existing 4A-4E commands
do not discover, start, install, contact or depend on Node.

| Option | Assessment |
| --- | --- |
| A: per-operation Python subprocess | Reject: executable/environment injection, repeated startup and secret IPC; no need to inherit the experimental bridge. |
| B: persistent authenticated local Node sidecar | Choose for the narrow BBS boundary. Fixed API, explicit launch, protected bearer capability, no subprocess spawning. Separate crash domain and version handshake. |
| C: separate JS companion CLI only / artifact handoff | Explicit packaging is desirable and retained; offline multi-step handoff alone complicates trustworthy issuance and consume-after-verification. The companion therefore serves the narrow BBS API. |
| D: native binding | No independently qualified maintained Python binding to this pinned JS implementation was established. Embedding another runtime expands packaging/ABI review. |
| E: different backend | Earlier research does not establish equivalent audited, supported cross-platform evidence. Do not replace primitives to avoid the runtime decision. |

## Trust and secret boundaries

Node binds only 127.0.0.1. Requests require a protected random 256-bit bearer
capability file, exact protocol version, exact JSON schema and bounded I/O.
No wildcard address, proxy, redirect, remote endpoint, CORS, browser origin,
arbitrary method, file path from requests or executable selection is supported.
A capability holder has authority to use the configured signing key; it is
sensitive local administrator material, never public holder/verifier input.

A dedicated verifier sidecar can run without an issuer secret key. An evaluator
sidecar loads only its explicitly configured encrypted BBS key and passphrase
file at startup. These secrets never cross HTTP. Python never receives BBS
private bytes. Phase 4B private keys never enter Node. No passphrases/tokens in
argv or environment. Private files and containing directories must be protected.

Python sends native BBS messages/signatures/proofs over authenticated loopback.
A malicious same-user/root process can read the capability or alter either
process; that is outside this local trust boundary, as with existing private
SQLite files. HTTP loopback is not protection against a compromised host.
Do not expose or tunnel this service to an untrusted network.

The Python issuance entry point accepts a real ReputationStore/Policy, not
an alleged validated snapshot or caller-provided result. The low-level signer
is a protected crypto service, not a public reputation issuer API.
Python performs BBS verification through the trusted companion before consuming
a request in its own SQLite transaction. There is no caller-supplied
"proof_valid" shortcut. Interrupted/backend-failed verification rolls back.

## Reproducibility and compatibility

Pin Digital Bazaar 3.1.0, Noble curves 2.4.0, Noble hashes 2.4.0 and registry
integrities. Separately package companion sources/lockfile, never node_modules
inside the Python wheel. No install hooks, runtime downloads or auto-updates.
Negotiate one exact API/profile and exact cryptographic dependency versions.

Use Node 24 LTS, floor 24.20.0, with current compatible 24.21.0 tested separately.
Do not reuse research-only Node 24.14.0: intervening security releases exist.
References:
- https://nodejs.org/en/blog/vulnerability/july-2026-security-releases
- https://nodejs.org/en/blog/release/v24.20.0
- https://nodejs.org/en/blog/release/v24.21.0

Node's private-key encryption uses OS crypto and memory-hard scrypt/AES-GCM.
Phase 4B PKCS8 storage is not a BLS scalar format; do not disguise BBS keys as
Ed25519 keys or export them through the identity SDK. Separate bounded encrypted
BBS envelopes are therefore necessary. Same passphrase and file-security rules,
explicit Windows NTFS ACL limitation, best-effort buffer wiping only.

This is an engineering architecture decision, not independent evidence that
the backend or MYT BBS/Ed25519 composition is cryptographically qualified.
