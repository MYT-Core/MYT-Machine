# Optional MYT BBS companion (v0.6.0-rc2 development build)

External cryptographic review: PENDING. Backend externally qualified: NO.
Public testing/review only. Not production-approved; do not deploy publicly.

Python remains the MYT Machine application. Existing 4A-4E operations require no
Node runtime. Only Phase 4F uses this explicitly installed, independently started
loopback service. No automatic subprocess spawning, npm installation, runtime
download, wallet RPC, daemon or blockchain access occurs.

Use patched Node 24 LTS >=24.20.0 <25. Install the exact shrinkwrap:
npm ci --ignore-scripts --no-fund. Do not use NODE_OPTIONS or NODE_PATH.
Launch from a protected account/environment. The runtime checks installed
crypto package versions, not just hardcoded version labels.

Create an owned private directory (0700 on Unix). Put a 16-1024 UTF-8 byte
passphrase on one line in a 0600 regular, single-link file. On Windows explicitly
restrict the directory and files to the service user with NTFS ACLs; POSIX mode
bits are not an ACL guarantee.

Provision a separate TLS key and certificate for each companion. For example,
generate a self-signed certificate with an IP SAN for 127.0.0.1 in the private
directory.

    umask 077
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc -days 365 -sha256 -subj "/CN=MYT BBS Companion" -addext "subjectAltName=IP:127.0.0.1" -keyout /protected/companion-tls-key.pem -out /protected/companion-tls-cert.pem
    node src/cli.mjs token-create --token-file /protected/capability
    node src/cli.mjs key-create --key-file /protected/bbs-key.json --passphrase-file /protected/passphrase
    node src/cli.mjs serve --port 39190 --token-file /protected/capability --tls-cert-file /protected/companion-tls-cert.pem --tls-key-file /protected/companion-tls-key.pem --key-file /protected/bbs-key.json --passphrase-file /protected/passphrase

Pass the certificate through a trusted channel to the Python client and keep
its local copy in a protected directory with owner-only write access. Use mode
0600 on Unix. For authorize, issue, present and verify supply the following
connection options together with the command's existing options.

    --bbs-url https://127.0.0.1:39190 --bbs-token-file /protected/capability --bbs-tls-cert-file /protected/companion-tls-cert.pem

For SDK clients pass the same PEM with BbsBackend(tls_cert_file=...).
Coordinate certificate replacement with service and client changes. Use separate
ports, certificates and capabilities for the signer and verification-only
service. A verification-only companion takes the TLS key and certificate and
omits the BBS key and passphrase options. The bearer capability on a signing
service grants cryptographic signing authority. When upgrading from RC1, stop
the old listeners and generate a fresh capability for each service. Distribute
the new capabilities only to their respective clients. If unauthorized use of
an RC1 signing capability is suspected, revoke the affected BBS issuer key and
reissue credentials under a new authorized key. Bind to loopback on a dedicated
or isolated host when untrusted local users share the system. Connection and
handshake limits bound resource use per connection.

Key files use the existing Node scrypt and AES-256-GCM implementations:
N=131072,r=8,p=1; random 16-byte salt and 12-byte nonce; authenticated metadata.
No custom encryption primitive is implemented. Strict canonical UTF-8 JSON
with exactly one trailing LF, exact schema, key-ID/public-secret match,
no overwrite, and non-symlink/single-link private files are required.
Wrong passphrase and corrupt-key failures have the same redacted output.
Best-effort buffer wiping is not a secure-memory guarantee in a managed runtime.

The header transport is canonical unpadded Base64url ONLY. The service decodes
using the existing strict decoder and requires exact equality with the bytes
computed from the complete canonical request. Those bytes, including the
domain-separation LF, go unchanged to native BBS presentationHeader.
The credential header is unchanged. No normalization or caller-chosen domain.

Packaging is explicit: npm pack --ignore-scripts. The archive contains only
the companion sources, this README, LICENSE and npm-shrinkwrap.json. It does not
bundle Node, node_modules, test fixtures or private data. The Python wheel does
not contain this companion.

Design and adversarial-review credit: community contributor fallacyofall.
The official profile is not wire-compatible with the unreleased experiments.
Backend: Digital Bazaar BBS 3.1.0; Noble curves/hashes 2.4.0 (exact locks).
The companion requires nonzero canonical scalars in standard BBS signature and
proof encodings. The mapping from messages to generators in the pinned
dependency remains in scope for external review.
External review of this exact composition remains mandatory.
