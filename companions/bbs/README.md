# Optional MYT BBS companion (unreleased candidate)

This is NOT independently cryptographically qualified. Do not deploy or release.

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

    node src/cli.mjs token-create --token-file /protected/capability
    node src/cli.mjs key-create --key-file /protected/bbs-key.json --passphrase-file /protected/passphrase
    node src/cli.mjs serve --port 39190 --token-file /protected/capability --key-file /protected/bbs-key.json --passphrase-file /protected/passphrase

A verifier can omit both key/passphrase options. Never expose this service,
forward its port, or give its capability to untrusted parties. Capability
possession grants cryptographic signing authority for the configured issuer.
The service is NOT a public issuance policy API. The official Python issuer
computes predicates from the real Phase 4E store before signing.

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
External review of this exact composition remains mandatory.
