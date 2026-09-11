# Exact dependency record

Recorded on 2026-09-10 on native Windows.

## Runtime

- Node.js: 22.19.0
- npm: 10.9.3
- operating system: Windows (native, not WSL)

The effective Node.js floor is 20.19.0 because the locked Noble 2.4.0 packages
declare that minimum, even though Digital Bazaar's package itself declares
Node.js 18 or newer.

## Locked packages

| Package | Exact version | Integrity |
|---|---:|---|
| `@digitalbazaar/bbs-signatures` | 3.1.0 | `sha512-wx86l/PFOaRcoLBPmzwpF9Oo4uYJrm4uq/B1rHX5OHD15NakmUINfRr8NAGDG356GeTBDGZkMsBFgNj1x0dc+g==` |
| `@noble/curves` | 2.4.0 | `sha512-P4/62zrgfH33CneE3Dn4WhJVA22YUU0eR51wKIan4NVRvwsA0YnPTwWGpNbpuacSujmSFLvyzpyuR30+fbq2Ew==` |
| `@noble/hashes` | 2.4.0 | `sha512-X5XaVWZIBCT7HHZGm5I7ZQXDwLG+bGXuSrMQAW+7Zvl87h1kmc1ZB1VSRJcpUfoUrGQp4Fkoxm5kZ+Ms+aW+eA==` |

`package-lock.json` lockfile version 3 is authoritative. Use `npm ci`, not an
unlocked install, to reproduce these transitive versions. Installation reported
zero known npm audit vulnerabilities at test time; that is a registry finding,
not a cryptographic audit or security approval.

No ZKryptium package is installed. Node's built-in `node:crypto` supplies
Ed25519 and SHA-256 for the Phase 4B-compatible layers.
