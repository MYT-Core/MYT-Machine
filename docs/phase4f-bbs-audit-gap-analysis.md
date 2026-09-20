# Exact-composition audit gap

CRYPTO BACKEND EXTERNALLY QUALIFIED = NO.
EXTERNAL CRYPTO REVIEW REQUIRED = YES.

The historical research considered Bulletproofs+ and then selected evaluator
credentials, not hidden-value arithmetic proofs. Preserve that distinction.

The Digital Bazaar 3.1.0 + Noble 2.4.0 + MYT composition does not have sufficient
independent qualification for production release. Earlier Noble audits of older
versions do not establish audit coverage of these exact versions or the MYT
application protocol. Passing signatures, vectors, adversarial tests, package
audits and Linux/Windows matrices are engineering evidence only.

BBS code references draft-irtf-cfrg-bbs-signatures-06. A reviewer must compare
the implemented protocol/version, point decoding, subgroup checks, native
proof challenge, random scalar generation, domain calculation, canonical
message positions, and the application's trust/subject/replay composition.
Do not infer standards compliance or security from the library name.

This profile requires no MYT trusted-setup ceremony or custom generators;
it uses the backend's specified generator derivation. That is not a proof
that all generator/domain assumptions have been independently reviewed.

Supply-chain assertions are narrower than an audit: exact version and registry
integrity pins, matching published source references, no install hooks or
native binaries in inspected dependency archives, and current advisory checks.
Registry hashes do not protect against a malicious correctly hashed upstream
release. Runtime package-version negotiation is not remote attestation.

No main integration, tag, release, PyPI publication, deployment or internal
cryptographic self-approval is authorized by a successful engineering run.
