# Reputation Attestation v1

## Design review before implementation

Phase 4E deliberately separates signed opinions, locally observed settlement
evidence, and caller-configured policy output. This specification is the v1
implementation contract. No universal score, wallet signing, REST signing or new
cryptographic primitive is introduced.

An artifact has exactly six fields: `type`, `version`, `issuer`, `statement`,
`id`, `signature`. `issuer` is an exact Phase 4B public identity document.
`version` is integer 1. All JSON objects reject duplicate/unknown/missing fields.

For `type="myt-reputation-attestation"`, statement has exactly:

| Field | Value |
| --- | --- |
| subject_machine_id | Canonical Phase 4B Machine ID |
| network | mainnet, testnet or stagenet |
| issued_at | Integer Unix seconds, 0 through 253402300799; issuer claim only |
| category | SERVICE_INTERACTION |
| outcome | POSITIVE, NEUTRAL or NEGATIVE |
| evidence_digest | null or 64 lowercase hexadecimal characters |

Issuer equal to subject is rejected, including by offline parsing. Different
Machine IDs do NOT prove independent controllers. No free-text notes, addresses,
invoice IDs, context strings, expiry or private commercial metadata are allowed.

For `type="myt-reputation-revocation"`, statement has exactly `network`,
`attestation_id` (the target content-addressed ID), and `issued_at` with the same
bounds. This authenticates an issuer's revocation, not the time or temporal order
of authorizations. See [revocation and policy](reputation-policy.md).

## Canonical bytes

`body` is the object containing only `type`, `version`, `issuer`, `statement`.
`J(body)` is ASCII JSON: lexicographically sorted keys at every level, compact
separators `,` and `:`, no whitespace/newline, no floats, no NaN/Infinity.

For an attestation:

```
content = ASCII("MYT-REPUTATION-ATTESTATION-V1\n") || J(body)
context = "myt-machine/reputation-attestation/v1"
```

For a revocation:

```
content = ASCII("MYT-REPUTATION-REVOCATION-V1\n") || J(body)
context = "myt-machine/reputation-revocation/v1"
```

For both, `id = "myt-reputation-v1:" + lowercase_hex(SHA256(content))`.
The ID is derived, never chosen by the issuer. It is checked on every parse.
The signature is the existing Phase 4B signature of `content` with `context`:
the final Ed25519 input is Phase 4B's versioned frame, not raw JSON. The signature
is canonical unpadded Base64url for 64 bytes. The canonical artifact digest is
`SHA256(ASCII("MYT-REPUTATION-ARTIFACT-V1\n") || J(artifact))`.

Artifacts are limited to 16384 UTF-8 bytes; files may have one trailing LF.
BOM, invalid UTF-8, bool-as-int, unsupported enums, malformed or non-canonical
identities/signatures/IDs, arbitrary nesting and control characters are rejected.
Permitted string values are closed ASCII formats, not untrusted free text.

## Meaning and replay

A valid signature proves the issuer key controller authorized exactly this
statement. It does not prove the statement true, an actual service interaction,
issuer trustworthiness, legal identity, independence, absence of collusion, or
when authorization happened. Timestamps are signed issuer claims.

IDs and canonical artifact digests are unique in local storage. Reimporting the
same artifact, including whitespace/key-order transport variants, is idempotent.
Same ID with changed content and different ID with unchanged content are rejected.
Network is signed and required at import/query boundaries.

Signatures and digests permit correlation. Disclosure is intentional, not a
privacy-preserving proof. No on-chain registry or Phase 4F construction is added.
