# MYT Machine Identity Protocol v1

Status: Phase 4B, implemented by `myt-machine-settlement` v0.2.0.

This document defines a small offline identity and signature protocol for
machines and agents. It does not define wallet ownership, payments, reputation,
discovery, revocation, or blockchain state.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are to be
interpreted as normative requirements.

## 1. Cryptographic Profile

- Signature algorithm: Ed25519 as defined by RFC 8032.
- Machine ID hash: SHA-256.
- Public-key encoding: raw 32-byte Ed25519 public key.
- Signature encoding: raw 64-byte Ed25519 signature.
- Private-key container: encrypted PKCS8 PEM.
- Binary transport: unpadded RFC 4648 Base64url.
- Machine ID transport: lowercase, unpadded RFC 4648 Base32.

Implementations MUST use a maintained cryptographic library. They MUST NOT
implement Ed25519, SHA-256, PKCS8 encryption, or random-number generation from
scratch.

The Python implementation requires `cryptography>=50.0.0` without an upper
bound. Versions below 50 are unsupported. Version 50.0.0 is the first release
patched for
[GHSA-g6cj-pr64-35w5](https://github.com/pyca/cryptography/security/advisories/GHSA-g6cj-pr64-35w5)
and includes the fixes for
[GHSA-jwv3-5hgf-82ww](https://github.com/pyca/cryptography/security/advisories/GHSA-jwv3-5hgf-82ww)
and
[GHSA-m2h6-j472-rp4c](https://github.com/pyca/cryptography/security/advisories/GHSA-m2h6-j472-rp4c).
The APIs used here are covered by pyca's documented API stability policy. Users
building `cryptography` from source remain responsible for linking against a
patched, supported OpenSSL version.

## 2. Canonical Encodings

Base64url values MUST:

- use only `A-Z`, `a-z`, `0-9`, `_`, and `-`;
- omit `=` padding;
- contain no whitespace;
- decode to the exact required byte length; and
- reproduce the exact input when decoded and re-encoded.

A public key therefore contains 43 Base64url characters and a signature
contains 86. A 32-byte challenge contains 43.

Machine ID Base32 MUST use lowercase `a-z` and `2-7`, omit padding, and pass the
same decode-then-re-encode canonicality check.

## 3. Machine ID

Given `public_key`, the raw 32-byte Ed25519 public key:

```text
machine_id_digest = SHA-256(
    ASCII("MYT-MACHINE-ID")
    || 0x00
    || ASCII("v1")
    || 0x00
    || ASCII("ed25519")
    || 0x00
    || public_key
)
```

The textual Machine ID is:

```text
"myt-machine-v1:" || lowercase_unpadded_base32(machine_id_digest)
```

Its exact syntax is:

```text
^myt-machine-v1:[a-z2-7]{52}$
```

The full 32-byte digest is retained. There is no truncation.

## 4. Public Identity Document

The public identity document contains exactly five fields:

```json
{
  "algorithm": "ed25519",
  "machine_id": "myt-machine-v1:...",
  "public_key": "43-character Base64url value",
  "type": "myt-machine-identity",
  "version": 1
}
```

Readers MUST:

- accept UTF-8 JSON without a BOM and no larger than 4096 bytes;
- reject duplicate, missing, and unknown fields;
- require exactly the type, integer version, and algorithm shown above;
- decode a canonical 32-byte public key;
- validate the canonical Machine ID; and
- derive the Machine ID again from the public key and require equality.

Writers MUST use sorted field names, compact JSON separators, ASCII output, and
one trailing LF. Readers MAY accept insignificant JSON whitespace. The JSON
serialization itself is not signed and contains no user metadata.

## 5. Signature Frame

A signature never covers an unframed application message. The exact bytes are:

```text
ASCII("MYT-MACHINE-SIGNATURE")
|| 0x00
|| 0x01
|| machine_id_digest[32]
|| uint16_be(context_length)
|| context_ascii[context_length]
|| uint64_be(message_length)
|| message[message_length]
```

`0x01` is the signature framing version.

The context is REQUIRED. It MUST contain 1 to 128 ASCII bytes and match:

```text
^[a-z0-9._:/-]+$
```

Applications SHOULD use a stable, application-specific context such as:

```text
myt-machine/message
myt-machine/auth/v1/service.example
```

Messages MUST contain 1 to 65,536 bytes. CLI `--message` text is encoded as
UTF-8 without normalization. `--message-file` and stdin preserve exact bytes.

The signature result contains only:

- algorithm;
- Machine ID;
- context;
- signature framing version; and
- canonical Base64url signature.

It intentionally omits both the message and `message_digest`. This avoids an
additional stable content fingerprint. Ed25519 signatures are deterministic,
so a signature can still correlate repeated content or permit guessing of
low-entropy messages. Applications SHOULD avoid treating signatures as private
or unlinkable artifacts.

## 6. Verification And Authentication

There are two distinct results:

1. Signature validity means the signature verifies against the public key and
   Machine ID contained in the supplied identity document.
2. Authentication means signature validity plus equality with a Machine ID
   independently expected by the verifier.

A document supplied by the signer is not an independent trust anchor.
Authentication and continuity use cases MUST pin or obtain the expected Machine
ID through a separate trusted channel.

Generic verification without an expected ID returns:

```json
{
  "signature_valid": true,
  "identity_matches": null,
  "authentication_valid": null,
  "valid": true
}
```

Verification with an expected ID returns:

```text
identity_matches = supplied_document.machine_id == expected_machine_id
authentication_valid = signature_valid AND identity_matches
valid = authentication_valid
```

A well-formed but incorrect signature or expected-ID mismatch is a negative
verification result, not a parsing error. Malformed or non-canonical input is an
error and MUST NOT be passed to Ed25519 verification.

## 7. Challenge-Response

A challenge nonce is exactly 32 random bytes generated by the verifier with a
cryptographically secure random-number generator. Base64url is transport only.
The signer decodes the transport value and signs the original 32 nonce bytes in
the signature frame.

A verifier SHOULD:

1. Generate a fresh 32-byte nonce.
2. Store the nonce, independently expected Machine ID, context, expiry, and
   `used=false` state.
3. Send only the canonical Base64url nonce and required context to the signer.
4. Verify the signature against the stored raw nonce and expected Machine ID.
5. Atomically change `used=false` to `used=true` only for an accepted response.
6. Reject expired, unknown, or previously used challenges.

Cryptographic verification alone does not prevent replay. A signature over an
old nonce remains cryptographically valid.

## 8. Private-Key Storage

Private keys MUST be encrypted PKCS8 PEM files. The Python implementation uses
`BestAvailableEncryption` from `cryptography`. Unencrypted, raw, malformed, and
non-Ed25519 private keys are rejected.

Passphrases:

- contain 16 to 1024 valid UTF-8 bytes;
- contain no NUL, CR, or LF after one terminal LF or CRLF is removed from a
  passphrase file;
- are accepted only from a protected file or interactive TTY prompt; and
- MUST NOT be accepted as a command-line value or environment variable.

On Unix, private-key and passphrase files MUST be regular non-symlink files with
mode `0600`. Reads use descriptor-based no-follow checks where supported.
Writes use exclusive creation and never overwrite. On Windows, encrypted PKCS8
and exclusive creation still apply; operators SHOULD restrict the file's NTFS
ACL to the service account.

Copying an encrypted private-key file and its passphrase copies the identity.
A passphrase protects data at rest but does not defend a process or account that
can read both files.

## 9. Deterministic Test Vector

This vector uses public test material derived from RFC 8032. Never use the seed
for a real identity. The machine-readable copy is
[`identity-v1-test-vector.json`](identity-v1-test-vector.json).

```text
seed_hex =
9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60

public_key_hex =
d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a

public_key_base64url =
11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo

machine_id_digest_hex =
31c8935bfe501fa02c078e7784de0fd12edd061c392f14b53c5e3be43618734a

machine_id =
myt-machine-v1:ghejgw76kap2alahrz3yjxqp2exn2bq4hexrjnj4ly56inqyonfa

message =
MYT Phase 4B deterministic vector

message_context =
myt-machine/test-vector/v1

message_frame_hex =
4d59542d4d414348494e452d5349474e4154555245000131c8935bfe501fa02c078e7784de0fd12edd061c392f14b53c5e3be43618734a001a6d79742d6d616368696e652f746573742d766563746f722f763100000000000000214d59542050686173652034422064657465726d696e697374696320766563746f72

message_signature_base64url =
-utjLP8D6SCMA3CvD2QJcw2I2vQXFGjrdOJt_rEWpBuRFY8-Hd4PyaMagV4IDHM3gn0Fn-PdBCH6YCqROzeMDA

nonce_hex =
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

nonce_base64url =
AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8

nonce_context =
myt-machine/auth/v1/test.example

nonce_frame_hex =
4d59542d4d414348494e452d5349474e4154555245000131c8935bfe501fa02c078e7784de0fd12edd061c392f14b53c5e3be43618734a00206d79742d6d616368696e652f617574682f76312f746573742e6578616d706c650000000000000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

nonce_signature_base64url =
zuJ0gMWNfXhR-460sl-OLGdZYW6dbIShA78X5XpwgvPTh7xpvU1eS4lFwGaHRztzl1Q0JRHHwsKsSb2d7hyJCg
```

Encrypted PEM output is intentionally absent because secure PKCS8 encryption
uses fresh random salt and encryption parameters.

## 10. Security Limits

Phase 4B does not provide:

- identity discovery or certification;
- key revocation or compromise recovery;
- replay storage or challenge lifecycle management;
- process isolation or protection after account compromise;
- guaranteed in-memory zeroization of Python key or passphrase objects;
- hardware-backed or non-exportable identity keys;
- anonymity, unlinkability, or message confidentiality;
- wallet-address ownership or payment authorization;
- reputation, marketplace, or consensus behavior; or
- key or algorithm rotation.

## 11. Future Identity Continuity

A new key produces a new Machine ID. Phase 4B has no mechanism for preserving
continuity or reputation across that change.

A later protocol may define a signed successor artifact that binds the old and
new identities, is signed by the old key, and may be countersigned by the new
key. Lost keys, compromised keys, revocation, recovery, algorithm migration,
and trust-policy changes require a separate threat model. Existing v1 Machine
IDs remain immutable identifiers for their original Ed25519 public keys.
