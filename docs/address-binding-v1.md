# MYT Machine Address Binding Protocol v1

Status: Phase 4C, implemented by `myt-machine-settlement` v0.3.0.

This document defines a minimal, selectively disclosed, off-chain binding
between a Phase 4B Machine Identity and an MYT settlement address. It does not
define an identity registry, discovery service, reputation system, revocation
service, or blockchain identity layer.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are to be
interpreted as normative requirements.

## 1. Security Meaning

> A valid binding proves that the controllers of the Machine Identity key and
> the MYT settlement-address spend key both authorized the same canonical
> binding statement. It does not prove when that authorization occurred,
> current liveness, continued key control, or exclusivity of key control.

Binding v1 contains no timestamp and no trusted time source. Implementations
MUST NOT claim that it proves a particular signing or authorization time.
Current control of the Machine Identity MUST be checked separately with a
fresh Phase 4B challenge-response exchange whose nonce, expected Machine ID,
context, expiry, and used state are managed by the verifier.

Both signature systems authenticate the same canonical binding payload. Their
final cryptographic inputs are different because the existing Phase 4B
signature frame and native MYT SigV2 each apply their own domain separation.
Implementations MUST preserve both existing mechanisms and MUST NOT replace
them with a new cryptographic primitive.

## 2. Artifact Schema

A Binding v1 artifact contains exactly these seven top-level fields:

```json
{
  "address": "MYT address",
  "identity": {
    "algorithm": "ed25519",
    "machine_id": "myt-machine-v1:...",
    "public_key": "canonical Base64url public key",
    "type": "myt-machine-identity",
    "version": 1
  },
  "identity_signature": "canonical Base64url Ed25519 signature",
  "network": "mainnet|testnet|stagenet",
  "type": "myt-machine-address-binding",
  "version": 1,
  "wallet_signature": "SigV2..."
}
```

The embedded `identity` is the complete, unchanged Phase 4B public identity
document. The Machine ID is not duplicated at the top level. The explicit
network prevents cross-network policy ambiguity even though MYT address
prefixes also encode network information.

Readers MUST:

- accept UTF-8 JSON without a BOM and no larger than 8192 bytes;
- reject duplicate, missing, and unknown fields at every object level;
- require the exact type and integer version values shown above;
- validate the embedded Phase 4B identity and independently derive its
  Machine ID again;
- accept only `mainnet`, `testnet`, or `stagenet`;
- accept only canonical ASCII MYT Base58 address text of at most 128 bytes;
- require a canonical 64-byte unpadded Base64url identity signature; and
- require a native `SigV2` value containing exactly 88 MYT Base58 characters
  after its prefix.

Artifact writers use sorted field names, compact JSON separators, ASCII
output, and one trailing LF. The artifact serialization itself is not what the
two signatures cover. Readers MAY accept insignificant JSON whitespace.

Binding output uses exclusive creation and is never overwritten. The Python
implementation stores it with mode `0600` on Unix and rejects symlink input.
The artifact is public cryptographic material, but restrictive storage reduces
accidental disclosure and unwanted linkability.

## 3. Canonical Binding Payload

The signed statement contains exactly five fields:

```json
{
  "address": "MYT address",
  "machine_id": "myt-machine-v1:...",
  "network": "mainnet|testnet|stagenet",
  "type": "myt-machine-address-binding-statement",
  "version": 1
}
```

It is encoded with lexicographically sorted field names, compact separators,
JSON ASCII escaping, and no trailing whitespace or LF. The exact payload given
to both signature APIs is:

```text
ASCII("MYT-MACHINE-ADDRESS-BINDING-V1")
|| 0x0a
|| canonical_statement_json_ascii
```

In pseudocode:

```text
canonical_content =
    b"MYT-MACHINE-ADDRESS-BINDING-V1\n"
    || json_ascii(
         statement,
         sort_keys=true,
         separators=(",", ":")
       )
```

There is no LF after the closing `}`. Neither the artifact signatures nor any
artifact-only formatting are included in the statement, so circular signing
is avoided.

## 4. Identity Authorization

The Machine Identity signs `canonical_content` through the existing Phase 4B
implementation with the required context:

```text
myt-machine/address-binding/v1
```

The final Ed25519 input is therefore the Phase 4B signature frame documented
in [`identity-v1.md`](identity-v1.md), containing the Machine ID digest,
context, and exact canonical content. No Phase 4B framing, identifier, or
signature behavior changes in Phase 4C.

## 5. Wallet Authorization

The selected MYT wallet address signs the exact same `canonical_content` ASCII
string through the native wallet RPC `sign` method with:

```json
{
  "account_index": 0,
  "address_index": 1,
  "signature_type": "spend"
}
```

The indexes above are illustrative. The CLI uses the configured global
`--account-index` and `--address-index` values. The native implementation
returns a `SigV2` spend signature and applies its existing MYT domain
separation, public-key binding, and randomized signature generation.

`binding create` requires an unrestricted, open, spend-key-capable Wallet RPC.
Operators SHOULD expose that RPC only on loopback or through strongly protected
authenticated and encrypted transport. An unrestricted spend-key-capable RPC
MUST NEVER be exposed without protection to an untrusted network.

The wallet `sign` request is a sensitive mutation and is submitted exactly
once. It is never retried automatically. A timeout or malformed response after
submission reports `outcome_unknown: true`; the caller MUST NOT blindly repeat
the operation. The implementation verifies the returned signature as native
SigV2 spend before writing the artifact.

## 6. Address Policy

Subaddresses are the privacy default. `binding create` selects the configured
account and address index. The primary standard address at account `0`, address
`0` is refused unless the caller explicitly supplies:

```text
--allow-standard-address
```

All non-primary selected addresses must be reported by Wallet RPC as
subaddresses. Integrated Addresses are unsupported in Binding v1 and are
rejected during both creation and verification. A binding SHOULD use a
dedicated subaddress and SHOULD NOT reuse one binding across unrelated
counterparties or services.

## 7. Verification

`binding show` performs strict artifact parsing and embedded identity
validation without Wallet RPC, a daemon, a blockchain, or a network.

`binding verify` performs these steps:

1. Strictly parse the artifact and embedded identity.
2. Reconstruct the canonical payload.
3. Verify the Phase 4B identity signature.
4. Ask Wallet RPC to parse the address for any MYT network.
5. Reject Integrated Addresses and require the parsed network to match the
   artifact.
6. Require the verifier wallet to be opened on that network.
7. Call native wallet RPC `verify` for the SigV2 signature and require version
   `2`, `old=false`, and signature type `spend`.
8. Apply independently expected Machine ID and network policy when supplied.

The verifier wallet does not need the bound address's private keys. A fresh or
watch-only wallet on the same MYT network can perform native verification.
Wallet RPC `verify` needs no daemon or blockchain access. This property is
covered by unit tests and was confirmed against two independent, disposable,
offline MYT Testnet wallets.

Verification reports:

```text
artifact_valid
address_valid
address_supported
address_type
network_valid
identity_signature_valid
wallet_signature_valid
wallet_signature_version
wallet_signature_type
wallet_signature_old
identity_matches
network_matches
binding_valid
authentication_valid
valid
```

`binding_valid` requires a supported address, matching address network, a
valid identity signature, and a native SigV2 spend signature. Without an
expected Machine ID, `identity_matches` and `authentication_valid` are `null`.
With an expected Machine ID, `authentication_valid` requires `binding_valid`,
an identity match, and an expected-network match when one was supplied.
`valid` requires `binding_valid` plus every supplied expectation.

A well-formed but incorrect signature, identity expectation, or network
expectation is a negative result with `success: true`, `valid: false`, and exit
code `1`. Malformed artifacts use exit code `2`; unsafe configuration uses
`3`; RPC transport, authentication, and protocol errors use `4`; native Wallet
RPC application errors use `5`.

## 8. Privacy And Disclosure

A binding intentionally creates linkability between one Machine ID and one MYT
address for every party that receives it. No binding is published
automatically, written to the MYT blockchain, or registered globally. The
controller decides when and to whom it is disclosed.

Binding v1 deliberately omits:

- timestamp or trusted time;
- expiry;
- nonce;
- purpose, scope, label, or free-form metadata;
- wallet balance or transaction history;
- payment ID; and
- revocation, rotation, or successor data.

These omissions keep the artifact minimal and reduce correlation surfaces.
They also mean a disclosed binding can be replayed indefinitely as a valid
authorization statement unless an application applies its own policy.

## 9. Threat Model And Limits

Phase 4C addresses substitution and cross-network confusion only when the
verifier validates both signatures and uses independently expected identity
and network values where authentication policy requires them.

- A stolen or copied identity key can authorize new identity-side statements.
- A stolen or copied wallet spend key can authorize new wallet-side statements.
- An attacker needs both authorizations over the same canonical content to
  create a new valid binding.
- A stolen binding artifact is public and remains cryptographically valid. It
  conveys no private key, but disclosure creates linkability.
- A false identity document changes the Machine ID or public key and invalidates
  the embedded identity signature unless the attacker controls the substituted
  identity key. An independently pinned Machine ID prevents document
  substitution from becoming authentication.
- Address, network, Machine ID, type, or version modification invalidates one or
  both signatures.
- A malicious Wallet RPC can lie about parsing or verification results. Use a
  trusted local implementation and verify software provenance.
- A malicious verifier can retain and redistribute a disclosed binding.
- Address reuse increases long-term linkability.
- Binding v1 does not prove current liveness, possession at verification time,
  uniqueness, exclusivity, legal identity, reputation, transaction history,
  balance, or authorization for a particular payment.
- There is no revocation, expiry, address rotation, key rotation, compromise
  recovery, registry, or discovery protocol in v1.

If either key is compromised or intentionally replaced, applications must stop
trusting the old binding through an external policy. Future versions may define
signed successor or revocation artifacts, but they require a separate threat
model.

## 10. Test Vector

The complete machine-readable fixture is
[`address-binding-v1-test-vector.json`](address-binding-v1-test-vector.json).
It publishes:

- the test-only RFC 8032 identity seed and public identity;
- the exact statement;
- the binding domain as ASCII and hex;
- the complete canonical content as ASCII and hex;
- the deterministic Phase 4B identity signature;
- a disposable MYT Testnet subaddress;
- a real native SigV2 spend signature; and
- the complete canonical artifact.

Never fund or reuse the published test identity or address. Native MYT SigV2
signing uses fresh randomness, so the fixed wallet signature is a verification
fixture, not an expected deterministic generation result. It was produced by
a disposable spend-key wallet and verified through a separate fresh offline
Testnet wallet.

The canonical content begins exactly with:

```text
MYT-MACHINE-ADDRESS-BINDING-V1\n
{"address":"TG98MfZho35G9uYHUwhd8cH49cNhU7AnC4KvCbHQwCag7ngJyYYLqwJZKoTQbH6z3hE4zEbN4vnpHJ4bybUmnpRz2TqmBwKEd","machine_id":"myt-machine-v1:ghejgw76kap2alahrz3yjxqp2exn2bq4hexrjnj4ly56inqyonfa","network":"testnet","type":"myt-machine-address-binding-statement","version":1}
```

The first displayed `\n` denotes the single byte `0x0a`; it is not two ASCII
characters. The JSON file contains the complete byte sequence in
`canonical_content_hex` for unambiguous interoperability testing.

## 11. Deployment Boundary

Phase 4C changes only the `myt-machine-settlement` Python SDK, CLI, tests, and
documentation. It does not change MYT Core, consensus, emission, HF17, block or
transaction formats, privacy mechanisms, daemon behavior, blockchain state, or
Wallet RPC schemas.
