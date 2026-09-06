# Payment Request v1

Phase 4D introduces an immutable request presented to a payer. Settlement state
belongs to the service's local `InvoiceRecord`; an imported request can never
assert that an invoice is paid. This separation prevents client-controlled JSON
from granting service access. The request factory and original primitives build
on **fallacyofall's PR #1**, adapted after the review in
[phase4d-pr1-review.md](phase4d-pr1-review.md).

## Exact schema

All ten fields are required. `memo` and `reference` may be `null`.

```json
{
  "type": "myt-payment-request",
  "version": 1,
  "invoice_id": "invoice-123",
  "network": "testnet",
  "recipient_address": "REPLACE_WITH_NATIVE_VALIDATED_MYT_SUBADDRESS",
  "amount_atomic": 100000000,
  "created_at": 1788600000,
  "expires_at": 1788603600,
  "memo": "API operation",
  "reference": "order-123"
}
```

The example address is explanatory, not a valid artifact. A deterministic
serialization fixture with a syntactically valid test-only address is in
[payment-request-v1-test-vector.json](payment-request-v1-test-vector.json).

- `invoice_id`: 1-128 ASCII letters, digits, underscore or hyphen. Default UUID4.
- `network`: exactly `mainnet`, `testnet` or `stagenet`; no default/fallback.
- Address syntax: MYT Base58 alphabet, 95 characters on Mainnet or 97 on
  Testnet/Stagenet for standard addresses/subaddresses. Integrated Addresses
  are unsupported. Parsing does not validate the checksum or prove control.
- `amount_atomic`: integer in `[1, 18446744073709551615]`. One MYT is
  1,000,000,000 atomic units. Booleans, floats, exponent notation and zero fail.
- Timestamps: integer Unix seconds, `0..253402300799`.
  `created_at < expires_at`; lifetime at most 30 days. Default lifetime: one hour.
- Memo: at most 1,024 UTF-8 bytes; reference: at most 256. Text must already be
  Unicode NFC and cannot contain control, format/bidi or surrogate characters.
- Input limit: 8,192 bytes. Strict UTF-8, no BOM, duplicate/unknown/missing fields,
  non-finite constants or float-valued JSON. The public constructor validates too.

Serialization sorts keys, uses compact JSON separators, ASCII Unicode escapes
and no trailing newline. There is no implicit Unicode normalization. File output
adds one LF after the canonical JSON. The exact canonical bytes are available
as `request.canonical_content`.

## Validation levels

`payment-request create` and `payment-request show` work offline and return
`address_validated: false`. They validate syntax and schema only.
`payment-request verify --network testnet` uses native Wallet RPC
`validate_address(any_net_type=false, allow_openalias=false)`, checks network,
rejects Integrated Addresses and checks `created_at <= now < expires_at`.
Neither operation proves payment or issuer identity. Persistent invoice creation
also requires native recipient/network validation.

Prefer a dedicated merchant-controlled subaddress per invoice. The application
selects it; Phase 4D does not create wallets or modify Wallet RPC address state.
Standard addresses are accepted after native validation but link billing records
more readily. Same syntactic lengths on Testnet and Stagenet do not substitute
for native network validation.

## Invoice-specific native proof message

```text
canonical = ASCII(compact_sorted_JSON(request.as_dict()))
proof_message = "myt-machine/invoice/v1:" + lowercase_hex(SHA256(canonical))
```

The payer supplies this exact message to the existing Phase 4A `prove-payment`
command for an existing transaction. It is authenticated by the native
`OutProofV2` construction. The hash is a standard SHA-256 content commitment,
not a replacement signature scheme. Changing any request term changes the
required message, preventing reassignment of a disclosed proof to another
invoice. The message is off-chain and does not change transaction format.

An OutProof does **not** identify a sender wallet address. It proves the native
transaction-key relationship for the recipient/transaction/message; Wallet RPC
also computes the received amount. Anyone receiving a proof may forward it.
Service customer authentication must be handled independently.

## Issuer signatures deferred

Requests in v0.4.0 are unsigned and contain no Machine ID or private-key handling.
The issuer must deliver terms over an authenticated application channel.
Optional issuer authorization is deferred to a reviewed artifact extension that
reuses Phase 4B identity signatures over this canonical immutable content under
a dedicated context. It must not sign mutable local state. A future signature
could prove Machine Identity authorization, not legal/physical identity, wallet
ownership, liveness or payment. Phase 4C bindings and fresh Phase 4B challenges
remain available independently without changing this v1 schema.

## CLI

```bash
myt-machine payment-request create --network testnet \
  --address "$RECIPIENT" --amount 0.1 --expires-in 3600 \
  --request-file request.json
myt-machine payment-request show --request-file request.json
myt-machine --rpc-url http://127.0.0.1:38083 --rpc-user verifier \
  --rpc-password-file rpc-password payment-request verify \
  --network testnet --request-file request.json
```

Creation refuses to overwrite a file; new files use Unix mode `0600`. `show`
and `verify` accept `--request-file -` for stdin. All commands return one JSON
document, using the existing CLI envelope and exit-code conventions.
