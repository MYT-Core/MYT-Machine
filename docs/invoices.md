# Durable invoices and read-only settlement verification

`PaymentRequest` is immutable payer-facing content. `InvoiceRecord` is trusted
local service state. `SQLiteInvoiceStore` persists records;
`BillingService` coordinates creation, verification and service gating.

## Lifecycle and time

Legal transitions are `PENDING -> PAID` and `PENDING -> EXPIRED` only. PAID and
EXPIRED are terminal in v1. `now == expires_at` means expired. PAID is never
silently downgraded or expired. There is no late-payment or partial-payment
accounting. Payment must be verified at the required confirmation threshold
**before** expiry; a transaction sent/mined before expiry but only checked after
expiry does not pay this invoice automatically. Resolve late transfers manually.

Queries, lists, explicit `expire()` and finalization persist expiry. No background
scheduler is required. The clock is local service Unix time, not a trusted
blockchain timestamp. A rollback before creation prevents finalization, and a
persisted EXPIRED state remains terminal even if the clock moves backwards.
Keep the service clock synchronized. `paid_at` records the local decision time,
not a cryptographically proven transaction time.

## What verification establishes

The actual MYT sources were inspected: `wallet_rpc_server::on_check_tx_proof`
and both `wallet2::check_tx_proof` overloads. They retrieve the requested
transaction from the daemon, compare the transaction hash, verify the native
proof against recipient and message, compute received outputs, and obtain pool
status and confirmation depth from the daemon.

Phase 4A `payment_status` is wallet-local. It does not establish an exact
recipient address, and a fresh verifier wallet may not know the transaction.
Phase 4D therefore never grants PAID from payment_status or a claimed TXID alone.

The official `WalletPaymentVerifier` calls only `validate_address` and
`check_tx_proof` using the existing Phase 4A proof wrapper. It requires:

1. Exact payment-proof schema, native `OutProofV2` form and normalized TXID.
2. Proof address equals the stored request recipient.
3. Proof message equals the request's canonical content commitment.
4. Configured service network, request network and opened wallet network agree.
5. Native proof verification succeeds for this recipient and transaction.
6. Received amount **exactly equals** the requested positive atomic amount.
7. Transaction is outside the mempool and reaches the stored threshold.
8. Invoice is still PENDING, before expiry, when the SQLite write lock is held.
9. `(network, txid)` has not been consumed by another local invoice.

Default threshold: **10 confirmations**, matching MYT's default transaction
spendable-age setting. Operators can require more or explicitly choose a positive
lower value; zero, booleans and floats are rejected. This is an application
acceptance policy, not a consensus change or a guarantee against a deep reorg.
Implausible confirmation counts outside uint32 are rejected, including unsigned
subtraction-underflow responses. Custom transaction unlock times and immediate
wallet spendability are not established by this API.

The proof does not prove a payer/sender wallet address, customer identity, legal
identity, a trustworthy wall-clock time, or current key control. Chain membership,
depth and network truth depend on a correctly configured, synchronized and
trusted wallet/daemon. Native proof cryptography does not make this a trustless
billing service. A locally connected independent/watch-only verifier wallet can
check a proof without the bound recipient's private spend key; its daemon still
needs the transaction. No outgoing payment occurs during verification.

Failed/nonexistent/disappearing transactions cannot yield finalized proof evidence.
Native Wallet RPC may report them as an application error rather than `good=false`.
RPC errors, timeouts, bad data and insufficient confirmations leave the invoice
unpaid; no automatic RPC retry is performed. Pre-threshold evidence is not
persisted or trusted on a later attempt. It must be verified afresh. After PAID,
v1 does not monitor/revoke access after a deep reorg; applications needing that
must separately reconcile finalized records and service delivery.

V1 does not enforce the transaction's mining time relative to request creation.
A previously unallocated transaction may be assigned using a fresh request-bound
proof if it satisfies policy. Use dedicated invoice addresses and a complete
shared consumption ledger to avoid reusing previously accepted historical funds.

## Persistence, concurrency and idempotency

SQLite uses explicit `BEGIN IMMEDIATE` transactions, FULL synchronization, an
exact version/application identifier and one connection per operation. Durable
constraints include invoice-ID uniqueness, idempotency-key uniqueness and
`UNIQUE(network, txid)`. Two simultaneous verifications cannot consume one TXID
for two invoices. One transaction cannot pay multiple invoices in the same
database/network, even if it contains multiple outputs. Existing PAID records
are returned idempotently without consuming another transaction.

Invoice creation idempotency hashes all client-controlled terms, including
network, address, amount, expiry duration, explicit invoice ID, memo, reference
and confirmation threshold. Automatically generated IDs/current time are excluded.
Same key and same terms returns the original record, including its current state.
Same key and different terms is a conflict. Retries still require a functioning
recipient-validation RPC. Idempotency is local to this durable database.

Amounts are decimal TEXT in SQLite to preserve the full unsigned 64-bit range;
the public API/artifact uses exact integers. Reads validate canonical request
content and payment-record invariants and fail closed on malformed stored data.
The database is trusted local state, not cryptographically tamper-evident. Anyone
who controls the database/application can forge service state; protect both.

The database contains request terms, state, confirmation policy, finalized TXID,
received amount, observed confirmations, local paid_at, idempotency key and its
creation-parameter digest. No full proof, IP, seed, key, RPC credential or payer
wallet address is stored. Backups and SQLite journals contain the same sensitive
billing data. Unix files require `0600`, regular files and a directory not writable
by other users. On Windows, restrict NTFS ACLs to the service identity; encryption
at rest is an operator concern. Keep a private, controlled parent directory.

Capacity is 100,000 invoices by default (configurable up to 1,000,000). Lists use
keyset pagination, at most 100 records, with an exclusive `after` invoice ID.
There is no public deletion/reset endpoint: removing PAID records or replacing
the database destroys duplicate-payment protection. Multiple services must share
one ledger or implement a coordinated external ledger; distinct DB files cannot
enforce global uniqueness. Retain accepted TXIDs when archiving.
