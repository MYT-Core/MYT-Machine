# Programmatic/API billing

Phase 4D provides a billing library and an optional stdlib WSGI reference adapter.
No web framework is a runtime dependency. There is no built-in public server,
wallet-spending endpoint, wallet unlock operation or deployment action.

## Python SDK

```python
from myt_machine import (
    BillingService, RpcConfig, SQLiteInvoiceStore,
    WalletPaymentVerifier, WalletRpcClient,
)

# Read credentials through the service's protected configuration mechanism.
client = WalletRpcClient(RpcConfig(
    url="http://127.0.0.1:38083",
    username=rpc_username,
    password=rpc_password,
))
store = SQLiteInvoiceStore("/private-service-state/invoices.sqlite")
billing = BillingService(
    store, network="testnet",
    verifier=WalletPaymentVerifier(client, network="testnet"),
)
invoice = billing.create_invoice(
    recipient_address, 100_000_000, expires_in=3600,
    idempotency_key="order-123", reference="operation-123",
)
request_for_client = invoice.request.as_dict()
proof_message_for_client = invoice.request.proof_message

# A client submits an existing Phase 4A payment-proof artifact. This call only
# verifies it. Normal automated tests use a fake RPC and never spend real MYT.
result = billing.verify_invoice(invoice.request.invoice_id, submitted_proof)

# First authenticate the customer, associate the invoice with the purchased
# operation, and check the stored price/recipient. Then gate service work:
billing.require_paid(invoice.request.invoice_id)
```

`require_paid` raises `InvoiceNotPaid` until settlement policy has passed. It is
not customer authentication or one-time service consumption. A client-supplied
invoice ID must not by itself authorize arbitrary work. Repeated access to a paid
invoice remains possible; the application must atomically enforce its own
fulfillment/idempotency policy. It must also select the price, recipient and
confirmation threshold. An arbitrary customer's self-created cheap invoice must
not buy a more expensive service.

`get_invoice`, `list_invoices`, `invoice_status` and `require_paid` work with a
`BillingService` without a verifier. Creation and verification require the
trusted read-only verifier. Custom verifier implementations are trusted service
code and must provide the same evidence guarantees, not payer-controlled plugins.

## CLI

Use a private state directory and the existing secure Wallet RPC options:

```bash
mkdir -p invoice-state
chmod 700 invoice-state

myt-machine --rpc-url http://127.0.0.1:38083 --rpc-user verifier \
  --rpc-password-file rpc-password invoice create \
  --db invoice-state/invoices.sqlite --network testnet \
  --address "$RECIPIENT" --amount 0.1 --expires-in 3600 \
  --confirmations 10 --idempotency-key order-123

myt-machine invoice get --db invoice-state/invoices.sqlite \
  --network testnet --invoice-id "$INVOICE_ID"
myt-machine invoice list --db invoice-state/invoices.sqlite \
  --network testnet --limit 50
myt-machine invoice status --db invoice-state/invoices.sqlite \
  --network testnet --invoice-id "$INVOICE_ID"

myt-machine --rpc-url http://127.0.0.1:38083 --rpc-user verifier \
  --rpc-password-file rpc-password invoice verify \
  --db invoice-state/invoices.sqlite --network testnet \
  --invoice-id "$INVOICE_ID" --proof-file proof.json
```

For an existing transaction, the payer can independently use Phase 4A
`prove-payment --txid "$TXID" --address "$RECIPIENT" --message "$PROOF_MESSAGE"`.
This is proof generation, not a new transfer. Phase 4D requires that exact invoice
message; a previously issued generic proof with an empty message is insufficient.
An actual transfer, if desired, must be independently and explicitly authorized
through Phase 4A. No example here initiates a payment.

Offline commands ignore Wallet RPC environment values. Invoice verification uses
exit `0` for PAID, `1` for a valid unpaid result, `2` for malformed input/conflict,
`3` for configuration, `4` for storage/transport/protocol failure and `5` for a
native Wallet RPC application error. Exactly one JSON document goes to stdout.

## Optional REST reference adapter

```python
from myt_machine.billing_http import BillingApplication

application = BillingApplication(billing, token=protected_random_service_token)
```

Mount `application` with a production WSGI server. The token must contain
32-256 ASCII letters/digits/underscore/hyphen; generate it cryptographically and
load it from protected configuration. It is compared in constant time and is
redacted in object representations. No endpoint returns it. There is no CORS
enablement or automatic HTTP access logging in this adapter.

This is a **trusted billing-operator API**, not an unauthenticated customer portal.
Except for minimal `/health`, all endpoints require `Authorization: Bearer TOKEN`.
Protect transport with TLS and restrict operator access; do not embed this token
in browser clients or distribute it to payers. Customer-facing routes need
application authentication, ownership checks and server-selected commercial terms.
Keep Wallet RPC itself on loopback or strongly protected authenticated transport.
Never expose the Wallet RPC interface through a public billing route.

| Method | Path | Behavior |
| --- | --- | --- |
| GET | `/health` | Minimal health response, no private state |
| POST | `/v1/invoices` | Create; optional `Idempotency-Key` header |
| GET | `/v1/invoices` | List; `limit=1..100`, optional `after` |
| GET | `/v1/invoices/{invoice_id}` | Invoice and immutable request |
| GET | `/v1/invoices/{invoice_id}/status` | PENDING / PAID / EXPIRED |
| POST | `/v1/invoices/{invoice_id}/verify` | Read-only proof check and atomic state update |

Creation body requires `recipient_address` and integer `amount_atomic`. Optional:
`expires_in`, `invoice_id`, `memo`, `reference`, `required_confirmations`. Network
comes from service configuration. Do not accept binary floating-point JSON
numbers for atomic amounts; JavaScript clients need a lossless JSON integer
strategy for values beyond Number.MAX_SAFE_INTEGER.

Verification body is exactly `{"proof": PAYMENT_PROOF_ARTIFACT}`. There are no
mark-paid, send, transfer, private-key or wallet-management routes. Responses
contain `schema_version: 1` and `success`, with JSON errors. A negative payment
observation is HTTP 200 with `paid: false`; validation errors are 400, bad auth
401, missing invoices 404, conflicts 409, RPC failures 502, configuration failures
503. Idempotent creation returns HTTP 200 and the same record.

Bodies require Content-Length and JSON UTF-8, at most 73,728 bytes. Chunked input,
duplicate JSON/query fields and unknown fields fail. Lists cap at 100 rows.
Configure header/body read timeouts, TLS, maximum concurrent requests, reverse
proxy rate limits and log redaction in the hosting service. The WSGI adapter
does not itself bind a socket or implement a production HTTP transport.

## Privacy and future adapters

Invoice disclosure links amount, recipient, reference/memo, TXID and service
usage. Use dedicated subaddresses and minimize references. Never place credentials,
keys or secrets in invoice IDs, idempotency keys, memo or reference: those are
intentionally stored and disclosed as billing data, not secret-redacted credential
fields. No payer address is derived or persisted. The ledger is local mutable
service state, not a public
blockchain record. Details and reorg/expiry limitations are in [invoices.md](invoices.md).

MCP is deferred. A future optional adapter should call the same `BillingService`
create/get/list/status/verify methods under the same authorization and size limits.
It must not recreate invoice logic or introduce a spending tool. Phase 4E/4F,
subscriptions, reputation, custody and marketplace functions are outside v0.4.0.
