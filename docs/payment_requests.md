# Phase 4D payment requests

`myt_machine.payment_requests` provides the first non-custodial Phase 4D primitive: a serializable MYT payment request / invoice.

A request contains a unique invoice ID, recipient MYT address, exact amount in atomic units, optional memo/reference text, creation and expiry timestamps, and one of three states: `PENDING`, `PAID`, or `EXPIRED`.

Amounts are always integers in atomic units. Floating-point amounts are rejected.

```python
from myt_machine.payment_requests import create_payment_request, serialize_payment_request

invoice = create_payment_request(
    "MYT_ADDRESS",
    2_500_000_000,
    expires_in=900,
    memo="API usage",
    reference="job-42",
)
print(serialize_payment_request(invoice))
```

The module does not spend funds, access private keys or seed material, change consensus, retry payments, or expose REST/MCP endpoints. `PaymentRequestVerifier` is intentionally small so a later adapter can connect these primitives to MYT Machine's existing payment-status/payment-proof flow.
