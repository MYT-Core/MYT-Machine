# MYT Phase 4D validation

Review date: 2026-09-06. Candidate: `myt-machine-settlement` 0.4.0.
Import package: `myt_machine`; CLI: `myt-machine`.
Runtime remains exactly `cryptography>=50.0.0`, with no additional dependency.

## Baseline and third-party provenance

- Official repository: https://github.com/MYT-Core/MYT-Machine
- Original main / released v0.3.0: `e996c4388b3495ffd1fecb6fe1b868b67ae106e9`.
- Safety reference: `safety/pre-phase4d-v0.3`.
- Integration branch: `feature/phase4d-payment-invoices-api-billing`.
- PR: https://github.com/MYT-Core/MYT-Machine/pull/1
- Author: `fallacyofall`, fork `fallacyofall/MYT-Machine`, branch
  `phase4d-payment-requests`, base `main` at the original main SHA.
- Original reviewed PR head:
  `9068e60946faa5f2250455e37a04250b677d4704`.
- New fully reviewed head:
  `41e0e6b78da4f6ca75f6fc5cf8059327f9b1c8ee`. Two commits against main.
  Head movement caused an explicit safety stop; review resumed only after
  authorization. This exact SHA must be rechecked before final integration.
- PR merge SHA: N/A. Direct merge is unsuitable; attribution-preserving
  supersession is the selected integration method, subject to replacement gates.

The complete original diff was inspected before integration: 462 additions,
one deletion, and exactly these paths:

| Original PR path | Added | Deleted |
| --- | ---: | ---: |
| `docs/payment_requests.md` | 22 | 0 |
| `src/myt_machine/__init__.py` | 17 | 1 |
| `src/myt_machine/payment_requests.py` | 272 | 0 |
| `tests/test_payment_requests.py` | 151 | 0 |

[The pre-integration forensic review](docs/phase4d-pr1-review.md) records all
findings. No malicious behavior, hidden binaries, new dependencies, workflows,
subprocess/network calls, credential reads or spending were found in the PR.
It is a useful deliberately limited primitive, not a finished billing system.

Blocking integration findings: untrusted artifacts carry mutable PAID state;
network binding is absent; parsing permits duplicates/unknown fields, float
versions and unbounded values; direct construction bypasses validation; recipient
validation accepts arbitrary text; IDs permit unsafe characters/falsy coercion;
pytest tests are not connected to the official unittest CI. Persistence,
confirmation and actual payment verification were explicitly deferred by the PR.

The request factory, exact uint64 validation, immutable dataclass, canonical
serialization, expiry boundary and read-only verifier concepts were adapted.
Attribution is preserved in source/docs and the implementation commit's
`Co-authored-by: Fallacyofall <hollyammaash@gmail.com>` trailer. The contributor's
commit and branch are not rewritten or force-pushed. A direct merge solely for
attribution would introduce an unsafe unpublished schema and is not performed.

### Updated PR delta and independent validation

The new commit changes exactly two paths: `payment_requests.py` (Mapping import
and two postponed return annotations) and `test_payment_requests.py` (unittest
conversion preserving all 18 cases, including four explicit amount rejection
methods). Delta: 133 additions / 132 deletions. The full current PR is 463
additions / one deletion in the same four files. Every changed line and the
complete final PR were reviewed. No unrelated logic, serialization, state,
amount/expiry, dependencies, packaging, permissions or network behavior changed.

CONTRIBUTOR FIX CLAIM: CONFIRMED. A fresh environment without pytest passes
18/18 contributor tests and 193/193 full unittest tests, Ruff, Bandit, compileall,
pip check, pip-audit and wheel/sdist/twine gates. The new GitHub run
[34039805952](https://github.com/MYT-Core/MYT-Machine/actions/runs/34039805952)
completed SUCCESS for all 14 jobs after safe fork approval. This replaces the
old failing PR CI result; it does not fix the unchanged architectural findings.

Independent probes reconfirmed imported PAID without evidence, accepted floating
version/unknown fields, bypassed constructor amount validation and absent network
binding. Consequently the official implementation remains an attributable
superseding integration. No direct merge of either contributor SHA is performed.

### Official change inventory

Exactly 25 intended tracked/new paths, with no temporary files or binaries:

```text
.github/workflows/ci.yml
MANIFEST.in
MYT_Phase4D_Validation.md
README.md
pyproject.toml
docs/api-billing.md
docs/invoices.md
docs/payment-request-v1-test-vector.json
docs/payment-requests.md
docs/phase4d-pr1-review.md
src/myt_machine/__init__.py
src/myt_machine/cli.py
src/myt_machine/billing.py
src/myt_machine/billing_cli.py
src/myt_machine/billing_http.py
src/myt_machine/invoice_store.py
src/myt_machine/invoice_verification.py
src/myt_machine/invoices.py
src/myt_machine/payment_requests.py
tests/billing_fakes.py
tests/test_billing_http.py
tests/test_cli_billing.py
tests/test_invoice_store.py
tests/test_invoice_verification.py
tests/test_payment_requests.py
```

## Architecture and protocol

- `payment_requests.py`: immutable validated request, strict bounded JSON,
  canonical bytes and request-bound proof message; usable without DB or RPC.
- `invoices.py`: local invoice record, exact evidence and lifecycle invariants.
- `invoice_store.py`: private SQLite store, transactions, persistence,
  idempotency and durable transaction uniqueness.
- `invoice_verification.py`: read-only native MYT OutProofV2 adapter using the
  unchanged Phase 4A settlement wrapper.
- `billing.py`: create/get/list/status/verify and application `require_paid` gate.
- `billing_http.py`: optional authenticated WSGI reference REST application.
- `billing_cli.py`: additive payment-request and invoice commands.

The request contains exactly `type`, `version`, `invoice_id`, `network`,
`recipient_address`, `amount_atomic`, `created_at`, `expires_at`, `memo`,
`reference`. Type is `myt-payment-request`; version is integer 1. Memo/reference
are required fields with nullable values. There is no imported payment state,
key, signature, payer identity or proof in the request.

Canonical bytes are ASCII-escaped, key-sorted compact JSON with no trailing LF.
Native proof message is `myt-machine/invoice/v1:` followed by lowercase SHA-256
of those exact bytes. This commits the existing native proof message to the
whole request; no new cryptographic primitive or signature format is introduced.
The [machine-readable deterministic vector](docs/payment-request-v1-test-vector.json)
publishes the request, exact canonical bytes/hex and message. Its address is
explicitly a syntax-only test fixture, not a payable address or real proof.

Strict parsing rejects duplicate/unknown/missing fields, BOM, invalid UTF-8,
floating/exponent/non-finite numbers, bool-as-int, unsafe IDs, oversized content,
invalid network and malformed address syntax. Amounts are positive uint64;
human amounts use the existing exact nine-decimal converter. ID/idempotency
limits are 128 ASCII characters; memo/reference are 1024/256 UTF-8 bytes in NFC
without control characters. Requests cap at 8192 bytes and 30 days lifetime;
timestamps are bounded integer Unix seconds.

Offline address parsing is syntax-only. Service creation and verification use
native `validate_address` with `any_net_type=False`, `allow_openalias=False`,
require configured/request/wallet networks to agree and reject integrated
addresses. Mainnet/testnet/stagenet are explicit, never inferred from a default.

## Payment and state guarantees

Legal transitions: PENDING -> PAID or PENDING -> EXPIRED. Both targets are
terminal. `now == expires_at` is EXPIRED. Verification must finish before expiry,
not merely transaction submission. Time is rechecked under the SQLite write lock
after RPC. No automatic late/partial/overpayment accounting; exact payment only.
PAID never silently expires. `paid_at` is local service decision time, not a
cryptographically proven transaction time.

The actual MYT `wallet_rpc_server::on_check_tx_proof` and
`wallet2::check_tx_proof` implementations were inspected read-only. The native
path fetches the transaction, checks its hash, verifies the proof against the
recipient/message, calculates received outputs, and returns pool/depth data.
Phase 4A payment-status is wallet-local and cannot substitute for this evidence.

PAID requires native OutProofV2 validity, exact recipient and request message,
exact amount, not-in-pool, configured positive confirmation threshold, matching
network, still-pending/unexpired state and an unused normalized TXID. Only
`validate_address` and `check_tx_proof` are called. No transfer, sign, key lookup,
wallet unlock, seed access or automatic retry occurs. Malformed replies,
nonexistent/failed transactions, errors/timeouts and disappearing pre-confirmation
transactions do not finalize payment. Evidence below threshold is not retained
as authority: every later attempt obtains fresh verification.

Default depth is 10 confirmations, aligned with MYT's default spendable age.
Zero and malformed thresholds fail. Unsigned-underflow-like confirmation values
outside uint32 fail. Depth is an application acceptance policy, not a consensus
change, spendability promise or protection against every reorganization.

Proofs do NOT identify the payer address, legal/customer identity, current key
control or an authorization time. Native cryptographic verification does not
remove trust in synchronized wallet/daemon chain data or local application state.
An independent wallet can verify a native proof without the recipient's private
spend key; this task inspected the source and used deterministic mocks, not a
new real-network experiment. Existing Phase 4C tests remain intact.

SQLite uses BEGIN IMMEDIATE, FULL synchronization, separate connections and
UNIQUE(network, txid). It handles concurrent same-invoice and cross-invoice
verification atomically. TXIDs are case-normalized. One TX cannot pay two
invoices in this ledger/network even with different outputs or newly generated
proofs. Same idempotency key/terms returns the original invoice; changed terms
conflict. Generated IDs/time are excluded from the creation fingerprint; all
client-controlled commercial terms and confirmation policy are included.

## API, privacy and limitations

The SDK lets a service create/share requests, inspect state and verify evidence.
`require_paid` is a payment-policy gate, NOT customer authentication, pricing
authorization or one-time fulfillment. Applications must authenticate clients,
bind invoices to server-selected price/recipient/work and enforce fulfillment.

REST routes: GET `/health`; POST/GET `/v1/invoices`;
GET `/v1/invoices/{id}`; GET `/v1/invoices/{id}/status`;
POST `/v1/invoices/{id}/verify`. Only minimal health is unauthenticated. All
billing routes require a protected operator bearer token, with constant-time
comparison and redacted errors/repr. This is NOT a public payer creation API.
No wallet-spending, mark-paid, seed, wallet-management or deletion endpoint exists.

Bodies cap at 73728 bytes; JSON schema/query fields are strict; lists use bounded
keyset pagination (100 maximum). Tokens stay server-side. The application does
not bind sockets, deploy services, provide CORS or log requester IPs. Production
hosting must enforce TLS, request deadlines, concurrency/rate limits and log
redaction. Wallet RPC remains loopback or strongly protected transport.

The private DB persists request terms, policy, state, TXID, received amount,
observed depth, local decision time and idempotency data. Full proofs, payer
addresses, IPs, secrets and wallet material are not persisted. Unix DBs require
0600, regular non-linked files and a controlled parent; Windows needs service-only
NTFS ACLs. Protect backups/journals as billing data. No encryption-at-rest or
cryptographic local-state tamper protection is claimed.

Limitations: terminal PAID is not continuously revoked after deep reorgs;
custom unlock times are not verified; late payments require manual handling;
old unallocated transactions can satisfy fresh request-bound proofs; deleting
ledger history loses duplicate protection; separate databases cannot enforce
global TX uniqueness. A shared durable consumption ledger and dedicated
subaddresses are recommended. Default capacity is 100000 invoices (maximum
1000000); archiving must preserve accepted TXIDs.

Optional Machine Identity-signed requests are explicitly deferred rather than
adding key handling or another signature protocol. A future version can reuse
Phase 4B domain-separated signatures over immutable canonical content, not state.
MCP is deferred to an adapter consuming BillingService under the same controls.
No Phase 4E/4F, custody, marketplace, subscriptions or economic claims were added.

## Validation evidence

Baseline: 175 tests, 175 passed, zero failed/errors/skipped, 9.124 seconds.
Independent PR: 18 new pytest tests passed (0.15 s); complete pytest 193 passed
and 201 subtests passed (7.28 s). Unittest runs the original 175 only when pytest
is installed; otherwise the new pytest module cannot import. Ruff found three
issues; Bandit, build and twine passed independently.

Original GitHub run `33985280237` was initially ACTION_REQUIRED. The unchanged
workflow was reviewed and approved. It concluded FAILURE: all 12 unit/CLI matrix
jobs failed; dependency audit's static-check step failed; packaging was skipped.
These failures are not treated as passing or bypassed by merging that commit.

Candidate: 318 tests total, including 143 new tests. Separate regression gates:
Phase 4A 66/66, Phase 4B 62/62, Phase 4C 47/47. Existing 175 tests and their files
their semantics are unchanged. New coverage includes strict parsers, canonical
vector, all lifecycle/payment negatives, expiry during RPC, maximum uint64,
process restart, concurrent idempotency/verification, durable TX reuse protection,
corrupt DB data, CLI/REST schemas, offline dispatch and redaction sentinels.

The second adversarial review concentrated on false PAID transitions, proof
substitution, confirmation underflow, wrong network, expiry races, response types,
duplicate-TX concurrency and service-authorization confusion. No unresolved
false-PAID path was found within the documented trusted-verifier/store model.
Matrix testing found and fixed Python 3.10's strict empty-query behavior and
three test-only SQLite connections that needed explicit close on Windows.

Final local CI-equivalent matrix (each row ran all 318 tests):

| OS | Python | cryptography floor / latest | Passed / failed / skipped | Seconds floor / latest |
| --- | --- | --- | --- | --- |
| Linux (WSL Ubuntu) | 3.10.21 | 50.0.0 / 50.0.1 | 318 / 0 / 0 | 9.629 / 9.327 |
| Linux (WSL Ubuntu) | 3.12.3 | 50.0.0 / 50.0.1 | 318 / 0 / 0 | 9.682 / 9.241 |
| Linux (WSL Ubuntu) | 3.13.15 | 50.0.0 / 50.0.1 | 318 / 0 / 0 | 8.418 / 8.370 |
| Native Windows | 3.10.21 | 50.0.0 / 50.0.1 | 313 / 0 / 5 | 15.589 / 14.372 |
| Native Windows | 3.12.14 | 50.0.0 / 50.0.1 | 313 / 0 / 5 | 13.325 / 12.883 |
| Native Windows | 3.13.9 | 50.0.0 / 50.0.1 | 313 / 0 / 5 | 13.124 / 12.891 |

Windows skips are three existing Unix/symlink tests and two new Unix DB
permission/symlink tests; all five execute on Linux. No unexpected skips,
failures or unittest warnings remained. Dependency wheels were installed from
official PyPI using explicit `--index-url https://pypi.org/simple`; exact
`cryptography.__version__`, `__file__`, Python version and `pip show` were logged
for each environment. Latest resolved to 50.0.1, not an unreleased checkout.

Security/package results: Ruff 0.16.3 passed; Bandit 1.9.4 passed; compileall and
pip check passed. pip-audit 2.10.1 found no known vulnerabilities for both tested
runtime configurations (50.0.0 and 50.0.1). The unpublished local package is
explicitly reported by pip-audit as unavailable in PyPI's vulnerability index;
its own code is covered by this review, not by an invented audit database entry.
Initial clean-venv pip 24.0 advisories were resolved by upgrading installation
tooling to current pip; no advisory was ignored. CI also updates pip first.

Wheel and sdist built with build 1.5.0; twine 7.0.0 checks passed. Wheel version
is 0.4.0 and its only Requires-Dist line is `cryptography>=50.0.0`. The sdist
includes protocol vectors, API/lifecycle docs and this validation report.
An isolated installed-wheel run, executed outside the source checkout, passed
318/318 tests (8.677 s). A separate deterministic fake-RPC billing exercise
passed creation idempotency, unpaid service denial, confirmation threshold,
wrong-request rejection, paid service gate, durable duplicate-TX rejection,
database reopen, authenticated REST list and response/DB secret-redaction checks.
Only validate_address/check_tx_proof were invoked. No real proof validity or
real-network E2E is claimed for fake data.

Reproduction gates: `python -m unittest discover -s tests -v`,
`ruff check src tests`, `bandit -q -r src/myt_machine`, `python -m pip check`,
`python -m pip_audit`, `python -m compileall -q src tests`, `python -m build`,
`python -m twine check dist/*`. Install the wheel into a separate venv, change
outside the checkout and rerun unittest with the absolute tests directory.
Do not perform a transfer as part of these tests.

GitHub candidate/main runs must independently pass before completion is declared.
No real MYT payment, wallet seed import, Testnet/Mainnet mutation or public service
was performed. Fake OutProofV2-shaped data exercises policy, not native crypto.

## Finalization record

After the authorized fresh review of 41e0e6b, the complete candidate matrix was
rerun on all twelve installed-wheel environments with source-byte comparisons:
Linux again 318/318 and Windows again 313 passed / five platform skips per run,
zero failures. Floor/latest remain 50.0.0/50.0.1. Ruff, Bandit, compileall,
pip check, both runtime audits, wheel/sdist/twine and clean-wheel verification
were repeated successfully. The repeated outside-checkout suite passed 318/318
in 9.100 seconds; the separate deterministic billing E2E passed again.

Local matrix, clean-wheel/build/security gates passed; GitHub Actions pending.
Main remains unchanged until GitHub gates and formal PR supersession complete.
The final main/remote SHA and execution evidence will be reported after the
authorized fast-forward. A commit cannot contain its own Git object hash; the
final execution report records that hash outside its hashed repository content.

No release, tag, PyPI publication, public deployment, Core, consensus, HF17,
blockchain, transaction-format or Wallet-RPC-schema change is authorized here.
