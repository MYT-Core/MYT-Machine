# MYT Machine Settlement, Identity, Address Binding, and Billing SDK/CLI

[![CI](https://github.com/MYT-Core/MYT-Machine/actions/workflows/ci.yml/badge.svg)](https://github.com/MYT-Core/MYT-Machine/actions/workflows/ci.yml)

`myt-machine` provides the Phase 4 machine-facing interfaces for MYT:

- Phase 4A: exact MYT amount handling, payments, wallet-local payment status,
  native payment proofs, and native wallet signatures through
  `myt-wallet-rpc`.
- Phase 4B: offline Ed25519 machine identities, signatures, and
  challenge-response building blocks that do not use a wallet or network.
- Phase 4C: selectively disclosed, two-sided cryptographic bindings between a
  Machine Identity and an MYT settlement address.
- Phase 4D: immutable payment requests, persistent invoices, read-only native
  payment verification and a programmatic API billing interface with optional
  authenticated WSGI routes.

Version `0.4.0` does not change MYT Core, consensus, emission, HF17, network
parameters, blockchain state, or wallet RPC schemas. The Phase 4A, Phase 4B and Phase 4C
interfaces remain backward compatible.

Phase 4D documentation: [Payment Request v1](docs/payment-requests.md),
[invoice lifecycle and verification](docs/invoices.md), and
[SDK, CLI and REST billing examples](docs/api-billing.md). The initial payment
request contribution by **fallacyofall** in PR #1 is credited in the
[forensic review](docs/phase4d-pr1-review.md).

Invoices never initiate outgoing payments. `PAID` requires an invoice-bound
native OutProofV2, exact amount, correct network/recipient, ten confirmations by
default and atomic transaction-reuse protection. Imported request artifacts
cannot supply a payment state. See the invoice documentation for expiry, reorg,
local-database trust and service-authorization limitations.

## Requirements

- Python 3.10 or newer
- `cryptography>=50.0.0`
- For settlement commands: a running `myt-wallet-rpc` with HTTP Digest
  Authentication and a synchronized MYT daemon
- For `binding create` and `binding verify`: a trusted Wallet RPC on the
  binding network; these commands do not require a daemon or blockchain access

Identity commands and `binding show` are fully offline. They do not require
wallet RPC, a daemon, a blockchain, Testnet, Mainnet, or internet access.

## Install

From the MYT repository:

```bash
python3 -m venv .venv-myt-machine
. .venv-myt-machine/bin/activate
python -m pip install .
myt-machine --help
```

On PowerShell, activate the environment with:

```powershell
.venv-myt-machine\Scripts\Activate.ps1
```

## Security Model

The complete protocol and threat boundaries are documented in
[`docs/identity-v1.md`](docs/identity-v1.md) and
[`docs/address-binding-v1.md`](docs/address-binding-v1.md).

- Wallet RPC passwords cannot be supplied with a CLI argument.
- Use `--rpc-password-file` or `MYT_WALLET_RPC_PASSWORD`.
- Password files must be UTF-8, contain one non-empty line, and should be mode
  `0600` on Unix.
- Plain HTTP is accepted only for loopback hosts by default.
- Use HTTPS for remote wallet RPC. `--allow-insecure-http` is an explicit,
  discouraged override.
- RPC URLs containing credentials, paths, queries, fragments, or unknown
  schemes are rejected.
- HTTPS uses normal system certificate verification.
- System proxy settings are ignored, so wallet traffic is not silently sent
  through an HTTP proxy.
- Responses are size-limited and JSON-RPC response IDs must match requests.
- The urllib transport keeps the Digest challenge and authenticated request on
  one connection because Epee scopes its nonce to that connection. The
  authenticated application request is still sent only once.
- RPC passwords, wallet passwords, seeds, private keys, transaction keys,
  transaction hex, and transaction metadata are never returned.
- A payment is submitted exactly once by the SDK. It is never retried after a
  timeout or malformed response.
- The Wallet RPC `sign` request used by `binding create` is also submitted
  exactly once and is never retried automatically.
- Identity private keys are encrypted PKCS8 PEM files and are never written to
  normal output.
- Identity passphrases are accepted only through a protected file or an
  interactive TTY prompt. There is no passphrase CLI option or environment
  variable.
- Identity operations reject malformed and non-canonical IDs, public keys,
  signatures, and challenge encodings before verification.
- Subaddresses are the binding privacy default. Binding the primary standard
  address requires explicit `--allow-standard-address`; Integrated Addresses
  are unsupported.
- Binding artifacts are selectively disclosed public material. Sharing one
  intentionally links its Machine ID and settlement address.

`binding create` requires an unrestricted, opened, spend-key-capable Wallet
RPC. Use loopback or strongly protected authenticated and encrypted transport.
Never expose such an RPC without protection to an untrusted network.

If communication fails after `transfer` or binding `sign` may have reached the
wallet, the error contains `"outcome_unknown": true`. Do not immediately repeat
the operation. Reconcile the payment or review the binding attempt first.

## Configuration

Global CLI options must appear before the command:

```text
--rpc-url URL
--rpc-user USER
--rpc-password-file FILE
--timeout SECONDS
--account-index INDEX
--address-index INDEX
--allow-insecure-http
```

Defaults:

| Setting | Default |
|---|---|
| Mainnet wallet RPC convention | `http://127.0.0.1:39083` |
| Testnet wallet RPC convention | `http://127.0.0.1:38083` |
| Timeout | `10` seconds |
| Account index | `0` |
| Address index | `0` |

Environment variables:

```text
MYT_WALLET_RPC_URL
MYT_WALLET_RPC_USER
MYT_WALLET_RPC_PASSWORD
MYT_WALLET_RPC_TIMEOUT
```

CLI values take precedence over environment values, which take precedence over
defaults. The account and address indexes remain CLI-only in v0.3.

Example using a protected password file:

```bash
mkdir -p "$HOME/.config/myt"
chmod 700 "$HOME/.config/myt"
install -m 600 /dev/null "$HOME/.config/myt/agent-a.rpc-password"
read -rsp 'Wallet RPC password: ' MYT_RPC_PASSWORD
printf '\n'
printf '%s\n' "$MYT_RPC_PASSWORD" > "$HOME/.config/myt/agent-a.rpc-password"
unset MYT_RPC_PASSWORD

myt-machine \
  --rpc-url http://127.0.0.1:38083 \
  --rpc-user agent-a \
  --rpc-password-file "$HOME/.config/myt/agent-a.rpc-password" \
  status
```

## Commands

```text
myt-machine status
myt-machine address
myt-machine balance
myt-machine pay --address <ADDRESS> --amount <MYT> [--priority 0-4]
myt-machine payment-status --txid <TXID>
myt-machine prove-payment --txid <TXID> --address <ADDRESS> [--message <TEXT>]
myt-machine verify-payment --proof-file <FILE|->
myt-machine sign-message --message <TEXT>
myt-machine verify-message --address <ADDRESS> --message <TEXT> --signature <SIGNATURE>
myt-machine identity create --private-key-file <FILE> --identity-file <FILE> [--passphrase-file <FILE>]
myt-machine identity show --identity-file <FILE>
myt-machine identity sign --private-key-file <FILE> --identity-file <FILE> [--passphrase-file <FILE>] --context <CONTEXT> (--message <TEXT> | --message-file <FILE|-> | --nonce-base64url <NONCE>)
myt-machine identity verify --identity-file <FILE> [--expected-machine-id <ID>] --context <CONTEXT> --signature <SIGNATURE> (--message <TEXT> | --message-file <FILE|-> | --nonce-base64url <NONCE>)
myt-machine [RPC OPTIONS] binding create --private-key-file <FILE> --identity-file <FILE> --binding-file <FILE> [--passphrase-file <FILE>] [--allow-standard-address]
myt-machine binding show --binding-file <FILE|->
myt-machine [RPC OPTIONS] binding verify --binding-file <FILE|-> [--expected-machine-id <ID>] [--expected-network mainnet|testnet|stagenet]
```

Every normal invocation writes exactly one compact JSON document and one
trailing newline to stdout. Diagnostic text is not mixed into stdout.

```json
{"balance":{"unlocked":{"atomic":1000000000,"myt":"1.000000000"}},"command":"balance","schema_version":1,"success":true}
```

Amounts are always represented with both an integer atomic value and a string
with exactly nine decimal places:

```json
{"atomic":100000000,"myt":"0.100000000"}
```

Input amounts must be plain decimal strings. Floats, exponent notation, zero or
negative payments, and more than nine decimal places are rejected.

## Exit Codes

| Code | Meaning |
|---:|---|
| `0` | Positive result |
| `1` | Valid request with a negative result, such as `valid: false` or `found: false` |
| `2` | Invalid CLI input, amount, TXID, or proof file |
| `3` | Unsafe or invalid configuration |
| `4` | Connection, authentication, timeout, or malformed RPC response |
| `5` | Wallet RPC application error, such as insufficient unlocked balance |

The JSON field `success` describes whether the command was processed without an
operational error. A verification can therefore return `success: true`,
`valid: false`, and exit code `1`.

## Offline Machine Identity

Create a protected passphrase file and a new identity. Existing output files
are never overwritten. On Unix, passphrase and private-key files must have mode
`0600`.

```bash
umask 077
mkdir -p identity
printf '%s\n' 'replace-with-a-long-random-passphrase' > identity/passphrase
chmod 600 identity/passphrase

myt-machine identity create \
  --private-key-file identity/machine-key.pem \
  --identity-file identity/machine-identity.json \
  --passphrase-file identity/passphrase

myt-machine identity show \
  --identity-file identity/machine-identity.json
```

The private key is an encrypted PKCS8 PEM file. The public identity document
contains only the Ed25519 public key, algorithm, protocol version, and derived
Machine ID. Copying the same private key copies the same identity.

Sign and verify a message:

```bash
SIGNATURE=$(myt-machine identity sign \
  --private-key-file identity/machine-key.pem \
  --identity-file identity/machine-identity.json \
  --passphrase-file identity/passphrase \
  --context myt-machine/message \
  --message 'hello from this machine' | \
  python -c 'import json,sys; print(json.load(sys.stdin)["signature"])')

myt-machine identity verify \
  --identity-file identity/machine-identity.json \
  --context myt-machine/message \
  --message 'hello from this machine' \
  --signature "$SIGNATURE"
```

Generic verification proves only that the signature matches the supplied
identity document. Authentication and continuity require an independently
pinned Machine ID:

```bash
myt-machine identity verify \
  --identity-file identity/machine-identity.json \
  --expected-machine-id "$EXPECTED_MACHINE_ID" \
  --context myt-machine/auth/v1/service.example \
  --nonce-base64url "$CHALLENGE" \
  --signature "$SIGNATURE"
```

With `--expected-machine-id`, `valid` is true only when both the signature and
the expected identity match. A verifier must generate the 32-byte challenge,
bind it to the intended context and Machine ID, enforce an expiry, and consume
it atomically. Cryptographic verification by itself does not prevent replay.

`identity sign` intentionally omits the message and `message_digest` from its
result. Ed25519 signatures are deterministic, however, so signatures over
low-entropy messages can still be correlated or tested against guesses. Use a
message file or stdin instead of `--message` when command-line visibility is a
concern.

The runtime floor is `cryptography>=50.0.0`. Versions below 50 are unsupported;
50.0.0 is the first release patched for
[GHSA-g6cj-pr64-35w5](https://github.com/pyca/cryptography/security/advisories/GHSA-g6cj-pr64-35w5),
and it also includes the fixes for
[GHSA-jwv3-5hgf-82ww](https://github.com/pyca/cryptography/security/advisories/GHSA-jwv3-5hgf-82ww)
and
[GHSA-m2h6-j472-rp4c](https://github.com/pyca/cryptography/security/advisories/GHSA-m2h6-j472-rp4c).
There is no artificial upper bound because pyca documents API stability for
the APIs used here. Users who build `cryptography` from source remain
responsible for linking it against a patched, supported OpenSSL version.

## Machine Identity Address Binding

A Binding v1 artifact contains an embedded Phase 4B public identity, an MYT
network and address, a Phase 4B identity signature, and a native MYT SigV2
spend signature. Both signatures authorize the exact same canonical binding
payload. Their final cryptographic inputs differ because Phase 4B and native
MYT SigV2 retain their existing domain separation.

A valid binding proves that the controllers of the Machine Identity key and
the MYT settlement-address spend key both authorized the same canonical
binding statement. It does not prove when that authorization occurred, current
liveness, continued key control, or exclusivity of key control. Use a fresh
Phase 4B challenge to check current Machine Identity liveness.

Create a binding for a dedicated subaddress. Global options must precede the
`binding` command, and the selected subaddress must already exist in the opened
wallet:

```bash
myt-machine \
  --rpc-url http://127.0.0.1:38083 \
  --rpc-user agent-b \
  --rpc-password-file /secure/agent-b.rpc-password \
  --account-index 0 \
  --address-index 1 \
  binding create \
  --private-key-file identity/machine-key.pem \
  --identity-file identity/machine-identity.json \
  --binding-file identity/testnet-binding.json \
  --passphrase-file identity/passphrase
```

This command needs an unrestricted, open, spend-key-capable Wallet RPC. Keep it
on loopback or behind strongly protected authenticated and encrypted transport.
Do not expose it unprotected to an untrusted network. The native Wallet RPC
`sign` request is sent exactly once and is never automatically retried.

The primary standard address at account `0`, address `0` is rejected unless
`--allow-standard-address` is explicitly supplied. Integrated Addresses are
unsupported in Address Binding v1.

Inspect an artifact without Wallet RPC:

```bash
myt-machine binding show --binding-file identity/testnet-binding.json
cat identity/testnet-binding.json | myt-machine binding show --binding-file -
```

Verify it with an independent wallet opened on the same network:

```bash
myt-machine \
  --rpc-url http://127.0.0.1:38084 \
  --rpc-user verifier \
  --rpc-password-file /secure/verifier.rpc-password \
  binding verify \
  --binding-file identity/testnet-binding.json \
  --expected-machine-id "$EXPECTED_MACHINE_ID" \
  --expected-network testnet
```

The verifier wallet does not need the bound address's private keys and does not
need a daemon or blockchain connection. A fresh or watch-only wallet on the
same network is sufficient for native SigV2 verification. Without an
independently expected Machine ID, the command verifies signatures but does not
claim Machine Identity authentication.

Bindings are timeless and have no expiry or revocation mechanism. They are
never published automatically or placed on-chain. Disclosure is an explicit
privacy decision and creates linkability between the Machine ID and address for
every recipient of the artifact.

## Payment Proof Artifact

`prove-payment` returns the native proof unchanged from MYT wallet RPC. The
artifact fields are at the top level of the command JSON, so its stdout can be
redirected directly to a file accepted by `verify-payment`:

```json
{
  "type": "myt-payment-proof",
  "version": 1,
  "txid": "...",
  "address": "...",
  "message": "invoice-42",
  "proof": "OutProofV2..."
}
```

```bash
myt-machine prove-payment \
  --txid "$TXID" \
  --address "$RECIPIENT" \
  --message invoice-42 > payment-proof.json

myt-machine verify-payment --proof-file payment-proof.json
cat payment-proof.json | myt-machine verify-payment --proof-file -
```

Proof inputs are UTF-8 JSON and limited to 64 KiB. Type, version, TXID, address,
message, and proof are validated before invoking wallet RPC.

## Python SDK

```python
from pathlib import Path

from myt_machine import MachineSettlement, RpcConfig, WalletRpcClient

password = Path("/secure/agent-a.rpc-password").read_text(encoding="utf-8").rstrip("\r\n")
client = WalletRpcClient(
    RpcConfig(
        url="http://127.0.0.1:38083",
        username="agent-a",
        password=password,
        timeout=10,
    )
)
settlement = MachineSettlement(client, account_index=0, address_index=0)

print(settlement.status())
print(settlement.balance())
```

Exact amount helpers are also public:

```python
from myt_machine import format_myt_amount, parse_myt_amount

assert parse_myt_amount("0.100000001") == 100_000_001
assert format_myt_amount(100_000_001) == "0.100000001"
```

Offline identity helpers are public as well:

```python
from myt_machine import (
    MachineIdentity,
    decode_challenge_nonce,
    load_public_identity,
)

public_identity = load_public_identity("identity/machine-identity.json")
nonce_bytes = decode_challenge_nonce(challenge_from_verifier)
verification = public_identity.verify(
    nonce_bytes,
    "myt-machine/auth/v1/service.example",
    signature,
    expected_machine_id=pinned_machine_id,
)
assert verification.authentication_valid is True
```

Address Binding v1 is available through the SDK:

```python
from myt_machine import (
    AddressBindingService,
    load_address_binding,
    load_private_identity,
    save_address_binding,
)

identity = load_private_identity("identity/machine-key.pem", passphrase_bytes)
creator = AddressBindingService(wallet_rpc_client, account_index=0, address_index=1)
binding = creator.create(identity)
save_address_binding(binding, "identity/testnet-binding.json")

public_binding = load_address_binding("identity/testnet-binding.json")
verifier = AddressBindingService(independent_testnet_wallet_rpc_client)
result = verifier.verify(
    public_binding,
    expected_machine_id=pinned_machine_id,
    expected_network="testnet",
)
assert result.authentication_valid is True
```

## Testnet End-to-End Runbook

This procedure submits a real Testnet payment. Use disposable wallets and do
not reuse production wallet or RPC credentials.

### 1. Prepare two wallets

Create two disposable Testnet wallets with `myt-wallet-cli --testnet`. Fund the
sender with more than `0.1 MYT` plus the transaction fee. Wait until both
wallets and the connected Testnet daemon are synchronized.

In receiver wallet B, create a dedicated subaddress and record its account and
address index. The examples below use account `0`, address index `1`. Do not use
an Integrated Address. Wallet B RPC must be unrestricted and spend-key-capable
for `binding create`; never expose it unprotected to an untrusted network.

Place each wallet password in a different mode-`0600` file. In two terminals,
start wallet RPC on loopback. Supplying only the username to `--rpc-login`
causes `myt-wallet-rpc` to prompt for the Digest Auth password instead of
putting it in shell history or the process list.

Enter the same password stored in the corresponding agent RPC password file
when each process prompts.

Sender:

```bash
./build/bin/myt-wallet-rpc \
  --testnet \
  --wallet-file /secure/testnet-agent-a \
  --password-file /secure/testnet-agent-a.wallet-password \
  --daemon-address http://127.0.0.1:38081 \
  --rpc-bind-ip 127.0.0.1 \
  --rpc-bind-port 38083 \
  --rpc-login agent-a
```

Receiver:

```bash
./build/bin/myt-wallet-rpc \
  --testnet \
  --wallet-file /secure/testnet-agent-b \
  --password-file /secure/testnet-agent-b.wallet-password \
  --daemon-address http://127.0.0.1:38081 \
  --rpc-bind-ip 127.0.0.1 \
  --rpc-bind-port 38084 \
  --rpc-login agent-b
```

Do not use `--disable-rpc-login`.

### 2. Define safe CLI prefixes

The examples use shell arrays so global options are always placed correctly:

```bash
A=(myt-machine --rpc-url http://127.0.0.1:38083 --rpc-user agent-a --rpc-password-file /secure/agent-a.rpc-password)
B=(myt-machine --rpc-url http://127.0.0.1:38084 --rpc-user agent-b --rpc-password-file /secure/agent-b.rpc-password)
B_BIND=("${B[@]}" --account-index 0 --address-index 1)
```

### 3. Check status and addresses

```bash
"${A[@]}" status
"${A[@]}" balance
"${A[@]}" address
"${B[@]}" status
"${B[@]}" balance
"${B[@]}" address
```

Confirm that `"${B_BIND[@]}" address` returns the dedicated receiver
subaddress.

### 4. Create Machine Identity B and its address binding

```bash
umask 077
E2E=phase4c-testnet-e2e
mkdir "$E2E"
read -rsp 'Disposable identity passphrase: ' PASSPHRASE
printf '\n'
printf '%s\n' "$PASSPHRASE" > "$E2E/passphrase"
chmod 600 "$E2E/passphrase"

myt-machine identity create \
  --private-key-file "$E2E/machine-b-key.pem" \
  --identity-file "$E2E/machine-b-identity.json" \
  --passphrase-file "$E2E/passphrase" > "$E2E/identity-create.json"

MACHINE_ID=$(python -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["machine_id"])' \
  "$E2E/identity-create.json")

"${B_BIND[@]}" binding create \
  --private-key-file "$E2E/machine-b-key.pem" \
  --identity-file "$E2E/machine-b-identity.json" \
  --binding-file "$E2E/machine-b-testnet-binding.json" \
  --passphrase-file "$E2E/passphrase" > "$E2E/binding-create.json"

"${A[@]}" binding verify \
  --binding-file "$E2E/machine-b-testnet-binding.json" \
  --expected-machine-id "$MACHINE_ID" \
  --expected-network testnet > "$E2E/binding-verify.json"

RECIPIENT=$(myt-machine binding show \
  --binding-file "$E2E/machine-b-testnet-binding.json" | \
  python -c 'import json,sys; print(json.load(sys.stdin)["binding"]["address"])')
```

The verification result must report `identity_signature_valid: true`,
`wallet_signature_valid: true`, `wallet_signature_version: 2`,
`wallet_signature_type: "spend"`, `binding_valid: true`,
`authentication_valid: true`, and `valid: true`.

### 5. Authenticate current Machine Identity liveness

The binding is timeless, so authenticate Machine B separately with a fresh
32-byte challenge. The verifier must store and atomically consume the nonce in
a real application.

```bash
CHALLENGE=$(openssl rand 32 | python -c \
  'import base64,sys; print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode().rstrip("="))')

IDENTITY_SIGNATURE=$(myt-machine identity sign \
  --private-key-file "$E2E/machine-b-key.pem" \
  --identity-file "$E2E/machine-b-identity.json" \
  --passphrase-file "$E2E/passphrase" \
  --context myt-machine/auth/v1/phase4c-testnet \
  --nonce-base64url "$CHALLENGE" | \
  python -c 'import json,sys; print(json.load(sys.stdin)["signature"])')

myt-machine identity verify \
  --identity-file "$E2E/machine-b-identity.json" \
  --expected-machine-id "$MACHINE_ID" \
  --context myt-machine/auth/v1/phase4c-testnet \
  --nonce-base64url "$CHALLENGE" \
  --signature "$IDENTITY_SIGNATURE" > "$E2E/challenge-verify.json"
```

Require `signature_valid: true`, `identity_matches: true`,
`authentication_valid: true`, and `valid: true` before payment.

### 6. Send and confirm 0.1 MYT

```bash
"${A[@]}" pay --address "$RECIPIENT" --amount 0.1
"${A[@]}" payment-status --txid "$TXID"
```

Record the returned `txid` as `TXID`. Check immediately, then check again after
at least one Testnet block. The final result must report `found: true`,
`state: "confirmed"`, and at least one confirmation.

`payment-status` is wallet-local. It only finds transactions known to the
opened wallet and is not a global explorer lookup.

### 7. Create and verify a payment proof

```bash
"${A[@]}" prove-payment \
  --txid "$TXID" \
  --address "$RECIPIENT" \
  --message phase4a-e2e > phase4a-payment-proof.json

"${B[@]}" verify-payment --proof-file phase4a-payment-proof.json
```

The receiver must report `valid: true`, the expected received amount, and the
current confirmation count.

### 8. Sign and verify a native wallet message

```bash
"${A[@]}" sign-message --message phase4a-agent-a
"${B[@]}" verify-message \
  --address "$SENDER" \
  --message phase4a-agent-a \
  --signature "$SIGNATURE"
```

Record `address` and `signature` from the signing result as `SENDER` and
`SIGNATURE`. Verification must return `valid: true`.

### 9. Negative, substitution, and transport tests

- Change the challenge, binding address, binding network, Machine ID,
  identity signature, wallet signature, TXID, and payment proof separately.
- Each validly formed but incorrect verification must return `valid: false` and
  exit code `1`.
- A non-canonical challenge or malformed binding must return exit code `2`.
- Use a wrong Digest Auth password and verify structured exit code `4` output.
- Use an unused loopback port and verify structured exit code `4` output.
- Search captured output for the test passwords and verify neither appears.

While `PASSPHRASE` is still set, include these release checks:

```bash
! grep -lF 'must-not-appear' "$E2E"/*.json
! grep -lF -- "$PASSPHRASE" "$E2E"/*.json
unset PASSPHRASE
```

The final release gate is successful only when Machine Identity creation,
binding creation, expected-ID and expected-network verification, fresh
challenge authentication, a real `0.1 MYT` payment, confirmation, native
`OutProofV2` creation, and proof verification all succeed in this order.

Record wallet heights, TXID, confirmation count, command outputs with secrets
removed, package version, and the Git commit used for the run.

## Scope Limits

- No wallet creation, wallet opening, seed management, or wallet-key management
- No automatic payment retry or payment idempotency
- No global blockchain transaction search
- No marketplace, reputation, global binding registry, or identity discovery
- No binding expiry, revocation, address rotation, or key rotation
- No Integrated Address support in Address Binding v1
- No consensus, daemon, HF17, emission, or network parameter changes

## Development

Run all tests without installing the package:

```bash
PYTHONPATH=src \
  python -m unittest discover -s tests -v
```

The GitHub Actions workflow tests Python 3.10, 3.12, and 3.13 on Linux and
Windows against both the dependency floor and latest compatible
`cryptography`. It also runs Ruff and Bandit, audits dependencies, compiles all
modules, validates package metadata, and builds and smoke-tests both a wheel
and source distribution.
