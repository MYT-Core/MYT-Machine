# MYT Machine Settlement SDK/CLI

[![CI](https://github.com/MYT-Core/MYT-Machine/actions/workflows/ci.yml/badge.svg)](https://github.com/MYT-Core/MYT-Machine/actions/workflows/ci.yml)

`myt-machine` is the Phase 4A machine-facing settlement interface for an
existing `myt-wallet-rpc` process. It provides exact MYT amount handling,
payments, wallet-local payment status, native payment proofs, and native
message signatures.

Version `0.1.0` does not change consensus, emission, HF17, network parameters,
wallet RPC schemas, or cryptography. It never creates or opens wallets and it
never handles seeds or private keys.

## Requirements

- Python 3.10 or newer
- A running `myt-wallet-rpc` with HTTP Digest Authentication enabled
- A synchronized MYT daemon connected to that wallet RPC

The installed package has no third-party runtime dependencies.

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

If communication fails after `transfer` may have reached the wallet, the error
contains `"outcome_unknown": true`. Do not immediately send the payment again.
First inspect the sender wallet or reconcile by invoice and destination.

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
defaults. The account and address indexes are CLI-only in v0.1.

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

## Testnet End-to-End Runbook

This procedure submits a real Testnet payment. Use disposable wallets and do
not reuse production wallet or RPC credentials.

### 1. Prepare two wallets

Create two disposable Testnet wallets with `myt-wallet-cli --testnet`. Fund the
sender with more than `0.1 MYT` plus the transaction fee. Wait until both
wallets and the connected Testnet daemon are synchronized.

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

Record the receiver address as `RECIPIENT`.

### 4. Send and confirm 0.1 MYT

```bash
"${A[@]}" pay --address "$RECIPIENT" --amount 0.1
"${A[@]}" payment-status --txid "$TXID"
```

Record the returned `txid` as `TXID`. Check immediately, then check again after
at least one Testnet block. The final result must report `found: true`,
`state: "confirmed"`, and at least one confirmation.

`payment-status` is wallet-local. It only finds transactions known to the
opened wallet and is not a global explorer lookup.

### 5. Create and verify a payment proof

```bash
"${A[@]}" prove-payment \
  --txid "$TXID" \
  --address "$RECIPIENT" \
  --message phase4a-e2e > phase4a-payment-proof.json

"${B[@]}" verify-payment --proof-file phase4a-payment-proof.json
```

The receiver must report `valid: true`, the expected received amount, and the
current confirmation count.

### 6. Sign and verify a message

```bash
"${A[@]}" sign-message --message phase4a-agent-a
"${B[@]}" verify-message \
  --address "$SENDER" \
  --message phase4a-agent-a \
  --signature "$SIGNATURE"
```

Record `address` and `signature` from the signing result as `SENDER` and
`SIGNATURE`. Verification must return `valid: true`.

### 7. Negative and transport tests

- Change one character in the proof, message, address, and signature separately.
- Each validly formed but incorrect verification must return `valid: false` and
  exit code `1`.
- Use a wrong Digest Auth password and verify structured exit code `4` output.
- Use an unused loopback port and verify structured exit code `4` output.
- Search captured output for the test passwords and verify neither appears.

Record wallet heights, TXID, confirmation count, command outputs with secrets
removed, package version, and the Git commit used for the run.

## Scope Limits

- No wallet creation, wallet opening, seed management, or key management
- No automatic payment retry or payment idempotency
- No global blockchain transaction search
- No marketplace, reputation, or agent identity protocol
- No consensus, daemon, HF17, emission, or network parameter changes

## Development

Run all tests without installing the package:

```bash
PYTHONPATH=src \
  python -m unittest discover -s tests -v
```

The dedicated GitHub Actions workflow tests Python 3.10, 3.12, and 3.13 on
Linux, includes a Windows run, compiles all modules, and builds both a wheel and
a source distribution.
