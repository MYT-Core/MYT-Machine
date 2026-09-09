# Phase 4E: off-chain agent reputation evidence

Phase 4A provides payments; 4B provides Machine Identity; 4C binds identity and
settlement address; 4D verifies invoices; 4E provides **verifiable evidence and
local policy**, not universal reputation. Phase 4F selective disclosure is future
work and is not implemented here.

**A Machine ID does not prove a unique person or independent controller.**
An attacker can create many identities and arrange colluding feedback and
self-controlled payments. There is no claim of global Sybil resistance.

## Three separate meanings

- A cryptographically attributable attestation proves that the issuer key
  controller authorized the exact signed opinion. It does not prove the opinion
  true, trustworthiness, a real interaction, independence or service quality.
- A local verified recipient-linked settlement observation requires a durable
  Phase 4D PAID invoice, an exact-recipient Phase 4C binding, and a **fresh** native
  OutProofV2 check with the invoice message, exact amount, matching stored TXID,
  correct network, no mempool state and the invoice's confirmation threshold.
- Local policy output counts only explicitly accepted opinions according to an
  operator-selected allowlist, age window, per-issuer limit and optional linkage.
  No automatic score is calculated from payments, identities, wallets or invoices.

The settlement observation is linked to the **recipient** identity only. A native
payment proof cannot identify a payer Machine ID. A binding proves both key
controllers authorized the same canonical binding statement. It does not prove
when authorization occurred, current liveness, continued/exclusive control,
legal identity or identity at the time of payment. Settlement is not proof of
service fulfillment. Current Machine Identity liveness requires a fresh 4B
challenge. Reorgs or a lying wallet/daemon can invalidate chain observations;
this layer does not continuously recheck them.

See the [artifact protocol](reputation-attestation-v1.md),
[deterministic public test vector](reputation-attestation-v1-test-vector.json),
and [policy, revocation and storage threat model](reputation-policy.md).

## Offline CLI E2E

These commands use no MYT, wallets or network after package installation. They
work in a new Bash terminal with the installed `myt-machine` on PATH. All keys
below are disposable. Do not reuse the public deterministic fixture as a key.

```bash
set -euo pipefail
umask 077
BASE=$(mktemp -d)
export BASE
PASSPHRASE=$(python -c 'import secrets; print(secrets.token_hex(32))')
printf '%s\n' "$PASSPHRASE" > "$BASE/passphrase"
export MYT_WALLET_RPC_URL=ftp://invalid.example
for role in issuer subject; do
  myt-machine identity create --private-key-file "$BASE/$role.pem" \
    --identity-file "$BASE/$role.json" --passphrase-file "$BASE/passphrase" \
    > "$BASE/$role-create.json"
done
ISSUER=$(python -c 'import json,os; print(json.load(open(os.environ["BASE"]+"/issuer.json"))["machine_id"])')
SUBJECT=$(python -c 'import json,os; print(json.load(open(os.environ["BASE"]+"/subject.json"))["machine_id"])')
NOW=$(date +%s)
myt-machine reputation attest --network testnet --subject "$SUBJECT" \
  --outcome POSITIVE --issued-at "$NOW" \
  --private-key-file "$BASE/issuer.pem" --identity-file "$BASE/issuer.json" \
  --passphrase-file "$BASE/passphrase" --output-file "$BASE/attestation.json" \
  > "$BASE/attest-result.json"
myt-machine reputation verify --network testnet --expected-issuer "$ISSUER" \
  --artifact-file "$BASE/attestation.json" > "$BASE/verify.json"
myt-machine reputation import --network testnet --db "$BASE/reputation.sqlite" \
  --artifact-file "$BASE/attestation.json" > "$BASE/import.json"
myt-machine reputation import --network testnet --db "$BASE/reputation.sqlite" \
  --artifact-file "$BASE/attestation.json" > "$BASE/reimport.json"
myt-machine reputation summary --network testnet --db "$BASE/reputation.sqlite" \
  --subject "$SUBJECT" --as-of "$NOW" > "$BASE/default-policy.json"
myt-machine reputation summary --network testnet --db "$BASE/reputation.sqlite" \
  --subject "$SUBJECT" --trusted-issuer "$ISSUER" --as-of "$NOW" \
  > "$BASE/accepted-policy.json"
myt-machine reputation revoke --network testnet --issued-at "$NOW" \
  --artifact-file "$BASE/attestation.json" --private-key-file "$BASE/issuer.pem" \
  --identity-file "$BASE/issuer.json" --passphrase-file "$BASE/passphrase" \
  --output-file "$BASE/revocation.json" > "$BASE/revoke-result.json"
myt-machine reputation import --network testnet --db "$BASE/reputation.sqlite" \
  --artifact-file "$BASE/revocation.json" > "$BASE/import-revocation.json"
myt-machine reputation summary --network testnet --db "$BASE/reputation.sqlite" \
  --subject "$SUBJECT" --trusted-issuer "$ISSUER" --as-of "$NOW" \
  > "$BASE/revoked-policy.json"
python - <<'PY'
import json, os
from pathlib import Path
p = Path(os.environ['BASE'])
def read(name):
    return json.loads((p / (name + '.json')).read_text())
assert read('verify')['valid']
assert read('import')['inserted'] and not read('reimport')['inserted']
assert read('default-policy')['local_policy_output']['accepted_attestations'] == 0
assert read('accepted-policy')['local_policy_output']['accepted_attestations'] == 1
assert read('revoked-policy')['local_policy_output']['accepted_attestations'] == 0
assert read('revoked-policy')['signed_opinions']['revoked_attestations'] == 1
print('Offline reputation E2E passed')
PY
! grep -lF 'must-not-appear' "$BASE"/*.json
! grep -lF -- "$PASSPHRASE" "$BASE"/*.json
! grep -lE 'BEGIN .*PRIVATE KEY|message_digest' "$BASE"/*.json
unset PASSPHRASE MYT_WALLET_RPC_URL
```

`verify` checks cryptography and supplied expectations, not issuer trust,
revocation delivery or truth. `get` and `list` intentionally disclose artifacts;
`summary` omits invoice IDs, addresses, proofs, transaction IDs and evidence IDs.
Exit codes retain the established envelope: 0 success, 1 negative verification or
not found, 2 malformed input, 3 unsafe configuration, 4 storage/transport/protocol
failure, 5 Wallet RPC application error. Passphrases use protected files or the
existing interactive prompt, never argv or environment.

## Optional read-only 4C/4D bridge

Use an existing local, protected invoice database and a trusted Wallet RPC. This
command never calls wallet `sign`, `transfer` or retries an application request:

```bash
myt-machine --rpc-url http://127.0.0.1:38083 --rpc-user verifier \
  --rpc-password-file ./wallet-rpc-password reputation record-settlement \
  --network testnet --db ./reputation.sqlite --invoice-db ./invoices.sqlite \
  --invoice-id YOUR_PAID_INVOICE_ID --binding-file ./recipient-binding.json \
  --proof-file ./invoice-outproof.json --expected-machine-id YOUR_EXPECTED_RECIPIENT_ID
```

The result's `evidence_digest` can optionally be disclosed with an attestation
using `--evidence-digest`. It is not an imported verification flag. A verifier
using `--require-settlement` must independently have the corresponding local
observation for that subject/network. Public artifacts cannot import PAID state.
The SQLite store is a trusted local boundary: an attacker controlling it or the
wallet/daemon can fabricate local observations. Cryptographic artifact checking
does not solve host compromise.

Local observation fields are exactly `type=myt-recipient-settlement-observation`,
`version=1`, `network`, `subject_machine_id`, `transaction_digest`, `request_digest`,
`binding_digest`. Hashes use SHA-256 over domain plus canonical ASCII JSON:

| Digest | Domain (ASCII, trailing LF) | Canonical object |
| --- | --- | --- |
| transaction_digest | MYT-REPUTATION-TX-V1 | {network, txid} |
| request_digest | MYT-REPUTATION-REQUEST-V1 | Full existing PaymentRequest v1 object |
| binding_digest | MYT-REPUTATION-BINDING-V1 | Full existing Binding v1 object |
| evidence_digest | MYT-RECIPIENT-SETTLEMENT-V1 | Exact observation object above |

No raw transaction IDs, proofs, invoice metadata or addresses are stored in the
reputation DB. Hashes are linkable, not anonymization or zero-knowledge; known
inputs can be tested. Only distribute artifacts intentionally and protect local
databases/backups. One network/transaction and one network/request may contribute
at most one observation even if the recipient has several valid bindings.

## Scope and release gate

No Phase 4E REST routes are added. Existing authenticated 4D WSGI behavior is
unchanged; no remote private-key operations or unauthenticated import service.
No new runtime dependency: `cryptography>=50.0.0` and the Python standard library.
Official pyca wheels supply their bundled OpenSSL; source-build users must use a
patched supported OpenSSL. No Core, consensus, HF17, transaction format or Wallet
RPC schema changes. All 318 prior regression tests remain release gates.

Before release: full tests, separate 4A/4B/4C/4D regressions, Linux/Windows matrix,
floor/latest dependency audit, Ruff, Bandit, compileall, wheel/sdist, twine check,
metadata verification, clean-installed-wheel tests and this offline E2E. Normal
tests use deterministic read-only wallet fakes and do not send funds. A passing
mock bridge test must not be described as a new real-network payment test.
