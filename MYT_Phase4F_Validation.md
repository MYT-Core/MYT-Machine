# MYT Phase 4F Official Candidate Validation

Date: 2026-09-20. Baseline: 73beb99102f56671d6b2d85c9368bfa788249dc2.
Branch: feature/phase4f-bbs-selective-disclosure. Main remains unchanged.
Python version: 0.5.1, not a release bump. These local feature artifacts are
NOT the published v0.5.1 files and must not replace them.

CRYPTO BACKEND EXTERNALLY QUALIFIED: NO.
EXTERNAL CRYPTO REVIEW REQUIRED: YES.

This is engineering evidence for an external-review candidate, not a production
release or a third-party cryptographic audit. GitHub CI is a separate mandatory
post-push gate; the final handoff must identify the exact feature SHA and run.
No merge, tag, release, PyPI publication or deployment is authorized.

## Architecture and precise claim

Optional separately packaged persistent Node loopback BBS companion; no
per-operation product subprocess spawning. Python retains all policy, actual
Phase 4E evidence, Phase 4B signing, canonical artifacts and SQLite replay state.
Existing 4A-4E operations neither require nor contact Node.

The verifier checks a trusted evaluator's signed assertion, not arithmetic
over a hidden committed integer. Only verified_recipient_settlement_events
is supported, at thresholds 1, 10, 25, 50 and 100. Exact count and full history
are not credentialized or disclosed. Four unrelated predicate booleans remain
hidden. Public subject/evaluator IDs, context and timestamps remain linkable.

Expected subject equality, exact not_before <= now < expires_at, native BBS
headers, signed issuer authorization/revocation, independent verifier policy,
4B subject control and consume-after-complete-verification are enforced.
Proof size is 400 bytes. No trusted-setup ceremony or new primitive is introduced.
A malicious trusted evaluator or compromised local host can invalidate trust
assumptions. Local revocation checking is not global discovery.

See docs/phase4f-protocol-v1.md, runtime architecture, codepath map, threat model,
audit-gap analysis and official-candidate-review-scope.md for exact bytes and scope.

## Continuation fixes and evidence

- Safety check reconfirmed local HEAD/main/origin-main and remote main at baseline.
  Remote feature branch was absent; no earlier commit was amended.
- Five new test SQLite connections are now closed deterministically with closing().
  No warning filters, stderr suppression or baseline hardening changes.
- Targeted Python 3.13: 64 new disclosure tests followed by 63 hardening tests
  in one process, 127 PASS on Linux and Windows, no ResourceWarnings.
- A nonprivileged Windows junction probe exposed an acceptance gap in the NEW
  disclosure private-parent check. New-only guards now reject reparse/symlink
  ancestors and reparse-marked input files/databases. No 4A-4E code changed.
- Two new cross-platform Python path tests and one native Node path test added.
  Junction creation ran without Administrator privileges or Developer Mode.
- A Windows clean-E2E helper initially wrote CRLF instead of canonical LF for its
  policy fixture. The product correctly rejected it. Fixed fixture byte writing,
  not parser rules. A PowerShell pip-stderr handling interruption was also corrected.
- Earlier failing diagnostic logs are retained outside the repo, not relabeled PASS.

## Automated test totals

Tracked baseline test files are byte-identical to baseline (git diff --exit-code).
The source version and runtime dependency floor are likewise unchanged.

| Suite | Linux | Native Windows |
| --- | --- | --- |
| Existing 4A/4B/4C/4D/4E/hardening | 487 PASS, 0 SKIP | 478 PASS, 9 documented platform SKIP |
| New permanent Python 4F | 66 PASS, 0 SKIP | 66 PASS, 0 SKIP |
| Full Python suite | 553 PASS, 0 SKIP | 544 PASS, 9 platform SKIP |
| Native Node suite, each supported version | 67 PASS, 0 SKIP | 67 PASS, 0 SKIP |
| Separate adversarial harness, each Python matrix row | 33 PASS | 33 PASS |
| Final separate valid-signature/transport attacks, clean wheel | 9 PASS | 9 PASS |
| Clean-wheel full suite | 553 PASS | 544 PASS, 9 platform SKIP |

Baseline breakdown remains 4A 66, 4B 62, 4C 47, 4D 143, 4E 106,
v0.5.1 hardening 63. Never report Windows as 487/487 PASS.
Exact nine test names, original reasons, alternative coverage and remaining
limitations: docs/phase4f-windows-platform-gates.md. No new skips are hidden.

The permanent and separate harness each exercise sixteen actual concurrent
processes consuming a real verified proof: exactly one success and fifteen
rejections. Restart replay, proof/request transplant, canonical header transport,
expected subject, issuer trust/revocation, corruption and secret redaction pass.

## Full local CI-equivalent matrix

Each row runs the full suite, separate 33 attacks, pip check and compileall.
The floor is cryptography 50.0.0; latest compatible public stable checked is 50.0.1.
Official version sources: https://pypi.org/pypi/cryptography/json and
https://nodejs.org/dist/index.json, checked 2026-09-20.

| Platform | Python | crypto floor | crypto latest |
| --- | --- | --- | --- |
| Linux | 3.10.21 | PASS | PASS |
| Linux | 3.12.3 | PASS | PASS |
| Linux | 3.13.15 | PASS | PASS |
| Windows native, non-admin | 3.10.21 | PASS | PASS |
| Windows native, non-admin | 3.12.14 | PASS | PASS |
| Windows native, non-admin | 3.13.9 | PASS | PASS |

These are the actual interpreter patch versions tested, not a claim that every
interpreter is the newest security patch. Deployment remains prohibited.
Node 24.20.0 floor and 24.21.0 current supported LTS each pass 67 native tests on
both OSes. Node floor additionally passes all 66 Python integration/path tests
and 33 adversarial cases on Python 3.12/cryptography 50.0.0 on both OSes.
No ResourceWarnings occur in final matrix logs.

## Security and supply chain

Ruff (src/tests and review helpers), Bandit (src), compileall and pip check pass.
pip-audit for cryptography 50.0.0 and 50.0.1 reports no known vulnerabilities in
their resolved graphs. npm audit reports zero vulnerabilities.
Registry archives match every SHA-512 shrinkwrap integrity; exact three-package
graph, licenses and source references are recorded in review evidence.
No install/preinstall/postinstall hooks or native binaries in inspected archives.
This is advisory/supply-chain evidence, not proof of absence of vulnerabilities.

- @digitalbazaar/bbs-signatures 3.1.0, BSD-3-Clause.
- @noble/curves 2.4.0, MIT.
- @noble/hashes 2.4.0, MIT.
- Python runtime requirement remains exactly cryptography>=50.0.0.
- No telemetry, runtime dependency downloads or extra remote networking in the
  new product boundary; authenticated loopback HTTP is explicit.

The additional final attacks use valid native signatures on future/expired
authorizations and credentials, a different subject and a false selected
predicate. They also test malformed authenticated JSON, an invalid capability,
and independent reconstruction of raw presentation-header bytes.

## Packaging and installed-artifact E2E

Wheel, sdist and explicit private companion tgz built locally. twine check
passes for Python distributions. Archive inspection finds no local private keys,
databases, personal absolute paths, research directories, external contributor
repositories, review harness, tests, node_modules or npm cache.
The sdist-rebuilt wheel payload matches the direct wheel entry-for-entry.
Python wheel does not contain or silently install Node.

Local validation-only SHA256 values:

    95023dde6b576fddff9f13b97dd187d72fb03ed85943a79bd5cf2b98d9b0b488  myt_machine_settlement-0.5.1-py3-none-any.whl
    1fb8ecd59c7e3dc3b52ab03006d66922866a59ceabd0cac6385868cf029afb9a  myt_machine_settlement-0.5.1.tar.gz
    78ef777c6e4ff2fd469c8caaca3913f43cddd136952ce0cfb6cc9a9826cf105b  myt-core-bbs-companion-0.6.0-dev.0.tgz

Clean-wheel E2E passes on Linux and native Windows, using a separately unpacked
locked companion, two fresh 4B identities, actual Phase 4E store/policy/summary,
credential issuance, independent verifier state, presentation and a keyless
verifier companion. Wrong audience and repeated consumption fail.
13 CLI responses are individually parsed and checked for secret sentinels.
Public historical vector framing, native credential signature and proof verify.
The vector's expired timestamps are NOT bypassed for live authentication.

E2E uses 37 synthetic, explicitly test-seeded local observations; it does not
claim new real blockchain payments. No Wallet RPC, daemon, funds, blockchain,
Testnet or Mainnet network access is needed or performed.
Private secrets are ephemeral; no passphrase, capability or private-key block
was observed in the tested normal JSON results.

Reproduce with an installed candidate wheel, explicit Node and separately
unpacked companion:

    python review/phase4f/clean_wheel_e2e.py --node NODE --companion-entry COMPANION/package/src/cli.mjs --vector docs/phase4f-header-vector.json

Run the local matrix with review/phase4f/run_matrix.py, isolated --environments,
new --logs directory and explicit --node-floor/--node-current paths.
Windows source-copy content is hash-checked; neither test command imports
another product checkout instead of the intended candidate.

## CI and publication boundary

Workflow keeps all twelve OS/Python/cryptography matrix jobs and adds four
Node/platform jobs. Security and packaging jobs make eighteen total.
CI includes old regressions, new native/integration tests, both adversarial
harnesses, archive inspection and packed-companion clean-wheel CLI E2E.
No deployment or publish step exists.
GitHub-hosted results are authoritative only after the feature commit is pushed;
the final report must supply that run URL, all results and remote SHA equality.
A successful local result alone must not be reported as hosted CI PASS.

## Contribution and research preservation

Public-handle credit: fallacyofall, architecture and adversarial-review references.
No inferred legal name, cherry-pick or blind repository import.
The earlier research records remain historical evidence, explicitly not current
production approval. Original six research-file hashes in the separate research
worktree remain unchanged. This report replaces only the FEATURE-COPY summary.

## Release prohibition

No release checklist item may substitute for independent qualification.
Before any future main integration or release: external exact-composition crypto
review, resolution/retest of findings and separate express authorization.
No merge/tag/release/PyPI/deployment in this task.
