# MYT Phase 4E validation

## Gate status

All local implementation, regression, platform, security and packaging gates
have passed. GitHub CI must also pass for the final candidate before a fast-forward
integration. No release publication is part of this milestone.

Repository: https://github.com/MYT-Core/MYT-Machine

Original main and peeled v0.4.0: `034e4576b4cd427f2f213e4fd0131104502c69f2`.
Baseline was clean; full unchanged suite: 318 tests passing before any code edit.
Existing distribution: myt-machine-settlement 0.4.0, cryptography>=50.0.0.
Branch: feature/phase4e-agent-reputation. Candidate version: 0.5.0.
Implementation commit: `a044ebf473c5252dab3951bfd631904a32c149d9`.
The validation-document commit changes only this report; the complete candidate
SHA is the enclosing Git commit. A document cannot embed its own future hash.
The delivery report records the resolved candidate/main SHAs and CI run results.
No tag, release, deployment or Phase 4F work is authorized by this gate.

## Architecture and semantics

Signed `ReputationArtifact` opinions/revocations reuse Phase 4B Ed25519 framing
and encrypted key handling. `ReputationStore` uses private bounded transactional
SQLite storage. `ReputationPolicy` computes deterministic local counts with an
empty default issuer allowlist. The read-only native 4C/4D bridge rechecks paid
invoice proof and exact recipient binding before storing a local observation.
CLI commands are additive; no new REST interface, runtime dependency or crypto.

The exact schema, domains, bytes, vector, replay semantics and disclosure limits
are in docs/reputation-attestation-v1.md and its machine-readable test vector.
The local policy, revocation authority, database trust boundary and capacity
limits are in docs/reputation-policy.md. docs/reputation.md contains the offline
E2E and the optional native Wallet RPC bridge usage.

## Security boundaries

Signatures attribute statements to issuer key controllers, not truth, independence,
legal identity, service quality or trustworthy time. Bindings do not prove when
authorization occurred or current/continued/exclusive key control. Payment proofs
never identify the payer Machine ID. Observations are recipient-linked, locally
trusted and neither portable certificates nor proof of complete history.

Self-opinions are rejected. Sybil/colluding issuers remain possible. Default local
policy accepts none, explicit allowlists and contribution caps are operator policy,
not MYT consensus. Many self-controlled transactions confer no automatic trust.
No global trust score, economic weights, registry, ZK, custom commitments or 4F.

Attestation ID and canonical digest uniqueness prevent transport replay; a native
transaction or invoice contributes only one observation per network. Signed
revocations retain the original opinion and work before target import without
letting unrelated issuers revoke it. Offline verifiers cannot discover unseen
revocations; signed timestamps are claims, not chronological proof.

The local database/host and configured wallet/daemon remain trusted. Corrupt
schemas, encodings, signatures and indexes fail closed, but a fully compromised
host can fabricate unsigned local observations. Reorgs are not continuously
monitored. Reputation hashes and signed disclosures are linkable. Raw transaction
IDs, invoice metadata, proofs, keys and RPC credentials are not persisted in the
reputation store. Generic get/list intentionally disclose public signed opinions;
summaries do not disclose payment history. Source-built cryptography still needs
a patched supported OpenSSL; the runtime floor remains 50.0.0.

## Adversarial review

Separate test_reputation_adversarial.py attacks fabricated PAID SQL rows,
concurrent event replay, evidence transplantation to another subject, repeated
opinions around one settlement, missing expected identity, corrupt digests and
summary history leaks. Other 4E tests cover forged signatures/bindings, canonical
ID substitutions, invalid native proofs, wrong networks, unknown issuers,
revocation pre-import attacks, file safety and structured secret-redacted CLI.
No successful forgery, duplicate counting or false payer attribution was found.

## Final local results

The complete suite contains **421 tests**: all **318 unchanged baseline tests**
and **103 new Phase 4E tests**. Separate installed-wheel phase runs also passed:

| Phase | Tests | Result |
| --- | ---: | --- |
| 4A settlement | 66 | PASS |
| 4B identity | 62 | PASS |
| 4C binding | 47 | PASS |
| 4D billing | 143 | PASS |
| 4E reputation | 103 | PASS |

The seven tests in test_reputation_adversarial.py are included in the 103, not
counted twice. Normal tests sent no funds and used deterministic read-only native
Wallet RPC fakes. The Phase 4E bridge was not represented as a new live Testnet
payment test; the complete existing 4D regression remains intact.

| Platform | Python | cryptography floor | Latest tested | Result per version |
| --- | --- | --- | --- | --- |
| Linux/WSL | 3.10.21 | 50.0.0 | 50.0.1 | 421 passed |
| Linux/WSL | 3.12.3 | 50.0.0 | 50.0.1 | 421 passed |
| Linux/WSL | 3.13.15 | 50.0.0 | 50.0.1 | 421 passed |
| Native Windows | 3.10.21 | 50.0.0 | 50.0.1 | 412 passed, 9 platform skips |
| Native Windows | 3.12.14 | 50.0.0 | 50.0.1 | 412 passed, 9 platform skips |
| Native Windows | 3.13.9 | 50.0.0 | 50.0.1 | 412 passed, 9 platform skips |

All twelve environments passed pip check and compileall. Windows skips cover
Unix permissions, symlinks and FIFO tests; they passed on Linux. cryptography
was installed from official PyPI wheels (files.pythonhosted.org), not a source
checkout or private package release. Version/install reports were retained in
the operator's external validation workspace. The runtime remains exactly
`cryptography>=50.0.0` with no additional runtime dependency.

Ruff 0.16.6: PASS. Bandit 1.9.4: PASS. pip-audit 2.10.1: no known vulnerabilities
in either floor or latest runtime environment and in the installed wheel
environment. The unpublished local distribution is explicitly skipped by
pip-audit's PyPI lookup; its source is covered by tests and static review, not
claimed to be audited by a vulnerability database. No advisories were suppressed.

Build 1.6.0 created wheel and sdist; twine 7.0.0 passed both. Wheel metadata requires
exactly `cryptography>=50.0.0`, distribution myt-machine-settlement, version 0.5.0.
All current package Python source bytes match the built wheel. Source distribution
contents include all reputation specifications, deterministic vector and test
helpers. Clean-wheel testing outside the source tree passed on Linux (421) and
native Windows (421 collected, 9 platform skips), including Windows CLI launcher.

The complete documented offline CLI E2E passed with a deliberately invalid RPC
environment: identity creation, signing, expected-issuer verification, import,
duplicate import, default and explicit policy, signed revocation and exclusion.
Passphrase and private-key marker scans of JSON output passed. No wallet, daemon,
blockchain, network dependency or funds are needed for these operations after
installation. Only the optional settlement-observation bridge queries trusted
Wallet RPC; it never signs or spends.

Personal-path, token and private-PEM scans of the 23 changed/new files passed.
The mathematical Python builtin `max` and CLI options `--max-age` and
`--max-per-issuer` are not personal names and were correctly distinguished from
personal-path matches. The RFC 8032 seed in the vector is explicitly public and
test-only, never a production secret. No unrelated tracked source/test changed.

## CI and integration

The workflow runs twelve Linux/Windows x Python 3.10/3.12/3.13 x floor/latest jobs,
one dependency/static audit and one dependent packaging/installed-wheel job.
Separate phase regression commands and 4E sdist checks were added. The existing
workflow permissions remain contents:read. There are no deployment or release
steps. All fourteen jobs must finish successfully before main integration.

The final delivered validation report includes the exact GitHub run URL, each job
conclusion, remote/local candidate equality and the fast-forward main SHA. If any
gate fails or main moves from the baseline unexpectedly, integration must stop.
No normal merge, rebase or force-push is needed for this feature.

## Changed files

```
.github/workflows/ci.yml
MANIFEST.in
MYT_Phase4E_Validation.md
README.md
pyproject.toml
docs/reputation.md
docs/reputation-policy.md
docs/reputation-attestation-v1.md
docs/reputation-attestation-v1-test-vector.json
src/myt_machine/__init__.py
src/myt_machine/cli.py
src/myt_machine/reputation.py
src/myt_machine/reputation_cli.py
src/myt_machine/reputation_files.py
src/myt_machine/reputation_policy.py
src/myt_machine/reputation_settlement.py
src/myt_machine/reputation_store.py
tests/reputation_fakes.py
tests/test_cli_reputation.py
tests/test_reputation_adversarial.py
tests/test_reputation_artifacts.py
tests/test_reputation_settlement.py
tests/test_reputation_store.py
```

## Required review record index

1. Original main: 034e4576b4cd427f2f213e4fd0131104502c69f2.
2. Candidate: implementation a044ebf473c5252dab3951bfd631904a32c149d9 plus this documentation-only commit; resolved final SHA in delivery record.
3. Architecture: immutable artifacts, private SQLite, local policy, optional read-only bridge.
4. Semantics: attributable evidence, not a universal score.
5. Fact/opinion/local-output separation: explicit separate summary sections.
6. Signature semantics: existing 4B frame with fixed 4E domains and canonical bytes.
7. Attestations prove issuer authorization of the statement.
8. They do not prove truth, independence, trust, legal identity, quality or time.
9. Sybil limits: allowlists/caps are local safeguards, not global resistance.
10. 4C: native SigV2 and identity signature verify the exact recipient relationship.
11. 4D: PAID plus fresh exact native proof and stored TXID match.
12. No payer Machine ID is inferred.
13. Storage: bounded private durable SQLite, one transaction per operation.
14. Replay: canonical ID/digest and per-network transaction/request uniqueness.
15. Revocation: signed issuer authority, pending import safe, original retained.
16. Policy: empty default allowlist, explicit as_of, age/caps/linkage, no weights.
17. Privacy: local-only intentional disclosure; hashes remain linkable.
18. 4F: stable hashes only, no ZK, accumulator or commitment construction.
19. Hostile review: no exploitable forgery, inflation or false attribution found within documented trust boundaries.
20. Tests: 421 total, all platform-appropriate tests pass.
21. 4A: 66 unchanged regression tests pass.
22. 4B: 62 unchanged regression tests pass.
23. 4C: 47 unchanged regression tests pass.
24. 4D: 143 unchanged regression tests pass.
25. 4E: 103 new tests pass, including 7 separate hostile-review cases.
26. Linux: all six matrix cells pass without skips.
27. Windows: all six cells pass with 9 explicitly platform-specific skips each.
28. Security: Ruff/Bandit/pip check/pip-audit/compileall pass, no new dependency.
29. Packaging: wheel/sdist/twine/metadata/clean-wheel tests and offline E2E pass.
30. CI: fourteen jobs required; exact runs/conclusions attached to delivery record.
31. Commits: implementation a044ebf473c5252dab3951bfd631904a32c149d9 and enclosing report-only commit, authored and committed by MYT-Core.
32. Final main: only the fully green candidate may be fast-forwarded; exact resolved SHA in delivery record.
33. Limitations: collusion, issuer lies, local host/wallet trust, revocation availability, linkability, no continuous reorg/liveness monitor.
34. Recommendation: eligible for independent release security review only after green candidate CI and verified integration; no tag or publication authorized.
