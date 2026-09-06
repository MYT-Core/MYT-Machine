# PR #1 review before integration

Reviewed source: `fallacyofall/MYT-Machine`, branch
`phase4d-payment-requests`, commit
`9068e60946faa5f2250455e37a04250b677d4704`.
Official base: `e996c4388b3495ffd1fecb6fe1b868b67ae106e9` (`v0.3.0`).
The head has not moved from the task's expected SHA. One contributor commit,
462 insertions and one deletion, was inspected in full before executing tests.

| File | Added | Deleted |
| --- | ---: | ---: |
| `docs/payment_requests.md` | 22 | 0 |
| `src/myt_machine/__init__.py` | 17 | 1 |
| `src/myt_machine/payment_requests.py` | 272 | 0 |
| `tests/test_payment_requests.py` | 151 | 0 |

## Findings

1. Payment requests carry imported mutable `PAID` state. This is untrusted
   payer-facing input, not evidence of settlement. Persistent local invoice
   state must be separate and only advance after verified payment evidence.
2. No network field exists. An artifact cannot be safely used by a service
   configured for a specific MYT network without an explicit network check.
3. JSON accepts duplicate keys, unknown fields, a floating version `1.0`,
   unbounded artifacts, and unbounded parsed timestamps. Canonical output
   alone does not make an ambiguous parser safe.
4. The public dataclass constructor bypasses factory validation. Serialization
   can emit invalid amounts and states from directly constructed instances.
5. Address validation accepts arbitrary non-whitespace text; the tests use a
   placeholder which is not a MYT address. Offline syntactic validation and
   native, network-aware Wallet RPC validation must be distinguished.
6. `invoice_id or uuid4()` silently substitutes an empty or false supplied ID;
   IDs also permit control characters/path separators.
7. The 18 new tests use pytest, whereas the official CI runs unittest without
   installing pytest. They are not integrated into the official regression gate.
8. No persistence, transaction uniqueness, confirmation policy or actual
   verification adapter is implemented. These were explicitly deferred in the PR.

No malicious code, subprocesses, RPC/network calls, spending, credential reads,
seed/private-key access, workflow/package changes, binary/generated files or
new runtime dependencies occur in the reviewed diff. Its useful contribution is
the small non-custodial request factory, exact positive uint64 amounts,
deterministic JSON, expiry boundary and read-only verifier abstraction.

## Integration decision

Independent local results: all 18 contributor tests pass; pytest runs 193
tests (175 existing + 18 new). The official unittest command runs only 175
when pytest happens to be installed, and otherwise fails importing the new
test module. Ruff reports three fixable issues. Bandit and wheel/sdist plus
twine checks pass. GitHub initially reports `ACTION_REQUIRED` for run
`33985280237`; this is not a successful CI result. After reviewing the unchanged
workflow, execution was approved so its actual results can be recorded.

The completed run is FAILURE: all 12 matrix jobs failed at Unit and CLI tests,
the audit job failed Static checks (three Ruff findings), and the packaging job
was skipped. The dependency-audit step itself passed. This is a real failing
gate, not ACTION_REQUIRED and not a success. Replacement CI must pass separately.

The unpublished request schema requires a substantive correctness redesign.
Direct merge is deferred; the official implementation adapts these concepts and
selected validation/factory code with explicit contributor attribution. The
original PR and commit remain intact. Supersession will occur only after the
replacement's test, security and packaging gates pass.

Credit: **fallacyofall**, PR #1. The official implementation commit will include
the contributor's original `Co-authored-by` identity. No contributor commits
will be amended or force-pushed.

## Fresh review of the contributor update

The first integration attempt stopped without committing/pushing because the
head moved. After explicit authorization, the current head was fetched and
fully reviewed anew:
`41e0e6b78da4f6ca75f6fc5cf8059327f9b1c8ee`.
Base remains `e996c4388b3495ffd1fecb6fe1b868b67ae106e9`.

Delta from `9068e60946faa5f2250455e37a04250b677d4704`: one commit,
`fix phase4d CI compatibility`, two files, 133 additions / 132 deletions:

- `src/myt_machine/payment_requests.py`: Mapping moves to collections.abc and
  two quoted return annotations become postponed annotations. Runtime request
  validation, serialization, amount, expiry and state logic are unchanged.
- `tests/test_payment_requests.py`: pytest functions become unittest methods;
  four parametrized invalid-amount cases become four explicit test methods.
  The empty dummy-verifier dataclass decorator is removed, an unused argument
  discarded, and unittest.main added. All original 18 cases remain represented.

No unrelated files, mode changes, Unicode tricks, dependencies, workflows,
packaging edits, file/network/subprocess access, secrets or spending were added.
The complete current PR still contains exactly the same four paths; its total
diff against main is now 463 additions / one deletion (the module is 273 lines).

Independent fresh environment without pytest: 18/18 contributor unittest tests
(0.003 s), 193/193 full tests (6.627 s), no failures/skips. Ruff, Bandit,
compileall, pip check, pip-audit, wheel/sdist build and twine all passed.
GitHub run [34039805952](https://github.com/MYT-Core/MYT-Machine/actions/runs/34039805952)
was safely approved after review and completed SUCCESS: 12 matrix jobs,
dependency/static audit and packaging. The contributor's fix claim is CONFIRMED.

Fresh behavior probes nevertheless confirmed that a claimed PAID state can be
imported without evidence, version 1.0 and unknown fields are accepted, a direct
constructor accepts a negative amount, and network binding is absent. These are
unchanged architectural findings, not malicious changes or failed CI fixes.
The passing current PR is superseded for these documented design reasons, not
because its already-fixed CI problem is being treated as current. Useful code
and concepts remain credited; the original contributor history is preserved.
Formal closure follows only after replacement validation and CI have passed.
