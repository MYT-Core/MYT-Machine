# Windows platform gate, 2026-09-20

The baseline is 73beb99102f56671d6b2d85c9368bfa788249dc2.
All tracked baseline test files are byte-identical to that commit:
git diff --exit-code BASELINE -- tests returned zero with empty output.
The nine skips below are existing behavior, not new Phase 4F skip conditions.
Do not edit those tests, suppress warnings or enable administrator/developer
privileges to turn these skips into artificial passes.

Expected old-suite totals: Linux 487 PASS; native Windows 478 PASS + 9 SKIP.
The complete suite adds 66 new Python tests. None of those may skip locally.
GitHub Windows runners may permit symlink creation and run more baseline tests;
that is not a reason to force a skip. Ordinary unittest failures always fail CI.

| Baseline test | Exact skip reason | Platform category | Windows coverage / remaining limitation |
| --- | --- | --- | --- |
| test_binding_artifacts.BindingArtifactTests.test_load_rejects_missing_directory_and_symlink | Symlinks are not available | Symlink creation privilege | Missing/nonregular cases run before this runtime skip. Legacy file-symlink rejection is not practically exercised in this environment; no equivalent claim. |
| test_cli_reputation.ReputationCliTests.test_fifo_symlink_rejected | Unix FIFO and symlink | FIFO and links | Windows has no Unix FIFO API. Other regular-file, schema and no-overwrite checks run; this exact old path is not exercised. |
| test_cli_reputation.ReputationCliTests.test_file_mode | Unix modes | POSIX 0600 | Windows requires operator-controlled NTFS ACLs. Exclusive creation is tested, but chmod is not proof of equivalent ACL protection. |
| test_identity_artifacts.IdentityArtifactTests.test_load_rejects_missing_nonregular_and_symlink_files | Symlinks are not available | Symlink creation privilege | Missing/nonregular cases run before skip. The exact legacy symlink case remains untested locally. |
| test_identity_keys.IdentityKeyTests.test_private_key_must_be_regular_nonsymlink_and_mode_0600 | Unix permission checks do not apply on Windows | POSIX mode and symlink | Encrypted PKCS8, wrong password, bounds and no-overwrite tests run. NTFS ACL equivalence and this exact legacy link case are not claimed. |
| test_invoice_store.InvoiceStoreTests.test_private_database_permissions | Unix permissions | POSIX 0600 | Database transactions and no-overwrite/corruption tests run; ACL administration remains operator responsibility. |
| test_invoice_store.InvoiceStoreTests.test_symlink_database_rejected | Unix symlink setup | Symlink | Legacy SQLite link case not exercised in this Windows configuration; new 4F path tests do not retroactively qualify it. |
| test_reputation_store.ReputationStoreTests.test_permissions | Unix mode enforcement | POSIX mode | State integrity/replay validation still runs; ACL equivalence not tested. |
| test_reputation_store.ReputationStoreTests.test_symlink_hardlink | Unix links | Link setup | New 4F hardlink tests run natively without privilege, but do not replace this legacy module's skipped test. |

Machine-readable exact allowlist: review/phase4f/windows-baseline-skips.json.
The local final matrix validates the full names AND reasons. Any additional,
changed or missing expected local skip fails its gate. The runner also rejects
ResourceWarnings; it never filters or suppresses them.

## New native, nonprivileged path checks

An explicit Windows directory-junction probe found that checking S_ISDIR alone
accepted a junction parent in the new Python 4F helper. Fixed only the new
disclosure boundary: reject reparse-point metadata and symlinks in every
ancestor; reject reparse-marked file/database inputs. Node rejects directory
links at every ancestor as well.

Permanent new tests create a Windows junction with ordinary mklink /J, not a
symbolic link requiring Developer Mode. They test immediate and nested linked
parents and assert no state file is created in the redirected target.
On Linux the same tests exercise directory symlinks.
Both platforms also test hardlinked private input/database files.
The Node test independently exercises linked parents for read and exclusive
write. Neither test path contains a skip.

This is not a complete NTFS reparse-tag taxonomy or a race-proof sandbox.
No custom filter-driver/cloud reparse points were installed or qualified.
Trusted private directories and ACLs remain required; hostile same-user/root
directory replacement is outside the documented boundary.

## SQLite test hygiene

Five new corruption tests used sqlite3.Connection as a transaction context but
did not close it. They now nest the transaction context inside contextlib.closing.
Production SQLite logic and baseline stderr tests were not weakened.
Python 3.13 ran the new disclosure tests followed by all 63 hardening tests in
one process: 127 PASS on both Linux and native Windows, no ResourceWarnings.
Final full-matrix evidence is recorded in MYT_Phase4F_Validation.md.
