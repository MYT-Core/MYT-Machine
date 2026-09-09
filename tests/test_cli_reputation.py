import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reputation_fakes import ISSUER, OTHER, SUBJECT, attest

from myt_machine.cli import main
from myt_machine.errors import ConfigurationError, InputError
from myt_machine.identity_artifacts import save_public_identity
from myt_machine.identity_keys import save_private_identity
from myt_machine.reputation_files import (
    load_reputation_artifact,
    save_reputation_artifact,
)

PASSPHRASE = b"must-not-appear-secret-sentinel"


class ReputationCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.file = self.root / "attestation.json"
        self.db = self.root / "reputation.sqlite"
        save_reputation_artifact(attest(), self.file)

    def run_cli(self, *args, stdin="", **kwargs):
        output = io.StringIO()
        code = main(
            ["reputation", *map(str, args)],
            stdin=io.StringIO(stdin),
            stdout=output,
            environ={
                "MYT_WALLET_RPC_URL": "ftp://must-not-appear",
                "MYT_WALLET_RPC_PASSWORD": PASSPHRASE.decode(),
            },
            client_factory=lambda _: self.fail("Offline reputation attempted RPC"),
            **kwargs,
        )
        text = output.getvalue()
        result = json.loads(text)
        self.assertEqual(len(text.strip().splitlines()), 1)
        for sentinel in (
            PASSPHRASE.decode(),
            "must-not-appear",
            "PRIVATE KEY",
            str(self.root),
        ):
            self.assertNotIn(sentinel, text)
        return code, result

    def import_one(self):
        return self.run_cli(
            "import",
            "--network",
            "testnet",
            "--db",
            self.db,
            "--artifact-file",
            self.file,
        )

    def key_files(self):
        save_private_identity(ISSUER, self.root / "key.pem", PASSPHRASE)
        save_public_identity(ISSUER.public_identity, self.root / "identity.json")
        (self.root / "passphrase").write_bytes(PASSPHRASE + b"\n")
        (self.root / "passphrase").chmod(0o600)
        return [
            "--private-key-file",
            self.root / "key.pem",
            "--identity-file",
            self.root / "identity.json",
            "--passphrase-file",
            self.root / "passphrase",
        ]

    def test_verify_offline(self):
        rc, d = self.run_cli(
            "verify", "--network", "testnet", "--artifact-file", self.file
        )
        self.assertEqual(rc, 0)
        self.assertTrue(d["valid"])
        self.assertFalse(d["statement_truth_verified"])

    def test_expected_issuer_negative(self):
        rc, d = self.run_cli(
            "verify",
            "--network",
            "testnet",
            "--artifact-file",
            self.file,
            "--expected-issuer",
            OTHER.machine_id,
        )
        self.assertEqual(rc, 1)
        self.assertFalse(d["valid"])
        self.assertTrue(d["signature_valid"])

    def test_wrong_network(self):
        rc, d = self.run_cli(
            "verify", "--network", "mainnet", "--artifact-file", self.file
        )
        self.assertEqual(rc, 1)
        self.assertFalse(d["valid"])

    def test_stdin(self):
        rc, _ = self.run_cli(
            "verify",
            "--network",
            "testnet",
            "--artifact-file",
            "-",
            stdin=attest().encoded,
        )
        self.assertEqual(rc, 0)

    def test_bad_json_redacted(self):
        rc, _ = self.run_cli(
            "verify",
            "--network",
            "testnet",
            "--artifact-file",
            "-",
            stdin='{"must-not-appear": "must-not-appear"}',
        )
        self.assertEqual(rc, 2)

    def test_unsafe_passphrase_argv_rejected(self):
        rc, _ = self.run_cli("attest", "--passphrase", PASSPHRASE.decode())
        self.assertEqual(rc, 2)

    def test_no_overwrite(self):
        with self.assertRaises(ConfigurationError):
            save_reputation_artifact(attest(), self.file)
        self.assertEqual(load_reputation_artifact(self.file, io.StringIO()), attest())

    def test_missing_file(self):
        rc, _ = self.run_cli(
            "verify", "--network", "testnet", "--artifact-file", self.root / "absent"
        )
        self.assertEqual(rc, 2)

    def test_import_get_list(self):
        rc, imported = self.import_one()
        self.assertEqual(rc, 0)
        self.assertTrue(imported["inserted"])
        self.assertFalse(self.import_one()[1]["inserted"])
        rc, result = self.run_cli(
            "get", "--network", "testnet", "--db", self.db, "--id", attest().id
        )
        self.assertEqual(rc, 0)
        self.assertEqual(result["artifact"], attest().as_dict())
        rc, result = self.run_cli("list", "--network", "testnet", "--db", self.db)
        self.assertEqual(rc, 0)
        self.assertEqual(len(result["artifacts"]), 1)

    def test_get_not_found(self):
        self.import_one()
        rc, result = self.run_cli(
            "get",
            "--network",
            "testnet",
            "--db",
            self.db,
            "--id",
            attest(issued_at=1001).id,
        )
        self.assertEqual(rc, 1)
        self.assertFalse(result["found"])

    def test_summary_explicit_policy(self):
        self.import_one()
        args = [
            "summary",
            "--network",
            "testnet",
            "--db",
            self.db,
            "--subject",
            SUBJECT.machine_id,
            "--as-of",
            "2000",
        ]
        self.assertEqual(
            self.run_cli(*args)[1]["local_policy_output"]["accepted_attestations"], 0
        )
        rc, result = self.run_cli(*args, "--trusted-issuer", ISSUER.machine_id)
        self.assertEqual(rc, 0)
        self.assertEqual(result["local_policy_output"]["accepted_attestations"], 1)

    def test_read_typo_does_not_create_database(self):
        rc, _ = self.run_cli("list", "--network", "testnet", "--db", self.db)
        self.assertEqual(rc, 3)
        self.assertFalse(self.db.exists())

    def test_attest_with_protected_key(self):
        keys = self.key_files()
        output = self.root / "new.json"
        rc, result = self.run_cli(
            "attest",
            "--network",
            "testnet",
            *keys,
            "--subject",
            SUBJECT.machine_id,
            "--outcome",
            "NEGATIVE",
            "--issued-at",
            "1000",
            "--output-file",
            output,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(
            load_reputation_artifact(output, io.StringIO()).id, result["id"]
        )

    def test_wrong_passphrase(self):
        keys = self.key_files()
        (self.root / "passphrase").write_bytes(b"wrong-passphrase-long-enough")
        rc, _ = self.run_cli(
            "attest",
            "--network",
            "testnet",
            *keys,
            "--subject",
            SUBJECT.machine_id,
            "--outcome",
            "POSITIVE",
            "--output-file",
            self.root / "new.json",
        )
        self.assertEqual(rc, 3)
        self.assertFalse((self.root / "new.json").exists())

    def test_revoke_then_import(self):
        keys = self.key_files()
        self.import_one()
        output = self.root / "revoke.json"
        rc, _ = self.run_cli(
            "revoke",
            "--network",
            "testnet",
            *keys,
            "--artifact-file",
            self.file,
            "--issued-at",
            "1001",
            "--output-file",
            output,
        )
        self.assertEqual(rc, 0)
        rc, _ = self.run_cli(
            "import", "--network", "testnet", "--db", self.db, "--artifact-file", output
        )
        self.assertEqual(rc, 0)
        rc, result = self.run_cli(
            "summary",
            "--network",
            "testnet",
            "--db",
            self.db,
            "--subject",
            SUBJECT.machine_id,
            "--trusted-issuer",
            ISSUER.machine_id,
            "--as-of",
            "2000",
        )
        self.assertEqual(result["signed_opinions"]["revoked_attestations"], 1)
        self.assertEqual(result["local_policy_output"]["accepted_attestations"], 0)

    def test_partial_write_cleanup(self):
        output = self.root / "partial.json"
        with (
            patch(
                "myt_machine.reputation_files.os.fsync",
                side_effect=OSError("must-not-appear"),
            ),
            self.assertRaises(ConfigurationError) as caught,
        ):
            save_reputation_artifact(attest(), output)
        self.assertNotIn("must-not-appear", str(caught.exception))
        self.assertFalse(output.exists())

    @unittest.skipIf(os.name == "nt", "Unix modes")
    def test_file_mode(self):
        self.assertEqual(self.file.stat().st_mode & 0o777, 0o600)

    @unittest.skipIf(os.name == "nt", "Unix FIFO and symlink")
    def test_fifo_symlink_rejected(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(InputError):
            load_reputation_artifact(fifo, io.StringIO())
        link = self.root / "link"
        link.symlink_to(self.file)
        with self.assertRaises(InputError):
            load_reputation_artifact(link, io.StringIO())
