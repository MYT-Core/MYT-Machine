"""Nonprivileged path-safety checks, including native Windows junctions."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from myt_machine.disclosure_files import private_parent, read_regular
from myt_machine.disclosure_store import DisclosureStore
from myt_machine.errors import ConfigurationError


class DisclosurePathTests(unittest.TestCase):
    def test_directory_link_and_link_ancestor_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir(mode=0o700)
            (target / "child").mkdir(mode=0o700)
            link = root / "link"
            if os.name == "nt":
                result = subprocess.run(
                    ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(
                    result.returncode, 0, "Nonprivileged junction creation failed"
                )
            else:
                link.symlink_to(target, target_is_directory=True)
            try:
                for path in (link / "state", link / "child" / "state"):
                    with self.subTest(ancestor=path.parent.name):
                        with self.assertRaises(ConfigurationError):
                            private_parent(path)
                        with self.assertRaises(ConfigurationError):
                            DisclosureStore(path)
                self.assertFalse((target / "state").exists())
                self.assertFalse((target / "child" / "state").exists())
            finally:
                if os.name == "nt":
                    link.rmdir()
                else:
                    link.unlink()

    def test_regular_file_hardlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "original"
            original.write_bytes(b"not-a-secret")
            original.chmod(0o600)
            link = root / "hardlink"
            os.link(original, link)
            for path in (original, link):
                with self.subTest(path=path.name):
                    with self.assertRaises(ConfigurationError):
                        read_regular(path, private=True)
                    with self.assertRaises(ConfigurationError):
                        DisclosureStore(path)
