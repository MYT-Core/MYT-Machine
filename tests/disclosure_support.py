"""Real optional companion fixtures. Test-only process spawning, never product code."""

import os
import secrets
import socket
import subprocess
import time
from pathlib import Path

from myt_machine.disclosure_backend import BbsBackend, DisclosureBackendError


class CompanionFixture:
    def __init__(self, root):
        self.root = Path(root)
        self.node = os.environ.get("MYT_TEST_NODE")
        if not self.node:
            raise RuntimeError(
                "Phase 4F integration tests require explicit MYT_TEST_NODE"
            )
        self.entry = Path(__file__).resolve().parents[1] / "companions/bbs/src/cli.mjs"
        self.token = self.root / "capability"
        self.password = self.root / "passphrase"
        self.key = self.root / "bbs-key.json"
        self.password.write_text(secrets.token_hex(32) + "\n", encoding="ascii")
        self.password.chmod(0o600)
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("NODE_OPTIONS", "NODE_PATH")
        }
        self.env = env
        self._run("token-create", "--token-file", str(self.token))
        self._run(
            "key-create",
            "--key-file",
            str(self.key),
            "--passphrase-file",
            str(self.password),
        )
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{port}"
        self.log = (self.root / "service.log").open("wb")
        self.process = subprocess.Popen(
            [
                self.node,
                str(self.entry),
                "serve",
                "--port",
                str(port),
                "--token-file",
                str(self.token),
                "--key-file",
                str(self.key),
                "--passphrase-file",
                str(self.password),
            ],
            env=env,
            stdout=self.log,
            stderr=self.log,
        )
        self.backend = None
        for _ in range(100):
            if self.process.poll() is not None:
                break
            try:
                backend = BbsBackend(url=self.url, token_file=self.token)
                backend.call("hello", {})
                self.backend = backend
                break
            except DisclosureBackendError:
                time.sleep(0.1)
        if self.backend is None:
            self.close()
            raise RuntimeError("Test companion did not become ready")

    def _run(self, *args):
        result = subprocess.run(
            [self.node, str(self.entry), *args],
            env=self.env,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if result.returncode:
            raise RuntimeError("Test companion initialization failed")

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()
