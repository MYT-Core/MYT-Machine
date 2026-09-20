"""Installed-wheel CLI E2E with explicit packed companion; synthetic evidence only."""
import argparse
import base64
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import myt_machine
from myt_machine import ReputationPolicy, ReputationStore
from myt_machine.disclosure_artifacts import base_messages, credential_messages
from myt_machine.disclosure_backend import BbsBackend, DisclosureBackendError

parser = argparse.ArgumentParser()
parser.add_argument("--node", required=True)
parser.add_argument("--companion-entry", required=True)
parser.add_argument("--vector", required=True)
args = parser.parse_args()
assert "site-packages" in str(Path(myt_machine.__file__)), "Must use installed wheel, not src"
assert myt_machine.__version__ == "0.5.1"
env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "NODE_PATH", "NODE_OPTIONS")}
env["MYT_WALLET_RPC_URL"] = "ftp://must-not-appear"
env["PYTHONUTF8"] = "1"
outputs = []
process = None


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


with tempfile.TemporaryDirectory(prefix="myt-clean-wheel-") as directory:
    root = Path(directory)
    root.chmod(0o700)
    phrase = secrets.token_hex(32)
    password = root / "passphrase"
    password.write_text(phrase + "\n", encoding="ascii")
    password.chmod(0o600)
    token, key = root / "capability", root / "bbs-key.json"
    log = (root / "companion.log").open("wb")

    def cli(*values, expected=0):
        done = subprocess.run(
            [sys.executable, "-m", "myt_machine", *map(str, values)],
            env=env, cwd=root, capture_output=True, timeout=40, check=False,
        )
        assert done.returncode == expected, ("CLI failed", values[0:2], done.returncode)
        assert not done.stderr, "Unexpected stderr"
        text = done.stdout.decode("utf-8")
        assert phrase not in text and "must-not-appear" not in text
        assert "PRIVATE KEY" not in text and "message_digest" not in text
        outputs.append(text)
        return json.loads(text)

    def node(*values):
        done = subprocess.run(
            [args.node, args.companion_entry, *map(str, values)],
            env=env, cwd=root, capture_output=True, timeout=40, check=False,
        )
        assert done.returncode == 0 and not done.stderr, "Companion CLI failed"
        assert phrase.encode() not in done.stdout
        return json.loads(done.stdout)

    def start(signing):
        global process
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        values = ["serve", "--port", str(port), "--token-file", str(token)]
        if signing:
            values += ["--key-file", str(key), "--passphrase-file", str(password)]
        process = subprocess.Popen(
            [args.node, args.companion_entry, *values], env=env, cwd=root,
            stdout=log, stderr=log,
        )
        backend = BbsBackend(url=f"http://127.0.0.1:{port}", token_file=token)
        for _ in range(100):
            try:
                result = backend.call("hello", {})
                assert result["signing"] is signing
                return [f"http://127.0.0.1:{port}", backend]
            except DisclosureBackendError:
                if process.poll() is not None:
                    break
                time.sleep(0.1)
        raise AssertionError("Companion readiness failed")

    def stop():
        global process
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
            process = None

    try:
        identities = {}
        for name in ("evaluator", "subject"):
            result = cli(
                "identity", "create", "--private-key-file", root / (name + ".pem"),
                "--identity-file", root / (name + ".json"), "--passphrase-file", password,
            )
            identities[name] = json.loads((root / (name + ".json")).read_text())["machine_id"]

        def identity(name):
            return ["--private-key-file", root / (name + ".pem"),
                    "--identity-file", root / (name + ".json"), "--passphrase-file", password]

        node("token-create", "--token-file", token)
        node("key-create", "--key-file", key, "--passphrase-file", password)
        url, backend = start(True)

        def backend_options():
            return ["--bbs-url", url, "--bbs-token-file", token]

        authorization = root / "authorization.json"
        auth = cli("disclosure", "authorize", *identity("evaluator"), *backend_options(),
                   "--network", "testnet", "--output-file", authorization)["artifact"]
        state = root / "issuer.sqlite"
        verifier = root / "verifier.sqlite"

        def status(path, *extra):
            return cli("disclosure", "issuer-status", "--state-db", path,
                       "--authorization-file", authorization,
                       "--expected-evaluator", identities["evaluator"], *extra)

        status(state)
        status(verifier)
        reputation = root / "reputation.sqlite"
        store = ReputationStore(reputation)
        for index in range(37):
            store._record_settlement({
                "type": "myt-recipient-settlement-observation", "version": 1,
                "network": "testnet", "subject_machine_id": identities["subject"],
                "transaction_digest": f"{index:064x}",
                "request_digest": f"{index + 1000:064x}", "binding_digest": "f" * 64,
            })
        policy_file = root / "policy.json"
        policy_file.write_bytes((canonical(ReputationPolicy().as_dict()) + "\n").encode("ascii"))
        digest = cli("disclosure", "policy-digest", "--reputation-policy-file", policy_file)["policy_digest"]
        policy = [
            "--expected-subject", identities["subject"], "--expected-evaluator", identities["evaluator"],
            "--expected-key-id", auth["statement"]["bbs_key_id"], "--network", "testnet",
            "--audience", "clean-wheel.example", "--policy-digest", digest, "--threshold", "25",
        ]
        credential = root / "credential.json"
        cred = cli("disclosure", "issue", *identity("evaluator"), *backend_options(),
                   "--authorization-file", authorization, "--state-db", state,
                   "--reputation-policy-file", policy_file, "--reputation-db", reputation,
                   "--subject", identities["subject"], "--output-file", credential)["artifact"]
        assert cred["claims"]["predicates"] == [True, True, True, False, False]
        assert "metric_value" not in cred["claims"]
        request, presentation = root / "request.json", root / "presentation.json"
        cli("disclosure", "request", *policy, "--state-db", verifier, "--output-file", request)
        proof = cli("disclosure", "present", *policy, *identity("subject"), *backend_options(),
                    "--state-db", state, "--credential-file", credential,
                    "--request-file", request, "--output-file", presentation)["artifact"]
        assert "predicates" not in proof["claims"] and "metric_value" not in proof["claims"]
        assert len(base64.urlsafe_b64decode(proof["proof"] + "==")) == 400
        stop()
        url, backend = start(False)
        common = ["disclosure", "verify", *policy, *backend_options(),
                  "--state-db", verifier, "--artifact-file", presentation]
        wrong = cli(*common, "--audience", "wrong.example", expected=1)
        assert wrong["valid"] is False and wrong["consumed"] is False
        good = cli(*common)
        assert good["valid"] is True and good["consumed"] is True
        replay = cli(*common, expected=1)
        assert replay["valid"] is False and replay["consumed"] is False
        cli("disclosure", "show", "--artifact-file", presentation)

        # A public historical crypto vector is not a current-time authentication.
        vector = json.loads(Path(args.vector).read_text(encoding="utf-8"))
        public = vector["presentation"]
        header = b"MYT-REPUTATION-DISCLOSURE-PRESENTATION-V1\n" + canonical(vector["request"]).encode()
        assert header.hex() == vector["presentation_header_hex"]
        assert base64.urlsafe_b64encode(header).decode().rstrip("=") == vector["presentation_header_base64url"]
        public_key = public["authorization"]["statement"]["bbs_public_key"]
        assert backend.call("verify-signature", {
            "public_key": public_key, "signature": vector["credential"]["signature"],
            "messages": credential_messages(vector["credential"]),
        }) == {"valid": True}
        assert backend.call("verify-proof", {
            "public_key": public_key, "proof": public["proof"],
            "messages": base_messages(public["authorization"], public["claims"]) + ["true"],
            "request": vector["request"], "threshold": vector["request"]["threshold"],
            "presentation_header": vector["presentation_header_base64url"],
        }) == {"valid": True}
        capability = token.read_text().strip()
        for text in outputs:
            assert capability not in text and phrase not in text
        print(json.dumps({
            "installed_wheel": True, "version": myt_machine.__version__,
            "separate_packed_companion": True, "keyless_verifier": True,
            "identity_to_real_phase4e_store_to_credential_to_disclosure": True,
            "synthetic_observations": True, "no_wallet_daemon_blockchain": True,
            "negative_audience": True, "durable_replay": True, "secret_redaction": True,
            "public_vector_native_verification": True, "proof_bytes": 400,
            "cli_json_documents": len(outputs), "crypto_external_qualification": False,
        }, sort_keys=True))
    finally:
        stop()
        log.close()
