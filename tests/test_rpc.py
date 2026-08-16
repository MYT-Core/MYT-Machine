import contextlib
import hashlib
import hmac
import json
import socket
import threading
import time
import unittest
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import parse_http_list, parse_keqv_list

from myt_machine.errors import (
    ConfigurationError,
    RpcAuthenticationError,
    RpcProtocolError,
    RpcTransportError,
    WalletRpcError,
)
from myt_machine.rpc import RpcConfig, WalletRpcClient

DIGEST_REALM = "monero-rpc"
DIGEST_USER = "agent"
DIGEST_PASSWORD = "secret"


class _RpcHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        return

    def _write(self, status, body=b"", headers=None):
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            pass

    def _digest_challenge(self):
        if not hasattr(self, "digest_nonce"):
            self.digest_nonce = f"nonce-{id(self):x}"
        self.send_response(401)
        self.send_header("Content-Length", "0")
        self.send_header(
            "WWW-Authenticate",
            (
                f'Digest qop="auth",algorithm=MD5,realm="{DIGEST_REALM}",'
                f'nonce="{self.digest_nonce}",stale=false'
            ),
        )
        self.send_header(
            "WWW-Authenticate",
            (
                f'Digest qop="auth",algorithm=MD5-sess,realm="{DIGEST_REALM}",'
                f'nonce="{self.digest_nonce}",stale=false'
            ),
        )
        self.end_headers()

    def _valid_digest(self, authorization):
        if not isinstance(authorization, str) or not authorization.startswith("Digest "):
            return False
        if not hasattr(self, "digest_nonce"):
            return False
        try:
            fields = parse_keqv_list(
                filter(None, parse_http_list(authorization.removeprefix("Digest ")))
            )
            username = fields["username"]
            realm = fields["realm"]
            nonce = fields["nonce"]
            uri = fields["uri"]
            response = fields["response"]
            qop = fields["qop"]
            nonce_count = fields["nc"]
            cnonce = fields["cnonce"]
        except (KeyError, TypeError, ValueError):
            return False
        if (
            username != DIGEST_USER
            or realm != DIGEST_REALM
            or nonce != self.digest_nonce
            or uri != self.path
            or qop != "auth"
        ):
            return False

        def md5(value):
            return hashlib.md5(value.encode("utf-8"), usedforsecurity=False).hexdigest()

        ha1 = md5(f"{DIGEST_USER}:{DIGEST_REALM}:{DIGEST_PASSWORD}")
        ha2 = md5(f"POST:{self.path}")
        expected = md5(
            f"{ha1}:{self.digest_nonce}:{nonce_count}:{cnonce}:auth:{ha2}"
        )
        return hmac.compare_digest(response, expected)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = None
        authorization = self.headers.get("Authorization")
        self.server.requests.append(  # type: ignore[attr-defined]
            {
                "path": self.path,
                "authorization": authorization,
                "payload": payload,
                "handler_id": id(self),
            }
        )
        mode = self.server.mode  # type: ignore[attr-defined]

        if mode in {"digest", "auth_fail"}:
            if authorization is None:
                self._digest_challenge()
                return
            if mode == "auth_fail" or not self._valid_digest(authorization):
                self._digest_challenge()
                return
        if mode == "timeout":
            time.sleep(0.2)
        if mode == "malformed":
            self._write(200, b"{not-json")
            return
        if mode == "oversized":
            self._write(200, b"x" * 2048)
            return

        request_id = payload.get("id") if isinstance(payload, dict) else None
        if mode == "wrong_id":
            request_id = "different"
        if mode == "rpc_error":
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -17, "message": "not enough money"},
            }
        else:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"height": 123, "ok": True},
            }
        encoded = json.dumps(response).encode("utf-8")
        self._write(200, encoded, {"Content-Type": "application/json"})


@contextlib.contextmanager
def rpc_server(mode="success") -> Iterator[tuple[str, ThreadingHTTPServer]]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RpcHandler)
    server.daemon_threads = True
    server.mode = mode  # type: ignore[attr-defined]
    server.requests = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class RpcConfigTests(unittest.TestCase):
    def test_password_is_redacted_from_repr(self):
        config = RpcConfig(username="agent", password="top-secret")
        self.assertNotIn("top-secret", repr(config))

    def test_credentials_must_be_paired(self):
        with self.assertRaises(ConfigurationError):
            RpcConfig(username="agent")
        with self.assertRaises(ConfigurationError):
            RpcConfig(password="secret")

    def test_remote_plain_http_requires_opt_in(self):
        with self.assertRaises(ConfigurationError):
            RpcConfig(url="http://example.com:39083")
        config = RpcConfig(url="http://example.com:39083", allow_insecure_http=True)
        self.assertEqual(config.url, "http://example.com:39083")

    def test_loopback_http_is_allowed(self):
        for url in (
            "http://127.0.0.1:39083",
            "http://[::1]:39083/",
            "http://localhost:39083",
            "http://localhost.:39083",
        ):
            with self.subTest(url=url):
                RpcConfig(url=url)

    def test_unsafe_url_components_are_rejected(self):
        invalid = (
            "ftp://127.0.0.1:39083",
            "http://user:pass@127.0.0.1:39083",
            "http://127.0.0.1:39083/json_rpc",
            "http://127.0.0.1:39083?x=1",
            "http://127.0.0.1:39083#fragment",
            "http://127.0.0.1:bad",
        )
        for url in invalid:
            with self.subTest(url=url), self.assertRaises(ConfigurationError):
                RpcConfig(url=url)

    def test_timeout_bounds(self):
        for timeout in (0, -1, 301, True, "10"):
            with self.subTest(timeout=timeout), self.assertRaises(ConfigurationError):
                RpcConfig(timeout=timeout)  # type: ignore[arg-type]

    def test_security_configuration_types_are_strict(self):
        invalid = (
            {"allow_insecure_http": "false"},
            {"username": 1, "password": "secret"},
            {"username": "agent", "password": 1},
            {"username": "agent\nother", "password": "secret"},
            {"username": "agent", "password": "secret\nother"},
        )
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(ConfigurationError):
                RpcConfig(**values)  # type: ignore[arg-type]

    def test_response_limit_is_bounded(self):
        for limit in (1023, 16_777_217, True, "1024"):
            with self.subTest(limit=limit), self.assertRaises(ConfigurationError):
                RpcConfig(max_response_bytes=limit)  # type: ignore[arg-type]

    def test_empty_credentials_are_rejected(self):
        for username, password in (("", "secret"), ("agent", "")):
            with self.subTest(username=username), self.assertRaises(ConfigurationError):
                RpcConfig(username=username, password=password)


class WalletRpcClientTests(unittest.TestCase):
    def test_successful_request(self):
        with rpc_server() as (url, server):
            client = WalletRpcClient(RpcConfig(url=url))
            result = client.call("get_height", {})
        self.assertEqual(result["height"], 123)
        request = server.requests[0]  # type: ignore[attr-defined]
        self.assertEqual(request["path"], "/json_rpc")
        self.assertEqual(request["payload"]["method"], "get_height")
        self.assertEqual(request["payload"]["params"], {})

    def test_digest_authentication_handshake_is_connection_scoped(self):
        with rpc_server("digest") as (url, server):
            client = WalletRpcClient(
                RpcConfig(url=url, username=DIGEST_USER, password=DIGEST_PASSWORD)
            )
            result = client.call("get_height")
        self.assertEqual(result["height"], 123)
        requests = server.requests  # type: ignore[attr-defined]
        self.assertEqual(len(requests), 2)
        self.assertIsNone(requests[0]["authorization"])
        self.assertTrue(requests[1]["authorization"].startswith("Digest "))
        self.assertEqual(requests[0]["handler_id"], requests[1]["handler_id"])

    def test_authenticated_mutation_reaches_application_once(self):
        with rpc_server("digest") as (url, server):
            client = WalletRpcClient(
                RpcConfig(url=url, username=DIGEST_USER, password=DIGEST_PASSWORD)
            )
            client.call("transfer", {}, mutation=True)
        authorized = [
            request
            for request in server.requests  # type: ignore[attr-defined]
            if request["authorization"] is not None
        ]
        self.assertEqual(len(authorized), 1)
        self.assertEqual(authorized[0]["payload"]["method"], "transfer")

    def test_authentication_failure_is_structured(self):
        with rpc_server("auth_fail") as (url, _):
            client = WalletRpcClient(RpcConfig(url=url, username="agent", password="wrong"))
            with self.assertRaises(RpcAuthenticationError):
                client.call("get_height")

    def test_wallet_rpc_error_is_preserved(self):
        with rpc_server("rpc_error") as (url, _):
            client = WalletRpcClient(RpcConfig(url=url))
            with self.assertRaises(WalletRpcError) as raised:
                client.call("transfer", {}, mutation=True)
        self.assertEqual(raised.exception.rpc_code, -17)
        self.assertEqual(raised.exception.rpc_message, "not enough money")

    def test_malformed_response_marks_mutation_unknown(self):
        with rpc_server("malformed") as (url, _):
            client = WalletRpcClient(RpcConfig(url=url))
            with self.assertRaises(RpcProtocolError) as raised:
                client.call("transfer", {}, mutation=True)
        self.assertTrue(raised.exception.details["outcome_unknown"])

    def test_wrong_response_id_is_rejected(self):
        with rpc_server("wrong_id") as (url, _):
            client = WalletRpcClient(RpcConfig(url=url))
            with self.assertRaises(RpcProtocolError):
                client.call("get_height")

    def test_response_size_limit(self):
        with rpc_server("oversized") as (url, _):
            client = WalletRpcClient(RpcConfig(url=url, max_response_bytes=1024))
            with self.assertRaises(RpcProtocolError):
                client.call("get_height")

    def test_transfer_timeout_is_not_retried(self):
        with rpc_server("timeout") as (url, server):
            client = WalletRpcClient(RpcConfig(url=url, timeout=0.05))
            with self.assertRaises(RpcTransportError) as raised:
                client.call("transfer", {}, mutation=True)
            time.sleep(0.25)
        self.assertTrue(raised.exception.details["outcome_unknown"])
        self.assertEqual(len(server.requests), 1)  # type: ignore[attr-defined]

    def test_invalid_params_fail_before_network(self):
        with rpc_server() as (url, server):
            client = WalletRpcClient(RpcConfig(url=url))
            with self.assertRaises(RpcProtocolError):
                client.call("get_height", [])  # type: ignore[arg-type]
        self.assertEqual(server.requests, [])  # type: ignore[attr-defined]

    def test_connection_failure_is_structured(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        client = WalletRpcClient(RpcConfig(url=f"http://127.0.0.1:{port}"))
        with self.assertRaises(RpcTransportError) as raised:
            client.call("get_height")
        self.assertEqual(raised.exception.details["kind"], "connection")
        self.assertFalse(raised.exception.details["outcome_unknown"])


if __name__ == "__main__":
    unittest.main()
