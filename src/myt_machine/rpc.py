"""Hardened JSON-RPC transport for myt-wallet-rpc."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import itertools
import json
import secrets
import ssl
import threading
from dataclasses import dataclass, field
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import SplitResult, urlsplit, urlunsplit
from urllib.request import (
    BaseHandler,
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
    parse_http_list,
    parse_keqv_list,
)

from ._version import __version__
from .errors import (
    ConfigurationError,
    RpcAuthenticationError,
    RpcProtocolError,
    RpcTransportError,
    WalletRpcError,
)

DEFAULT_RPC_URL = "http://127.0.0.1:39083"
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_RESPONSE_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 16_777_216
MAX_AUTH_CHALLENGE_BYTES = 65_536


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class _DigestChallengeError(Exception):
    pass


class _ConnectionResponse:
    """Adapter that lets urllib process an http.client response safely."""

    def __init__(
        self,
        connection: http.client.HTTPConnection,
        response: http.client.HTTPResponse,
        url: str,
    ) -> None:
        self._connection = connection
        self._response = response
        self.code = response.status
        self.status = response.status
        self.reason = response.reason
        self.msg = response.reason
        self.headers = response.headers
        self.url = url

    def read(self, amount: int | None = None) -> bytes:
        return self._response.read(amount)

    def info(self):  # type: ignore[no-untyped-def]
        return self.headers

    def geturl(self) -> str:
        return self.url

    def close(self) -> None:
        try:
            self._response.close()
        finally:
            self._connection.close()

    def __enter__(self) -> _ConnectionResponse:  # noqa: PYI034
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:  # type: ignore[no-untyped-def]
        self.close()


class _PersistentDigestHandler(BaseHandler):
    """Perform Digest challenge and authentication on one HTTP connection.

    Epee scopes its nonce to a connection. urllib's built-in HTTP handler closes
    after every request, so its standard Digest handler cannot authenticate to
    MYT wallet RPC. This handler retains urllib's opener and Request API while
    keeping only the challenge pair on a single http.client connection.
    """

    handler_order = 480

    def __init__(self, username: str | None, password: str | None) -> None:
        self.username = username
        self.password = password
        self._ssl_context = ssl.create_default_context()

    @staticmethod
    def _request_headers(request: Request, *, close: bool) -> dict[str, str]:
        headers = dict(request.unredirected_hdrs)
        headers.update({key: value for key, value in request.headers.items() if key not in headers})
        headers["Connection"] = "close" if close else "keep-alive"
        return {name.title(): value for name, value in headers.items()}

    def _connection(self, request: Request) -> http.client.HTTPConnection:
        parsed = urlsplit(request.full_url)
        if parsed.hostname is None:
            raise _DigestChallengeError("Wallet RPC request URL has no hostname")
        timeout = float(request.timeout)
        if parsed.scheme == "http":
            return http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
        if parsed.scheme == "https":
            return http.client.HTTPSConnection(
                parsed.hostname,
                parsed.port,
                timeout=timeout,
                context=self._ssl_context,
            )
        raise _DigestChallengeError("Wallet RPC request URL has an unsupported scheme")

    @staticmethod
    def _send(
        connection: http.client.HTTPConnection,
        request: Request,
        headers: dict[str, str],
    ) -> http.client.HTTPResponse:
        connection.request(
            request.get_method(),
            request.selector,
            body=request.data,
            headers=headers,
            encode_chunked=request.has_header("Transfer-encoding"),
        )
        return connection.getresponse()

    @staticmethod
    def _challenge(headers: Any) -> dict[str, str] | None:
        values = headers.get_all("WWW-Authenticate", [])
        for value in values:
            scheme, separator, fields = value.partition(" ")
            if not separator or scheme.lower() != "digest":
                continue
            try:
                parsed = parse_keqv_list(filter(None, parse_http_list(fields)))
            except (TypeError, ValueError):
                continue
            realm = parsed.get("realm")
            nonce = parsed.get("nonce")
            algorithm = parsed.get("algorithm", "MD5")
            qop = parsed.get("qop")
            if not all(isinstance(value, str) for value in (realm, nonce, algorithm, qop)):
                continue
            qop_values = {entry.strip().lower() for entry in qop.split(",")}
            if algorithm.upper() == "MD5" and "auth" in qop_values:
                return {
                    "realm": realm,
                    "nonce": nonce,
                    "algorithm": "MD5",
                    "qop": "auth",
                }
        return None

    @staticmethod
    def _quoted(value: str, field_name: str) -> str:
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise _DigestChallengeError(f"Wallet RPC Digest {field_name} contains controls")
        return value.replace("\\", "\\\\").replace('"', '\\"')

    def _authorization(self, request: Request, challenge: dict[str, str]) -> str:
        if self.username is None or self.password is None:
            raise _DigestChallengeError("Wallet RPC Digest credentials are missing")

        username = self._quoted(self.username, "username")
        realm = self._quoted(challenge["realm"], "realm")
        nonce = self._quoted(challenge["nonce"], "nonce")
        uri = self._quoted(request.selector, "URI")
        cnonce = secrets.token_hex(16)
        nonce_count = "00000001"

        def md5(value: str) -> str:
            return hashlib.md5(value.encode("utf-8"), usedforsecurity=False).hexdigest()

        ha1 = md5(f"{self.username}:{challenge['realm']}:{self.password}")
        ha2 = md5(f"{request.get_method()}:{request.selector}")
        response = md5(
            f"{ha1}:{challenge['nonce']}:{nonce_count}:{cnonce}:auth:{ha2}"
        )
        return (
            f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
            f'uri="{uri}", response="{response}", algorithm=MD5, qop=auth, '
            f'nc={nonce_count}, cnonce="{cnonce}"'
        )

    def _open(self, request: Request) -> _ConnectionResponse:
        connection = self._connection(request)
        try:
            response = self._send(
                connection,
                request,
                self._request_headers(request, close=self.username is None),
            )
            if response.status != 401 or self.username is None:
                return _ConnectionResponse(connection, response, request.full_url)

            challenge_body = response.read(MAX_AUTH_CHALLENGE_BYTES + 1)
            if len(challenge_body) > MAX_AUTH_CHALLENGE_BYTES:
                raise _DigestChallengeError("Wallet RPC Digest challenge exceeds the size limit")
            challenge = self._challenge(response.headers)
            if challenge is None:
                return _ConnectionResponse(connection, response, request.full_url)

            headers = self._request_headers(request, close=True)
            headers["Authorization"] = self._authorization(request, challenge)
            authenticated = self._send(connection, request, headers)
            return _ConnectionResponse(connection, authenticated, request.full_url)
        except Exception:
            connection.close()
            raise

    def http_open(self, request: Request) -> _ConnectionResponse:
        return self._open(request)

    def https_open(self, request: Request) -> _ConnectionResponse:
        return self._open(request)


def _is_loopback(hostname: str) -> bool:
    normalized = hostname.rstrip(".").lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _normalize_url(url: str, allow_insecure_http: bool) -> str:
    if not isinstance(url, str) or not url:
        raise ConfigurationError("Wallet RPC URL must be a non-empty string")
    try:
        parsed = urlsplit(url)
        _ = parsed.port
    except ValueError as exc:
        raise ConfigurationError("Wallet RPC URL contains an invalid port") from exc

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ConfigurationError("Wallet RPC URL must use http or https")
    if not parsed.hostname:
        raise ConfigurationError("Wallet RPC URL must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigurationError("Credentials must not be embedded in the Wallet RPC URL")
    if parsed.query or parsed.fragment:
        raise ConfigurationError("Wallet RPC URL must not contain a query or fragment")
    if parsed.path not in {"", "/"}:
        raise ConfigurationError("Wallet RPC URL must not include an RPC path")
    if scheme == "http" and not _is_loopback(parsed.hostname) and not allow_insecure_http:
        raise ConfigurationError(
            "Unencrypted Wallet RPC is only allowed on loopback; use HTTPS or --allow-insecure-http"
        )

    normalized = SplitResult(scheme, parsed.netloc, "", "", "")
    return urlunsplit(normalized).rstrip("/")


@dataclass(frozen=True)
class RpcConfig:
    url: str = DEFAULT_RPC_URL
    username: str | None = None
    password: str | None = field(default=None, repr=False, compare=False)
    timeout: float = DEFAULT_TIMEOUT
    allow_insecure_http: bool = False
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        if not isinstance(self.allow_insecure_http, bool):
            raise ConfigurationError("Wallet RPC insecure HTTP override must be a boolean")
        normalized_url = _normalize_url(self.url, self.allow_insecure_http)
        object.__setattr__(self, "url", normalized_url)

        if (self.username is None) != (self.password is None):
            raise ConfigurationError("Wallet RPC username and password must be configured together")
        if self.username is not None:
            if not isinstance(self.username, str) or not self.username:
                raise ConfigurationError("Wallet RPC username must be a non-empty string")
            if any(character in self.username for character in "\r\n\x00"):
                raise ConfigurationError("Wallet RPC username contains invalid characters")
        if self.password is not None:
            if not isinstance(self.password, str) or not self.password:
                raise ConfigurationError("Wallet RPC password must be a non-empty string")
            if any(character in self.password for character in "\r\n\x00"):
                raise ConfigurationError("Wallet RPC password contains invalid characters")
        if isinstance(self.timeout, bool) or not isinstance(self.timeout, (int, float)):
            raise ConfigurationError("Wallet RPC timeout must be a number")
        if not 0 < float(self.timeout) <= 300:
            raise ConfigurationError("Wallet RPC timeout must be greater than 0 and at most 300 seconds")
        if (
            isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
            or self.max_response_bytes < 1024
            or self.max_response_bytes > MAX_RESPONSE_BYTES
        ):
            raise ConfigurationError("Wallet RPC response limit must be between 1024 and 16777216 bytes")


class WalletRpcClient:
    """Minimal wallet RPC client with no automatic application retries."""

    def __init__(self, config: RpcConfig) -> None:
        self.config = config
        self.url = config.url
        self.endpoint = f"{config.url}/json_rpc"
        handlers: list[Any] = [
            ProxyHandler({}),
            _NoRedirectHandler(),
            _PersistentDigestHandler(config.username, config.password),
        ]
        self._opener = build_opener(*handlers)
        self._ids = itertools.count(1)
        self._id_lock = threading.Lock()

    def _request_id(self) -> str:
        with self._id_lock:
            return str(next(self._ids))

    def call(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        mutation: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(method, str) or not method:
            raise RpcProtocolError("Wallet RPC method must be a non-empty string")
        if params is not None and not isinstance(params, dict):
            raise RpcProtocolError("Wallet RPC params must be an object")

        request_id = self._request_id()
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params is not None:
            payload["params"] = params
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        request = Request(
            self.endpoint,
            data=encoded,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": f"myt-machine/{__version__}",
            },
            method="POST",
        )

        try:
            with self._opener.open(request, timeout=float(self.config.timeout)) as response:
                body = response.read(self.config.max_response_bytes + 1)
        except _DigestChallengeError as exc:
            raise RpcProtocolError(str(exc), outcome_unknown=mutation) from None
        except HTTPError as exc:
            status = exc.code
            exc.close()
            if status == 401:
                raise RpcAuthenticationError() from None
            raise RpcTransportError(
                "Wallet RPC returned an unexpected HTTP status",
                kind="http",
                outcome_unknown=mutation,
                http_status=status,
            ) from None
        except TimeoutError:
            raise RpcTransportError(
                "Wallet RPC request timed out",
                kind="timeout",
                outcome_unknown=mutation,
            ) from None
        except URLError as exc:
            reason = exc.reason
            kind = "timeout" if isinstance(reason, TimeoutError) else "connection"
            message = (
                "Wallet RPC request timed out"
                if kind == "timeout"
                else "Unable to connect to Wallet RPC"
            )
            raise RpcTransportError(
                message,
                kind=kind,
                outcome_unknown=mutation,
            ) from None
        except OSError:
            raise RpcTransportError(
                "Unable to communicate with Wallet RPC",
                kind="connection",
                outcome_unknown=mutation,
            ) from None

        def response_protocol_error(message: str) -> RpcProtocolError:
            return RpcProtocolError(message, outcome_unknown=mutation)

        if len(body) > self.config.max_response_bytes:
            raise response_protocol_error("Wallet RPC response exceeds the configured size limit")
        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise response_protocol_error("Wallet RPC returned malformed JSON") from None
        if not isinstance(decoded, dict):
            raise response_protocol_error("Wallet RPC response must be a JSON object")
        if decoded.get("id") != request_id:
            raise response_protocol_error("Wallet RPC response ID does not match the request")

        if "error" in decoded:
            error = decoded["error"]
            if not isinstance(error, dict):
                raise response_protocol_error("Wallet RPC error response is malformed")
            rpc_code = error.get("code")
            rpc_message = error.get("message")
            if isinstance(rpc_code, bool) or not isinstance(rpc_code, int) or not isinstance(rpc_message, str):
                raise response_protocol_error("Wallet RPC error response is malformed")
            raise WalletRpcError(rpc_code, rpc_message)

        result = decoded.get("result")
        if not isinstance(result, dict):
            raise response_protocol_error("Wallet RPC response does not contain an object result")
        return result
