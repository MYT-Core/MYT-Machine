"""Explicit authenticated loopback BBS companion. No process discovery/spawning."""

from __future__ import annotations

import http.client
import math
import re
import secrets
from urllib.parse import urlsplit

from .disclosure_artifacts import PROFILE, SUITE, encoded, exact, strict_object
from .disclosure_files import read_regular
from .errors import ConfigurationError, MytMachineError


class DisclosureBackendError(MytMachineError):
    code = "disclosure_backend_error"


class BbsBackend:
    """A capability grants local signing authority; never hand it to untrusted users."""

    def __init__(self, *, url: str, token_file, timeout: float = 15):
        try:
            endpoint = urlsplit(url)
            if (
                endpoint.scheme != "http"
                or endpoint.hostname != "127.0.0.1"
                or endpoint.username is not None
                or endpoint.password is not None
                or endpoint.path not in ("", "/")
                or endpoint.query
                or endpoint.fragment
                or endpoint.port is None
                or not 1024 <= endpoint.port <= 65535
            ):
                raise ValueError
            if (
                isinstance(timeout, bool)
                or not math.isfinite(timeout)
                or not 0 < timeout <= 30
            ):
                raise ValueError
            token = read_regular(token_file, 65, private=True)
            if re.fullmatch(b"[0-9a-f]{64}\n", token) is None:
                raise ValueError
        except (TypeError, ValueError):
            raise ConfigurationError(
                "Invalid local BBS companion configuration"
            ) from None
        self._port = endpoint.port
        self._token = token[:-1].decode("ascii")
        self._timeout = timeout
        # Version negotiation occurs inside call, immediately before each operation.

    def __repr__(self) -> str:
        return "BbsBackend(<protected local capability>)"

    def _handshake(self):
        result = self._call("hello", {})
        try:
            exact(result, {"profile", "ciphersuite", "versions", "signing", "node"})
            if result["profile"] != PROFILE or result["ciphersuite"] != SUITE:
                raise ValueError
            if result["versions"] != {
                "bbs": "3.1.0",
                "curves": "2.4.0",
                "hashes": "2.4.0",
            }:
                raise ValueError
            if type(result["signing"]) is not bool:
                raise ValueError
            parts = result["node"].split(".")
            if len(parts) != 3 or any(not p.isdigit() for p in parts):
                raise ValueError
            if int(parts[0]) != 24 or int(parts[1]) < 20:
                raise ValueError
        except (ValueError, TypeError, KeyError, AttributeError, MytMachineError):
            raise DisclosureBackendError("Incompatible BBS companion") from None

    def _call(self, operation: str, params: dict) -> dict:
        request_id = secrets.token_hex(16)
        data = (
            encoded(
                {
                    "version": 1,
                    "id": request_id,
                    "operation": operation,
                    "params": params,
                }
            )
            + b"\n"
        )
        if len(data) > 32768:
            raise DisclosureBackendError("BBS request size limit")
        conn = http.client.HTTPConnection(
            "127.0.0.1", self._port, timeout=self._timeout
        )
        try:
            # http.client neither follows redirects nor discovers system proxies.
            conn.request(
                "POST",
                "/v1",
                body=data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + self._token,
                    "Connection": "close",
                },
            )
            response = conn.getresponse()
            if (
                response.status != 200
                or response.getheader("Content-Type") != "application/json"
            ):
                raise ValueError
            raw = response.read(32769)
            value = strict_object(raw)
            exact(value, {"version", "id", "result"})
            if (
                type(value["version"]) is not int
                or value["version"] != 1
                or value["id"] != request_id
            ):
                raise ValueError
            if type(value["result"]) is not dict:
                raise ValueError
            return value["result"]
        except (OSError, ValueError, http.client.HTTPException, MytMachineError):
            # Never surface remote response bodies, tokens, paths or secret exception text.
            raise DisclosureBackendError(
                "BBS companion request failed; no automatic retry"
            ) from None
        finally:
            conn.close()

    def call(self, operation: str, params: dict) -> dict:
        self._handshake()
        return self._call(operation, params)
