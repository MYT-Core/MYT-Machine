"""Optional WSGI reference adapter. Never exposes Wallet RPC or spending.

Mount behind a production WSGI server and authenticated protected transport.
The token authorizes a trusted billing operator, not arbitrary paying clients.
"""

from __future__ import annotations

import hmac
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs

from .billing import BillingService
from .errors import ConfigurationError, InputError, MytMachineError
from .invoices import InvoiceConflict, InvoiceNotFound
from .payment_requests import canonical_json, strict_json, validate_identifier

MAX_HTTP_BODY = 73728
_STATUS = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    411: "Length Required",
    413: "Content Too Large",
    415: "Unsupported Media Type",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}


class _HttpError(Exception):
    def __init__(self, status: int, code: str) -> None:
        self.status = status
        self.code = code


class BillingApplication:
    def __init__(self, service: BillingService, *, token: str) -> None:
        if (
            not isinstance(token, str)
            or re.fullmatch(r"[A-Za-z0-9_-]{32,256}", token) is None
        ):
            raise ConfigurationError(
                "Billing API token must be 32-256 ASCII token characters"
            )
        self._service = service
        self._token = token

    def __repr__(self) -> str:
        return "BillingApplication(token=<redacted>)"

    @staticmethod
    def _body(environ: dict[str, Any]) -> dict[str, Any]:
        if environ.get("HTTP_TRANSFER_ENCODING"):
            raise _HttpError(400, "transfer_encoding_unsupported")
        if environ.get("CONTENT_TYPE", "").lower() not in {
            "application/json",
            "application/json; charset=utf-8",
        }:
            raise _HttpError(415, "json_required")
        length_text = environ.get("CONTENT_LENGTH", "")
        if not length_text:
            raise _HttpError(411, "content_length_required")
        if re.fullmatch(r"[0-9]{1,6}", length_text) is None:
            raise _HttpError(400, "invalid_content_length")
        length = int(length_text)
        if length > MAX_HTTP_BODY:
            raise _HttpError(413, "body_too_large")
        body = environ["wsgi.input"].read(length)
        if len(body) != length:
            raise _HttpError(400, "incomplete_body")
        data = strict_json(body, MAX_HTTP_BODY)
        if not isinstance(data, dict):
            raise InputError("JSON body must be an object")
        return data

    def _dispatch(self, environ: dict[str, Any]) -> dict[str, Any]:
        path = environ.get("PATH_INFO", "")
        method = environ.get("REQUEST_METHOD", "")
        query = environ.get("QUERY_STRING", "")
        if len(path) > 256 or len(query) > 512:
            raise _HttpError(400, "invalid_url")
        if path == "/health" and method == "GET" and not query:
            return {"status": "ok"}
        authorization = environ.get("HTTP_AUTHORIZATION", "")
        if (
            not isinstance(authorization, str)
            or not authorization.isascii()
            or len(authorization) > 300
            or not hmac.compare_digest(authorization, "Bearer " + self._token)
        ):
            raise _HttpError(401, "unauthorized")
        if path == "/v1/invoices":
            if method == "GET":
                try:
                    params = (
                        parse_qs(
                            query,
                            keep_blank_values=True,
                            strict_parsing=True,
                            max_num_fields=2,
                        )
                        if query
                        else {}
                    )
                except ValueError:
                    raise InputError("Invalid pagination query") from None
                if set(params) - {"limit", "after"} or any(
                    len(v) != 1 for v in params.values()
                ):
                    raise InputError("Invalid pagination query")
                limit_text = params.get("limit", ["50"])[0]
                if re.fullmatch(r"[0-9]{1,3}", limit_text) is None:
                    raise InputError("Invalid page size")
                records = self._service.list_invoices(
                    limit=int(limit_text), after=params.get("after", [None])[0]
                )
                return {
                    "invoices": [r.as_dict() for r in records],
                    "next_after": records[-1].request.invoice_id if records else None,
                }
            if query:
                raise InputError("Unexpected query parameters")
            if method == "POST":
                data = self._body(environ)
                required = {"recipient_address", "amount_atomic"}
                optional = {
                    "expires_in",
                    "invoice_id",
                    "memo",
                    "reference",
                    "required_confirmations",
                }
                if not required <= set(data) or set(data) - required - optional:
                    raise InputError("Invalid invoice creation schema")
                record = self._service.create_invoice(
                    **data,
                    idempotency_key=environ.get("HTTP_IDEMPOTENCY_KEY"),
                )
                return {"invoice": record.as_dict()}
            raise _HttpError(405, "method_not_allowed")
        parts = path.split("/")
        if len(parts) not in {4, 5} or parts[:3] != ["", "v1", "invoices"]:
            raise _HttpError(404, "not_found")
        invoice_id = validate_identifier(parts[3])
        if query:
            raise InputError("Unexpected query parameters")
        if len(parts) == 4 and method == "GET":
            return {"invoice": self._service.get_invoice(invoice_id).as_dict()}
        if len(parts) == 5 and parts[4] == "status" and method == "GET":
            return {
                "invoice_id": invoice_id,
                "state": self._service.invoice_status(invoice_id).value,
            }
        if len(parts) == 5 and parts[4] == "verify" and method == "POST":
            data = self._body(environ)
            if set(data) != {"proof"}:
                raise InputError("Verification body must contain only proof")
            return self._service.verify_invoice(invoice_id, data["proof"]).as_dict()
        raise _HttpError(405, "method_not_allowed")

    def __call__(
        self, environ: dict[str, Any], start_response: Callable[..., Any]
    ) -> list[bytes]:
        status = 200
        try:
            payload = {"schema_version": 1, "success": True, **self._dispatch(environ)}
        except _HttpError as exc:
            status = exc.status
            payload = {
                "schema_version": 1,
                "success": False,
                "error": {"code": exc.code},
            }
        except MytMachineError as exc:
            if isinstance(exc, InvoiceNotFound):
                status = 404
            elif isinstance(exc, InvoiceConflict):
                status = 409
            elif isinstance(exc, InputError):
                status = 400
            elif isinstance(exc, ConfigurationError):
                status = 503
            else:
                status = 502
            # Do not return provider text, credentials, SQL or file paths.
            payload = {
                "schema_version": 1,
                "success": False,
                "error": {"code": exc.code},
            }
        except Exception:  # noqa: BLE001 - boundary must never expose provider secrets.
            status = 500
            payload = {
                "schema_version": 1,
                "success": False,
                "error": {"code": "internal_error"},
            }
        encoded = canonical_json(payload).encode("ascii") + b"\n"
        start_response(
            f"{status} {_STATUS[status]}",
            [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Content-Length", str(len(encoded))),
                ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff"),
            ],
        )
        return [encoded]
