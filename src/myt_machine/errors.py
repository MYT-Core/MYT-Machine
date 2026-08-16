"""Structured errors shared by the SDK and CLI."""

from __future__ import annotations

from typing import Any


class MytMachineError(Exception):
    code = "machine_error"
    exit_code = 4

    def __init__(self, message: str, **details: Any) -> None:
        super().__init__(message)
        self.message = message
        self.details = {key: value for key, value in details.items() if value is not None}

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, **self.details}


class InputError(MytMachineError):
    code = "invalid_input"
    exit_code = 2


class ConfigurationError(MytMachineError):
    code = "invalid_configuration"
    exit_code = 3


class RpcTransportError(MytMachineError):
    code = "rpc_transport_error"
    exit_code = 4

    def __init__(
        self,
        message: str,
        *,
        kind: str = "transport",
        outcome_unknown: bool = False,
        http_status: int | None = None,
    ) -> None:
        super().__init__(
            message,
            kind=kind,
            outcome_unknown=outcome_unknown,
            http_status=http_status,
        )


class RpcAuthenticationError(RpcTransportError):
    code = "rpc_authentication_failed"

    def __init__(self, message: str = "Wallet RPC authentication failed") -> None:
        super().__init__(message, kind="authentication", outcome_unknown=False, http_status=401)


class RpcProtocolError(MytMachineError):
    code = "rpc_protocol_error"
    exit_code = 4


class WalletRpcError(MytMachineError):
    code = "wallet_rpc_error"
    exit_code = 5

    def __init__(self, rpc_code: int, rpc_message: str) -> None:
        super().__init__(
            "Wallet RPC rejected the request",
            rpc_code=rpc_code,
            rpc_message=rpc_message,
        )
        self.rpc_code = rpc_code
        self.rpc_message = rpc_message
