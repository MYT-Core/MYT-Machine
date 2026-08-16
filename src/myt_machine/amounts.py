"""Exact MYT amount conversion without floating-point arithmetic."""

from __future__ import annotations

import re
from typing import Any

from .errors import InputError, RpcProtocolError

ATOMIC_UNITS_PER_MYT = 1_000_000_000
UINT64_MAX = (1 << 64) - 1
_AMOUNT_PATTERN = re.compile(r"^(0|[1-9][0-9]*)(?:\.([0-9]{1,9}))?$")


def parse_myt_amount(value: str, *, require_positive: bool = False) -> int:
    """Convert a decimal MYT string to atomic units exactly."""
    if not isinstance(value, str):
        raise InputError("MYT amount must be supplied as a decimal string")

    match = _AMOUNT_PATTERN.fullmatch(value)
    if match is None:
        raise InputError(
            "Invalid MYT amount; use plain decimal notation with at most 9 decimal places"
        )

    whole = int(match.group(1))
    fraction = (match.group(2) or "").ljust(9, "0")
    atomic = whole * ATOMIC_UNITS_PER_MYT + int(fraction or "0")
    if atomic > UINT64_MAX:
        raise InputError("MYT amount exceeds the wallet RPC uint64 range")
    if require_positive and atomic == 0:
        raise InputError("Payment amount must be greater than zero")
    return atomic


def format_myt_amount(atomic: int) -> str:
    """Format atomic units as a canonical fixed-precision MYT string."""
    if isinstance(atomic, bool) or not isinstance(atomic, int):
        raise RpcProtocolError("Wallet RPC returned a non-integer amount")
    if atomic < 0 or atomic > UINT64_MAX:
        raise RpcProtocolError("Wallet RPC returned an amount outside the uint64 range")
    whole, fraction = divmod(atomic, ATOMIC_UNITS_PER_MYT)
    return f"{whole}.{fraction:09d}"


def amount_object(atomic: int) -> dict[str, Any]:
    """Return the stable JSON representation used by the SDK and CLI."""
    return {"atomic": atomic, "myt": format_myt_amount(atomic)}
