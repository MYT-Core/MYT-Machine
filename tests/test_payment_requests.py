import json
from dataclasses import dataclass

import pytest

from myt_machine.errors import InputError
from myt_machine.payment_requests import (
    PAYMENT_REQUEST_TYPE,
    PAYMENT_REQUEST_VERSION,
    PaymentRequestState,
    PaymentRequestVerifier,
    PaymentVerification,
    create_payment_request,
    parse_payment_request,
    serialize_payment_request,
)

ADDRESS = "MYT_TEST_ADDRESS_123"


def test_create_payment_request_uses_atomic_integer_and_defaults_to_pending():
    request = create_payment_request(ADDRESS, 1_250_000_000, expires_in=300, now=1_000)
    assert request.recipient_address == ADDRESS
    assert request.amount_atomic == 1_250_000_000
    assert request.created_at == 1_000
    assert request.expires_at == 1_300
    assert request.state is PaymentRequestState.PENDING
    assert request.invoice_id


def test_create_payment_request_supports_memo_reference_and_custom_id():
    request = create_payment_request(
        ADDRESS,
        5,
        expires_in=10,
        memo="GPU job",
        reference="job-42",
        invoice_id="invoice-42",
        now=100,
    )
    assert request.memo == "GPU job"
    assert request.reference == "job-42"
    assert request.invoice_id == "invoice-42"


@pytest.mark.parametrize("value", [1.0, True, "1", None])
def test_floating_point_and_non_integer_amounts_are_rejected(value):
    with pytest.raises(InputError, match="integer"):
        create_payment_request(ADDRESS, value, expires_in=60, now=0)


def test_zero_amount_is_rejected():
    with pytest.raises(InputError, match="greater than zero"):
        create_payment_request(ADDRESS, 0, expires_in=60, now=0)


def test_expiry_is_derived_without_mutating_pending_request():
    request = create_payment_request(ADDRESS, 1, expires_in=10, now=100)
    assert request.effective_state(now=109) is PaymentRequestState.PENDING
    assert request.effective_state(now=110) is PaymentRequestState.EXPIRED
    assert request.state is PaymentRequestState.PENDING


def test_mark_paid_returns_paid_copy():
    request = create_payment_request(ADDRESS, 1, expires_in=10, now=100)
    paid = request.mark_paid(now=109)
    assert paid.state is PaymentRequestState.PAID
    assert request.state is PaymentRequestState.PENDING


def test_expired_request_cannot_be_marked_paid():
    request = create_payment_request(ADDRESS, 1, expires_in=10, now=100)
    with pytest.raises(InputError, match="Expired"):
        request.mark_paid(now=110)


def test_paid_request_cannot_be_expired():
    request = create_payment_request(ADDRESS, 1, expires_in=10, now=100).mark_paid(now=101)
    with pytest.raises(InputError, match="Paid"):
        request.expire(now=110)


def test_expire_requires_elapsed_expiry():
    request = create_payment_request(ADDRESS, 1, expires_in=10, now=100)
    with pytest.raises(InputError, match="not reached"):
        request.expire(now=109)
    expired = request.expire(now=110)
    assert expired.state is PaymentRequestState.EXPIRED


def test_serialization_round_trip_is_stable():
    request = create_payment_request(
        ADDRESS,
        123,
        expires_in=60,
        memo="hello",
        reference="ref-1",
        invoice_id="invoice-1",
        now=1_000,
    )
    encoded = serialize_payment_request(request)
    decoded = json.loads(encoded)
    assert decoded["type"] == PAYMENT_REQUEST_TYPE
    assert decoded["version"] == PAYMENT_REQUEST_VERSION
    assert decoded["amount_atomic"] == 123
    assert parse_payment_request(encoded) == request
    assert serialize_payment_request(parse_payment_request(encoded)) == encoded


def test_parse_accepts_bytes_and_mapping():
    request = create_payment_request(ADDRESS, 9, expires_in=60, invoice_id="inv", now=1)
    encoded = serialize_payment_request(request)
    assert parse_payment_request(encoded.encode("utf-8")) == request
    assert parse_payment_request(json.loads(encoded)) == request


def test_parse_rejects_unknown_state():
    request = create_payment_request(ADDRESS, 9, expires_in=60, invoice_id="inv", now=1)
    data = request.as_dict()
    data["state"] = "CANCELLED"
    with pytest.raises(InputError, match="PENDING, PAID, or EXPIRED"):
        parse_payment_request(data)


def test_parse_rejects_invalid_expiry_order():
    request = create_payment_request(ADDRESS, 9, expires_in=60, invoice_id="inv", now=1)
    data = request.as_dict()
    data["expires_at"] = data["created_at"]
    with pytest.raises(InputError, match="later than"):
        parse_payment_request(data)


def test_effective_state_can_be_serialized_without_mutating_request():
    request = create_payment_request(ADDRESS, 9, expires_in=10, invoice_id="inv", now=1)
    assert request.as_dict(resolve_expiry=True, now=11)["state"] == "EXPIRED"
    assert request.state is PaymentRequestState.PENDING


@dataclass
class DummyVerifier:
    def verify(self, request):
        return PaymentVerification(paid=True, txid="a" * 64, proof={"kind": "test"})


def test_verifier_protocol_is_small_and_runtime_checkable():
    verifier = DummyVerifier()
    assert isinstance(verifier, PaymentRequestVerifier)
    request = create_payment_request(ADDRESS, 1, expires_in=60, now=0)
    result = verifier.verify(request)
    assert result.paid is True
    assert result.txid == "a" * 64
