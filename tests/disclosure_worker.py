"""Spawn-compatible worker for the real durable one-time verification regression."""

from myt_machine.disclosure import DisclosurePolicy, verify_reputation_presentation
from myt_machine.disclosure_artifacts import parse_disclosure
from myt_machine.disclosure_backend import BbsBackend
from myt_machine.disclosure_store import DisclosureStore


def consume(data):
    raw, policy, path, url, token = data
    return verify_reputation_presentation(
        presentation=parse_disclosure(raw),
        policy=DisclosurePolicy(**policy),
        store=DisclosureStore(path),
        backend=BbsBackend(url=url, token_file=token),
    ).valid
