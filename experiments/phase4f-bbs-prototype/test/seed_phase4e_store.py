"""Test-only creation of trusted Phase 4E settlement observations."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from myt_machine.reputation_store import ReputationStore  # noqa: E402


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def main() -> int:
    if len(sys.argv) != 4:
        return 2
    database_path, subject_machine_id, count_text = sys.argv[1:]
    count = int(count_text)
    if not 0 <= count <= 100_000:
        return 2
    store = ReputationStore(database_path)
    for index in range(count):
        # Only tests may call the private trusted bridge. Production observations
        # still enter through record_verified_settlement after native verification.
        store._record_settlement(
            {
                "type": "myt-recipient-settlement-observation",
                "version": 1,
                "network": "testnet",
                "subject_machine_id": subject_machine_id,
                "transaction_digest": digest(f"transaction-{index}"),
                "request_digest": digest(f"request-{index}"),
                "binding_digest": digest(f"binding-{index}"),
            }
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
