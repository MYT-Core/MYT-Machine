"""Real Phase 4E ReputationStore -> bounded Phase 4F evaluator adapter."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_REPOSITORY_ROOT / "src"))

from myt_machine.errors import MytMachineError  # noqa: E402
from myt_machine.payment_requests import canonical_json  # noqa: E402
from myt_machine.reputation_policy import ReputationPolicy, reputation_summary  # noqa: E402
from myt_machine.reputation_store import ReputationStore, settlement_digest  # noqa: E402


_MAX_INPUT_BYTES = 65_536
_REQUEST_FIELDS = {
    "subject_machine_id",
    "network",
    "policy",
    "as_of",
    "requested_predicate",
}
_POLICY_FIELDS = {
    "trusted_issuers",
    "max_per_issuer",
    "min_age",
    "max_age",
    "require_settlement",
}
_PREDICATE_FIELDS = {"metric_id", "operator", "threshold"}


class Phase4eAdapterError(Exception):
    """A redacted error crossing the evaluator boundary."""


def _reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Phase4eAdapterError("JSON contains a duplicate field")
        result[key] = value
    return result


def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise Phase4eAdapterError(f"{name} is not an integer")
    if value < minimum or value > maximum:
        raise Phase4eAdapterError(f"{name} is outside its bounds")
    return value


def _digest(prefix: bytes, value: dict[str, Any]) -> str:
    return hashlib.sha256(prefix + canonical_json(value).encode("ascii")).hexdigest()


def _snapshot_manifest(store: ReputationStore, network: str) -> dict[str, Any]:
    artifacts, settlements = store.snapshot(network=network)
    return {
        "artifact_digests": sorted(artifact.digest for artifact in artifacts),
        "settlement_digests": sorted(settlement_digest(item) for item in settlements),
    }


def evaluate_request(database_path: str, request: dict[str, Any]) -> dict[str, Any]:
    """Evaluate only data returned by the production Phase 4E boundary."""
    if not isinstance(request, dict) or set(request) != _REQUEST_FIELDS:
        raise Phase4eAdapterError("Evaluator request has missing or unknown fields")
    policy_value = request["policy"]
    if not isinstance(policy_value, dict) or set(policy_value) != _POLICY_FIELDS:
        raise Phase4eAdapterError("ReputationPolicy has missing or unknown fields")
    trusted_issuers = policy_value["trusted_issuers"]
    if not isinstance(trusted_issuers, list):
        raise Phase4eAdapterError("ReputationPolicy trusted issuers must be a list")
    predicate_request = request["requested_predicate"]
    if not isinstance(predicate_request, dict) or set(predicate_request) != _PREDICATE_FIELDS:
        raise Phase4eAdapterError("Predicate request has missing or unknown fields")
    if (
        predicate_request["metric_id"] != "verified_recipient_settlement_events"
        or predicate_request["operator"] != "gte"
    ):
        raise Phase4eAdapterError("Predicate is not in the bounded catalog")
    threshold = _bounded_int(predicate_request["threshold"], "Predicate threshold", 0, 10_000)
    try:
        if not Path(database_path).is_file():
            raise Phase4eAdapterError("Phase 4E reputation database does not exist")
        policy = ReputationPolicy(
            trusted_issuers=tuple(trusted_issuers),
            max_per_issuer=policy_value["max_per_issuer"],
            min_age=policy_value["min_age"],
            max_age=policy_value["max_age"],
            require_settlement=policy_value["require_settlement"],
        )
        store = ReputationStore(database_path)
        before = _snapshot_manifest(store, request["network"])
        summary = reputation_summary(
            store,
            subject=request["subject_machine_id"],
            network=request["network"],
            policy=policy,
            as_of=request["as_of"],
        )
        after = _snapshot_manifest(store, request["network"])
        if before != after:
            raise Phase4eAdapterError("Phase 4E evidence changed during evaluation")
    except Phase4eAdapterError:
        raise
    except (MytMachineError, OSError, TypeError, ValueError):
        raise Phase4eAdapterError("Phase 4E evaluation failed") from None
    effective_policy = policy.as_dict()
    policy_digest = _digest(b"MYT-PHASE4F-REPUTATION-POLICY-V1\n", effective_policy)
    evidence_digest = _digest(
        b"MYT-PHASE4F-PHASE4E-EVALUATION-V1\n",
        {"evidence_manifest": before, "summary": summary},
    )
    evaluation = {
        "subject_machine_id": summary["subject_machine_id"],
        "network": summary["network"],
        "phase4e_evidence_digest": evidence_digest,
        "policy_digest": policy_digest,
        "objective_local_observations": summary["objective_local_observations"],
        "signed_opinions": summary["signed_opinions"],
        "local_policy_output": summary["local_policy_output"],
    }
    metric_value = evaluation["objective_local_observations"][
        "verified_recipient_settlement_events"
    ]
    _bounded_int(metric_value, "Predicate metric", 0, 100_000)
    predicate = {
        "metric_id": "verified_recipient_settlement_events",
        "operator": "gte",
        "threshold": threshold,
        "result": metric_value >= threshold,
        "metric_value": metric_value,
    }
    return {
        "type": "myt-phase4f-evaluator-result",
        "version": 1,
        "assertion_semantics": "trusted-evaluator-assertion-not-mathematical-range-proof",
        "evaluation": evaluation,
        "predicate": predicate,
    }


def _read_request() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
    if len(raw) > _MAX_INPUT_BYTES:
        raise Phase4eAdapterError("Evaluator request exceeds its size limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise Phase4eAdapterError("Evaluator request is not valid JSON") from None
    if not isinstance(value, dict):
        raise Phase4eAdapterError("Evaluator request must be an object")
    return value


def _main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--database", required=True)
    arguments = parser.parse_args()
    try:
        result = evaluate_request(arguments.database, _read_request())
        print(json.dumps({"ok": True, "result": result}, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
        return 0
    except Phase4eAdapterError as error:
        print(json.dumps({"ok": False, "error": str(error)}, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(_main())
