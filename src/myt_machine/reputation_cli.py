"""Local-only reputation CLI; only record-settlement uses read-only Wallet RPC."""

from pathlib import Path

from .billing_cli import _load
from .binding_artifacts import parse_address_binding
from .errors import ConfigurationError, InputError
from .identity_artifacts import load_public_identity
from .identity_keys import load_private_identity
from .invoice_store import SQLiteInvoiceStore
from .payment_requests import NETWORKS, unix_time
from .reputation import (
    MAX_REPUTATION_BYTES,
    create_attestation,
    create_revocation,
)
from .reputation_files import (
    ensure_reputation_output,
    load_reputation_artifact,
    save_reputation_artifact,
)
from .reputation_policy import ReputationPolicy, reputation_summary
from .reputation_settlement import record_verified_settlement
from .reputation_store import ReputationStore


def add_reputation_parsers(subparsers):
    root = subparsers.add_parser(
        "reputation", help="Local off-chain evidence, opinions and policy"
    )
    actions = root.add_subparsers(dest="reputation_command", required=True)
    for name in (
        "attest",
        "verify",
        "import",
        "get",
        "list",
        "summary",
        "revoke",
        "record-settlement",
    ):
        p = actions.add_parser(name)
        p.add_argument("--network", choices=sorted(NETWORKS), required=True)
        if name in {"attest", "revoke"}:
            p.add_argument("--private-key-file", required=True)
            p.add_argument("--identity-file", required=True)
            p.add_argument("--passphrase-file")
            p.add_argument("--output-file", required=True)
            p.add_argument("--issued-at", type=int)
        if name in {"verify", "import", "revoke"}:
            p.add_argument("--artifact-file", required=True)
        if name == "verify":
            p.add_argument("--expected-issuer")
        if name in {"attest", "summary"}:
            p.add_argument("--subject", required=True)
        if name == "attest":
            p.add_argument(
                "--outcome", choices=["POSITIVE", "NEUTRAL", "NEGATIVE"], required=True
            )
            p.add_argument("--evidence-digest")
        if name in {"import", "get", "list", "summary", "record-settlement"}:
            p.add_argument("--db", required=True)
        if name == "get":
            p.add_argument("--id", required=True)
        if name == "list":
            p.add_argument("--subject")
            p.add_argument("--after")
            p.add_argument("--limit", type=int, default=50)
        if name == "summary":
            p.add_argument("--trusted-issuer", action="append", default=[])
            p.add_argument("--max-per-issuer", type=int, default=1)
            p.add_argument("--min-age", type=int, default=0)
            p.add_argument("--max-age", type=int, default=253402300799)
            p.add_argument("--require-settlement", action="store_true")
            p.add_argument("--as-of", type=int, required=True)
        if name == "record-settlement":
            p.add_argument("--invoice-db", required=True)
            p.add_argument("--invoice-id", required=True)
            p.add_argument("--binding-file", required=True)
            p.add_argument("--proof-file", required=True)
            p.add_argument("--expected-machine-id", required=True)


def run_reputation_command(args, stdin, client_factory, passphrase_loader):
    action = args.reputation_command
    if action in {"attest", "revoke"}:
        ensure_reputation_output(args.output_file)
        public = load_public_identity(args.identity_file)
        identity = load_private_identity(args.private_key_file, passphrase_loader(args))
        if identity.public_identity != public:
            raise ConfigurationError("Private key and issuer identity do not match")
        now = unix_time(args.issued_at)
        if action == "attest":
            artifact = create_attestation(
                identity,
                subject_machine_id=args.subject,
                network=args.network,
                issued_at=now,
                outcome=args.outcome,
                evidence=args.evidence_digest,
            )
        else:
            target = load_reputation_artifact(args.artifact_file, stdin)
            if target.statement["network"] != args.network:
                raise InputError("Revocation network does not match attestation")
            artifact = create_revocation(identity, target, issued_at=now)
        save_reputation_artifact(artifact, args.output_file)
        return {
            "id": artifact.id,
            "artifact_digest": artifact.digest,
            "network": args.network,
        }, True
    if action == "verify":
        artifact = load_reputation_artifact(args.artifact_file, stdin)
        signature_valid = artifact.verify()
        valid = artifact.verify(
            expected_network=args.network, expected_issuer=args.expected_issuer
        )
        return {
            "valid": valid,
            "signature_valid": signature_valid,
            "id": artifact.id,
            "statement_truth_verified": False,
            "revocation_target_checked": False,
            "issuer_trust_evaluated": False,
        }, valid
    if action not in {"import", "record-settlement"} and not Path(args.db).is_file():
        raise ConfigurationError("Reputation database does not exist")
    if action == "import":
        artifact = load_reputation_artifact(args.artifact_file, stdin)
        if not artifact.verify(expected_network=args.network):
            return {"valid": False, "imported": False}, False
        inserted = ReputationStore(args.db).import_artifact(
            artifact, network=args.network
        )
        return {"valid": True, "id": artifact.id, "inserted": inserted}, True
    store = ReputationStore(args.db)
    if action == "get":
        artifact = store.get(args.id, network=args.network)
        return {
            "found": artifact is not None,
            "artifact": artifact.as_dict() if artifact else None,
        }, artifact is not None
    if action == "list":
        artifacts = store.list(
            network=args.network,
            subject=args.subject,
            limit=args.limit,
            after=args.after,
        )
        return {"artifacts": [a.as_dict() for a in artifacts]}, True
    if action == "summary":
        policy = ReputationPolicy(
            tuple(args.trusted_issuer),
            args.max_per_issuer,
            args.min_age,
            args.max_age,
            args.require_settlement,
        )
        return reputation_summary(
            store,
            subject=args.subject,
            network=args.network,
            policy=policy,
            as_of=args.as_of,
        ), True
    if not Path(args.invoice_db).is_file():
        raise ConfigurationError("Invoice database does not exist")
    if args.binding_file == "-" and args.proof_file == "-":
        raise InputError("Only one artifact may use stdin")
    try:
        binding = parse_address_binding(
            _load(args.binding_file, stdin, MAX_REPUTATION_BYTES)
        )
        proof = _load(args.proof_file, stdin, 131072)
    except InputError:
        raise InputError("Invalid binding or payment proof input") from None
    return record_verified_settlement(
        store,
        SQLiteInvoiceStore(args.invoice_db),
        client_factory(),
        network=args.network,
        invoice_id=args.invoice_id,
        binding=binding,
        proof=proof,
        expected_machine_id=args.expected_machine_id,
    ), True
