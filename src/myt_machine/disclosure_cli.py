"""Explicit optional disclosure commands. Never configure or call Wallet RPC."""

from dataclasses import asdict
from pathlib import Path

from .disclosure import (
    DisclosurePolicy,
    authorize_bbs_key,
    create_disclosure_request,
    issue_reputation_credential,
    present_reputation_credential,
    reputation_policy_digest,
    revoke_bbs_key,
    verify_reputation_presentation,
)
from .disclosure_artifacts import LEVELS, exact, strict_object
from .disclosure_backend import BbsBackend
from .disclosure_files import (
    load_disclosure,
    private_parent,
    read_regular,
    save_disclosure,
)
from .disclosure_store import DisclosureStore
from .errors import ConfigurationError, InputError
from .identity_artifacts import load_public_identity
from .identity_keys import load_private_identity
from .reputation_policy import ReputationPolicy
from .reputation_store import ReputationStore


def add_disclosure_parsers(subparsers):
    root = subparsers.add_parser(
        "disclosure", help="Unreleased optional BBS evaluator assertions"
    )
    actions = root.add_subparsers(dest="disclosure_command", required=True)
    for name in (
        "authorize",
        "revoke",
        "issuer-status",
        "issue",
        "request",
        "present",
        "verify",
        "show",
        "policy-digest",
    ):
        p = actions.add_parser(name)
        if name in ("authorize", "issue", "present", "verify"):
            p.add_argument("--bbs-url", required=True)
            p.add_argument("--bbs-token-file", required=True)
        if name in ("authorize", "revoke", "issue", "present"):
            p.add_argument("--private-key-file", required=True)
            p.add_argument("--identity-file", required=True)
            p.add_argument("--passphrase-file")
        if name in ("authorize", "revoke", "issue", "present", "request"):
            p.add_argument("--output-file", required=True)
        if name in ("request", "present", "verify", "issuer-status", "issue"):
            p.add_argument("--state-db", required=True)
        if name in ("request", "present", "verify"):
            p.add_argument("--expected-subject", required=True)
            p.add_argument("--expected-evaluator", required=True)
            p.add_argument("--expected-key-id", required=True)
            p.add_argument(
                "--network", choices=["mainnet", "testnet", "stagenet"], required=True
            )
            p.add_argument("--audience", required=True)
            p.add_argument("--policy-digest", required=True)
            p.add_argument("--threshold", type=int, choices=list(LEVELS), required=True)
            p.add_argument("--issuer-status-max-age", type=int, default=300)
        if name == "authorize":
            p.add_argument(
                "--network", choices=["mainnet", "testnet", "stagenet"], required=True
            )
        if name in ("authorize", "issue", "request"):
            p.add_argument(
                "--lifetime",
                type=int,
                default={"authorize": 86400, "issue": 3600, "request": 120}[name],
            )
        if name in ("revoke", "issuer-status", "issue"):
            p.add_argument("--authorization-file", required=True)
        if name == "revoke":
            p.add_argument(
                "--reason",
                choices=["compromised", "retired", "unspecified"],
                required=True,
            )
        if name == "issuer-status":
            p.add_argument("--expected-evaluator", required=True)
            p.add_argument("--revocation-file", action="append", default=[])
        if name in ("issue", "policy-digest"):
            p.add_argument("--reputation-policy-file", required=True)
        if name == "issue":
            p.add_argument("--reputation-db", required=True)
            p.add_argument("--subject", required=True)
        if name == "present":
            p.add_argument("--credential-file", required=True)
            p.add_argument("--request-file", required=True)
        if name in ("verify", "show"):
            p.add_argument("--artifact-file", required=True)


def _reputation_policy(path):
    value = strict_object(read_regular(path, 32768))
    exact(
        value,
        {
            "trusted_issuers",
            "max_per_issuer",
            "min_age",
            "max_age",
            "require_settlement",
        },
    )
    if type(value["trusted_issuers"]) is not list:
        raise InputError("Invalid reputation policy")
    return ReputationPolicy(
        **{**value, "trusted_issuers": tuple(value["trusted_issuers"])}
    )


def run_disclosure_command(args, passphrase_loader):
    action = args.disclosure_command
    if hasattr(args, "output_file"):
        path = Path(args.output_file).absolute()
        private_parent(path)
        if path.exists() or path.is_symlink():
            raise ConfigurationError("Disclosure output already exists")
    if action == "show":
        return {"artifact": load_disclosure(args.artifact_file).as_dict()}, True
    if action == "policy-digest":
        return {
            "policy_digest": reputation_policy_digest(
                _reputation_policy(args.reputation_policy_file)
            )
        }, True
    identity = None
    if hasattr(args, "private_key_file"):
        try:
            public = load_public_identity(args.identity_file)
        except InputError:
            raise InputError("Cannot load disclosure identity") from None
        identity = load_private_identity(args.private_key_file, passphrase_loader(args))
        if identity.public_identity != public:
            raise ConfigurationError("Disclosure private and public identities differ")
    backend = (
        BbsBackend(url=args.bbs_url, token_file=args.bbs_token_file)
        if hasattr(args, "bbs_url")
        else None
    )
    state = DisclosureStore(args.state_db) if hasattr(args, "state_db") else None
    policy = None
    if action in ("request", "present", "verify"):
        policy = DisclosurePolicy(
            args.expected_subject,
            args.expected_evaluator,
            args.expected_key_id,
            args.network,
            args.audience,
            args.policy_digest,
            args.threshold,
            args.issuer_status_max_age,
        )
    if action == "authorize":
        value = authorize_bbs_key(
            identity, backend, network=args.network, lifetime=args.lifetime
        )
    elif action == "revoke":
        value = revoke_bbs_key(
            identity, load_disclosure(args.authorization_file), reason=args.reason
        )
    elif action == "issuer-status":
        state.refresh_issuer(
            load_disclosure(args.authorization_file),
            expected_evaluator=args.expected_evaluator,
            revocations=[load_disclosure(f) for f in args.revocation_file],
        )
        return {
            "local_status_checked": True,
            "global_revocation_freshness": False,
        }, True
    elif action == "issue":
        value = issue_reputation_credential(
            reputation_store=ReputationStore(args.reputation_db),
            policy=_reputation_policy(args.reputation_policy_file),
            subject=args.subject,
            identity=identity,
            authorization=load_disclosure(args.authorization_file),
            issuer_state=state,
            backend=backend,
            lifetime=args.lifetime,
        )
    elif action == "request":
        value = create_disclosure_request(policy, state, lifetime=args.lifetime)
    elif action == "present":
        value = present_reputation_credential(
            credential=load_disclosure(args.credential_file),
            request=load_disclosure(args.request_file),
            policy=policy,
            identity=identity,
            issuer_state=state,
            backend=backend,
        )
    elif action == "verify":
        result = verify_reputation_presentation(
            presentation=load_disclosure(args.artifact_file),
            policy=policy,
            store=state,
            backend=backend,
        )
        return asdict(result), result.valid
    else:
        raise InputError("Unknown disclosure command")
    save_disclosure(args.output_file, value)
    return {"artifact": value.as_dict()}, True
