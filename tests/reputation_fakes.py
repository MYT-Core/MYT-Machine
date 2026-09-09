"""Public deterministic fixtures, never production keys or real settlement."""

from billing_fakes import ADDRESS, FakeBillingRpc
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from myt_machine.binding import BINDING_CONTEXT, AddressBinding, create_binding_content
from myt_machine.identity import MachineIdentity
from myt_machine.reputation import create_attestation

SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
ISSUER = MachineIdentity(Ed25519PrivateKey.from_private_bytes(SEED))
SUBJECT = MachineIdentity(Ed25519PrivateKey.from_private_bytes(bytes(range(32))))
OTHER = MachineIdentity(Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))))


def attest(**changes):
    values = {
        "subject_machine_id": SUBJECT.machine_id,
        "network": "testnet",
        "issued_at": 1000,
        "outcome": "POSITIVE",
    }
    values.update(changes)
    return create_attestation(ISSUER, **values)


def binding_for(identity=SUBJECT, network="testnet", address=ADDRESS):
    return AddressBinding(
        identity.public_identity,
        network,
        address,
        identity.sign(
            create_binding_content(identity.machine_id, network, address),
            BINDING_CONTEXT,
        ).signature,
        "SigV2" + "1" * 88,
    )


class ReputationRpc(FakeBillingRpc):
    def __init__(self):
        super().__init__()
        self.binding_good = True

    def call(self, method, params=None, *, mutation=False):
        if mutation:
            raise AssertionError("Reputation must not mutate wallets")
        if method == "validate_address" and params["any_net_type"] is True:
            self.calls.append((method, params, mutation))
            return {
                "valid": self.valid,
                "nettype": self.network,
                "integrated": self.integrated,
                "subaddress": self.subaddress,
            }
        if method == "verify":
            self.calls.append((method, params, mutation))
            return {
                "good": self.binding_good,
                "version": 2,
                "old": False,
                "signature_type": "spend",
            }
        return super().call(method, params, mutation=mutation)
