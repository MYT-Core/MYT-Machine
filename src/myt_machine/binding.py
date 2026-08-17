"""MYT Machine Address Binding v1 protocol and Wallet RPC operations."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .errors import ConfigurationError, InputError, RpcProtocolError
from .identity import (
    IdentityVerification,
    MachineIdentity,
    PublicMachineIdentity,
    decode_signature,
    machine_id_digest,
)
from .rpc import WalletRpcClient
from .settlement import MachineSettlement, _rpc_bool, _rpc_int, _rpc_string
from .validation import validate_uint32

BINDING_TYPE = "myt-machine-address-binding"
BINDING_VERSION = 1
BINDING_STATEMENT_TYPE = "myt-machine-address-binding-statement"
BINDING_CONTEXT = "myt-machine/address-binding/v1"
BINDING_DOMAIN = b"MYT-MACHINE-ADDRESS-BINDING-V1\n"
BINDING_NETWORKS = frozenset({"mainnet", "testnet", "stagenet"})

_BASE58_PATTERN = re.compile(r"^[1-9A-HJ-NP-Za-km-z]+$")
_WALLET_SIGNATURE_PATTERN = re.compile(r"^SigV2[1-9A-HJ-NP-Za-km-z]{88}$")
MAX_BINDING_ADDRESS_BYTES = 128


def _validate_binding_network(network: str) -> str:
    if not isinstance(network, str) or network not in BINDING_NETWORKS:
        raise InputError("Binding network must be mainnet, testnet, or stagenet")
    return network


def _validate_binding_address(address: str) -> str:
    if not isinstance(address, str):
        raise InputError("Binding address must be a string")
    try:
        encoded = address.encode("ascii")
    except UnicodeEncodeError:
        raise InputError("Binding address must be ASCII MYT Base58") from None
    if (
        not encoded
        or len(encoded) > MAX_BINDING_ADDRESS_BYTES
        or _BASE58_PATTERN.fullmatch(address) is None
    ):
        raise InputError("Binding address must be canonical ASCII MYT Base58")
    return address


def _validate_wallet_signature(signature: str) -> str:
    if (
        not isinstance(signature, str)
        or _WALLET_SIGNATURE_PATTERN.fullmatch(signature) is None
    ):
        raise InputError(
            "Wallet binding signature must be a canonical MYT SigV2 spend signature"
        )
    return signature


def create_binding_content(machine_id: str, network: str, address: str) -> bytes:
    """Return the canonical payload authenticated by both signature systems.

    Phase 4B and MYT SigV2 apply their own existing domain separation around
    this same payload, so their final cryptographic inputs are intentionally
    different.
    """

    machine_id_digest(machine_id)
    normalized_network = _validate_binding_network(network)
    normalized_address = _validate_binding_address(address)
    statement = {
        "address": normalized_address,
        "machine_id": machine_id,
        "network": normalized_network,
        "type": BINDING_STATEMENT_TYPE,
        "version": BINDING_VERSION,
    }
    canonical_json = json.dumps(
        statement,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return BINDING_DOMAIN + canonical_json


@dataclass(frozen=True)
class AddressBinding:
    """A validated, self-contained public Address Binding v1 artifact."""

    identity: PublicMachineIdentity
    network: str
    address: str
    identity_signature: str
    wallet_signature: str

    def __post_init__(self) -> None:
        if not isinstance(self.identity, PublicMachineIdentity):
            raise InputError("Binding identity must be a public machine identity")
        object.__setattr__(self, "network", _validate_binding_network(self.network))
        object.__setattr__(self, "address", _validate_binding_address(self.address))
        decode_signature(self.identity_signature)
        object.__setattr__(
            self,
            "wallet_signature",
            _validate_wallet_signature(self.wallet_signature),
        )

    @property
    def machine_id(self) -> str:
        return self.identity.machine_id

    @property
    def canonical_content(self) -> bytes:
        return create_binding_content(self.machine_id, self.network, self.address)

    def verify_identity(
        self,
        *,
        expected_machine_id: str | None = None,
    ) -> IdentityVerification:
        return self.identity.verify(
            self.canonical_content,
            BINDING_CONTEXT,
            self.identity_signature,
            expected_machine_id=expected_machine_id,
        )

    def as_dict(self) -> dict[str, Any]:
        # Local import avoids a module cycle with strict artifact parsing.
        from .identity_artifacts import public_identity_document

        return {
            "address": self.address,
            "identity": public_identity_document(self.identity),
            "identity_signature": self.identity_signature,
            "network": self.network,
            "type": BINDING_TYPE,
            "version": BINDING_VERSION,
            "wallet_signature": self.wallet_signature,
        }


@dataclass(frozen=True)
class AddressBindingVerification:
    """Full cryptographic and policy result for an Address Binding v1."""

    artifact_valid: bool
    machine_id: str
    network: str
    address: str
    address_valid: bool
    address_supported: bool | None
    address_type: str | None
    network_valid: bool | None
    identity_signature_valid: bool
    wallet_signature_valid: bool | None
    wallet_signature_version: int | None
    wallet_signature_type: str | None
    wallet_signature_old: bool | None
    identity_matches: bool | None
    network_matches: bool | None
    binding_valid: bool
    authentication_valid: bool | None
    valid: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "artifact_valid": self.artifact_valid,
            "machine_id": self.machine_id,
            "network": self.network,
            "address": self.address,
            "address_valid": self.address_valid,
            "address_supported": self.address_supported,
            "address_type": self.address_type,
            "network_valid": self.network_valid,
            "identity_signature_valid": self.identity_signature_valid,
            "wallet_signature_valid": self.wallet_signature_valid,
            "wallet_signature_version": self.wallet_signature_version,
            "wallet_signature_type": self.wallet_signature_type,
            "wallet_signature_old": self.wallet_signature_old,
            "identity_matches": self.identity_matches,
            "network_matches": self.network_matches,
            "binding_valid": self.binding_valid,
            "authentication_valid": self.authentication_valid,
            "valid": self.valid,
        }


class AddressBindingService:
    """Create and verify bindings through native MYT Wallet RPC SigV2 calls."""

    def __init__(
        self,
        client: WalletRpcClient,
        *,
        account_index: int = 0,
        address_index: int = 0,
    ) -> None:
        self.client = client
        self.account_index = validate_uint32(account_index, "account index")
        self.address_index = validate_uint32(address_index, "address index")
        self._settlement = MachineSettlement(
            client,
            account_index=self.account_index,
            address_index=self.address_index,
        )

    @staticmethod
    def _validated_address(response: dict[str, Any]) -> dict[str, Any] | None:
        valid = _rpc_bool(response.get("valid"), "address validity")
        if not valid:
            return None
        network = _validate_binding_network(
            _rpc_string(response.get("nettype"), "network type")
        )
        integrated = _rpc_bool(
            response.get("integrated"),
            "integrated-address flag",
        )
        subaddress = _rpc_bool(
            response.get("subaddress"),
            "subaddress flag",
        )
        if integrated and subaddress:
            raise RpcProtocolError(
                "Wallet RPC returned contradictory MYT address-type flags"
            )
        if integrated:
            address_type = "integrated"
        elif subaddress:
            address_type = "subaddress"
        else:
            address_type = "standard"
        return {
            "network": network,
            "integrated": integrated,
            "subaddress": subaddress,
            "address_type": address_type,
        }

    def _validate_address(
        self,
        address: str,
        *,
        any_net_type: bool,
    ) -> dict[str, Any] | None:
        response = self.client.call(
            "validate_address",
            {
                "address": address,
                "any_net_type": any_net_type,
                "allow_openalias": False,
            },
        )
        return self._validated_address(response)

    @staticmethod
    def _wallet_verification_metadata(
        response: dict[str, Any],
    ) -> tuple[bool, int, bool, str]:
        return (
            _rpc_bool(response.get("good"), "signature verification result"),
            _rpc_int(
                response.get("version"),
                "signature version",
                maximum=0xFFFFFFFF,
            ),
            _rpc_bool(response.get("old"), "legacy-signature flag"),
            _rpc_string(
                response.get("signature_type"),
                "signature type",
                allow_empty=True,
            ),
        )

    def create(
        self,
        identity: MachineIdentity,
        *,
        allow_standard_address: bool = False,
    ) -> AddressBinding:
        if not isinstance(identity, MachineIdentity):
            raise InputError("Binding creation requires a MachineIdentity")
        if not isinstance(allow_standard_address, bool):
            raise ConfigurationError(
                "Standard-address binding override must be a boolean"
            )

        selected = self._settlement.address()
        address = _validate_binding_address(selected["address"])
        address_info = self._validate_address(address, any_net_type=False)
        if address_info is None:
            raise RpcProtocolError(
                "Wallet RPC returned an address that is invalid for its wallet network"
            )
        if address_info["integrated"]:
            raise ConfigurationError(
                "Integrated addresses are unsupported by Address Binding v1"
            )

        expected_subaddress = not (
            self.account_index == 0 and self.address_index == 0
        )
        if address_info["subaddress"] != expected_subaddress:
            raise RpcProtocolError(
                "Wallet RPC address type does not match the selected wallet index"
            )
        if not address_info["subaddress"] and not allow_standard_address:
            raise ConfigurationError(
                "The primary standard address requires --allow-standard-address; "
                "use a dedicated subaddress by default"
            )

        content = create_binding_content(
            identity.machine_id,
            address_info["network"],
            address,
        )
        identity_signature = identity.sign(content, BINDING_CONTEXT)

        # WalletRpcClient performs no automatic RPC retries. This sensitive call
        # must remain exactly once per binding-creation attempt.
        sign_response = self.client.call(
            "sign",
            {
                "data": content.decode("ascii"),
                "account_index": self.account_index,
                "address_index": self.address_index,
                "signature_type": "spend",
            },
            mutation=True,
        )
        wallet_signature = _validate_wallet_signature(
            _rpc_string(sign_response.get("signature"), "wallet signature")
        )

        verify_response = self.client.call(
            "verify",
            {
                "data": content.decode("ascii"),
                "address": address,
                "signature": wallet_signature,
            },
        )
        good, version, old, signature_type = self._wallet_verification_metadata(
            verify_response
        )
        if not good or version != 2 or old or signature_type != "spend":
            raise RpcProtocolError(
                "Wallet RPC did not verify the generated signature as SigV2 spend"
            )

        binding = AddressBinding(
            identity=identity.public_identity,
            network=address_info["network"],
            address=address,
            identity_signature=identity_signature.signature,
            wallet_signature=wallet_signature,
        )
        if not binding.verify_identity().signature_valid:
            raise RpcProtocolError(
                "Generated machine-identity binding signature failed verification"
            )
        return binding

    def _result(
        self,
        binding: AddressBinding,
        identity_result: IdentityVerification,
        *,
        expected_network: str | None,
        address_valid: bool,
        address_supported: bool | None,
        address_type: str | None,
        network_valid: bool | None,
        wallet_signature_valid: bool | None,
        wallet_signature_version: int | None,
        wallet_signature_type: str | None,
        wallet_signature_old: bool | None,
    ) -> AddressBindingVerification:
        network_matches = (
            None
            if expected_network is None
            else binding.network == expected_network
        )
        binding_valid = bool(
            address_valid
            and address_supported
            and network_valid
            and identity_result.signature_valid
            and wallet_signature_valid
        )

        expectations_match = True
        if identity_result.identity_matches is not None:
            expectations_match = (
                expectations_match and identity_result.identity_matches
            )
        if network_matches is not None:
            expectations_match = expectations_match and network_matches

        authentication_valid = (
            None
            if identity_result.identity_matches is None
            else binding_valid and expectations_match
        )
        has_expectations = (
            identity_result.identity_matches is not None
            or network_matches is not None
        )
        valid = binding_valid and (
            expectations_match if has_expectations else True
        )
        return AddressBindingVerification(
            artifact_valid=True,
            machine_id=binding.machine_id,
            network=binding.network,
            address=binding.address,
            address_valid=address_valid,
            address_supported=address_supported,
            address_type=address_type,
            network_valid=network_valid,
            identity_signature_valid=identity_result.signature_valid,
            wallet_signature_valid=wallet_signature_valid,
            wallet_signature_version=wallet_signature_version,
            wallet_signature_type=wallet_signature_type,
            wallet_signature_old=wallet_signature_old,
            identity_matches=identity_result.identity_matches,
            network_matches=network_matches,
            binding_valid=binding_valid,
            authentication_valid=authentication_valid,
            valid=valid,
        )

    def verify(
        self,
        binding: AddressBinding,
        *,
        expected_machine_id: str | None = None,
        expected_network: str | None = None,
    ) -> AddressBindingVerification:
        if not isinstance(binding, AddressBinding):
            raise InputError("Binding verification requires an AddressBinding")
        normalized_expected_network = (
            None
            if expected_network is None
            else _validate_binding_network(expected_network)
        )
        identity_result = binding.verify_identity(
            expected_machine_id=expected_machine_id
        )

        address_info = self._validate_address(
            binding.address,
            any_net_type=True,
        )
        if address_info is None:
            return self._result(
                binding,
                identity_result,
                expected_network=normalized_expected_network,
                address_valid=False,
                address_supported=None,
                address_type=None,
                network_valid=None,
                wallet_signature_valid=None,
                wallet_signature_version=None,
                wallet_signature_type=None,
                wallet_signature_old=None,
            )

        network_valid = address_info["network"] == binding.network
        if address_info["integrated"]:
            return self._result(
                binding,
                identity_result,
                expected_network=normalized_expected_network,
                address_valid=True,
                address_supported=False,
                address_type="integrated",
                network_valid=network_valid,
                wallet_signature_valid=None,
                wallet_signature_version=None,
                wallet_signature_type=None,
                wallet_signature_old=None,
            )

        if not network_valid:
            return self._result(
                binding,
                identity_result,
                expected_network=normalized_expected_network,
                address_valid=True,
                address_supported=True,
                address_type=address_info["address_type"],
                network_valid=False,
                wallet_signature_valid=None,
                wallet_signature_version=None,
                wallet_signature_type=None,
                wallet_signature_old=None,
            )

        current_network_info = self._validate_address(
            binding.address,
            any_net_type=False,
        )
        if current_network_info is None:
            raise ConfigurationError(
                "Verifier Wallet RPC is opened on a different MYT network"
            )
        if (
            current_network_info["network"] != address_info["network"]
            or current_network_info["address_type"] != address_info["address_type"]
        ):
            raise RpcProtocolError(
                "Wallet RPC returned inconsistent MYT address validation results"
            )

        response = self.client.call(
            "verify",
            {
                "data": binding.canonical_content.decode("ascii"),
                "address": binding.address,
                "signature": binding.wallet_signature,
            },
        )
        good, version, old, signature_type = self._wallet_verification_metadata(
            response
        )
        wallet_signature_valid = (
            good
            and version == 2
            and not old
            and signature_type == "spend"
        )
        return self._result(
            binding,
            identity_result,
            expected_network=normalized_expected_network,
            address_valid=True,
            address_supported=True,
            address_type=address_info["address_type"],
            network_valid=True,
            wallet_signature_valid=wallet_signature_valid,
            wallet_signature_version=version,
            wallet_signature_type=signature_type,
            wallet_signature_old=old,
        )
