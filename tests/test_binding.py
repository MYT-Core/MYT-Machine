import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from myt_machine.binding import (
    BINDING_CONTEXT,
    BINDING_DOMAIN,
    AddressBinding,
    AddressBindingService,
    create_binding_content,
)
from myt_machine.binding_artifacts import parse_address_binding
from myt_machine.errors import (
    ConfigurationError,
    InputError,
    RpcProtocolError,
    RpcTransportError,
)
from myt_machine.identity import (
    MachineIdentity,
    decode_signature,
    encode_signature,
)

VECTOR_PATH = Path(__file__).parents[1] / "docs" / "identity-v1-test-vector.json"
VECTOR = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
BINDING_VECTOR_PATH = (
    Path(__file__).parents[1] / "docs" / "address-binding-v1-test-vector.json"
)
BINDING_VECTOR = json.loads(BINDING_VECTOR_PATH.read_text(encoding="utf-8"))
STANDARD_ADDRESS = "9" + "A" * 94
SUBADDRESS = "B" + "C" * 94
OTHER_ADDRESS = "D" + "E" * 94
WALLET_SIGNATURE = "SigV2" + "1" * 88


def vector_identity():
    private_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(VECTOR["seed_hex"])
    )
    return MachineIdentity(private_key)


def address_response(address=SUBADDRESS, index=1):
    return {
        "address": address,
        "addresses": [
            {
                "address": address,
                "label": "binding",
                "address_index": index,
                "used": False,
            }
        ],
    }


def valid_address_response(
    *,
    nettype="testnet",
    subaddress=True,
    integrated=False,
    valid=True,
):
    if not valid:
        return {"valid": False}
    return {
        "valid": True,
        "integrated": integrated,
        "subaddress": subaddress,
        "nettype": nettype,
        "openalias_address": "",
    }


def wallet_verify_response(
    *, good=True, version=2, old=False, signature_type="spend"
):
    return {
        "good": good,
        "version": version,
        "old": old,
        "signature_type": signature_type,
    }


class StubClient:
    def __init__(self, responses=None):
        self.url = "http://127.0.0.1:38083"
        self.responses = {
            key: list(value) for key, value in (responses or {}).items()
        }
        self.calls = []

    def call(self, method, params=None, *, mutation=False):
        self.calls.append(
            {"method": method, "params": params, "mutation": mutation}
        )
        queue = self.responses.get(method, [])
        if not queue:
            raise AssertionError(f"Unexpected RPC method: {method}")
        response = queue.pop(0)
        if isinstance(response, Exception):
            raise response
        if callable(response):
            return response(params, mutation)
        return response


def make_binding(
    *,
    identity=None,
    network="testnet",
    address=SUBADDRESS,
    wallet_signature=WALLET_SIGNATURE,
):
    signer = vector_identity() if identity is None else identity
    content = create_binding_content(signer.machine_id, network, address)
    signature = signer.sign(content, BINDING_CONTEXT)
    return AddressBinding(
        identity=signer.public_identity,
        network=network,
        address=address,
        identity_signature=signature.signature,
        wallet_signature=wallet_signature,
    )


class BindingProtocolTests(unittest.TestCase):
    def test_published_binding_vector_is_byte_exact(self):
        identity = vector_identity()
        self.assertEqual(BINDING_VECTOR["machine_id"], identity.machine_id)
        self.assertEqual(
            BINDING_VECTOR["identity_seed_hex"],
            VECTOR["seed_hex"],
        )
        content = create_binding_content(
            BINDING_VECTOR["machine_id"],
            BINDING_VECTOR["network"],
            BINDING_VECTOR["address"],
        )
        self.assertEqual(content.hex(), BINDING_VECTOR["canonical_content_hex"])
        self.assertEqual(
            content.decode("ascii"), BINDING_VECTOR["canonical_content_ascii"]
        )
        self.assertEqual(
            identity.sign(content, BINDING_CONTEXT).signature,
            BINDING_VECTOR["identity_signature_base64url"],
        )
        binding = parse_address_binding(BINDING_VECTOR["artifact"])
        self.assertTrue(binding.verify_identity().signature_valid)
        self.assertEqual(binding.canonical_content, content)
        self.assertEqual(binding.wallet_signature, BINDING_VECTOR["wallet_signature"])
        self.assertNotIn("wallet_seed", BINDING_VECTOR)

    def test_canonical_content_is_byte_exact_and_deterministic(self):
        expected_json = json.dumps(
            {
                "address": SUBADDRESS,
                "machine_id": VECTOR["machine_id"],
                "network": "testnet",
                "type": "myt-machine-address-binding-statement",
                "version": 1,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        expected = BINDING_DOMAIN + expected_json
        first = create_binding_content(VECTOR["machine_id"], "testnet", SUBADDRESS)
        second = create_binding_content(VECTOR["machine_id"], "testnet", SUBADDRESS)
        self.assertEqual(first, expected)
        self.assertEqual(first, second)
        self.assertFalse(first.endswith(b"\n"))

    def test_phase4b_signature_authenticates_exact_canonical_content(self):
        identity = vector_identity()
        content = create_binding_content(identity.machine_id, "testnet", SUBADDRESS)
        signature = identity.sign(content, BINDING_CONTEXT)
        result = identity.public_identity.verify(
            content,
            BINDING_CONTEXT,
            signature.signature,
            expected_machine_id=identity.machine_id,
        )
        self.assertTrue(result.authentication_valid)
        self.assertEqual(signature.context, "myt-machine/address-binding/v1")

    def test_content_rejects_noncanonical_inputs(self):
        invalid = (
            ("not-an-id", "testnet", SUBADDRESS),
            (VECTOR["machine_id"], "devnet", SUBADDRESS),
            (VECTOR["machine_id"], "testnet", "contains  space"),
            (VECTOR["machine_id"], "testnet", "O" * 95),
            (VECTOR["machine_id"], "testnet", "A" * 129),
        )
        for machine_id, network, address in invalid:
            with self.subTest(network=network, address=address), self.assertRaises(
                InputError
            ):
                create_binding_content(machine_id, network, address)

    def test_binding_document_is_self_contained(self):
        binding = make_binding()
        document = binding.as_dict()
        self.assertEqual(document["type"], "myt-machine-address-binding")
        self.assertEqual(document["version"], 1)
        self.assertEqual(document["identity"]["machine_id"], VECTOR["machine_id"])
        self.assertNotIn("machine_id", {key: value for key, value in document.items() if key != "identity"})
        self.assertTrue(binding.verify_identity().valid)

    def test_binding_rejects_malformed_wallet_signature(self):
        with self.assertRaises(InputError):
            make_binding(wallet_signature="SigV2-not-canonical")


class BindingServiceTests(unittest.TestCase):
    def test_create_subaddress_signs_same_payload_once(self):
        client = StubClient(
            {
                "get_address": [address_response()],
                "validate_address": [valid_address_response()],
                "sign": [{"signature": WALLET_SIGNATURE}],
                "verify": [wallet_verify_response()],
            }
        )
        identity = vector_identity()
        binding = AddressBindingService(
            client, account_index=0, address_index=1
        ).create(identity)

        self.assertEqual(binding.address, SUBADDRESS)
        self.assertEqual(binding.network, "testnet")
        self.assertTrue(binding.verify_identity().signature_valid)
        self.assertEqual(
            [call["method"] for call in client.calls],
            ["get_address", "validate_address", "sign", "verify"],
        )
        sign_calls = [call for call in client.calls if call["method"] == "sign"]
        self.assertEqual(len(sign_calls), 1)
        self.assertTrue(sign_calls[0]["mutation"])
        self.assertEqual(
            sign_calls[0]["params"],
            {
                "data": binding.canonical_content.decode("ascii"),
                "account_index": 0,
                "address_index": 1,
                "signature_type": "spend",
            },
        )
        self.assertEqual(
            client.calls[-1]["params"]["data"],
            sign_calls[0]["params"]["data"],
        )

    def test_primary_standard_address_requires_explicit_opt_in(self):
        client = StubClient(
            {
                "get_address": [address_response(STANDARD_ADDRESS, 0)],
                "validate_address": [
                    valid_address_response(subaddress=False)
                ],
            }
        )
        with self.assertRaisesRegex(ConfigurationError, "allow-standard-address"):
            AddressBindingService(client).create(vector_identity())
        self.assertNotIn("sign", [call["method"] for call in client.calls])

    def test_primary_standard_address_can_be_explicitly_allowed(self):
        client = StubClient(
            {
                "get_address": [address_response(STANDARD_ADDRESS, 0)],
                "validate_address": [
                    valid_address_response(subaddress=False)
                ],
                "sign": [{"signature": WALLET_SIGNATURE}],
                "verify": [wallet_verify_response()],
            }
        )
        binding = AddressBindingService(client).create(
            vector_identity(), allow_standard_address=True
        )
        self.assertEqual(binding.address, STANDARD_ADDRESS)
        self.assertEqual(
            len([call for call in client.calls if call["method"] == "sign"]), 1
        )

    def test_integrated_address_is_unsupported_for_creation(self):
        client = StubClient(
            {
                "get_address": [address_response(STANDARD_ADDRESS, 0)],
                "validate_address": [
                    valid_address_response(
                        subaddress=False,
                        integrated=True,
                    )
                ],
            }
        )
        with self.assertRaisesRegex(ConfigurationError, "Integrated"):
            AddressBindingService(client).create(
                vector_identity(), allow_standard_address=True
            )
        self.assertNotIn("sign", [call["method"] for call in client.calls])

    def test_selected_index_and_rpc_address_type_must_agree(self):
        client = StubClient(
            {
                "get_address": [address_response()],
                "validate_address": [
                    valid_address_response(subaddress=False)
                ],
            }
        )
        with self.assertRaises(RpcProtocolError):
            AddressBindingService(client, address_index=1).create(vector_identity())
        self.assertNotIn("sign", [call["method"] for call in client.calls])

    def test_sign_timeout_is_not_retried_and_outcome_is_unknown(self):
        timeout = RpcTransportError(
            "Wallet RPC request timed out",
            kind="timeout",
            outcome_unknown=True,
        )
        client = StubClient(
            {
                "get_address": [address_response()],
                "validate_address": [valid_address_response()],
                "sign": [timeout],
            }
        )
        with self.assertRaises(RpcTransportError) as raised:
            AddressBindingService(client, address_index=1).create(vector_identity())
        self.assertTrue(raised.exception.details["outcome_unknown"])
        sign_calls = [call for call in client.calls if call["method"] == "sign"]
        self.assertEqual(len(sign_calls), 1)
        self.assertTrue(sign_calls[0]["mutation"])

    def test_generated_wallet_signature_must_be_canonical_and_verify_as_spend_v2(self):
        cases = (
            ({"signature": "SigV1bad"}, None),
            ({"signature": WALLET_SIGNATURE}, wallet_verify_response(good=False)),
            ({"signature": WALLET_SIGNATURE}, wallet_verify_response(version=1)),
            ({"signature": WALLET_SIGNATURE}, wallet_verify_response(old=True)),
            (
                {"signature": WALLET_SIGNATURE},
                wallet_verify_response(signature_type="view"),
            ),
        )
        for sign_response, verify_response in cases:
            with self.subTest(sign_response=sign_response, verify=verify_response):
                responses = {
                    "get_address": [address_response()],
                    "validate_address": [valid_address_response()],
                    "sign": [sign_response],
                }
                if verify_response is not None:
                    responses["verify"] = [verify_response]
                client = StubClient(responses)
                with self.assertRaises((InputError, RpcProtocolError)):
                    AddressBindingService(client, address_index=1).create(
                        vector_identity()
                    )
                self.assertEqual(
                    len([call for call in client.calls if call["method"] == "sign"]),
                    1,
                )

    def test_independent_wallet_verifies_complete_binding(self):
        binding = make_binding()
        client = StubClient(
            {
                "validate_address": [
                    valid_address_response(),
                    valid_address_response(),
                ],
                "verify": [wallet_verify_response()],
            }
        )
        result = AddressBindingService(client).verify(
            binding,
            expected_machine_id=binding.machine_id,
            expected_network="testnet",
        )
        self.assertTrue(result.valid)
        self.assertTrue(result.binding_valid)
        self.assertTrue(result.authentication_valid)
        self.assertTrue(result.identity_signature_valid)
        self.assertTrue(result.wallet_signature_valid)
        self.assertEqual(result.address_type, "subaddress")
        self.assertEqual(
            [call["method"] for call in client.calls],
            ["validate_address", "validate_address", "verify"],
        )
        self.assertFalse(any(call["mutation"] for call in client.calls))

    def test_generic_verification_does_not_claim_identity_authentication(self):
        binding = make_binding()
        client = StubClient(
            {
                "validate_address": [
                    valid_address_response(),
                    valid_address_response(),
                ],
                "verify": [wallet_verify_response()],
            }
        )
        result = AddressBindingService(client).verify(binding)
        self.assertTrue(result.valid)
        self.assertTrue(result.binding_valid)
        self.assertIsNone(result.identity_matches)
        self.assertIsNone(result.network_matches)
        self.assertIsNone(result.authentication_valid)

    def test_expected_identity_or_network_mismatch_is_negative(self):
        binding = make_binding()
        other_id = MachineIdentity.generate().machine_id
        cases = (
            (other_id, "testnet", False, True),
            (binding.machine_id, "mainnet", True, False),
        )
        for expected_id, expected_network, id_match, network_match in cases:
            with self.subTest(expected_network=expected_network):
                client = StubClient(
                    {
                        "validate_address": [
                            valid_address_response(),
                            valid_address_response(),
                        ],
                        "verify": [wallet_verify_response()],
                    }
                )
                result = AddressBindingService(client).verify(
                    binding,
                    expected_machine_id=expected_id,
                    expected_network=expected_network,
                )
                self.assertFalse(result.valid)
                self.assertFalse(result.authentication_valid)
                self.assertEqual(result.identity_matches, id_match)
                self.assertEqual(result.network_matches, network_match)
                self.assertTrue(result.binding_valid)

    def test_modified_identity_or_wallet_signature_is_negative(self):
        original = make_binding()
        changed = bytearray(decode_signature(original.identity_signature))
        changed[0] ^= 1
        modified_identity = AddressBinding(
            identity=original.identity,
            network=original.network,
            address=original.address,
            identity_signature=encode_signature(bytes(changed)),
            wallet_signature=original.wallet_signature,
        )
        cases = (
            (modified_identity, wallet_verify_response(), False, True),
            (original, wallet_verify_response(good=False), True, False),
            (original, wallet_verify_response(signature_type="view"), True, False),
        )
        for binding, wallet_response, identity_valid, wallet_valid in cases:
            with self.subTest(wallet_response=wallet_response):
                client = StubClient(
                    {
                        "validate_address": [
                            valid_address_response(),
                            valid_address_response(),
                        ],
                        "verify": [wallet_response],
                    }
                )
                result = AddressBindingService(client).verify(binding)
                self.assertFalse(result.valid)
                self.assertEqual(result.identity_signature_valid, identity_valid)
                self.assertEqual(result.wallet_signature_valid, wallet_valid)

    def test_invalid_integrated_and_cross_network_addresses_short_circuit(self):
        binding = make_binding()
        cases = (
            (valid_address_response(valid=False), False, None, None),
            (
                valid_address_response(subaddress=False, integrated=True),
                True,
                False,
                "integrated",
            ),
            (
                valid_address_response(nettype="mainnet"),
                True,
                True,
                "subaddress",
            ),
        )
        for response, address_valid, supported, address_type in cases:
            with self.subTest(response=response):
                client = StubClient({"validate_address": [response]})
                result = AddressBindingService(client).verify(binding)
                self.assertFalse(result.valid)
                self.assertEqual(result.address_valid, address_valid)
                self.assertEqual(result.address_supported, supported)
                self.assertEqual(result.address_type, address_type)
                self.assertIsNone(result.wallet_signature_valid)
                self.assertNotIn("verify", [call["method"] for call in client.calls])

    def test_verifier_wallet_must_be_on_binding_network(self):
        binding = make_binding()
        client = StubClient(
            {
                "validate_address": [
                    valid_address_response(),
                    valid_address_response(valid=False),
                ]
            }
        )
        with self.assertRaisesRegex(ConfigurationError, "different MYT network"):
            AddressBindingService(client).verify(binding)
        self.assertNotIn("verify", [call["method"] for call in client.calls])

    def test_contradictory_address_flags_are_protocol_error(self):
        binding = make_binding()
        client = StubClient(
            {
                "validate_address": [
                    valid_address_response(integrated=True, subaddress=True)
                ]
            }
        )
        with self.assertRaises(RpcProtocolError):
            AddressBindingService(client).verify(binding)


if __name__ == "__main__":
    unittest.main()
