# Candidate code-path map

External qualification: NO. The transport fix is not a primitive change.

| MYT boundary | Actual pinned upstream path |
| --- | --- |
| crypto.mjs generate | lib/index.js generateKeyPair -> bbs/keypair.js KeyGen, SkToPk |
| canonical secret/public match | secretKeyToPublicKey -> SkToPk; Noble G2 decoding, assertValidity |
| native credential signing | sign -> bbs/interface.js Sign -> bbs/core.js CoreSign |
| credential verification | verifySignature -> Verify -> CoreVerify |
| randomized selective proof | deriveProof -> ProofGen -> CoreProofGen |
| single presentation verification | verifyProof -> ProofVerify -> CoreProofVerify |
| presentation challenge | ProofChallengeCalculate includes presentation-header length and bytes |
| signed credential domain | calculate_domain includes public key, generators, API ID and header |
| hash/group operations | exact Noble curves 2.4.0 and hashes 2.4.0 |
| subject/evaluator signatures | unchanged MYT Phase 4B identity.py |
| true local metric | unchanged reputation_policy.py reputation_summary, ReputationStore.snapshot |
| one-time state | disclosure_store.py and verify_reputation_presentation transaction |

Python constructs the canonical request bytes. Only the loopback JSON transport
represents them as unpadded Base64url. header.mjs uses the existing unb64 helper
and independently compares to the exact canonical request. The returned buffer
goes directly to native presentationHeader. Credential HEADER remains
MYT-REPUTATION-CREDENTIAL-V1 followed by one LF.

Randomness: upstream generateKeyPair without seed -> WebCrypto getRandomValues;
upstream ProofGen -> native random scalars; Python challenges -> secrets;
encrypted-key salt/nonce and local capability -> Node crypto.randomBytes.
No fixture RNG or seeded key option is exposed by the official production API.
No batch-verification interface is used or exposed.

Review the exact installed tarballs and shrinkwrap, not merely a similarly named
tag. Digital Bazaar 3.1.0 source commit:
1b03d2528922ea6ee6f290a198136421f282fed8.
Noble curves 2.4.0:
656c4364dffa44c64aa0c49914b8000b278b67a9.
Noble hashes 2.4.0:
663c2aeeffc308ac0cded59bd32f7c212adacfc2.

Sources:
- https://github.com/digitalbazaar/bbs-signatures/tree/1b03d2528922ea6ee6f290a198136421f282fed8/lib
- https://github.com/paulmillr/noble-curves/tree/656c4364dffa44c64aa0c49914b8000b278b67a9
- https://github.com/paulmillr/noble-hashes/tree/663c2aeeffc308ac0cded59bd32f7c212adacfc2
