# Current Candidate Scope (2026-09-20)

The material below is retained historical research/external-contribution evidence.
The official feature candidate now implements evaluator-signed BBS selective disclosure;
not an arithmetic hidden-value range proof, private-balance proof, counterparty
anonymity or general ZK computation. Current normative protocol and engineering
results: [Phase 4F protocol](phase4f-protocol-v1.md) and
[validation](../MYT_Phase4F_Validation.md). External cryptographic qualification
remains NO; no main merge or release is authorized. Earlier versions, counts and
blocked prototype decisions below are not current runtime support claims.

---

# Phase 4F Whitepaper Mapping

Status: design stopped before implementation, 2026-09-10.
Baseline: MYT Machine 0.5.0, commit
`ff1624ff6263bfd4142550391a381f96006a0413`.

The local published MYT Whitepaper v1.3 was read, particularly sections 12-14
(PDF pages 15-18). It was not edited. This mapping describes the actual released
machine layer separately from proposals. No Phase 4F feature is marked complete.

| Historical goal | Classification at this gate | Actual scope / limitation |
| --- | --- | --- |
| Demonstrate one settlement without exposing unrelated history | ALREADY PROVIDED BY EXISTING 4A-4E FUNCTIONALITY | Phase 4A uses native payment proofs; Phase 4D packages payment/request verification. The selected TXID, destination and disclosed result are not hidden. |
| Exportable enterprise verification artifacts | PARTIALLY IMPLEMENTED | Versioned identity, binding, billing and reputation artifacts exist. This is not general financial auditing, regulatory certification or completeness of enterprise records. |
| Automated API settlement verification | ALREADY PROVIDED BY EXISTING 4A-4E FUNCTIONALITY | SDK/CLI and billing verification provide machine-readable results with explicit semantics. No blanket legal-compliance claim follows. |
| Zero-knowledge balance ranges | DEFERRED | A reputation count is not a wallet balance. No balance circuit, wallet statement or MYT Core modification was implemented. |
| Zero-knowledge transaction-set auditing | DEFERRED | No hidden transaction-set membership/completeness proof exists in this work. |
| Counterparty-blind payment proof | DEFERRED | Existing OutProofV2 verification uses a recipient address; it does not hide that address from the verifier or authenticate payer Machine Identity. |
| Hidden local-policy reputation thresholds | DEFERRED | The Phase 4F candidate was evaluated but not selected. Only external backend feasibility probes exist. |
| Machine identity and settlement-address association | ALREADY PROVIDED BY EXISTING 4A-4E FUNCTIONALITY | Phases 4B and 4C implement off-chain identity and signed address binding, with their existing limitations. |

The classification IMPLEMENTED IN 4F is intentionally unused: a working external
range-proof probe is not an implemented MYT disclosure product.

## Statements Needing Future Whitepaper Clarification

Section 13 groups all selective-disclosure functionality as future work. Some
single-payment and exportable verification functionality now exists in the
off-chain machine layer. That does not make the other ZK goals live on mainnet.

Section 12.1's general description of hiding counterparty relationships must be
narrowed when describing current OutProofV2 artifacts: the selected recipient is
an input to verification. Unrelated payment history need not be disclosed, but
counterparty-blind verification is a distinct, unimplemented capability.

Section 14 describes the identity layer as planned; released Phases 4B/4C now
provide concrete off-chain identity/binding functionality. They do not create
consensus identities, prove a person/device is unique, or establish payer identity.

## Boundaries Preserved

MYT Core remains a neutral settlement layer. No consensus, HF17, emission,
RandomX, transaction-format, blockchain or Wallet-RPC-schema changes were made.
This investigation made no transfers and accessed no wallet, daemon, Testnet or
Mainnet. Research/builds used public upstream network sources; proposed proof
operations themselves require no network or on-chain writes.

If Phase 4F resumes, disclosure must remain explicit and holder-controlled.
Stable subject/credential identifiers are linkable. Thresholds at domain
boundaries and repeated adaptive threshold queries can reveal more than users
expect. No anonymous-credential, universal-score or full-history claim is made.

See [the design gate](phase4f-cryptographic-design.md) and
[validation report](../MYT_Phase4F_Validation.md).

## Credential Architecture Mapping Addendum

The [new credential review](phase4f-credential-architecture-review.md) identifies
a narrower potential 4F milestone. BBS could selectively disclose an evaluator's
signed assertion that a local reputation predicate was satisfied, without
including full history or the exact count. That is **not** an arithmetic proof
of the count and does not establish the evaluator's honesty or completeness.

| Goal | Classification after credential review | Scope |
| --- | --- | --- |
| Off-chain identity, binding, invoices and single-payment proof verification | ALREADY PROVIDED BY 4A-4E | Existing semantics unchanged |
| Caller-local deterministic reputation evaluation | ALREADY PROVIDED BY 4E | Explicit trust and local observations; no global score |
| ZK presentation of evaluator-signed reputation predicate claims | WOULD BE ADDRESSED BY PROPOSED 4F B | Architecture promising; no qualified backend or product implementation |
| Hide exact reputation count while disclosing a predicate | PARTIALLY ADDRESSED BY PROPOSAL | No count field needed, but repeated/boundary predicates and metadata permit inference |
| Arithmetic inequality on a hidden signed integer | DEFERRED | B does not provide it; A remains blocked and tested C fails request-binding gate |
| Hidden wallet-balance ranges and private transaction-set auditing | DEFERRED | Not solved by reputation credentials |
| Counterparty-blind settlement proofs | DEFERRED | OutProofV2 recipient input remains visible |
| Anonymous subjects, globally certified trust and service-quality proof | OUT OF SCOPE | Proposed subject ID remains public and evaluator trust remains explicit |

No item is marked IMPLEMENTED IN 4F. No published whitepaper was edited. A future
public description must say "zero-knowledge selective disclosure of
evaluator-signed reputation predicate claims", not "MYT proves reputation scores
or wallet balance ranges in zero knowledge".
