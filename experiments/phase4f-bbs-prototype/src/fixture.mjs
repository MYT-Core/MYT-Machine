import * as bbs from '@digitalbazaar/bbs-signatures';
import {
  CIPHERSUITE,
  ChallengeStore,
  artifactSizes,
  computeBoundedPredicate,
  createKeyAuthorization,
  createMachineIdentity,
  createPresentation,
  evaluateValidatedPhase4eSnapshot,
  issueCredential,
  sha256Hex,
  utf8,
  verifyPresentation,
} from './phase4f.mjs';

export const FIXED_TIME = 1_700_000_100;
export const TEST_SEEDS = Object.freeze({
  evaluator_ed25519: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
  subject_ed25519: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
  wrong_subject_ed25519: '1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100',
  attester_a_ed25519: 'f0e0d0c0b0a090807060504030201000102030405060708090a0b0c0d0e0f001',
  attester_b_ed25519: '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
  bbs_key_material: '4f3c2d1e0f102132435465768798a9bacbdcedfe0f1e2d3c4b5a69788796a5b4',
  alternate_bbs_key_material: 'b4a5968778695a4b3c2d1e0ffeeddbca9b8a7968574635241302f1e0d1c2b3a4',
});

function syntheticDigest(label) {
  return sha256Hex(utf8(`MYT-PHASE4E-SYNTHETIC-V1\0${label}`));
}

export function createSyntheticPhase4eSnapshot({subject, attesterA, attesterB}) {
  const settlementEvents = Array.from({length: 37}, (_, index) => ({
    evidence_digest: syntheticDigest(`settlement-${index}`),
    subject_machine_id: subject.publicIdentity.machine_id,
    network: 'testnet',
    verified: true,
  }));
  return {
    source: 'validated-phase4e-v0.5.x-snapshot',
    subject_machine_id: subject.publicIdentity.machine_id,
    network: 'testnet',
    settlement_events: settlementEvents,
    attestations: [
      {
        id: `myt-reputation-v1:${syntheticDigest('attestation-a')}`,
        issuer_machine_id: attesterA.publicIdentity.machine_id,
        subject_machine_id: subject.publicIdentity.machine_id,
        network: 'testnet',
        issued_at: FIXED_TIME - 60,
        outcome: 'POSITIVE',
        evidence_digest: settlementEvents[0].evidence_digest,
        signature_valid: true,
        revoked: false,
      },
      {
        id: `myt-reputation-v1:${syntheticDigest('attestation-b')}`,
        issuer_machine_id: attesterB.publicIdentity.machine_id,
        subject_machine_id: subject.publicIdentity.machine_id,
        network: 'testnet',
        issued_at: FIXED_TIME - 90,
        outcome: 'POSITIVE',
        evidence_digest: settlementEvents[1].evidence_digest,
        signature_valid: true,
        revoked: false,
      },
    ],
  };
}

export async function buildFixture({
  credentialIssuedAt = FIXED_TIME,
  credentialExpiresAt = FIXED_TIME + 3_600,
  requestCreatedAt = FIXED_TIME,
  requestLifetimeSeconds = 300,
  presentationTime = FIXED_TIME,
} = {}) {
  const evaluator = createMachineIdentity(TEST_SEEDS.evaluator_ed25519);
  const subject = createMachineIdentity(TEST_SEEDS.subject_ed25519);
  const wrongSubject = createMachineIdentity(TEST_SEEDS.wrong_subject_ed25519);
  const attesterA = createMachineIdentity(TEST_SEEDS.attester_a_ed25519);
  const attesterB = createMachineIdentity(TEST_SEEDS.attester_b_ed25519);
  const bbsKeyPair = await bbs.generateKeyPair({
    seed: new Uint8Array(Buffer.from(TEST_SEEDS.bbs_key_material, 'hex')),
    ciphersuite: CIPHERSUITE,
  });
  const alternateBbsKeyPair = await bbs.generateKeyPair({
    seed: new Uint8Array(Buffer.from(TEST_SEEDS.alternate_bbs_key_material, 'hex')),
    ciphersuite: CIPHERSUITE,
  });
  const authorization = createKeyAuthorization({
    evaluatorIdentity: evaluator,
    bbsPublicKey: bbsKeyPair.publicKey,
    network: 'testnet',
    notBefore: FIXED_TIME - 100,
    expiresAt: FIXED_TIME + 86_400,
  });
  const snapshot = createSyntheticPhase4eSnapshot({subject, attesterA, attesterB});
  const policy = {
    trusted_issuers: [
      attesterA.publicIdentity.machine_id,
      attesterB.publicIdentity.machine_id,
    ].sort(),
    max_per_issuer: 1,
    min_age: 0,
    max_age: 86_400,
    require_settlement: true,
  };
  const evaluation = evaluateValidatedPhase4eSnapshot({
    snapshot,
    policy,
    asOf: FIXED_TIME,
  });
  const predicate = computeBoundedPredicate({
    evaluation,
    metricId: 'verified_recipient_settlement_events',
    operator: 'gte',
    threshold: 25,
  });
  const credential = await issueCredential({
    bbsSecretKey: bbsKeyPair.secretKey,
    authorization,
    trustedEvaluatorMachineId: evaluator.publicIdentity.machine_id,
    evaluation,
    predicate,
    issuedAt: credentialIssuedAt,
    expiresAt: credentialExpiresAt,
  });
  const challengeStore = new ChallengeStore();
  const request = challengeStore.issue({
    audience: 'https://verifier.example/myt-machine',
    network: 'testnet',
    policyDigest: evaluation.policy_digest,
    requestedPredicate: {
      metric_id: predicate.metric_id,
      operator: predicate.operator,
      threshold: predicate.threshold,
      required_result: true,
    },
    now: requestCreatedAt,
    lifetimeSeconds: requestLifetimeSeconds,
    nonce: new Uint8Array(Buffer.from(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
      'hex'
    )),
  });
  const presentation = await createPresentation({
    credential,
    authorization,
    subjectIdentity: subject,
    request,
    now: presentationTime,
  });
  return {
    evaluator,
    subject,
    wrongSubject,
    attesterA,
    attesterB,
    bbsKeyPair,
    alternateBbsKeyPair,
    authorization,
    snapshot,
    policy,
    evaluation,
    predicate,
    credential,
    challengeStore,
    request,
    presentation,
  };
}

export async function buildVector() {
  const fixture = await buildFixture();
  const verificationStore = new ChallengeStore();
  verificationStore.register(fixture.request);
  const expectedVerification = await verifyPresentation({
    presentation: fixture.presentation,
    challengeStore: verificationStore,
    trustedEvaluatorMachineId: fixture.evaluator.publicIdentity.machine_id,
    now: FIXED_TIME,
  });
  if(!expectedVerification.valid) {
    throw new Error(`Generated vector did not verify: ${expectedVerification.reason}`);
  }
  return {
    metadata: {
      status: 'EXPERIMENTAL-NOT-FOR-PRODUCTION',
      vector_version: 1,
      backend: '@digitalbazaar/bbs-signatures@3.1.0',
      ciphersuite: CIPHERSUITE,
      note: 'Seeds are public test fixtures. BBS proofs are randomized, so regeneration changes proof bytes while preserving verification.',
    },
    public_test_seeds: TEST_SEEDS,
    phase4e_snapshot: fixture.snapshot,
    reputation_policy: fixture.policy,
    evaluator_output: fixture.evaluation,
    bounded_predicate_assertion: fixture.predicate,
    evaluator_identity: fixture.evaluator.publicIdentity,
    subject_identity: fixture.subject.publicIdentity,
    bbs_issuer_public_key: Buffer.from(fixture.bbsKeyPair.publicKey).toString('base64url'),
    key_authorization: fixture.authorization,
    credential: fixture.credential,
    presentation_request: fixture.request,
    presentation: fixture.presentation,
    sizes: artifactSizes({
      credential: fixture.credential,
      presentation: fixture.presentation,
    }),
    expected_verification: expectedVerification,
  };
}
