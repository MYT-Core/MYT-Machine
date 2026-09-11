import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {dirname, resolve} from 'node:path';
import {
  ChallengeStore,
  DISCLOSED_MESSAGE_INDEXES,
  HIDDEN_MESSAGE_INDEXES,
  KEY_AUTH_CONTEXT,
  MESSAGE_SCHEMA,
  SUBJECT_CONTROL_CONTEXT,
  b64url,
  createKeyAuthorization,
  createMachineIdentity,
  createPresentation,
  createSubjectControl,
  issueCredential,
  signPhase4b,
  verifyCredentialSignature,
  verifyKeyAuthorization,
  verifyPresentation,
} from '../src/phase4f.mjs';
import {FIXED_TIME, TEST_SEEDS, buildFixture} from '../src/fixture.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function freshStore(request) {
  const store = new ChallengeStore();
  store.register(request);
  return store;
}

async function verifyFixture(fixture, overrides = {}) {
  return verifyPresentation({
    presentation: overrides.presentation ?? fixture.presentation,
    challengeStore: overrides.challengeStore ?? freshStore(
      (overrides.presentation ?? fixture.presentation).request
    ),
    trustedEvaluatorMachineId: overrides.trustedEvaluatorMachineId ??
      fixture.evaluator.publicIdentity.machine_id,
    now: overrides.now ?? FIXED_TIME,
  });
}

test('Phase 4B framing matches the published v1 deterministic vector', () => {
  const identity = createMachineIdentity(TEST_SEEDS.evaluator_ed25519);
  assert.equal(
    identity.publicIdentity.machine_id,
    'myt-machine-v1:ghejgw76kap2alahrz3yjxqp2exn2bq4hexrjnj4ly56inqyonfa'
  );
  const signature = signPhase4b(
    identity,
    'myt-machine/test-vector/v1',
    new TextEncoder().encode('MYT Phase 4B deterministic vector')
  );
  assert.equal(
    signature,
    '-utjLP8D6SCMA3CvD2QJcw2I2vQXFGjrdOJt_rEWpBuRFY8-Hd4PyaMagV4IDHM3gn0Fn-PdBCH6YCqROzeMDA'
  );
});

test('valid end-to-end evaluator assertion and subject-control presentation passes', async () => {
  const fixture = await buildFixture();
  const result = await verifyFixture(fixture);
  assert.equal(result.valid, true);
  assert.equal(result.predicate.metric_id, 'verified_recipient_settlement_events');
  assert.equal(result.predicate.threshold, 25);
  assert.equal(fixture.predicate.metric_value, 37);
  assert.equal(fixture.evaluation.local_policy_output.accepted_attestations, 2);
});

test('selective disclosure hides exact metric and Phase 4E evidence digest', async () => {
  const fixture = await buildFixture();
  const disclosedIndexes = fixture.presentation.disclosed_messages.map(m => m.index);
  assert.deepEqual(disclosedIndexes, [...DISCLOSED_MESSAGE_INDEXES]);
  assert.deepEqual(HIDDEN_MESSAGE_INDEXES.map(index => MESSAGE_SCHEMA[index]), [
    'phase4e_evidence_digest',
    'metric_value',
  ]);
  assert.equal(
    fixture.presentation.disclosed_messages.some(m => m.value === '37'),
    false
  );
  assert.equal(
    fixture.presentation.disclosed_messages.some(
      m => m.value === fixture.evaluation.phase4e_evidence_digest
    ),
    false
  );
});

test('BBS credential signature validates and message tampering fails', async () => {
  const fixture = await buildFixture();
  assert.equal(await verifyCredentialSignature({
    credential: fixture.credential,
    authorization: fixture.authorization,
  }), true);
  const tampered = structuredClone(fixture.credential);
  tampered.messages[8] = '38';
  assert.equal(await verifyCredentialSignature({
    credential: tampered,
    authorization: fixture.authorization,
  }), false);
});

test('raw proof is 336 bytes with exactly two hidden messages', async () => {
  const fixture = await buildFixture();
  assert.equal(Buffer.from(fixture.presentation.bbs_proof, 'base64url').length, 336);
  assert.equal(HIDDEN_MESSAGE_INDEXES.length, 2);
});

test('replaying a previously accepted presentation is rejected', async () => {
  const fixture = await buildFixture();
  const first = await verifyPresentation({
    presentation: fixture.presentation,
    challengeStore: fixture.challengeStore,
    trustedEvaluatorMachineId: fixture.evaluator.publicIdentity.machine_id,
    now: FIXED_TIME,
  });
  const replay = await verifyPresentation({
    presentation: fixture.presentation,
    challengeStore: fixture.challengeStore,
    trustedEvaluatorMachineId: fixture.evaluator.publicIdentity.machine_id,
    now: FIXED_TIME,
  });
  assert.equal(first.valid, true);
  assert.equal(replay.valid, false);
  assert.match(replay.reason, /already used/);
});

test('audience substitution invalidates the BBS presentation header', async () => {
  const fixture = await buildFixture();
  const attack = structuredClone(fixture.presentation);
  attack.request.audience = 'https://attacker.example/substituted-audience';
  const result = await verifyFixture(fixture, {presentation: attack});
  assert.equal(result.valid, false);
  assert.match(result.reason, /BBS selective-disclosure proof is invalid/);
});

test('challenge substitution invalidates the BBS presentation header', async () => {
  const fixture = await buildFixture();
  const attack = structuredClone(fixture.presentation);
  attack.request.challenge = b64url(new Uint8Array(32).fill(0xff));
  const result = await verifyFixture(fixture, {presentation: attack});
  assert.equal(result.valid, false);
  assert.match(result.reason, /BBS selective-disclosure proof is invalid/);
});

test('requested-predicate substitution is rejected', async () => {
  const fixture = await buildFixture();
  const attack = structuredClone(fixture.presentation);
  attack.request.requested_predicate.threshold = 26;
  const result = await verifyFixture(fixture, {presentation: attack});
  assert.equal(result.valid, false);
  assert.match(result.reason, /claims do not satisfy/);
});

test('disclosed claim tampering is rejected', async () => {
  const fixture = await buildFixture();
  const attack = structuredClone(fixture.presentation);
  const issuedAt = attack.disclosed_messages.find(m => m.name === 'issued_at');
  issuedAt.value = String(FIXED_TIME - 1);
  const result = await verifyFixture(fixture, {presentation: attack});
  assert.equal(result.valid, false);
  assert.match(result.reason, /BBS selective-disclosure proof is invalid/);
});

test('wrong BBS issuer authorization is rejected', async () => {
  const fixture = await buildFixture();
  const attack = structuredClone(fixture.presentation);
  attack.key_authorization = createKeyAuthorization({
    evaluatorIdentity: fixture.evaluator,
    bbsPublicKey: fixture.alternateBbsKeyPair.publicKey,
    network: 'testnet',
    notBefore: FIXED_TIME - 100,
    expiresAt: FIXED_TIME + 86_400,
  });
  const result = await verifyFixture(fixture, {presentation: attack});
  assert.equal(result.valid, false);
  assert.match(result.reason, /claims do not satisfy/);
});

test('wrong Phase 4B subject controller is rejected', async () => {
  const fixture = await buildFixture();
  const attack = structuredClone(fixture.presentation);
  const proof = new Uint8Array(Buffer.from(attack.bbs_proof, 'base64url'));
  attack.subject_control = createSubjectControl({
    subjectIdentity: fixture.wrongSubject,
    request: attack.request,
    proof,
    keyId: fixture.authorization.key_id,
    subjectMachineId: fixture.subject.publicIdentity.machine_id,
  });
  const result = await verifyFixture(fixture, {presentation: attack});
  assert.equal(result.valid, false);
  assert.match(result.reason, /does not match the BBS credential subject/);
});

test('expired credential is rejected even when its BBS proof is valid', async () => {
  const fixture = await buildFixture({
    credentialIssuedAt: FIXED_TIME - 50,
    credentialExpiresAt: FIXED_TIME - 1,
    requestCreatedAt: FIXED_TIME - 50,
    requestLifetimeSeconds: 100,
    presentationTime: FIXED_TIME - 20,
  });
  const result = await verifyFixture(fixture, {now: FIXED_TIME});
  assert.equal(result.valid, false);
  assert.match(result.reason, /Credential is expired/);
});

test('expired verifier challenge is rejected', async () => {
  const fixture = await buildFixture({
    requestCreatedAt: FIXED_TIME,
    requestLifetimeSeconds: 1,
    presentationTime: FIXED_TIME,
  });
  const result = await verifyFixture(fixture, {now: FIXED_TIME + 2});
  assert.equal(result.valid, false);
  assert.match(result.reason, /challenge is expired/);
});

test('valid evaluator key authorization passes', async () => {
  const fixture = await buildFixture();
  const result = verifyKeyAuthorization({
    authorization: fixture.authorization,
    trustedEvaluatorMachineId: fixture.evaluator.publicIdentity.machine_id,
    expectedNetwork: 'testnet',
    now: FIXED_TIME,
  });
  assert.equal(result.valid, true);
  assert.equal(result.keyId, fixture.authorization.key_id);
});

test('tampered key authorization content is rejected', async () => {
  const fixture = await buildFixture();
  const attack = structuredClone(fixture.presentation);
  attack.key_authorization.expires_at += 1;
  const result = await verifyFixture(fixture, {presentation: attack});
  assert.equal(result.valid, false);
  assert.match(result.reason, /ID does not match/);
});

test('cryptographically valid but expired key authorization is rejected', async () => {
  const fixture = await buildFixture();
  const attack = structuredClone(fixture.presentation);
  attack.key_authorization = createKeyAuthorization({
    evaluatorIdentity: fixture.evaluator,
    bbsPublicKey: fixture.bbsKeyPair.publicKey,
    network: 'testnet',
    notBefore: FIXED_TIME - 100,
    expiresAt: FIXED_TIME - 1,
  });
  const result = await verifyFixture(fixture, {presentation: attack});
  assert.equal(result.valid, false);
  assert.match(result.reason, /authorization is expired/);
});

test('key authorization from an untrusted evaluator is rejected', async () => {
  const fixture = await buildFixture();
  const result = await verifyFixture(fixture, {
    trustedEvaluatorMachineId: fixture.wrongSubject.publicIdentity.machine_id,
  });
  assert.equal(result.valid, false);
  assert.match(result.reason, /evaluator is not trusted/);
});

test('key authorization with a wrong signed purpose is rejected', async () => {
  const fixture = await buildFixture();
  const attack = structuredClone(fixture.presentation);
  attack.key_authorization = createKeyAuthorization({
    evaluatorIdentity: fixture.evaluator,
    bbsPublicKey: fixture.bbsKeyPair.publicKey,
    network: 'testnet',
    notBefore: FIXED_TIME - 100,
    expiresAt: FIXED_TIME + 86_400,
    purpose: 'different-purpose',
  });
  const result = await verifyFixture(fixture, {presentation: attack});
  assert.equal(result.valid, false);
  assert.match(result.reason, /wrong purpose/);
});

test('key authorization for the wrong signed network is rejected', async () => {
  const fixture = await buildFixture();
  const attack = structuredClone(fixture.presentation);
  attack.key_authorization = createKeyAuthorization({
    evaluatorIdentity: fixture.evaluator,
    bbsPublicKey: fixture.bbsKeyPair.publicKey,
    network: 'mainnet',
    notBefore: FIXED_TIME - 100,
    expiresAt: FIXED_TIME + 86_400,
  });
  const result = await verifyFixture(fixture, {presentation: attack});
  assert.equal(result.valid, false);
  assert.match(result.reason, /wrong network/);
});

test('issuer refuses a BBS secret key that does not match the authorization', async () => {
  const fixture = await buildFixture();
  await assert.rejects(issueCredential({
    bbsSecretKey: fixture.alternateBbsKeyPair.secretKey,
    authorization: fixture.authorization,
    trustedEvaluatorMachineId: fixture.evaluator.publicIdentity.machine_id,
    evaluation: fixture.evaluation,
    predicate: fixture.predicate,
    issuedAt: FIXED_TIME,
    expiresAt: FIXED_TIME + 3_600,
  }), /does not match the authorized public key/);
});

test('two proofs from one credential are randomized and independently valid', async () => {
  const fixture = await buildFixture();
  const second = await createPresentation({
    credential: fixture.credential,
    authorization: fixture.authorization,
    subjectIdentity: fixture.subject,
    request: fixture.request,
    now: FIXED_TIME,
  });
  assert.notEqual(second.bbs_proof, fixture.presentation.bbs_proof);
  assert.notEqual(
    second.subject_control.signature,
    fixture.presentation.subject_control.signature
  );
  assert.equal((await verifyFixture(fixture)).valid, true);
  assert.equal((await verifyFixture(fixture, {presentation: second})).valid, true);
});

test('stored generated vector verifies as a standalone artifact', async () => {
  const vector = JSON.parse(await readFile(
    resolve(root, 'vectors', 'phase4f-v1.json'), 'utf8'
  ));
  const store = freshStore(vector.presentation_request);
  const result = await verifyPresentation({
    presentation: vector.presentation,
    challengeStore: store,
    trustedEvaluatorMachineId: vector.evaluator_identity.machine_id,
    now: FIXED_TIME,
  });
  assert.equal(result.valid, true);
  assert.equal(result.proof_bytes, vector.sizes.raw_bbs_proof_bytes);
});

test('protocol contexts are stable and Phase 4B-compatible ASCII', () => {
  assert.equal(KEY_AUTH_CONTEXT, 'myt-machine/phase4f/bbs-key-authorization/v1');
  assert.equal(SUBJECT_CONTROL_CONTEXT, 'myt-machine/phase4f/subject-control/v1');
});
