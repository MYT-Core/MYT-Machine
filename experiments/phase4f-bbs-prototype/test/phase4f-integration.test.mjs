import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import {after, before, test} from 'node:test';
import {fileURLToPath} from 'node:url';

import {
  HIDDEN_MESSAGE_INDEXES,
  createKeyRevocation,
  createPresentation,
  issueCredential,
  verifyPresentation,
} from '../src/phase4f.mjs';
import {
  PythonPhase4eAdapter,
  PythonSqliteChallengeStore,
} from '../src/python-bridge.mjs';
import {loadBbsSecretKey, saveBbsSecretKey} from '../src/secure-key-store.mjs';
import {FIXED_TIME, buildFixture} from '../src/fixture.mjs';


const experimentRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const pythonExecutable = process.env.MYT_PHASE4F_PYTHON;
const seedScript = resolve(experimentRoot, 'test', 'seed_phase4e_store.py');
let temporaryRoot;
let fixture;

before(async () => {
  assert.ok(pythonExecutable, 'MYT_PHASE4F_PYTHON must name Python 3.10+');
  temporaryRoot = mkdtempSync(join(tmpdir(), 'myt-phase4f-integration-'));
  const prototype = await buildFixture();
  const reputationDatabase = join(temporaryRoot, 'reputation.sqlite');
  const seeded = spawnSync(
    pythonExecutable,
    [seedScript, reputationDatabase, prototype.subject.publicIdentity.machine_id, '37'],
    {encoding: 'utf8', windowsHide: true, shell: false}
  );
  assert.equal(seeded.status, 0, 'test Phase 4E store must be created');
  const adapterResult = new PythonPhase4eAdapter({pythonExecutable}).evaluate({
    databasePath: reputationDatabase,
    subjectMachineId: prototype.subject.publicIdentity.machine_id,
    network: 'testnet',
    policy: {
      trusted_issuers: [],
      max_per_issuer: 1,
      min_age: 0,
      max_age: 253402300799,
      require_settlement: false,
    },
    asOf: FIXED_TIME,
    requestedPredicate: {
      metric_id: 'verified_recipient_settlement_events',
      operator: 'gte',
      threshold: 25,
    },
  });
  const encryptedKeyPath = join(temporaryRoot, 'bbs-issuer-key.json');
  const passphrase = Buffer.from('production-candidate-test-passphrase', 'utf8');
  const saved = await saveBbsSecretKey({
    path: encryptedKeyPath,
    secretKey: prototype.bbsKeyPair.secretKey,
    passphrase,
  });
  assert.equal(saved.keyId, prototype.authorization.key_id);
  const loadedSecretKey = await loadBbsSecretKey({
    path: encryptedKeyPath,
    passphrase,
    expectedKeyId: prototype.authorization.key_id,
  });
  const issuerStatusStore = new PythonSqliteChallengeStore({
    databasePath: join(temporaryRoot, 'issuer-status.sqlite'),
    pythonExecutable,
  });
  let credential;
  try {
    credential = await issueCredential({
      bbsSecretKey: loadedSecretKey,
      authorization: prototype.authorization,
      trustedEvaluatorMachineId: prototype.evaluator.publicIdentity.machine_id,
      evaluation: adapterResult.evaluation,
      predicate: adapterResult.predicate,
      issuedAt: FIXED_TIME,
      expiresAt: FIXED_TIME + 3_600,
      keyStatusStore: issuerStatusStore,
    });
  } finally {
    loadedSecretKey.fill(0);
    passphrase.fill(0);
  }
  fixture = {...prototype, adapterResult, credential};
});

after(() => {
  if(temporaryRoot) {
    rmSync(temporaryRoot, {recursive: true, force: true});
  }
});

function issuePresentation(databaseName, nonceByte) {
  const databasePath = join(temporaryRoot, databaseName);
  const challengeStore = new PythonSqliteChallengeStore({
    databasePath, pythonExecutable,
  });
  const request = challengeStore.issue({
    audience: 'https://verifier.example/myt-machine',
    network: 'testnet',
    policyDigest: fixture.adapterResult.evaluation.policy_digest,
    requestedPredicate: {
      metric_id: fixture.adapterResult.predicate.metric_id,
      operator: fixture.adapterResult.predicate.operator,
      threshold: fixture.adapterResult.predicate.threshold,
      required_result: true,
    },
    now: FIXED_TIME,
    lifetimeSeconds: 120,
    nonce: new Uint8Array(32).fill(nonceByte),
  });
  return createPresentation({
    credential: fixture.credential,
    authorization: fixture.authorization,
    subjectIdentity: fixture.subject,
    request,
    now: FIXED_TIME,
    keyStatusStore: challengeStore,
  }).then(presentation => ({databasePath, challengeStore, presentation}));
}

test('real Phase 4E store feeds the BBS credential without disclosing value 37', async () => {
  assert.equal(fixture.adapterResult.predicate.metric_value, 37);
  assert.equal(fixture.adapterResult.predicate.result, true);
  assert.deepEqual(HIDDEN_MESSAGE_INDEXES, [6, 8]);
  const run = await issuePresentation('real-phase4e.sqlite', 1);
  assert.equal(run.presentation.disclosed_messages.some(item => item.value === '37'), false);
  const result = await verifyPresentation({
    presentation: run.presentation,
    challengeStore: run.challengeStore,
    keyStatusStore: run.challengeStore,
    trustedEvaluatorMachineId: fixture.evaluator.publicIdentity.machine_id,
    now: FIXED_TIME,
  });
  assert.equal(result.valid, true);
});

test('accepted challenge remains consumed after verifier restart', async () => {
  const run = await issuePresentation('restart.sqlite', 2);
  const firstVerifier = new PythonSqliteChallengeStore({
    databasePath: run.databasePath, pythonExecutable,
  });
  const first = await verifyPresentation({
    presentation: run.presentation,
    challengeStore: firstVerifier,
    keyStatusStore: firstVerifier,
    trustedEvaluatorMachineId: fixture.evaluator.publicIdentity.machine_id,
    now: FIXED_TIME,
  });
  const restartedVerifier = new PythonSqliteChallengeStore({
    databasePath: run.databasePath, pythonExecutable,
  });
  const replay = await verifyPresentation({
    presentation: run.presentation,
    challengeStore: restartedVerifier,
    keyStatusStore: restartedVerifier,
    trustedEvaluatorMachineId: fixture.evaluator.publicIdentity.machine_id,
    now: FIXED_TIME,
  });
  assert.equal(first.valid, true);
  assert.equal(replay.valid, false);
  assert.match(replay.reason, /already used/);
});

test('shared durable verifier state permits exactly one acceptance', async () => {
  const run = await issuePresentation('shared.sqlite', 3);
  const verifierA = new PythonSqliteChallengeStore({
    databasePath: run.databasePath, pythonExecutable,
  });
  const verifierB = new PythonSqliteChallengeStore({
    databasePath: run.databasePath, pythonExecutable,
  });
  const results = await Promise.all([verifierA, verifierB].map(challengeStore =>
    verifyPresentation({
      presentation: run.presentation,
      challengeStore,
      keyStatusStore: challengeStore,
      trustedEvaluatorMachineId: fixture.evaluator.publicIdentity.machine_id,
      now: FIXED_TIME,
    })
  ));
  assert.equal(results.filter(result => result.valid).length, 1);
  assert.equal(results.filter(result => !result.valid).length, 1);
});

test('signed key revocation survives restart and blocks presentation', async () => {
  const run = await issuePresentation('revocation.sqlite', 4);
  const revocation = createKeyRevocation({
    evaluatorIdentity: fixture.evaluator,
    authorization: fixture.authorization,
    revokedAt: FIXED_TIME,
    reason: 'compromised',
  });
  const registration = {
    revocation,
    authorization: fixture.authorization,
    trustedEvaluatorMachineId: fixture.evaluator.publicIdentity.machine_id,
    expectedNetwork: 'testnet',
    now: FIXED_TIME,
  };
  assert.equal(run.challengeStore.registerKeyRevocation(registration), true);
  assert.equal(run.challengeStore.registerKeyRevocation(registration), false);
  const restartedStore = new PythonSqliteChallengeStore({
    databasePath: run.databasePath, pythonExecutable,
  });
  const result = await verifyPresentation({
    presentation: run.presentation,
    challengeStore: restartedStore,
    keyStatusStore: restartedStore,
    trustedEvaluatorMachineId: fixture.evaluator.publicIdentity.machine_id,
    now: FIXED_TIME,
  });
  assert.equal(result.valid, false);
  assert.match(result.reason, /issuer key is revoked/);
});
