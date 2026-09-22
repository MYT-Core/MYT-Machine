import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

import {
  canonicalJson,
  createPresentationRequest,
  validatePresentationRequest,
  verifyKeyRevocation,
} from './phase4f.mjs';

const challengeBridge = fileURLToPath(
  new URL('../bridge/challenge_store.py', import.meta.url)
);
const phase4eBridge = fileURLToPath(
  new URL('../bridge/phase4e_adapter.py', import.meta.url)
);

function assertNonEmptyString(value, name, maximum = 4_096) {
  if(typeof value !== 'string' || value.length === 0 || value.length > maximum ||
    /[\u0000\r\n]/.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function bridgeCall({pythonExecutable, script, databasePath, args = [], payload}) {
  assertNonEmptyString(pythonExecutable, 'Python executable');
  assertNonEmptyString(databasePath, 'Database path');
  const result = spawnSync(
    pythonExecutable,
    [script, '--database', resolve(databasePath), ...args],
    {
      input: `${canonicalJson(payload)}\n`,
      encoding: 'utf8',
      windowsHide: true,
      shell: false,
      timeout: 15_000,
      maxBuffer: 1_048_576,
    }
  );
  if(result.error) {
    throw new Error('Python security bridge could not be executed');
  }
  let response;
  try {
    response = JSON.parse(result.stdout);
  } catch {
    throw new Error('Python security bridge returned an invalid response');
  }
  if(result.status !== 0 || response?.ok !== true) {
    throw new Error(
      typeof response?.error === 'string' ? response.error :
        'Python security bridge rejected the request'
    );
  }
  return response;
}

function configuredPython(value) {
  const executable = value ?? process.env.MYT_PHASE4F_PYTHON;
  if(!executable) {
    throw new Error('Set MYT_PHASE4F_PYTHON to an approved Python 3.10+ executable');
  }
  return assertNonEmptyString(executable, 'Python executable');
}

export class PythonSqliteChallengeStore {
  constructor({databasePath, pythonExecutable} = {}) {
    this.databasePath = resolve(assertNonEmptyString(databasePath, 'Database path'));
    this.pythonExecutable = configuredPython(pythonExecutable);
    bridgeCall({
      pythonExecutable: this.pythonExecutable,
      script: challengeBridge,
      databasePath: this.databasePath,
      args: ['--action', 'init'],
      payload: {},
    });
  }

  #call(action, payload) {
    return bridgeCall({
      pythonExecutable: this.pythonExecutable,
      script: challengeBridge,
      databasePath: this.databasePath,
      args: ['--action', action],
      payload,
    });
  }

  issue({
    audience,
    network,
    policyDigest,
    requestedPredicate,
    now,
    lifetimeSeconds = 120,
    nonce,
  }) {
    const request = createPresentationRequest({
      audience,
      network,
      policyDigest,
      requestedPredicate,
      now,
      lifetimeSeconds,
      nonce,
    });
    this.register(request);
    return request;
  }

  register(request) {
    validatePresentationRequest(request);
    this.#call('register', {request});
  }

  lookup(challenge, now) {
    const response = this.#call('lookup', {challenge, now});
    validatePresentationRequest(response.request);
    return response.request;
  }

  consume(challenge, now) {
    this.#call('consume', {challenge, now});
  }

  prune({now, retentionSeconds = 86_400}) {
    return this.#call('prune', {
      now,
      retention_seconds: retentionSeconds,
    }).deleted;
  }

  registerKeyRevocation({
    revocation,
    authorization,
    trustedEvaluatorMachineId,
    expectedNetwork,
    now,
  }) {
    const result = verifyKeyRevocation({
      revocation,
      authorization,
      trustedEvaluatorMachineId,
      expectedNetwork,
      now,
    });
    if(!result.valid) {
      throw new Error(result.reason);
    }
    return this.#call('register-key-revocation', {revocation}).inserted;
  }

  lookupKeyRevocation(keyId) {
    return this.#call('lookup-key-revocation', {key_id: keyId}).revocation;
  }
}

export class PythonPhase4eAdapter {
  constructor({pythonExecutable} = {}) {
    this.pythonExecutable = configuredPython(pythonExecutable);
  }

  evaluate({
    databasePath,
    subjectMachineId,
    network,
    policy,
    asOf,
    requestedPredicate,
  }) {
    const response = bridgeCall({
      pythonExecutable: this.pythonExecutable,
      script: phase4eBridge,
      databasePath,
      payload: {
        subject_machine_id: subjectMachineId,
        network,
        policy,
        as_of: asOf,
        requested_predicate: requestedPredicate,
      },
    });
    const result = response.result;
    if(!result || result.type !== 'myt-phase4f-evaluator-result' ||
      result.version !== 1 ||
      result.assertion_semantics !==
        'trusted-evaluator-assertion-not-mathematical-range-proof') {
      throw new Error('Phase 4E adapter returned an unsupported result');
    }
    return result;
  }
}
