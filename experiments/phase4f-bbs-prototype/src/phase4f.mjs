import * as bbs from '@digitalbazaar/bbs-signatures';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as ed25519Sign,
  verify as ed25519Verify,
} from 'node:crypto';

const encoder = new TextEncoder();

export const CIPHERSUITE = 'BLS12-381-SHA-256';
export const CREDENTIAL_HEADER = utf8('MYT-MACHINE-PHASE4F-CREDENTIAL-V1\n');
export const KEY_AUTH_CONTEXT = 'myt-machine/phase4f/bbs-key-authorization/v1';
export const KEY_REVOCATION_CONTEXT = 'myt-machine/phase4f/bbs-key-revocation/v1';
export const SUBJECT_CONTROL_CONTEXT = 'myt-machine/phase4f/subject-control/v1';
export const PRESENTATION_PREFIX = 'MYT-MACHINE-PHASE4F-PRESENTATION-V1\n';

export const MESSAGE_SCHEMA = Object.freeze([
  'schema',
  'evaluator_machine_id',
  'bbs_key_id',
  'subject_machine_id',
  'network',
  'policy_digest',
  'phase4e_evidence_digest',
  'metric_id',
  'metric_value',
  'predicate_metric_id',
  'predicate_operator',
  'predicate_threshold',
  'predicate_result',
  'issued_at',
  'expires_at',
]);

// Only the exact local metric and the Phase 4E evidence digest remain hidden.
export const HIDDEN_MESSAGE_INDEXES = Object.freeze([6, 8]);
export const DISCLOSED_MESSAGE_INDEXES = Object.freeze(
  MESSAGE_SCHEMA.map((_, index) => index).filter(
    index => !HIDDEN_MESSAGE_INDEXES.includes(index)
  )
);

const MACHINE_ID_DOMAIN = utf8('MYT-MACHINE-ID\0v1\0ed25519\0');
const SIGNATURE_DOMAIN = utf8('MYT-MACHINE-SIGNATURE\0');
const ED25519_PKCS8_SEED_PREFIX = Buffer.from(
  '302e020100300506032b657004220420', 'hex'
);
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
const MACHINE_ID_RE = /^myt-machine-v1:[a-z2-7]{52}$/;
const CONTEXT_RE = /^[a-z0-9._:/-]+$/;
const HEX_32_RE = /^[0-9a-f]{64}$/;
const NETWORKS = new Set(['mainnet', 'testnet', 'stagenet']);
const MAX_TIMESTAMP = 253402300799;
const KEY_AUTH_FIELDS = Object.freeze([
  'type', 'version', 'evaluator', 'ciphersuite', 'bbs_public_key',
  'key_id', 'purpose', 'network', 'not_before', 'expires_at',
]);
const KEY_REVOCATION_FIELDS = Object.freeze([
  'type', 'version', 'evaluator_machine_id', 'bbs_key_id',
  'authorization_id', 'network', 'revoked_at', 'reason',
]);
const KEY_REVOCATION_REASONS = new Set([
  'unspecified', 'compromised', 'rotated', 'retired',
]);

export const PREDICATE_CATALOG = Object.freeze({
  verified_recipient_settlement_events: Object.freeze({
    operators: Object.freeze(['gte']),
    metricMinimum: 0,
    metricMaximum: 100_000,
    thresholdMinimum: 0,
    thresholdMaximum: 10_000,
  }),
});

export function utf8(value) {
  return encoder.encode(value);
}

export function b64url(value) {
  return Buffer.from(value).toString('base64url');
}

export function decodeB64url(value, {expectedBytes, name = 'value'} = {}) {
  if(typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`${name} is not canonical unpadded Base64url`);
  }
  const decoded = Buffer.from(value, 'base64url');
  if((expectedBytes !== undefined && decoded.length !== expectedBytes) ||
    decoded.toString('base64url') !== value) {
    throw new Error(`${name} is not canonical unpadded Base64url`);
  }
  return new Uint8Array(decoded);
}

export function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function canonicalJson(value) {
  if(value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if(typeof value === 'number') {
    if(!Number.isSafeInteger(value)) {
      throw new Error('Canonical JSON permits only safe integers');
    }
    return JSON.stringify(value);
  }
  if(Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  if(value && typeof value === 'object' &&
    Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map(
      key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    ).join(',')}}`;
  }
  throw new Error('Unsupported canonical JSON value');
}

function canonicalPayload(prefix, value) {
  return utf8(`${prefix}${canonicalJson(value)}`);
}

function assertExactKeys(value, expected, name) {
  if(!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if(actual.length !== wanted.length || actual.some((key, i) => key !== wanted[i])) {
    throw new Error(`${name} has missing or unknown fields`);
  }
}

function assertSafeInteger(value, name, minimum = 0, maximum = MAX_TIMESTAMP) {
  if(!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} is outside its integer bounds`);
  }
  return value;
}

function assertNetwork(network) {
  if(!NETWORKS.has(network)) {
    throw new Error('Unsupported MYT network');
  }
  return network;
}

function base32Encode(value) {
  let bits = 0;
  let accumulator = 0;
  let output = '';
  for(const byte of value) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while(bits >= 5) {
      bits -= 5;
      output += BASE32_ALPHABET[(accumulator >>> bits) & 31];
    }
  }
  if(bits > 0) {
    output += BASE32_ALPHABET[(accumulator << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(value) {
  let bits = 0;
  let accumulator = 0;
  const output = [];
  for(const char of value) {
    const digit = BASE32_ALPHABET.indexOf(char);
    if(digit < 0) {
      throw new Error('Invalid Machine ID Base32');
    }
    accumulator = (accumulator << 5) | digit;
    bits += 5;
    if(bits >= 8) {
      bits -= 8;
      output.push((accumulator >>> bits) & 255);
    }
  }
  const decoded = Buffer.from(output);
  if(decoded.length !== 32 || base32Encode(decoded) !== value) {
    throw new Error('Machine ID is not canonical');
  }
  return decoded;
}

function machineIdDigest(machineId) {
  if(typeof machineId !== 'string' || !MACHINE_ID_RE.test(machineId)) {
    throw new Error('Machine ID has an invalid format');
  }
  return base32Decode(machineId.slice('myt-machine-v1:'.length));
}

export function deriveMachineId(publicKeyBytes) {
  if(!(publicKeyBytes instanceof Uint8Array) || publicKeyBytes.length !== 32) {
    throw new Error('Ed25519 public key must contain exactly 32 bytes');
  }
  const digest = createHash('sha256')
    .update(MACHINE_ID_DOMAIN)
    .update(publicKeyBytes)
    .digest();
  return `myt-machine-v1:${base32Encode(digest)}`;
}

export function createMachineIdentity(seedHex) {
  if(typeof seedHex !== 'string' || !HEX_32_RE.test(seedHex)) {
    throw new Error('Test identity seed must be exactly 32 bytes of lowercase hex');
  }
  const seed = Buffer.from(seedHex, 'hex');
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_SEED_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicDer = createPublicKey(privateKey).export({format: 'der', type: 'spki'});
  const publicKey = new Uint8Array(publicDer.subarray(-32));
  const publicIdentity = {
    algorithm: 'ed25519',
    machine_id: deriveMachineId(publicKey),
    public_key: b64url(publicKey),
    type: 'myt-machine-identity',
    version: 1,
  };
  return {privateKey, publicIdentity};
}

export function validateIdentityDocument(identity) {
  assertExactKeys(
    identity,
    ['algorithm', 'machine_id', 'public_key', 'type', 'version'],
    'Phase 4B identity'
  );
  if(identity.type !== 'myt-machine-identity' || identity.version !== 1 ||
    identity.algorithm !== 'ed25519') {
    throw new Error('Unsupported Phase 4B identity profile');
  }
  const rawPublicKey = decodeB64url(identity.public_key, {
    expectedBytes: 32,
    name: 'Phase 4B public key',
  });
  if(deriveMachineId(rawPublicKey) !== identity.machine_id) {
    throw new Error('Phase 4B Machine ID does not match its public key');
  }
  const publicKey = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(rawPublicKey)]),
    format: 'der',
    type: 'spki',
  });
  return {rawPublicKey, publicKey};
}

export function phase4bSignatureFrame(machineId, context, message) {
  const digest = machineIdDigest(machineId);
  if(typeof context !== 'string' || context.length === 0 ||
    Buffer.byteLength(context, 'ascii') > 128 || !CONTEXT_RE.test(context)) {
    throw new Error('Invalid Phase 4B signature context');
  }
  if(!(message instanceof Uint8Array) || message.length === 0 || message.length > 65_536) {
    throw new Error('Invalid Phase 4B signature message');
  }
  const contextBytes = Buffer.from(context, 'ascii');
  const contextLength = Buffer.alloc(2);
  contextLength.writeUInt16BE(contextBytes.length);
  const messageLength = Buffer.alloc(8);
  messageLength.writeBigUInt64BE(BigInt(message.length));
  return Buffer.concat([
    Buffer.from(SIGNATURE_DOMAIN),
    Buffer.from([1]),
    digest,
    contextLength,
    contextBytes,
    messageLength,
    Buffer.from(message),
  ]);
}

export function signPhase4b(identity, context, message) {
  const frame = phase4bSignatureFrame(
    identity.publicIdentity.machine_id, context, message
  );
  return b64url(ed25519Sign(null, frame, identity.privateKey));
}

export function verifyPhase4b(identityDocument, context, message, signature) {
  try {
    const {publicKey} = validateIdentityDocument(identityDocument);
    const rawSignature = decodeB64url(signature, {
      expectedBytes: 64,
      name: 'Phase 4B signature',
    });
    const frame = phase4bSignatureFrame(identityDocument.machine_id, context, message);
    return ed25519Verify(null, frame, publicKey, rawSignature);
  } catch {
    return false;
  }
}

export function bbsKeyId(publicKey, ciphersuite = CIPHERSUITE) {
  return `myt-phase4f-bbs-key-v1:${sha256Hex(Buffer.concat([
    Buffer.from(ciphersuite, 'ascii'), Buffer.from([0]), Buffer.from(publicKey),
  ]))}`;
}

function keyRevocationBody(revocation) {
  return Object.fromEntries(KEY_REVOCATION_FIELDS.map(key => [key, revocation[key]]));
}

function keyRevocationContent(body) {
  return canonicalPayload('MYT-PHASE4F-BBS-KEY-REVOCATION-V1\n', body);
}

function keyAuthorizationBody(authorization) {
  return Object.fromEntries(KEY_AUTH_FIELDS.map(key => [key, authorization[key]]));
}

function keyAuthorizationContent(body) {
  return canonicalPayload('MYT-PHASE4F-BBS-KEY-AUTHORIZATION-V1\n', body);
}

export function createKeyAuthorization({
  evaluatorIdentity,
  bbsPublicKey,
  network,
  notBefore,
  expiresAt,
  purpose = 'myt-phase4f-reputation-credential',
}) {
  validateIdentityDocument(evaluatorIdentity.publicIdentity);
  assertNetwork(network);
  assertSafeInteger(notBefore, 'Key authorization not-before');
  assertSafeInteger(expiresAt, 'Key authorization expiry');
  if(expiresAt <= notBefore) {
    throw new Error('Key authorization expiry must follow not-before');
  }
  if(!(bbsPublicKey instanceof Uint8Array) || bbsPublicKey.length !== 96) {
    throw new Error('BBS public key must contain exactly 96 bytes');
  }
  const body = {
    type: 'myt-phase4f-bbs-key-authorization',
    version: 1,
    evaluator: evaluatorIdentity.publicIdentity,
    ciphersuite: CIPHERSUITE,
    bbs_public_key: b64url(bbsPublicKey),
    key_id: bbsKeyId(bbsPublicKey),
    purpose,
    network,
    not_before: notBefore,
    expires_at: expiresAt,
  };
  const content = keyAuthorizationContent(body);
  return {
    ...body,
    id: `myt-phase4f-key-auth-v1:${sha256Hex(content)}`,
    signature: signPhase4b(evaluatorIdentity, KEY_AUTH_CONTEXT, content),
  };
}

export function verifyKeyAuthorization({
  authorization,
  trustedEvaluatorMachineId,
  expectedNetwork,
  now,
}) {
  try {
    assertExactKeys(
      authorization,
      [...KEY_AUTH_FIELDS, 'id', 'signature'],
      'BBS key authorization'
    );
    if(authorization.type !== 'myt-phase4f-bbs-key-authorization' ||
      authorization.version !== 1 || authorization.ciphersuite !== CIPHERSUITE) {
      throw new Error('Unsupported BBS key authorization profile');
    }
    if(authorization.purpose !== 'myt-phase4f-reputation-credential') {
      throw new Error('BBS key authorization has the wrong purpose');
    }
    assertNetwork(authorization.network);
    if(authorization.network !== expectedNetwork) {
      throw new Error('BBS key authorization has the wrong network');
    }
    assertSafeInteger(now, 'Verification time');
    assertSafeInteger(authorization.not_before, 'Key authorization not-before');
    assertSafeInteger(authorization.expires_at, 'Key authorization expiry');
    if(now < authorization.not_before) {
      throw new Error('BBS key authorization is not active yet');
    }
    if(now >= authorization.expires_at) {
      throw new Error('BBS key authorization is expired');
    }
    validateIdentityDocument(authorization.evaluator);
    if(authorization.evaluator.machine_id !== trustedEvaluatorMachineId) {
      throw new Error('BBS key authorization evaluator is not trusted');
    }
    const publicKey = decodeB64url(authorization.bbs_public_key, {
      expectedBytes: 96,
      name: 'BBS public key',
    });
    if(bbsKeyId(publicKey, authorization.ciphersuite) !== authorization.key_id) {
      throw new Error('BBS key authorization key ID does not match its public key');
    }
    const body = keyAuthorizationBody(authorization);
    const content = keyAuthorizationContent(body);
    if(authorization.id !== `myt-phase4f-key-auth-v1:${sha256Hex(content)}`) {
      throw new Error('BBS key authorization ID does not match its content');
    }
    if(!verifyPhase4b(
      authorization.evaluator,
      KEY_AUTH_CONTEXT,
      content,
      authorization.signature
    )) {
      throw new Error('BBS key authorization Phase 4B signature is invalid');
    }
    return {valid: true, publicKey, keyId: authorization.key_id};
  } catch(error) {
    return {valid: false, reason: error.message};
  }
}

export function createKeyRevocation({
  evaluatorIdentity,
  authorization,
  revokedAt,
  reason = 'unspecified',
}) {
  validateIdentityDocument(evaluatorIdentity.publicIdentity);
  assertSafeInteger(revokedAt, 'Key revocation time');
  if(!KEY_REVOCATION_REASONS.has(reason)) {
    throw new Error('Unsupported BBS key revocation reason');
  }
  if(authorization.evaluator?.machine_id !==
    evaluatorIdentity.publicIdentity.machine_id) {
    throw new Error('BBS key revocation evaluator does not own the authorization');
  }
  const authorizationCheckTime = Math.min(
    Math.max(revokedAt, authorization.not_before),
    authorization.expires_at - 1
  );
  const authResult = verifyKeyAuthorization({
    authorization,
    trustedEvaluatorMachineId: evaluatorIdentity.publicIdentity.machine_id,
    expectedNetwork: authorization.network,
    now: authorizationCheckTime,
  });
  if(!authResult.valid) {
    throw new Error(authResult.reason);
  }
  const body = {
    type: 'myt-phase4f-bbs-key-revocation',
    version: 1,
    evaluator_machine_id: evaluatorIdentity.publicIdentity.machine_id,
    bbs_key_id: authorization.key_id,
    authorization_id: authorization.id,
    network: authorization.network,
    revoked_at: revokedAt,
    reason,
  };
  const content = keyRevocationContent(body);
  return {
    ...body,
    id: `myt-phase4f-key-revocation-v1:${sha256Hex(content)}`,
    signature: signPhase4b(evaluatorIdentity, KEY_REVOCATION_CONTEXT, content),
  };
}

export function verifyKeyRevocation({
  revocation,
  authorization,
  trustedEvaluatorMachineId,
  expectedNetwork,
  now,
}) {
  try {
    assertExactKeys(
      revocation,
      [...KEY_REVOCATION_FIELDS, 'id', 'signature'],
      'BBS key revocation'
    );
    if(revocation.type !== 'myt-phase4f-bbs-key-revocation' ||
      revocation.version !== 1 || !KEY_REVOCATION_REASONS.has(revocation.reason)) {
      throw new Error('Unsupported BBS key revocation profile');
    }
    assertSafeInteger(revocation.revoked_at, 'Key revocation time');
    const authResult = verifyKeyAuthorization({
      authorization,
      trustedEvaluatorMachineId,
      expectedNetwork,
      now,
    });
    if(!authResult.valid) {
      throw new Error(authResult.reason);
    }
    if(revocation.evaluator_machine_id !== trustedEvaluatorMachineId ||
      revocation.evaluator_machine_id !== authorization.evaluator.machine_id ||
      revocation.bbs_key_id !== authorization.key_id ||
      revocation.authorization_id !== authorization.id ||
      revocation.network !== expectedNetwork) {
      throw new Error('BBS key revocation does not match its authorization');
    }
    const body = keyRevocationBody(revocation);
    const content = keyRevocationContent(body);
    if(revocation.id !==
      `myt-phase4f-key-revocation-v1:${sha256Hex(content)}`) {
      throw new Error('BBS key revocation ID does not match its content');
    }
    if(!verifyPhase4b(
      authorization.evaluator,
      KEY_REVOCATION_CONTEXT,
      content,
      revocation.signature
    )) {
      throw new Error('BBS key revocation Phase 4B signature is invalid');
    }
    return {valid: true, keyId: authorization.key_id};
  } catch(error) {
    return {valid: false, reason: error.message};
  }
}

async function rejectRevokedKey({
  keyStatusStore,
  authorization,
  trustedEvaluatorMachineId,
  expectedNetwork,
  now,
}) {
  if(!keyStatusStore) {
    return;
  }
  const revocation = await keyStatusStore.lookupKeyRevocation(authorization.key_id);
  if(revocation === null) {
    return;
  }
  const result = verifyKeyRevocation({
    revocation,
    authorization,
    trustedEvaluatorMachineId,
    expectedNetwork,
    now,
  });
  if(!result.valid) {
    throw new Error(`Stored BBS key revocation is invalid: ${result.reason}`);
  }
  throw new Error('BBS issuer key is revoked');
}

function validatePolicy(policy) {
  assertExactKeys(
    policy,
    ['trusted_issuers', 'max_per_issuer', 'min_age', 'max_age', 'require_settlement'],
    'ReputationPolicy'
  );
  if(!Array.isArray(policy.trusted_issuers) || policy.trusted_issuers.length > 1_000 ||
    new Set(policy.trusted_issuers).size !== policy.trusted_issuers.length) {
    throw new Error('ReputationPolicy trusted issuers are invalid');
  }
  policy.trusted_issuers.forEach(machineIdDigest);
  assertSafeInteger(policy.max_per_issuer, 'Per-issuer limit', 1, 100);
  assertSafeInteger(policy.min_age, 'Minimum age');
  assertSafeInteger(policy.max_age, 'Maximum age');
  if(policy.max_age < policy.min_age || typeof policy.require_settlement !== 'boolean') {
    throw new Error('ReputationPolicy bounds are invalid');
  }
}

export function evaluateValidatedPhase4eSnapshot({snapshot, policy, asOf}) {
  if(!snapshot || snapshot.source !== 'validated-phase4e-v0.5.x-snapshot') {
    throw new Error('Evaluator accepts only an explicitly validated Phase 4E snapshot');
  }
  machineIdDigest(snapshot.subject_machine_id);
  assertNetwork(snapshot.network);
  assertSafeInteger(asOf, 'Policy as-of time');
  validatePolicy(policy);
  if(!Array.isArray(snapshot.settlement_events) ||
    snapshot.settlement_events.length > 100_000 ||
    !Array.isArray(snapshot.attestations) || snapshot.attestations.length > 10_000) {
    throw new Error('Phase 4E snapshot exceeds prototype bounds');
  }

  const settlementDigests = new Set();
  for(const event of snapshot.settlement_events) {
    if(event.verified !== true || event.subject_machine_id !== snapshot.subject_machine_id ||
      event.network !== snapshot.network || !HEX_32_RE.test(event.evidence_digest)) {
      throw new Error('Phase 4E settlement event is not a validated matching observation');
    }
    settlementDigests.add(event.evidence_digest);
  }

  const accepted = [];
  const contributions = new Map();
  let validAttestations = 0;
  let revokedAttestations = 0;
  const ordered = [...snapshot.attestations].sort((a, b) =>
    (b.issued_at - a.issued_at) || a.id.localeCompare(b.id)
  );
  for(const attestation of ordered) {
    if(attestation.signature_valid !== true ||
      attestation.subject_machine_id !== snapshot.subject_machine_id ||
      attestation.network !== snapshot.network ||
      !['POSITIVE', 'NEUTRAL', 'NEGATIVE'].includes(attestation.outcome) ||
      !HEX_32_RE.test(attestation.evidence_digest)) {
      throw new Error('Phase 4E attestation is not a validated matching artifact');
    }
    machineIdDigest(attestation.issuer_machine_id);
    assertSafeInteger(attestation.issued_at, 'Attestation issued-at');
    validAttestations += 1;
    if(attestation.revoked === true) {
      revokedAttestations += 1;
      continue;
    }
    const age = asOf - attestation.issued_at;
    const issuerCount = contributions.get(attestation.issuer_machine_id) ?? 0;
    if(attestation.issuer_machine_id === snapshot.subject_machine_id ||
      !policy.trusted_issuers.includes(attestation.issuer_machine_id) ||
      age < policy.min_age || age > policy.max_age ||
      (policy.require_settlement && !settlementDigests.has(attestation.evidence_digest)) ||
      issuerCount >= policy.max_per_issuer) {
      continue;
    }
    contributions.set(attestation.issuer_machine_id, issuerCount + 1);
    accepted.push(attestation);
  }

  const evidenceDigest = sha256Hex(utf8(canonicalJson(snapshot)));
  const policyDigest = sha256Hex(utf8(canonicalJson(policy)));
  return {
    subject_machine_id: snapshot.subject_machine_id,
    network: snapshot.network,
    phase4e_evidence_digest: evidenceDigest,
    policy_digest: policyDigest,
    objective_local_observations: {
      verified_recipient_settlement_events: settlementDigests.size,
    },
    signed_opinions: {
      cryptographically_valid_attestations: validAttestations,
      revoked_attestations: revokedAttestations,
    },
    local_policy_output: {
      policy,
      as_of: asOf,
      accepted_attestations: accepted.length,
      unique_machine_identity_issuers: contributions.size,
      positive: accepted.filter(a => a.outcome === 'POSITIVE').length,
      neutral: accepted.filter(a => a.outcome === 'NEUTRAL').length,
      negative: accepted.filter(a => a.outcome === 'NEGATIVE').length,
    },
  };
}

export function computeBoundedPredicate({evaluation, metricId, operator, threshold}) {
  const catalog = PREDICATE_CATALOG[metricId];
  if(!catalog || !catalog.operators.includes(operator)) {
    throw new Error('Predicate is not in the bounded catalog');
  }
  assertSafeInteger(
    threshold, 'Predicate threshold', catalog.thresholdMinimum, catalog.thresholdMaximum
  );
  const metricValue = evaluation.objective_local_observations[metricId];
  assertSafeInteger(
    metricValue, 'Predicate metric', catalog.metricMinimum, catalog.metricMaximum
  );
  const result = operator === 'gte' && metricValue >= threshold;
  return {metric_id: metricId, operator, threshold, result, metric_value: metricValue};
}

function credentialMessages({authorization, evaluation, predicate, issuedAt, expiresAt}) {
  return [
    'myt-phase4f-reputation-credential-v1',
    authorization.evaluator.machine_id,
    authorization.key_id,
    evaluation.subject_machine_id,
    evaluation.network,
    evaluation.policy_digest,
    evaluation.phase4e_evidence_digest,
    predicate.metric_id,
    String(predicate.metric_value),
    predicate.metric_id,
    predicate.operator,
    String(predicate.threshold),
    String(predicate.result),
    String(issuedAt),
    String(expiresAt),
  ];
}

function validateCredentialShape(credential) {
  assertExactKeys(
    credential,
    ['type', 'version', 'ciphersuite', 'key_id', 'header', 'messages', 'bbs_signature'],
    'BBS credential'
  );
  if(credential.type !== 'myt-phase4f-reputation-credential' ||
    credential.version !== 1 || credential.ciphersuite !== CIPHERSUITE ||
    credential.header !== b64url(CREDENTIAL_HEADER) ||
    !Array.isArray(credential.messages) ||
    credential.messages.length !== MESSAGE_SCHEMA.length ||
    credential.messages.some(message => typeof message !== 'string')) {
    throw new Error('Unsupported or malformed BBS credential');
  }
  decodeB64url(credential.bbs_signature, {expectedBytes: 80, name: 'BBS signature'});
}

export async function issueCredential({
  bbsSecretKey,
  authorization,
  trustedEvaluatorMachineId,
  evaluation,
  predicate,
  issuedAt,
  expiresAt,
  keyStatusStore,
}) {
  assertSafeInteger(issuedAt, 'Credential issued-at');
  assertSafeInteger(expiresAt, 'Credential expiry');
  if(expiresAt <= issuedAt || expiresAt - issuedAt > 86_400) {
    throw new Error('Credential lifetime must be between 1 second and 24 hours');
  }
  const authResult = verifyKeyAuthorization({
    authorization,
    trustedEvaluatorMachineId,
    expectedNetwork: evaluation.network,
    now: issuedAt,
  });
  if(!authResult.valid) {
    throw new Error(authResult.reason);
  }
  await rejectRevokedKey({
    keyStatusStore,
    authorization,
    trustedEvaluatorMachineId,
    expectedNetwork: evaluation.network,
    now: issuedAt,
  });
  if(!(bbsSecretKey instanceof Uint8Array) || bbsSecretKey.length !== 32) {
    throw new Error('BBS secret key must contain exactly 32 bytes');
  }
  const derivedPublicKey = await bbs.secretKeyToPublicKey({
    secretKey: bbsSecretKey,
    ciphersuite: CIPHERSUITE,
  });
  if(!Buffer.from(derivedPublicKey).equals(Buffer.from(authResult.publicKey))) {
    throw new Error('BBS secret key does not match the authorized public key');
  }
  if(predicate.metric_value !==
    evaluation.objective_local_observations[predicate.metric_id]) {
    throw new Error('Predicate metric was not computed from the evaluation');
  }
  const recomputed = computeBoundedPredicate({
    evaluation,
    metricId: predicate.metric_id,
    operator: predicate.operator,
    threshold: predicate.threshold,
  });
  if(canonicalJson(recomputed) !== canonicalJson(predicate)) {
    throw new Error('Predicate assertion does not match evaluator computation');
  }
  const messages = credentialMessages({
    authorization, evaluation, predicate, issuedAt, expiresAt,
  });
  const signature = await bbs.sign({
    secretKey: bbsSecretKey,
    publicKey: authResult.publicKey,
    header: CREDENTIAL_HEADER,
    messages: messages.map(utf8),
    ciphersuite: CIPHERSUITE,
  });
  const verified = await bbs.verifySignature({
    publicKey: authResult.publicKey,
    signature,
    header: CREDENTIAL_HEADER,
    messages: messages.map(utf8),
    ciphersuite: CIPHERSUITE,
  });
  if(!verified) {
    throw new Error('New BBS credential failed issuer self-verification');
  }
  return {
    type: 'myt-phase4f-reputation-credential',
    version: 1,
    ciphersuite: CIPHERSUITE,
    key_id: authorization.key_id,
    header: b64url(CREDENTIAL_HEADER),
    messages,
    bbs_signature: b64url(signature),
  };
}

export async function verifyCredentialSignature({credential, authorization}) {
  try {
    validateCredentialShape(credential);
    const publicKey = decodeB64url(authorization.bbs_public_key, {
      expectedBytes: 96,
      name: 'BBS public key',
    });
    return await bbs.verifySignature({
      publicKey,
      signature: decodeB64url(credential.bbs_signature, {
        expectedBytes: 80,
        name: 'BBS signature',
      }),
      header: CREDENTIAL_HEADER,
      messages: credential.messages.map(utf8),
      ciphersuite: CIPHERSUITE,
    });
  } catch {
    return false;
  }
}

function validateRequestedPredicate(predicate) {
  assertExactKeys(
    predicate,
    ['metric_id', 'operator', 'threshold', 'required_result'],
    'Requested predicate'
  );
  const catalog = PREDICATE_CATALOG[predicate.metric_id];
  if(!catalog || !catalog.operators.includes(predicate.operator) ||
    predicate.required_result !== true) {
    throw new Error('Requested predicate is not supported');
  }
  assertSafeInteger(
    predicate.threshold,
    'Requested predicate threshold',
    catalog.thresholdMinimum,
    catalog.thresholdMaximum
  );
}

export function validatePresentationRequest(request) {
  assertExactKeys(
    request,
    [
      'type', 'version', 'challenge', 'audience', 'network', 'policy_digest',
      'requested_predicate', 'created_at', 'expires_at',
    ],
    'Presentation request'
  );
  if(request.type !== 'myt-phase4f-presentation-request' || request.version !== 1) {
    throw new Error('Unsupported presentation request');
  }
  decodeB64url(request.challenge, {expectedBytes: 32, name: 'Verifier challenge'});
  if(typeof request.audience !== 'string' || request.audience.length < 1 ||
    request.audience.length > 256 || /[\u0000-\u001f\u007f]/.test(request.audience)) {
    throw new Error('Invalid verifier audience');
  }
  assertNetwork(request.network);
  if(typeof request.policy_digest !== 'string' || !HEX_32_RE.test(request.policy_digest)) {
    throw new Error('Invalid requested policy digest');
  }
  validateRequestedPredicate(request.requested_predicate);
  assertSafeInteger(request.created_at, 'Challenge creation time');
  assertSafeInteger(request.expires_at, 'Challenge expiry');
  if(request.expires_at <= request.created_at ||
    request.expires_at - request.created_at > 300) {
    throw new Error('Challenge lifetime must be between 1 and 300 seconds');
  }
  return request;
}

export function presentationHeader(request) {
  validatePresentationRequest(request);
  return canonicalPayload(PRESENTATION_PREFIX, request);
}

export function createPresentationRequest({
  audience,
  network,
  policyDigest,
  requestedPredicate,
  now,
  lifetimeSeconds = 120,
  nonce,
}) {
  assertSafeInteger(now, 'Challenge creation time');
  assertSafeInteger(lifetimeSeconds, 'Challenge lifetime', 1, 300);
  const challengeBytes = nonce ?? randomBytes(32);
  if(!(challengeBytes instanceof Uint8Array) || challengeBytes.length !== 32) {
    throw new Error('Verifier challenge must contain exactly 32 bytes');
  }
  const request = {
    type: 'myt-phase4f-presentation-request',
    version: 1,
    challenge: b64url(challengeBytes),
    audience,
    network,
    policy_digest: policyDigest,
    requested_predicate: requestedPredicate,
    created_at: now,
    expires_at: now + lifetimeSeconds,
  };
  validatePresentationRequest(request);
  return request;
}

export class ChallengeStore {
  #records = new Map();

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
    if(this.#records.has(request.challenge)) {
      throw new Error('Duplicate verifier challenge');
    }
    this.#records.set(request.challenge, {request: structuredClone(request), used: false});
  }

  lookup(challenge, now) {
    const record = this.#records.get(challenge);
    if(!record) {
      throw new Error('Verifier challenge is unknown');
    }
    if(record.used) {
      throw new Error('Verifier challenge was already used');
    }
    if(now >= record.request.expires_at) {
      throw new Error('Verifier challenge is expired');
    }
    return structuredClone(record.request);
  }

  consume(challenge) {
    const record = this.#records.get(challenge);
    if(!record || record.used) {
      throw new Error('Verifier challenge cannot be consumed');
    }
    record.used = true;
  }
}

function subjectControlMessage({request, proof, keyId, subjectMachineId}) {
  return canonicalPayload('MYT-PHASE4F-SUBJECT-CONTROL-V1\n', {
    request_digest: sha256Hex(presentationHeader(request)),
    proof_digest: sha256Hex(proof),
    bbs_key_id: keyId,
    subject_machine_id: subjectMachineId,
  });
}

export function createSubjectControl({
  subjectIdentity,
  request,
  proof,
  keyId,
  subjectMachineId = subjectIdentity.publicIdentity.machine_id,
}) {
  const message = subjectControlMessage({
    request, proof, keyId, subjectMachineId,
  });
  return {
    identity: subjectIdentity.publicIdentity,
    context: SUBJECT_CONTROL_CONTEXT,
    signature: signPhase4b(subjectIdentity, SUBJECT_CONTROL_CONTEXT, message),
  };
}

export async function createPresentation({
  credential,
  authorization,
  subjectIdentity,
  request,
  now,
  keyStatusStore,
}) {
  validateCredentialShape(credential);
  validatePresentationRequest(request);
  if(now < request.created_at || now >= request.expires_at) {
    throw new Error('Presentation request is not currently active');
  }
  const authResult = verifyKeyAuthorization({
    authorization,
    trustedEvaluatorMachineId: authorization.evaluator.machine_id,
    expectedNetwork: request.network,
    now,
  });
  if(!authResult.valid) {
    throw new Error(authResult.reason);
  }
  await rejectRevokedKey({
    keyStatusStore,
    authorization,
    trustedEvaluatorMachineId: authorization.evaluator.machine_id,
    expectedNetwork: request.network,
    now,
  });
  if(!(await verifyCredentialSignature({credential, authorization}))) {
    throw new Error('Holder received an invalid BBS credential');
  }
  if(credential.key_id !== authorization.key_id ||
    credential.messages[2] !== authorization.key_id ||
    credential.messages[3] !== subjectIdentity.publicIdentity.machine_id ||
    credential.messages[4] !== request.network ||
    credential.messages[5] !== request.policy_digest ||
    credential.messages[9] !== request.requested_predicate.metric_id ||
    credential.messages[10] !== request.requested_predicate.operator ||
    credential.messages[11] !== String(request.requested_predicate.threshold) ||
    credential.messages[12] !== 'true') {
    throw new Error('Credential does not satisfy the verifier request or subject binding');
  }
  const proof = await bbs.deriveProof({
    publicKey: authResult.publicKey,
    signature: decodeB64url(credential.bbs_signature, {
      expectedBytes: 80,
      name: 'BBS signature',
    }),
    header: CREDENTIAL_HEADER,
    messages: credential.messages.map(utf8),
    presentationHeader: presentationHeader(request),
    disclosedMessageIndexes: [...DISCLOSED_MESSAGE_INDEXES],
    ciphersuite: CIPHERSUITE,
  });
  const subjectControl = createSubjectControl({
    subjectIdentity,
    request,
    proof,
    keyId: credential.key_id,
    subjectMachineId: credential.messages[3],
  });
  return {
    type: 'myt-phase4f-reputation-presentation',
    version: 1,
    request,
    key_authorization: authorization,
    disclosed_messages: DISCLOSED_MESSAGE_INDEXES.map(index => ({
      index,
      name: MESSAGE_SCHEMA[index],
      value: credential.messages[index],
    })),
    bbs_proof: b64url(proof),
    subject_control: subjectControl,
  };
}

function parseCanonicalInteger(value, name, minimum = 0, maximum = MAX_TIMESTAMP) {
  if(typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${name} is not a canonical integer string`);
  }
  const parsed = Number(value);
  assertSafeInteger(parsed, name, minimum, maximum);
  return parsed;
}

function validateDisclosedMessages(disclosed) {
  if(!Array.isArray(disclosed) || disclosed.length !== DISCLOSED_MESSAGE_INDEXES.length) {
    throw new Error('Presentation has the wrong disclosed message set');
  }
  const values = new Map();
  disclosed.forEach((entry, position) => {
    assertExactKeys(entry, ['index', 'name', 'value'], 'Disclosed message');
    const expectedIndex = DISCLOSED_MESSAGE_INDEXES[position];
    if(entry.index !== expectedIndex || entry.name !== MESSAGE_SCHEMA[expectedIndex] ||
      typeof entry.value !== 'string') {
      throw new Error('Presentation disclosed message indexes or names are non-canonical');
    }
    values.set(entry.name, entry.value);
  });
  return values;
}

export async function verifyPresentation({
  presentation,
  challengeStore,
  trustedEvaluatorMachineId,
  now,
  keyStatusStore,
}) {
  try {
    assertSafeInteger(now, 'Verification time');
    assertExactKeys(
      presentation,
      [
        'type', 'version', 'request', 'key_authorization', 'disclosed_messages',
        'bbs_proof', 'subject_control',
      ],
      'Presentation'
    );
    if(presentation.type !== 'myt-phase4f-reputation-presentation' ||
      presentation.version !== 1) {
      throw new Error('Unsupported presentation profile');
    }
    validatePresentationRequest(presentation.request);
    const storedRequest = await challengeStore.lookup(
      presentation.request.challenge, now
    );
    if(canonicalJson(storedRequest) !== canonicalJson(presentation.request)) {
      throw new Error('Presentation request does not match verifier state');
    }
    const authResult = verifyKeyAuthorization({
      authorization: presentation.key_authorization,
      trustedEvaluatorMachineId,
      expectedNetwork: storedRequest.network,
      now,
    });
    if(!authResult.valid) {
      throw new Error(authResult.reason);
    }
    await rejectRevokedKey({
      keyStatusStore,
      authorization: presentation.key_authorization,
      trustedEvaluatorMachineId,
      expectedNetwork: storedRequest.network,
      now,
    });
    const values = validateDisclosedMessages(presentation.disclosed_messages);
    if(values.get('schema') !== 'myt-phase4f-reputation-credential-v1' ||
      values.get('evaluator_machine_id') !== trustedEvaluatorMachineId ||
      values.get('bbs_key_id') !== authResult.keyId ||
      values.get('network') !== storedRequest.network ||
      values.get('policy_digest') !== storedRequest.policy_digest ||
      values.get('metric_id') !== storedRequest.requested_predicate.metric_id ||
      values.get('predicate_metric_id') !== storedRequest.requested_predicate.metric_id ||
      values.get('predicate_operator') !== storedRequest.requested_predicate.operator ||
      values.get('predicate_threshold') !==
        String(storedRequest.requested_predicate.threshold) ||
      values.get('predicate_result') !== 'true') {
      throw new Error('Disclosed credential claims do not satisfy the verifier request');
    }
    machineIdDigest(values.get('subject_machine_id'));
    const issuedAt = parseCanonicalInteger(values.get('issued_at'), 'Credential issued-at');
    const expiresAt = parseCanonicalInteger(values.get('expires_at'), 'Credential expiry');
    if(expiresAt <= issuedAt) {
      throw new Error('Credential lifetime is invalid');
    }
    if(now < issuedAt) {
      throw new Error('Credential is not active yet');
    }
    if(now >= expiresAt) {
      throw new Error('Credential is expired');
    }

    const proof = decodeB64url(presentation.bbs_proof, {name: 'BBS proof'});
    const proofVerified = await bbs.verifyProof({
      publicKey: authResult.publicKey,
      proof,
      header: CREDENTIAL_HEADER,
      presentationHeader: presentationHeader(storedRequest),
      disclosedMessages: presentation.disclosed_messages.map(entry => utf8(entry.value)),
      disclosedMessageIndexes: [...DISCLOSED_MESSAGE_INDEXES],
      ciphersuite: CIPHERSUITE,
    });
    if(!proofVerified) {
      throw new Error('BBS selective-disclosure proof is invalid');
    }

    assertExactKeys(
      presentation.subject_control,
      ['identity', 'context', 'signature'],
      'Subject control proof'
    );
    if(presentation.subject_control.context !== SUBJECT_CONTROL_CONTEXT) {
      throw new Error('Subject control proof has the wrong context');
    }
    validateIdentityDocument(presentation.subject_control.identity);
    if(presentation.subject_control.identity.machine_id !==
      values.get('subject_machine_id')) {
      throw new Error('Subject control identity does not match the BBS credential subject');
    }
    const controlMessage = subjectControlMessage({
      request: storedRequest,
      proof,
      keyId: authResult.keyId,
      subjectMachineId: values.get('subject_machine_id'),
    });
    if(!verifyPhase4b(
      presentation.subject_control.identity,
      SUBJECT_CONTROL_CONTEXT,
      controlMessage,
      presentation.subject_control.signature
    )) {
      throw new Error('Phase 4B subject control signature is invalid');
    }

    await challengeStore.consume(storedRequest.challenge, now);
    return {
      valid: true,
      evaluator_machine_id: trustedEvaluatorMachineId,
      subject_machine_id: values.get('subject_machine_id'),
      predicate: {
        metric_id: values.get('predicate_metric_id'),
        operator: values.get('predicate_operator'),
        threshold: Number(values.get('predicate_threshold')),
        result: true,
      },
      proof_bytes: proof.length,
    };
  } catch(error) {
    return {valid: false, reason: error.message};
  }
}

export function artifactSizes({credential, presentation}) {
  const proofBytes = decodeB64url(presentation.bbs_proof, {name: 'BBS proof'}).length;
  const signatureBytes = decodeB64url(credential.bbs_signature, {
    expectedBytes: 80,
    name: 'BBS signature',
  }).length;
  return {
    raw_bbs_signature_bytes: signatureBytes,
    raw_bbs_proof_bytes: proofBytes,
    bbs_proof_base64url_characters: presentation.bbs_proof.length,
    complete_credential_json_bytes: Buffer.byteLength(canonicalJson(credential)),
    complete_presentation_json_bytes: Buffer.byteLength(canonicalJson(presentation)),
    hidden_message_count: HIDDEN_MESSAGE_INDEXES.length,
    disclosed_message_count: DISCLOSED_MESSAGE_INDEXES.length,
  };
}
