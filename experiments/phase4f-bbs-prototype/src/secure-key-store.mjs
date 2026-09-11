import * as bbs from '@digitalbazaar/bbs-signatures';
import {
  closeSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from 'node:crypto';

import {
  CIPHERSUITE,
  b64url,
  bbsKeyId,
  canonicalJson,
  decodeB64url,
  utf8,
} from './phase4f.mjs';


const TYPE = 'myt-phase4f-encrypted-bbs-private-key';
const AAD_PREFIX = 'MYT-PHASE4F-BBS-PRIVATE-KEY-V1\n';
const SCRYPT_N = 131_072;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_MAXMEM = 256 * 1024 * 1024;
const MAX_FILE_BYTES = 8_192;
const KEY_ID_RE = /^myt-phase4f-bbs-key-v1:[0-9a-f]{64}$/;

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

function copyPassphrase(passphrase) {
  if(!(passphrase instanceof Uint8Array) ||
    passphrase.length < 16 || passphrase.length > 1_024) {
    throw new Error('BBS key passphrase must contain 16-1024 bytes');
  }
  const copy = Buffer.from(passphrase);
  if(copy.includes(0) || copy.includes(10) || copy.includes(13)) {
    copy.fill(0);
    throw new Error('BBS key passphrase contains a forbidden character');
  }
  return copy;
}

function metadata({keyId, salt, nonce}) {
  return {
    type: TYPE,
    version: 1,
    key_id: keyId,
    kdf: {
      name: 'scrypt',
      n: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
      salt: b64url(salt),
    },
    cipher: {
      name: 'aes-256-gcm',
      nonce: b64url(nonce),
    },
  };
}

function aad(value) {
  return utf8(`${AAD_PREFIX}${canonicalJson(value)}`);
}

function deriveWrappingKey(passphrase, salt) {
  return scryptSync(passphrase, salt, 32, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAXMEM,
  });
}

function validateEnvelope(value) {
  assertExactKeys(
    value,
    ['type', 'version', 'key_id', 'kdf', 'cipher', 'ciphertext', 'authentication_tag'],
    'Encrypted BBS key'
  );
  assertExactKeys(value.kdf, ['name', 'n', 'r', 'p', 'salt'], 'BBS key KDF');
  assertExactKeys(value.cipher, ['name', 'nonce'], 'BBS key cipher');
  if(value.type !== TYPE || value.version !== 1 || !KEY_ID_RE.test(value.key_id) ||
    value.kdf.name !== 'scrypt' || value.kdf.n !== SCRYPT_N ||
    value.kdf.r !== SCRYPT_R || value.kdf.p !== SCRYPT_P ||
    value.cipher.name !== 'aes-256-gcm') {
    throw new Error('Unsupported encrypted BBS key profile');
  }
  const salt = decodeB64url(value.kdf.salt, {expectedBytes: 16, name: 'KDF salt'});
  const nonce = decodeB64url(value.cipher.nonce, {
    expectedBytes: 12, name: 'Encryption nonce',
  });
  const ciphertext = decodeB64url(value.ciphertext, {
    expectedBytes: 32, name: 'Encrypted BBS key',
  });
  const authenticationTag = decodeB64url(value.authentication_tag, {
    expectedBytes: 16, name: 'Authentication tag',
  });
  return {salt, nonce, ciphertext, authenticationTag};
}

function assertProtectedKeyFile(path) {
  const information = lstatSync(path);
  if(!information.isFile() || information.nlink !== 1) {
    throw new Error('Encrypted BBS key must be a regular non-linked file');
  }
  if(process.platform !== 'win32' && (information.mode & 0o777) !== 0o600) {
    throw new Error('Encrypted BBS key permissions must be 0600');
  }
  if(information.size < 1 || information.size > MAX_FILE_BYTES) {
    throw new Error('Encrypted BBS key file has an invalid size');
  }
}

function writeExclusiveKeyFile(path, encoded) {
  let descriptor;
  try {
    descriptor = openSync(path, 'wx', 0o600);
    writeFileSync(descriptor, encoded, {encoding: 'ascii'});
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    assertProtectedKeyFile(path);
  } catch {
    if(descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // Keep the external failure deliberately path-free.
      }
    }
    throw new Error('Encrypted BBS key could not be saved');
  }
}

export async function saveBbsSecretKey({path, secretKey, passphrase}) {
  if(typeof path !== 'string' || path.length === 0 || path.length > 4_096 ||
    /[\u0000\r\n]/.test(path)) {
    throw new Error('Encrypted BBS key path is invalid');
  }
  if(!(secretKey instanceof Uint8Array) || secretKey.length !== 32) {
    throw new Error('BBS secret key must contain exactly 32 bytes');
  }
  const publicKey = await bbs.secretKeyToPublicKey({
    secretKey,
    ciphersuite: CIPHERSUITE,
  });
  const keyId = bbsKeyId(publicKey);
  const salt = randomBytes(16);
  const nonce = randomBytes(12);
  const password = copyPassphrase(passphrase);
  let wrappingKey;
  let secretCopy;
  try {
    wrappingKey = deriveWrappingKey(password, salt);
    const keyMetadata = metadata({keyId, salt, nonce});
    const cipher = createCipheriv('aes-256-gcm', wrappingKey, nonce);
    cipher.setAAD(aad(keyMetadata));
    secretCopy = Buffer.from(secretKey);
    const ciphertext = Buffer.concat([
      cipher.update(secretCopy),
      cipher.final(),
    ]);
    const envelope = {
      ...keyMetadata,
      ciphertext: b64url(ciphertext),
      authentication_tag: b64url(cipher.getAuthTag()),
    };
    writeExclusiveKeyFile(path, `${canonicalJson(envelope)}\n`);
    return {keyId, publicKey};
  } finally {
    password.fill(0);
    wrappingKey?.fill(0);
    secretCopy?.fill(0);
  }
}

export async function loadBbsSecretKey({path, passphrase, expectedKeyId}) {
  if(typeof expectedKeyId !== 'string' || !KEY_ID_RE.test(expectedKeyId)) {
    throw new Error('Expected BBS key ID is invalid');
  }
  let password;
  let wrappingKey;
  let plaintext;
  try {
    assertProtectedKeyFile(path);
    const encoded = readFileSync(path, 'ascii');
    const envelope = JSON.parse(encoded);
    if(`${canonicalJson(envelope)}\n` !== encoded) {
      throw new Error('Encrypted BBS key file is not canonical');
    }
    const {salt, nonce, ciphertext, authenticationTag} = validateEnvelope(envelope);
    if(envelope.key_id !== expectedKeyId) {
      throw new Error('Encrypted BBS key does not match the expected key ID');
    }
    password = copyPassphrase(passphrase);
    wrappingKey = deriveWrappingKey(password, salt);
    const decipher = createDecipheriv('aes-256-gcm', wrappingKey, nonce);
    decipher.setAAD(aad(metadata({keyId: envelope.key_id, salt, nonce})));
    decipher.setAuthTag(authenticationTag);
    plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    if(plaintext.length !== 32) {
      throw new Error('Decrypted BBS key has an invalid length');
    }
    const publicKey = await bbs.secretKeyToPublicKey({
      secretKey: plaintext,
      ciphersuite: CIPHERSUITE,
    });
    if(bbsKeyId(publicKey) !== expectedKeyId) {
      throw new Error('Decrypted BBS key does not match its key ID');
    }
    return Uint8Array.from(plaintext);
  } catch {
    throw new Error('Encrypted BBS key could not be loaded');
  } finally {
    password?.fill(0);
    wrappingKey?.fill(0);
    plaintext?.fill(0);
  }
}
