import {randomBytes, scrypt, createCipheriv, createDecipheriv} from 'node:crypto';
import {promisify} from 'node:util';
import {SUITE, b64, unb64, keyId, exact, encode, parse, requireThat} from './encoding.mjs';
import {readRegular, writeExclusive, passphrase} from './files.mjs';
import {generate, publicFromSecret, checkPublic} from './crypto.mjs';

const kdf = promisify(scrypt);
const PARAMS = Object.freeze({N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024});
const KDF = 'scrypt-N131072-r8-p1';
function associated(v) {
  return encode({type: v.type, version: v.version, ciphersuite: v.ciphersuite,
    public_key: v.public_key, key_id: v.key_id, kdf: v.kdf, cipher: v.cipher});
}
function validate(v) {
  exact(v, ['type', 'version', 'ciphersuite', 'public_key', 'key_id',
    'kdf', 'cipher', 'salt', 'nonce', 'ciphertext', 'tag']);
  requireThat(v.type === 'myt-bbs-encrypted-private-key' && v.version === 1 &&
    v.ciphersuite === SUITE && v.kdf === KDF && v.cipher === 'AES-256-GCM');
  const pub = checkPublic(unb64(v.public_key, 96));
  requireThat(v.key_id === keyId(pub));
  unb64(v.salt, 16); unb64(v.nonce, 12);
  unb64(v.ciphertext, 32); unb64(v.tag, 16);
  return v;
}
export async function createKey(file, passwordFile) {
  let password, secret, derived;
  try {
    password = passphrase(passwordFile);
    const keys = await generate();
    secret = Buffer.from(keys.secretKey);
    keys.secretKey.fill(0);
    const pub = Buffer.from(keys.publicKey);
    const salt = randomBytes(16), nonce = randomBytes(12);
    derived = Buffer.from(await kdf(password, salt, 32, PARAMS));
    const value = {type: 'myt-bbs-encrypted-private-key', version: 1,
      ciphersuite: SUITE, public_key: b64(pub), key_id: keyId(pub),
      kdf: KDF, cipher: 'AES-256-GCM'};
    const cipher = createCipheriv('aes-256-gcm', derived, nonce);
    cipher.setAAD(associated(value));
    const ciphertext = Buffer.concat([cipher.update(secret), cipher.final()]);
    Object.assign(value, {salt: b64(salt), nonce: b64(nonce),
      ciphertext: b64(ciphertext), tag: b64(cipher.getAuthTag())});
    writeExclusive(file, encode(validate(value)));
    return {public_key: b64(pub), key_id: value.key_id, ciphersuite: SUITE};
  } finally { password?.fill(0); secret?.fill(0); derived?.fill(0); }
}
export async function loadKey(file, passwordFile) {
  let password, secret, derived, success = false;
  try {
    const value = validate(parse(readRegular(file, 4096), 4096));
    password = passphrase(passwordFile);
    derived = Buffer.from(await kdf(password, unb64(value.salt, 16), 32, PARAMS));
    const cipher = createDecipheriv('aes-256-gcm', derived, unb64(value.nonce, 12));
    cipher.setAAD(associated(value));
    cipher.setAuthTag(unb64(value.tag, 16));
    secret = Buffer.concat([cipher.update(unb64(value.ciphertext, 32)), cipher.final()]);
    const publicKey = await publicFromSecret(secret);
    requireThat(b64(publicKey) === value.public_key);
    success = true;
    return {secretKey: secret, publicKey};
  } catch {
    throw new Error('Cannot unlock BBS key');
  } finally {
    password?.fill(0); derived?.fill(0);
    if(!success) secret?.fill(0);
  }
}
