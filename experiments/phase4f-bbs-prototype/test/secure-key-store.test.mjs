import * as bbs from '@digitalbazaar/bbs-signatures';
import assert from 'node:assert/strict';
import {mkdtempSync, readFileSync, rmSync, statSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {after, before, test} from 'node:test';

import {CIPHERSUITE, b64url, bbsKeyId, canonicalJson} from '../src/phase4f.mjs';
import {loadBbsSecretKey, saveBbsSecretKey} from '../src/secure-key-store.mjs';
import {TEST_SEEDS} from '../src/fixture.mjs';


const passphrase = Buffer.from('phase4f-test-passphrase-keep-secret', 'utf8');
let root;
let keyPair;

before(async () => {
  root = mkdtempSync(join(tmpdir(), 'myt-phase4f-keys-'));
  keyPair = await bbs.generateKeyPair({
    seed: new Uint8Array(Buffer.from(TEST_SEEDS.bbs_key_material, 'hex')),
    ciphersuite: CIPHERSUITE,
  });
});

after(() => {
  if(root) {
    rmSync(root, {recursive: true, force: true});
  }
});

test('encrypted BBS key round-trips and is bound to its public key ID', async () => {
  const path = join(root, 'issuer-key.json');
  const saved = await saveBbsSecretKey({
    path, secretKey: keyPair.secretKey, passphrase,
  });
  assert.equal(saved.keyId, bbsKeyId(keyPair.publicKey));
  assert.deepEqual(Buffer.from(saved.publicKey), Buffer.from(keyPair.publicKey));
  if(process.platform !== 'win32') {
    assert.equal(statSync(path).mode & 0o777, 0o600);
  }
  const loaded = await loadBbsSecretKey({
    path, passphrase, expectedKeyId: saved.keyId,
  });
  assert.deepEqual(Buffer.from(loaded), Buffer.from(keyPair.secretKey));
  loaded.fill(0);
});

test('wrong passphrase and wrong expected key ID fail closed', async () => {
  const path = join(root, 'wrong-passphrase.json');
  const saved = await saveBbsSecretKey({
    path, secretKey: keyPair.secretKey, passphrase,
  });
  await assert.rejects(loadBbsSecretKey({
    path,
    passphrase: Buffer.from('this-passphrase-is-not-correct'),
    expectedKeyId: saved.keyId,
  }), /could not be loaded/);
  const other = await bbs.generateKeyPair({
    seed: new Uint8Array(Buffer.from(TEST_SEEDS.alternate_bbs_key_material, 'hex')),
    ciphersuite: CIPHERSUITE,
  });
  await assert.rejects(loadBbsSecretKey({
    path, passphrase, expectedKeyId: bbsKeyId(other.publicKey),
  }), /could not be loaded/);
});

test('authenticated encryption rejects a modified key file', async () => {
  const path = join(root, 'tampered.json');
  const saved = await saveBbsSecretKey({
    path, secretKey: keyPair.secretKey, passphrase,
  });
  const envelope = JSON.parse(readFileSync(path, 'ascii'));
  envelope.authentication_tag = b64url(Buffer.alloc(16, 0xff));
  writeFileSync(path, `${canonicalJson(envelope)}\n`, 'ascii');
  await assert.rejects(loadBbsSecretKey({
    path, passphrase, expectedKeyId: saved.keyId,
  }), /could not be loaded/);
});

test('encrypted key creation never overwrites an existing file', async () => {
  const path = join(root, 'no-overwrite.json');
  await saveBbsSecretKey({path, secretKey: keyPair.secretKey, passphrase});
  await assert.rejects(saveBbsSecretKey({
    path, secretKey: keyPair.secretKey, passphrase,
  }));
});
