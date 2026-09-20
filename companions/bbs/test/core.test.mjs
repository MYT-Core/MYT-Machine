import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {encode, parse, b64, unb64, keyId, PROFILE} from '../src/encoding.mjs';
import {createKey, loadKey} from '../src/keys.mjs';
import {generate, execute} from '../src/crypto.mjs';
import {readRegular, writeExclusive} from '../src/files.mjs';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'myt-bbs-test-'));
const pass = path.join(dir, 'pass');
fs.writeFileSync(pass, randomBytes(32).toString('hex') + '\n', {mode: 0o600});
test.after(() => fs.rmSync(dir, {recursive: true, force: true}));
const canonical = encode({a: 1, b: true});
test('canonical round trip', () => assert.deepEqual(parse(canonical), {a: 1, b: true}));
for(const [name, raw] of [
  ['bom', Buffer.concat([Buffer.from([239,187,191]), canonical])],
  ['utf16', Buffer.from('{"a":1,"b":true}\n', 'utf16le')],
  ['highbit', Buffer.concat([Buffer.from([251]), canonical.subarray(1)])],
  ['duplicate', Buffer.from('{"a":0,"a":1,"b":true}\n')],
  ['escaped duplicate', Buffer.from('{"a":0,"\\u0061":1,"b":true}\n')],
  ['spaces', Buffer.from('{"a": 1,"b":true}\n')],
  ['trailing', Buffer.concat([canonical, Buffer.from('x')])],
  ['missing newline', canonical.subarray(0, -1)],
  ['extra newline', Buffer.concat([canonical, Buffer.from('\n')])],
  ['null', Buffer.from('{"a":null}\n')],
  ['exponent', Buffer.from('{"a":1e0}\n')],
  ['fraction', Buffer.from('{"a":1.5}\n')],
  ['surrogate', Buffer.from('{"a":"\\ud800"}\n')],
  ['control', Buffer.from('{"a":"\\u0000"}\n')],
  ['oversized', Buffer.alloc(32769, 32)],
]) {
  test('reject encoding ' + name, () => assert.throws(() => parse(raw)));
}
test('base64 rejects padding', () => assert.throws(() => unb64('AA==', 1)));
test('base64 rejects unused bits', () => assert.throws(() => unb64('AB', 1)));
test('directory junction or symlink and nested ancestor fail closed', () => {
  const target = path.join(dir, 'link-target');
  fs.mkdirSync(target, {mode: 0o700});
  fs.mkdirSync(path.join(target, 'child'), {mode: 0o700});
  const link = path.join(dir, 'linked-parent');
  fs.symlinkSync(target, link, process.platform === 'win32' ? 'junction' : 'dir');
  try {
    for(const file of [path.join(link, 'file'), path.join(link, 'child', 'file')]) {
      assert.throws(() => writeExclusive(file, Buffer.from('not-secret')));
      assert.throws(() => readRegular(file, 100));
    }
    assert.equal(fs.existsSync(path.join(target, 'file')), false);
    assert.equal(fs.existsSync(path.join(target, 'child', 'file')), false);
  } finally { fs.unlinkSync(link); }
});

test('exclusive create never overwrites', () => {
  const f = path.join(dir, 'exclusive');
  writeExclusive(f, Buffer.from('a'));
  assert.throws(() => writeExclusive(f, Buffer.from('b')));
  assert.equal(fs.readFileSync(f).toString(), 'a');
});
test('hardlinks rejected', () => {
  const f = path.join(dir, 'linked');
  fs.linkSync(pass, f);
  try { assert.throws(() => readRegular(f, 1026)); }
  finally { fs.unlinkSync(f); }
});
test('key encryption round trip and redacted failure', async () => {
  const key = path.join(dir, 'key.json');
  const publicResult = await createKey(key, pass);
  const loaded = await loadKey(key, pass);
  assert.equal(b64(loaded.publicKey), publicResult.public_key);
  assert.equal(keyId(loaded.publicKey), publicResult.key_id);
  loaded.secretKey.fill(0);
  const wrong = path.join(dir, 'wrong');
  fs.writeFileSync(wrong, 'must-not-appear-wrong-password\n', {mode: 0o600});
  await assert.rejects(loadKey(key, wrong), {message: 'Cannot unlock BBS key'});
  await assert.rejects(createKey(key, pass));
  const raw = fs.readFileSync(key);
  fs.writeFileSync(key, Buffer.concat([Buffer.from([251]), raw.subarray(1)]));
  await assert.rejects(loadKey(key, pass), {message: 'Cannot unlock BBS key'});
});
const keys = await generate();
test.after(() => keys.secretKey.fill(0));
const msgs = [PROFILE, ...Array(9).fill('public'), 'true','true','true','false','false'];
const common = {public_key: b64(keys.publicKey), messages: msgs};
const signed = await execute('sign', common, keys);
const request = {
  type: 'myt-reputation-disclosure-request', version: 1,
  purpose: 'myt-reputation-selective-disclosure-v1',
  expected_subject_machine_id: 'myt-machine-v1:' + 'a'.repeat(52),
  expected_evaluator_machine_id: 'myt-machine-v1:' + 'c'.repeat(51) + 'a',
  expected_issuer_key_id: keyId(keys.publicKey), network: 'testnet',
  challenge: b64(Buffer.alloc(32, 1)), audience: 'test.example',
  policy_digest: 'a'.repeat(64), metric_id: 'verified_recipient_settlement_events',
  threshold: 25, not_before: 100, expires_at: 200
};
const ph = b64(Buffer.concat([Buffer.from('MYT-REPUTATION-DISCLOSURE-PRESENTATION-V1\n'),
  encode(request).subarray(0, -1)]));
test('native signature correct', async () =>
  assert.deepEqual(await execute('verify-signature', {...common, ...signed}), {valid: true}));
test('signature rejects reordered messages', async () => {
  const v = {...common, ...signed, messages: [...msgs]};
  v.messages[1] = 'different';
  assert.deepEqual(await execute('verify-signature', v), {valid: false});
});
const proof = await execute('derive-proof', {...common, ...signed, presentation_header: ph, request, threshold: 25});
const verification = {public_key: common.public_key, messages: [...msgs.slice(0,10),'true'],
  ...proof, presentation_header: ph, request, threshold: 25};
test('native proof exactly 400 bytes', () => assert.equal(unb64(proof.proof, 400).length, 400));
test('native proof verifies', async () =>
  assert.deepEqual(await execute('verify-proof', verification), {valid: true}));
test('proof changes between presentations', async () => {
  const other = await execute('derive-proof', {...common, ...signed, presentation_header: ph, request, threshold: 25});
  assert.notEqual(other.proof, proof.proof);
});
for(const field of ['presentation_header', 'threshold', 'messages', 'public_key']) {
  test('native proof binds ' + field, async () => {
    const changed = {...verification, request: {...request}};
    if(field === 'presentation_header') {
      changed.request.challenge = b64(Buffer.alloc(32, 2));
      changed[field] = b64(Buffer.concat([Buffer.from('MYT-REPUTATION-DISCLOSURE-PRESENTATION-V1\n'),
        encode(changed.request).subarray(0, -1)]));
    }
    if(field === 'threshold') changed[field] = 50;
    if(field === 'messages') changed[field] = [...msgs.slice(0,9), 'changed', 'true'];
    if(field === 'public_key') {
      const other = await generate(); changed[field] = b64(other.publicKey); other.secretKey.fill(0);
    }
    assert.deepEqual(await execute('verify-proof', changed), {valid: false});
  });
}
test('unasserted threshold cannot be presented', async () => {
  await assert.rejects(execute('derive-proof', {...common, ...signed, presentation_header: ph, request, threshold: 50}));
});
test('unsupported threshold cannot be presented', async () => {
  await assert.rejects(execute('derive-proof', {...common, ...signed, presentation_header: ph, request, threshold: 26}));
});
test('malformed key rejects', async () => {
  await assert.rejects(execute('validate-key', {public_key: b64(Buffer.alloc(96))}));
});
test('signer rejects wrong public key', async () => {
  const other = await generate();
  try { await assert.rejects(execute('sign', {...common, public_key: b64(other.publicKey)}, keys)); }
  finally { other.secretKey.fill(0); }
});
test('no seeded key generation in production interface', () => assert.equal(generate.length, 0));
