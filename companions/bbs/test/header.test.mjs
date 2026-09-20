import test from 'node:test';
import assert from 'node:assert/strict';
import {encode, b64} from '../src/encoding.mjs';
import {decodePresentationHeader} from '../src/header.mjs';

const request = {
  type: 'myt-reputation-disclosure-request', version: 1,
  purpose: 'myt-reputation-selective-disclosure-v1',
  expected_subject_machine_id: 'myt-machine-v1:' + 'a'.repeat(52),
  expected_evaluator_machine_id: 'myt-machine-v1:' + 'c'.repeat(51) + 'a',
  expected_issuer_key_id: 'myt-bbs-key-v1:' + '0'.repeat(64), network: 'testnet',
  challenge: b64(Buffer.alloc(32)), audience: 'test.example',
  policy_digest: '0'.repeat(64), metric_id: 'verified_recipient_settlement_events',
  threshold: 25, not_before: 100, expires_at: 200
};
const raw = Buffer.concat([Buffer.from('MYT-REPUTATION-DISCLOSURE-PRESENTATION-V1\n'),
  encode(request).subarray(0,-1)]);
const transport = b64(raw);
test('exact original header bytes preserved including domain newline', () => {
  assert.deepEqual(decodePresentationHeader(transport, request), raw);
  assert.equal(raw[raw.indexOf(10)], 10);
});
for(const [name, bad] of [
  ['padding', transport + '='], ['empty',''], ['whitespace',' '+transport],
  ['CR',transport+'\r'], ['LF',transport+'\n'], ['alphabet','+'+transport.slice(1)],
  ['slash','/'+transport.slice(1)], ['unicode','\u00e9'+transport.slice(1)],
  ['oversize','A'.repeat(12000)], ['raw_header',raw.toString('ascii')],
  ['changed_bytes',b64(Buffer.concat([Buffer.from('X'),raw.subarray(1)]))],
  ['removed_newline',b64(Buffer.from(raw.toString('ascii').replace('\n','')))],
  ['CRLF',b64(Buffer.from(raw.toString('ascii').replace('\n','\r\n')))],
  ['wrong_domain',b64(Buffer.concat([Buffer.from('NOT'),raw.subarray(3)]))],
  ['padded_header_bytes',b64(Buffer.concat([raw,Buffer.from(' ')]))],
]) {
  test('reject header transport ' + name, () => assert.throws(() => decodePresentationHeader(bad,request)));
}
for(const field of Object.keys(request)) {
  test('request mismatch ' + field, () => {
    const changed = {...request};
    changed[field] = typeof changed[field] === 'number' ? changed[field] + 1 : changed[field] + 'x';
    assert.throws(() => decodePresentationHeader(transport, changed));
  });
}
test('reject noncanonical unused Base64 bits', () => {
  let r = {...request};
  while(Buffer.concat([Buffer.from('MYT-REPUTATION-DISCLOSURE-PRESENTATION-V1\n'),
    encode(r).subarray(0,-1)]).length % 3 === 0) r.audience += 'x';
  const v = b64(Buffer.concat([Buffer.from('MYT-REPUTATION-DISCLOSURE-PRESENTATION-V1\n'),
    encode(r).subarray(0,-1)]));
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const bad = v.slice(0,-1) + alphabet[alphabet.indexOf(v.at(-1)) + 1];
  assert.throws(() => decodePresentationHeader(bad,r));
});
