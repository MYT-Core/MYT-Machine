import * as bbs from '@digitalbazaar/bbs-signatures';
import {decodePresentationHeader} from './header.mjs';
import {bls12_381} from '@noble/curves/bls12-381.js';
import {SUITE, HEADER, PROFILE, exact, requireThat, b64, unb64} from './encoding.mjs';

export function checkPublic(raw) {
  requireThat(raw.length === 96);
  const point = bls12_381.G2.Point.fromBytes(raw);
  point.assertValidity();
  requireThat(!point.equals(bls12_381.G2.Point.ZERO));
  requireThat(Buffer.from(point.toBytes()).equals(Buffer.from(raw)));
  return raw;
}
export async function generate() {
  // No seed or fixture RNG crosses the production API.
  return bbs.generateKeyPair({ciphersuite: SUITE});
}
export async function publicFromSecret(secretKey) {
  requireThat(secretKey.length === 32);
  // Reject noncanonical scalars rather than accepting upstream's modular reduction.
  const scalar = BigInt('0x' + Buffer.from(secretKey).toString('hex'));
  requireThat(scalar > 0n && scalar < bls12_381.fields.Fr.ORDER);
  return bbs.secretKeyToPublicKey({secretKey, ciphersuite: SUITE});
}
function messages(values, count) {
  requireThat(Array.isArray(values) && values.length === count);
  const result = values.map(v => {
    requireThat(typeof v === 'string' && /^[\x21-\x7e]{1,256}$/.test(v));
    return Buffer.from(v, 'ascii');
  });
  requireThat(values[0] === PROFILE);
  if(count === 15) requireThat(values.slice(10).every(v => v === 'true' || v === 'false'));
  if(count === 11) requireThat(values[10] === 'true');
  return result;
}
function indices(threshold) {
  const levels = [1, 10, 25, 50, 100];
  requireThat(Number.isInteger(threshold) && levels.includes(threshold));
  return [...Array(10).keys(), 10 + levels.indexOf(threshold)];
}
export async function execute(op, params, keys) {
  if(op === 'public-key') {
    exact(params, []);
    requireThat(keys !== undefined);
    return {public_key: b64(keys.publicKey)};
  }
  if(op === 'validate-key') {
    exact(params, ['public_key']);
    checkPublic(unb64(params.public_key, 96));
    return {valid: true};
  }
  const full = ['public_key', 'messages'];
  if(op === 'sign') {
    exact(params, full);
    requireThat(keys !== undefined);
    const publicKey = checkPublic(unb64(params.public_key, 96));
    requireThat(Buffer.from(publicKey).equals(Buffer.from(keys.publicKey)));
    return {signature: b64(await bbs.sign({
      secretKey: keys.secretKey, publicKey, header: HEADER,
      messages: messages(params.messages, 15), ciphersuite: SUITE
    }))};
  }
  if(op === 'verify-signature') {
    exact(params, [...full, 'signature']);
    return {valid: await bbs.verifySignature({
      publicKey: checkPublic(unb64(params.public_key, 96)),
      signature: unb64(params.signature, 80), header: HEADER,
      messages: messages(params.messages, 15), ciphersuite: SUITE
    })};
  }
  if(op === 'derive-proof') {
    exact(params, [...full, 'signature', 'presentation_header', 'request', 'threshold']);
    const publicKey = checkPublic(unb64(params.public_key, 96));
    const signature = unb64(params.signature, 80);
    const msgs = messages(params.messages, 15);
    requireThat(params.messages[10 + [1, 10, 25, 50, 100].indexOf(params.threshold)] === 'true');
    const opts = {publicKey, signature, header: HEADER, messages: msgs, ciphersuite: SUITE};
    requireThat(await bbs.verifySignature(opts));
    const proof = await bbs.deriveProof({
      ...opts, presentationHeader: decodePresentationHeader(params.presentation_header, params.request),
      disclosedMessageIndexes: indices(params.threshold)
    });
    requireThat(proof.length === 400);
    return {proof: b64(proof)};
  }
  if(op === 'verify-proof') {
    exact(params, [...full, 'proof', 'presentation_header', 'request', 'threshold']);
    return {valid: await bbs.verifyProof({
      publicKey: checkPublic(unb64(params.public_key, 96)),
      proof: unb64(params.proof, 400), header: HEADER,
      presentationHeader: decodePresentationHeader(params.presentation_header, params.request),
      disclosedMessages: messages(params.messages, 11),
      disclosedMessageIndexes: indices(params.threshold), ciphersuite: SUITE
    })};
  }
  throw new Error('Unsupported companion operation');
}
