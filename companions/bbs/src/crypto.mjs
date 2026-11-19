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
  requireThat(nonzeroScalar(secretKey));
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
function nonzeroScalar(raw) {
  const scalar = BigInt('0x' + Buffer.from(raw).toString('hex'));
  return scalar > 0n && scalar < bls12_381.fields.Fr.ORDER;
}

function validProofEncoding(proof) {
  try {
    for(let offset = 0; offset < 144; offset += 48) {
      const raw = proof.subarray(offset, offset + 48);
      const point = bls12_381.G1.Point.fromBytes(raw);
      point.assertValidity();
      if(point.equals(bls12_381.G1.Point.ZERO) || !Buffer.from(point.toBytes()).equals(Buffer.from(raw))) {
        return false;
      }
    }
  } catch {
    return false;
  }
  for(let offset = 144; offset < proof.length; offset += 32) {
    if(!nonzeroScalar(proof.subarray(offset, offset + 32))) return false;
  }
  return true;
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
    const signature = await bbs.sign({
      secretKey: keys.secretKey, publicKey, header: HEADER,
      messages: messages(params.messages, 15), ciphersuite: SUITE
    });
    requireThat(nonzeroScalar(signature.subarray(48)));
    return {signature: b64(signature)};
  }
  if(op === 'verify-signature') {
    exact(params, [...full, 'signature']);
    const signature = unb64(params.signature, 80);
    if(!nonzeroScalar(signature.subarray(48))) return {valid: false};
    return {valid: await bbs.verifySignature({
      publicKey: checkPublic(unb64(params.public_key, 96)),
      signature, header: HEADER,
      messages: messages(params.messages, 15), ciphersuite: SUITE
    })};
  }
  if(op === 'derive-proof') {
    exact(params, [...full, 'signature', 'presentation_header', 'request', 'threshold']);
    const publicKey = checkPublic(unb64(params.public_key, 96));
    const signature = unb64(params.signature, 80);
    requireThat(nonzeroScalar(signature.subarray(48)));
    const msgs = messages(params.messages, 15);
    requireThat(params.messages[10 + [1, 10, 25, 50, 100].indexOf(params.threshold)] === 'true');
    const opts = {publicKey, signature, header: HEADER, messages: msgs, ciphersuite: SUITE};
    requireThat(await bbs.verifySignature(opts));
    const proof = await bbs.deriveProof({
      ...opts, presentationHeader: decodePresentationHeader(params.presentation_header, params.request),
      disclosedMessageIndexes: indices(params.threshold)
    });
    requireThat(proof.length === 400 && validProofEncoding(proof));
    return {proof: b64(proof)};
  }
  if(op === 'verify-proof') {
    exact(params, [...full, 'proof', 'presentation_header', 'request', 'threshold']);
    const proof = unb64(params.proof, 400);
    if(!validProofEncoding(proof)) return {valid: false};
    return {valid: await bbs.verifyProof({
      publicKey: checkPublic(unb64(params.public_key, 96)),
      proof, header: HEADER,
      presentationHeader: decodePresentationHeader(params.presentation_header, params.request),
      disclosedMessages: messages(params.messages, 11),
      disclosedMessageIndexes: indices(params.threshold), ciphersuite: SUITE
    })};
  }
  throw new Error('Unsupported companion operation');
}
