// Canonical transport only; cryptographic primitives remain upstream.
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';

export const SUITE = 'BLS12-381-SHA-256';
export const HEADER = Buffer.from('MYT-REPUTATION-CREDENTIAL-V1\n');
export const PROFILE = 'myt-reputation-bbs-v1';
export const VERSIONS = Object.freeze({
  bbs: '3.1.0', curves: '2.4.0', hashes: '2.4.0'
});
export function requireThat(ok) {
  if(!ok) throw new Error('Invalid companion input');
}
export function exact(v, fields) {
  requireThat(v !== null && typeof v === 'object' && !Array.isArray(v) &&
    Object.keys(v).sort().join('\0') === [...fields].sort().join('\0'));
  return v;
}
export function canonical(v, depth = 0) {
  requireThat(depth <= 12);
  if(typeof v === 'string') {
    requireThat(/^[\x20-\x7e]*$/.test(v));
    return JSON.stringify(v);
  }
  if(typeof v === 'boolean') return JSON.stringify(v);
  if(typeof v === 'number') {
    requireThat(Number.isSafeInteger(v));
    return JSON.stringify(v);
  }
  if(Array.isArray(v)) {
    requireThat(v.length <= 128);
    return '[' + v.map(x => canonical(x, depth + 1)).join(',') + ']';
  }
  requireThat(v !== null && typeof v === 'object' &&
    Object.getPrototypeOf(v) === Object.prototype);
  return '{' + Object.keys(v).sort().map(k =>
    canonical(k, depth + 1) + ':' + canonical(v[k], depth + 1)).join(',') + '}';
}
export function encode(v) {
  return Buffer.from(canonical(v) + '\n', 'ascii');
}
export function parse(raw, limit = 32768) {
  requireThat(Buffer.isBuffer(raw) && raw.length > 0 && raw.length <= limit);
  // ignoreBOM=true preserves BOM, which JSON/canonical equality must reject.
  const text = new TextDecoder('utf-8', {fatal: true, ignoreBOM: true}).decode(raw);
  const v = JSON.parse(text);
  // Also rejects duplicate/escaped keys, whitespace, exponent forms and BOMs.
  requireThat(encode(v).equals(raw));
  requireThat(v !== null && !Array.isArray(v) && typeof v === 'object');
  return v;
}
export function b64(raw) { return Buffer.from(raw).toString('base64url'); }
export function unb64(v, n) {
  requireThat(typeof v === 'string' && /^[A-Za-z0-9_-]+$/.test(v) &&
    v.length === Math.ceil(n * 8 / 6));
  const raw = Buffer.from(v, 'base64url');
  requireThat(raw.length === n && b64(raw) === v);
  return raw;
}
export function keyId(publicKey) {
  requireThat(publicKey.length === 96);
  return 'myt-bbs-key-v1:' + createHash('sha256').update(
    Buffer.concat([Buffer.from('MYT-BBS-KEY-V1\0' + SUITE + '\0'), publicKey])
  ).digest('hex');
}
export function runtimeGate() {
  const [major, minor] = process.versions.node.split('.').map(Number);
  requireThat(major === 24 && minor >= 20);
  requireThat(!process.env.NODE_OPTIONS && !process.env.NODE_PATH);
  const packages = [
    ['@digitalbazaar/bbs-signatures', '../package.json', VERSIONS.bbs],
    ['@noble/curves/bls12-381.js', './package.json', VERSIONS.curves],
    ['@noble/hashes/sha2.js', './package.json', VERSIONS.hashes]
  ];
  for(const [name, relative, expected] of packages) {
    const metadata = JSON.parse(readFileSync(new URL(relative, import.meta.resolve(name)), 'utf8'));
    requireThat(metadata.version === expected);
  }
}
