// Transport encoding only. Domain separation and native BBS ph bytes do not change.
import {encode, exact, requireThat, unb64} from './encoding.mjs';

export function decodePresentationHeader(transport, request) {
  exact(request, ['type', 'version', 'purpose', 'expected_subject_machine_id',
    'expected_evaluator_machine_id', 'expected_issuer_key_id', 'network',
    'challenge', 'audience', 'policy_digest', 'metric_id', 'threshold',
    'not_before', 'expires_at']);
  requireThat(request.type === 'myt-reputation-disclosure-request' &&
    request.version === 1 && request.purpose === 'myt-reputation-selective-disclosure-v1' &&
    request.metric_id === 'verified_recipient_settlement_events');
  for(const field of ['expected_subject_machine_id', 'expected_evaluator_machine_id']) {
    requireThat(typeof request[field] === 'string' &&
      /^myt-machine-v1:[a-z2-7]{51}[aq]$/.test(request[field]));
  }
  requireThat(typeof request.expected_issuer_key_id === 'string' &&
    /^myt-bbs-key-v1:[0-9a-f]{64}$/.test(request.expected_issuer_key_id));
  requireThat(['mainnet', 'testnet', 'stagenet'].includes(request.network));
  unb64(request.challenge, 32);
  requireThat(typeof request.audience === 'string' && /^[\x21-\x7e]{1,256}$/.test(request.audience));
  requireThat(typeof request.policy_digest === 'string' && /^[0-9a-f]{64}$/.test(request.policy_digest));
  requireThat([1, 10, 25, 50, 100].includes(request.threshold));
  requireThat(Number.isSafeInteger(request.not_before) && request.not_before >= 0 &&
    Number.isSafeInteger(request.expires_at) && request.expires_at <= 253402300799 &&
    request.expires_at > request.not_before && request.expires_at - request.not_before <= 300);
  const expected = Buffer.concat([
    Buffer.from('MYT-REPUTATION-DISCLOSURE-PRESENTATION-V1\n'),
    encode(request).subarray(0, -1)
  ]);
  requireThat(expected.length <= 8192);
  // Existing canonical decoder: exact length, alphabet, no padding, re-encode check.
  const raw = unb64(transport, expected.length);
  requireThat(raw.equals(expected));
  return raw;
}
