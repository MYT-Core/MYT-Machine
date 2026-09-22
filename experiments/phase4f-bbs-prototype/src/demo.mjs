import {buildVector} from './fixture.mjs';

const vector = await buildVector();
console.log(JSON.stringify({
  status: vector.metadata.status,
  backend: vector.metadata.backend,
  architecture: [
    'validated Phase 4E snapshot',
    'local ReputationPolicy evaluation',
    'bounded evaluator assertion',
    'Phase 4B-authorized BBS issuer key',
    'BBS credential',
    'fresh verifier request bound into BBS proof',
    'Phase 4B subject-control signature bound to that proof',
  ],
  assertion_semantics: 'Trusted evaluator asserted 37 >= 25; this is not a mathematical ZK range proof of a hidden integer.',
  disclosed: vector.presentation.disclosed_messages.map(message => message.name),
  hidden: ['phase4e_evidence_digest', 'metric_value'],
  predicate: vector.expected_verification.predicate,
  verification_valid: vector.expected_verification.valid,
  sizes: vector.sizes,
}, null, 2));
