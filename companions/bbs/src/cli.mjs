#!/usr/bin/env node
import {randomBytes} from 'node:crypto';
import {parseArgs} from 'node:util';
import {runtimeGate, requireThat, canonical} from './encoding.mjs';
import {writeExclusive} from './files.mjs';
import {createKey} from './keys.mjs';
import {serve} from './service.mjs';

// Private values are never accepted in argv/environment or printed in errors.
try {
  runtimeGate();
  const {values, positionals} = parseArgs({allowPositionals: true, strict: true, options: {
    'token-file': {type: 'string'}, 'key-file': {type: 'string'},
    'passphrase-file': {type: 'string'}, port: {type: 'string'}
  }});
  requireThat(positionals.length === 1);
  const command = positionals[0];
  let result;
  if(command === 'token-create') {
    requireThat(Object.keys(values).length === 1 && values['token-file']);
    writeExclusive(values['token-file'], Buffer.from(randomBytes(32).toString('hex') + '\n'));
    result = {created: true};
  } else if(command === 'key-create') {
    requireThat(Object.keys(values).length === 2 && values['key-file'] && values['passphrase-file']);
    requireThat(values['key-file'] !== values['passphrase-file']);
    result = await createKey(values['key-file'], values['passphrase-file']);
  } else {
    requireThat(command === 'serve' && values['token-file'] && values.port &&
      /^[1-9][0-9]{3,4}$/.test(values.port));
    const server = await serve({port: Number(values.port), tokenFile: values['token-file'],
      keyFile: values['key-file'], passwordFile: values['passphrase-file']});
    for(const signal of ['SIGINT', 'SIGTERM']) {
      process.once(signal, () => { server.close(); server.closeAllConnections(); });
    }
    result = {listening: true, port: Number(values.port)};
  }
  process.stdout.write(canonical({success: true, result}) + '\n');
} catch {
  process.stdout.write('{"error":"Companion operation failed","success":false}\n');
  process.exitCode = 3;
}
