import https from 'node:https';
import {timingSafeEqual} from 'node:crypto';
import {capability, readRegular} from './files.mjs';
import {encode, parse, exact, requireThat, PROFILE, SUITE, VERSIONS, runtimeGate} from './encoding.mjs';
import {execute} from './crypto.mjs';
import {loadKey} from './keys.mjs';

export async function serve({port, tokenFile, keyFile, passwordFile, tlsCertFile, tlsKeyFile}) {
  runtimeGate();
  requireThat(Number.isInteger(port) && port >= 1024 && port <= 65535);
  requireThat(Boolean(keyFile) === Boolean(passwordFile));
  const token = capability(tokenFile);
  const keys = keyFile ? await loadKey(keyFile, passwordFile) : undefined;
  const cert = readRegular(tlsCertFile, 16384, false);
  const key = readRegular(tlsKeyFile, 16384);
  let busy = false;
  const server = https.createServer({
    cert, key, minVersion: 'TLSv1.2', maxHeaderSize: 4096,
    handshakeTimeout: 3000, connectionsCheckingInterval: 1000
  }, async (req, res) => {
    const fail = () => {
      if(!res.headersSent) {
        res.writeHead(400, {'Content-Type': 'application/json', 'Connection': 'close'});
        res.end(encode({error: 'Companion request rejected'}));
      } else res.destroy();
    };
    try {
      requireThat(!busy && req.method === 'POST' && req.url === '/v1' &&
        req.headers.host === '127.0.0.1:' + port && !req.headers.origin &&
        !req.headers['transfer-encoding'] &&
        req.headers['content-type'] === 'application/json');
      const supplied = Buffer.from(req.headers.authorization || '', 'ascii');
      const expected = Buffer.concat([Buffer.from('Bearer '), token]);
      requireThat(supplied.length === expected.length && timingSafeEqual(supplied, expected));
      const length = req.headers['content-length'];
      requireThat(typeof length === 'string' && /^[1-9][0-9]{0,4}$/.test(length) &&
        Number(length) <= 32768);
      busy = true;
      try {
        let size = 0;
        const chunks = [];
        for await(const chunk of req) {
          size += chunk.length;
          requireThat(size <= Number(length));
          chunks.push(chunk);
        }
        requireThat(size === Number(length));
        const value = parse(Buffer.concat(chunks));
        exact(value, ['id', 'version', 'operation', 'params']);
        requireThat(value.version === 1 && typeof value.id === 'string' &&
          /^[0-9a-f]{32}$/.test(value.id));
        let result;
        if(value.operation === 'hello') {
          exact(value.params, []);
          result = {profile: PROFILE, ciphersuite: SUITE, versions: VERSIONS,
            signing: keys !== undefined, node: process.versions.node};
        } else {
          result = await execute(value.operation, value.params, keys);
        }
        res.writeHead(200, {'Content-Type': 'application/json', 'Cache-Control': 'no-store'});
        res.end(encode({id: value.id, version: 1, result}));
      } finally { busy = false; }
    } catch { fail(); }
  });
  key.fill(0);
  server.requestTimeout = 10000;
  server.headersTimeout = 5000;
  server.keepAliveTimeout = 1000;
  server.maxConnections = 32;
  server.setTimeout(10000, socket => socket.destroy());
  server.on('clientError', (_error, socket) => socket.destroy());
  server.on('close', () => { keys?.secretKey.fill(0); token.fill(0); });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  return server;
}
