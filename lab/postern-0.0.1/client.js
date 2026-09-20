'use strict';
const tls = require('node:tls');
const { randomUUID } = require('node:crypto');
const { load, network, identity, key } = require('./lib/config');
const tlsOptions = require('./lib/tls-options');
const { ALPN, exact, reader, frame, validateRequest } = require('./lib/protocol');

function send(config, op, body = {}) {
  return Promise.resolve().then(() => {
    network(config);
    const id = identity(config.id), psk = key(config.psk);
    const request = validateRequest({ v: 1, id: randomUUID(), op, body });
    const encoded = frame(request);
    return new Promise((resolve, reject) => {
      let offered = false, settled = false;
      const socket = tls.connect({
        ...tlsOptions, host: config.host, port: config.port,
        ...(config.localAddress ? { localAddress: config.localAddress } : {}),
        rejectUnauthorized: true,
        // Certificates are not a fallback identity mechanism for this PSK-only client.
        checkServerIdentity: () => new Error('Certificate authentication is not permitted'),
        pskCallback: () => { offered = true; return { identity: id, psk }; }
      });
      const finish = (error, value) => {
        if (settled) return;
        settled = true; clearTimeout(timer); socket.destroy();
        if (error) reject(error); else resolve(value);
      };
      const timer = setTimeout(() => finish(new Error('Channel deadline exceeded')), 5000);
      socket.once('error', e => finish(e));
      socket.once('close', () => finish(new Error('Channel closed without valid response')));
      socket.once('secureConnect', () => {
        // OpenSSL reports external-PSK handshakes as session reuse. We never pass
        // a stored session. Require this, no peer certificate, and ephemeral X25519.
        const ephemeral = socket.getEphemeralKeyInfo();
        if (!offered || !socket.authorized || !socket.isSessionReused() ||
            socket.getPeerCertificate().raw || socket.alpnProtocol !== ALPN ||
            !ephemeral || ephemeral.name !== 'X25519') return finish(new Error('PSK authentication failed'));
        socket.on('data', reader(value => {
          if (!exact(value, ['v', 'id', 'ok', 'result']) || value.v !== 1 || value.id !== request.id ||
              value.ok !== true || value.result !== (op === 'ping' ? 'pong' : 'accepted')) return finish(new Error('Invalid response'));
          finish(null, value);
        }, e => finish(e)));
        socket.write(encoded);
      });
    });
  });
}
if (require.main === module) {
  Promise.resolve().then(() => {
    const [, , file, op, text] = process.argv;
    if (!file || !op) throw new Error('Usage: node client.js CONFIG.json ping|message [TEXT]');
    return send(load(file), op, op === 'message' ? { text } : {});
  }).then(v => console.log(JSON.stringify(v))).catch(e => { console.error(e.message); process.exitCode = 1; });
}
module.exports = { send };
