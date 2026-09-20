'use strict';
const tls = require('node:tls');
const { randomBytes } = require('node:crypto');
const { load, peers } = require('./lib/config');
const tlsOptions = require('./lib/tls-options');
const { ALPN, reader, frame, validateRequest } = require('./lib/protocol');

function createChannelServer(config, { audit = () => {}, onMessage = () => {} } = {}) {
  const enrolled = peers(config);
  const authenticated = new WeakMap();
  const sockets = new Set();
  const unknownKey = randomBytes(32);
  let tokens = 40, updated = performance.now();
  const emit = value => { try { audit(value); } catch {} };
  const server = tls.createServer({
    ...tlsOptions, handshakeTimeout: 3000,
    // No certificate identity or certificate fallback is configured.
    pskCallback: (socket, id) => {
      const now = performance.now();
      tokens = Math.min(40, tokens + (now - updated) / 1000 * 10); updated = now;
      if (tokens < 1) return null;
      tokens -= 1;
      const peer = enrolled.get(id);
      if (!peer || (peer.address && socket.remoteAddress !== peer.address)) return unknownKey;
      peer.tokens = Math.min(20, peer.tokens + (now - peer.updated) / 1000 * 5); peer.updated = now;
      if (peer.tokens < 1) return null;
      peer.tokens -= 1;
      // This is only a candidate identity until the TLS handshake verifies the binder/Finished.
      authenticated.set(socket, peer);
      return peer.psk;
    }
  }, socket => {
    socket.on('error', () => {});
    const peer = authenticated.get(socket);
    if (!peer || socket.getProtocol() !== 'TLSv1.3' || socket.alpnProtocol !== ALPN) return socket.destroy();
    socket.on('data', reader(value => {
      const request = validateRequest(value);
      if (!peer.operations.includes(request.op)) return socket.destroy();
      if (request.op === 'message') {
        const result = onMessage(Object.freeze({ peer: peer.id, id: request.id, text: request.body.text }));
        if (result && typeof result.then === 'function') {
          // Never acknowledge asynchronous completion that this starter does not track.
          Promise.resolve(result).catch(() => {});
          throw new Error('Receiver must be synchronous');
        }
      }
      emit({ event: 'accepted', peer: peer.id, id: request.id, op: request.op,
        bytes: request.op === 'message' ? Buffer.byteLength(request.body.text) : 0 });
      socket.end(frame({ v: 1, id: request.id, ok: true, result: request.op === 'ping' ? 'pong' : 'accepted' }));
    }, () => socket.destroy()));
  });
  server.maxConnections = 64;
  server.on('connection', socket => {
    sockets.add(socket);
    const timer = setTimeout(() => socket.destroy(), 5000); timer.unref();
    socket.on('error', () => {});
    socket.once('close', () => { clearTimeout(timer); sockets.delete(socket); });
  });
  server.on('tlsClientError', () => {});
  return {
    server,
    listen: () => new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(config.port, config.host, () => { server.removeListener('error', reject); resolve(server.address()); });
    }),
    close: () => new Promise(resolve => { sockets.forEach(s => s.destroy()); server.close(resolve); })
  };
}
if (require.main === module) {
  Promise.resolve().then(() => {
    const channel = createChannelServer(load(process.argv[2] || 'demo/server.json'), { audit: v => console.log(JSON.stringify(v)) });
    channel.server.on('error', e => { console.error(e.message); process.exitCode = 1; });
    return channel.listen().then(address => {
      console.log(JSON.stringify({ event: 'listening', ...address }));
      const stop = () => channel.close();
      process.once('SIGINT', stop); process.once('SIGTERM', stop);
    });
  }).catch(e => { console.error(e.message); process.exitCode = 1; });
}
module.exports = { createChannelServer };
