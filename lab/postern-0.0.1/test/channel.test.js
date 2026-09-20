'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes, randomUUID } = require('node:crypto');
const tls = require('node:tls');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { setup } = require('../scripts/setup');
const { peers, network, key } = require('../lib/config');
const tlsOptions = require('../lib/tls-options');
const { frame, reader, MAX_FRAME } = require('../lib/protocol');
const { createChannelServer } = require('../server');
const { send } = require('../client');
let directory, config, client, channel;
const messages = [];
function start(c, options) {
  const ch = createChannelServer(c, options);
  return new Promise((resolve, reject) => {
    ch.server.once('error', reject);
    ch.server.listen(0, '127.0.0.1', () => resolve(ch));
  });
}
before(() => {
  directory = fs.mkdtempSync(path.join(os.tmpdir(), 'direct-tls-'));
  const result = setup(path.join(directory, 'demo')); config = result.server; client = result.client;
  return start(config, { onMessage: value => { messages.push(value); } }).then(ch => {
    channel = ch; client.port = ch.server.address().port;
  });
});
after(() => (channel ? channel.close() : Promise.resolve()).then(() => fs.rmSync(directory, { recursive: true, force: true })));
const request = (op = 'ping', body = {}) => ({ v: 1, id: randomUUID(), op, body });
function raw(bytes, overrides = {}) {
  return new Promise((resolve, reject) => {
    let received = 0;
    const socket = tls.connect({ ...tlsOptions, host: client.host, port: client.port,
      rejectUnauthorized: true, pskCallback: () => ({ identity: client.id, psk: Buffer.from(client.psk, 'hex') }), ...overrides });
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('Test deadline exceeded')); }, 6500);
    socket.on('error', () => {});
    socket.on('data', b => { received += b.length; });
    socket.once('secureConnect', () => socket.write(bytes));
    socket.once('close', () => { clearTimeout(timer); resolve(received); });
  });
}
const rejectsRaw = (bytes, options) => raw(bytes, options).then(n => assert.equal(n, 0));

test('Node-only setup generates matching random keys and refuses overwrite', () => {
  assert.equal(config.peers[0].psk, client.psk); assert.equal(key(client.psk).length, 32);
  assert.throws(() => setup(path.join(directory, 'demo')));
  if (process.platform !== 'win32') assert.equal(fs.statSync(path.join(directory, 'demo/client.json')).mode & 0o777, 0o600);
});
test('PSK mutual authentication and Unicode delivery', () => send(client, 'ping').then(v => {
  assert.equal(v.result, 'pong'); return send(client, 'message', { text: 'Hello Octo 🔐' });
}).then(v => { assert.equal(v.result, 'accepted'); assert.equal(messages[0].peer, client.id); assert.equal(messages[0].text, 'Hello Octo 🔐'); }));
test('wrong secret rejected', () => assert.rejects(send({ ...client, psk: randomBytes(32).toString('hex') }, 'ping')));
test('unknown peer rejected even with another peer secret', () => assert.rejects(send({ ...client, id: 'unknown' }, 'ping')));
test('missing PSK rejected', () => rejectsRaw(frame(request()), { pskCallback: undefined }));
test('TLS 1.2 rejected', () => rejectsRaw(frame(request()), { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2', ciphers: 'PSK-AES128-GCM-SHA256' }));
test('missing ALPN rejected', () => rejectsRaw(frame(request()), { ALPNProtocols: [] }));
test('unknown operation rejected', () => rejectsRaw(frame(request('exec', { command: 'ignored' }))));
test('claimed JSON identity rejected', () => rejectsRaw(frame({ ...request(), peer: 'admin' })));
test('overlong text rejected', () => rejectsRaw(frame(request('message', { text: 'x'.repeat(4097) }))));
test('oversized frame header rejected immediately', () => {
  const h = Buffer.alloc(4); h.writeUInt32BE(MAX_FRAME + 1); return rejectsRaw(h);
});
test('malformed JSON rejected', () => rejectsRaw(Buffer.from([0, 0, 0, 1, 123])));
test('invalid UTF-8 rejected', () => rejectsRaw(Buffer.from([0, 0, 0, 1, 255])));
test('coalesced extra frames rejected', () => rejectsRaw(Buffer.concat([frame(request()), frame(request())])));
test('fragmented frame decoding', () => {
  const input = request('message', { text: 'é🔐' }); let actual;
  const read = reader(v => { actual = v; }, e => { throw e; });
  for (const b of frame(input)) read(Buffer.from([b])); assert.deepEqual(actual, input);
});
test('remote listening requires explicit flag; public client addresses allowed', () => {
  assert.throws(() => peers({ ...config, host: '0.0.0.0' }));
  assert.doesNotThrow(() => peers({ ...config, host: '0.0.0.0', allowRemote: true }));
  assert.doesNotThrow(() => network({ ...client, host: '203.0.113.1' }));
});
test('weak-format keys and duplicate peer keys rejected', () => {
  assert.throws(() => key('password'));
  assert.throws(() => peers({ ...config, peers: [config.peers[0], { ...config.peers[0], id: 'peer-02' }] }));
});
test('operation permissions enforced', () => start({ ...config, peers: [{ ...config.peers[0], operations: ['ping'] }] })
  .then(ch => assert.rejects(send({ ...client, port: ch.server.address().port }, 'message', { text: 'denied' })).finally(() => ch.close())));
test('optional source address restriction enforced', () => start({ ...config, peers: [{ ...config.peers[0], address: '127.0.0.2' }] })
  .then(ch => assert.rejects(send({ ...client, port: ch.server.address().port }, 'ping')).finally(() => ch.close())));
test('source address restriction admits matching peer', () => start({ ...config, peers: [{ ...config.peers[0], address: '127.0.0.1' }] })
  .then(ch => send({ ...client, port: ch.server.address().port }, 'ping').then(v => assert.equal(v.result, 'pong')).finally(() => ch.close())));
test('wrong-key server cannot impersonate enrolled server', () => start({ ...config, peers: [{ ...config.peers[0], psk: randomBytes(32).toString('hex') }] })
  .then(ch => assert.rejects(send({ ...client, port: ch.server.address().port }, 'message', { text: 'secret' })).finally(() => ch.close())));
test('receiver failure does not acknowledge or crash service', () => start(config, { onMessage: () => { throw new Error('failed'); } })
  .then(ch => assert.rejects(send({ ...client, port: ch.server.address().port }, 'message', { text: 'failed' }))
    .then(() => send({ ...client, port: ch.server.address().port }, 'ping')).finally(() => ch.close())));
test('async receiver is not acknowledged as complete', () => start(config, { onMessage: () => Promise.resolve() })
  .then(ch => assert.rejects(send({ ...client, port: ch.server.address().port }, 'message', { text: 'async' })).finally(() => ch.close())));
test('rate limit bounds burst of authenticated connections', () => start(config).then(ch =>
  Promise.allSettled(Array.from({ length: 30 }, () => send({ ...client, port: ch.server.address().port }, 'ping')))
    .then(results => { assert.ok(results.some(r => r.status === 'fulfilled')); assert.ok(results.some(r => r.status === 'rejected')); }).finally(() => ch.close())));
test('partial application frame reaches absolute deadline', () => rejectsRaw(Buffer.from([0])));
