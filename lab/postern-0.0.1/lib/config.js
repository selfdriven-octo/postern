'use strict';
const fs = require('node:fs');
const net = require('node:net');

function identity(value) {
  if (typeof value !== 'string' || !/^[a-zA-Z0-9_-]{1,64}$/.test(value)) throw new Error('Invalid peer identity');
  return value;
}
function key(value) {
  if (typeof value !== 'string' || !/^[a-fA-F0-9]{64}$/.test(value)) throw new Error('PSK must be 32 random bytes encoded as 64 hex characters');
  return Buffer.from(value, 'hex');
}
function network(c, server = false) {
  if (!c || net.isIP(c.host) !== 4 || (!server && c.host === '0.0.0.0') ||
      !Number.isInteger(c.port) || c.port < 1 || c.port > 65535) throw new Error('Use literal IPv4 and a valid port');
  if (server && !c.host.startsWith('127.') && c.allowRemote !== true) {
    throw new Error('Set allowRemote: true explicitly to listen beyond loopback');
  }
  if (c.localAddress !== undefined && net.isIP(c.localAddress) !== 4) throw new Error('Invalid localAddress');
}
function peers(c) {
  network(c, true);
  if (!Array.isArray(c.peers) || !c.peers.length || c.peers.length > 256) throw new Error('Invalid peers');
  const result = new Map(), secrets = new Set();
  for (const p of c.peers) {
    identity(p.id);
    const psk = key(p.psk);
    if (result.has(p.id) || secrets.has(psk.toString('hex'))) throw new Error('Each peer requires a unique identity and key');
    if (p.address !== undefined && net.isIP(p.address) !== 4) throw new Error('Invalid peer source address');
    if (!Array.isArray(p.operations) || !p.operations.length ||
        !p.operations.every(op => ['ping', 'message'].includes(op))) throw new Error('Invalid operations');
    secrets.add(psk.toString('hex'));
    result.set(p.id, { ...p, psk, tokens: 20, updated: performance.now() });
  }
  return result;
}
function load(file) {
  if (fs.statSync(file).size > 65536) throw new Error('Configuration too large');
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}
module.exports = { identity, key, network, peers, load };
