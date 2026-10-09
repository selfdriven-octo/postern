'use strict';
// Educational stop-and-wait ARQ framing layered over lib.js audio frames.
// No encryption, authentication, or claimed TELRPC compatibility.
const crypto = require('node:crypto');
const { crc32 } = require('./lib');
const MAGIC = Buffer.from('PFA2');
const VERSION = 1;
const TYPES = Object.freeze({ START: 1, DATA: 2, ACK: 3 });
const CHUNK_SIZE = 48;
const MAX_TRANSFER = 16 * 1024;
const HEADER_LENGTH = 14;
const OVERHEAD = HEADER_LENGTH + 4;

function u16(v, what) { if (!Number.isInteger(v) || v < 0 || v > 65535) throw new Error(`Invalid ${what}`); }
function u32(v, what) { if (!Number.isInteger(v) || v < 0 || v > 0xffffffff) throw new Error(`Invalid ${what}`); }
function encodePacket({type, id, seq, total, data = Buffer.alloc(0)}) {
  if (!Object.values(TYPES).includes(type)) throw new Error('Invalid packet type');
  u32(id, 'session ID'); u16(seq, 'sequence'); u16(total, 'total');
  if (!Buffer.isBuffer(data)) data = Buffer.from(data);
  if (data.length > CHUNK_SIZE) throw new Error('Packet data too long');
  if (type === TYPES.ACK && data.length) throw new Error('ACK must be empty');
  const buf = Buffer.alloc(HEADER_LENGTH + data.length + 4);
  MAGIC.copy(buf, 0);
  buf[4] = VERSION;
  buf[5] = type;
  buf.writeUInt32BE(id, 6);
  buf.writeUInt16BE(seq, 10);
  buf.writeUInt16BE(total, 12);
  data.copy(buf, HEADER_LENGTH);
  buf.writeUInt32BE(crc32(buf.subarray(0, buf.length - 4)), buf.length - 4);
  return buf;
}
function parsePacket(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < OVERHEAD || buf.length > OVERHEAD + CHUNK_SIZE) throw new Error('Invalid packet length');
  if (!buf.subarray(0, 4).equals(MAGIC) || buf[4] !== VERSION) throw new Error('Unknown packet protocol');
  const type = buf[5];
  if (!Object.values(TYPES).includes(type)) throw new Error('Unknown packet type');
  if (crc32(buf.subarray(0, -4)) !== buf.readUInt32BE(buf.length - 4)) throw new Error('Packet CRC mismatch');
  const data = Buffer.from(buf.subarray(HEADER_LENGTH, -4));
  if (type === TYPES.ACK && data.length) throw new Error('Nonempty ACK');
  return {type, id: buf.readUInt32BE(6), seq: buf.readUInt16BE(10), total: buf.readUInt16BE(12), data};
}
function makePackets(input, sessionId = crypto.randomBytes(4).readUInt32BE(0)) {
  if (!Buffer.isBuffer(input)) input = Buffer.from(input);
  if (!input.length || input.length > MAX_TRANSFER) throw new Error(`Input must be 1..${MAX_TRANSFER} bytes`);
  const total = Math.ceil(input.length / CHUNK_SIZE);
  const digest = crypto.createHash('sha256').update(input).digest();
  const meta = Buffer.alloc(36);
  meta.writeUInt32BE(input.length, 0);
  digest.copy(meta, 4);
  const packets = [encodePacket({type: TYPES.START, id: sessionId, seq: 0, total, data: meta})];
  for (let n = 0; n < total; n++) packets.push(encodePacket({type: TYPES.DATA, id: sessionId, seq: n + 1, total, data: input.subarray(n * CHUNK_SIZE, (n + 1) * CHUNK_SIZE)}));
  return {id: sessionId, total, digest: digest.toString('hex'), packets};
}
class Receiver {
  constructor(onComplete) {
    if (typeof onComplete !== 'function') throw new Error('onComplete callback required');
    this.onComplete = onComplete;
    this.states = new Map();
  }
  async accept(raw) {
    let p;
    try { p = parsePacket(raw); } catch { return null; }
    if (p.type === TYPES.ACK) return null;
    if (p.type === TYPES.START) {
      if (p.seq !== 0 || p.data.length !== 36 || p.total === 0 || p.total > Math.ceil(MAX_TRANSFER / CHUNK_SIZE)) return null;
      const size = p.data.readUInt32BE(0);
      if (size < 1 || size > MAX_TRANSFER || Math.ceil(size / CHUNK_SIZE) !== p.total) return null;
      const sha = p.data.subarray(4).toString('hex');
      const old = this.states.get(p.id);
      // A retransmitted START must be idempotent. Never silently switch identities.
      if (old && (old.sha !== sha || old.size !== size)) return null;
      if (!old) {
        if (this.states.size >= 16) return null;
        this.states.set(p.id, {size, sha, total: p.total, chunks: [], next: 1, done: false});
      }
      return encodePacket({type: TYPES.ACK, id: p.id, seq: 0, total: p.total});
    }
    const s = this.states.get(p.id);
    if (!s || p.total !== s.total || p.seq < 1 || p.seq > s.total) return null;
    if (p.seq < s.next) return encodePacket({type: TYPES.ACK, id: p.id, seq: p.seq, total: s.total});
    if (p.seq !== s.next || s.done) return null; // stop-and-wait: no out-of-order chunks
    const expectedSize = p.seq < s.total ? CHUNK_SIZE : s.size - CHUNK_SIZE * (s.total - 1);
    if (p.data.length !== expectedSize) return null;
    s.chunks.push(p.data); s.next++;
    if (p.seq === s.total) {
      const bytes = Buffer.concat(s.chunks);
      if (crypto.createHash('sha256').update(bytes).digest('hex') !== s.sha) {
        this.states.delete(p.id); // digest mismatch: fail closed
        return null;
      }
      try { await this.onComplete(bytes, {id: p.id, sha256: s.sha}); }
      catch (err) { s.chunks.pop(); s.next--; throw err; } // allow retry after storage error
      s.done = true;
      s.chunks = [];
    }
    return encodePacket({type: TYPES.ACK, id: p.id, seq: p.seq, total: s.total});
  }
}
async function transmit(input, port, options = {}) {
  const {id, total, digest, packets} = makePackets(input, options.sessionId);
  const retries = options.retries ?? 5;
  const ackTimeout = options.ackTimeout ?? 12000;
  if (!Number.isInteger(retries) || retries < 0 || retries > 50) throw new Error('Retries must be 0..50');
  if (!Number.isInteger(ackTimeout) || ackTimeout < 1000 || ackTimeout > 180000) throw new Error('ackTimeout must be 1000..180000 milliseconds');
  let retransmissions = 0;
  for (const [index, raw] of packets.entries()) {
    if (options.signal?.aborted) throw new Error('Transfer interrupted');
    let acknowledged = false;
    for (let attempt = 0; attempt <= retries && !acknowledged; attempt++) {
      if (options.signal?.aborted) throw new Error('Transfer interrupted');
      if (attempt) retransmissions++;
      options.onStatus?.(`TX session=${id.toString(16).padStart(8, '0')} packet=${index}/${total} attempt=${attempt + 1}`);
      options.onEvent?.({event:'tx_attempt',id,packet:index,total,attempt:attempt+1,retry:attempt>0});
      await port.send(raw);
      const deadline = Date.now() + ackTimeout;
      while (Date.now() < deadline) {
        if (options.signal?.aborted) throw new Error('Transfer interrupted');
        const packetRaw = await port.receive(Math.max(1, deadline - Date.now()));
        if (!packetRaw) break;
        let ack;
        try { ack = parsePacket(packetRaw); } catch { continue; }
        if (ack.type === TYPES.ACK && ack.id === id && ack.seq === index && ack.total === total) {
          acknowledged = true;
          options.onStatus?.(`ACK packet=${index}/${total}`);
          options.onEvent?.({event:'ack_received',id,packet:index,total,attempt:attempt+1});
          break;
        }
      }
      if (!acknowledged) options.onEvent?.({event:'ack_timeout',id,packet:index,total,attempt:attempt+1});
    }
    if (!acknowledged) {
      options.onEvent?.({event:'transfer_failed',id,packet:index,total,attempts:retries+1});
      throw new Error(`No ACK for packet ${index}/${total} after ${retries + 1} attempts`);
    }
  }
  return {id, total, digest, retransmissions};
}
async function receiveLoop(port, receiver, options = {}) {
  const signal = options.signal;
  while (!signal?.aborted) {
    const raw = await port.receive(1200);
    if (!raw) continue;
    let packet;
    try { packet = parsePacket(raw); } catch { continue; }
    if (packet.type === TYPES.ACK) continue;
    options.onStatus?.(`RX session=${packet.id.toString(16).padStart(8,'0')} seq=${packet.seq} type=${packet.type}`);
    options.onEvent?.({event:'rx_valid',id:packet.id,packet:packet.seq,type:packet.type,total:packet.total});
    try {
      const ack = await receiver.accept(raw);
      if (ack) { await port.send(ack); options.onEvent?.({event:'ack_sent',id:packet.id,packet:packet.seq,total:packet.total}); }
      else options.onEvent?.({event:'rx_no_ack',id:packet.id,packet:packet.seq});
    } catch (err) { options.onStatus?.(`Receiver error: ${err.message}`); options.onEvent?.({event:'rx_error',message:err.message}); }
  }
}
module.exports = {MAGIC, TYPES, CHUNK_SIZE, MAX_TRANSFER, encodePacket, parsePacket, makePackets, Receiver, transmit, receiveLoop};
