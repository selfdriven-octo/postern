'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const { modulate, decode } = require('../lib');
const { TYPES, CHUNK_SIZE, MAX_TRANSFER, makePackets, encodePacket, parsePacket, Receiver, transmit, receiveLoop } = require('../protocol');
const { submitSignedCbor } = require('../cardano');

class MockPort {
  constructor() {this.peer = null; this.queue = []; this.waiters = []; this.filter = null;}
  connect(peer) {this.peer = peer; peer.peer = this;}
  async send(raw) {
    const packet = parsePacket(raw);
    if (this.filter?.(packet)) return; // simulate lost audio frames
    const pcm = modulate(raw, {baud:100});
    // Simulate an analogue recording with a non-bit-aligned leading offset.
    const shifted = new Float32Array(pcm.length + 41);
    shifted.set(pcm, 41);
    const restored = decode(shifted, {baud:100}).payload;
    this.peer.enqueue(restored);
  }
  enqueue(raw) {
    const waiter = this.waiters.shift();
    if (waiter) {clearTimeout(waiter.timer); waiter.resolve(raw);}
    else this.queue.push(raw);
  }
  receive(timeoutMs) {
    if (this.queue.length) return Promise.resolve(this.queue.shift());
    return new Promise(resolve => {
      const waiter = {resolve, timer:null};
      waiter.timer = setTimeout(() => {
        const ix = this.waiters.indexOf(waiter);
        if (ix !== -1) this.waiters.splice(ix,1);
        resolve(null);
      }, timeoutMs);
      this.waiters.push(waiter);
    });
  }
}

test('packet integrity, strict format and roundtrip', () => {
  const original = encodePacket({type:TYPES.DATA, id:0xabcdef12, seq:3, total:5, data:Buffer.from([0,128,255])});
  assert.deepEqual(parsePacket(original), {type:TYPES.DATA,id:0xabcdef12,seq:3,total:5,data:Buffer.from([0,128,255])});
  const damaged = Buffer.from(original); damaged[15] ^= 0x80;
  assert.throws(() => parsePacket(damaged), /CRC/);
  assert.throws(() => encodePacket({type:TYPES.DATA,id:1,seq:1,total:1,data:Buffer.alloc(CHUNK_SIZE+1)}), /too long/);
});

test('start / multiple data / ack, duplicates and no premature commit', async () => {
  const input = crypto.randomBytes(145);
  const {packets} = makePackets(input, 0x12345678);
  let completed = 0;
  const rx = new Receiver(async (b, info) => {assert.deepEqual(b,input); assert.equal(info.id,0x12345678); completed++;});
  assert.equal(parsePacket(await rx.accept(packets[0])).seq,0);
  assert.equal(parsePacket(await rx.accept(packets[0])).seq,0);
  assert.equal(await rx.accept(packets[2]),null); // out of order is not accepted
  for (let n=1; n<packets.length;n++) {
    assert.equal(parsePacket(await rx.accept(packets[n])).seq,n);
    assert.equal(parsePacket(await rx.accept(packets[n])).seq,n);
  }
  assert.equal(completed,1);
});

test('reject changed metadata / invalid input size / corrupted payload digest', async () => {
  assert.throws(() => makePackets(Buffer.alloc(MAX_TRANSFER+1)), /Input must/);
  const inbuf = Buffer.from('The data must agree with the START sha256');
  const {packets, id, total} = makePackets(inbuf,44);
  let complete = 0;
  const rx = new Receiver(async () => {complete++;});
  assert.ok(await rx.accept(packets[0]));
  const alt = makePackets(Buffer.from('Different payload'),44);
  assert.equal(await rx.accept(alt.packets[0]),null); // no session-id substitution
  const damagedButCrcValid = encodePacket({type:TYPES.DATA,id,seq:1,total,data:Buffer.alloc(inbuf.length, 0)});
  assert.equal(await rx.accept(damagedButCrcValid),null);
  assert.equal(complete,0);
});

test('end-to-end audio-link ARQ resends after dropped ACK and data frame', async () => {
  const sender = new MockPort();
  const receiver = new MockPort();
  sender.connect(receiver);
  const dropped = new Set();
  sender.filter = p => {
    if (p.type === TYPES.DATA && p.seq === 2 && !dropped.has('data2')) {dropped.add('data2');return true;}
    return false;
  };
  receiver.filter = p => {
    if (p.type === TYPES.ACK && p.seq === 1 && !dropped.has('ack1')) {dropped.add('ack1');return true;}
    return false;
  };
  const input = crypto.randomBytes(113);
  let saved = null; let doneCount=0;
  const rx = new Receiver(async b => {saved=b;doneCount++;});
  const stop = new AbortController();
  const txEvents=[]; const rxEvents=[];
  const task = receiveLoop(receiver,rx,{signal:stop.signal,onEvent:e=>rxEvents.push(e)});
  try {
    const result = await transmit(input,sender,{ackTimeout:1000,retries:3,sessionId:0x11223344,onEvent:e=>txEvents.push(e)});
    assert.deepEqual(saved,input);
    assert.equal(doneCount,1);
    assert.equal(result.retransmissions,2);
    assert.equal(result.total,3);
    assert.equal(result.digest,crypto.createHash('sha256').update(input).digest('hex'));
    assert.deepEqual([...dropped].sort(),['ack1','data2']);
    assert.equal(txEvents.filter(e=>e.event==='tx_attempt').length,6);
    assert.equal(txEvents.filter(e=>e.event==='ack_timeout').length,2);
    assert.equal(txEvents.filter(e=>e.event==='ack_received').length,4);
    assert.ok(rxEvents.some(e=>e.event==='ack_sent'));
  } finally {stop.abort(); await task;}
});

test('lost final ACK does not lead to duplicate delivery', async () => {
  const sender = new MockPort(); const receiver = new MockPort();
  sender.connect(receiver);
  let dropped=false, commits=0;
  receiver.filter = p => {
    if (p.type === TYPES.ACK && p.seq === 1 && !dropped) { dropped=true;return true; }
    return false;
  };
  const ctrl=new AbortController();
  const task=receiveLoop(receiver, new Receiver(async () => {commits++;}), {signal:ctrl.signal});
  try {
    const r=await transmit(Buffer.from('TEST'),sender,{ackTimeout:1000,retries:2});
    assert.equal(commits,1);
    assert.equal(r.retransmissions,1);
    assert.equal(dropped,true);
  } finally {ctrl.abort();await task;}
});

test('sender fails closed after exhausted ACK retries', async () => {
  const a = new MockPort(); const b = new MockPort(); a.connect(b);
  // No receiver loop running.
  await assert.rejects(() => transmit(Buffer.from('HELLO'),a,{ackTimeout:1000,retries:0}), /No ACK/);
});

test('Cardano HTTP submit is explicit, posts exact bytes, validates response', async () => {
  const data = Buffer.from([0x84,0x81,0x12,0xa0,0x80]);
  let received, header;
  const server = http.createServer((req,res) => {
    header = req.headers;
    const parts=[];
    req.on('data',d=>parts.push(d)).on('end',()=>{
      received=Buffer.concat(parts);
      res.writeHead(202,{'content-type':'text/plain'});
      res.end('test-transaction-hash');
    });
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const endpoint = `http://127.0.0.1:${server.address().port}/api/v0/tx/submit`;
  try {
    await assert.rejects(()=>submitSignedCbor(data,{endpoint}),/HTTPS required/);
    const result = await submitSignedCbor(data,{endpoint,allowLocalHttp:true,projectId:'test-id'});
    assert.equal(result.httpStatus,202);
    assert.equal(result.response,'test-transaction-hash');
    assert.deepEqual(received,data);
    assert.equal(header['content-type'],'application/cbor');
    assert.equal(header.project_id,'test-id');
  } finally {server.close();}
});
