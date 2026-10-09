'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { crc32, buildFrame, modulate, floatWav, parseWav, decode } = require('../lib');

function samePayload(input, options = {}) {
  const pcm = modulate(input, options);
  const wav = floatWav(pcm);
  const rx = decode(parseWav(wav));
  assert.deepEqual(rx.payload, input);
  assert.equal(rx.sha256, crypto.createHash('sha256').update(input).digest('hex'));
  return rx;
}

test('known standard CRC32 test vector', () => {
  assert.equal(crc32(Buffer.from('123456789')), 0xcbf43926);
});

test('frame byte layout and length', () => {
  const frame = buildFrame(Buffer.from('OK'));
  assert.equal(frame.length, 16 + 4 + 4 + 2 + 4);
  assert.equal(frame.subarray(0, 16).toString('hex'), '55'.repeat(16));
  assert.equal(frame.subarray(16, 20).toString('hex'), 'd391c5a7');
  assert.equal(frame.readUInt16BE(22), 2);
});

test('complete clean roundtrip 200 baud', () => {
  const tx = samePayload(Buffer.from('A signed-transaction binary transport demonstration.'));
  assert.equal(tx.baud, 200);
});

test('complete clean roundtrip 100 baud', () => {
  const tx = samePayload(Buffer.from([0, 255, 128, 12, 22, 255, 0, 0]), {baud: 100});
  assert.equal(tx.baud, 100);
});

test('random binary payload roundtrip', () => {
  const payload = crypto.randomBytes(141);
  samePayload(payload);
});

test('noisy, attenuated, offset samples decode', () => {
  const payload = Buffer.from('An audio gateway can carry offline signed data.');
  const pcm = modulate(payload);
  const offset = 137;
  const received = new Float32Array(pcm.length + offset + 301);
  // Deterministic pseudo-random broadband noise; signal amplitude down to ~45%.
  let state = 123456789;
  for (let i = 0; i < received.length; i++) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    const noise = ((state / 0xffffffff) * 2 - 1) * 0.10;
    received[i] = noise + (i >= offset && i - offset < pcm.length ? pcm[i - offset] * 0.45 : 0);
  }
  const rx = decode(parseWav(floatWav(received)));
  assert.deepEqual(rx.payload, payload);
});

test('reject garbage rather than misreport success', () => {
  const noise = new Float32Array(24000);
  assert.throws(() => decode(noise), /No valid frame/);
});

test('reject damaged transaction data via CRC32', () => {
  const pcm = modulate(Buffer.from('Integrity-check payload'));
  // Blank out multiple payload bits (after preamble + sync + header).
  const bitStart = (16 + 4 + 4) * 8;
  const ix = 2400 + bitStart * 40;
  pcm.fill(0, ix, ix + 40 * 32);
  assert.throws(() => decode(pcm, { baud: 200 }), /No valid frame/);
});

test('repeated transmission survives first frame corruption', () => {
  const payload = Buffer.from('Recovery from a corrupted first frame.');
  const pcm = modulate(payload, { repeats: 2 });
  // Destroy a chunk near the beginning of the first frame only.
  pcm.fill(0, 2400 + 4500, 2400 + 9000);
  const rx = decode(pcm, { baud: 200 });
  assert.deepEqual(rx.payload, payload);
});
