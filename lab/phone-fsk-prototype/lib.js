'use strict';

// Educational 2-FSK audio transport. NOT a TELRPC implementation or full ITU/Bell modem.
// 1 bit = 1200 Hz; 0 bit = 2200 Hz. Continuous-phase at 8 kHz, 200 bits/s.
// Structure: 16 * 0x55 (preamble), 0xD391C5A7 (sync),
//            version:1, flags:1, payloadLength:2, payload, CRC32:4
// Integers in the frame are big-endian; frame bits are MSB-first.

const crypto = require('node:crypto');

const SAMPLE_RATE = 8000;
const DEFAULT_BAUD = 200;
const ALLOWED_BAUD = [100, 200];
const FREQ_1 = 1200;
const FREQ_0 = 2200;
const PREAMBLE = Buffer.alloc(16, 0x55);
const SYNC = Buffer.from([0xD3, 0x91, 0xC5, 0xA7]);
const MAX_PAYLOAD = 4096;

const CRC_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let j = 0; j < 8; j++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : c >>> 1;
  CRC_TABLE[i] = c >>> 0;
}
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function buildFrame(payload) {
  if (!Buffer.isBuffer(payload)) payload = Buffer.from(payload);
  if (payload.length > MAX_PAYLOAD) throw new Error(`Payload exceeds ${MAX_PAYLOAD} byte maximum`);
  const body = Buffer.alloc(4 + payload.length);
  body[0] = 1; // version
  body[1] = 0; // flags, reserved
  body.writeUInt16BE(payload.length, 2);
  payload.copy(body, 4);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([PREAMBLE, SYNC, body, crc]);
}
function byteBits(buf) {
  const bits = new Uint8Array(buf.length * 8);
  for (let i = 0; i < buf.length; i++) {
    for (let bit = 7; bit >= 0; bit--) bits[i * 8 + 7 - bit] = (buf[i] >> bit) & 1;
  }
  return bits;
}
function bitsUInt(bits, at, count) {
  let x = 0;
  for (let i = 0; i < count; i++) x = ((x << 1) | bits[at + i]) >>> 0;
  return x >>> 0;
}
function readByte(bits, at) { return bitsUInt(bits, at, 8); }

function modulate(payload, opts = {}) {
  const baud = opts.baud ?? DEFAULT_BAUD;
  const repeats = opts.repeats ?? 1;
  if (!ALLOWED_BAUD.includes(baud)) throw new Error(`Baud must be ${ALLOWED_BAUD.join(' or ')}`);
  if (!Number.isInteger(repeats) || repeats < 1 || repeats > 5) throw new Error('Repeats must be 1..5');
  const samplesPerBit = SAMPLE_RATE / baud;
  const bits = byteBits(buildFrame(payload));
  const leadSamples = Math.round(0.30 * SAMPLE_RATE);
  const gapSamples = Math.round(0.35 * SAMPLE_RATE);
  const tailSamples = Math.round(0.30 * SAMPLE_RATE);
  const frameSamples = bits.length * samplesPerBit;
  const all = new Float32Array(leadSamples + repeats * frameSamples + (repeats - 1) * gapSamples + tailSamples);
  let base = leadSamples;
  for (let repeat = 0; repeat < repeats; repeat++) {
    let phase = 0;
    for (let b = 0; b < bits.length; b++) {
      const f = bits[b] ? FREQ_1 : FREQ_0;
      const step = 2 * Math.PI * f / SAMPLE_RATE;
      for (let k = 0; k < samplesPerBit; k++) {
        const ix = b * samplesPerBit + k;
        // 5ms taper at frame edges to avoid audible clicks.
        const edge = Math.min(1, ix / 40, (frameSamples - ix - 1) / 40);
        all[base + ix] = 0.78 * Math.sin(phase) * Math.max(0, edge);
        phase += step;
        if (phase >= 2 * Math.PI) phase -= 2 * Math.PI;
      }
    }
    base += frameSamples + (repeat === repeats - 1 ? 0 : gapSamples);
  }
  return all;
}
function floatWav(samples, sampleRate = SAMPLE_RATE) {
  // Simple RIFF PCM16 mono writer.
  const dataSize = samples.length * 2;
  const out = Buffer.alloc(44 + dataSize);
  out.write('RIFF', 0);
  out.writeUInt32LE(36 + dataSize, 4);
  out.write('WAVEfmt ', 8);
  out.writeUInt32LE(16, 16);
  out.writeUInt16LE(1, 20);
  out.writeUInt16LE(1, 22);
  out.writeUInt32LE(sampleRate, 24);
  out.writeUInt32LE(sampleRate * 2, 28);
  out.writeUInt16LE(2, 32);
  out.writeUInt16LE(16, 34);
  out.write('data', 36);
  out.writeUInt32LE(dataSize, 40);
  for (let i = 0; i < samples.length; i++) {
    const v = Math.max(-1, Math.min(1, samples[i]));
    out.writeInt16LE(Math.round(v * (v < 0 ? 32768 : 32767)), 44 + i * 2);
  }
  return out;
}
function parseWav(wav) {
  if (wav.length < 44 || wav.toString('ascii', 0, 4) !== 'RIFF' || wav.toString('ascii', 8, 12) !== 'WAVE') {
    throw new Error('Input must be a RIFF WAVE file. Convert M4A/MP3 with ffmpeg first.');
  }
  let fmt = null;
  let dataOffset = -1;
  let dataLength = 0;
  for (let at = 12; at + 8 <= wav.length;) {
    const id = wav.toString('ascii', at, at + 4);
    const len = wav.readUInt32LE(at + 4);
    const start = at + 8;
    if (start + len > wav.length) throw new Error('Truncated WAV chunk');
    if (id === 'fmt ') {
      if (len < 16) throw new Error('Malformed WAV fmt chunk');
      fmt = {
        format: wav.readUInt16LE(start), channels: wav.readUInt16LE(start + 2),
        sampleRate: wav.readUInt32LE(start + 4), blockAlign: wav.readUInt16LE(start + 12),
        bits: wav.readUInt16LE(start + 14)
      };
    }
    if (id === 'data' && dataOffset === -1) { dataOffset = start; dataLength = len; }
    at = start + len + (len & 1);
  }
  if (!fmt || dataOffset < 0) throw new Error('Missing WAV fmt or data');
  if (![1, 2].includes(fmt.channels) || fmt.sampleRate < 8000 || fmt.sampleRate > 96000) {
    throw new Error('Supported WAV: 1 or 2 channels, 8kHz to 96kHz');
  }
  if (!((fmt.format === 1 && fmt.bits === 16) || (fmt.format === 3 && fmt.bits === 32))) {
    throw new Error('Supported WAV: PCM16 or IEEE float32. Convert other formats with ffmpeg.');
  }
  if (fmt.blockAlign !== fmt.channels * fmt.bits / 8) throw new Error('Malformed WAV block alignment');
  const count = Math.floor(dataLength / fmt.blockAlign);
  const mono = new Float32Array(count);
  for (let i = 0; i < count; i++) {
    const at = dataOffset + i * fmt.blockAlign;
    let sum = 0;
    for (let c = 0; c < fmt.channels; c++) {
      const pos = at + c * fmt.bits / 8;
      sum += fmt.format === 1 ? wav.readInt16LE(pos) / 32768 : wav.readFloatLE(pos);
    }
    mono[i] = sum / fmt.channels;
  }
  if (fmt.sampleRate === SAMPLE_RATE) return mono;
  const len = Math.floor(mono.length * SAMPLE_RATE / fmt.sampleRate);
  const reduced = new Float32Array(len);
  // Linear resampling is adequate for this demo, not an anti-aliasing production resampler.
  for (let i = 0; i < len; i++) {
    const pos = i * fmt.sampleRate / SAMPLE_RATE;
    const low = Math.floor(pos);
    const frac = pos - low;
    reduced[i] = (mono[low] || 0) * (1 - frac) + (mono[Math.min(low + 1, mono.length - 1)] || 0) * frac;
  }
  return reduced;
}
function toneEnergy(samples, start, n, coeff) {
  let a = 0, b = 0;
  for (let i = start; i < start + n; i++) {
    const next = samples[i] + coeff * a - b;
    b = a;
    a = next;
  }
  return a * a + b * b - coeff * a * b;
}
const COEFF_1 = 2 * Math.cos(2 * Math.PI * FREQ_1 / SAMPLE_RATE);
const COEFF_0 = 2 * Math.cos(2 * Math.PI * FREQ_0 / SAMPLE_RATE);
const SYNC_WORD = SYNC.readUInt32BE(0);

function parseFrameAt(bits, syncStart) {
  const bodyStart = syncStart + 32;
  if (bodyStart + 64 > bits.length) return null;
  const version = readByte(bits, bodyStart);
  const flags = readByte(bits, bodyStart + 8);
  const len = bitsUInt(bits, bodyStart + 16, 16);
  if (version !== 1 || flags !== 0 || len > MAX_PAYLOAD) return null;
  const bodyBits = (4 + len) * 8;
  const crcStart = bodyStart + bodyBits;
  if (crcStart + 32 > bits.length) return null;
  const body = Buffer.alloc(4 + len);
  for (let i = 0; i < body.length; i++) body[i] = readByte(bits, bodyStart + i * 8);
  const gotCRC = bitsUInt(bits, crcStart, 32);
  const expectedCRC = crc32(body);
  if (gotCRC !== expectedCRC) return null;
  return { payload: body.subarray(4), length: len, crc32: gotCRC };
}
function hamming32(a, b) {
  let x = (a ^ b) >>> 0, n = 0;
  while (x) { x &= x - 1; n++; }
  return n;
}
function decode(samples, opts = {}) {
  const baudRates = opts.baud ? [opts.baud] : ALLOWED_BAUD.slice().reverse();
  for (const baud of baudRates) {
    if (!ALLOWED_BAUD.includes(baud)) throw new Error(`Baud must be ${ALLOWED_BAUD.join(' or ')}`);
    const samplesPerBit = SAMPLE_RATE / baud;
    // Search timing phase because WAV recordings start at arbitrary sample offsets.
    for (let phase = 0; phase < samplesPerBit; phase++) {
      const nbits = Math.floor((samples.length - phase) / samplesPerBit);
      if (nbits < (PREAMBLE.length + SYNC.length + 8) * 8) continue;
      const bits = new Uint8Array(nbits);
      for (let b = 0, at = phase; b < nbits; b++, at += samplesPerBit) {
        const one = toneEnergy(samples, at, samplesPerBit, COEFF_1);
        const zero = toneEnergy(samples, at, samplesPerBit, COEFF_0);
        bits[b] = one > zero ? 1 : 0;
      }
      let roll = 0;
      for (let i = 0; i < bits.length; i++) {
        roll = ((roll << 1) | bits[i]) >>> 0;
        if (i < 128 + 31) continue;
        // Allow up to two bit errors in sync; CRC32 validates the complete frame.
        if (hamming32(roll, SYNC_WORD) > 2) continue;
        const syncStart = i - 31;
        let preambleErrors = 0;
        for (let p = syncStart - 128, j = 0; j < 128; j++, p++) {
          const expected = (j & 1) === 1 ? 1 : 0; // 0x55 MSB-first
          if (bits[p] !== expected) preambleErrors++;
        }
        if (preambleErrors > 24) continue;
        const packet = parseFrameAt(bits, syncStart);
        if (packet) {
          return {
            ...packet,
            baud,
            phase,
            sampleOffset: phase + (syncStart - 128) * samplesPerBit,
            sha256: crypto.createHash('sha256').update(packet.payload).digest('hex')
          };
        }
      }
    }
  }
  throw new Error('No valid frame found (failed sync or CRC32). Try a cleaner recording, a lower baud rate, or more repeats.');
}

module.exports = { SAMPLE_RATE, DEFAULT_BAUD, MAX_PAYLOAD, buildFrame, byteBits, crc32,
  modulate, floatWav, parseWav, decode };
