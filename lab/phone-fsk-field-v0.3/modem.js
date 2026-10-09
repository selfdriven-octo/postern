#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const crypto = require('node:crypto');
const { modulate, floatWav, parseWav, decode, MAX_PAYLOAD, DEFAULT_BAUD } = require('./lib');

function usage() {
  console.log(`Phone FSK demo — 1200/2200 Hz; ${DEFAULT_BAUD} bits/sec default; not a TELRPC implementation

Usage:
  node modem.js encode --in FILE --out FILE.wav [--baud 100|200] [--repeat 1..5]
  node modem.js decode --in FILE.wav --out FILE [--baud 100|200]
  node modem.js inspect --in FILE.wav [--baud 100|200]

All payloads are treated as binary. For Cardano, supply a *signed transaction CBOR* file,
not a seed phrase, private key or unsigned transaction. This does not broadcast to a chain.
Input WAV: PCM16 or float32 mono/stereo, 8kHz–96kHz; compressed audio must be converted.
Maximum payload: ${MAX_PAYLOAD} bytes.
`);
}
function opt(args, name, fallback) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : fallback;
}
function requireFile(name, val) {
  if (!val || val.startsWith('--')) throw new Error(`${name} is required`);
  return val;
}
function run() {
  const [command, ...args] = process.argv.slice(2);
  if (!command || ['help', '--help', '-h'].includes(command)) return usage();
  const file = requireFile('--in', opt(args, '--in'));
  const out = opt(args, '--out');
  const baudArg = opt(args, '--baud');
  const baud = baudArg === undefined ? undefined : Number(baudArg);
  if (command === 'encode') {
    requireFile('--out', out);
    const payload = fs.readFileSync(file);
    const repeats = Number(opt(args, '--repeat', '1'));
    const samples = modulate(payload, { baud, repeats });
    fs.writeFileSync(out, floatWav(samples));
    console.log(`Encoded ${payload.length} bytes to ${out} | ${baud || DEFAULT_BAUD} bit/s | ${repeats} repeat(s) | ${(samples.length / 8000).toFixed(2)}s`);
    console.log('Payload SHA-256:', crypto.createHash('sha256').update(payload).digest('hex'));
  } else if (command === 'decode' || command === 'inspect') {
    if (command === 'decode') requireFile('--out', out);
    const decoded = decode(parseWav(fs.readFileSync(file)), { baud });
    if (command === 'decode') fs.writeFileSync(out, decoded.payload);
    console.log(`CRC32 VALID | ${decoded.length} bytes | baud=${decoded.baud} | sample-phase=${decoded.phase}`);
    console.log('Payload SHA-256:', decoded.sha256);
    if (command === 'decode') console.log(`Recovered bytes to ${out}`);
  } else {
    return usage();
  }
}
try { run(); } catch (e) { console.error('ERROR:', e.message); process.exitCode = 1; }
