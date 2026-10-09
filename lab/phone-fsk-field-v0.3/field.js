#!/usr/bin/env node
'use strict';
// One-way mobile-voice-call experiment: audio test cards and capture analysis.
// This is a field instrument, not a modem standard or BER estimator.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { SAMPLE_RATE, modulate, floatWav, parseWav, scanFrames } = require('./lib');

function arg(args, name, fallback) {
  const i = args.indexOf(name);
  if (i < 0) return fallback;
  if (!args[i+1] || args[i+1].startsWith('--')) throw new Error(`Expected value for ${name}`);
  return args[i+1];
}
function intArg(args, name, fallback, min, max) {
  const n = Number(arg(args,name,String(fallback)));
  if (!Number.isInteger(n) || n < min || n > max) throw new Error(`${name} must be ${min}..${max}`);
  return n;
}
function ensureNotExists(p) { if (fs.existsSync(p)) throw new Error(`Refusing to overwrite ${p}`); }
function generate(args) {
  const baud = intArg(args, '--baud', 100, 100, 200);
  if (![100,200].includes(baud)) throw new Error('--baud must be 100 or 200');
  const count = intArg(args, '--count', 6, 1, 20);
  const gapMs = intArg(args, '--gap-ms', 1000, 750, 4000);
  const wavPath = path.resolve(arg(args, '--out', `field-${baud}.wav`));
  const manifestPath = path.resolve(arg(args, '--manifest', `field-${baud}.json`));
  ensureNotExists(wavPath); ensureNotExists(manifestPath);
  const runId = crypto.randomBytes(4).toString('hex');
  const frames = [];
  const preSamples = SAMPLE_RATE * 3;
  const parts = [new Float32Array(preSamples)];
  let cursor = preSamples;
  for (let seq=0;seq<count;seq++) {
    // Constant-length payload: marker, random trial ID, sequence, count, and a nonce.
    const payload = Buffer.alloc(16);
    payload.write('FST3', 0, 'ascii');
    Buffer.from(runId, 'hex').copy(payload, 4);
    payload.writeUInt16BE(seq, 8);
    payload.writeUInt16BE(count, 10);
    crypto.randomBytes(4).copy(payload, 12);
    const audio = modulate(payload, {baud});
    parts.push(audio);
    frames.push({sequence: seq, payloadHex:payload.toString('hex'), expectedStartSeconds: Number((cursor / SAMPLE_RATE).toFixed(3))});
    cursor += audio.length;
    const silence = new Float32Array(Math.round(gapMs / 1000 * SAMPLE_RATE));
    parts.push(silence);
    cursor += silence.length;
  }
  parts.push(new Float32Array(SAMPLE_RATE * 3));
  cursor += SAMPLE_RATE * 3;
  const samples = new Float32Array(cursor);
  let at = 0;
  for (const part of parts) { samples.set(part, at); at += part.length; }
  const manifest = {format:'phone-fsk-field-v0.3', createdUtc:new Date().toISOString(), runId,
    baud, count, gapMs, durationSeconds:Number((cursor / SAMPLE_RATE).toFixed(3)),
    wavSha256:crypto.createHash('sha256').update(floatWav(samples)).digest('hex'), frames};
  // wx protects against overwriting recordings/results from prior field runs.
  fs.writeFileSync(wavPath, floatWav(samples), {flag:'wx'});
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2)+'\n', {flag:'wx'});
  console.log(`Generated ${count} numbered frames at ${baud} bit/s; ${manifest.durationSeconds}s audio.`);
  console.log(`Audio: ${wavPath}\nManifest: ${manifestPath}\nRun ID: ${runId}`);
}
function reportStats(samples) {
  let clipping = 0, sum = 0, max = 0;
  for (const x of samples) { const a = Math.abs(x); sum += x*x; max=Math.max(a,max); if (a >= .98) clipping++; }
  return { durationSeconds:Number((samples.length / SAMPLE_RATE).toFixed(3)),
    rms:Number(Math.sqrt(sum/Math.max(1,samples.length)).toFixed(4)),
    peak:Number(max.toFixed(4)), clippedSamples:clipping,
    clippingPercent:Number((clipping*100/Math.max(1,samples.length)).toFixed(3)) };
}
function analyzeRecording(samples, manifest) {
  if (manifest.format !== 'phone-fsk-field-v0.3') throw new Error('Incorrect field-test manifest');
  if (![100,200].includes(manifest.baud) || !Number.isInteger(manifest.count) || manifest.count < 1 || manifest.count > 20 ||
      !Array.isArray(manifest.frames) || manifest.frames.length !== manifest.count || !/^[a-f0-9]{8}$/.test(manifest.runId)) {
    throw new Error('Invalid field-test manifest');
  }
  const rxFrames = scanFrames(samples, {baud:manifest.baud});
  const received = new Map(), unknown = [];
  for (const {payload,sampleOffset} of rxFrames) {
    const seq = payload.length === 16 ? payload.readUInt16BE(8) : -1;
    const runId = payload.length >= 8 ? payload.subarray(4,8).toString('hex') : '';
    const expected = manifest.frames[seq];
    if (payload.subarray(0,4).toString('ascii') === 'FST3' && runId === manifest.runId &&
        expected && expected.payloadHex === payload.toString('hex')) {
      if (!received.has(seq)) received.set(seq,{sequence:seq,atSeconds:Number((sampleOffset/SAMPLE_RATE).toFixed(3))});
    } else unknown.push({atSeconds:Number((sampleOffset/SAMPLE_RATE).toFixed(3))});
  }
  const got = [...received.values()].sort((a,b)=>a.sequence-b.sequence);
  const missed = manifest.frames.filter(f=>!received.has(f.sequence)).map(f=>f.sequence);
  return {format:'phone-fsk-field-report-v0.3',runId:manifest.runId, baud:manifest.baud,
    expectedFrames:manifest.count, verifiedFrames:got.length, missingFrames:missed,
    frameDeliveryPercent:Number((got.length*100/manifest.count).toFixed(1)),
    recovered:got, unknownValidFrames:unknown.length,
    signal:reportStats(samples),
    caveat:'Frame-delivery rate is not bit-error rate. Missing frames may reflect clipping, sync loss, silence suppression, noise, or CRC rejection. No on-chain or cellular test is implied.'};
}
function analyze(args) {
  const wavArg=arg(args,'--in'); const manifestArg=arg(args,'--manifest');
  if (!wavArg || !manifestArg) throw new Error('Provide --in received.wav and --manifest field.json');
  const wavPath = path.resolve(wavArg);
  const manifestPath = path.resolve(manifestArg);
  if (!fs.existsSync(wavPath) || !fs.existsSync(manifestPath)) throw new Error('Missing WAV or manifest file');
  const outputPath = path.resolve(arg(args,'--out','field-report.json'));
  ensureNotExists(outputPath);
  const samples = parseWav(fs.readFileSync(wavPath));
  const report = analyzeRecording(samples, JSON.parse(fs.readFileSync(manifestPath,'utf8')));
  fs.writeFileSync(outputPath, JSON.stringify(report,null,2)+'\n', {flag:'wx'});
  console.log(`Verified ${report.verifiedFrames}/${report.expectedFrames} frames (${report.frameDeliveryPercent}%) at ${report.baud} bit/s`);
  console.log(`Missing sequence numbers: ${report.missingFrames.join(', ') || 'none'}`);
  console.log(`Peak=${report.signal.peak}, clipping=${report.signal.clippingPercent}%`);
  console.log(`Report: ${outputPath}`);
}
function record(args) {
  const out = path.resolve(arg(args,'--out','received.wav'));
  const seconds = intArg(args,'--seconds',75,5,180);
  ensureNotExists(out);
  const cmd = spawnSync('sox',['-q','-d','-r','8000','-c','1','-b','16','-e','signed-integer',out,'trim','0',String(seconds)], {stdio:'inherit'});
  if (cmd.error) throw new Error(`SoX required: ${cmd.error.message}. Install with brew install sox.`);
  if (cmd.status !== 0) throw new Error(`SoX recording exited ${cmd.status}`);
  console.log(`Saved: ${out}`);
}
function compare(args) {
  const inputs = arg(args,'--reports');
  if (!inputs) throw new Error('Provide --reports report-100.json,report-200.json');
  const paths = inputs.split(',').map(p=>p.trim());
  if (paths.length < 1 || paths.length > 20) throw new Error('Expect 1..20 reports');
  const out = path.resolve(arg(args,'--out','comparison.md'));
  ensureNotExists(out);
  const rows = paths.map(p=> {
    const r=JSON.parse(fs.readFileSync(p,'utf8'));
    if (r.format !== 'phone-fsk-field-report-v0.3') throw new Error(`Invalid report: ${p}`);
    return `| ${path.basename(p).replace(/\|/g,'-')} | ${r.baud} | ${r.verifiedFrames}/${r.expectedFrames} | ${r.frameDeliveryPercent}% | ${r.signal.clippingPercent}% | ${r.missingFrames.join(', ')||'—'} |`;
  });
  const markdown=`# Phone FSK field comparison\n\n` +
    `| Recording | bit/s | Verified frames | Delivery | Clipping | Missing seq |\n`+
    `|---|---:|---:|---:|---:|---|\n`+rows.join('\n')+`\n\n`+
    `Frame delivery is not BER; results reflect only valid CRC-checked frames. `+
    `Test conditions (phone model, network, routing, volume, location) should be documented separately.\n`;
  fs.writeFileSync(out,markdown,{flag:'wx'});
  console.log(markdown);
  console.log(`Saved ${out}`);
}
function help() {
  console.log(`Mobile phone FSK field-test v0.3 (offline, ONE WAY first)

  node field.js generate --baud 100 --count 6 --out test-100.wav --manifest test-100.json
  node field.js record --out received-100.wav --seconds 75
  node field.js analyze --in received-100.wav --manifest test-100.json --out report-100.json
  node field.js compare --reports report-100.json,report-200.json --out comparison.md

Also test --baud 200; count=1..20, gap-ms=750..4000. Audio is 8kHz mono PCM WAV.
Receive with external mic recording the PHONE speaker during a live voice call.
Play the generated WAV into the OTHER PHONE's mic; do not play into your own mic.
No phone access or hardware testing performed by this software.`);
}
if (require.main === module) {
  try {
    const [command,...args] = process.argv.slice(2);
    if (['--help','-h','help',undefined].includes(command)) help();
    else if (command === 'generate') generate(args);
    else if (command === 'analyze') analyze(args);
    else if (command === 'record') record(args);
    else if (command === 'compare') compare(args);
    else throw new Error(`Unknown command: ${command}`);
  } catch (err) { console.error(`ERROR: ${err.message}`); process.exitCode=1; }
}
module.exports = {generate, analyzeRecording, reportStats};
