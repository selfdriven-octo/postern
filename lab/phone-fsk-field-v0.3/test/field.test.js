'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { generate, analyzeRecording } = require('../field');
const { parseWav, floatWav, scanFrames, SAMPLE_RATE } = require('../lib');

function testWave(baud, count) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'phone-fsk-'));
  const wavPath = path.join(tmp,'probe.wav'), manifestPath=path.join(tmp,'probe.json');
  try {
    generate(['--baud',String(baud),'--count',String(count),'--out',wavPath,'--manifest',manifestPath]);
    return {samples:parseWav(fs.readFileSync(wavPath)), manifest:JSON.parse(fs.readFileSync(manifestPath,'utf8'))};
  } finally {fs.rmSync(tmp,{recursive:true,force:true});}
}

test('field generator and scanner recover every 100-bit/s beacon', () => {
  const {samples,manifest}=testWave(100,3);
  const result=analyzeRecording(samples,manifest);
  assert.equal(result.verifiedFrames,3);
  assert.deepEqual(result.missingFrames,[]);
  assert.equal(result.frameDeliveryPercent,100);
  assert.equal(result.unknownValidFrames,0);
});

test('field scanner 200-bit/s decodes extra recording lead-in and quiet attenuation', () => {
  const {samples,manifest}=testWave(200,3);
  const padded=new Float32Array(samples.length+SAMPLE_RATE);
  for (let i=0;i<samples.length;i++) padded[i+SAMPLE_RATE]=samples[i]*0.18;
  const report=analyzeRecording(parseWav(floatWav(padded)),manifest);
  assert.equal(report.verifiedFrames,3);
  assert.equal(report.signal.clippedSamples,0);
});

test('a deliberately silenced trial is counted as a missing frame, not as bit errors', () => {
  const {samples,manifest}=testWave(100,3);
  const corrupted = new Float32Array(samples);
  const start=Math.floor((manifest.frames[1].expectedStartSeconds - .05)*SAMPLE_RATE);
  const end=Math.floor((manifest.frames[1].expectedStartSeconds + 4.25)*SAMPLE_RATE);
  corrupted.fill(0,start,end);
  const result=analyzeRecording(corrupted,manifest);
  assert.equal(result.verifiedFrames,2);
  assert.deepEqual(result.missingFrames,[1]);
  assert.equal(result.frameDeliveryPercent,66.7);
});

test('scan rejects silence as non-existent frames', () => {
  assert.deepEqual(scanFrames(new Float32Array(SAMPLE_RATE*6),{baud:100}),[]);
});
