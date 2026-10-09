'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {LiveAudioPort} = require('../audio');
const {modulate} = require('../lib');
const {encodePacket,TYPES,parsePacket} = require('../protocol');

// Exercises the live-stream receive scanning logic using synthetic microphone PCM.
// Does not claim to test real audio hardware or a cellular voice call.
test('streaming audio port extracts two consecutive packets without replay', async () => {
  const input1 = encodePacket({type:TYPES.START,id:123,seq:0,total:1,data:Buffer.alloc(36)});
  const input2 = encodePacket({type:TYPES.ACK,id:123,seq:0,total:1});
  const s1 = modulate(input1,{baud:200});
  const s2 = modulate(input2,{baud:200});
  const pcm = new Float32Array(s1.length+s2.length+111);
  pcm.set(s1,111);
  pcm.set(s2,111+s1.length);
  const raw = Buffer.alloc(pcm.length*2);
  for (let n=0;n<pcm.length;n++) raw.writeInt16LE(Math.round(Math.max(-1,Math.min(1,pcm[n]))*32767),n*2);
  const port = new LiveAudioPort({baud:200});
  port.pcm=raw;
  port.totalSamples=pcm.length;
  assert.deepEqual(await port.receive(250),input1);
  assert.deepEqual(await port.receive(250),input2);
  assert.equal(parsePacket(input2).type,TYPES.ACK);
  port.close();
});
