'use strict';
// Real sound-card I/O uses SoX (brew install sox). The modulation remains dependency-free JS.
const { spawn, spawnSync } = require('node:child_process');
const { modulate, floatWav, decode, SAMPLE_RATE } = require('./lib');
const { parsePacket } = require('./protocol');

function requireSox(bin = 'sox') {
  const check = spawnSync(bin, ['--version'], {encoding:'utf8'});
  if (check.error || check.status !== 0) throw new Error(`SoX is required for live I/O. Install with brew install sox. (${check.error?.message || check.stderr})`);
}
function playWav(wav, bin = 'sox') {
  return new Promise((resolve, reject) => {
    const proc = spawn(bin, ['-q', '-t', 'wav', '-', '-d'], {stdio:['pipe', 'ignore', 'pipe']});
    let stderr = '';
    proc.stderr.on('data', d => { stderr += d.toString().slice(0, 2048); });
    proc.on('error', reject);
    proc.stdin.on('error', err => { if (err.code !== 'EPIPE') reject(err); });
    proc.on('close', code => code === 0 ? resolve() : reject(new Error(`SoX playback failed (${code}): ${stderr}`)));
    proc.stdin.end(wav);
  });
}
class LiveAudioPort {
  constructor({baud = 100, sox = 'sox', maxSeconds = 24} = {}) {
    if (![100, 200].includes(baud)) throw new Error('Baud must be 100 or 200');
    this.baud = baud;
    this.sox = sox;
    this.maxSamples = SAMPLE_RATE * maxSeconds;
    this.totalSamples = 0;
    this.consumed = 0;
    this.pcm = Buffer.alloc(0);
    this.odd = Buffer.alloc(0);
    this.error = null;
    this.closed = false;
  }
  start() {
    requireSox(this.sox);
    // Raw signed 16-bit PCM, 8 kHz mono. SoX converts hardware sample rate.
    this.recorder = spawn(this.sox, ['-q', '-d', '-t', 'raw', '-r', '8000', '-c', '1', '-e', 'signed-integer', '-b', '16', '-'], {stdio:['ignore','pipe','pipe']});
    this.recorder.on('error', err => { this.error = err; });
    let stderr = '';
    this.recorder.stderr.on('data', d => { stderr += d.toString().slice(0,1024); });
    this.recorder.on('exit', (code, signal) => { if (!this.closed) this.error = new Error(`SoX microphone stopped (${code}/${signal}): ${stderr}`); });
    this.recorder.stdout.on('data', b => {
      if (this.odd.length) { b = Buffer.concat([this.odd, b]); this.odd = Buffer.alloc(0); }
      if (b.length & 1) { this.odd = Buffer.from(b.subarray(-1)); b = b.subarray(0,-1); }
      this.pcm = Buffer.concat([this.pcm, b]);
      this.totalSamples += b.length / 2;
      if (this.pcm.length > this.maxSamples * 2) this.pcm = Buffer.from(this.pcm.subarray(-this.maxSamples * 2));
    });
    return this;
  }
  async send(raw) {
    if (this.error) throw this.error;
    return playWav(floatWav(modulate(raw, {baud: this.baud})), this.sox);
  }
  async receive(timeoutMs = 12000) {
    const deadline = Date.now() + timeoutMs;
    let lastTriedSamples = -1;
    while (!this.closed && Date.now() < deadline) {
      if (this.error) throw this.error;
      const base = this.totalSamples - this.pcm.length / 2;
      const from = Math.max(base, this.consumed);
      const avail = this.totalSamples - from;
      // Wait for at least the 28-byte modem frame + 18-byte protocol packet.
      const minSamples = Math.floor(46 * 8 * SAMPLE_RATE / this.baud);
      if (avail >= minSamples && this.totalSamples - lastTriedSamples >= 0.35 * SAMPLE_RATE) {
        lastTriedSamples = this.totalSamples;
        const offset = (from - base) * 2;
        const buf = this.pcm.subarray(offset);
        const samples = new Float32Array(Math.floor(buf.length / 2));
        for (let i = 0; i < samples.length; i++) samples[i] = buf.readInt16LE(i * 2) / 32768;
        try {
          const decoded = decode(samples, {baud:this.baud});
          const frameEnd = from + decoded.sampleOffset + (28 + decoded.length) * 8 * SAMPLE_RATE / decoded.baud;
          this.consumed = Math.max(this.consumed, Math.floor(frameEnd));
          // Valid audio frame but malformed protocol packet: ignore safely.
          try { parsePacket(decoded.payload); return decoded.payload; } catch { /* ignore */ }
        } catch { /* incomplete or corrupted frame; keep listening */ }
      }
      await new Promise(resolve => setTimeout(resolve, 200));
    }
    return null;
  }
  close() {
    this.closed = true;
    if (this.recorder && !this.recorder.killed) this.recorder.kill('SIGTERM');
  }
}
module.exports = { LiveAudioPort, requireSox, playWav };
