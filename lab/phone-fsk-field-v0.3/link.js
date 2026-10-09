#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { LiveAudioPort } = require('./audio');
const { Receiver, transmit, receiveLoop, MAX_TRANSFER } = require('./protocol');
const { submitSignedCbor } = require('./cardano');
function argument(args, key, fallback) {
  const at = args.indexOf(key);
  if (at < 0) return fallback;
  const value = args[at+1];
  if (!value || value.startsWith('--')) throw new Error(`Missing value for ${key}`);
  return value;
}
function usage() {
  console.log(`Phone FSK v0.3 — live microphone/speaker ARQ over audio, NOT TELRPC

Install SoX: brew install sox  (macOS)

  node link.js send --in signed.tx.cbor [--baud 100|200] [--retries 5] [--ack-timeout 12000]
  node link.js receive --out-dir ./received [--baud 100|200]
      [--submit --submit-url https://<cardano-provider>/api/v0/tx/submit]
      [--project-id-env BLOCKFROST_PROJECT_ID] [--expect-sha256 64_HEX_DIGEST]
  Both: [--log-json log.jsonl]  Sender: [--summary-json summary.json]

Receiver must start before sender. Use two computers with audio connections, or
phones on an ongoing voice call with sound-card/headset adapters.

The default receiver ONLY writes recovered bytes to disk. --submit must be explicit.
The ACK confirms verified receipt, NOT blockchain inclusion. Never transmit keys.
`);
}
async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (!command || ['--help','-h','help'].includes(command)) return usage();
  if (!['send','receive'].includes(command)) throw new Error('Command must be send or receive');
  const baud = Number(argument(args,'--baud','100'));
  const logPath = argument(args,'--log-json');
  const summaryPath = argument(args,'--summary-json');
  if (summaryPath && command !== 'send') throw new Error('--summary-json is for send only');
  if (logPath && fs.existsSync(logPath)) throw new Error(`Log already exists: ${logPath}`);
  if (summaryPath && fs.existsSync(summaryPath)) throw new Error(`Summary already exists: ${summaryPath}`);
  if (logPath) fs.writeFileSync(logPath, '', {flag:'wx',mode:0o600});
  const onEvent = logPath ? event => fs.appendFileSync(logPath,JSON.stringify({utc:new Date().toISOString(), ...event})+'\n') : undefined;
  const port = new LiveAudioPort({baud}).start();
  const controller = new AbortController();
  process.on('SIGINT', () => {controller.abort(); port.close(); process.exitCode=130;});
  try {
    if (command === 'send') {
      const input = argument(args,'--in');
      if (!input) throw new Error('--in file required');
      const bytes = fs.readFileSync(input);
      if (!bytes.length || bytes.length > MAX_TRANSFER) throw new Error(`Size must be 1..${MAX_TRANSFER} bytes`);
      console.log(`Sending ${bytes.length} bytes at ${baud} bit/s. Start the receiver first.`);
      const start = Date.now();
      const packetEvents = [];
      const result = await transmit(bytes, port, {
        signal: controller.signal,
        retries: Number(argument(args,'--retries','5')),
        ackTimeout: Number(argument(args,'--ack-timeout','12000')),
        onStatus: console.log,
        onEvent: event => { packetEvents.push(event); onEvent?.(event); }
      });
      const summary = {format:'phone-fsk-link-summary-v0.3',success:true,session:result.id.toString(16),
        sizeBytes:bytes.length,baud,sha256:result.digest,packetCount:result.total+1,
        attempts:packetEvents.filter(e=>e.event==='tx_attempt').length,
        ackTimeouts:packetEvents.filter(e=>e.event==='ack_timeout').length,
        retransmissions:result.retransmissions,durationSeconds:Number(((Date.now()-start)/1000).toFixed(3)),
        disclaimer:'An ACK verifies receiver protocol acceptance only, NOT blockchain submission or finality.'};
      if (summaryPath) fs.writeFileSync(summaryPath,JSON.stringify(summary,null,2)+'\n',{flag:'wx',mode:0o600});
      onEvent?.({event:'transfer_complete',...summary});
      console.log(`TRANSFER COMPLETE (transport ACK only) session=${result.id.toString(16)} sha256=${result.digest} retransmissions=${result.retransmissions}`);
    } else {
      const dir = path.resolve(argument(args,'--out-dir','./received'));
      fs.mkdirSync(dir, {recursive:true});
      const shouldSubmit = args.includes('--submit');
      const submitUrl = argument(args,'--submit-url');
      if (shouldSubmit && !submitUrl) throw new Error('--submit requires --submit-url');
      if (!shouldSubmit && submitUrl) throw new Error('--submit-url requires --submit');
      const projectId = shouldSubmit ? process.env[argument(args,'--project-id-env','BLOCKFROST_PROJECT_ID')] : undefined;
      if (shouldSubmit && !projectId && !args.includes('--no-project-id')) throw new Error('Missing provider project ID environment variable. Or pass --no-project-id for unauthenticated node endpoint.');
      const expectedSha = argument(args,'--expect-sha256');
      if (expectedSha && !/^[0-9a-f]{64}$/i.test(expectedSha)) throw new Error('--expect-sha256 must be a SHA-256 hex digest');
      const receiver = new Receiver(async (bytes, info) => {
        if (expectedSha && info.sha256 !== expectedSha.toLowerCase()) throw new Error('Unapproved incoming SHA-256; refusing to save or submit');
        const filename = `session-${info.id.toString(16).padStart(8,'0')}-${info.sha256.slice(0,12)}${shouldSubmit ? '.cbor' : '.bin'}`;
        const dest = path.join(dir, filename);
        fs.writeFileSync(dest, bytes, {flag:'wx', mode:0o600});
        console.log(`VERIFIED and SAVED ${bytes.length} bytes sha256=${info.sha256} to ${dest}`);
        onEvent?.({event:'file_saved',session:info.id.toString(16),sizeBytes:bytes.length,sha256:info.sha256,path:dest});
        if (shouldSubmit) {
          // Submission deliberately does not block transport ACK; separately logged.
          setImmediate(() => submitSignedCbor(bytes, {endpoint:submitUrl, projectId, allowLocalHttp:args.includes('--allow-local-http')})
            .then(result => console.log(`SUBMIT HTTP ${result.httpStatus}: ${result.response}`))
            .catch(err => console.error(`SUBMIT FAILED: ${err.message}`)));
        }
      });
      console.log(`Listening at ${baud} bit/s. Saving recovered bytes to ${dir}. Blockchain submit: ${shouldSubmit?'ENABLED':'DISABLED'}`);
      await receiveLoop(port, receiver, {signal:controller.signal, onStatus:console.log, onEvent});
    }
  } finally { port.close(); }
}
main().catch(err => {console.error(`ERROR: ${err.message}`); process.exitCode = 1;});
