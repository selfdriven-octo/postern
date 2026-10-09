# Phone FSK v0.3 — live audio data link + optional Cardano gateway

This is an **independent educational prototype**, not TELRPC, a standards-compliant Bell 202 modem, a cryptocurrency wallet, or a production-secure transport. It sends arbitrary binary data via audible telephone-style FSK and includes **two-way stop-and-wait acknowledgements, chunk retransmission, microphone/speaker input/output and an optional Cardano CBOR submit adapter**.

- FSK frequencies: **1,200 Hz (bit 1)** and **2,200 Hz (bit 0)**.
- Rates: **100 or 200 bits/sec**, one modem audio frame per control/data packet.
- Chunks: 48 bytes; max total transfer 16 KiB.
- Checks: modem CRC32, link packet CRC32, and whole-file SHA-256.
- Real audio is through **SoX**, called as an external program. JS uses only Node.js built-ins; no npm dependencies.
- **No actual phone call was available for testing here.** Local audio/software simulated tests pass. Real VoLTE, codec, audio adapter and device compatibility are unknown.

## New in v0.3 — real-phone field-test tooling

A new **one-way audio field test** lets you generate numbered FSK frames, record a real cellular call, and evaluate delivery with CRC verification. It also adds optional JSONL event logs and a sender JSON summary for two-way ACK/retry sessions. The project has **not** tested a real phone call; these are tools to measure one on your equipment.

```sh
node field.js generate --baud 100 --count 6 --out test-100.wav --manifest test-100.json
# Call between two phones, play test-100.wav to the sending phone mic, record the receiving phone speaker:
node field.js record --out call-100.wav --seconds 75
node field.js analyze --in call-100.wav --manifest test-100.json --out report-100.json
# Repeat at 200 baud; compare reports:
node field.js compare --reports report-100.json,report-200.json --out comparison.md
```

**Start with `FIELD-TEST.md`** for the device setup and controlled test procedure. The sample files in `examples/` are *synthetic clean-loopback reference data*, not phone-call measurements.

## Requirements

- Node.js 18+ (Node 22 recommended).
- For live microphone/speaker I/O, install SoX. On a Mac: `brew install sox`.
- Allow microphone permission to Terminal on macOS if prompted (System Settings → Privacy & Security → Microphone).
- A pair of devices/computers connected through an audio path, ideally with direct audio adapters. Use two Macs to start, then experiment through a phone call. You will likely need audio routing interfaces to prevent feedback. This is **not a native iPhone app**.
- For offline audio-only demonstration, SoX is not required.

## 1. Quick local test (no equipment)

```sh
cd phone-fsk-prototype
npm test
node modem.js encode --in examples/hello.txt --out outgoing.wav --baud 200
node modem.js decode --in outgoing.wav --out recovered.txt
cmp examples/hello.txt recovered.txt
```

Audio sample: `demo.wav` (v0.1-style repeat). On macOS: `afplay demo.wav`.

## 2. Live microphone/speaker communication

Start the receiver **first**, on computer B:

```sh
node link.js receive --out-dir ./received --baud 200
```

Then, on computer A:

```sh
node link.js send --in examples/hello.txt --baud 200 --retries 5
```

Both endpoints must use the **same baud**. The sender speaks a START packet followed by data chunks, and waits for an ACK audio packet after each one. It retransmits chunks on timeout. The receiver stores the final complete binary file in `./received/session-....bin` after checking SHA-256. An ACK signifies successful *audio transfer*, not Cardano submission.

Both systems continuously capture their default microphone through SoX, and use their default speaker for output. Route the TX audio at each end to the other endpoint's microphone input through your test link. For a telephone experiment, pass the audio through a **live voice call** and use appropriate phone/headset adapters. Use 100 bit/s when 200 bit/s fails:

```sh
node link.js receive --out-dir ./received --baud 100
node link.js send --in examples/hello.txt --baud 100 --ack-timeout 15000
```

On macOS, watch for microphone privacy permission issues. If SoX exits, the CLI reports its stderr. Run Ctrl+C to stop the receiver.

**Estimated ideal timings at 100 bit/s:** START audio ~7.2 s, a full 48-byte data packet ~8.1 s, an ACK ~4.3 s; at 200 bit/s roughly half the modulated portion of those durations. Real call setup/latency/retries add overhead. This is a *slow* transport, intended for small signed transaction CBOR blobs, not general internet connectivity.

## 3. Optional Cardano **preprod** gateway

Create and sign a *complete* transaction for Cardano **preprod** independently, producing raw signed transaction CBOR bytes (`signed.tx.cbor`). A transaction body or a CLI JSON text envelope is **not** the same as raw complete CBOR; convert appropriately before transferring.

To receive and **only save** the transaction:

```sh
node link.js receive --out-dir ./received --baud 100
```

To explicitly enable network submission on computer B, first set its project ID and then start the receiver:

```sh
export BLOCKFROST_PROJECT_ID='your_preprod_project_id'
node link.js receive --out-dir ./received --baud 100 \
  --submit \
  --submit-url https://cardano-preprod.blockfrost.io/api/v0/tx/submit
```

Then on **computer A**:

```sh
node link.js send --in signed.tx.cbor --baud 100
```

The receiver stores recovered CBOR in `./received`, and *after saving* independently attempts `POST /tx/submit` using `Content-Type: application/cbor` and the `project_id` header. This is the official Blockfrost request contract, and its endpoint is **network-specific**. A successful submit API response does **not** guarantee inclusion/finality; independently check transaction status via a blockchain node/explorer.

For a controlled test with an allowlisted input, computer B can add `--expect-sha256 DIGEST_OF_SIGNED_CBOR`. The command refuses to save or submit any other payload digest. This limits accidental/unwanted submission but is **not a sender authentication mechanism**.

Gateway safety defaults:

- No network submission unless `--submit` is explicitly present.
- Requires HTTPS (plain HTTP accepted only with `--allow-local-http` pointing to localhost for local tests).
- No keys or signing inside this project. Never transmit seed phrases/private keys.
- The received payload is **untrusted**. The code does not inspect CBOR, verify signatures itself, check UTxO freshness, guarantee chain inclusion, or authenticate the calling party.
- Before a real deployment, add sender authentication, encrypted authenticated responses, policy checks, durable anti-replay, and rate limiting.
- Keep an actual receiving service protected; anyone able to feed its microphone could send it data.

## 4. Structure

| File | Function |
|---|---|
| `lib.js` | FSK modulation, WAV I/O, Goertzel receiver, modem CRC32 |
| `modem.js` | v0.1 compatible offline encode/decode/inspect commands |
| `protocol.js` | START/DATA/ACK chunks, retransmission, SHA-256 assembly |
| `audio.js` | SoX microphone stream, bounded scanning buffer, speaker playback |
| `link.js` | Sender and receiver CLI for a live two-way audio link |
| `cardano.js` | Explicit signed CBOR HTTP submission (network/provider configured by user) |
| `FORMAT.md` | Both binary framing definitions |
| `field.js` | Generate, record, decode and compare one-way field trials |
| `FIELD-TEST.md` | Practical mobile-call testing procedure |
| `test/` | Modem, protocol, live-stream scanning, lost frame and HTTP gateway tests |

## Limitations

- Real mobile calls have speech codecs, voice-activity detection, echo suppression, packet loss, resampling, clock skew and automatic gain control. A traditional two-tone modem can fail badly. No adaptive symbol timing, forward error correction, or verified over-the-air phone call tests are implemented here.
- **ACKs are not authenticated.** An attacker injecting audio can spoof them. File SHA-256 is not a MAC; CRCs are not authentication. Protect trusted endpoints and do not confuse transport ACK with authenticated blockchain status.
- Only one in-order chunk is in flight. Long transfers are slow. When there is a dropped final ACK, keep the receiver running to ACK duplicates.
- Session replay/cache is memory-only, limited to 16 sessions until restart. File output uses exclusive create to avoid silent overwrites.
- The example uses the default SoX input/output devices; it has no UI for selecting sound cards or changing codec settings, and cannot control phone call audio routing.

No connection to the phone line or blockchain is needed for the automated tests. See `FORMAT.md` for exact structure and `test/link.test.js` for the simulated two-way session.

MIT License.

### Optional G.711 codec simulation

```sh
sh scripts/codec-smoke.sh
```

This synthesises and roundtrips a WAV frame through both G.711 µ-law and A-law companding with SoX, then checks the decoded payload. This **does not** simulate a mobile speech codec, packet loss, jitter, acoustic coupling, or an end-to-end telephone call.
