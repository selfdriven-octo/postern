# Real mobile voice-call test: Phone FSK v0.3

**Status:** Equipment-independent test kit, **not** a claim of a successful real cellular voice call. You must perform the physical experiment. It is not a TELRPC implementation or certified communications equipment.

## Objective

Determine whether the 1,200/2,200 Hz binary FSK survives an actual phone call. Measure the proportion of 16-byte test frames recovered with a **valid CRC** at 100 and 200 bit/s. Measure ACK timeouts/retransmissions later, once one-way transmission works.

## What you need

- Two smartphones with an active ordinary **voice call**, ideally in separate rooms or locations to avoid acoustic feedback. Disable Bluetooth and hands-free/headset routing unless intentionally part of the test.
- Two computers (Macs are fine), one near each phone, with working speakers and microphones. Use headphones/headset adaptors or a hardware audio interface for a cleaner second experiment.
- Node.js 18+ installed on at least the analysis machine; SoX on the recording Mac (`brew install sox`). You can use macOS `afplay` to play WAV. `field.js generate/analyze` needs only Node built-ins.
- Avoid production blockchain transactions until the communications channel is characterised.

## Phase A: baseline, **no phone call**

On sending Mac A:

```sh
node field.js generate --baud 100 --count 6 --out test-100.wav --manifest test-100.json
```

On receiving Mac B, in the same room, start a microphone recording **before** playing the sample:

```sh
node field.js record --out local-100.wav --seconds 60
```

Play `test-100.wav` using `afplay test-100.wav` on Mac A. Afterwards copy `local-100.wav` from B to A (or move the manifest to B) and analyse:

```sh
node field.js analyze --in local-100.wav --manifest test-100.json --out report-local-100.json
```

A 0% result here means a local audio/recording/volume/timing problem, not a mobile-network failure. Reduce background noise, verify mic permissions, try speaker volume around 30–50%, and place the microphones in a fixed position. The report also shows sample clipping.

## Phase B: through a mobile telephone voice call

```text
Mac A speaker => Phone A microphone
                   |  ongoing cellular voice call
Mac B microphone <= Phone B speaker
```

1. Put phones A and B on a normal voice call. Keep them physically separated (ideally different rooms) to prevent acoustic feedback. Keep voice-call routing consistent.
2. Put Phone A on speakerphone. Position Mac A's speaker near **Phone A's microphone**.
3. Put Phone B on speakerphone. Position Mac B's microphone near **Phone B's speaker**. Avoid playing test audio on Mac B during this one-way test.
4. Start `node field.js record --out call-100.wav --seconds 75` on Mac B.
5. While B is recording, execute `afplay test-100.wav` on Mac A. The supplied `test-100.wav` lasts about 37 seconds. **Don't talk** during test audio.
6. Copy the recorded WAV to the machine with the JSON manifest and run:

```sh
node field.js analyze --in call-100.wav --manifest test-100.json --out report-call-100.json
```

7. Repeat with 200 bit/s:

```sh
node field.js generate --baud 200 --count 6 --out test-200.wav --manifest test-200.json
# Start a new B recording over the ongoing voice call:
node field.js record --out call-200.wav --seconds 60
# Play test-200.wav on Mac A while recording on Mac B.
node field.js analyze --in call-200.wav --manifest test-200.json --out report-call-200.json
node field.js compare --reports report-call-100.json,report-call-200.json --out comparison.md
```

**Important:** This is an acoustic approximation. The placement and mobile OS audio processing will strongly influence results. A clean result would be encouraging, but is not proof of reliable wired, Bluetooth, VoLTE, VoWiFi or PSTN interoperability. A failed result can be due to the codec, echo canceller, automatic gain control, voice activity detection, noisy acoustic coupling, symbol timing drift, or incorrect device routing.

## Phase C: two-way ARQ when Phase B works

For acknowledgements and retries, **both computers need bidirectional audio routes** into and out of their respective phones. Avoid feedback using isolated sound cards / TRRS interfaces or other properly designed send/receive paths. Speakerphone acoustics are unreliable in full-duplex mode. Start the receiver first:

```sh
# B
node link.js receive --out-dir ./received --baud 100 --log-json rx-events.jsonl
# A
node link.js send --in examples/hello.txt --baud 100 --retries 5 --ack-timeout 20000 \
  --log-json tx-events.jsonl --summary-json tx-summary.json
```

`tx-summary.json` contains packet count, attempts, ACK timeouts, retransmissions and elapsed time. `tx-events.jsonl` and `rx-events.jsonl` are one JSON object per event. A timeout **does not prove** that a data packet was lost: the ACK may have been lost or delayed.

**Performance caveat:** Stop-and-wait at 100 bit/s with ~48-byte data chunks is intentionally slow. For any Cardano test, start with harmless data, and **never** play or transmit private keys or recovery phrases. The `--submit` option is OFF by default.

## What to write down for each physical test

- Date/time and call duration; A and B phone models; operator/network where known; voice vs VoLTE/VoWiFi; Bluetooth and speakerphone settings.
- Audio coupling: acoustic, cable/TRRS interface, or USB sound card; distance from speaker to microphone; speaker volume.
- Background noise / echoes / interruptions and whether voice-call muting/silence suppression was apparent.
- Baud rate; number of frames; verified/missing frames; clipping; captured WAV and JSON report.

### Interpretation

- `6/6`: all six *CRC-verified* frames passed through the tested path. It does not establish low bit-error rate or general reliability.
- `0/6`: no valid frames recovered; use local baseline and listen to the recording before blaming the phone codec.
- `5/6`: one or more physical frames were lost/corrupted; cannot infer the precise bit-error rate (BER) from CRC acceptance alone.
- `ACK timeout` in phase C: neither path is individually identified as failing. Track both directions separately.

The captured audio may include voices or private details. Obtain consent when appropriate and don't publish call recordings by default.
