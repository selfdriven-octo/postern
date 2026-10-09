# Phone FSK prototype — binary data over audio

A working, **dependency-free Node.js** proof of concept for moving bytes across an audio link.
It is **not** TELRPC's proprietary protocol, is **not** a full Bell 202 modem, and is **not** a blockchain wallet or transaction submitter.

**Use case:** Construct and *sign* a transaction offline; transmit the already signed CBOR bytes through an audio channel; decode and verify the bytes at a gateway, where separate software can submit them to a blockchain.

## Requirements

- Node.js 18+; no `npm install` necessary.
- For a microphone/phone recording, a WAV file (mono/stereo, PCM16 or float32, sample rate 8–96 kHz).
- Optional `ffmpeg` to convert phone audio recordings from M4A/MP3 to WAV.

## Run a local loopback demonstration

```sh
node modem.js encode --in examples/hello.txt --out outgoing.wav --baud 200 --repeat 2
node modem.js decode --in outgoing.wav --out recovered.txt
cmp examples/hello.txt recovered.txt
npm test
```

Play the generated `outgoing.wav` on macOS:

```sh
afplay outgoing.wav
```

The decoder prints `CRC32 VALID`, number of recovered bytes, bit rate, and SHA-256 digest.
If the input WAV contains multiple transmissions, the decoder searches for a valid one.

## Transport an already-signed Cardano transaction

If a Cardano wallet has already built and signed a valid **complete transaction CBOR** file (not just the transaction body), the modem can transport its bytes *unchanged*:

```sh
node modem.js encode --in signed.tx.cbor --out tx.wav --baud 100 --repeat 3
node modem.js decode --in received.wav --out recovered.tx.cbor
shasum -a 256 signed.tx.cbor recovered.tx.cbor
```

The SHA-256 digests should match. SHA-256 here is only a **file integrity comparison**; a Cardano transaction ID is derived differently from its transaction body. The gateway still needs to validate the transaction and hand it to a trusted submit API/node. This prototype neither checks Cardano signatures nor submits anything to the network.

**NEVER pass seed phrases or private keys as payload.** The audio channel is not encrypted; anyone nearby or on the call may record it.

## Testing across an actual telephone voice call

1. Use a **short** payload (20–60 bytes) for the first test.
2. Encode at 100 bits/sec with `--repeat 3`.
3. Play `outgoing.wav` into one end of a live telephone voice call (ideally via a direct audio adapter rather than an acoustic speaker/mic).
4. Record the audio reaching the other end. Record lawfulness and consent requirements vary by jurisdiction: obtain any required consent.
5. If recorded as `.m4a`, convert it:

   ```sh
   ffmpeg -i received.m4a -ac 1 -ar 8000 -c:a pcm_s16le received.wav
   ```

6. Decode:

   ```sh
   node modem.js decode --in received.wav --out result.bin
   ```

**Known caveat:** modern cellular voice codecs, echo cancellation, gain control, audio compression, network jitter, and voice activity detection can *destroy non-speech tones*. Passing local WAV roundtrips does not show that a real phone call will work. A more resilient production approach would require calibration, forward error correction, adaptive timing recovery, signal classification, interleaving and extensive phone-network tests.

### Speeds

| Payload size | 100 bit/s, 1 repeat | 200 bit/s, 1 repeat |
| --- | --- | --- |
| 32 bytes | approx. 5.4 s | approx. 3.0 s |
| 256 bytes | approx. 23.3 s | approx. 12.0 s |
| 1,024 bytes | approx. 84.8 s | approx. 42.7 s |

Timing includes the 28-byte framing overhead and 0.6 seconds of leading/trailing silence. Each extra repeat adds the frame's transmission time plus a 0.35-second gap. Max payload is 4,096 bytes; for noisy calls, consider a short-packet, acknowledgement-based protocol rather than large individual frames.

## Implementation overview

- **Physical:** binary FSK, 1 => 1,200 Hz; 0 => 2,200 Hz, constant phase across bits, 8 kHz PCM.
- **Bit rates:** 100 or 200 bits/sec, MSB-first.
- **Framing:** 16 × `0x55`, four-byte sync word, one-byte version, one-byte reserved flags, two-byte big-endian payload length, payload, four-byte CRC32.
- **Receiver:** Goertzel energy detector across candidate bit alignments, sync/preamble scan, length and CRC validation.
- **Integrity:** CRC32 rejects accidental audio corruption. The SHA-256 value in CLI output is not an authenticator. Use cryptographic signatures and authenticated gateway responses for end-to-end security.
- **Reliability:** repeat an entire frame 1–5 times. No FEC or acknowledgements in v0.1.

See `FORMAT.md` for the wire format.

## Next engineering steps

1. A full-duplex ACK/NACK control channel and 32–64-byte chunk framing (retransmit only damaged chunks).
2. Interleaved forward error correction and clock-drift tracking.
3. Lab validation through a real cellular call, VoLTE/VoNR, and G.711/A-law/µ-law gateways.
4. Strong replay protection, gateway authentication and transaction-state freshness.
5. A Cardano-specific adapter that submits a validated, signed transaction using an explicitly configured node/provider.

## Security and scope

Audio transport is **not air-gapping** in the strict sense. It is a different communication path. The chain can still be internet-connected at the gateway, even when the sender has no data connection. The receiver should treat all received bytes as untrusted and enforce size limits, submitter policy, cryptographic verification, and transaction replay/idempotency rules.

License: MIT.
