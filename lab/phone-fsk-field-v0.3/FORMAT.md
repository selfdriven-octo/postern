# Phone FSK v0.1 — educational framing format

This format is invented solely for this prototype and must not be confused with Bell 202, V.21, V.23 or TELRPC itself.

Audio:

- mono 8,000 PCM samples/sec; 16-bit signed WAV output
- 100 or 200 bits/sec, respectively 80 or 40 samples/bit
- phase-continuous 2-FSK; nominal 1 = 1,200 Hz, 0 = 2,200 Hz
- most-significant bit of each byte first
- each frame has a ~5ms fade at both edges, with 300ms silence before the first frame, 350ms between repeats, 300ms after the final frame

Frame:

| Field | Length | Contents |
| --- | ---: | --- |
| Preamble | 16 bytes | `55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55` |
| Sync | 4 bytes | `D3 91 C5 A7` |
| Version | 1 byte | `01` |
| Flags | 1 byte | `00` (reserved) |
| Length | 2 bytes | unsigned big endian payload length, <= 4,096 |
| Payload | 0 to 4,096 bytes | raw byte array |
| CRC32 | 4 bytes | IEEE reflected CRC32 of Version + Flags + Length + Payload; stored unsigned big-endian |

A successful receiver must verify version, flags, payload length and CRC. The CRC isn't a cryptographic message authentication code. A real production protocol must separately authenticate the sender and the gateway response and bind transactions to nonces/replay control.

## Extension v0.2 — stop-and-wait binary link packets

Each v0.2 packet is sent as the **payload** of one v0.1 audio modem frame above. The v0.1 modem frame's 4,096-byte limit remains unchanged; this extension deliberately uses much smaller payloads to recover from errors faster.

| Field | Bytes | Content |
| --- | ---: | --- |
| Magic | 4 | ASCII `PFA2` |
| Version | 1 | `01` |
| Type | 1 | `01` START, `02` DATA, `03` ACK |
| Session ID | 4 | Random unsigned uint32, big-endian |
| Sequence | 2 | uint16, big-endian (`0`=START, `1..N`=DATA) |
| Total chunks | 2 | uint16, big-endian |
| Packet data | 0–48 | Binary bytes (type dependent) |
| CRC32 | 4 | IEEE CRC32 of all preceding link packet bytes, big-endian |

**START data** (36 bytes): total message length (`uint32`) and SHA-256 of the complete transferred bytes (32 bytes).

**DATA:** Up to 48 bytes, non-final chunks always exactly 48 bytes. Receiver permits only the next in-order sequence. An accepted duplicate is ACKed without being committed again.

**ACK:** No data, same session ID, sequence and total chunk count as the accepted packet.

The receiver verifies the complete payload SHA-256 **before** acknowledging the final DATA packet. Saving happens before ACK. Optional Cardano submission is asynchronous after saving, so its status is not included in the ACK. This is a deliberately simple ARQ prototype; no secure identity proof, cryptographic authentication, authenticated channel receipt, sequence-age expiry, encryption, or forward-error correction is included.

## v0.3 field-beacon payload (one-way test only)

This is **not** the ARQ packet protocol. Each test beacon is exactly 16 bytes
inside the v0.1 FSK frame (which already provides CRC32):

| Byte offset | Size | Meaning |
|---|---:|---|
| 0 | 4 | ASCII `FST3` |
| 4 | 4 | Random run ID |
| 8 | 2 | Sequence number (big-endian, zero based) |
| 10 | 2 | Number of test frames |
| 12 | 4 | Random nonce unique to the beacon |

A manifest records all expected exact payloads and SHA-256 of the generated WAV.
The offline scanner deduplicates nearby successful timing phases. It records
**complete, CRC-verified frame delivery**. It is NOT a raw BER analyser.
