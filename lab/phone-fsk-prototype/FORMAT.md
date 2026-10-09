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
