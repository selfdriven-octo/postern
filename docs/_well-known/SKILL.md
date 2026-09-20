---
name: postern
description: Work on Postern — the mutually authenticated, encrypted Noise_IK-over-UDP channel between explicitly enrolled devices (github.com/selfdriven-octo/postern) and its site postern.network. Use when enrolling or revoking peers, running the responder, adding or granting operations, changing the wire protocol or limits, integrating an agent with Postern, or editing postern.network or its agent.json.
---

# Postern

Postern is a small door in a thick wall: one UDP port, a Noise handshake that only enrolled keys can complete, and a narrow set of named operations behind it. Everyone else gets silence.

The design has two goals, and every change must preserve both:

1. **Minimise what is reachable before authentication** — one size check, one rate-limited handshake, nothing else.
2. **Minimise what is permitted after authentication** — each key gets named operations and nothing more.

Postern is a strong minimal design, not a proven "most resistant" protocol. Say that plainly wherever it is described.

---

## Non-negotiable invariants

An agent working on Postern must never:

- **Add a public registration path.** No sign-up endpoint, no password login, no self-service enrolment. Keys are enrolled out of band, by a person, through a channel they already trust.
- **Reply to unauthenticated traffic.** Unknown keys, malformed packets, oversize datagrams, rate-limited handshakes and replays are dropped silently: no error, no banner, no version string.
- **Implement cryptography by hand.** The handshake comes from `noise-handshake`; the primitives come from libsodium. Change framing and policy, not crypto.
- **Read, print, log or commit a secret key.** `*.key.json` holds private keys (mode `0600`) and stays out of git, chat, tickets and logs. Only public keys move between parties.
- **Let a handler act on attacker-controlled structure.** No `eval`, no `Function`, no `child_process`, no filesystem path or shell built from request data, no dynamic dispatch beyond the fixed handler table.
- **Treat an authenticated message as an authorised action.** Postern establishes *who* is speaking. Whether a requested action is safe is a separate decision that sits above the channel, and an AI receiver needs its own action-authorisation layer.
- **Weaken a bound without saying so.** Datagram size, plaintext size, handshake rate and the replay window are security parameters. Change them deliberately, in one place, and record why.

---

## Protocol

| Item | Value |
|---|---|
| Transport | UDP over IP. Default port `51820`, which is also WireGuard's default: pick another port if real WireGuard runs on the same host. |
| Handshake | `Noise_IK_25519_ChaChaPoly_BLAKE2b` via `noise-handshake`. This is WireGuard's IK pattern family; WireGuard itself uses `IKpsk2` with BLAKE2s. |
| Prologue | `mnc/1` in the reference implementation. Both ends must match. |
| Transport AEAD | ChaCha20-Poly1305. An explicit 64-bit counter travels on the wire; the AEAD nonce is 32-bit, so re-handshake before `2^32 − 2` messages. |
| Anti-replay | Sliding window of 2048 counters, checked **after** AEAD verification. |
| Session idle TTL | 180 s |

**Wire format** (the first byte is the type):

```
0x01 INIT       [type][initIdx:4][noise msg1]
0x02 RESP       [type][initIdx:4][respIdx:4][noise msg2]
0x03 TRANSPORT  [type][receiverIdx:4][counter:8 BE][ciphertext + tag]
```

**Processing order on the responder.** Keep this order; everything before step 4 is unauthenticated.

1. Guard: drop if the datagram is over 1500 bytes or the source is not allowlisted.
2. INIT only: per-source token bucket (burst 5, 1/s). Drop if it is empty.
3. Run the Noise handshake. Drop if it is malformed.
4. **Enrolment gate:** drop if the recovered static key is not in the registry, is revoked, or comes from an IP outside that peer's `ips` list.
5. TRANSPORT: AEAD-open, then check the replay window, then re-check enrolment (so revocation takes effect on the next packet).
6. Hand the plaintext to the application with the peer's enrolled `ops`.

The peer's source address is updated for roaming only after step 5 succeeds.

---

## Repository layout (reference implementation)

The repository could not be read when this skill was written, so this layout comes from the reference implementation. **Check it against the repo and correct any path that differs.**

```
src/keys.js      identity keypairs (0600) + Registry: authorisedPeer, allowedOps, ipAllowed, reload
src/replay.js    ReplayWindow (sliding, 2048)
src/guard.js     Guard: datagram cap, source allowlist, per-source handshake token bucket
src/channel.js   Responder / Initiator / Session: framing, Noise_IK, transport AEAD, replay
src/app.js       the narrow application: strict schema, fixed HANDLERS table, per-peer ops
src/server.js    binds one UDP port and wires guard → channel → app
src/client.js    request(): handshake, one request, one authenticated reply
src/enroll.js    CLI: keygen | pub | add | revoke | list
test.js          end-to-end suite: happy path plus every negative case
```

Run `npm test` after every change. All checks must pass, including the negative ones: unenrolled key gets silence, forbidden op, bad op, bad JSON, over-cap plaintext, over-cap datagram dropped silently, replay dropped, revoked key refused, handshake flood rate-limited.

---

## Operating procedures

**Generate identities** (on a trusted machine):

```bash
node src/enroll.js keygen server.key.json
node src/enroll.js keygen alice.key.json
node src/enroll.js pub alice.key.json   # the only part that leaves the machine
```

**Enrol a peer** with the smallest set of operations it needs, and pin its source IP when that IP is stable:

```bash
node src/enroll.js add peers.json <pubhex> ping,status --ip 203.0.113.7
```

**Revoke** a key, then reload the registry (or restart the server). Any live session for that key is dropped on its next packet.

```bash
node src/enroll.js revoke peers.json <pubhex>
```

**Run the responder:**

```bash
MNC_PORT=51820 MNC_ALLOW_IPS=203.0.113.7,203.0.113.8 node src/server.js
```

Each registry entry in `peers.json` has this shape:

```json
{ "pub": "<x25519 public key, hex>", "ops": ["ping", "status"], "ips": [], "revoked": false }
```

---

## The application contract

Requests and replies are JSON inside the encrypted channel.

- **Request:** `{ "op": "<name>", "id": "<1–64 chars>", "args": { … } }`
- **Success:** `{ "ok": true, "id": "…", "result": { … } }`
- **Failure:** `{ "ok": false, "id": "…" | null, "error": { "code": "…", "message": "…" } }`

The limits are a 1024-byte plaintext, an `id` of up to 64 characters, and `args` of up to 512 bytes serialised.

Error codes are `too_large`, `bad_json`, `bad_shape`, `bad_op`, `bad_id`, `bad_args`, `args_too_large`, `forbidden`, `handler_error` and `reply_too_large`.

The reference operations are `ping`, `status` and `echo`.

### Adding an operation

1. Add one function to the fixed `HANDLERS` table in `src/app.js`. It receives validated `args` and `{ peerPub }`, and returns a plain JSON-serialisable object.
2. Validate every argument explicitly: type, length and allowed values. Assume `args` is hostile even from an enrolled peer.
3. Keep the reply bounded under the plaintext cap.
4. Grant the op per peer in `peers.json`. Never grant it to all peers by default.
5. Add a test for the op itself and for a peer *without* the grant receiving `forbidden`.
6. If the op triggers a real-world action, put the action-authorisation check in the handler path, not in the channel.

---

## postern.network

`index.html` is a single self-contained Jekyll page with the front matter `layout: null` and `permalink: "/"`.

**Visual system.** The page is a P1 green-phosphor terminal: one hue, with hierarchy carried by brightness rather than colour.

- **Tokens:** `--bg #020a04`, `--ink #c8ffc8`, `--muted #63c46f`, `--dim #3d7d48`, and accent `--brass #33ff33`. The name `--brass` is historical; it is green.
- **Fonts:** VT323 for body copy (single weight, so emphasis is brightness, never bold or italic). JetBrains Mono for headings, labels, logs and the hex dump. Poppins **only** for the "Supported by the selfdriven.foundation" line.
- **No second hue.** Every element, including the selfdriven link, stays in the green scale.

**Structure.** The page runs in this order:

- a full-viewport masonry doorway hero with a continuous wall and an open, lit arch
- a probe ticker
- the live gate log with a "try the door" button that never gets a reply
- the thesis statement
- two paths (unknown packet vs enrolled peer)
- six properties
- an annotated transport hex dump
- "what it carries"
- three stated limits
- "there is no sign-up"
- a footer

**Links.** A GitHub link sits in the nav (`github ↗`, on the first row next to the wordmark on phones) and in the footer. The selfdriven attribution is text only, with no logo.

**iOS Safari rendering rule.** Do **not** use `position: fixed` full-viewport overlays, `mix-blend-mode` on fixed layers, or `backdrop-filter` on the nav or chips. On a page this long, iOS drops tiles from those composited layers and paints the white canvas through them.

- Put grain and scanlines on `body` as background layers, using an alpha-baked grain PNG.
- Give nav and chips solid backgrounds.
- Set a background on both `html` and `body`.

**Honesty block.** Keep the closing caveat ("A strong minimal design — not a proven 'most resistant' protocol…") and the three limits: a stolen key, your link, and the message.

---

## agent.json

The manifest is served at `/.well-known/agent.json`. Update it whenever any of these change: protocol parameters, limits, operations, error codes, repository or site URLs, or the stated limitations.

Jekyll skips dot-directories, so `_config.yml` must contain:

```yaml
include: [".well-known"]
```

Leave `identity.responderStaticKey` as the placeholder `<responder-x25519-public-key>`. The responder key is distributed to enrolled peers out of band. Never publish a fabricated or test key there as if it were live.

---

## Checklist before delivering a Postern change

- [ ] No registration path, no reply to unauthenticated traffic, no hand-rolled crypto.
- [ ] No secret key read, printed, logged or committed.
- [ ] Guard → rate limit → handshake → enrolment gate → AEAD → replay → re-check enrolment order intact.
- [ ] New ops live in the fixed table, validate every argument, are granted per peer, and have tests.
- [ ] `npm test` passes, including every negative case.
- [ ] Changed bounds, protocol values or ops mirrored into `agent.json` and this skill.
- [ ] Site changes keep the single green hue, the font roles, and the iOS rendering rule.
