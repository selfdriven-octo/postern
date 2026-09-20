# Postern

A small door in a thick wall: one UDP port, a Noise handshake that only enrolled
keys can complete, and a narrow set of named operations behind it. Everyone else
gets silence.

Two goals, and every change preserves both:

1. **Minimise what is reachable before authentication** — one size check, one
   rate-limited handshake, nothing else.
2. **Minimise what is permitted after authentication** — each key gets named
   operations and nothing more.

Postern is a strong minimal design, **not** a proven "most resistant" protocol.
Resistance depends on how much code an attacker can reach, how keys are
protected, and what an authenticated peer is allowed to do.

---

## What this is not

This is not WireGuard, and it does not reimplement it. The handshake comes from
[`noise-handshake`](https://www.npmjs.com/package/noise-handshake) and the
primitives from libsodium. This repository contributes the framing, the session
and replay handling, the pre-authentication guard, the enrolment model and the
narrow application — not cryptography.

Protocol: `Noise_IK_25519_ChaChaPoly_BLAKE2b`. That is WireGuard's IK pattern
*family*; WireGuard itself uses `IKpsk2` with BLAKE2s and is not wire-compatible.

Where kernel WireGuard is available and appropriate, prefer it for the tunnel and
run this project's narrow application (`src/app.js`) behind it. Use Postern where
you cannot run kernel WireGuard, or where the channel must terminate at the
actual receiving application rather than at a gateway.

---

## Install

```bash
npm install
npm test          # channel suite: 13 checks
npm run test:mesh # mesh suite: 26 checks
```

Node 18+. One runtime dependency.

---

## Two modes

### Client–server

One node binds a port and answers; the others call it.

```bash
node src/enroll.js keygen server.key.json
node src/enroll.js keygen alice.key.json
node src/enroll.js add peers.json $(node src/enroll.js pub alice.key.json) ping,status

MNC_PORT=51820 node src/server.js
```

```js
const { request } = require('./src/client')
const { loadIdentity } = require('./src/keys')

const r = await request({
  identity: loadIdentity('alice.key.json'),
  responderStaticPub: Buffer.from(require('./server.key.json').publicKey, 'hex'),
  host: '203.0.113.1', port: 51820,
  op: 'ping', args: {}
})
// { ok: true, id: 'r1', result: { pong: true } }
```

### Peer-to-peer mesh

Every node answers *and* calls on one socket. No hub, no directory, no authority.
See **[MESH.md](MESH.md)** for the full runbook — it is written for a team of
about eight.

```bash
node src/roster-cli.js init roster.json
node src/roster-cli.js add-device roster.json ana ana-laptop <pubhex> \
  --addr 203.0.113.7:51820 --ops ping,status,roster
node src/roster-cli.js list roster.json

POSTERN_KEY=ana.key.json POSTERN_ROSTER=roster.json POSTERN_PORT=51820 node src/peer.js
```

`kill -HUP <pid>` re-reads the roster, so a revocation takes effect without a
restart.

---

## Layout

```
src/keys.js        identity keypairs (0600) and the flat peer registry
src/replay.js      sliding anti-replay window (2048)
src/guard.js       datagram cap, source allowlist, per-source handshake limiter
src/channel.js     Responder / Initiator / Session — framing, Noise_IK, transport AEAD
src/app.js         the narrow application: strict schema, fixed handler table, per-peer ops
src/server.js      client-server: binds one port, wires guard -> channel -> app
src/client.js      client-server: one request, one authenticated reply
src/enroll.js      CLI: keygen | pub | add | revoke | list
src/roster.js      mesh: people -> devices -> grants, fingerprint, addresses
src/node.js        mesh: one socket, both roles, merged sessions, keep-alives
src/peer.js        mesh: runs one node; SIGHUP re-reads the roster
src/roster-cli.js  mesh CLI: init | add-device | revoke | grant | addr | list | fingerprint
test.js            channel suite
test-mesh.js       mesh suite
site/              postern.network — single-page site and its manifest
SKILL.md           instructions for an agent working on this repository
```

---

## Protocol

| Item | Value |
|---|---|
| Transport | UDP over IP. Default port `51820` — also WireGuard's default, so choose another if both run on one host. |
| Handshake | `Noise_IK_25519_ChaChaPoly_BLAKE2b` |
| Transport AEAD | ChaCha20-Poly1305. A 64-bit counter travels on the wire; the AEAD nonce is 32-bit, so re-handshake before `2^32 − 2` messages. |
| Anti-replay | Sliding window of 2048, checked **after** AEAD verification |
| Session idle TTL | 180 s |
| Keep-alive (mesh) | 25 s, under the usual ~30 s NAT UDP binding |

```
0x01 INIT       [type][initIdx:4][noise msg1]
0x02 RESP       [type][initIdx:4][respIdx:4][noise msg2]
0x03 TRANSPORT  [type][receiverIdx:4][counter:8 BE][ciphertext + tag]
```

Order on receipt — everything before step 4 is unauthenticated:

1. Drop if the datagram is over 1500 bytes or the source is not allowlisted.
2. `INIT` only: per-source token bucket (burst 5, 1/s). Drop if empty.
3. Run the Noise handshake. Drop if malformed.
4. **Enrolment gate:** drop unless the recovered static key is enrolled, live,
   and from an allowed address.
5. `TRANSPORT`: AEAD-open, check the replay window, re-check enrolment.
6. Hand the plaintext to the application with that peer's grants.

---

## The application

```
request  { "op": "<name>", "id": "<1-64 chars>", "args": { ... } }
success  { "ok": true,  "id": "...", "result": { ... } }
failure  { "ok": false, "id": "...", "error": { "code": "...", "message": "..." } }
```

Bounds: 1024-byte plaintext, 64-character `id`, 512 bytes of serialised `args`.
Reference operations: `ping`, `status`, `roster`, `echo`.

To add one: write a function in the fixed `HANDLERS` table in `src/app.js`,
validate every argument explicitly, keep the reply inside the cap, grant it per
peer, and test both the operation and a peer *without* the grant receiving
`forbidden`. Never `eval`, spawn, or build a path or shell command from input.

---

## Rules that are easy to get wrong

- **Never add a public registration path.** Keys are enrolled out of band, by a
  person, through a channel already trusted.
- **Never reply to unauthenticated traffic.** No error, no banner, no version
  string. There must be nothing to grep.
- **Never read, print, log or commit a secret key.** `*.key.json` holds private
  keys at mode `0600` and is in `.gitignore`. Only public keys travel.
- **Simultaneous open (mesh).** If both peers dial at once, both handshakes
  succeed and each side holds two sessions. Both sides discard the same one with
  no negotiation: keep the session whose **initiator holds the higher static
  public key**.
- **A restart beats that rule.** The key rule applies only within 1500 ms. A
  later handshake is a peer that restarted, and the **new session must win**, or
  the pair deadlocks until the TTL.
- **Authenticated is not authorised.** Postern decides *who* is speaking.
  Whether an action is safe is a separate decision above the channel — and an AI
  peer acting on a request needs its own authorisation layer.

---

## Limits, stated plainly

- **A stolen key.** A compromised enrolled device crosses the boundary like any
  legitimate one. Protect keys at rest, revoke quickly, keep grants small.
- **Availability.** Encryption cannot stop someone flooding your link. That needs
  upstream protection and, where it matters, independent connectivity.
- **The message.** An authenticated packet can still ask for something harmful.
- **Revocation in a mesh has no authority behind it.** It takes effect per node,
  as each node updates. A node holding a stale roster still trusts a revoked key.
  The mesh suite asserts this deliberately; the `roster` operation exists so two
  peers can compare fingerprints and make a disagreement visible.
