'use strict'
// A Postern node: one UDP socket that both answers and calls.
//
// The split Responder/Initiator in channel.js is client-server by shape. A mesh
// peer must do both on one port, so this module keeps a single session table
// and demultiplexes on the first byte:
//
//   0x01 INIT       -> someone is calling us     (responder path)
//   0x02 RESP       -> our call was answered     (initiator path)
//   0x03 TRANSPORT  -> traffic on a live session (either)
//
// Everything the server does before authentication still happens here in the
// same order: size cap, source allowlist, per-source handshake rate limit,
// Noise, then the enrolment gate.

const dgram = require('dgram')
const crypto = require('crypto')
const Noise = require('noise-handshake')
const { Session, T_INIT, T_RESP, T_DATA, PROLOGUE } = require('./channel')
const { Guard } = require('./guard')
const app = require('./app')

const HANDSHAKE_TIMEOUT = 5000
const KEEPALIVE_MS = 25000        // under the usual ~30s NAT UDP binding
const SESSION_TTL = 3 * 60 * 1000
const REQUEST_TIMEOUT = 8000
// Two handshakes that land inside this window are treated as a genuine race
// (both peers dialled at once) and resolved by the deterministic key rule.
// Anything later is a peer that restarted or lost its table, and the NEW
// session must win — otherwise the pair deadlocks until the session TTL.
const RACE_WINDOW_MS = 1500

function u32 () { return crypto.randomBytes(4).readUInt32BE(0) }
function toHex (b) { return Buffer.from(b).toString('hex') }

class Node {
  constructor ({ identity, roster, port = 0, host = '0.0.0.0', guard, onMessage } = {}) {
    this.identity = identity
    this.selfPub = toHex(identity.publicKey)
    this.roster = roster
    this.port = port
    this.host = host
    this.guard = guard || new Guard({ maxPacket: 1500, hsCapacity: 5, hsPerSec: 1 })
    this.onMessage = onMessage || null

    this.sessions = new Map()   // localIdx      -> Session
    this.byPeer = new Map()     // peerPub       -> Session (the live one)
    this.pending = new Map()    // localIdx      -> { hs, peerPub, addr, at }
    this.outbox = new Map()     // peerPub       -> [Buffer] awaiting a session
    this.requests = new Map()   // requestId     -> { resolve, reject, timer }
    this.sock = null
    this._timers = []
  }

  // ---------------------------------------------------------------- lifecycle

  start () {
    return new Promise((resolve) => {
      this.sock = dgram.createSocket({ type: 'udp4', recvBufferSize: 1 << 20 })
      this.sock.on('message', (buf, rinfo) => this._onDatagram(buf, rinfo))
      this.sock.on('error', () => {})
      this.sock.bind(this.port, this.host, () => {
        this.port = this.sock.address().port
        this._timers.push(setInterval(() => this._keepalive(), KEEPALIVE_MS))
        this._timers.push(setInterval(() => this._sweep(), 30000))
        for (const t of this._timers) if (t.unref) t.unref()
        resolve(this)
      })
    })
  }

  stop () {
    for (const t of this._timers) clearInterval(t)
    this._timers = []
    for (const r of this.requests.values()) { clearTimeout(r.timer); r.reject(new Error('node stopped')) }
    this.requests.clear()
    this.guard.stop()
    try { this.sock.close() } catch {}
  }

  // ------------------------------------------------------------------ dialling

  // Open a channel to an enrolled peer. Safe to call repeatedly.
  connect (peerPub) {
    peerPub = String(peerPub).toLowerCase()
    if (this.byPeer.has(peerPub)) return true
    if (!this.roster.authorisedPeer(peerPub)) return false
    for (const p of this.pending.values()) if (p.peerPub === peerPub) return true

    const addr = this.roster.addressOf(peerPub)
    if (!addr) return false // no address: we can only wait to be called

    const hs = new Noise('IK', true, this.identity)
    hs.initialise(PROLOGUE, Buffer.from(peerPub, 'hex'))
    const localIdx = this._freshIdx()
    const head = Buffer.alloc(5)
    head.writeUInt8(T_INIT, 0)
    head.writeUInt32BE(localIdx, 1)
    const pkt = Buffer.concat([head, hs.send()])

    this.pending.set(localIdx, { hs, peerPub, addr, at: Date.now() })
    this.sock.send(pkt, addr.port, addr.address)
    return true
  }

  // Send one authenticated message. Queued if the channel is still opening.
  send (peerPub, plaintext) {
    peerPub = String(peerPub).toLowerCase()
    const s = this.byPeer.get(peerPub)
    if (s) return this._sealTo(s, plaintext)
    if (!this.connect(peerPub)) return false
    const q = this.outbox.get(peerPub) || []
    q.push(plaintext)
    this.outbox.set(peerPub, q)
    return true
  }

  // Send a request and wait for the matching reply.
  request (peerPub, op, args = {}, timeoutMs = REQUEST_TIMEOUT) {
    return new Promise((resolve, reject) => {
      const id = crypto.randomBytes(8).toString('hex')
      const timer = setTimeout(() => { this.requests.delete(id); reject(new Error('timeout')) }, timeoutMs)
      this.requests.set(id, { resolve, reject, timer })
      if (!this.send(peerPub, Buffer.from(JSON.stringify({ op, id, args }), 'utf8'))) {
        clearTimeout(timer); this.requests.delete(id)
        reject(new Error('no route to peer'))
      }
    })
  }

  // --------------------------------------------------------------- datagrams

  _onDatagram (buf, rinfo) {
    if (!this.guard.admit(rinfo.address, buf.length)) return
    if (buf.length < 1) return
    if (buf[0] === T_INIT) return this._onInit(buf, rinfo)
    if (buf[0] === T_RESP) return this._onResp(buf, rinfo)
    if (buf[0] === T_DATA) return this._onData(buf, rinfo)
  }

  _onInit (buf, rinfo) {
    if (buf.length < 5) return
    if (!this.guard.allowHandshake(rinfo.address)) return

    const remoteIdx = buf.readUInt32BE(1)
    const hs = new Noise('IK', false, this.identity)
    hs.initialise(PROLOGUE)
    try { hs.recv(buf.subarray(5)) } catch { return }
    if (!hs.rs) return

    // the enrolment gate
    const peerPub = toHex(hs.rs)
    if (!this.roster.authorisedPeer(peerPub)) return
    if (!this.roster.ipAllowed(peerPub, rinfo.address)) return

    let msg2
    try { msg2 = hs.send() } catch { return }
    if (!hs.complete) return

    const localIdx = this._freshIdx()
    const s = new Session({
      localIdx, remoteIdx, peerPub,
      txKey: hs.tx, rxKey: hs.rx,
      addr: { address: rinfo.address, port: rinfo.port }
    })
    s.initiatedByUs = false
    s.createdAt = Date.now()

    const head = Buffer.alloc(9)
    head.writeUInt8(T_RESP, 0)
    head.writeUInt32BE(remoteIdx, 1)
    head.writeUInt32BE(localIdx, 5)
    this.sock.send(Buffer.concat([head, msg2]), rinfo.port, rinfo.address)

    this._install(s)
  }

  _onResp (buf, rinfo) {
    if (buf.length < 9) return
    const localIdx = buf.readUInt32BE(1)
    const p = this.pending.get(localIdx)
    if (!p) return
    const remoteIdx = buf.readUInt32BE(5)
    try { p.hs.recv(buf.subarray(9)) } catch { return }
    if (!p.hs.complete) return
    this.pending.delete(localIdx)

    const s = new Session({
      localIdx, remoteIdx, peerPub: p.peerPub,
      txKey: p.hs.tx, rxKey: p.hs.rx,
      addr: { address: rinfo.address, port: rinfo.port }
    })
    s.initiatedByUs = true
    s.createdAt = Date.now()
    this._install(s)
  }

  _onData (buf, rinfo) {
    if (buf.length < 13) return
    const s = this.sessions.get(buf.readUInt32BE(1))
    if (!s) return
    const counter = Number(buf.readBigUInt64BE(5))
    const pt = s.open(counter, buf.subarray(13))
    if (pt === null) return
    // revocation takes effect on the next packet
    if (!this.roster.authorisedPeer(s.peerPub)) { this._drop(s); return }
    s.addr = { address: rinfo.address, port: rinfo.port } // roaming, post-auth only
    if (pt.length === 0) return // keep-alive

    let obj = null
    try { obj = JSON.parse(pt.toString('utf8')) } catch {}

    // a reply to something we asked
    if (obj && typeof obj.ok === 'boolean' && obj.id && this.requests.has(obj.id)) {
      const r = this.requests.get(obj.id)
      this.requests.delete(obj.id)
      clearTimeout(r.timer)
      r.resolve(obj)
      return
    }

    if (this.onMessage) this.onMessage(pt, s.peerPub, this)

    // otherwise it is a request for us: answer under this peer's grants
    const reply = app.handle(pt, s.peerPub, this.roster.allowedOps(s.peerPub), { roster: this.roster })
    if (reply) this._sealTo(s, reply)
  }

  // -------------------------------------------------------- session bookkeeping

  // Simultaneous open: if both peers dial at once, both handshakes succeed and
  // each side ends up holding two sessions. Both sides must discard the SAME
  // one without talking about it, so the rule is purely local and deterministic:
  // keep the session whose INITIATOR holds the higher static public key.
  _install (fresh) {
    const existing = this.byPeer.get(fresh.peerPub)
    if (!existing) {
      this.sessions.set(fresh.localIdx, fresh)
      this.byPeer.set(fresh.peerPub, fresh)
      this._flush(fresh.peerPub)
      return fresh
    }
    const concurrent = (Date.now() - (existing.createdAt || 0)) < RACE_WINDOW_MS
    const winner = concurrent ? this._preferred(existing, fresh) : fresh
    if (winner === fresh) {
      this.sessions.delete(existing.localIdx)
      this.sessions.set(fresh.localIdx, fresh)
      this.byPeer.set(fresh.peerPub, fresh)
    }
    // the loser is simply never installed; anything already sent on it is lost
    // and resent by the caller's retry, exactly as for a dropped datagram
    this._flush(fresh.peerPub)
    return winner
  }

  _preferred (a, b) {
    const initiatorOf = (s) => (s.initiatedByUs ? this.selfPub : s.peerPub)
    return initiatorOf(a) >= initiatorOf(b) ? a : b
  }

  _flush (peerPub) {
    const q = this.outbox.get(peerPub)
    if (!q || !q.length) return
    const s = this.byPeer.get(peerPub)
    if (!s) return
    this.outbox.delete(peerPub)
    for (const pt of q) this._sealTo(s, pt)
  }

  _sealTo (session, plaintext) {
    const pkt = session.seal(plaintext)
    if (pkt === null) { this._drop(session); return false } // counter exhausted
    this.sock.send(pkt, session.addr.port, session.addr.address)
    return true
  }

  _drop (session) {
    this.sessions.delete(session.localIdx)
    if (this.byPeer.get(session.peerPub) === session) this.byPeer.delete(session.peerPub)
  }

  _freshIdx () {
    let i
    do { i = u32() } while (this.sessions.has(i) || this.pending.has(i))
    return i
  }

  _keepalive () {
    const empty = Buffer.alloc(0)
    for (const s of this.byPeer.values()) this._sealTo(s, empty)
  }

  _sweep () {
    const now = Date.now()
    for (const s of [...this.sessions.values()]) {
      if (now - s.touched > SESSION_TTL) this._drop(s)
    }
    for (const [idx, p] of [...this.pending]) {
      if (now - p.at > HANDSHAKE_TIMEOUT) this.pending.delete(idx)
    }
  }

  // ------------------------------------------------------------------ helpers

  get openPeers () { return [...this.byPeer.keys()] }

  // Open a channel to every live peer in the roster that we have an address for.
  connectAll () {
    let n = 0
    for (const p of this.roster.peersOf(this.selfPub)) if (this.connect(p.pub)) n++
    return n
  }
}

module.exports = { Node }
