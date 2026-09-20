'use strict'
// The mutually authenticated encrypted channel.
//
//   Handshake: Noise_IK (same pattern family as WireGuard) via noise-handshake.
//              - initiator knows the responder's static key in advance (IK)
//              - responder learns + authenticates the initiator's static key
//              - ephemeral keys per session => forward secrecy
//   Transport: ChaCha20-Poly1305 (from the derived per-direction keys), with an
//              explicit per-session counter carried in the header, checked
//              against a sliding anti-replay window AFTER AEAD verification.
//
// Wire format (first byte = type):
//   0x01 INIT      [type][initIdx:4][noise msg1]
//   0x02 RESP      [type][initIdx:4][respIdx:4][noise msg2]
//   0x03 TRANSPORT [type][receiverIdx:4][counter:8 BE][ciphertext]

const crypto = require('crypto')
const Noise = require('noise-handshake')
const Cipher = require('noise-handshake/cipher')
const { ReplayWindow } = require('./replay')

const T_INIT = 0x01
const T_RESP = 0x02
const T_DATA = 0x03

const EMPTY_AD = Buffer.alloc(0)
const PROLOGUE = Buffer.from('mnc/1') // domain separation; must match both sides
const MAX_COUNTER = 0xffffffff - 1     // AEAD nonce is a 32-bit counter -> rekey before wrap
const SESSION_TTL = 3 * 60 * 1000      // drop idle/half-open sessions

function u32 () { return crypto.randomBytes(4).readUInt32BE(0) }
function toHex (b) { return Buffer.from(b).toString('hex') }

function encodeTransport (receiverIdx, counter, ct) {
  const h = Buffer.alloc(1 + 4 + 8)
  h.writeUInt8(T_DATA, 0)
  h.writeUInt32BE(receiverIdx, 1)
  h.writeBigUInt64BE(BigInt(counter), 5)
  return Buffer.concat([h, ct])
}

// A live, authenticated session (one per handshake).
class Session {
  constructor ({ localIdx, remoteIdx, peerPub, txKey, rxKey, addr }) {
    this.localIdx = localIdx      // index the peer must put in packets to me
    this.remoteIdx = remoteIdx    // index I put in packets to the peer
    this.peerPub = peerPub        // authenticated identity (hex)
    this.send = new Cipher(txKey)
    this.recv = new Cipher(rxKey)
    this.sendCounter = 0
    this.replay = new ReplayWindow()
    this.addr = addr
    this.touched = Date.now()
  }

  seal (plaintext) {
    if (this.sendCounter > MAX_COUNTER) return null // caller must re-handshake
    const counter = this.sendCounter++
    this.send.setNonce(counter)
    const ct = this.send.encrypt(plaintext, EMPTY_AD)
    this.touched = Date.now()
    return encodeTransport(this.remoteIdx, counter, ct)
  }

  open (counter, ct) {
    this.recv.setNonce(counter)
    let pt
    try { pt = this.recv.decrypt(ct, EMPTY_AD) } catch { return null } // forged/corrupt
    if (!this.replay.check(counter)) return null                       // replay/old
    this.touched = Date.now()
    return pt
  }
}

// ---------------------------------------------------------------------------
// Responder (the server): binds one UDP port, answers enrolled initiators only.
// ---------------------------------------------------------------------------
class Responder {
  constructor ({ identity, registry, guard }) {
    this.identity = identity   // { publicKey, secretKey } Buffers
    this.registry = registry
    this.guard = guard
    this.sessions = new Map()  // localIdx -> Session
    this._gc = setInterval(() => this._sweep(), 30000)
    if (this._gc.unref) this._gc.unref()
  }

  _sweep () {
    const now = Date.now()
    for (const [idx, s] of this.sessions) if (now - s.touched > SESSION_TTL) this.sessions.delete(idx)
  }

  freshIdx () { let i; do { i = u32() } while (this.sessions.has(i)) ; return i }

  // Feed every datagram here. Returns an action for the socket layer:
  //   { send: Buffer }                              -> unicast reply to rinfo
  //   { message: Buffer, session, peerPub }         -> authenticated app payload
  //   null                                          -> dropped (stay silent)
  onDatagram (buf, rinfo) {
    if (!this.guard.admit(rinfo.address, buf.length)) return null
    if (buf.length < 1) return null
    const type = buf[0]
    if (type === T_INIT) return this._onInit(buf, rinfo)
    if (type === T_DATA) return this._onData(buf, rinfo)
    return null // responder never receives RESP
  }

  _onInit (buf, rinfo) {
    if (buf.length < 5) return null
    // Rate-limit the expensive path per source before doing any crypto.
    if (!this.guard.allowHandshake(rinfo.address)) return null

    const initIdx = buf.readUInt32BE(1)
    const msg1 = buf.subarray(5)

    const hs = new Noise('IK', false, this.identity)
    hs.initialise(PROLOGUE)
    try { hs.recv(msg1) } catch { return null } // malformed handshake -> silence
    if (!hs.rs) return null

    // THE ENROLMENT GATE: only keys we put in the registry, out of band, pass.
    const peerPub = toHex(hs.rs)
    if (!this.registry.authorisedPeer(peerPub)) return null
    if (!this.registry.ipAllowed(peerPub, rinfo.address)) return null

    let msg2
    try { msg2 = hs.send() } catch { return null }
    if (!hs.complete) return null

    const localIdx = this.freshIdx()
    const s = new Session({
      localIdx,
      remoteIdx: initIdx,
      peerPub,
      txKey: hs.tx,
      rxKey: hs.rx,
      addr: { address: rinfo.address, port: rinfo.port }
    })
    this.sessions.set(localIdx, s)

    const head = Buffer.alloc(1 + 4 + 4)
    head.writeUInt8(T_RESP, 0)
    head.writeUInt32BE(initIdx, 1)
    head.writeUInt32BE(localIdx, 5)
    return { send: Buffer.concat([head, msg2]) }
  }

  _onData (buf, rinfo) {
    if (buf.length < 1 + 4 + 8) return null
    const receiverIdx = buf.readUInt32BE(1)
    const s = this.sessions.get(receiverIdx)
    if (!s) return null
    // A stolen key on a new device can't hijack an existing session's source,
    // but we do keep following a roaming peer only after AEAD verification.
    const counter = Number(buf.readBigUInt64BE(5))
    const ct = buf.subarray(13)
    const pt = s.open(counter, ct)
    if (pt === null) return null
    // Re-check enrolment on every message so revocation takes effect promptly.
    if (!this.registry.authorisedPeer(s.peerPub)) { this.sessions.delete(receiverIdx); return null }
    s.addr = { address: rinfo.address, port: rinfo.port } // roaming, post-auth only
    return { message: pt, session: s, peerPub: s.peerPub }
  }

  reply (session, plaintext) {
    const pkt = session.seal(plaintext)
    if (pkt === null) { this.sessions.delete(session.localIdx); return null }
    return pkt
  }

  stop () { clearInterval(this._gc) }
}

// ---------------------------------------------------------------------------
// Initiator (an enrolled peer/client).
// ---------------------------------------------------------------------------
class Initiator {
  constructor ({ identity, responderStaticPub }) {
    this.identity = identity
    this.responderStaticPub = Buffer.isBuffer(responderStaticPub)
      ? responderStaticPub : Buffer.from(responderStaticPub, 'hex')
    this.localIdx = u32()
    this.session = null
    this.hs = null
  }

  // Returns the INIT packet to send to the responder.
  startHandshake () {
    this.hs = new Noise('IK', true, this.identity)
    this.hs.initialise(PROLOGUE, this.responderStaticPub)
    const msg1 = this.hs.send()
    const head = Buffer.alloc(1 + 4)
    head.writeUInt8(T_INIT, 0)
    head.writeUInt32BE(this.localIdx, 1)
    return Buffer.concat([head, msg1])
  }

  // Feed datagrams from the responder. Returns:
  //   { ready: true }          handshake completed, channel open
  //   { message: Buffer }      authenticated payload from the responder
  //   null                     dropped
  onDatagram (buf) {
    if (buf.length < 1) return null
    const type = buf[0]

    if (type === T_RESP) {
      if (this.session || !this.hs) return null
      if (buf.length < 9) return null
      if (buf.readUInt32BE(1) !== this.localIdx) return null // not our handshake
      const remoteIdx = buf.readUInt32BE(5)
      const msg2 = buf.subarray(9)
      try { this.hs.recv(msg2) } catch { return null }
      if (!this.hs.complete) return null
      this.session = new Session({
        localIdx: this.localIdx,
        remoteIdx,
        peerPub: toHex(this.responderStaticPub),
        txKey: this.hs.tx,
        rxKey: this.hs.rx,
        addr: null
      })
      this.hs = null
      return { ready: true }
    }

    if (type === T_DATA) {
      if (!this.session) return null
      if (buf.length < 13) return null
      if (buf.readUInt32BE(1) !== this.localIdx) return null
      const counter = Number(buf.readBigUInt64BE(5))
      const pt = this.session.open(counter, buf.subarray(13))
      if (pt === null) return null
      return { message: pt }
    }

    return null
  }

  seal (plaintext) {
    if (!this.session) throw new Error('channel not open')
    const pkt = this.session.seal(plaintext)
    if (pkt === null) throw new Error('counter exhausted; re-handshake required')
    return pkt
  }
}

module.exports = { Responder, Initiator, Session, T_INIT, T_RESP, T_DATA, PROLOGUE }
