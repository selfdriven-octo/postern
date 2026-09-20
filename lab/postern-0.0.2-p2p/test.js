'use strict'
const dgram = require('dgram')
const fs = require('fs')
const os = require('os')
const path = require('path')
const assert = require('assert')

const { generateIdentity, saveIdentity, loadIdentity } = require('./src/keys')
const { startServer } = require('./src/server')
const { request } = require('./src/client')
const { Initiator } = require('./src/channel')

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mnc-'))
let pass = 0, fail = 0
function ok (name, cond) { cond ? (pass++, console.log('  ok  -', name)) : (fail++, console.log('FAIL  -', name)) }

async function main () {
  // enrol: server + two clients (alice authorised, mallory NOT enrolled)
  const serverId = generateIdentity(); saveIdentity(path.join(dir, 'server.key.json'), serverId)
  const aliceId = generateIdentity()
  const malloryId = generateIdentity()
  const bobId = generateIdentity() // enrolled but only for 'ping'

  fs.writeFileSync(path.join(dir, 'peers.json'), JSON.stringify([
    { pub: aliceId.publicKey.toLowerCase(), ops: ['ping', 'status', 'echo'], ips: [], revoked: false },
    { pub: bobId.publicKey.toLowerCase(), ops: ['ping'], ips: [], revoked: false }
  ], null, 2))

  // Generous handshake limits for the functional tests (all from 127.0.0.1);
  // the DoS limiter is exercised separately in rateLimitTest().
  const srv = await startServer({ dir, port: 0, hsCapacity: 100, hsPerSec: 100 })
  const port = srv.sock.address().port
  const host = '127.0.0.1'
  const serverPub = Buffer.from(serverId.publicKey, 'hex')
  const idBuf = (i) => ({ publicKey: Buffer.from(i.publicKey, 'hex'), secretKey: Buffer.from(i.secretKey, 'hex') })

  // 1. happy path: authorised peer, authorised op
  const r1 = await request({ identity: idBuf(aliceId), responderStaticPub: serverPub, host, port, op: 'ping', args: {} })
  ok('authorised ping returns pong', r1 && r1.ok === true && r1.result.pong === true)

  const r2 = await request({ identity: idBuf(aliceId), responderStaticPub: serverPub, host, port, op: 'echo', args: { text: 'hello octonomous' } })
  ok('echo round-trips text', r2 && r2.ok === true && r2.result.text === 'hello octonomous')

  const r3 = await request({ identity: idBuf(aliceId), responderStaticPub: serverPub, host, port, op: 'status', args: {} })
  ok('status returns structured data', r3 && r3.ok === true && typeof r3.result.uptimeSec === 'number')

  // 2. per-peer authority: bob is enrolled but not authorised for 'status'
  const r4 = await request({ identity: idBuf(bobId), responderStaticPub: serverPub, host, port, op: 'status', args: {} })
  ok('enrolled-but-unauthorised op is forbidden', r4 && r4.ok === false && r4.error.code === 'forbidden')

  const r5 = await request({ identity: idBuf(bobId), responderStaticPub: serverPub, host, port, op: 'ping', args: {} })
  ok('bob may still call his one authorised op', r5 && r5.ok === true)

  // 3. unknown key: mallory is not enrolled -> handshake must get no response
  let mallorySawReply = false
  await new Promise((resolve) => {
    const init = new Initiator({ identity: idBuf(malloryId), responderStaticPub: serverPub })
    const sock = dgram.createSocket('udp4')
    sock.on('message', () => { mallorySawReply = true })
    sock.send(init.startHandshake(), port, host)
    setTimeout(() => { sock.close(); resolve() }, 600)
  })
  ok('unenrolled key gets silence (no handshake response)', mallorySawReply === false)

  // 4. bad schema / unknown op from an authorised peer -> structured error, no crash
  const r6 = await rawRequest(idBuf(aliceId), serverPub, host, port, Buffer.from(JSON.stringify({ op: 'exec', id: 'x', args: {} })))
  ok('unknown op rejected', r6 && r6.ok === false && r6.error.code === 'bad_op')

  const r7 = await rawRequest(idBuf(aliceId), serverPub, host, port, Buffer.from('not json at all'))
  ok('non-JSON rejected', r7 && r7.ok === false && r7.error.code === 'bad_json')

  // 5a. plaintext over the app cap (but datagram still under the guard cap) -> too_large
  const overApp = Buffer.from(JSON.stringify({ op: 'echo', id: 'x', args: { text: 'A'.repeat(1200) } }))
  const r8 = await rawRequest(idBuf(aliceId), serverPub, host, port, overApp)
  ok('over-app-cap plaintext rejected (too_large)', r8 && r8.ok === false && r8.error.code === 'too_large')

  // 5b. datagram over the guard cap -> dropped unread, no reply at all
  const dropped = await expectNoReply(host, port, Buffer.alloc(1600, 0x03))
  ok('over-datagram-cap packet dropped silently', dropped === true)

  // 6. replay: capture a valid sealed packet and resend it -> must be dropped
  const replayResult = await replayTest(idBuf(aliceId), serverPub, host, port)
  ok('replayed transport packet is dropped', replayResult.firstOk && replayResult.replayDropped)

  // 7. revocation: revoke alice, reload, new handshake must be refused
  const peers = JSON.parse(fs.readFileSync(path.join(dir, 'peers.json'), 'utf8'))
  peers.find(p => p.pub === aliceId.publicKey.toLowerCase()).revoked = true
  fs.writeFileSync(path.join(dir, 'peers.json'), JSON.stringify(peers, null, 2))
  srv.reload()
  let revokedSawReply = false
  await new Promise((resolve) => {
    const init = new Initiator({ identity: idBuf(aliceId), responderStaticPub: serverPub })
    const sock = dgram.createSocket('udp4')
    sock.on('message', () => { revokedSawReply = true })
    sock.send(init.startHandshake(), port, host)
    setTimeout(() => { sock.close(); resolve() }, 600)
  })
  ok('revoked key can no longer handshake', revokedSawReply === false)

  // 8. DoS guard: a burst of handshakes from one source is capped.
  const rl = await rateLimitTest(dir)
  ok('handshake flood is rate-limited (some dropped)', rl.answered > 0 && rl.answered < rl.sent)

  srv.close()
  console.log(`\n${pass} passed, ${fail} failed`)
  process.exit(fail ? 1 : 0)
}

// send raw bytes; resolve true if the server stays silent
function expectNoReply (host, port, bytes, ms = 500) {
  return new Promise((resolve) => {
    const sock = dgram.createSocket('udp4')
    let replied = false
    sock.on('message', () => { replied = true })
    sock.send(bytes, port, host)
    setTimeout(() => { sock.close(); resolve(!replied) }, ms)
  })
}

// send an arbitrary (already schema-shaped or not) plaintext over a real session
function rawRequest (identity, serverPub, host, port, plaintext) {
  return new Promise((resolve, reject) => {
    const init = new Initiator({ identity, responderStaticPub: serverPub })
    const sock = dgram.createSocket('udp4')
    const t = setTimeout(() => { sock.close(); reject(new Error('timeout')) }, 3000)
    sock.on('message', (buf) => {
      const r = init.onDatagram(buf)
      if (!r) return
      if (r.ready) { sock.send(init.seal(plaintext), port, host); return }
      if (r.message) { clearTimeout(t); sock.close(); try { resolve(JSON.parse(r.message.toString())) } catch { resolve(null) } }
    })
    sock.send(init.startHandshake(), port, host)
  })
}

// open a session, send one packet, capture its bytes, then resend the same bytes
function replayTest (identity, serverPub, host, port) {
  return new Promise((resolve, reject) => {
    const init = new Initiator({ identity, responderStaticPub: serverPub })
    const sock = dgram.createSocket('udp4')
    let sealed = null
    let firstOk = false
    let replies = 0
    const t = setTimeout(() => { sock.close(); resolve({ firstOk, replayDropped: replies === 1 }) }, 1500)
    sock.on('message', (buf) => {
      const r = init.onDatagram(buf)
      if (!r) return
      if (r.ready) {
        sealed = init.seal(Buffer.from(JSON.stringify({ op: 'ping', id: 'r1', args: {} })))
        sock.send(sealed, port, host) // first, legitimate
        return
      }
      if (r.message) {
        replies++
        if (replies === 1) {
          firstOk = true
          // now replay the exact same bytes; server must drop it (no 2nd reply)
          sock.send(Buffer.from(sealed), port, host)
        }
      }
    })
    sock.on('error', reject)
    sock.send(init.startHandshake(), port, host)
  })
}

// Spin up a server with a tight handshake budget and fire a burst of INITs
// from one source. Count how many draw a RESP.
async function rateLimitTest (baseDir) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'mnc-rl-'))
  const sid = generateIdentity(); saveIdentity(path.join(d, 'server.key.json'), sid)
  const peer = generateIdentity()
  fs.writeFileSync(path.join(d, 'peers.json'), JSON.stringify([
    { pub: peer.publicKey.toLowerCase(), ops: ['ping'], ips: [], revoked: false }
  ]))
  const srv = await startServer({ dir: d, port: 0, hsCapacity: 3, hsPerSec: 0 })
  const port = srv.sock.address().port
  const serverPub = Buffer.from(sid.publicKey, 'hex')
  const idBuf = { publicKey: Buffer.from(peer.publicKey, 'hex'), secretKey: Buffer.from(peer.secretKey, 'hex') }

  const sent = 12
  let answered = 0
  await new Promise((resolve) => {
    let outstanding = sent
    for (let i = 0; i < sent; i++) {
      const { Initiator } = require('./src/channel')
      const init = new Initiator({ identity: idBuf, responderStaticPub: serverPub })
      const sock = dgram.createSocket('udp4')
      sock.on('message', () => { answered++; sock.close(); if (--outstanding === 0) resolve() })
      sock.send(init.startHandshake(), port, '127.0.0.1')
      setTimeout(() => { try { sock.close() } catch {} ; if (--outstanding === 0) resolve() }, 700)
    }
  })
  srv.close()
  return { sent, answered }
}

main().catch((e) => { console.error(e); process.exit(1) })
