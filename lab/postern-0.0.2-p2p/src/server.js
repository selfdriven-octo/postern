'use strict'
// The endpoint. Exposes exactly one UDP port. No web interface, no SSH here,
// no application listener on the public interface. Every datagram flows:
//   guard (size/allowlist/rate) -> Noise_IK auth -> narrow authorised app.

const dgram = require('dgram')
const path = require('path')
const { loadIdentity, Registry } = require('./keys')
const { Guard } = require('./guard')
const { Responder } = require('./channel')
const app = require('./app')

function startServer (opts = {}) {
  const dir = opts.dir || process.cwd()
  const port = opts.port ?? 51820 // 0 => ephemeral (tests); don't treat as falsy
  const host = opts.host || '0.0.0.0'

  const identity = loadIdentity(opts.identityPath || path.join(dir, 'server.key.json'))
  const registry = new Registry(opts.peersPath || path.join(dir, 'peers.json'))
  const guard = new Guard({
    allowSourceIps: opts.allowSourceIps || [],
    maxPacket: opts.maxPacket || 1500,
    hsCapacity: opts.hsCapacity || 5,
    hsPerSec: opts.hsPerSec || 1
  })
  const responder = new Responder({ identity, registry, guard })

  const sock = dgram.createSocket({ type: 'udp4', recvBufferSize: 1 << 20 })

  sock.on('message', (buf, rinfo) => {
    const action = responder.onDatagram(buf, rinfo)
    if (!action) return // silent drop

    if (action.send) { sock.send(action.send, rinfo.port, rinfo.address); return }

    if (action.message) {
      const allowed = registry.allowedOps(action.peerPub)
      const reply = app.handle(action.message, action.peerPub, allowed)
      if (!reply) return
      const pkt = responder.reply(action.session, reply)
      if (pkt) sock.send(pkt, action.session.addr.port, action.session.addr.address)
    }
  })

  sock.on('error', (e) => { console.error('[server] socket error', e.message) })

  return new Promise((resolve) => {
    sock.bind(port, host, () => {
      const a = sock.address()
      console.log(`[server] listening udp ${a.address}:${a.port}  static=${identity.publicKey.toString('hex').slice(0, 16)}…`)
      resolve({
        sock,
        responder,
        registry,
        guard,
        reload: () => registry.reload(),
        close: () => { guard.stop(); responder.stop(); sock.close() }
      })
    })
  })
}

module.exports = { startServer }

if (require.main === module) {
  startServer({
    dir: process.env.MNC_DIR || process.cwd(),
    port: Number(process.env.MNC_PORT || 51820),
    allowSourceIps: (process.env.MNC_ALLOW_IPS || '').split(',').filter(Boolean)
  }).catch((e) => { console.error(e); process.exit(1) })
}
