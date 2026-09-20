'use strict'
// An enrolled peer. Knows the responder's static public key in advance (IK),
// opens the channel, sends one strict request, prints the authenticated reply.

const dgram = require('dgram')
const { Initiator } = require('./channel')

function request ({ identity, responderStaticPub, host, port, op, args = {}, timeoutMs = 4000 }) {
  return new Promise((resolve, reject) => {
    const init = new Initiator({ identity, responderStaticPub })
    const sock = dgram.createSocket('udp4')
    let done = false

    const timer = setTimeout(() => finish(new Error('timeout')), timeoutMs)
    function finish (err, val) {
      if (done) return
      done = true
      clearTimeout(timer)
      sock.close()
      err ? reject(err) : resolve(val)
    }

    sock.on('error', (e) => finish(e))
    sock.on('message', (buf) => {
      const r = init.onDatagram(buf)
      if (!r) return
      if (r.ready) {
        const req = Buffer.from(JSON.stringify({ op, id: 'r1', args }), 'utf8')
        sock.send(init.seal(req), port, host)
        return
      }
      if (r.message) {
        try { finish(null, JSON.parse(r.message.toString('utf8'))) } catch { finish(null, r.message) }
      }
    })

    sock.send(init.startHandshake(), port, host)
  })
}

module.exports = { request }
