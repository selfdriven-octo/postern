'use strict'
// The application that runs AFTER authentication. Kept deliberately narrow:
//   - bounded message size
//   - one strict schema, validated by hand (no dynamic parsing of structure)
//   - a fixed table of permitted operations (no eval, no spawn, no code paths
//     selected by attacker-controlled strings beyond this allowlist)
//   - per-peer authority: an authenticated peer may only call the ops enrolled
//     for its key. Tunnel membership is not general access.

// Kept below the guard's datagram cap (1500) so a valid packet's plaintext is
// bounded at both layers: the guard drops oversize datagrams unread, and this
// rejects anything that slips through when the datagram cap is raised.
const MAX_PLAINTEXT = 1024
const MAX_ID_LEN = 64
const MAX_ARG_BYTES = 512

// Fixed handler table. Each handler receives (args, ctx) and returns a plain
// JSON-serialisable object. Handlers must never execute received code, read
// arbitrary paths, or shell out based on input.
const HANDLERS = {
  ping (args) {
    return { pong: true }
  },
  status (args, ctx) {
    return {
      peer: ctx.peerPub.slice(0, 16) + '…',
      uptimeSec: Math.round(process.uptime()),
      now: new Date().toISOString()
    }
  },
  // Lets two peers confirm they hold the same roster. In a mesh there is no
  // authority to push a revocation, so the useful thing is to make a
  // disagreement visible rather than silent.
  roster (args, ctx) {
    if (!ctx || !ctx.roster) return { known: false }
    return { known: true, version: ctx.roster.version, fingerprint: ctx.roster.fingerprint }
  },
  echo (args) {
    // echo is intentionally trivial and length-bounded by the schema check
    const text = typeof args.text === 'string' ? args.text : ''
    return { text: text.slice(0, 256) }
  }
}

const OPS = new Set(Object.keys(HANDLERS))

function fail (id, code, msg) {
  return { ok: false, id: id || null, error: { code, message: msg } }
}

// Validate the strict schema. Returns { req } or { err }.
function parse (plaintext) {
  if (plaintext.length > MAX_PLAINTEXT) return { err: ['too_large', 'message exceeds limit'] }

  let msg
  try { msg = JSON.parse(plaintext.toString('utf8')) } catch { return { err: ['bad_json', 'not JSON'] } }
  if (msg === null || typeof msg !== 'object' || Array.isArray(msg)) return { err: ['bad_shape', 'object required'] }

  const { op, id, args } = msg
  if (typeof op !== 'string' || !OPS.has(op)) return { err: ['bad_op', 'unknown operation'] }
  if (typeof id !== 'string' || id.length === 0 || id.length > MAX_ID_LEN) return { err: ['bad_id', 'id required'] }
  const a = (args === undefined) ? {} : args
  if (a === null || typeof a !== 'object' || Array.isArray(a)) return { err: ['bad_args', 'args must be object'] }
  if (Buffer.byteLength(JSON.stringify(a), 'utf8') > MAX_ARG_BYTES) return { err: ['args_too_large', 'args too large'] }

  return { req: { op, id, args: a } }
}

// Handle one authenticated payload from `peerPub`, whose enrolled authority is
// `allowedOps` (a Set). Returns a Buffer to send back, or null for no reply.
function handle (plaintext, peerPub, allowedOps, ctx = {}) {
  const { req, err } = parse(plaintext)
  if (err) return encode(fail(null, err[0], err[1]))

  if (!allowedOps.has(req.op)) return encode(fail(req.id, 'forbidden', 'peer not authorised for op'))

  let result
  try {
    result = HANDLERS[req.op](req.args, { peerPub, ...ctx })
  } catch (e) {
    return encode(fail(req.id, 'handler_error', 'operation failed'))
  }
  return encode({ ok: true, id: req.id, result })
}

function encode (obj) {
  const b = Buffer.from(JSON.stringify(obj), 'utf8')
  return b.length > MAX_PLAINTEXT ? Buffer.from(JSON.stringify(fail(null, 'reply_too_large', '')), 'utf8') : b
}

module.exports = { handle, parse, OPS, MAX_PLAINTEXT, HANDLERS }
