'use strict'
// Identity keys and the enrolled-peer registry.
// Enrolment = adding a peer's static public key here, out of band, through a
// trusted channel. There is no registration endpoint and no password login.

const fs = require('fs')
const dh = require('noise-handshake/dh')

// --- static identity keypair (persistent) ---------------------------------

function generateIdentity () {
  const kp = dh.generateKeyPair()
  return {
    publicKey: Buffer.from(kp.publicKey).toString('hex'),
    secretKey: Buffer.from(kp.secretKey).toString('hex')
  }
}

function loadIdentity (path) {
  const j = JSON.parse(fs.readFileSync(path, 'utf8'))
  return {
    publicKey: Buffer.from(j.publicKey, 'hex'),
    secretKey: Buffer.from(j.secretKey, 'hex')
  }
}

function saveIdentity (path, id) {
  // 0600: keys are secrets. Protect them at rest and restrict the process user.
  fs.writeFileSync(path, JSON.stringify(id, null, 2), { mode: 0o600 })
  fs.chmodSync(path, 0o600)
}

// --- enrolled-peer registry ------------------------------------------------
// A peer entry:
//   { pub:   <hex x25519 public key>          // the cryptographic identity
//     ops:   ["ping","status", ...]           // authority granted AFTER auth
//     ips:   ["203.0.113.7"] | []             // optional stable source allowlist
//     revoked: false }                        // revocation flag

class Registry {
  constructor (path) {
    this.path = path
    this.byPub = new Map()
    if (path) this.reload()
  }

  reload () {
    const arr = JSON.parse(fs.readFileSync(this.path, 'utf8'))
    this.byPub.clear()
    for (const p of arr) this.byPub.set(p.pub.toLowerCase(), p)
    return this
  }

  // The enrolment gate. Returns the peer record only if the key is known and
  // not revoked. Everything else about the packet is irrelevant until this
  // passes.
  authorisedPeer (pubHex) {
    const p = this.byPub.get(String(pubHex).toLowerCase())
    if (!p || p.revoked) return null
    return p
  }

  allowedOps (pubHex) {
    const p = this.authorisedPeer(pubHex)
    return p ? new Set(p.ops || []) : new Set()
  }

  // Optional per-peer source-IP allowlist. Empty/absent => any source (the key
  // is still the identity check; this only shrinks exposure where IPs are stable).
  ipAllowed (pubHex, ip) {
    const p = this.byPub.get(String(pubHex).toLowerCase())
    if (!p || !Array.isArray(p.ips) || p.ips.length === 0) return true
    return p.ips.includes(ip)
  }
}

module.exports = { generateIdentity, loadIdentity, saveIdentity, Registry }
