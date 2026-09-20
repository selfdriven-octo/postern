'use strict'
// The roster: who is in the team, which devices each person holds, and what
// each device may ask for. It replaces the flat peers.json for a mesh.
//
// A peer is a DEVICE, not a person, so a stolen laptop can be revoked without
// disturbing that person's phone. Devices are grouped under a person so one
// revocation is one obvious edit.
//
// The fingerprint covers trust-bearing fields only — keys, grants, revocation,
// version — and deliberately NOT network addresses. A peer that changes IP
// does not change the fingerprint, so the number everyone reads aloud on a
// call stays stable while people roam.

const fs = require('fs')
const crypto = require('crypto')

// Crockford base32, minus the letters that get misheard.
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

function toBase32 (buf) {
  let bits = 0, value = 0, out = ''
  for (const b of buf) {
    value = (value << 8) | b
    bits += 8
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  return out
}

// Canonical form of everything that matters for trust. Sorted so two nodes
// that agree on content always agree on the fingerprint.
function canonical (roster) {
  const people = (roster.people || [])
    .map(p => ({
      name: String(p.name),
      devices: (p.devices || [])
        .map(d => ({
          id: String(d.id),
          pub: String(d.pub).toLowerCase(),
          ops: [...(d.ops || [])].sort(),
          ips: [...(d.ips || [])].sort(),
          revoked: !!d.revoked
        }))
        .sort((a, b) => a.pub.localeCompare(b.pub))
    }))
    .sort((a, b) => a.name.localeCompare(b.name))
  return JSON.stringify({ version: Number(roster.version) || 0, people })
}

// 60 bits, grouped for reading aloud: "K7QF-2M9X-4TPB"
function fingerprint (roster) {
  const digest = crypto.createHash('sha256').update(canonical(roster)).digest()
  const s = toBase32(digest.subarray(0, 8)).slice(0, 12)
  return s.slice(0, 4) + '-' + s.slice(4, 8) + '-' + s.slice(8, 12)
}

class Roster {
  constructor (path) {
    this.path = path
    if (path) this.reload()
  }

  reload () {
    const raw = JSON.parse(fs.readFileSync(this.path, 'utf8'))
    this.load(raw)
    return this
  }

  load (raw) {
    this.raw = raw
    this.version = Number(raw.version) || 0
    this.byPub = new Map()     // pub -> { ...device, person }
    for (const person of raw.people || []) {
      for (const d of person.devices || []) {
        this.byPub.set(String(d.pub).toLowerCase(), { ...d, person: person.name })
      }
    }
    this.fingerprint = fingerprint(raw)
    return this
  }

  // --- the interface channel.js and app.js expect of a registry ---

  authorisedPeer (pubHex) {
    const d = this.byPub.get(String(pubHex).toLowerCase())
    if (!d || d.revoked) return null
    return d
  }

  allowedOps (pubHex) {
    const d = this.authorisedPeer(pubHex)
    return d ? new Set(d.ops || []) : new Set()
  }

  ipAllowed (pubHex, ip) {
    const d = this.byPub.get(String(pubHex).toLowerCase())
    if (!d || !Array.isArray(d.ips) || d.ips.length === 0) return true
    return d.ips.includes(ip)
  }

  // --- mesh additions ---

  // Where to send a first packet. Absent means "wait for them to call us".
  addressOf (pubHex) {
    const d = this.byPub.get(String(pubHex).toLowerCase())
    if (!d || !d.addr) return null
    const i = String(d.addr).lastIndexOf(':')
    if (i < 1) return null
    const port = Number(d.addr.slice(i + 1))
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null
    return { address: d.addr.slice(0, i), port }
  }

  labelOf (pubHex) {
    const d = this.byPub.get(String(pubHex).toLowerCase())
    return d ? `${d.person}/${d.id}` : String(pubHex).slice(0, 8) + '…'
  }

  // Every live device except our own — the mesh this node should reach.
  peersOf (selfPubHex) {
    const self = String(selfPubHex).toLowerCase()
    const out = []
    for (const [pub, d] of this.byPub) {
      if (pub === self || d.revoked) continue
      out.push({ pub, ...d })
    }
    return out
  }

  // Devices belonging to one person, live or not. Revoking a person is this
  // list, which is why devices are grouped rather than listed flat.
  devicesOf (personName) {
    const out = []
    for (const [pub, d] of this.byPub) {
      if (d.person === personName) out.push({ pub, ...d })
    }
    return out
  }
}

module.exports = { Roster, fingerprint, canonical }
