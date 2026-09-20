'use strict'
// Minimise the processing reachable BEFORE authentication.
// The only unauthenticated work the responder does is: a cheap size/allowlist
// check, then one Noise handshake. Handshakes are rate-limited per source so a
// flood of probes cannot force unbounded crypto work. Nothing here replies to
// junk — silence is the correct response to an unauthenticated probe.

class TokenBucket {
  constructor (capacity, refillPerSec) {
    this.capacity = capacity
    this.tokens = capacity
    this.refill = refillPerSec
    this.last = Date.now()
  }

  take (n = 1) {
    const now = Date.now()
    this.tokens = Math.min(this.capacity, this.tokens + ((now - this.last) / 1000) * this.refill)
    this.last = now
    if (this.tokens >= n) { this.tokens -= n; return true }
    return false
  }
}

class Guard {
  constructor (opts = {}) {
    // global source allowlist (in addition to any per-peer list in the registry)
    this.globalAllow = new Set(opts.allowSourceIps || [])
    this.maxPacket = opts.maxPacket || 1500          // drop oversize datagrams unread
    this.hsCapacity = opts.hsCapacity || 5           // burst of handshakes per source
    this.hsPerSec = opts.hsPerSec || 1               // sustained handshakes per source
    this.buckets = new Map()                         // ip -> TokenBucket
    this.sweepEvery = opts.sweepEvery || 60000
    this._sweep = setInterval(() => this.buckets.clear(), this.sweepEvery)
    if (this._sweep.unref) this._sweep.unref()
  }

  // Cheapest possible checks, run on every datagram before parsing.
  admit (ip, length) {
    if (length > this.maxPacket) return false
    if (this.globalAllow.size && !this.globalAllow.has(ip)) return false
    return true
  }

  // Called only when a datagram is a handshake INIT (the expensive path).
  allowHandshake (ip) {
    let b = this.buckets.get(ip)
    if (!b) { b = new TokenBucket(this.hsCapacity, this.hsPerSec); this.buckets.set(ip, b) }
    return b.take(1)
  }

  stop () { clearInterval(this._sweep) }
}

module.exports = { Guard, TokenBucket }
