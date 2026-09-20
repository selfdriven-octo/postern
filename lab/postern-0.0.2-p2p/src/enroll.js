#!/usr/bin/env node
'use strict'
// Out-of-band enrolment tooling. Run on a trusted machine; move the resulting
// public keys between parties through a channel you already trust.
//
//   node src/enroll.js keygen server.key.json
//   node src/enroll.js keygen alice.key.json
//   node src/enroll.js pub alice.key.json
//   node src/enroll.js add    peers.json <pubhex> ping,status --ip 203.0.113.7
//   node src/enroll.js revoke peers.json <pubhex>
//   node src/enroll.js list   peers.json

const fs = require('fs')
const { generateIdentity, saveIdentity, loadIdentity } = require('./keys')

const [cmd, ...rest] = process.argv.slice(2)

function readPeers (p) { return fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : [] }
function writePeers (p, arr) { fs.writeFileSync(p, JSON.stringify(arr, null, 2)) }

switch (cmd) {
  case 'keygen': {
    const out = rest[0]; if (!out) exit('keygen <path>')
    const id = generateIdentity(); saveIdentity(out, id)
    console.log('public key:', id.publicKey)
    console.log('saved secret to', out, '(chmod 600)')
    break
  }
  case 'pub': {
    const id = loadIdentity(rest[0]); console.log(Buffer.from(id.publicKey).toString('hex'))
    break
  }
  case 'add': {
    const [p, pub, ops] = rest
    if (!p || !pub) exit('add <peers.json> <pubhex> [op1,op2] [--ip x]')
    const ipFlag = rest.indexOf('--ip')
    const ip = ipFlag !== -1 ? rest[ipFlag + 1] : null
    const arr = readPeers(p).filter(x => x.pub.toLowerCase() !== pub.toLowerCase())
    arr.push({ pub: pub.toLowerCase(), ops: (ops || '').split(',').filter(Boolean), ips: ip ? [ip] : [], revoked: false })
    writePeers(p, arr); console.log('enrolled', pub.slice(0, 16) + '…', 'ops=', ops || '(none)')
    break
  }
  case 'revoke': {
    const [p, pub] = rest; if (!p || !pub) exit('revoke <peers.json> <pubhex>')
    const arr = readPeers(p)
    const e = arr.find(x => x.pub.toLowerCase() === pub.toLowerCase())
    if (!e) exit('not found')
    e.revoked = true; writePeers(p, arr); console.log('revoked', pub.slice(0, 16) + '…')
    break
  }
  case 'list': {
    for (const e of readPeers(rest[0])) {
      console.log((e.revoked ? 'REVOKED ' : 'active  '), e.pub.slice(0, 16) + '…', 'ops=[' + (e.ops || []).join(',') + ']', 'ips=[' + (e.ips || []).join(',') + ']')
    }
    break
  }
  default:
    exit('commands: keygen | pub | add | revoke | list')
}

function exit (m) { console.error('usage:', m); process.exit(1) }
