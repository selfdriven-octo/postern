#!/usr/bin/env node
'use strict'
// Roster tooling for a team mesh.
//
//   node src/roster-cli.js init        roster.json
//   node src/roster-cli.js add-device  roster.json <person> <device-id> <pubhex> [--addr host:port] [--ops ping,status] [--ip 203.0.113.7]
//   node src/roster-cli.js revoke      roster.json --device <device-id>
//   node src/roster-cli.js revoke      roster.json --person <person>
//   node src/roster-cli.js grant       roster.json <device-id> ping,status
//   node src/roster-cli.js addr        roster.json <device-id> host:port
//   node src/roster-cli.js list        roster.json
//   node src/roster-cli.js fingerprint roster.json
//
// The fingerprint is the number the whole team reads aloud to confirm they hold
// the same roster. It covers keys, grants and revocations — not addresses — so
// it stays stable while people roam.

const fs = require('fs')
const { Roster, fingerprint } = require('./roster')

const [cmd, ...rest] = process.argv.slice(2)
const file = rest[0]

function read (p) { return JSON.parse(fs.readFileSync(p, 'utf8')) }
// bump=false for routing-only edits: an address is not trust data, so it must
// not move the fingerprint or oblige the team to re-verify.
function write (p, doc, bump = true) {
  if (bump) doc.version = (Number(doc.version) || 0) + 1
  doc.updated = new Date().toISOString().slice(0, 10)
  fs.writeFileSync(p, JSON.stringify(doc, null, 2) + '\n')
  console.log(`roster v${doc.version}   fingerprint ${fingerprint(doc)}`)
  if (bump) console.log('every peer must hold this version — read the fingerprint aloud to confirm')
  else console.log('routing only — fingerprint unchanged, no re-verification needed')
}
function flag (name, dflt = null) {
  const i = rest.indexOf('--' + name)
  return i === -1 ? dflt : rest[i + 1]
}
function findDevice (doc, id) {
  for (const p of doc.people || []) for (const d of p.devices || []) if (d.id === id) return { person: p, device: d }
  return null
}
function die (m) { console.error(m); process.exit(1) }

switch (cmd) {
  case 'init': {
    if (!file) die('usage: init <roster.json>')
    if (fs.existsSync(file)) die(file + ' already exists')
    write(file, { roster: 'postern', version: 0, people: [] })
    break
  }

  case 'add-device': {
    const [, person, id, pub] = rest
    if (!file || !person || !id || !pub) die('usage: add-device <roster.json> <person> <device-id> <pubhex> [--addr host:port] [--ops a,b] [--ip x]')
    if (!/^[0-9a-f]{64}$/i.test(pub)) die('public key must be 64 hex characters')
    const doc = read(file)
    if (findDevice(doc, id)) die('device id already in roster: ' + id)
    for (const p of doc.people || []) for (const d of p.devices || []) {
      if (d.pub.toLowerCase() === pub.toLowerCase()) die('that key is already enrolled as ' + d.id)
    }
    let p = (doc.people || []).find(x => x.name === person)
    if (!p) { p = { name: person, devices: [] }; (doc.people = doc.people || []).push(p) }
    const ip = flag('ip')
    p.devices.push({
      id,
      pub: pub.toLowerCase(),
      addr: flag('addr') || null,
      ops: (flag('ops') || '').split(',').filter(Boolean),
      ips: ip ? [ip] : [],
      revoked: false
    })
    write(file, doc)
    break
  }

  case 'revoke': {
    const doc = read(file)
    const personName = flag('person')
    const deviceId = flag('device')
    if (!personName && !deviceId) die('usage: revoke <roster.json> --person <name> | --device <id>')
    let n = 0
    for (const p of doc.people || []) {
      for (const d of p.devices || []) {
        if ((personName && p.name === personName) || (deviceId && d.id === deviceId)) { d.revoked = true; n++ }
      }
    }
    if (!n) die('nothing matched')
    console.log(`revoked ${n} device(s)`)
    write(file, doc)
    break
  }

  case 'grant': {
    const [, id, ops] = rest
    if (!file || !id) die('usage: grant <roster.json> <device-id> <op1,op2>')
    const doc = read(file)
    const hit = findDevice(doc, id)
    if (!hit) die('no such device: ' + id)
    hit.device.ops = (ops || '').split(',').filter(Boolean)
    write(file, doc)
    break
  }

  case 'addr': {
    const [, id, addr] = rest
    if (!file || !id || !addr) die('usage: addr <roster.json> <device-id> <host:port>')
    const doc = read(file)
    const hit = findDevice(doc, id)
    if (!hit) die('no such device: ' + id)
    hit.device.addr = addr
    write(file, doc, false)   // routing, not trust
    break
  }

  case 'list': {
    const doc = read(file)
    const r = new Roster().load(doc)
    console.log(`roster v${doc.version}   fingerprint ${r.fingerprint}`)
    for (const p of doc.people || []) {
      console.log(`\n${p.name}`)
      for (const d of p.devices || []) {
        console.log(`  ${d.revoked ? 'REVOKED' : 'active '}  ${d.id.padEnd(18)} ${d.pub.slice(0, 16)}…  ops=[${(d.ops || []).join(',')}]  ${d.addr || '(no address — inbound only)'}`)
      }
    }
    const live = [...r.byPub.values()].filter(d => !d.revoked).length
    const links = live * (live - 1) / 2
    console.log(`\n${live} live device${live === 1 ? '' : 's'} · ${links} link${links === 1 ? '' : 's'} in a full mesh`)
    break
  }

  case 'fingerprint': {
    const doc = read(file)
    console.log(fingerprint(doc))
    break
  }

  default:
    die('commands: init | add-device | revoke | grant | addr | list | fingerprint')
}
