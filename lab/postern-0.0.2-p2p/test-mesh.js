'use strict'
// Mesh tests: a symmetric node, an 8-person team, simultaneous open,
// revocation across the mesh, and roster agreement.

const { generateIdentity } = require('./src/keys')
const { Roster, fingerprint } = require('./src/roster')
const { Node } = require('./src/node')
const { Guard } = require('./src/guard')

let pass = 0, fail = 0
function ok (name, cond, extra) {
  cond ? (pass++, console.log('  ok  -', name))
       : (fail++, console.log('FAIL  -', name, extra === undefined ? '' : '→ ' + JSON.stringify(extra)))
}
const sleep = (ms) => new Promise(r => setTimeout(r, ms))
const idBuf = (i) => ({ publicKey: Buffer.from(i.publicKey, 'hex'), secretKey: Buffer.from(i.secretKey, 'hex') })

// Every node in these tests shares 127.0.0.1, so the per-source handshake
// limiter would throttle a 28-link mesh. Real peers have distinct addresses.
const looseGuard = () => new Guard({ maxPacket: 1500, hsCapacity: 500, hsPerSec: 500 })

// Build N nodes, bind them, then publish a roster carrying their real ports.
async function buildTeam (names, opsFor = () => ['ping', 'status', 'roster', 'echo']) {
  const members = names.map(name => ({ name, identity: generateIdentity() }))
  const empty = new Roster().load({ version: 0, people: [] })
  const nodes = []
  for (const m of members) {
    const n = new Node({ identity: idBuf(m.identity), roster: empty, guard: looseGuard() })
    await n.start()
    m.port = n.port
    nodes.push(n)
  }
  const doc = {
    version: 1,
    people: members.map(m => ({
      name: m.name,
      devices: [{
        id: m.name + '-laptop',
        pub: m.identity.publicKey.toLowerCase(),
        addr: '127.0.0.1:' + m.port,
        ops: opsFor(m.name),
        ips: [],
        revoked: false
      }]
    }))
  }
  const roster = new Roster().load(doc)
  nodes.forEach(n => { n.roster = roster })
  return { members, nodes, roster, doc }
}

async function main () {
  // ---------------------------------------------------------------- 1. two-way
  {
    const { members, nodes } = await buildTeam(['ana', 'ben'])
    const [A, B] = nodes
    const [pa, pb] = members.map(m => m.identity.publicKey.toLowerCase())

    const r1 = await A.request(pb, 'ping')
    ok('a peer can call another peer', r1.ok === true && r1.result.pong === true)

    // the same socket must also answer in the other direction
    const r2 = await B.request(pa, 'ping')
    ok('the same node answers as well as calls', r2.ok === true && r2.result.pong === true)

    ok('one session per pair on each side', A.byPeer.size === 1 && B.byPeer.size === 1,
      { a: A.byPeer.size, b: B.byPeer.size })

    // exactly one side should consider itself the initiator
    const aInit = A.byPeer.get(pb).initiatedByUs
    const bInit = B.byPeer.get(pa).initiatedByUs
    ok('the two sides agree who initiated', aInit !== bInit, { aInit, bInit })

    nodes.forEach(n => n.stop())
  }

  // ------------------------------------------------------- 2. simultaneous open
  {
    const { members, nodes } = await buildTeam(['ana', 'ben'])
    const [A, B] = nodes
    const [pa, pb] = members.map(m => m.identity.publicKey.toLowerCase())

    A.connect(pb); B.connect(pa)      // both dial in the same tick
    await sleep(500)

    ok('simultaneous open leaves one session each side',
      A.byPeer.size === 1 && B.byPeer.size === 1 && A.sessions.size === 1 && B.sessions.size === 1,
      { aPeers: A.byPeer.size, bPeers: B.byPeer.size, aSess: A.sessions.size, bSess: B.sessions.size })

    // both sides must keep the SAME session: the one initiated by the higher key
    const higher = pa >= pb ? 'a' : 'b'
    const aKeptOwn = A.byPeer.get(pb).initiatedByUs
    const bKeptOwn = B.byPeer.get(pa).initiatedByUs
    const keptSide = aKeptOwn ? 'a' : (bKeptOwn ? 'b' : 'none')
    ok('both sides keep the session initiated by the higher key',
      keptSide === higher && aKeptOwn !== bKeptOwn, { higher, keptSide, aKeptOwn, bKeptOwn })

    const r = await A.request(pb, 'ping')
    ok('the surviving session carries traffic', r.ok === true)

    nodes.forEach(n => n.stop())
  }

  // ------------------------------------------------------- 3. an 8-person team
  {
    const names = ['ana', 'ben', 'cho', 'dev', 'eli', 'fay', 'gus', 'hal']
    const { members, nodes, roster } = await buildTeam(names)
    const pubs = members.map(m => m.identity.publicKey.toLowerCase())

    ok('roster holds 8 people, 8 devices', roster.byPub.size === 8 && roster.raw.people.length === 8)
    ok('each node sees 7 peers', nodes.every(n => roster.peersOf(n.selfPub).length === 7))

    // every node dials every other: 28 links
    nodes.forEach(n => n.connectAll())
    await sleep(900)

    const fullyOpen = nodes.every(n => n.byPeer.size === 7)
    ok('all 28 links open (7 peers per node)', fullyOpen, nodes.map(n => n.byPeer.size))

    // every ordered pair exchanges a real request
    let okCount = 0, attempted = 0
    for (let i = 0; i < nodes.length; i++) {
      const results = await Promise.all(
        pubs.filter((_, j) => j !== i).map(p => nodes[i].request(p, 'ping').catch(() => null))
      )
      attempted += results.length
      okCount += results.filter(r => r && r.ok).length
    }
    ok('all 56 ordered pairs answer', okCount === 56 && attempted === 56, { okCount, attempted })

    // everyone agrees on the roster fingerprint
    const fps = await Promise.all(pubs.slice(1).map(p => nodes[0].request(p, 'roster')))
    const agreed = fps.every(r => r.ok && r.result.fingerprint === roster.fingerprint)
    ok('all peers report the same roster fingerprint', agreed, roster.fingerprint)

    nodes.forEach(n => n.stop())
  }

  // ------------------------------------------- 4. revocation across the mesh
  {
    const { members, nodes, doc } = await buildTeam(['ana', 'ben', 'cho'])
    const [A, B, C] = nodes
    const pubs = members.map(m => m.identity.publicKey.toLowerCase())
    nodes.forEach(n => n.connectAll())
    await sleep(600)

    const before = await A.request(pubs[2], 'ping')
    ok('cho answers before revocation', before.ok === true)

    // revoke cho everywhere — in a mesh this is every node's own edit
    doc.version = 2
    doc.people.find(p => p.name === 'cho').devices[0].revoked = true
    const updated = new Roster().load(doc)
    A.roster = updated            // ana updates; ben deliberately does NOT

    const afterRefused = await A.request(pubs[2], 'ping', {}, 700).then(() => false).catch(() => true)
    ok('a revoked device gets no answer on its live session', afterRefused)

    // and cannot open a new one
    C.byPeer.clear(); C.sessions.clear()
    const rehandshake = await C.request(pubs[0], 'ping', {}, 700).then(() => false).catch(() => true)
    ok('a revoked device cannot re-handshake', rehandshake)

    // ben never updated, so he still trusts cho — the real cost of having no
    // authority to push a revocation. This is the mesh's weak point, on purpose.
    const stale = await C.request(pubs[1], 'ping', {}, 2000).then(r => r.ok).catch(() => false)
    ok('a node that has not updated still trusts the revoked device', stale === true)

    nodes.forEach(n => n.stop())
  }

  // ------------------------------------------------ 5. per-peer authority
  {
    const { members, nodes } = await buildTeam(['ana', 'ben'],
      (name) => name === 'ben' ? ['ping'] : ['ping', 'status', 'roster', 'echo'])
    const [A, B] = nodes
    const pubs = members.map(m => m.identity.publicKey.toLowerCase())

    const allowed = await B.request(pubs[0], 'status')
    ok('ana grants ben only what ben was granted (ping ok)', (await B.request(pubs[0], 'ping')).ok === true)
    ok('ben is refused an op he was not granted', allowed.ok === false && allowed.error.code === 'forbidden',
      allowed)

    nodes.forEach(n => n.stop())
  }

  // ------------------------------------------------ 6. fingerprint behaviour
  {
    const base = {
      version: 1,
      people: [{ name: 'ana', devices: [{ id: 'l', pub: 'aa'.repeat(32), addr: '1.2.3.4:51820', ops: ['ping'], ips: [], revoked: false }] }]
    }
    const moved = JSON.parse(JSON.stringify(base)); moved.people[0].devices[0].addr = '9.9.9.9:4000'
    const regranted = JSON.parse(JSON.stringify(base)); regranted.people[0].devices[0].ops = ['ping', 'status']
    const revoked = JSON.parse(JSON.stringify(base)); revoked.people[0].devices[0].revoked = true
    const reordered = { people: base.people, version: 1 }

    ok('a roaming address does not change the fingerprint', fingerprint(base) === fingerprint(moved))
    ok('changing a grant does change it', fingerprint(base) !== fingerprint(regranted))
    ok('revoking does change it', fingerprint(base) !== fingerprint(revoked))
    ok('key order does not change it', fingerprint(base) === fingerprint(reordered))
    ok('fingerprint is readable aloud', /^[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(fingerprint(base)),
      fingerprint(base))
  }

  // ------------------------------------------------ 7. keep-alive is inert
  {
    const { members, nodes } = await buildTeam(['ana', 'ben'])
    const [A, B] = nodes
    const pubs = members.map(m => m.identity.publicKey.toLowerCase())
    await A.request(pubs[1], 'ping')

    A._keepalive()          // empty plaintext on every live session
    await sleep(200)
    const after = await A.request(pubs[1], 'ping')
    ok('a keep-alive draws no reply and does not disturb the session', after.ok === true)

    nodes.forEach(n => n.stop())
  }

  // ------------------------------------------ 8. a peer restarts and re-dials
  {
    const { members, nodes } = await buildTeam(['ana', 'ben'])
    const [A, B] = nodes
    const pubs = members.map(m => m.identity.publicKey.toLowerCase())
    await A.request(pubs[1], 'ping')
    const oldIdx = A.byPeer.get(pubs[1]).localIdx

    await sleep(1600)               // past the race window
    B.byPeer.clear(); B.sessions.clear()   // ben restarts, loses his table

    const r = await B.request(pubs[0], 'ping', {}, 3000).catch(() => null)
    ok('a restarted peer can re-handshake and is answered', r !== null && r.ok === true)
    ok('the old session was replaced, not kept',
      A.byPeer.get(pubs[0 + 1]) && A.byPeer.get(pubs[1]).localIdx !== oldIdx)

    nodes.forEach(n => n.stop())
  }

  console.log(`\n${pass} passed, ${fail} failed`)
  process.exit(fail ? 1 : 0)
}

main().catch(e => { console.error(e); process.exit(1) })
