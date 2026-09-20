'use strict'
// Run one node of the mesh.
//
//   POSTERN_KEY=ana.key.json POSTERN_ROSTER=roster.json POSTERN_PORT=51820 node src/peer.js
//
// It binds one UDP port, dials every peer in the roster that has an address,
// answers the ones that dial it, and prints nothing that an onlooker could use.

const path = require('path')
const { loadIdentity } = require('./keys')
const { Roster } = require('./roster')
const { Node } = require('./node')

async function startPeer (opts = {}) {
  const dir = opts.dir || process.cwd()
  const identity = loadIdentity(opts.identityPath || process.env.POSTERN_KEY || path.join(dir, 'node.key.json'))
  const roster = new Roster(opts.rosterPath || process.env.POSTERN_ROSTER || path.join(dir, 'roster.json'))
  const node = new Node({
    identity,
    roster,
    port: opts.port ?? Number(process.env.POSTERN_PORT || 51820),
    host: opts.host || '0.0.0.0'
  })
  await node.start()

  const me = roster.labelOf(node.selfPub)
  const peers = roster.peersOf(node.selfPub)
  console.log(`[postern] ${me} listening udp/${node.port}`)
  console.log(`[postern] roster v${roster.version}  fingerprint ${roster.fingerprint}  (${peers.length} peers)`)
  node.connectAll()

  // Re-read the roster on SIGHUP so a revocation takes effect without a restart.
  process.on('SIGHUP', () => {
    try {
      roster.reload()
      console.log(`[postern] roster reloaded: v${roster.version}  fingerprint ${roster.fingerprint}`)
      node.connectAll()
    } catch (e) {
      console.error('[postern] roster reload failed:', e.message)
    }
  })

  return node
}

module.exports = { startPeer }

if (require.main === module) {
  startPeer().catch(e => { console.error(e.message); process.exit(1) })
}
