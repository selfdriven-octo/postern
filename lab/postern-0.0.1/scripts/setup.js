'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { randomBytes } = require('node:crypto');

function setup(directory = 'demo') {
  fs.mkdirSync(directory, { mode: 0o700 }); // Refuse to overwrite existing identities.
  const psk = randomBytes(32).toString('hex');
  const server = { host: '127.0.0.1', port: 9443,
    peers: [{ id: 'peer-01', psk, operations: ['ping', 'message'] }] };
  const client = { host: '127.0.0.1', port: 9443, id: 'peer-01', psk };
  for (const [name, config] of [['server', server], ['client', client]]) {
    fs.writeFileSync(path.join(directory, name + '.json'), JSON.stringify(config, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  }
  return { server, client };
}
if (require.main === module) {
  try { setup(process.argv[2] || 'demo'); console.log('Created private server/client configs. Keep both secret.'); }
  catch (e) { console.error(e.message); process.exitCode = 1; }
}
module.exports = { setup };
