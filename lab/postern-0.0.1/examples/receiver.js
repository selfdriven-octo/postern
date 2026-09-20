'use strict';

const { createChannelServer } = require('../server');
const { load } = require('../lib/config');

// Run from the project root: node examples/receiver.js demo/server.json
// This opt-in example prints message content. The default server only logs metadata.
Promise.resolve().then(() => {
  const channel = createChannelServer(load(process.argv[2] || 'demo/server.json'), {
    onMessage: message => {
      console.log(JSON.stringify({ event: 'message', ...message }));
    }
  });
  channel.server.on('error', error => { console.error(error.message); process.exitCode = 1; });
  return channel.listen().then(address => {
    console.log(JSON.stringify({ event: 'listening', ...address }));
    const stop = () => channel.close();
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  });
}).catch(error => { console.error(error.message); process.exitCode = 1; });
