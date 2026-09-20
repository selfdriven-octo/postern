'use strict';
const { constants } = require('node:crypto');
const { ALPN } = require('./protocol');
module.exports = Object.freeze({
  minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
  // Node's legacy external-PSK callback uses SHA-256 with TLS 1.3.
  ciphers: 'TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256',
  ecdhCurve: 'X25519', ALPNProtocols: [ALPN],
  secureOptions: constants.SSL_OP_NO_TICKET
});
