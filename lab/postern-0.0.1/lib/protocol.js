'use strict';

const { TextDecoder } = require('node:util');
const MAX_FRAME = 8192;
const ALPN = 'secure-node/1';
const decoder = new TextDecoder('utf-8', { fatal: true });

function exact(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k));
}

function validateRequest(value) {
  if (!exact(value, ['v', 'id', 'op', 'body']) || value.v !== 1 ||
      typeof value.id !== 'string' || !/^[0-9a-f-]{36}$/.test(value.id)) {
    throw new Error('Invalid request');
  }
  if (value.op === 'ping' && exact(value.body, [])) return value;
  if (value.op === 'message' && exact(value.body, ['text']) &&
      typeof value.body.text === 'string' && Buffer.byteLength(value.body.text) <= 4096) return value;
  throw new Error('Invalid operation or body');
}

function frame(value) {
  const body = Buffer.from(JSON.stringify(value));
  if (!body.length || body.length > MAX_FRAME) throw new Error('Frame too large');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(body.length);
  return Buffer.concat([header, body]);
}

// One request/response per connection. Storage is fixed, even for hostile lengths.
// TCP chunk boundaries do not affect parsing. Trailing bytes are rejected.
function reader(onValue, onError) {
  const header = Buffer.alloc(4);
  const body = Buffer.alloc(MAX_FRAME);
  let headerUsed = 0;
  let bodyUsed = 0;
  let length = null;
  let done = false;
  return chunk => {
    try {
      if (done) throw new Error('Extra frame');
      let offset = 0;
      if (headerUsed < 4) {
        const count = Math.min(4 - headerUsed, chunk.length);
        chunk.copy(header, headerUsed, 0, count);
        headerUsed += count;
        offset += count;
        if (headerUsed !== 4) return;
        length = header.readUInt32BE();
        if (length < 1 || length > MAX_FRAME) throw new Error('Invalid frame length');
      }
      const count = chunk.length - offset;
      if (bodyUsed + count > length) throw new Error('Trailing bytes');
      chunk.copy(body, bodyUsed, offset);
      bodyUsed += count;
      if (bodyUsed === length) {
        done = true;
        onValue(JSON.parse(decoder.decode(body.subarray(0, length))));
      }
    } catch (error) {
      done = true;
      onError(error);
    }
  };
}

module.exports = { MAX_FRAME, ALPN, exact, validateRequest, frame, reader };
