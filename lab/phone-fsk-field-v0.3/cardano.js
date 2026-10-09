'use strict';
// Deliberately narrow adapter: submit COMPLETE already-signed transaction CBOR only.
// No keys, wallets, transaction construction, or signing performed here.
async function submitSignedCbor(cbor, options) {
  const endpoint = options?.endpoint;
  if (!endpoint) throw new Error('Explicit Cardano submit endpoint required');
  if (!Buffer.isBuffer(cbor) || !cbor.length || cbor.length > 16384) throw new Error('Invalid signed CBOR file size');
  const url = new URL(endpoint);
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(options.allowLocalHttp && local && url.protocol === 'http:')) {
    throw new Error('HTTPS required for submit endpoint (except explicit localhost test)');
  }
  if (url.username || url.password) throw new Error('Credentials in URL not allowed');
  const headers = {'content-type':'application/cbor', 'accept':'text/plain, application/json'};
  if (options.projectId) headers.project_id = options.projectId;
  const response = await fetch(url.toString(), {
    method:'POST', headers, body:cbor, redirect:'error', signal:AbortSignal.timeout(options.timeoutMs ?? 15000)
  });
  const responseBody = (await response.text()).slice(0, 2048);
  if (!response.ok) throw new Error(`Submit API HTTP ${response.status}: ${responseBody}`);
  return {httpStatus:response.status, response:responseBody};
}
module.exports = {submitSignedCbor};
