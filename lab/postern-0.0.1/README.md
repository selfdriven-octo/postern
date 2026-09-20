# postern-0.0.1

https://postern.network

**Node.js only: no WireGuard, npm packages, certificate files, external OpenSSL executable, or separate server software.**

The stack is **IP → TCP → TLS 1.3 → small structured messages**. Each client/server pair shares a different random 256-bit authentication key (PSK). Node's built-in TLS implementation performs the handshake and encryption. There is no custom encryption or certificate generator.

## Quick start

Install a maintained Node.js 24 or newer. Tested on Node 24.19.0 on Linux. All commands below use only Node; npm is optional.

From this project folder:

```bash
node scripts/setup.js
node server.js demo/server.json
```

In another terminal:

```bash
node client.js demo/client.json ping
node client.js demo/client.json message "Hello Octo"
```

Ping returns `pong`; a message returns `accepted`. Both responses include a generated request ID. By default the server logs metadata, not message content, and discards content after validation.

To see received messages, stop the default server and run this opt-in receiver:

```bash
node examples/receiver.js demo/server.json
```

Send another message. The receiver prints its content as JSON. Avoid sensitive text in command-line arguments because shell history and process listings may expose it; use the API instead.

Run the tests with `node --test`. No install or build step is needed.

The setup command creates a new `demo` directory and refuses to overwrite an existing one. To generate another pair, use `node scripts/setup.js identities` or another new path. Both output JSON files contain the shared secret. POSIX directories/files are created with permissions `0700`/`0600`. On Windows, apply restrictive NTFS ACLs to the directory. No generated secrets are included in this download.

## Use two machines directly

1. Generate a pair of configs on a trusted machine with `node scripts/setup.js identities`.
2. Place the source code and `server.json` on the server. Keep that config private.
3. In `server.json`, change `host` to the server's local interface address, or `0.0.0.0` to listen on all IPv4 interfaces, and add `"allowRemote": true`. Keep port `9443`, or choose another unused TCP port. On a cloud host, the bind address is commonly its private interface address, even when clients use an associated public IP.
4. Securely transfer **only that peer's `client.json`** to the client. It contains a secret, so do not email it publicly, put it in a shared repository, or copy it through an unauthenticated channel. In this file set `host` to the server's reachable public or LAN IPv4 address and match the port.
5. Permit inbound TCP on that port in the server's host firewall and cloud security group. Restrict source IPs where practical. If the server is behind a router, it needs an appropriate inbound port mapping or another reachable deployment. Client-side NAT normally needs no configuration. This package does not alter firewall or router rules.
6. Start `node server.js /path/to/server.json` on the server and run `node client.js /path/to/client.json ping` on the client.

Only the server needs an inbound listening port. Neither side needs a VPN. Direct addresses avoid a DNS dependency; this version deliberately accepts literal IPv4 addresses only.

An optional `address` field in each server `peers` entry restricts the client's observed source IPv4 address. With NAT this is its public egress address. Omit it for mobile clients with changing addresses; authentication still requires the peer's secret. An optional client `localAddress` selects its outgoing local interface.

For more peers, generate fresh pairs in different directories and copy each generated peer entry into the server's `peers` array, giving it a unique `id`. Set the corresponding client `id` identically. Never share one PSK among multiple peers. The server rejects duplicate IDs and duplicate keys. A peer's `operations` can be restricted to `["ping"]` or `["message"]`.

To revoke a peer, remove its entry and restart the server, which drops existing connections. For rotation, provision a fresh random secret to that peer and update the server, then restart. There is no automatic rotation or config hot reload. Run the service as a dedicated unprivileged OS account and keep Node and the OS patched.

## JavaScript API

CommonJS and `.then()` throughout:

```javascript
const { send } = require('./client');
const { load } = require('./lib/config');

send(load('demo/client.json'), 'message', { text: 'Hello Octo' })
  .then(response => console.log(response))
  .catch(error => console.error(error.message));
```

Receive with a short synchronous callback:

```javascript
const { createChannelServer } = require('./server');
const { load } = require('./lib/config');

const channel = createChannelServer(load('demo/server.json'), {
  onMessage: ({ peer, id, text }) => {
    console.log(JSON.stringify({ peer, id, text }));
  }
});

channel.listen()
  .then(address => console.log(address))
  .catch(error => console.error(error.message));
```

Peer identity comes from the successfully authenticated TLS connection, never a JSON claim. Keep the callback short and synchronous; a promise return is rejected rather than acknowledged as completed. This cannot cancel work a callback already started. To support durable asynchronous work, add a bounded durable queue and explicit acknowledgement/idempotency semantics.

`accepted` means the request passed validation and the synchronous callback returned. It does not promise storage or execution. There is no inbox, server push, automatic retry, or application-level duplicate detection. A lost response leaves the sender uncertain whether the request was accepted. Add durable deduplication before using messages to trigger non-idempotent actions.

## Security properties and trade-offs

| Area | Implementation |
|---|---|
| Encryption/authentication | Standard TLS 1.3 external-PSK authentication using one random 32-byte secret per pair |
| Cipher suites | ChaCha20-Poly1305 or AES-128-GCM, with SHA-256 |
| Ephemeral exchange | X25519; the client checks that it was negotiated |
| Certificate fallback | None; the client rejects certificate authentication and keeps `rejectUnauthorized: true` |
| Identity separation | Unique key per peer; permission check before application dispatch |
| Protocol | Required ALPN, four-byte length prefix, UTF-8 JSON, exact field sets |
| Size limits | 8192-byte frame and 4096-byte text |
| Connections | 64 concurrent sockets, 3-second TLS handshake timeout, 5-second absolute connection deadline |
| Handshake admission | PSK callback: global burst 40/refill 10 per second; per-peer burst 20/refill 5 per second |
| Key generation | Node `crypto.randomBytes(32)`; no passwords or embedded default secret |
| Logs | Metadata by default, no PSKs or message content |

The identity label is not secret and may be visible in the TLS ClientHello. Choose opaque labels if names are sensitive. A PSK authenticates possession of a shared secret: either holder can impersonate the other to a party using that same key. It does not provide digital signatures or non-repudiation. Keys in JSON are plaintext secrets at rest, protected by OS permissions; use suitable secret provisioning for your deployment. A random-looking format alone does not prove entropy: always generate keys with the provided setup tool or a cryptographically secure generator.

Node reports external-PSK TLS 1.3 handshakes as session reuse. The client does not cache or provide resumable sessions and checks that there is no peer certificate. The server dispatches only sockets for which its configured PSK callback selected a known peer and the handshake completed successfully. The application does not implement early data.

Removing WireGuard means TCP and TLS are reachable before peer authentication. This service is discoverable and responds during handshakes; it is not a silent network boundary. Its rate limits cannot prevent TCP/kernel work, all TLS parsing, or upstream bandwidth exhaustion. An attacker may also consume the global handshake budget and deny legitimate clients. Restrict network reachability and use upstream protection where availability matters.

TLS protects its records against network replay, not duplicate logical submissions by an authorised peer. Compromised endpoints, stolen PSKs, malicious authorised content, runtime vulnerabilities and supply-chain compromise remain relevant. Treat text as data; do not grant it execution authority or treat it as trusted instructions for AI. This version is not a post-quantum design.

This is a tested reference implementation, not an audited security product. Zero additional packages reduces installation and package-management dependencies; it does not remove Node, V8, Node's bundled OpenSSL, the OS or the network from the trusted stack. Node's documentation notes that TLS-PSK is a less-used path with historical implementation vulnerabilities; keep the runtime maintained and use it where secure per-peer key provisioning is practical.

## Verification

The automated suite uses actual loopback TLS sessions and requires only Node. It checks successful delivery, wrong/missing keys, unknown peers, server impersonation with a wrong key, TLS downgrade rejection, ALPN, source restrictions, permissions, message bounds, malformed framing, callback errors, rate limits and connection deadlines. Internet routing and host firewall rules need validation on your target deployment.

Source: [Node.js TLS pre-shared key documentation](https://nodejs.org/api/tls.html#pre-shared-keys), checked 14 September 2026. Cryptographic randomness uses [Node.js crypto](https://nodejs.org/api/crypto.html#cryptorandombytessize-callback).
