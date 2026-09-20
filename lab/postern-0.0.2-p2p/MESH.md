# A Postern mesh for a small team

A runbook for putting 8 people on a full mesh: no hub, no server, no authority.
Each node answers and calls on one UDP port, and each node decides for itself
who it will speak to and what they may ask.

At this size the numbers are comfortable. Eight people with one device each is
**28 links**, and every node holds **7 entries**. Adding a second device per
person makes it 16 endpoints and 120 links, which is still workable but is the
point where the roster stops fitting on one screen.

---

## 1. Everyone makes a key

On their own machine, each person runs:

```bash
node src/enroll.js keygen ana.key.json
node src/enroll.js pub   ana.key.json      # this is the only part they send you
```

The `.key.json` file never leaves the machine. It holds the private key and is
written `0600`. Only the 64-character public key is shared.

## 2. One person assembles the roster

```bash
node src/roster-cli.js init roster.json
node src/roster-cli.js add-device roster.json ana ana-laptop <anapub> \
  --addr 203.0.113.7:51820 --ops ping,status,roster
node src/roster-cli.js add-device roster.json ben ben-laptop <benpub> \
  --ops ping,roster                         # no address: inbound only
```

A peer is a **device**, not a person, so a stolen laptop can be revoked without
touching that person's phone. Devices are grouped under a person, so revoking
someone is one obvious edit.

`--ops` is what *you* grant that device when it calls you. Grant the least each
one needs; there is no default.

`--addr` is where to send a first packet. Omit it for a peer that can only be
called *by* others — a laptop behind NAT, say. As long as one side has an
address, the channel opens.

## 3. Verify the roster together

```bash
node src/roster-cli.js list roster.json
```

```
roster v3   fingerprint BP9B-M5T4-PDDG
```

Send the roster file to everyone, then get on a call and **read the fingerprint
aloud**. If all eight hear their own screen read back, everyone holds the same
keys and the same grants. If one person reads a different number, stop and find
out why before anyone runs a node.

The fingerprint covers keys, grants and revocations — **not addresses**. People
can roam, and their address can be corrected, without the number moving and
without the team re-verifying:

```bash
node src/roster-cli.js addr roster.json ben-laptop 198.51.100.4:51820
# routing only — fingerprint unchanged, no re-verification needed
```

## 4. Everyone runs a node

```bash
POSTERN_KEY=ana.key.json POSTERN_ROSTER=roster.json POSTERN_PORT=51820 node src/peer.js
```

```
[postern] ana/ana-laptop listening udp/51820
[postern] roster v3  fingerprint BP9B-M5T4-PDDG  (7 peers)
```

Each node dials every peer that has an address and answers everyone else. A peer
can check that another agrees with it at any time:

```
roster -> { known: true, version: 3, fingerprint: "BP9B-M5T4-PDDG" }
```

That operation exists because a mesh has no authority to push an update. The
useful thing is not to prevent disagreement but to make it **visible**.

## 5. Revoking

```bash
node src/roster-cli.js revoke roster.json --device ana-laptop   # one device
node src/roster-cli.js revoke roster.json --person ana          # everything of theirs
```

Distribute the new roster, then each node picks it up without restarting:

```bash
kill -HUP <pid>
```

A revoked key is refused on its **next packet**, and cannot open a new channel.

**This is the mesh's weak point, and it is worth being plain about it.** There is
no authority to push a revocation: it takes effect on each node when that node
updates. A colleague who has not pulled the new roster still trusts the revoked
key. The test suite asserts exactly this, because it is a property to manage,
not a bug to hide. In practice: revoke, send the roster, and confirm the new
fingerprint from all eight before you consider it done.

---

## Reachability, which is the real work

Eight laptops that sleep, roam and sit behind NAT will mostly not be reachable
by each other. Three ways through, in order of how much they cost:

1. **One peer with a stable address.** A small always-on box is a full peer that
   happens to always be up — not a hub. Everyone can reach it, and it holds no
   more authority than anyone else.
2. **Keep-alives.** Nodes send an empty encrypted packet every 25 s, under the
   usual ~30 s NAT UDP binding, so a pair that has spoken once keeps working.
3. **Hole punching through a rendezvous.** Works, but adds a third party that
   learns who is trying to reach whom. It is exactly the component this design
   avoids, so it is a deliberate trade, not an obvious upgrade.

What you should **not** do is put a hub in the middle that terminates every
channel. It would see all plaintext and all metadata, and it would be the single
box whose compromise exposes the team.

---

## What the mesh does not change

- Enrolment is still out of band, by a person, through a channel already trusted.
- Strangers still get silence.
- Each key still gets named operations and nothing more.
- Authenticated is still not authorised. An AI peer acting on a request needs
  its own authorisation layer above the channel.

## Where this would go next

Anchoring each device key to a KERI AID, with rotation and revocation as
verifiable events, would turn "everyone please update your file" into something
a node can verify for itself. It costs a dependency the current design
deliberately does not have — a real trade, and the one genuine answer to the
revocation-propagation problem above.
