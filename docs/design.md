# Design

## Scope

One Basecamp `ui_qml` module that does what 1ty.me does without a server. The sender's
Basecamp is the only holder of the secret. The first authenticated request gets exactly
one release. After that the sender destroys the key, so no copy that could be opened
exists anywhere.

Out of scope for v1: holding the secret while the sender's Basecamp is uninstalled or
never returns, files, payloads over 64 KB, a clickable deep link, sending the link from
inside the app.

## Why this shape

The installed Logos stack has nowhere to park a secret for an absent sender. Logos
Storage replicates only from online nodes and has no delete. The chat module starts a
new identity on every launch. The delivery module sends every message as non-ephemeral
and the fleet's store nodes keep them for about three days. So the sender's own machine
holds the secret, and "self-destruct" means destroying keys, since the network cannot
delete bytes.

Store catch-up in delivery module 0.3 makes the handshake asynchronous. A node that
restarts replays what it missed, so the sender and the recipient do not need to be online
at the same time.

## Keys and link

At create time the backend draws `K_link` (32 bytes, goes only in the link), `K_rel`
(32 bytes, stays only on the sender) and a 12-byte nonce. The data key is
`HKDF-SHA256(salt = K_link || passkey, ikm = K_rel, info = "onesecret/v1/dek")`, where
`passkey` is Argon2id of the passphrase when one is set, otherwise empty. The ciphertext
`C` is AES-256-GCM over `{name, body}` with the secret id as associated data.

From `K_link` alone both sides derive the id (16 bytes, base32), the content topic
`/logos-onesecret/1/s-<id>/json` and an HMAC key `K_claim`.

Link: `os1_` + base64url(`0x01` || `K_link` || first 8 bytes of SHA-256(C) || CRC-8),
60 characters. The commitment lets the recipient reject substituted content. The CRC
turns a paste typo into an immediate "invalid link".

The sender never writes `K_link` to disk. A seized sender machine holds ciphertext it
cannot open once the link has left it.

## At rest

The backend keeps its state under Basecamp's module data directory, in a folder of its
own: `secrets/<id>.sec` on the sender, `claims/<id>.clm` on the recipient, `reader.key`
once a reader has an identity, and `opened/<id>.json` markers. Records are AES-256-GCM
under one at-rest key.

Where that key lives decides what the encryption is worth. On macOS it is an item in the
user's login Keychain (service "Logos Onesecret", one item per data directory), written
and read by the backend process; the Keychain's access control keeps other processes
from reading it without the user's consent. A `rest.key` file from an earlier version is
moved into the Keychain and wiped at the first start. On Linux and Windows there is no
platform store yet and the key stays in a 0600 `rest.key` file beside the records, which
protects against exported or synced copies of the folder and nothing more: anyone with
the user's file access, including any other Basecamp module, can read it. Disk
encryption is the control there. The footer says which one is in use.

Two limits of the Keychain route: every Basecamp plugin backend runs inside the same
`ui-host` binary, so the Keychain cannot tell plugins apart, and a Basecamp upgrade may
make macOS ask once whether the new binary may use the item.

Next step, not built: wrap the at-rest key under a key held on a hardware token, so the
app's records cannot be opened without the token present. In this ecosystem that is
Keycard through Basecamp's keycard module; it needs that module's contract and a start-up
unlock flow.
Writes go to a temp file, fsync, then rename. Wipes overwrite with zeros, fsync and
unlink. A tombstone with the id, state, timestamps and the claimant's fingerprint stays
for 30 days so later requests get an authenticated answer.

## Messages

All messages are JSON on the secret's content topic, each with a fresh random `from` so
a shard observer cannot link one sender's secrets together.

1. **claim** (recipient): ephemeral X25519 public key `R`, a 16-byte nonce `n`, and
   `HMAC(K_claim, "claim" || id || R || n)`. Repeated while unanswered: every ten minutes
   on the first day, hourly after that, for up to two weeks.
2. **release** (sender, first valid claim only): ephemeral `E`,
   `K_wrap = HKDF(X25519(e, R), salt = id, info = "release" || E || R)`, and AES-256-GCM
   over `flags || argon_salt || K_rel || C` under `K_wrap`. The released state, `R` and
   the envelope are written to disk atomically before the message is published; `K_rel`
   and `C` are wiped right after. A repeat claim with the same `R` gets the identical
   envelope again. A claim with a different `R` gets a **gone**.
3. **open** (recipient): unwrap with `r`, check the ciphertext commitment from the link,
   derive the data key, decrypt, show once, wipe `r`, `K_link` and the stored claim.
4. **ack** (recipient): `HMAC(HKDF(K_wrap, "ack"), "ack" || id || R)`. Only the party that
   decrypted can produce it. The sender then wipes the envelope and marks Opened.
5. **gone** (sender): reason (opened, expired, burned) with
   `HMAC(K_claim, "gone" || id || reason || at || R || n)`, so a bystander cannot forge it.

Duplicates are dropped by message hash. Messages recovered from the store after a
restart are handled like live ones.

## Delivery glue

The backend arms the delivery module's events once, then probes
`getAvailableNodeInfoIDs`. If that succeeds another app owns the node and Onesecret uses
it, inheriting its preset. Otherwise it creates one with
`{"mode":"Core","preset":"logos.dev"}` and starts it. Subscriptions retry six times at
three-second intervals. `getConnectionStatus` drives the footer. Claim beacons wait for
a connected node.

The config must be the layered shape. A bare top-level `logLevel` routes through the
legacy flat parser, which pins the p2p port to 60000 and breaks a second instance on one
machine.

## Several readers

A secret carries a reader count, 1 by default and up to 50. Each distinct claimant key
gets its own release, derived with its own ephemeral key, so readers cannot open each
other's envelopes. The sender keeps `K_rel` and `C` until the last allowed reader has
been served, then wipes them in the same atomic write that records that reader. Receipts
are per reader; the Sent tab lists each one with its device fingerprint. A reader who
asks again gets their own envelope again. Anyone beyond the count gets an authenticated
"gone". The guarantee is therefore: destroyed once N different people have each read it
once, and it is any N holders of the link, not chosen ones.

## Names and profiles

See [names.md](names.md): the anonymous profile, names as domains, DNS verification (off
by default), the sealed name tag in the claim, the version 2 link whose claim HMAC covers
the tag, and the two-key wrap of the release.

## Expiry

Presets of 1, 24, 48 and 72 hours, or a custom 1 hour to 14 days. The secret's lifetime
is independent of the network's three-day message retention: the recipient's app keeps
re-asking, so the sender finds a recent request on return however long the secret lives.

## Alternatives considered

- A custodian design with a second always-on node and split keys. Same availability as
  the chosen design unless the second node exists, with roughly twice the code.
- A design inside the chat module's conversations. Strongest wire crypto, but the chat
  module starts a new identity on every launch, so any restart would destroy unopened
  secrets.
- Ciphertext in the network and the key in the link. Whoever holds the link can fetch
  the archived ciphertext any number of times.
- Logos Storage as the holder. No self-destruct, and replicas serve only from online
  nodes.

## Residual risks

- The recipient can copy or photograph the text while the panel is open.
- The text sits in the view's JavaScript heap until the process exits.
- A forensic recovery of the sender's overwritten file, plus the local rest key, still
  needs the link to decrypt anything.
- A forensic recovery of the recipient's wiped claim, plus the rest key, plus the
  archived release from the fleet within three days, could reconstruct the secret. The
  recipient saw it anyway.
- Any loaded Basecamp module can send junk claims. Each costs one HMAC check.
- A future Basecamp that enforces inter-module access policies would need Onesecret
  listed as an allowed caller of the delivery module.
