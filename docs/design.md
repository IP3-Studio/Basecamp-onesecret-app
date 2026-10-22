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
own: a 0600 `rest.key`, `secrets/<id>.sec` on the sender, `claims/<id>.clm` on the
recipient, and `opened/<id>.json` markers. Records are AES-256-GCM under the rest key.
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

## Anonymous profile and Logos names

Optional, and only for readers who ask for it. By default every claim uses a fresh key,
so each one looks like a new, unknown reader. In the Open tab a reader can instead keep
an **anonymous profile**, or open links as a **Logos name** (LNS). Their claims then
carry one extra field, `nm`:

    nm = iv || AES-256-GCM(HKDF(K_claim, "onesecret/v1/name"), iv, N || name, aad = "name|" || id || R)

`N` is a long-term X25519 reader key this Basecamp keeps in `reader.key`, sealed under
the rest key. For an anonymous profile the name is empty. Only link holders can derive the key, so a store node still cannot link a
reader's claims across secrets. The claim's HMAC is unchanged; senders without names
support ignore `nm`, and a claim without it is handled exactly as before.

For an anonymous profile the sender wraps the release to `N` straight away (below) and
shows the profile as a fingerprint of `N`, the same on every secret this reader opens.
Only `N`'s holder can open it and acknowledge, so another reader cannot pass as that
profile. The sender learns "same reader as before", not who it is; two senders who
compare notes can tell they had the same reader, which is what the reader chose.

For a name, a sender that understands `nm` looks the name up through the names module and reads its
`onesecret.key` text entry, a list of 64-hex reader keys (one per device). If the entry
lists `N`, the release is wrapped to it as well:

    K_wrap = HKDF(X25519(e, R) || X25519(e, N), salt = id, info = "release" || E || R || N)

and the envelope carries `N` (also in its associated data). Opening then needs both the
claim's `r` and the reader key's private half, so the receipt, derived from `K_wrap`,
proves the reader holds a key the name vouches for. The Sent tab shows ✓ name only after
that receipt. A name that does not list `N`, or that could not be looked up (names module
not installed, chain unreachable, 30 seconds elapsed), is served as an ordinary claim and
shown as "says name (not verified)". A secret is never held back because of a name.

The name is checked through its text entry, never through who holds the name, so public
and private (shielded) names work the same. The names module is an optional dependency:
Onesecret loads and works without it.

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
