# Names and profiles

Design note for v0.3.0. It takes the anonymous profile and the sealed name tag from
pull request 3 by jefdiesel, and makes the verification step pluggable, with a DNS
verifier built in and switched off by default. No new build dependency.

## What a reader can choose

Nothing, which is the default. Every link you open uses a fresh key, and each one looks
to the sender like a new, unknown reader.

An anonymous profile. Your claims carry a long-term reader key, so a sender can tell it
is the same reader again without learning who. The profile is one identity shown to every
sender; two senders who compare receipts can tell they had the same reader.

A name. Today that is a domain you control, such as `alice.example.com`. Your claims carry
the name and your reader key. What the sender makes of it depends on the sender's own
verification setting below. A name with no dots is kept for a later verifier (Logos
names); it travels the same way and is shown as unverified until one exists.

## What a sender sees

The sender chooses how names are checked, in the Sent tab:

- **Off**, the default. Nothing is looked up. The receipt says `says alice.example.com
  (not verified)`. The release is bound to the reader's key all the same, so the receipt
  still proves it was the same device that asked.
- **DNS**. The sender queries the TXT record at `_onesecret.alice.example.com`. If it
  lists the reader's key, the receipt says `alice.example.com, DNS-verified` once the read
  is acknowledged. If it does not, or the lookup fails or takes too long, the claim is
  served as under Off.

A domain owner publishes one TXT record per device:

    _onesecret.alice.example.com.  TXT  "v=onesecret1 k=<64 hex of the reader key>"

The Open tab shows the exact record for this Basecamp.

## Wire changes

The claim gains one field, `nm`:

    nm = iv || AES-256-GCM(HKDF(K_claim, "onesecret/v1/name"), iv, N || name, aad = "name|" || id || R)

Only link holders can derive the key, so store nodes cannot read the name or link a
reader's claims across secrets. The name is empty for an anonymous profile.

Links move to version 2. For a version 2 link the claim's HMAC covers `nm` as well
(`"claim" || id || R || n || nm`, with `nm` empty when absent), so an observer on the
shard cannot strip a reader's name from a claim in transit. Version 1 links keep the old
HMAC. A reader on v0.2.0 cannot open a v0.3.0 link and is told the link is invalid; a
v0.3.0 reader opens v0.2.0 links as before.

When a reader key `N` is in play the release is wrapped to it as well:

    K_wrap = HKDF(X25519(e, R) || X25519(e, N), salt = id, info = "release" || E || R || N)

with `N` in the envelope and in its associated data. Opening needs both the claim's `r`
and the reader key's private half, and the receipt, derived from `K_wrap`, proves the
reader holds that key. With no `N` the bytes are identical to v0.2.0.

Compatibility: an old sender ignores `nm` and releases as today; an old reader never sends
`nm`; a new sender never wraps to `N` for it.

## Sender-side rules

A secret is never held back because of a name. A DNS lookup is bounded to five seconds,
at most three run at once, the queue is capped at 32 and anything beyond it is served
unverified, and answers are cached for ten minutes per name so a reader's repeated
beacons do not repeat the query.

The reader key is created the first time a reader turns the profile on or saves a name,
and kept in `reader.key` sealed under the rest key. If that file cannot be read, the
profile and the name are switched off with a message; the app still starts and still
serves the secrets it holds.

A reader key that is not a valid X25519 point makes the sender serve the claim without
the name rather than refuse it. A release wrapped to a key this Basecamp no longer holds
is reported as such in the Open tab rather than waited on.

## Trust and privacy limits

- A DNS query tells the sender's resolver, and the name's authoritative servers, that this
  sender looked that name up at that moment. That is why DNS verification is off by
  default and the setting says so.
- Plain DNS is not authenticated. A lying resolver or a hijacked zone can make a key look
  listed. The lookup does not validate DNSSEC. The tick therefore reads "DNS-verified",
  which is weaker than a chain-backed name would be.
- Verification binds a key to a name, never to a person. Whoever controls the zone
  controls the name.
- Any reader can type any name. Without verification the sender sees exactly that: what
  the reader said.

## The Logos names verifier

Pull request 3 by jefdiesel added a third setting, **Logos names**, merged in v0.3.1. A
name without a dot, such as `alice`, is a [Logos name](https://github.com/jefdiesel/logos-names).
The sender resolves it through the names module, an optional dependency that is not
bundled and not required, and reads the name's `onesecret.key` text entry, a list of
64-hex reader keys. If it lists the reader's key the release is bound to it and the
receipt reads `alice, Logos name verified`. The reader lists a key once with
`names set-text alice onesecret.key <key>`, which the Open tab shows.

Without the module, or when the lookup fails or exceeds its five-second bound, the claim is
served as under Off. Verification reads the name's text entry only, never who holds the
name, so public and private names work the same. The module's contract is generated from
its flake at build time, which is a build dependency on that repository.

A verifier answers one question: which reader keys does this name list? DNS and the names
module are the two so far.

## Tests

`tests/two-party.mjs` gains four steps. A local DNS responder in the test driver serves
the TXT record for a made-up domain, and the sender under test is pointed at it through
`ONESECRET_DNS_SERVER`, so the DNS-verified path runs end to end without touching real
DNS. The steps: anonymous profile across two secrets (same profile, bound and
acknowledged); a name with verification off (shown as said, not verified); a name with DNS
on and no record (served, not verified); a name with DNS on and a listed key (served,
bound, DNS-verified after the receipt); a Logos name with the names verifier on and no
names module installed (served, not verified).
