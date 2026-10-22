# Testing

## Crypto self-test

`src/crypto.cpp` carries a self-test that runs at backend start and from
`tests/crypto_selftest.cpp` on the host. It checks the RFC 5869 HKDF vector, the RFC 4231
HMAC vector, AES-GCM round trip and tamper detection, X25519 agreement, base64url at
every length, link encode and decode with CRC detection, and Argon2id determinism. The
backend refuses to run if any check fails.

## Two-party protocol test

`tests/two-party.mjs` launches two isolated instances of the module builder's standalone
host and drives both through the QML inspector from logos-qt-mcp. Each instance gets its
own user directory and HOME, so the delivery module's persistence and the module's own
state are separate. The release Basecamp binary has no inspector; the same `.lgx` runs
in both.

```bash
nix build .#ui-dev -o result-ui-dev
ONESECRET_RUN=$PWD/result-ui-dev/bin/run-logos-standalone-ui \
ONESECRET_QML=$PWD/src/qml \
ONESECRET_WORK=$PWD/.two-party/run1 \
node tests/two-party.mjs
```

Steps, all against the live `logos.dev` fleet:

| Step | Checks |
|---|---|
| 0 | Presets and custom expiry values reach the backend; an out-of-range value disables Create |
| 1 | Create on A, open on B, A shows Opened with B's device fingerprint |
| 2 | Opening the same link again on B is refused |
| 3 | A link with one character changed is rejected before any network traffic |
| 4 | Passphrase: wrong rejected, right opens |
| 5 | Burn on A, B is told it was burned |
| 6 | A offline when B claims, A restarts 47 s later, A recovers the claim from the store, releases, B opens |
| 7 | A offline for the claim, then B offline for the release, both halves recovered after each side's own restart |
| 8 | A secret for two readers: B and C (a third instance) both read it, A lists two receipts with distinct fingerprints |
| 9 | A single-reader secret: B reads it, C is told it is gone |

Results on 22 October 2026: all ten steps pass on macOS (Apple Silicon) and, through the
`linux-two-party` workflow, on Linux x86_64 and Linux ARM64 runners. The online open takes
about two seconds end to end. After a restart, the stored messages arrive in a burst within
a second of the node connecting.

The Linux workflow runs on every push to `main` and on request. It builds the dev host with
Nix on the runner, runs the test against the live fleet, and uploads the screenshots and
logs as artefacts.

Screenshots and both instance logs land in the work directory.

## Not covered automatically

- Expiry (the minimum lifetime is one hour).
- A 64 KB body.
- The Basecamp Chat app owning the delivery node.

## Lessons from the first runs

- Stopping the standalone host's parent process leaves its backend child alive for a
  moment, long enough to answer a claim. The driver kills the process group and waits
  for every child to exit.
- A child declared inside a design-system `LogosFrame` lands in its content layout. A
  click-swallowing MouseArea there covered the dialog's buttons.
- A claim beacon sent before the node has peers fails with a transient error. Beacons
  now wait for the connected state.
