# Basecamp Onesecret

> **Disclaimer.** This is a personal, experimental hobby project. It is not an
> official Logos product. Not audited. It is provided as is, with no warranty of
> any kind and no affiliation with or endorsement by any of the projects it
> interoperates with. See [License](#license).

An unofficial read-once secret app for the Basecamp desktop shell, in the spirit of
1ty.me and Onetime Secret. You paste a secret and get a link. Whoever opens the link
first gets the secret, once. There is no server. Your own Basecamp holds the only key
and destroys it on that first read.

It is a `ui_qml` module: a QML view rendered by Basecamp, with a process-isolated C++
backend that does the cryptography and talks to Logos Messaging through Basecamp's
delivery module.

## How it works

The secret is encrypted on your machine with a key split in two. One half travels in
the link. The other half stays on your Basecamp. When the recipient pastes the link
into their Onesecret, their app asks yours for the second half over Logos Messaging.
Your app answers once, wrapped to a one-off key that only that recipient can open, then
wipes everything it held. Anyone who asks later is told the secret is gone.

Messages that crossed the network stay on the fleet's store nodes for about three
days. They are encrypted to keys that both sides have erased, so they cannot be read.

## The one rule

Your Basecamp is the only place the secret exists, so the recipient's request has to
reach it while Basecamp is running with Onesecret loaded. If your laptop is closed when
the recipient opens the link, their request waits on the network and your app answers
it the next time it starts. The network keeps each request and answer for about three
days, and the recipient's app repeats its request whenever it is open, for up to two
weeks. The two of you need to be online at some point before the secret expires, and
you need to return within about three days of one of their requests.

Basecamp does not reopen apps at launch. Open Onesecret each time you start Basecamp
if you have secrets waiting to be read.

## What self-destruct means here

- On the first read your Basecamp destroys the release key and the encrypted secret.
  It keeps a small record so later requests get an authenticated "already opened".
- The recipient's app destroys its keys after showing the secret and refuses to show it
  again.
- The recipient can still copy or photograph what they saw.
- Whoever opens the link first wins. If someone else might see the link on the way,
  set a passphrase and send it by a different route.

## Install

Download the `.lgx` for your platform from the
[latest release](../../releases/latest):

| Asset | Platform |
|---|---|
| `onesecret_ui-darwin-arm64.lgx` | macOS Apple Silicon |
| `onesecret_ui-linux-x86_64.lgx` | Linux x86_64 |
| `onesecret_ui-linux-aarch64.lgx` | Linux ARM64 |

In Basecamp open **Modules**, click **Install LGX Package**, select the file, and
**Load** it. Requires Basecamp 0.3.2 or later. Release files are unsigned; each one
ships with a `.sha256` file to compare against.

CLI alternative:

```bash
BASECAMP_DIR="$HOME/Library/Application Support/Logos/LogosBasecamp"   # macOS
# BASECAMP_DIR="$HOME/.local/share/Logos/LogosBasecamp"                # Linux

lgpm --modules-dir "$BASECAMP_DIR/modules" \
     --ui-plugins-dir "$BASECAMP_DIR/plugins" \
     --allow-unsigned \
     install --file onesecret_ui-darwin-arm64.lgx
```

Both sender and recipient need Basecamp with Onesecret installed and loaded, on the
same network preset.

## Use

**Send.** Create tab: type the secret, pick how long it may wait (1, 24, 48 or 72 hours,
or a custom value from 1 hour to 14 days), add a passphrase if you want one, click
Create link. Copy the link and send it over any channel. The Sent tab shows each
secret's state: Pending, Key released (read not yet confirmed), Opened with the time and
the recipient's device fingerprint, Expired, Burned. Burn destroys a pending secret
immediately.

**Receive.** Open tab: paste the link, add the passphrase if you were given one, click
Open. If the sender's Basecamp is online the secret appears within seconds. If it is
offline the request waits; you can close the app and come back. The secret is shown
once, in a panel you close deliberately. Copy it before closing if you need to keep it.

## Network preset

Two public presets exist and both parties must use the same one:

- `logos.dev` (default). Open to anyone, no membership needed.
- `logos.test`. The preset the Basecamp Chat app uses. Since October 2026 sending on
  it needs a funded RLN membership, which the RLN Membership app registers.

If another app such as Chat already started the delivery node, Onesecret uses that node
and inherits its preset. The footer shows which preset is live.

## Limits

- No server, so no always-on availability. See the one rule above.
- Text only, up to 64 KB.
- The recipient needs Basecamp and this module. There is no browser page.
- The fact that a secret was exchanged, its size and rough time are visible to nodes on
  the network. The content is not.
- Any other loaded Basecamp module sees the same network traffic and could send junk
  requests. It cannot read the secret without the link.
- Overwriting a file is not physical erasure on an SSD. The pending copy is encrypted
  under a local key, and the sender's disk never holds the link half of the key.
- This runs on Logos testnet infrastructure with no uptime promise.

## Protocol

See [docs/design.md](docs/design.md) for the full design and
[docs/testing.md](docs/testing.md) for how it was tested.

## Build from source

Requires Nix with flakes.

```bash
git clone https://github.com/IP3-Studio/Basecamp-onesecret-app
cd Basecamp-onesecret-app
nix build                      # compile the plugin
nix build .#lgx-portable       # package a shareable .lgx for your platform
nix run .                      # run it in the standalone dev host
```

The crypto layer has a host-side self-test against any OpenSSL 3:

```bash
clang++ -std=c++17 -Isrc -I/opt/homebrew/opt/openssl@3/include src/crypto.cpp tests/crypto_selftest.cpp \
  -L/opt/homebrew/opt/openssl@3/lib -lcrypto -o /tmp/selftest && /tmp/selftest
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
