# NostrKey for Hermes Agent

**Give your Hermes Agent its own cryptographic identity.**

A Hermes plugin that wraps the `nostrkey` Nostr-identity library and
exposes it as five agent tools. Same crypto, same wire format, same npub
as the human-facing [NostrKey](https://nostrkey.com) browser extension
and the OpenClaw [`pip install nostrkey`](https://pypi.org/project/nostrkey/) SDK.

**v0.1.0** — five tools (generate, whoami, save, load, sign_event),
encrypted backup with PBKDF2 + ChaCha20-Poly1305, BIP-39 seed phrase
support, zero C dependencies.

## Why?

Hermes Agent is sovereign by design — no platform middleman, no shared
API key, runs on your own substrate. The missing piece is *identity*:
without a keypair your agent can't sign its work, can't send encrypted
DMs, can't persist a verifiable presence on the open Nostr network.
This plugin gives Hermes its own npub, the same kind a human user has.

A few things your Hermes can do once it has its own npub:

- **Sign its own work** — every published note is cryptographically
  signed. Anyone can verify it came from your agent, not an impersonator.
- **Send and receive encrypted messages** — private NIP-44 channels
  between your agent and its human, or between two agents.
- **Persist memory across sessions** — encrypted identity files survive
  container restarts. Your agent picks up with the same identity.
- **Publish to the Nostr network** — your agent is a first-class
  participant on any relay, not a wrapper around a borrowed account.

## Install

```bash
hermes plugins install HumanjavaEnterprises/nostrkey.app.HA-python.src
```

Or drop the repo directly into `$HERMES_HOME/plugins/`:

```bash
git clone https://github.com/HumanjavaEnterprises/nostrkey.app.HA-python.src \
  $HERMES_HOME/plugins/nostrkey
```

Then restart Hermes (or `/reload-skills`) and the `nostrkey` toolset
becomes available.

## Quick Start

In a Hermes chat:

```text
> Generate a Nostr identity for yourself and tell me the npub.
```

Hermes calls `nostrkey_generate`, holds the identity in module memory
for the rest of the session, and returns the npub. To make it persist
across restarts:

```text
> Save your identity. Use this passphrase: <strong-passphrase>
```

Next session:

```text
> Load your identity. Passphrase: <strong-passphrase>
```

Default save path is `$HERMES_HOME/.nostrkey/identity.nostrkey`.

## Tools

| Tool | Purpose |
|---|---|
| `nostrkey_generate` | Create a new keypair; optionally also a 12-word seed phrase |
| `nostrkey_whoami` | Return loaded identity's npub + public-key hex |
| `nostrkey_save` | Encrypt + persist current identity to disk |
| `nostrkey_load` | Decrypt + load identity from disk |
| `nostrkey_sign_event` | Sign a Nostr event with the current identity |

## Backup & Recovery

If the encrypted identity file is gone, that identity is gone. No reset
flow. Three backup options the underlying library supports:

1. **Seed phrase** — call `nostrkey_generate` with `with_seed_phrase: true`
   and write the 12 words on paper.
2. **Encrypted file** — `nostrkey_save` writes to disk; copy that file
   to backup storage.
3. **Encrypted token** — exposed by the library directly; a future tool
   may surface it.

## Security

- secp256k1 Schnorr signatures (BIP-340)
- NIP-44 encryption for messages
- ChaCha20-Poly1305 for identity-file encryption
- 600,000 PBKDF2 iterations on passphrase-derived keys
- Path-traversal validation on save/load file paths

## Sibling Project

The OpenClaw build of this same library lives at
[`nostrkey.app.OC-python.src`](https://github.com/HumanjavaEnterprises/nostrkey.app.OC-python.src)
and ships as `pip install nostrkey`. Both repos vendor the same core
crypto module — bugfixes need to land in both.

## License

MIT — see `LICENSE`.
