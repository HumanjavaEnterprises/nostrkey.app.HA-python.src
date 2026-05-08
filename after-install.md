# nostrkey for Hermes — installed ✓

Your Hermes Agent now has 5 tools in the `nostrkey` toolset:

- `nostrkey_generate` — create a fresh keypair
- `nostrkey_whoami` — print loaded npub
- `nostrkey_save` — encrypt + persist to disk
- `nostrkey_load` — decrypt + load from disk
- `nostrkey_sign_event` — sign a Nostr event

## First run

```text
> Generate me a Nostr identity, then save it.
```

The default save location is `$HERMES_HOME/.nostrkey/identity.nostrkey` —
encrypted with the passphrase you supply. If you lose the passphrase the
identity is gone; there is no recovery flow.

## Dependencies

This plugin vendors the `nostrkey` library and depends on:
`cryptography`, `bech32`, `mnemonic`, `websockets`. Hermes installs them
into its venv on first load. If imports fail, run:

```bash
uv pip install cryptography bech32 mnemonic websockets
```

inside the Hermes venv.

## Source

- This plugin: <https://github.com/HumanjavaEnterprises/nostrkey.app.HA-python.src>
- Underlying library (PyPI / OpenClaw): <https://pypi.org/project/nostrkey/>
- Docs: <https://loginwithnostr.com/hermes>
