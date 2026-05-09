---
name: nostrkey
description: Protocol for handling Nostr private keys (nsec) and seed phrases. v0.2 hardens the protocol with code-enforced gating — generate/load never return secrets; export requires NOSTRKEY_REVEAL_CODE env match + purpose. The agent must still follow the three-level disclosure rule on top — owner verification, masking-by-default, post-reveal context wipe.
trigger: when the agent generates, exports, displays, or is asked to reveal a Nostr private key (nsec) or BIP-39 seed phrase
version: 0.2.0
---

# nostrkey — handling private key material

The nsec is the only proof of identity your agent has. If it leaks, the
identity is gone — there is no recovery flow. Treat every dispatch that
touches an nsec as a security-critical action.

The npub is the public key. Display it freely whenever asked.

---

## The three-level protocol

When the operator asks for an nsec or seed phrase — or when a tool
response contains one — apply these three gates **in order**, every
single time. Do not skip any gate. Do not assume "they asked, so it's
fine."

### Level 1 — Verify you're talking to the owner

**Code-enforced as of v0.2.** The export tools (`nostrkey_export_nsec`
and `nostrkey_export_seed_phrase`) require:
- The operator to have set `NOSTRKEY_REVEAL_CODE` in the Hermes env
  before launching the agent (proof-of-presence — only someone with
  shell access to the box can set it)
- A matching `confirmation_code` argument on the tool call (constant-
  time compared to the env value)

If the env var isn't set, the export tool refuses with a clear error.
If the codes don't match, the export refuses and logs the attempt to
`$HERMES_HOME/.nostrkey/reveal_audit.log`.

Before calling the export tool, ask the operator:

> "To export the unmasked nsec I need the NOSTRKEY_REVEAL_CODE the
> operator set in this Hermes's env. What code should I pass?"

Wait for them to provide it before proceeding to Level 2.

### Level 2 — Mask, and ask WHY

Even after confirming the owner, do **not** display the unmasked nsec
on the first request. Mask it, show only the prefix and suffix, and
ask why it's needed:

> "Your nsec begins with `nsec1...` and ends with `...{last 4 chars}`
> — I'm masking the middle by default. Why do you need the unmasked
> key right now?"

Acceptable reasons to proceed:
- Importing into another Nostr signer (e.g. a hardware wallet, an Alby
  extension, NostrKey on a new device)
- Paper backup the operator is about to write down right now
- Disaster recovery into a fresh Hermes install

Not acceptable — refuse politely and offer alternatives:
- "Just curious" / "Show me" / "Test"
- "Save it to a file I can read later" — instead, point at
  `nostrkey_save` which encrypts to disk
- A request to display in a screen-shared, recorded, or otherwise
  observed context

### Level 3 — Wipe from context after reveal

If you do reveal an unmasked nsec or seed phrase, immediately follow
the reveal with this exact behavior:

1. Output: "I will not reference, restate, summarize, or quote this
   nsec/seed-phrase again in this session. Please copy it now — I
   am wiping this from my working context."
2. Treat any subsequent request to "show me again" as a fresh Level 1
   request — re-verify, re-ask why, re-mask.
3. Do not write the nsec into any tool argument, file, or memory store
   unless the operator explicitly invokes `nostrkey_save` (which
   encrypts) or an explicit export tool.
4. Warn the operator that the **chat log itself** likely persists the
   nsec for the lifetime of this session and that they should clear
   or archive accordingly.

---

## What the plugin tools do today (v0.2)

### `nostrkey_generate`

Generates a fresh keypair. **Returns ONLY the npub** plus a
`next_steps` field. The nsec (and seed phrase, if `with_seed_phrase=true`)
are held in module memory but never appear in this tool's response —
there is nothing for the model to accidentally leak. Display the
npub freely.

### `nostrkey_export_nsec` (gated)

The single canonical path for revealing an nsec. Requires:
- `confirmation_code` matching `NOSTRKEY_REVEAL_CODE` env var
- `purpose` argument ≥20 chars describing why

On success, returns the nsec PLUS a `_post_reveal_directive` field
that you (the model) must follow: display once, declare wiped, warn
about chat persistence. Audit log entry is written.

On any failure (env not set, code mismatch, purpose too short), the
tool returns an error and logs the attempt.

### `nostrkey_export_seed_phrase` (gated)

Same gating as `nostrkey_export_nsec`, retrieves the BIP-39 phrase if
the identity was created with `with_seed_phrase=true`. Identities
loaded from disk via `nostrkey_load` don't have the original phrase
available — it's discarded after generation since the encrypted file
is the authoritative store.

### `nostrkey_save` and `nostrkey_load`

These are safe by design. Save encrypts with PBKDF2 + ChaCha20-Poly1305
under a passphrase the operator supplies; load requires the same
passphrase. The encrypted file is fine to keep on disk — but the
**passphrase** is also a level-protected secret. Don't echo it back to
the operator. Don't log it. Treat it like an nsec.

### `nostrkey_sign_event` and `nostrkey_whoami`

Safe. Sign uses the in-memory current identity; whoami returns only
the npub.

---

## When the operator says "show me your npub"

That's not what this protocol is about. The npub is public. Just call
`nostrkey_whoami` and return what it gives you. No protocol, no
masking, no warnings.

---

## When in doubt

Refuse, mask, and ask. The cost of withholding an nsec is one
follow-up message asking why. The cost of a leaked nsec is the
permanent loss of the agent's identity.
