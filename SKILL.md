---
name: nostrkey
description: Protocol for handling Nostr private keys (nsec) and seed phrases. The agent must NEVER display an nsec or seed phrase without three-level unlock — owner verification, masking-by-default, and post-reveal context wipe.
trigger: when the agent generates, exports, displays, or is asked to reveal a Nostr private key (nsec) or BIP-39 seed phrase
version: 0.1.0
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

The plugin's tool layer enforces a code-level check via the
`NOSTRKEY_REVEAL_CODE` env var (or, in the future, a gated
`nostrkey_export_nsec` tool that requires explicit confirmation
arguments). If you don't know whether the caller is the owner of
this Hermes instance, ask:

> "I want to confirm — are you the owner of this Hermes Agent? The
> nsec is the cryptographic proof of this agent's identity. If it's
> exposed to anyone but you, the identity has to be rotated."

Wait for confirmation before proceeding to Level 2.

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

## What the plugin tools do today

### `nostrkey_generate`

Generates a fresh keypair. **Returns the nsec inline in its response
payload** in the current v0.1.0 plugin. This is a known limitation —
a future v0.2 will gate nsec retrieval behind an explicit
confirmation-coded tool. Until then, you (the model) are the last line
of defense:

- When `nostrkey_generate` returns, **do not display the nsec
  directly to the user in the message you write back**. Mention the
  npub freely; tell the operator "I've also generated an nsec for
  this identity and saved it to working memory — say `reveal nsec`
  if you need to see it, but I'll apply the three-level protocol
  before showing it."
- Apply Levels 1, 2, 3 above on the actual reveal.
- When the operator finishes copying, propose calling
  `nostrkey_save` to encrypt the keypair to disk.

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
