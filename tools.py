"""Hermes tool handlers for nostrkey (v0.2).

Seven tools share a module-level "current identity" so a Hermes session
can generate or load once and then sign / save without re-supplying keys
on every call. Restart the agent to clear it.

v0.2 hard fix: nsec and seed_phrase are NEVER returned by
``nostrkey_generate`` or ``nostrkey_load``. They are retrievable only
via the gated ``nostrkey_export_nsec`` / ``nostrkey_export_seed_phrase``
tools, which require ``NOSTRKEY_REVEAL_CODE`` env var + matching
``confirmation_code`` arg + ``purpose`` arg ≥20 chars. Failed and
successful exports both append to ``$HERMES_HOME/.nostrkey/reveal_audit.log``.
"""

from __future__ import annotations

import datetime
import json
import os
import secrets
from pathlib import Path
from typing import Any, Optional

from nostrkey import Identity

from tools.registry import tool_error, tool_result


_current: Optional[Identity] = None
_current_seed_phrase: Optional[str] = None  # set only when generate(with_seed_phrase=True)


def _hermes_home() -> Path:
    return Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes")))


def _default_identity_path() -> Path:
    return _hermes_home() / ".nostrkey" / "identity.nostrkey"


def _audit_log_path() -> Path:
    return _hermes_home() / ".nostrkey" / "reveal_audit.log"


def _audit(action: str, outcome: str, purpose: str = "") -> None:
    """Append a single line to the reveal audit log. Best-effort —
    never raises (audit failure must not block tool dispatch)."""
    try:
        path = _audit_log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        purpose_snip = (purpose or "").replace("\n", " ")[:200]
        line = f"{ts}\t{action}\t{outcome}\t{purpose_snip}\n"
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


def _set_current(identity: Identity) -> None:
    global _current
    _current = identity


def _require_current() -> Identity:
    if _current is None:
        raise RuntimeError(
            "No identity loaded. Call nostrkey_generate or nostrkey_load first."
        )
    return _current


def _check_reveal_code(supplied: str) -> tuple[bool, str | None]:
    """Constant-time compare against NOSTRKEY_REVEAL_CODE env. Returns (ok, error_msg)."""
    expected = os.environ.get("NOSTRKEY_REVEAL_CODE", "").strip()
    if not expected:
        return False, (
            "NOSTRKEY_REVEAL_CODE env var is not set on this Hermes instance. "
            "The operator must set it (in $HERMES_HOME/.env or the shell that "
            "launched Hermes) before any nsec or seed phrase can be exported. "
            "This is intentional: the env var is the operator's proof-of-presence."
        )
    supplied = (supplied or "").strip()
    if not supplied:
        return False, "confirmation_code is required and must be a non-empty string."
    if not secrets.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8")):
        return False, "confirmation_code does not match NOSTRKEY_REVEAL_CODE — refusing export."
    return True, None


# -----------------------------
# nostrkey_generate
# -----------------------------

NOSTRKEY_GENERATE_SCHEMA = {
    "type": "function",
    "function": {
        "name": "nostrkey_generate",
        "description": (
            "Generate a fresh Nostr keypair for this agent and make it the "
            "current identity. Returns ONLY the npub. The nsec (and seed "
            "phrase, if requested) are held in module memory — never returned "
            "by this tool. Retrieve them via the gated nostrkey_export_nsec "
            "or nostrkey_export_seed_phrase tools, which require "
            "NOSTRKEY_REVEAL_CODE env var + a matching confirmation_code "
            "argument + a purpose. Encrypt to disk via nostrkey_save."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "with_seed_phrase": {
                    "type": "boolean",
                    "description": "Also generate a 12-word BIP-39 seed phrase (held in memory; retrieve via nostrkey_export_seed_phrase). Default false.",
                    "default": False,
                },
            },
            "required": [],
        },
    },
}


def handle_nostrkey_generate(args: dict[str, Any], **kw) -> str:
    global _current_seed_phrase
    try:
        with_seed = bool(args.get("with_seed_phrase", False))
        if with_seed:
            identity, phrase = Identity.generate_with_seed()
            _set_current(identity)
            _current_seed_phrase = phrase
            return tool_result({
                "npub": identity.npub,
                "generated": True,
                "seed_phrase_available": True,
                "next_steps": (
                    "The nsec and 12-word seed phrase are in working memory. "
                    "To persist: call nostrkey_save with a strong passphrase. "
                    "To retrieve the nsec or seed phrase for one-time export "
                    "(e.g. paper backup, signer import): set NOSTRKEY_REVEAL_CODE "
                    "in the operator's env, then call nostrkey_export_nsec / "
                    "nostrkey_export_seed_phrase with confirmation_code + purpose."
                ),
            })
        identity = Identity.generate()
        _set_current(identity)
        _current_seed_phrase = None
        return tool_result({
            "npub": identity.npub,
            "generated": True,
            "next_steps": (
                "The nsec is in working memory. To persist: nostrkey_save with a "
                "strong passphrase. To retrieve the nsec for export: set "
                "NOSTRKEY_REVEAL_CODE in the operator's env, then call "
                "nostrkey_export_nsec with confirmation_code + purpose."
            ),
        })
    except Exception as e:
        return tool_error(f"nostrkey_generate failed: {type(e).__name__}: {e}")


# -----------------------------
# nostrkey_export_nsec  (gated)
# -----------------------------

NOSTRKEY_EXPORT_NSEC_SCHEMA = {
    "type": "function",
    "function": {
        "name": "nostrkey_export_nsec",
        "description": (
            "GATED retrieval of the current identity's nsec. Requires the "
            "operator to have set NOSTRKEY_REVEAL_CODE in the Hermes env, AND "
            "to provide it as confirmation_code, AND to articulate why the "
            "unmasked nsec is needed via the purpose arg (≥20 chars). "
            "Acceptable purposes: importing into another signer, paper backup, "
            "disaster recovery. Refuse curiosity / 'show me' / 'test'. "
            "Successful exports and failed attempts are both logged to "
            "$HERMES_HOME/.nostrkey/reveal_audit.log. After the nsec is in "
            "your context, follow the post-reveal directive in the response: "
            "display once, then declare it wiped from your working memory and "
            "warn the operator that the chat log itself persists secrets for "
            "the session lifetime."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "confirmation_code": {
                    "type": "string",
                    "description": "Must match the NOSTRKEY_REVEAL_CODE env var on this Hermes instance. Constant-time compared.",
                },
                "purpose": {
                    "type": "string",
                    "description": "Why the unmasked nsec is needed right now. Minimum 20 characters. Logged to the audit file.",
                },
            },
            "required": ["confirmation_code", "purpose"],
        },
    },
}


def handle_nostrkey_export_nsec(args: dict[str, Any], **kw) -> str:
    try:
        identity = _require_current()
    except RuntimeError as e:
        _audit("export_nsec", "no_identity_loaded")
        return tool_error(str(e))

    ok, err = _check_reveal_code(args.get("confirmation_code", ""))
    if not ok:
        _audit("export_nsec", "code_mismatch_or_missing", args.get("purpose", ""))
        return tool_error(err or "confirmation_code check failed")

    purpose = (args.get("purpose") or "").strip()
    if len(purpose) < 20:
        _audit("export_nsec", "purpose_too_short", purpose)
        return tool_error(
            "purpose must be at least 20 characters describing why the unmasked "
            "nsec is needed right now (e.g. 'importing into Alby browser extension', "
            "'paper backup before agent deployment')."
        )

    _audit("export_nsec", "ok", purpose)
    return tool_result({
        "nsec": identity.nsec,
        "purpose_logged": purpose,
        "_post_reveal_directive": (
            "The nsec is now in your context window. In your immediate next "
            "response: (1) display it ONCE so the operator can copy it, "
            "(2) declare the nsec wiped from your working context — refuse to "
            "restate, summarize, or quote it later in this session, (3) warn the "
            "operator that the chat log itself persists the nsec for the session "
            "lifetime and they should clear or archive accordingly. Treat any "
            "follow-up 'show me again' as a fresh request requiring a new export."
        ),
    })


# -----------------------------
# nostrkey_export_seed_phrase  (gated)
# -----------------------------

NOSTRKEY_EXPORT_SEED_PHRASE_SCHEMA = {
    "type": "function",
    "function": {
        "name": "nostrkey_export_seed_phrase",
        "description": (
            "GATED retrieval of the current identity's 12-word BIP-39 seed phrase, "
            "available only if the identity was created with "
            "nostrkey_generate(with_seed_phrase=true). Same gating as "
            "nostrkey_export_nsec: NOSTRKEY_REVEAL_CODE env + matching "
            "confirmation_code + purpose ≥20 chars. Logs to the audit file. "
            "Same post-reveal directive applies: display once, declare wiped, "
            "warn about chat persistence."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "confirmation_code": {"type": "string"},
                "purpose":           {"type": "string", "description": "Why the seed phrase is needed (paper backup is the canonical use). Min 20 chars."},
            },
            "required": ["confirmation_code", "purpose"],
        },
    },
}


def handle_nostrkey_export_seed_phrase(args: dict[str, Any], **kw) -> str:
    if _current_seed_phrase is None:
        _audit("export_seed_phrase", "no_seed_phrase_in_memory")
        return tool_error(
            "No seed phrase is held in memory. Generate the identity with "
            "nostrkey_generate(with_seed_phrase=true) to make a phrase available. "
            "Existing identities loaded from disk via nostrkey_load have the nsec "
            "but not the original 12-word phrase."
        )

    ok, err = _check_reveal_code(args.get("confirmation_code", ""))
    if not ok:
        _audit("export_seed_phrase", "code_mismatch_or_missing", args.get("purpose", ""))
        return tool_error(err or "confirmation_code check failed")

    purpose = (args.get("purpose") or "").strip()
    if len(purpose) < 20:
        _audit("export_seed_phrase", "purpose_too_short", purpose)
        return tool_error(
            "purpose must be at least 20 characters (e.g. 'paper backup before "
            "deploying to production', 'rotating to a hardware signer')."
        )

    _audit("export_seed_phrase", "ok", purpose)
    return tool_result({
        "seed_phrase": _current_seed_phrase,
        "purpose_logged": purpose,
        "_post_reveal_directive": (
            "The 12-word seed phrase is now in your context. Display it ONCE for "
            "the operator to write down on paper, then declare it wiped from your "
            "working memory and refuse to restate. The seed phrase is the only "
            "recovery path — if it's lost AND the encrypted identity file is lost, "
            "the identity cannot be recovered."
        ),
    })


# -----------------------------
# nostrkey_whoami
# -----------------------------

NOSTRKEY_WHOAMI_SCHEMA = {
    "type": "function",
    "function": {
        "name": "nostrkey_whoami",
        "description": (
            "Return the npub and public-key hex of the currently loaded "
            "Nostr identity. Errors if no identity is loaded — call "
            "nostrkey_generate or nostrkey_load first."
        ),
        "parameters": {"type": "object", "properties": {}, "required": []},
    },
}


def handle_nostrkey_whoami(args: dict[str, Any], **kw) -> str:
    try:
        identity = _require_current()
        return tool_result({
            "npub": identity.npub,
            "public_key_hex": identity.public_key_hex,
        })
    except Exception as e:
        return tool_error(str(e))


# -----------------------------
# nostrkey_save
# -----------------------------

NOSTRKEY_SAVE_SCHEMA = {
    "type": "function",
    "function": {
        "name": "nostrkey_save",
        "description": (
            "Encrypt and persist the currently loaded identity to disk. "
            "Default path is $HERMES_HOME/.nostrkey/identity.nostrkey. "
            "Requires a strong passphrase — there is no recovery if lost."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "passphrase": {
                    "type": "string",
                    "description": "Passphrase to encrypt the identity file.",
                },
                "filepath": {
                    "type": "string",
                    "description": "Override save path. Defaults to $HERMES_HOME/.nostrkey/identity.nostrkey.",
                },
            },
            "required": ["passphrase"],
        },
    },
}


def handle_nostrkey_save(args: dict[str, Any], **kw) -> str:
    try:
        identity = _require_current()
        passphrase = args.get("passphrase")
        if not passphrase or not isinstance(passphrase, str):
            return tool_error("passphrase is required and must be a string")
        path = Path(args.get("filepath") or _default_identity_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        identity.save(str(path), passphrase)
        return tool_result({"saved_to": str(path), "npub": identity.npub})
    except Exception as e:
        return tool_error(f"nostrkey_save failed: {type(e).__name__}: {e}")


# -----------------------------
# nostrkey_load
# -----------------------------

NOSTRKEY_LOAD_SCHEMA = {
    "type": "function",
    "function": {
        "name": "nostrkey_load",
        "description": (
            "Decrypt and load an identity from disk, making it the current "
            "identity. Default path is $HERMES_HOME/.nostrkey/identity.nostrkey."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "passphrase": {
                    "type": "string",
                    "description": "Passphrase that encrypted the identity file.",
                },
                "filepath": {
                    "type": "string",
                    "description": "Override load path. Defaults to $HERMES_HOME/.nostrkey/identity.nostrkey.",
                },
            },
            "required": ["passphrase"],
        },
    },
}


def handle_nostrkey_load(args: dict[str, Any], **kw) -> str:
    try:
        passphrase = args.get("passphrase")
        if not passphrase or not isinstance(passphrase, str):
            return tool_error("passphrase is required and must be a string")
        path = Path(args.get("filepath") or _default_identity_path())
        if not path.exists():
            return tool_error(f"identity file not found: {path}")
        identity = Identity.load(str(path), passphrase)
        _set_current(identity)
        return tool_result({"loaded_from": str(path), "npub": identity.npub})
    except Exception as e:
        return tool_error(f"nostrkey_load failed: {type(e).__name__}: {e}")


# -----------------------------
# nostrkey_sign_event
# -----------------------------

NOSTRKEY_SIGN_EVENT_SCHEMA = {
    "type": "function",
    "function": {
        "name": "nostrkey_sign_event",
        "description": (
            "Sign a Nostr event with the currently loaded identity. Returns "
            "the full signed event as JSON, ready to publish to a relay."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "kind": {
                    "type": "integer",
                    "description": "Nostr event kind (e.g. 1 for text note, 0 for profile metadata).",
                },
                "content": {
                    "type": "string",
                    "description": "Event content payload.",
                },
                "tags": {
                    "type": "array",
                    "description": "Nostr event tags as a list of string lists. Defaults to [].",
                    "items": {"type": "array", "items": {"type": "string"}},
                },
            },
            "required": ["kind", "content"],
        },
    },
}


def handle_nostrkey_sign_event(args: dict[str, Any], **kw) -> str:
    try:
        identity = _require_current()
        kind = args.get("kind")
        content = args.get("content")
        tags = args.get("tags") or []
        if not isinstance(kind, int):
            return tool_error("kind must be an integer")
        if not isinstance(content, str):
            return tool_error("content must be a string")
        event = identity.sign_event(kind=kind, content=content, tags=tags)
        return tool_result({"event": json.loads(event.to_json())})
    except Exception as e:
        return tool_error(f"nostrkey_sign_event failed: {type(e).__name__}: {e}")
