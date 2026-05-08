"""Hermes tool handlers for nostrkey.

Five tools share a module-level "current identity" so a Hermes session
can generate or load once and then sign / save without re-supplying keys
on every call. Restart the agent to clear it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

from nostrkey import Identity

from tools.registry import tool_error, tool_result


_current: Optional[Identity] = None


def _hermes_home() -> Path:
    return Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes")))


def _default_identity_path() -> Path:
    return _hermes_home() / ".nostrkey" / "identity.nostrkey"


def _set_current(identity: Identity) -> None:
    global _current
    _current = identity


def _require_current() -> Identity:
    if _current is None:
        raise RuntimeError(
            "No identity loaded. Call nostrkey_generate or nostrkey_load first."
        )
    return _current


# -----------------------------
# nostrkey_generate
# -----------------------------

NOSTRKEY_GENERATE_SCHEMA = {
    "type": "function",
    "function": {
        "name": "nostrkey_generate",
        "description": (
            "Generate a fresh Nostr keypair (nsec + npub) for this agent and "
            "make it the current identity. Optionally returns a BIP-39 seed "
            "phrase for paper backup."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "with_seed_phrase": {
                    "type": "boolean",
                    "description": "Also return a 12-word BIP-39 seed phrase. Default false.",
                    "default": False,
                },
            },
            "required": [],
        },
    },
}


def handle_nostrkey_generate(args: dict[str, Any], **kw) -> str:
    try:
        with_seed = bool(args.get("with_seed_phrase", False))
        if with_seed:
            identity, phrase = Identity.generate_with_seed()
            _set_current(identity)
            return tool_result({
                "npub": identity.npub,
                "nsec": identity.nsec,
                "seed_phrase": phrase,
                "warning": "Save the seed phrase offline. It is the only recovery path.",
            })
        identity = Identity.generate()
        _set_current(identity)
        return tool_result({"npub": identity.npub, "nsec": identity.nsec})
    except Exception as e:
        return tool_error(f"nostrkey_generate failed: {type(e).__name__}: {e}")


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
