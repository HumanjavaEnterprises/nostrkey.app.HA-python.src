"""Nostr event creation, serialization, and signing (NIP-01)."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field

from nostrkey._secp256k1 import schnorr_sign as _schnorr_sign
from nostrkey._secp256k1 import schnorr_verify as _schnorr_verify


@dataclass
class NostrEvent:
    """A signed Nostr event.

    Warning: Do not modify fields after signing — the signature will be invalid.
    """

    id: str
    pubkey: str
    created_at: int
    kind: int
    tags: list[list[str]]
    content: str
    sig: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "pubkey": self.pubkey,
            "created_at": self.created_at,
            "kind": self.kind,
            "tags": self.tags,
            "content": self.content,
            "sig": self.sig,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


@dataclass
class UnsignedEvent:
    """An unsigned Nostr event ready for signing."""

    kind: int
    content: str
    tags: list[list[str]] = field(default_factory=list)
    created_at: int = 0

    def __post_init__(self):
        if self.created_at == 0:
            self.created_at = int(time.time())


def serialize_event(pubkey: str, event: UnsignedEvent) -> str:
    """Serialize an event for hashing per NIP-01.

    Returns the JSON serialization: [0, pubkey, created_at, kind, tags, content]
    """
    return json.dumps(
        [0, pubkey, event.created_at, event.kind, event.tags, event.content],
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_event_id(pubkey: str, event: UnsignedEvent) -> str:
    """Compute the event ID (SHA-256 of the serialized event)."""
    serialized = serialize_event(pubkey, event)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def sign_event(private_key_hex: str, event: UnsignedEvent) -> NostrEvent:
    """Sign an unsigned event with a private key.

    Args:
        private_key_hex: The signer's private key in hex.
        event: The unsigned event to sign.

    Returns:
        A fully signed NostrEvent.
    """
    from nostrkey.keys import private_key_to_public_key

    pubkey = private_key_to_public_key(private_key_hex)
    event_id = compute_event_id(pubkey, event)

    sig = _schnorr_sign(bytes.fromhex(private_key_hex), bytes.fromhex(event_id))

    return NostrEvent(
        id=event_id,
        pubkey=pubkey,
        created_at=event.created_at,
        kind=event.kind,
        tags=event.tags,
        content=event.content,
        sig=sig.hex(),
    )


def verify_event(event: NostrEvent) -> bool:
    """Verify a signed event's signature."""
    unsigned = UnsignedEvent(
        kind=event.kind,
        content=event.content,
        tags=event.tags,
        created_at=event.created_at,
    )
    expected_id = compute_event_id(event.pubkey, unsigned)
    if not hmac.compare_digest(expected_id, event.id):
        return False

    try:
        return _schnorr_verify(
            bytes.fromhex(event.pubkey), bytes.fromhex(event.id), bytes.fromhex(event.sig)
        )
    except Exception:
        return False
