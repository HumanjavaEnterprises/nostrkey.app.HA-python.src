"""High-level OpenClaw identity management.

Provides a simple interface for creating, saving, loading, and using
a Nostr identity for AI entities.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_module
import json
import os
import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from nostrkey.events import NostrEvent, UnsignedEvent, sign_event
from nostrkey.keys import (
    _validate_hex_key,
    _validate_private_key,
    generate_keypair,
    hex_to_npub,
    hex_to_nsec,
    nsec_to_hex,
    private_key_to_public_key,
)


def _validate_path(filepath: str) -> str:
    """Resolve and validate a file path against path traversal attacks."""
    resolved = os.path.realpath(filepath)
    if ".." in resolved:
        raise ValueError(f"Invalid path: path traversal detected in {filepath!r}")
    return resolved


@dataclass
class Identity:
    """A Nostr identity for an OpenClaw AI entity.

    Holds the keypair and provides methods for signing events,
    saving/loading identity files, and accessing key formats.
    """

    _private_key_hex: str = field(repr=False)
    _public_key_hex: str = field(repr=False)

    @classmethod
    def generate(cls) -> Identity:
        """Generate a new random identity."""
        privkey, pubkey = generate_keypair()
        return cls(_private_key_hex=privkey, _public_key_hex=pubkey)

    @classmethod
    def generate_with_seed(cls, strength: int = 128) -> tuple[Identity, str]:
        """Generate a new identity with a BIP-39 seed phrase backup.

        The seed phrase is 12 words (or 24 with strength=256) that can
        restore this exact identity. Write them down. Store them safely.
        The same words always produce the same keys.

        Args:
            strength: 128 for 12 words, 256 for 24 words.

        Returns:
            Tuple of (Identity, seed_phrase_string).
        """
        from nostrkey.seed import generate_seed_phrase, seed_phrase_to_private_key

        phrase = generate_seed_phrase(strength)
        privkey_hex = seed_phrase_to_private_key(phrase)
        pubkey_hex = private_key_to_public_key(privkey_hex)
        identity = cls(_private_key_hex=privkey_hex, _public_key_hex=pubkey_hex)
        return identity, phrase

    @classmethod
    def from_seed(cls, phrase: str) -> Identity:
        """Restore an identity from a BIP-39 seed phrase (NIP-06).

        Args:
            phrase: A valid BIP-39 seed phrase (12 or 24 words).

        Returns:
            The derived Identity.

        Raises:
            ValueError: If the seed phrase is invalid.
        """
        from nostrkey.seed import seed_phrase_to_private_key

        privkey_hex = seed_phrase_to_private_key(phrase)
        pubkey_hex = private_key_to_public_key(privkey_hex)
        return cls(_private_key_hex=privkey_hex, _public_key_hex=pubkey_hex)

    @classmethod
    def from_nsec(cls, nsec: str) -> Identity:
        """Create an identity from an existing nsec."""
        privkey_hex = nsec_to_hex(nsec)
        pubkey_hex = private_key_to_public_key(privkey_hex)
        return cls(_private_key_hex=privkey_hex, _public_key_hex=pubkey_hex)

    @classmethod
    def from_hex(cls, private_key_hex: str) -> Identity:
        """Create an identity from an existing hex private key."""
        _validate_private_key(private_key_hex)
        pubkey_hex = private_key_to_public_key(private_key_hex)
        return cls(_private_key_hex=private_key_hex, _public_key_hex=pubkey_hex)

    @property
    def npub(self) -> str:
        """Public key in bech32 npub format."""
        return hex_to_npub(self._public_key_hex)

    @property
    def nsec(self) -> str:
        """Private key in bech32 nsec format."""
        return hex_to_nsec(self._private_key_hex)

    @property
    def public_key_hex(self) -> str:
        """Public key in hex format."""
        return self._public_key_hex

    @property
    def private_key_hex(self) -> str:
        """Private key in hex format."""
        return self._private_key_hex

    def sign_event(
        self, kind: int, content: str, tags: list[list[str]] | None = None
    ) -> NostrEvent:
        """Create and sign a Nostr event.

        Args:
            kind: Event kind (1 = text note, 0 = metadata, etc.).
            content: Event content string.
            tags: Optional list of tags.

        Returns:
            A signed NostrEvent ready for publishing.
        """
        unsigned = UnsignedEvent(kind=kind, content=content, tags=tags or [])
        return sign_event(self._private_key_hex, unsigned)

    def save(self, filepath: str, passphrase: str) -> None:
        """Save the identity to an encrypted file.

        Uses PBKDF2 key derivation and ChaCha20-Poly1305 AEAD encryption.

        Args:
            filepath: Path to save the identity file.
            passphrase: Passphrase to encrypt the private key.
        """
        if not passphrase:
            raise ValueError("Passphrase must not be empty")
        filepath = _validate_path(filepath)
        salt = secrets.token_bytes(16)
        key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 600_000)
        nonce = secrets.token_bytes(12)

        privkey_bytes = bytes.fromhex(self._private_key_hex)
        aead = ChaCha20Poly1305(key)
        encrypted = aead.encrypt(nonce, privkey_bytes, salt)

        data = {
            "version": 3,
            "npub": self.npub,
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "encrypted_nsec": base64.b64encode(encrypted).decode(),
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, filepath: str, passphrase: str) -> Identity:
        """Load an identity from an encrypted file.

        Supports version 1 (XOR, no auth), version 2 (XOR + HMAC),
        and version 3 (ChaCha20-Poly1305 AEAD).

        Args:
            filepath: Path to the identity file.
            passphrase: Passphrase to decrypt the private key.

        Returns:
            The decrypted Identity.

        Raises:
            ValueError: If the passphrase is wrong or the file is corrupted.
        """
        filepath = _validate_path(filepath)
        with open(filepath) as f:
            data = json.load(f)

        version = data.get("version")
        if version not in (2, 3):
            if version == 1:
                raise ValueError(
                    "Version 1 identity files are no longer supported — re-save with a current version"
                )
            raise ValueError(f"Unsupported identity file version: {version}")

        salt = base64.b64decode(data["salt"])
        encrypted = base64.b64decode(data["encrypted_nsec"])

        if version == 3:
            key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 600_000)
            nonce = base64.b64decode(data["nonce"])
            aead = ChaCha20Poly1305(key)
            try:
                privkey_bytes = aead.decrypt(nonce, encrypted, salt)
            except Exception:
                raise ValueError("Invalid passphrase or corrupted file")
            return cls.from_hex(privkey_bytes.hex())

        # Legacy v2 support
        key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 600_000)
        stored_mac = base64.b64decode(data["hmac"])
        expected_mac = hmac_module.new(key, salt + encrypted, hashlib.sha256).digest()
        if not hmac_module.compare_digest(stored_mac, expected_mac):
            raise ValueError("Invalid passphrase or corrupted file")

        privkey_bytes = bytes(a ^ b for a, b in zip(encrypted, key))
        return cls.from_hex(privkey_bytes.hex())

    def backup_card(self) -> dict:
        """Return a structured backup card with all key formats.

        This is the identity's "birth certificate." Print it, paste it
        into a password manager, or store it somewhere safe. Anyone with
        the nsec controls this identity.

        Returns:
            Dict with npub, nsec, public_key_hex, and a warning.
        """
        return {
            "npub": self.npub,
            "nsec": self.nsec,
            "public_key_hex": self._public_key_hex,
            "warning": "Store this securely. Anyone with the nsec controls this identity.",
        }

    def export_token(self, passphrase: str) -> str:
        """Export the identity as a single encrypted string.

        Portable format — paste into a password manager, a DM to yourself,
        or an environment variable. Uses the same ChaCha20-Poly1305 AEAD
        encryption as save(), but returns a string instead of writing a file.

        Args:
            passphrase: Passphrase to encrypt the private key.

        Returns:
            An encrypted token string in the format 'nostrkey:v3:base64data'.
        """
        if not passphrase:
            raise ValueError("Passphrase must not be empty")
        salt = secrets.token_bytes(16)
        key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 600_000)
        nonce = secrets.token_bytes(12)

        privkey_bytes = bytes.fromhex(self._private_key_hex)
        aead = ChaCha20Poly1305(key)
        encrypted = aead.encrypt(nonce, privkey_bytes, salt)

        # Pack: salt (16) + nonce (12) + encrypted (32 + 16 tag = 48)
        payload = salt + nonce + encrypted
        encoded = base64.urlsafe_b64encode(payload).decode()
        return f"nostrkey:v3:{encoded}"

    @classmethod
    def from_token(cls, token: str, passphrase: str) -> Identity:
        """Restore an identity from an encrypted token string.

        Args:
            token: The token from export_token() ('nostrkey:v3:base64data').
            passphrase: The passphrase used to encrypt.

        Returns:
            The decrypted Identity.

        Raises:
            ValueError: If the token format is invalid, passphrase is wrong,
                or the data is corrupted.
        """
        if not token or not isinstance(token, str):
            raise ValueError("Token must be a non-empty string")
        if not passphrase:
            raise ValueError("Passphrase must not be empty")

        parts = token.split(":")
        if len(parts) != 3 or parts[0] != "nostrkey" or parts[1] != "v3":
            raise ValueError(
                "Invalid token format. Expected 'nostrkey:v3:<base64data>'"
            )

        try:
            payload = base64.urlsafe_b64decode(parts[2])
        except Exception:
            raise ValueError("Invalid token: base64 decode failed")

        if len(payload) < 76:  # 16 salt + 12 nonce + 32 key + 16 tag
            raise ValueError("Invalid token: payload too short")

        salt = payload[:16]
        nonce = payload[16:28]
        encrypted = payload[28:]

        key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 600_000)
        aead = ChaCha20Poly1305(key)
        try:
            privkey_bytes = aead.decrypt(nonce, encrypted, salt)
        except Exception:
            raise ValueError("Invalid passphrase or corrupted token")

        return cls.from_hex(privkey_bytes.hex())

    def wipe(self) -> None:
        """Best-effort zeroing of private key material from memory.

        Call this when the identity is no longer needed. Note: CPython
        string interning means this cannot guarantee full erasure, but
        it removes the direct references.
        """
        self._private_key_hex = "0" * 64
        self._public_key_hex = "0" * 64

    def __del__(self) -> None:
        try:
            self.wipe()
        except Exception:
            pass

    def __repr__(self) -> str:
        return f"Identity(npub={self.npub[:20]}...)"

    def __str__(self) -> str:
        return self.npub
