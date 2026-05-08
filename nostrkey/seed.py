"""BIP-39 seed phrase support for Nostr identities (NIP-06).

Generates and restores Nostr keypairs from human-readable seed phrases.
The derivation path follows NIP-06: m/44'/1237'/0'/0/0.

12 words you can write on paper, speak aloud, or memorize.
The same seed phrase always produces the same identity.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_module
import struct

from mnemonic import Mnemonic

from nostrkey._secp256k1 import _point_mul, G, N as _SECP256K1_ORDER

# NIP-06 derivation path: m/44'/1237'/0'/0/0
_NIP06_PATH = [(44, True), (1237, True), (0, True), (0, False), (0, False)]


def _derive_hardened(
    parent_key: bytes, parent_chain: bytes, index: int
) -> tuple[bytes, bytes]:
    """BIP-32 hardened child key derivation."""
    data = b"\x00" + parent_key + struct.pack(">I", 0x80000000 | index)
    I = hmac_module.new(parent_chain, data, hashlib.sha512).digest()
    child_int = (
        int.from_bytes(I[:32], "big") + int.from_bytes(parent_key, "big")
    ) % _SECP256K1_ORDER
    if child_int == 0:
        raise ValueError("Derived key is zero — astronomically unlikely, retry with next index")
    return child_int.to_bytes(32, "big"), I[32:]


def _derive_normal(
    parent_key: bytes, parent_chain: bytes, index: int
) -> tuple[bytes, bytes]:
    """BIP-32 normal (non-hardened) child key derivation."""
    d = int.from_bytes(parent_key, "big")
    point = _point_mul(d, G)
    if point is None:
        raise ValueError("Invalid parent key for derivation")
    # BIP-32 compressed pubkey: 0x02 if y is even, 0x03 if odd
    prefix = b"\x02" if point[1] % 2 == 0 else b"\x03"
    pub_compressed = prefix + point[0].to_bytes(32, "big")
    data = pub_compressed + struct.pack(">I", index)
    I = hmac_module.new(parent_chain, data, hashlib.sha512).digest()
    child_int = (
        int.from_bytes(I[:32], "big") + int.from_bytes(parent_key, "big")
    ) % _SECP256K1_ORDER
    if child_int == 0:
        raise ValueError("Derived key is zero — astronomically unlikely, retry with next index")
    return child_int.to_bytes(32, "big"), I[32:]


def _derive_nip06(seed_bytes: bytes) -> bytes:
    """Derive a Nostr private key from BIP-39 seed bytes via NIP-06 path.

    Path: m/44'/1237'/0'/0/0

    Args:
        seed_bytes: The 64-byte BIP-39 seed.

    Returns:
        32-byte private key.
    """
    # BIP-32 master key from seed
    I = hmac_module.new(b"Bitcoin seed", seed_bytes, hashlib.sha512).digest()
    key, chain = I[:32], I[32:]

    # Walk the derivation path
    for index, hardened in _NIP06_PATH:
        if hardened:
            key, chain = _derive_hardened(key, chain, index)
        else:
            key, chain = _derive_normal(key, chain, index)

    return key


def generate_seed_phrase(strength: int = 128) -> str:
    """Generate a new BIP-39 seed phrase.

    Args:
        strength: Entropy bits. 128 = 12 words, 256 = 24 words.

    Returns:
        A space-separated BIP-39 mnemonic string.
    """
    if strength not in (128, 256):
        raise ValueError("Strength must be 128 (12 words) or 256 (24 words)")
    m = Mnemonic("english")
    return m.generate(strength)


def validate_seed_phrase(phrase: str) -> bool:
    """Check if a seed phrase is valid BIP-39.

    Args:
        phrase: Space-separated mnemonic words.

    Returns:
        True if valid, False otherwise.
    """
    if not phrase or not isinstance(phrase, str):
        return False
    m = Mnemonic("english")
    return m.check(phrase)


def seed_phrase_to_private_key(phrase: str) -> str:
    """Derive a Nostr private key from a BIP-39 seed phrase.

    Uses NIP-06 derivation path: m/44'/1237'/0'/0/0.

    Args:
        phrase: A valid BIP-39 seed phrase.

    Returns:
        The private key as a hex string.

    Raises:
        ValueError: If the seed phrase is invalid.
    """
    if not validate_seed_phrase(phrase):
        raise ValueError("Invalid BIP-39 seed phrase")
    m = Mnemonic("english")
    seed_bytes = m.to_seed(phrase, passphrase="")
    privkey = _derive_nip06(seed_bytes)
    return privkey.hex()
