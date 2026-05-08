"""NIP-44 encryption and decryption for Nostr."""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import struct

from nostrkey._secp256k1 import ecdh as _ecdh


def _compute_shared_secret(private_key_hex: str, public_key_hex: str) -> bytes:
    """Compute the shared secret between two keys using ECDH."""
    return _ecdh(bytes.fromhex(private_key_hex), bytes.fromhex(public_key_hex))


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF extract step."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF expand step."""
    blocks = []
    block = b""
    for i in range(1, (length + 31) // 32 + 1):
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        blocks.append(block)
    return b"".join(blocks)[:length]


def _calc_padded_len(unpadded_len: int) -> int:
    """Calculate NIP-44 padded length for a given plaintext length."""
    if unpadded_len <= 0:
        raise ValueError("Plaintext must not be empty")
    if unpadded_len <= 32:
        return 32
    next_power = 1 << (math.floor(math.log2(unpadded_len - 1)) + 1)
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * (math.floor((unpadded_len - 1) / chunk) + 1)


def _pad_plaintext(plaintext: bytes) -> bytes:
    """Pad plaintext using the NIP-44 padding algorithm."""
    unpadded_len = len(plaintext)
    if unpadded_len > 65535:
        raise ValueError("Plaintext too long (max 65535 bytes)")

    padded_len = _calc_padded_len(unpadded_len)
    padding = b"\x00" * (padded_len - unpadded_len)
    return struct.pack(">H", unpadded_len) + plaintext + padding


def _unpad_plaintext(padded: bytes) -> bytes:
    """Remove padding from decrypted plaintext."""
    if len(padded) < 2:
        raise ValueError("Decryption failed")
    actual_len = struct.unpack(">H", padded[:2])[0]
    if actual_len > len(padded) - 2:
        raise ValueError("Decryption failed")
    return padded[2 : 2 + actual_len]


def encrypt(sender_nsec: str, recipient_npub: str, plaintext: str) -> str:
    """Encrypt a message using NIP-44.

    Args:
        sender_nsec: Sender's private key (nsec bech32 or hex).
        recipient_npub: Recipient's public key (npub bech32 or hex).
        plaintext: The message to encrypt.

    Returns:
        Base64-encoded ciphertext with version prefix.
    """
    if not plaintext:
        raise ValueError("Plaintext must not be empty")

    import base64

    from nostrkey.keys import nsec_to_hex, npub_to_hex

    # Accept both bech32 and hex
    privkey_hex = nsec_to_hex(sender_nsec) if sender_nsec.startswith("nsec") else sender_nsec
    pubkey_hex = npub_to_hex(recipient_npub) if recipient_npub.startswith("npub") else recipient_npub

    shared_secret = _compute_shared_secret(privkey_hex, pubkey_hex)
    conversation_key = _hkdf_extract(b"nip44-v2", shared_secret)

    nonce = secrets.token_bytes(32)
    keys = _hkdf_expand(conversation_key, nonce, 76)
    chacha_key = keys[:32]
    chacha_nonce = keys[32:44]
    hmac_key = keys[44:76]

    padded = _pad_plaintext(plaintext.encode("utf-8"))

    # ChaCha20 encryption (using XOR stream)
    from nostrkey._chacha20 import chacha20_encrypt

    ciphertext = chacha20_encrypt(chacha_key, chacha_nonce, padded)

    # HMAC
    mac = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()

    # Version 2 prefix
    payload = b"\x02" + nonce + ciphertext + mac
    return base64.b64encode(payload).decode("ascii")


def decrypt(recipient_nsec: str, sender_npub: str, ciphertext_b64: str) -> str:
    """Decrypt a NIP-44 encrypted message.

    Args:
        recipient_nsec: Recipient's private key (nsec bech32 or hex).
        sender_npub: Sender's public key (npub bech32 or hex).
        ciphertext_b64: Base64-encoded ciphertext.

    Returns:
        Decrypted plaintext string.
    """
    import base64

    from nostrkey.keys import nsec_to_hex, npub_to_hex

    privkey_hex = nsec_to_hex(recipient_nsec) if recipient_nsec.startswith("nsec") else recipient_nsec
    pubkey_hex = npub_to_hex(sender_npub) if sender_npub.startswith("npub") else sender_npub

    payload = base64.b64decode(ciphertext_b64)

    if len(payload) < 99:
        raise ValueError("Ciphertext too short")

    version = payload[0]
    if version != 2:
        raise ValueError(f"Unsupported NIP-44 version: {version}")

    nonce = payload[1:33]
    mac = payload[-32:]
    encrypted = payload[33:-32]

    shared_secret = _compute_shared_secret(privkey_hex, pubkey_hex)
    conversation_key = _hkdf_extract(b"nip44-v2", shared_secret)

    keys = _hkdf_expand(conversation_key, nonce, 76)
    chacha_key = keys[:32]
    chacha_nonce = keys[32:44]
    hmac_key = keys[44:76]

    # Verify HMAC
    expected_mac = hmac.new(hmac_key, nonce + encrypted, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("HMAC verification failed — message tampered or wrong key")

    from nostrkey._chacha20 import chacha20_encrypt

    padded = chacha20_encrypt(chacha_key, chacha_nonce, encrypted)
    return _unpad_plaintext(padded).decode("utf-8")
