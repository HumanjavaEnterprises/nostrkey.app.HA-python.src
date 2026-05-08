"""Key generation and bech32 encoding/decoding for Nostr (NIP-19)."""

from __future__ import annotations

import bech32

from nostrkey._secp256k1 import generate_keypair_bytes, private_to_public


def generate_keypair() -> tuple[str, str]:
    """Generate a new Nostr keypair.

    Returns:
        Tuple of (private_key_hex, public_key_hex).
    """
    priv_bytes, pub_bytes = generate_keypair_bytes()
    return priv_bytes.hex(), pub_bytes.hex()


def hex_to_nsec(private_key_hex: str) -> str:
    """Convert a hex private key to bech32 nsec format."""
    return _bech32_encode("nsec", bytes.fromhex(private_key_hex))


def hex_to_npub(public_key_hex: str) -> str:
    """Convert a hex public key to bech32 npub format."""
    return _bech32_encode("npub", bytes.fromhex(public_key_hex))


def nsec_to_hex(nsec: str) -> str:
    """Convert a bech32 nsec to hex private key."""
    return _bech32_decode("nsec", nsec).hex()


def npub_to_hex(npub: str) -> str:
    """Convert a bech32 npub to hex public key."""
    return _bech32_decode("npub", npub).hex()


def _validate_hex_key(hex_str: str, name: str = "key") -> None:
    """Validate that a string is a 64-character hex key.

    Args:
        hex_str: The hex string to validate.
        name: Label for error messages.

    Raises:
        ValueError: If the string is not exactly 64 valid hex characters.
    """
    if len(hex_str) != 64:
        raise ValueError(f"Invalid {name}: must be 64 hex characters")
    try:
        int(hex_str, 16)
    except ValueError:
        raise ValueError(f"Invalid {name}: must be 64 hex characters")


N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _validate_private_key(hex_str: str) -> None:
    """Validate that a string is a valid secp256k1 private key.

    Checks format (64 hex chars) and range (1 <= d < N).

    Args:
        hex_str: The hex string to validate.

    Raises:
        ValueError: If the key is invalid or out of range.
    """
    _validate_hex_key(hex_str, "private key")
    d = int(hex_str, 16)
    if d == 0 or d >= N:
        raise ValueError("Invalid private key: out of valid range")


def private_key_to_public_key(private_key_hex: str) -> str:
    """Derive the public key from a private key."""
    _validate_private_key(private_key_hex)
    return private_to_public(bytes.fromhex(private_key_hex)).hex()


def _bech32_encode(hrp: str, data: bytes) -> str:
    """Encode bytes to bech32."""
    converted = bech32.convertbits(list(data), 8, 5, True)
    if converted is None:
        raise ValueError("Failed to convert bits for bech32 encoding")
    return bech32.bech32_encode(hrp, converted)


def _bech32_decode(expected_hrp: str, bech32_str: str) -> bytes:
    """Decode bech32 string to bytes."""
    hrp, data = bech32.bech32_decode(bech32_str)
    if hrp != expected_hrp:
        raise ValueError(f"Expected hrp '{expected_hrp}', got '{hrp}'")
    if data is None:
        raise ValueError("Failed to decode bech32 string")
    converted = bech32.convertbits(data, 5, 8, False)
    if converted is None:
        raise ValueError("Failed to convert bits from bech32")
    return bytes(converted)
