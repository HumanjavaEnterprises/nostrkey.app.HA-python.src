"""Minimal ChaCha20 implementation for NIP-44 encryption.

This is a pure-Python fallback. For production use, consider replacing with
a C-backed implementation like `cryptography` package.
"""

from __future__ import annotations

import struct


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    """ChaCha20 quarter round operation."""
    mask = 0xFFFFFFFF
    state[a] = (state[a] + state[b]) & mask
    state[d] ^= state[a]
    state[d] = ((state[d] << 16) | (state[d] >> 16)) & mask
    state[c] = (state[c] + state[d]) & mask
    state[b] ^= state[c]
    state[b] = ((state[b] << 12) | (state[b] >> 20)) & mask
    state[a] = (state[a] + state[b]) & mask
    state[d] ^= state[a]
    state[d] = ((state[d] << 8) | (state[d] >> 24)) & mask
    state[c] = (state[c] + state[d]) & mask
    state[b] ^= state[c]
    state[b] = ((state[b] << 7) | (state[b] >> 25)) & mask


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Generate a single ChaCha20 block (64 bytes)."""
    constants = b"expand 32-byte k"
    state = list(struct.unpack("<4I", constants))
    state += list(struct.unpack("<8I", key))
    state += [counter]
    state += list(struct.unpack("<3I", nonce))

    working = state[:]
    for _ in range(10):  # 20 rounds = 10 double rounds
        # Column rounds
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        # Diagonal rounds
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)

    output = []
    for i in range(16):
        output.append(struct.pack("<I", (working[i] + state[i]) & 0xFFFFFFFF))
    return b"".join(output)


def chacha20_encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """Encrypt/decrypt data using ChaCha20 (symmetric — same function for both)."""
    result = bytearray()
    counter = 0
    for i in range(0, len(data), 64):
        block = _chacha20_block(key, counter, nonce)
        chunk = data[i : i + 64]
        result.extend(a ^ b for a, b in zip(chunk, block))
        counter += 1
    return bytes(result)
