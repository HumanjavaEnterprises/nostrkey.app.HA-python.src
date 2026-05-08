"""Pure-Python secp256k1 operations using the cryptography package.

Replaces the secp256k1 C binding with cryptography's EC primitives
plus a BIP-340 Schnorr implementation. Zero native build dependencies.
"""

from __future__ import annotations

import hashlib
import secrets

from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    SECP256K1,
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicNumbers,
    generate_private_key,
)

# secp256k1 curve constants
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


# ---------------------------------------------------------------------------
# Low-level EC point arithmetic (for BIP-340 Schnorr)
# ---------------------------------------------------------------------------

def _lift_x(x: int) -> tuple[int, int] | None:
    """Recover a curve point from its x coordinate (even y)."""
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if y_sq != pow(y, 2, P):
        return None
    if y % 2 != 0:
        y = P - y
    return (x, y)


def _point_add(
    p1: tuple[int, int] | None, p2: tuple[int, int] | None
) -> tuple[int, int] | None:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2:
        return None
    if x1 == x2:
        lam = (3 * x1 * x1 * pow(2 * y1, P - 2, P)) % P
    else:
        lam = ((y2 - y1) * pow(x2 - x1, P - 2, P)) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _point_mul(n: int, point: tuple[int, int]) -> tuple[int, int] | None:
    result = None
    addend = point
    while n:
        if n & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        n >>= 1
    return result


def _tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_keypair_bytes() -> tuple[bytes, bytes]:
    """Generate a new secp256k1 keypair.

    Returns:
        Tuple of (private_key_bytes_32, x_only_public_key_bytes_32).
    """
    privkey = generate_private_key(SECP256K1())
    priv_bytes = privkey.private_numbers().private_value.to_bytes(32, "big")
    pub_x = privkey.public_key().public_numbers().x.to_bytes(32, "big")
    return priv_bytes, pub_x


def private_to_public(private_key_bytes: bytes) -> bytes:
    """Derive the x-only public key from a 32-byte private key."""
    d = int.from_bytes(private_key_bytes, "big")
    point = _point_mul(d, G)
    if point is None:
        raise ValueError("Invalid private key")
    return point[0].to_bytes(32, "big")


def schnorr_sign(private_key_bytes: bytes, msg_hash: bytes) -> bytes:
    """BIP-340 Schnorr sign a 32-byte message hash.

    Args:
        private_key_bytes: 32-byte private key.
        msg_hash: 32-byte message hash (typically SHA-256 of the event serialization).

    Returns:
        64-byte Schnorr signature.
    """
    d = int.from_bytes(private_key_bytes, "big")
    P_point = _point_mul(d, G)
    if P_point is None:
        raise ValueError("Invalid private key")

    # Negate d if P.y is odd (BIP-340 convention)
    if P_point[1] % 2 != 0:
        d = N - d

    px = P_point[0].to_bytes(32, "big")
    aux = secrets.token_bytes(32)
    t = (d ^ int.from_bytes(_tagged_hash("BIP0340/aux", aux), "big"))
    k0 = (
        int.from_bytes(
            _tagged_hash("BIP0340/nonce", t.to_bytes(32, "big") + px + msg_hash),
            "big",
        )
        % N
    )
    if k0 == 0:
        raise ValueError("Nonce is zero — retry with different aux randomness")

    R = _point_mul(k0, G)
    if R is None:
        raise ValueError("R point is at infinity")

    k = k0 if R[1] % 2 == 0 else N - k0
    e = (
        int.from_bytes(
            _tagged_hash(
                "BIP0340/challenge", R[0].to_bytes(32, "big") + px + msg_hash
            ),
            "big",
        )
        % N
    )
    sig = R[0].to_bytes(32, "big") + ((k + e * d) % N).to_bytes(32, "big")
    return sig


def schnorr_verify(public_key_x_bytes: bytes, msg_hash: bytes, sig: bytes) -> bool:
    """BIP-340 Schnorr verify a signature.

    Args:
        public_key_x_bytes: 32-byte x-only public key.
        msg_hash: 32-byte message hash.
        sig: 64-byte signature.

    Returns:
        True if the signature is valid.
    """
    P_point = _lift_x(int.from_bytes(public_key_x_bytes, "big"))
    if P_point is None:
        return False

    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if r >= P or s >= N:
        return False

    e = (
        int.from_bytes(
            _tagged_hash(
                "BIP0340/challenge", sig[:32] + public_key_x_bytes + msg_hash
            ),
            "big",
        )
        % N
    )
    R = _point_add(_point_mul(s, G), _point_mul(N - e, P_point))
    if R is None or R[1] % 2 != 0 or R[0] != r:
        return False
    return True


def ecdh(private_key_bytes: bytes, public_key_x_bytes: bytes) -> bytes:
    """Compute ECDH shared secret.

    Args:
        private_key_bytes: 32-byte private key.
        public_key_x_bytes: 32-byte x-only public key of the other party.

    Returns:
        32-byte shared secret.
    """
    d = int.from_bytes(private_key_bytes, "big")

    # Reconstruct full public key (assume even y)
    point = _lift_x(int.from_bytes(public_key_x_bytes, "big"))
    if point is None:
        raise ValueError("Invalid public key")

    x, y = point
    pub_numbers = EllipticCurvePublicNumbers(x, y, SECP256K1())
    pub_key = pub_numbers.public_key()

    priv_numbers = EllipticCurvePrivateNumbers(d, pub_numbers)
    # We need our own public key for the private numbers
    our_point = _point_mul(d, G)
    if our_point is None:
        raise ValueError("Invalid private key")
    our_pub_numbers = EllipticCurvePublicNumbers(our_point[0], our_point[1], SECP256K1())
    priv_numbers = EllipticCurvePrivateNumbers(d, our_pub_numbers)
    priv_key = priv_numbers.private_key()

    shared = priv_key.exchange(ECDH(), pub_key)
    # NIP-44 expects the raw 32-byte x-coordinate, not a hash.
    # cryptography's ECDH().exchange() already returns the raw x-coordinate bytes.
    return shared
