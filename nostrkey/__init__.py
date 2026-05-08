"""NostrKey — Nostr identity SDK for OpenClaw AI entities."""

from nostrkey.identity import Identity
from nostrkey.keys import generate_keypair, nsec_to_hex, npub_to_hex, hex_to_nsec, hex_to_npub
from nostrkey.seed import generate_seed_phrase, validate_seed_phrase, seed_phrase_to_private_key

__version__ = "0.2.9"
__all__ = [
    "Identity",
    "generate_keypair",
    "nsec_to_hex",
    "npub_to_hex",
    "hex_to_nsec",
    "hex_to_npub",
    "generate_seed_phrase",
    "validate_seed_phrase",
    "seed_phrase_to_private_key",
]
