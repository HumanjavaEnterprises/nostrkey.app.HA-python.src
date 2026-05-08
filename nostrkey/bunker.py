"""NIP-46 Nostr Connect (Bunker) client for delegated signing.

Allows an OpenClaw bot to request signing from a human's NostrKey app
via relay-mediated encrypted messages.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from urllib.parse import parse_qs, urlparse

import websockets

from nostrkey.crypto import decrypt, encrypt
from nostrkey.events import NostrEvent, UnsignedEvent, sign_event
from nostrkey.keys import private_key_to_public_key
from nostrkey.relay import validate_relay_url


logger = logging.getLogger(__name__)


class BunkerClient:
    """NIP-46 bunker client for delegated signing.

    The bot connects to a relay and communicates with the human's
    NostrKey via encrypted NIP-04/NIP-44 messages.

    Usage:
        bunker = BunkerClient(bot_nsec_hex)
        await bunker.connect("bunker://npub1human...?relay=wss://relay.example.com")
        signed = await bunker.sign_event(kind=1, content="Hello")
        await bunker.disconnect()
    """

    def __init__(self, client_private_key_hex: str):
        self._privkey = client_private_key_hex
        self._pubkey = private_key_to_public_key(client_private_key_hex)
        self._remote_pubkey: str | None = None
        self._relay_url: str | None = None
        self._ws = None
        self._sub_id: str = "bunker"

    async def connect(self, bunker_url: str) -> None:
        """Connect to a bunker via a bunker:// URL.

        Args:
            bunker_url: NIP-46 bunker URL (bunker://npub...?relay=wss://...)
        """
        parsed = urlparse(bunker_url)
        if parsed.scheme != "bunker":
            raise ValueError(f"Expected bunker:// URL, got {parsed.scheme}://")

        self._remote_pubkey = parsed.netloc
        params = parse_qs(parsed.query)
        relays = params.get("relay", [])
        if not relays:
            raise ValueError("Bunker URL must include a relay parameter")
        self._relay_url = relays[0]
        validate_relay_url(self._relay_url)

        self._ws = await websockets.connect(self._relay_url, open_timeout=30)

        # Subscribe to responses from the remote signer
        self._sub_id = f"bunker-{uuid.uuid4()}"
        sub_msg = json.dumps([
            "REQ",
            self._sub_id,
            {"kinds": [24133], "authors": [self._remote_pubkey], "#p": [self._pubkey]},
        ])
        await self._ws.send(sub_msg)

        # Send connect request
        await self._send_request("connect", [self._pubkey])

    async def sign_event(
        self, kind: int, content: str, tags: list[list[str]] | None = None
    ) -> NostrEvent | None:
        """Request the remote signer to sign an event.

        Args:
            kind: Event kind.
            content: Event content.
            tags: Optional event tags.

        Returns:
            Signed NostrEvent if approved, None if rejected.
        """
        unsigned = UnsignedEvent(kind=kind, content=content, tags=tags or [])
        event_json = json.dumps({
            "kind": unsigned.kind,
            "content": unsigned.content,
            "tags": unsigned.tags,
            "created_at": unsigned.created_at,
        })
        response = await self._send_request("sign_event", [event_json])
        if response and response.get("result"):
            evt = json.loads(response["result"])
            return NostrEvent(**evt)
        return None

    async def get_public_key(self) -> str | None:
        """Request the remote signer's public key."""
        response = await self._send_request("get_public_key", [])
        if response:
            return response.get("result")
        return None

    async def disconnect(self) -> None:
        """Disconnect from the bunker."""
        if self._ws:
            await self._ws.close()
            self._ws = None

    async def _send_request(self, method: str, params: list) -> dict | None:
        """Send an encrypted NIP-46 request and wait for response."""
        if not self._ws or not self._remote_pubkey:
            raise RuntimeError("Not connected — call connect() first")

        request_id = str(uuid.uuid4())
        request = json.dumps({"id": request_id, "method": method, "params": params})

        # Encrypt the request
        ciphertext = encrypt(self._privkey, self._remote_pubkey, request)

        # Wrap in a kind 24133 event
        wrapper = sign_event(
            self._privkey,
            UnsignedEvent(
                kind=24133,
                content=ciphertext,
                tags=[["p", self._remote_pubkey]],
            ),
        )

        await self._ws.send(json.dumps(["EVENT", wrapper.to_dict()]))

        # Wait for response
        async for raw in self._ws:
            data = json.loads(raw)
            if data[0] == "EVENT" and data[1] == self._sub_id:
                evt = data[2]
                if evt["pubkey"] != self._remote_pubkey:
                    continue
                try:
                    decrypted = decrypt(self._privkey, evt["pubkey"], evt["content"])
                    response = json.loads(decrypted)
                    if response.get("id") == request_id:
                        return response
                except (json.JSONDecodeError, ValueError, KeyError) as exc:
                    logger.debug("Failed to process bunker response: %s", type(exc).__name__)
                    continue
            elif data[0] == "EOSE":
                continue

        return None
