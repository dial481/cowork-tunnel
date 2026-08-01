#!/usr/bin/env python3
"""Standalone WebSocket-to-SSH relay.

Install on each server you want to reach. Bridges authenticated WebSocket
connections to the local sshd on 127.0.0.1:22.

Security model:
  1. Bearer token on WebSocket upgrade (rejects before the tunnel opens)
  2. TLS via nginx/Cloudflare (relay listens plain WS on localhost only)
  3. sshd still requires a valid SSH key (the token is the first lock, not the
     only lock)

Usage:
  # Generate a token
  python3 -c "import secrets; print(secrets.token_urlsafe(32))"

  # Run the relay
  RELAY_TOKEN=<token> python3 standalone.py

  # Custom ports
  RELAY_TOKEN=<token> SSH_PORT=22 WS_PORT=8765 python3 standalone.py

Environment variables:
  RELAY_TOKEN      - Required. Bearer token for authentication.
  SSH_HOST         - sshd address (default: 127.0.0.1)
  SSH_PORT         - sshd port (default: 22)
  WS_HOST          - Listen address (default: 127.0.0.1)
  WS_PORT          - Listen port (default: 8765)
  MAX_CONNECTIONS  - Max concurrent tunnels (default: 10)
  RATE_LIMIT       - Max new connections per minute (default: 20). See README:
                     behind a reverse proxy this is a single shared bucket,
                     not per-client.

Designed for: Anthropic Cowork cloud sessions that can only reach HTTPS.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
import signal
import sys
import time
from collections import defaultdict
from urllib.parse import parse_qs, urlparse

try:
    import websockets
except ImportError:
    print("[relay] pip install websockets", file=sys.stderr)
    sys.exit(1)

try:
    from websockets.asyncio.server import serve
except ImportError:
    from websockets.server import serve  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
RELAY_TOKEN = os.environ.get("RELAY_TOKEN", "")
SSH_HOST = os.environ.get("SSH_HOST", "127.0.0.1")
SSH_PORT = int(os.environ.get("SSH_PORT", "22"))
WS_HOST = os.environ.get("WS_HOST", "127.0.0.1")
WS_PORT = int(os.environ.get("WS_PORT", "8765"))
MAX_CONNECTIONS = int(os.environ.get("MAX_CONNECTIONS", "10"))
RATE_LIMIT = int(os.environ.get("RATE_LIMIT", "20"))

CONNECT_TIMEOUT = 10
BUF_SIZE = 65536

log = logging.getLogger("relay")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [relay] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ---------------------------------------------------------------------------
# Rate limiting
#
# Keyed on the peer address. Behind nginx every peer is 127.0.0.1, so in the
# documented deployment this is one shared bucket rather than per-client. That
# is intentional for a single-user relay; see README.
# ---------------------------------------------------------------------------
_conn_times: dict[str, list[float]] = defaultdict(list)
_active: int = 0


def _rate_ok(ip: str) -> bool:
    """Record a connection attempt and report whether it is within the limit."""
    now = time.monotonic()
    recent = [t for t in _conn_times[ip] if now - t < 60]
    # Drop keys that have gone quiet so the table cannot grow without bound.
    for key in [k for k, v in _conn_times.items() if k != ip and (not v or now - v[-1] >= 60)]:
        del _conn_times[key]
    if len(recent) >= RATE_LIMIT:
        _conn_times[ip] = recent
        return False
    recent.append(now)
    _conn_times[ip] = recent
    return True


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
def _extract_token(websocket) -> str | None:
    """Extract the bearer token from the query string or Authorization header."""
    try:
        path = websocket.request.path if hasattr(websocket, "request") else websocket.path
    except Exception:
        path = getattr(websocket, "path", "/")

    token = None
    if "?" in path:
        token = parse_qs(urlparse(path).query).get("token", [None])[0]

    if not token:
        try:
            headers = (
                websocket.request.headers
                if hasattr(websocket, "request")
                else websocket.request_headers
            )
        except Exception:
            headers = getattr(websocket, "request_headers", {})
        auth = headers.get("Authorization", "") or headers.get("authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]

    return token


def _token_valid(supplied: str) -> bool:
    """Timing-safe token comparison that tolerates non-ASCII tokens."""
    return hmac.compare_digest(supplied.encode("utf-8"), RELAY_TOKEN.encode("utf-8"))


# ---------------------------------------------------------------------------
# Bridge
# ---------------------------------------------------------------------------
async def _pump(websocket, reader, writer) -> None:
    """Shuttle bytes both ways until either side ends, then tear both down."""

    async def ws_to_tcp() -> None:
        try:
            async for msg in websocket:
                writer.write(msg if isinstance(msg, bytes) else msg.encode())
                await writer.drain()
        except (websockets.ConnectionClosed, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            # Signal EOF to sshd so it closes and unblocks tcp_to_ws.
            try:
                if writer.can_write_eof():
                    writer.write_eof()
            except Exception:
                pass

    async def tcp_to_ws() -> None:
        try:
            while True:
                data = await reader.read(BUF_SIZE)
                if not data:
                    break
                await websocket.send(data)
        except (websockets.ConnectionClosed, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            # Closing the socket unblocks ws_to_tcp's `async for`.
            try:
                await websocket.close()
            except Exception:
                pass

    tasks = [asyncio.create_task(ws_to_tcp()), asyncio.create_task(tcp_to_ws())]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def bridge(websocket):
    global _active

    if not RELAY_TOKEN:
        log.error("RELAY_TOKEN not set")
        await websocket.close(1008, "Server misconfigured")
        return

    if not _token_valid(_extract_token(websocket) or ""):
        log.warning("Auth failed from %s", getattr(websocket, "remote_address", ("?",))[0])
        await websocket.close(4003, "Forbidden")
        return

    remote_ip = getattr(websocket, "remote_address", ("0.0.0.0",))[0]
    if not _rate_ok(remote_ip):
        log.warning("Rate limit hit for %s", remote_ip)
        await websocket.close(4029, "Too many connections")
        return

    if _active >= MAX_CONNECTIONS:
        log.warning("Max connections (%d) reached", MAX_CONNECTIONS)
        await websocket.close(4029, "Server busy")
        return

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(SSH_HOST, SSH_PORT), timeout=CONNECT_TIMEOUT
        )
    except asyncio.TimeoutError:
        log.error("Timeout connecting to sshd at %s:%d", SSH_HOST, SSH_PORT)
        await websocket.close(1011, "sshd unreachable")
        return
    except OSError as e:
        log.error("Cannot reach sshd at %s:%d: %s", SSH_HOST, SSH_PORT, e)
        await websocket.close(1011, "sshd unreachable")
        return

    _active += 1
    log.info("Session opened from %s (active: %d)", remote_ip, _active)
    try:
        await _pump(websocket, reader, writer)
    except Exception as e:  # noqa: BLE001 - a broken tunnel must not kill the relay
        log.debug("Session error: %s", e)
    finally:
        if not writer.is_closing():
            writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        _active -= 1
        log.info("Session closed from %s (active: %d)", remote_ip, _active)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
async def main():
    if not RELAY_TOKEN:
        log.error("Set RELAY_TOKEN environment variable before starting")
        sys.exit(1)

    log.info(
        "Standalone relay on %s:%d -> sshd %s:%d (max %d)",
        WS_HOST,
        WS_PORT,
        SSH_HOST,
        SSH_PORT,
        MAX_CONNECTIONS,
    )

    async with serve(bridge, WS_HOST, WS_PORT, ping_interval=30, ping_timeout=120, max_size=None):
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        await stop.wait()

    log.info("Relay shut down")


if __name__ == "__main__":
    asyncio.run(main())
